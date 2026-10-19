#!/usr/bin/env python3
r"""fix43：cloud_cred_password(1203) 的**值锚判定窗口** + **语法位置守卫**。

背景（已证实；证据与量化见 test-result/fix43/ 与先行探针 /tmp/ctxprobe/）：

`perform_constant_classifying` 给 1203 判据传的 `stmt` 是
`truncated_contexts[sid] = extract_context(raw_stmt, s, 512)` —— 以**语句第一个常量**为锚、
按空白切成 token 取相邻 3 个。于是：

  · 语句里第 2 个以后的常量，判定窗口里常常根本没有这个值。fix31（三族）与 fix42（五族）的
    位置判据一律**先要求「值在窗口里」**（`if value not in stmt: return False`），窗口不含该
    值时它们全部失效 —— normal_quarkpan_v2 实测 1,959 个 1203 去重值里 1,037 个的任何一行
    source_snippet 都不含该值；
  · 语句内常量的处理顺序还受 PYTHONHASHSEED 影响，同一个值的判定会随种子漂移。

本轮两半（**必须同批落地**；先行探针实测：只改窗口会让样本 A 新增 187 对 risk>=4、其中
162 对是**反向进入 1203**）：

  ① **值锚窗口** `_ccp_value_anchor_context(raw_stmt, value, fallback)`
     以当前值在 raw_stmt 里的**独立出现**（口径 = `_ccp_occurrence_positions`，与
     `_bound_value_keys` 同一套「独立出现」细则）为中心取 ±256 字符（总长 512，与既有
     `extract_context(..., 512)` 同量级）。**只接在 1203 判定处**：主循环其余逻辑、
     `truncated_contexts`、其他判据、入库 source_snippet 一律不动。值在 raw_stmt 里找不到独立
     出现（或语句本身 <=512 字符，此时旧窗口本来就等于整条语句）→ **退回旧窗口**。

     判定口径 = 「**修复前判 1203 ∧ 值锚窗口判 1203**」（`is_cloud_password_before_fix43` +
     `_ccp_value_anchor_context`）。值锚窗口只用于**收窄**：修复前不是 1203 的值一行不动
     （反向进入 1203 = 0 是红线，那 162 对反向值正是「旧窗口没有密码语境、值锚窗口有」）；
     修复前判 1203 的值在值锚窗口里站不住就改判 `cloud_cred_noise(1207, risk0)`。

  ② **语法位置守卫** `is_cloud_password_position_noise(value, stmt)`
     在 fix31 三条保护**之后**判三类位置判据，命中即判噪音：

       B 字符串表元素     `e = [ "alphaOne", "betaTwo", "tableCellLabel4", … ]`
       C 成员访问         值紧跟在一个 `.` 之后（`t.data.emoney7`）；`. 左侧必须是标识符字符或
                          `]`/`)`（引号不在字符表里 → CSS 选择器 `'.mt-input__icon` 不算）
       E 扁平数组元素     最近的未配对 `[`…`]` 里 >=6 个字面量元素（B 的窄化形态）

     另三类**不在这里实现**（各自有 owner，单测钉死了对面的行为）：
       · i18n 键名位 —— fix42 P1（`is_cloud_password_i18n_key`）的射程；fix42 单测把「右侧不是
         含中日韩字符的字面量」这一支钉成**不是噪音**（P1_NEGATIVE_CASES），所以本守卫刻意不带
         无 CJK 的兄弟规则。fix43 在这里的贡献是**窗口**：值锚窗口让 P1 从「窗口里没有值」的
         失效状态复活（`(0,a.default)(o,"KEY","中文")` 一族）。
       · 对象键位（值右侧紧跟 `:`，含 `cond ? "a" : "b"` 的三元分支）—— fix31 键名位保护的射程，
         而且是**刻意保护**的位置。
       · 日志 callee 实参 —— fix31 ① 与 fix42 P4 的射程；更宽的 callee 词根（`trackEvent` /
         `logger.` / `sentry.`）是 fix31 单测钉死的已知残留，本守卫不得收进来。

三条保护（fix31 已有，本守卫一律排在其后）：值绑在任何键上 / 值处于键名位 / 值是
password·pwd·passwd 名 callee 的实参。另外两条红线：fix12 核定值白名单，以及 fix31c 的
**材料形豁免**（fix42 单测把「材料形值坐在串表里」钉成必须保持 1203）。

不可排除的四类（守卫不许碰）：非密码名函数实参（含 `Utf8.parse("…")` 这类疑似真阳性）、
比较运算数、`return` 位（fix12 红线值在这里）、三元键位。

用法: .venv/bin/python -X utf8 unit-tests/test_fix43_ccp_value_anchor.py
"""

import inspect
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402
import test_fix31_ccp_family_guards as F31  # noqa: E402  （保护集/红线值的唯一来源）

CCP = IDT.CLOUD_CRED_PASSWORD
CCP_NAME = "CLOUD_CRED_PASSWORD"
NOISE_NAME = "CLOUD_CRED_NOISE"
ANCHOR = "_ccp_value_anchor_context"            # ① 值锚窗口
GUARD = "is_cloud_password_position_noise"      # ② 语法位置守卫
BASELINE = "is_cloud_password_before_fix43"     # 主循环的「修复前口径」记账入口
_ID_TO_SLUG = {v: k for k, v in vars(IDT).items()
               if isinstance(v, int) and k.isupper() and not k.startswith("CTG_")}


def _risk_by_name():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "constant_types.json")
    with open(path, encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"].upper()] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risk_by_name()


def _hook(name):
    fn = getattr(C, name, None)
    if fn is None:
        raise AssertionError("constants_classifier.%s 尚未实现（RED）" % name)
    return fn


def _rows(constants, statements, fix43_off=False):
    """跑完整分类，返回原始行 (slug_id, content, src, snippet)。

    fix43_off=True 时把本轮两个入口换掉（值锚窗口 -> 恒返回旧窗口、位置守卫 -> 恒 False）
    = **fix43 之前的代码路径**；对照只靠同一进程内的开关，不依赖 git stash / checkout。
    """
    a, g = _hook(ANCHOR), _hook(GUARD)
    if fix43_off:
        C._ccp_value_anchor_context = lambda _raw, _v, fallback: fallback
        C.is_cloud_password_position_noise = lambda _v, _st: False
    try:
        return C.perform_constant_classifying(list(statements), list(constants))
    finally:
        C._ccp_value_anchor_context = a
        C.is_cloud_password_position_noise = g


def _labels(constants, statements, value, fix43_off=False):
    return sorted({_ID_TO_SLUG.get(r[0], str(r[0]))
                   for r in _rows(constants, statements, fix43_off) if r[1] == value})


def _snippet_of(constants, statements, value):
    for r in _rows(constants, statements):
        if r[1] == value:
            return r[3]
    return None


# =========================================================
# 合成长语句：第一个常量在语句头（旧窗口的锚），目标值在 ~700 字符之后的尾巴里
# =========================================================
FIRST = "passWordCtx9"                     # 旧窗口的锚：token 内含 passWord -> 语境闸门打开
HEAD = 'var seedByte = 1; var passWordCtx9 = this.data.passWord;'
PLAIN_FIRST = "plainCtx7"                  # 旧窗口的锚**不带密码语境**（反向对照用）
PLAIN_HEAD = 'var seedByte = 1; var plainCtx7 = this.themeColor;'


def _long(tail, filler_tokens=90, head=HEAD):
    filler = " ".join("padTok%d" % i for i in range(filler_tokens))
    return head + " " + filler + " " + tail


def _consts(value, first=FIRST):
    """两条常量：第一条（first）决定旧窗口，第二条是本次要判的目标值。"""
    return [(first, 0, 0), (value, 0, 0)]


# 三类可排除位置（值锚窗口里仍带着密码语境 —— 排除只可能来自位置判据或 P1 的窗口）
I18N_VALUE = "HomeBannerLabel7"
I18N_TAIL = ('t.setData({pwdErr: 1}), (0,a.default)(o,"%s","首页横幅"), '
             'this.setPwdState(!1);' % I18N_VALUE)
STRTABLE_VALUE = "tableCellLabel4"
STRTABLE_TAIL = ('e = [ "alphaOne", "betaTwo", "mossText", "gammaThree", "%s", "deltaFour" ], '
                 'this.checkPwd(t.pwd);' % STRTABLE_VALUE)
MEMBER_VALUE = "slotContentValue9"
MEMBER_TAIL = 'this.cache["slot7"].%s, this.loadPwd(t.pwd);' % MEMBER_VALUE
ARRAY_VALUE = "flatArrayItem3"
ARRAY_TAIL = ('n = [ "itemOne", "itemTwo", "itemThree", "itemFour", "itemFive", "%s" ], '
              'a.verifyPwd(n);' % ARRAY_VALUE)

EXCLUDE_CASES = [
    # (类名, 值, 尾巴)
    ("i18n_key_via_fix42_P1", I18N_VALUE, I18N_TAIL),
    ("B_string_table", STRTABLE_VALUE, STRTABLE_TAIL),
    ("C_member_access", MEMBER_VALUE, MEMBER_TAIL),
    ("E_flat_array", ARRAY_VALUE, ARRAY_TAIL),
]

# 值锚窗口**判 1203**、但旧窗口没有密码语境 -> 修复前不是 1203 -> 本轮不许把它拉进 1203
REVERSE_VALUE = "tableCellLabel4"
REVERSE_TAIL = ('e = [ "alphaOne", "betaTwo", "mossText", "gammaThree", "%s", "deltaFour" ], '
                'this.checkPwd(t.pwd);' % REVERSE_VALUE)

# 短语句（旧窗口 == 值锚窗口）：位置守卫在**旧窗口**上命中的值同样要显式落 1207
SHORT_TABLE_VALUE = "tableCellLabel4"
SHORT_TABLE_STMT = 'e = [ "%s", "pwdErr", "alphaOne" ], t.setData();' % SHORT_TABLE_VALUE

# 不可排除的四类（fn_arg / compare / return / 三元键位）—— 守卫不许碰它们
FNARG_VALUE = "mossText4"
FNARG_TAIL = 't.setData({pwdErr: 1}), a.parseKey("%s"), this.setPwdState(!1);' % FNARG_VALUE
COMPARE_VALUE = "mossText4"
COMPARE_TAIL = ('t.setData({pwdErr: 1}), "%s" === e.detail.value.pwd ? (t.ok = 1) : 0;'
                % COMPARE_VALUE)
RETURN_VALUE = "kdfTestVector3"
RETURN_TAIL = ('c.login = function(t) { if (t.password) return "%s"; }, t.checkPwd();'
               % RETURN_VALUE)
TERNARY_A = "slotTokenA7"
TERNARY_B = "slotTokenB8"
TERNARY_TAIL = ('this.hasSetPassword ? "%s" : "%s", this.setPwdState(!0);'
                % (TERNARY_A, TERNARY_B))
KEEP_CASES = [
    ("fn_arg", FNARG_VALUE, FNARG_TAIL),
    ("compare", COMPARE_VALUE, COMPARE_TAIL),
    ("return", RETURN_VALUE, RETURN_TAIL),
    ("ternary_key_a", TERNARY_A, TERNARY_TAIL),
    ("ternary_key_b", TERNARY_B, TERNARY_TAIL),
]

# 值绑在（直接 / 后缀）密码键上 + 密码名 callee 的实参 —— 三条保护，必须逐位不变
BOUND_VALUE = "slotContentValue9"
BOUND_TAIL = 'o.login = function(t) { t.passWord = "%s"; }, t.loadPwd();' % BOUND_VALUE
SUFFIX_BOUND_VALUE = "mossText4"
SUFFIX_BOUND_TAIL = ('q.user = function(t) { t.signBoardPasswordField = "%s"; };'
                     % SUFFIX_BOUND_VALUE)
CALLEE_VALUE = "tableCellLabel4"
CALLEE_TAIL = 'o.loginWithPassword("demo", "%s"), t.checkPwd();' % CALLEE_VALUE
PROTECTED_CASES = [
    ("bound_direct_key", BOUND_VALUE, BOUND_TAIL),
    ("bound_suffix_key", SUFFIX_BOUND_VALUE, SUFFIX_BOUND_TAIL),
    ("pwd_callee_arg", CALLEE_VALUE, CALLEE_TAIL),
]

# 值**不在 raw_stmt 里**（= 库里 snippet-absent 的 1139 值口径）：行为必须逐位不变
ABSENT_VALUE = "HomeBannerLabel7"
ABSENT_STMT = 'this.setData({pwdErr: 1}), t.passWord, t.checkPwd(this.data.pwd);'


# =========================================================
# ① 值锚窗口：语义 + 「非首常量」的排除
# =========================================================
def test_fix43_anchor_window_semantics():
    """值锚窗口 = 以值的独立出现为中心的 ±256 字符；定位不到时退回旧窗口。"""
    anchor = _hook(ANCHOR)
    stmt = _long(I18N_TAIL)
    old = C.extract_context(stmt, FIRST, 512)
    win = anchor(stmt, I18N_VALUE, old)
    assert I18N_VALUE in win, win
    assert 0 < len(win) <= len(stmt), len(win)
    assert win in stmt, "值锚窗口必须是 raw_stmt 的**连续切片**"
    base = stmt.index(win)
    i = stmt.index(I18N_VALUE)
    assert base <= i, (base, i)
    assert base + len(win) >= i + len(I18N_VALUE), (base, len(win), i)
    assert base >= i - 256, (base, i)
    assert base + len(win) <= i + len(I18N_VALUE) + 256, (base, len(win), i)
    # 旧窗口（以第一个常量为锚）里**没有**目标值 —— 这正是本轮的病根
    assert FIRST in old and I18N_VALUE not in old, old
    # 值不在 raw_stmt 里（长语句、找不到独立出现）-> 逐位退回旧窗口
    absent_long = _long('t.setData({pwdErr: 1}), this.checkPwd(this.data.pwd);')
    assert I18N_VALUE not in absent_long, absent_long
    old2 = C.extract_context(absent_long, FIRST, 512)
    assert anchor(absent_long, I18N_VALUE, old2) == old2
    # 语句本身够短（<=512）-> 就是整条语句（与 extract_context 同口径）
    short = 'this.setData({pwdErr: 1}), t.checkPwd();'
    assert anchor(short, "pwdErr", short) == short


def test_fix43_anchor_removes_non_first_constant():
    """长语句里**非首常量**的 i18n 键（P1 窗口复活）/ 字符串表元素 / 成员访问 / 数组元素：被排除。"""
    for name, value, tail in EXCLUDE_CASES:
        stmt = _long(tail)
        before = _labels(_consts(value), [stmt], value, fix43_off=True)
        after = _labels(_consts(value), [stmt], value)
        assert CCP_NAME in before, "[%s] 修复前本应判 1203: %r" % (name, before)
        assert CCP_NAME not in after, "[%s] 修复后仍判 1203: %r" % (name, after)
        # 值的出现位置在旧窗口之外（= 现行口径的判定窗口里根本没有这个值）
        assert value not in C.extract_context(stmt, FIRST, 512), name


def test_fix43_excluded_values_land_at_risk_0():
    """被排除的值显式落 risk 0 出口，且**不许**掉进任何 risk>=4 桶。"""
    for name, value, tail in EXCLUDE_CASES:
        stmt = _long(tail)
        after = _labels(_consts(value), [stmt], value)
        bad = [n for n in after if (RISK.get(n) or 0) >= 4]
        assert not bad, "[%s] 掉进 risk>=4 桶: %r" % (name, bad)
        # 显式改判（不是静默消失）：本轮从 1203 移出的值仍留下**一行** risk0 记录
        assert NOISE_NAME in after, "[%s] 应显式改判 %s: %r" % (name, NOISE_NAME, after)


def test_fix43_guard_hit_in_old_window_also_lands_at_risk_0():
    """短语句（旧窗口 == 值锚窗口）：守卫在**旧窗口**上命中的值同样显式落 1207。"""
    before = _labels([(SHORT_TABLE_VALUE, 0, 0)], [SHORT_TABLE_STMT], SHORT_TABLE_VALUE,
                     fix43_off=True)
    after = _labels([(SHORT_TABLE_VALUE, 0, 0)], [SHORT_TABLE_STMT], SHORT_TABLE_VALUE)
    assert CCP_NAME in before, before
    assert CCP_NAME not in after, after
    assert after == [NOISE_NAME], after
    assert (RISK.get(NOISE_NAME) or 0) == 0, RISK.get(NOISE_NAME)


def test_fix43_snippet_unchanged():
    """入库 snippet 仍是**旧窗口**（本轮只改判定，不改落库内容）。"""
    stmt = _long(I18N_TAIL)
    old = C.extract_context(stmt, FIRST, 512)
    assert _snippet_of(_consts(I18N_VALUE), [stmt], I18N_VALUE) == old
    stmt2 = _long(FNARG_TAIL)
    old2 = C.extract_context(stmt2, FIRST, 512)
    assert _snippet_of(_consts(FNARG_VALUE), [stmt2], FNARG_VALUE) == old2


# =========================================================
# ② 红线：反向进入 1203 = 0
# =========================================================
def test_fix43_no_reverse_entry_into_1203():
    """值锚窗口判 1203、旧窗口不判的值（反向候选）**一行不动**（修复前不是 1203 就不许拉进来）。"""
    stmt = _long(REVERSE_TAIL, head=PLAIN_HEAD)
    before = _labels(_consts(REVERSE_VALUE, first=PLAIN_FIRST), [stmt], REVERSE_VALUE,
                     fix43_off=True)
    after = _labels(_consts(REVERSE_VALUE, first=PLAIN_FIRST), [stmt], REVERSE_VALUE)
    assert CCP_NAME not in before, before
    assert before == after, (before, after)
    assert CCP_NAME not in after, after
    # 值锚窗口的**语境闸门**确实是开的（这正是先行探针里 anchor-only 会把 162 个值拉进 1203
    # 的原因）；本用例钉的就是「闸门开着也不许拉进来」
    win = _hook(ANCHOR)(stmt, REVERSE_VALUE, C.extract_context(stmt, PLAIN_FIRST, 512))
    assert REVERSE_VALUE in win and "pwd" in win.lower()
    assert C.has_cloud_password_context(win, REVERSE_VALUE) is True, win


def test_fix43_baseline_helper_is_the_old_behaviour():
    """`is_cloud_password_before_fix43` = 位置守卫关断后的同一台判据（主循环记账的依据）。"""
    baseline = _hook(BASELINE)
    for name, value, tail in EXCLUDE_CASES + KEEP_CASES:
        stmt = _long(tail)
        win = C.extract_context(stmt, FIRST, 512)
        saved = C.is_cloud_password_position_noise
        C.is_cloud_password_position_noise = lambda _v, _st: False
        try:
            expect = C.is_cloud_password(value, win)
        finally:
            C.is_cloud_password_position_noise = saved
        assert baseline(value, win) == expect, name
        assert C.CCP_POSITION_GUARD_OFF is False, "关断开关必须复位"


# =========================================================
# ③ 不可排除的四类：fn_arg / compare / return / 三元键位
# =========================================================
def test_fix43_unremovable_positions_keep_1203():
    """fn_arg（含 `Utf8.parse("…")` 这类疑似真阳性）、compare、return、三元键位一律不动。"""
    for name, value, tail in KEEP_CASES:
        stmt = _long(tail)
        before = _labels(_consts(value), [stmt], value, fix43_off=True)
        after = _labels(_consts(value), [stmt], value)
        assert CCP_NAME in before, "[%s] 修复前本应判 1203: %r" % (name, before)
        assert before == after, "[%s] 判定被改动: %r -> %r" % (name, before, after)


def test_fix43_bounded_and_keyname_positions_keep_1203():
    """直接 / 后缀密码键绑定、密码名 callee 实参：三条保护逐位不变。"""
    for name, value, tail in PROTECTED_CASES:
        stmt = _long(tail)
        before = _labels(_consts(value), [stmt], value, fix43_off=True)
        after = _labels(_consts(value), [stmt], value)
        assert before == after, "[%s] 判定被改动: %r -> %r" % (name, before, after)
        assert CCP_NAME in after, "[%s] 应保持 1203: %r" % (name, after)


# =========================================================
# ④ 保护集 100%：fix31 的材料形/红线值 + fix12 红线值 + fix31c 已知残留
# =========================================================
def test_fix43_fix31c_protected_material_kept():
    """fix31c 的 10 条受保护材料（TPL = return + fn_arg 位）在 fix43 下逐位不变。"""
    for v in F31.FIX31C_PROTECTED_MATERIAL:
        stmt = F31.FIX31C_TPL % v
        before = _labels([(v, 0, 0)], [stmt], v, fix43_off=True)
        after = _labels([(v, 0, 0)], [stmt], v)
        assert before == after, (v, before, after)
        assert CCP_NAME in after, (v, after)


def test_fix43_real_corpus_1203_evidence_kept():
    """fix31c 的真语料 1203 证据（盐的拼接位 / fix12 红线值的 return 位）逐位不变。"""
    for v, stmt in F31.FIX31C_REAL_CORPUS_1203:
        before = _labels([(v, 0, 0)], [stmt], v, fix43_off=True)
        after = _labels([(v, 0, 0)], [stmt], v)
        assert before == after, (v, before, after)
        assert CCP_NAME in after, (v, after)


def test_fix43_fix12_redline_values_kept():
    """fix12 人工核定红线值 × fix31 的三种语境（键绑定 / 赋值 / 密码名 callee）：逐位不变。"""
    for v in F31.REDLINE_VALUES:
        for tmpl in F31.REDLINE_STMTS:
            stmt = tmpl % v
            before = _labels([(v, 0, 0)], [stmt], v, fix43_off=True)
            after = _labels([(v, 0, 0)], [stmt], v)
            assert before == after, (v, tmpl, before, after)
            assert CCP_NAME in after, (v, tmpl, after)


def test_fix43_fix31c_known_residual_still_pinned():
    """fix31c 钉死的 44 个混淆串残留（无绑定 + 有密码语境的 TPL）依然一条不多一条不少。"""
    still = [v for v in (F31.FIX31C_NOISE_DROPPED + F31.FIX31C_KNOWN_RESIDUAL)
             if CCP_NAME in _labels([(v, 0, 0)], [F31.FIX31C_TPL % v], v)]
    assert set(still) == set(F31.FIX31C_KNOWN_RESIDUAL), (
        sorted(set(still) - set(F31.FIX31C_KNOWN_RESIDUAL)),
        sorted(set(F31.FIX31C_KNOWN_RESIDUAL) - set(still)))


# =========================================================
# ⑤ 值不在 raw_stmt 里：行为逐位不变
# =========================================================
def test_fix43_value_absent_from_raw_stmt_unchanged():
    before = _labels([(ABSENT_VALUE, 0, 0)], [ABSENT_STMT], ABSENT_VALUE, fix43_off=True)
    after = _labels([(ABSENT_VALUE, 0, 0)], [ABSENT_STMT], ABSENT_VALUE)
    assert before == after, (before, after)
    assert _snippet_of([(ABSENT_VALUE, 0, 0)], [ABSENT_STMT], ABSENT_VALUE) == \
        C.extract_context(ABSENT_STMT, ABSENT_VALUE, 512)


# =========================================================
# ⑥ 守卫本身：只认三类位置，保护位置 / 材料形 / 红线值一律 False
# =========================================================
def test_fix43_guard_predicate_matrix():
    guard = _hook(GUARD)
    anchor = _hook(ANCHOR)
    for name, value, tail in EXCLUDE_CASES[1:]:      # B / C / E 三类
        win = anchor(_long(tail), value, "")
        assert guard(value, win) is True, (name, value)
    for name, value, tail in KEEP_CASES + PROTECTED_CASES:
        win = anchor(_long(tail), value, "")
        assert guard(value, win) is False, (name, value)
        # 值不在窗口里 -> 没有位置依据，一律 False
        blanked = win.replace(value, "x" * len(value))
        assert guard(value, blanked) is False, (name, value)
    # 材料形值坐在串表里：fix42 P3 单测钉死了必须保持 1203
    material = 't = [ "alpha", "beta", "gamma", "4829106KzWqLm", "delta", "epsilon" ]'
    assert C.is_cloud_password_material_shape("4829106KzWqLm") is True
    assert guard("4829106KzWqLm", material) is False
    # 红线值即使坐在可排除位置上也不许被排除（值白名单）
    for v in F31.REDLINE_VALUES:
        win = 'this.setData({pwdErr:1}), e = [ "alphaOne", "betaTwo", "%s" ], t.checkPwd();' % v
        assert guard(v, win) is False, v
    # CSS 选择器形态：`'.mt-input__icon` 里的那一份不是成员访问
    # （unit-tests/test_cloud_password_bem.py 钉死了该族保持 1203）
    assert guard("mt-input__icon", "pwdStyle = '.mt-input__icon{color:#fff}'") is False


def test_fix43_guard_is_after_the_three_fix31_protections():
    """顺序不变量：三条保护在前，位置守卫在后，且守卫自己也要复核三条保护。"""
    src = inspect.getsource(C.is_cloud_password_noise)
    i_guard = src.index("if %s(value, stmt):" % GUARD)
    for proto in ("_ccp_bound_to_any_key", "_ccp_keyname_position", "_ccp_password_callee_arg"):
        assert src.index(proto) < i_guard, proto
    gsrc = inspect.getsource(_hook(GUARD))
    for proto in ("_ccp_bound_to_any_key", "_ccp_keyname_position", "_ccp_password_callee_arg"):
        assert proto in gsrc, proto
    assert "return False" in gsrc
    assert "is_cloud_password_material_shape" in gsrc
    assert "CCP_POSITION_REDLINE_VALUES" in gsrc


def test_fix43_anchor_reachable_only_from_cloud_password():
    """值锚窗口只接在 1203 判定处；入库 snippet 仍走旧窗口；其余判据不受影响。"""
    src = inspect.getsource(C.perform_constant_classifying)
    assert ANCHOR in src, "值锚窗口必须接在 perform_constant_classifying 的 1203 判定处"
    assert BASELINE in src, "主循环必须先用修复前口径记账（反向进入 1203 = 0 的实现手段）"
    assert "is_cloud_password(s, _ccp_value_anchor_context(" in src, "值锚窗口必须参与 1203 判定"
    assert "process_cloud_password(s, stmt," in src, "入库 snippet 必须仍用旧窗口"
    assert GUARD in inspect.getsource(C.is_cloud_password_noise)


# =========================================================
# runner（本机 .venv 没装 pytest）
# =========================================================
def _run_standalone():
    import traceback
    cases = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in cases:
        try:
            fn()
            print("PASS %s" % name)
        except Exception:  # pylint: disable=broad-except
            failed.append(name)
            print("FAIL %s" % name)
            traceback.print_exc()
    print("=" * 60)
    print("fix43 cloud_cred_password 值锚窗口 + 位置守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
