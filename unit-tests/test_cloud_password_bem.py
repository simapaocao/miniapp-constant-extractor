#!/usr/bin/env python3
r"""BEM 类名在 cloud_cred_password(1203) 的窄口误报修复的回归验证。

问题（窄口，只此一族）：`is_segmented_identifier_name` 的值形判据
（fix12 引入，RE_IDENTIFIER_NAME_VALUE）要求分隔符是**单个** `.` / `-` / `_`：

    ^[A-Za-z]+[0-9]*(?:[.\-_][A-Za-z]+[0-9]*)+$

CSS 的 BEM 写法用**双写分隔符**（`__` 元素 / `--` 修饰符），于是这一类
「多段词形标识符」从判据里漏了出去，值自己含 pwd/password 时就能把
has_cloud_password_context 的闸门顶开（自指，同 fix12 的成因）：

    password: "mt-input__icon"                        -> cloud_cred_password(1203)
    pwdStyle = '.field__error-message{color:#f00}'    -> cloud_cred_password(1203)
    pwd: "password-component--bank-navbar"            -> cloud_cred_password(1203)

改法（**唯一改动点**）：分隔符允许**单个** `.` / `-` / `_` **或同字符双写** `__` / `--` ——
`(?:--|__|[.\-_])`；段的形状 `[A-Za-z]+[0-9]*`（要求每一段以字母开头）原样保留。
收窄的原因：证据只支持 BEM 的 `__`（元素）/ `--`（修饰符），
**混写**的连续分隔符（`..` / `.-` / `._` …）没有库内依据，不纳入。

本文件固化的边界：
  · BEM 三族（`__` / `--` / 混合）不再判 1203；
  · fix12 / fix15 / fix16 的人工核定真阳性在**值形**与**判定**上逐位不变
    （password1 / Admin123 / o0IN8wTN50QMxX-V4siq_GSRFuts / mnP7XKDCaWFjINWi …）；
  · 材料形 `MyPwd__2024`（**双写分隔符 + 纯数字段**）必须**不命中** ——
    新判据里纯数字段不以字母开头，仍落在判据外，这是本次的显式保护项；
  · 单分隔符的既有射程（auth.updatePassword / RESET_PASSWORD / eye-fill …）不动；
  · 段允许「字母 + 结尾数字」是 fix12 的既有口径，因此 `Admin123__pwd` 这类**多段**写法
    按名字处理 —— 它的单分隔符孪生写法（`Admin123-pwd`）修复前就是同样处理，本次不是
    新增损失；被点名的单段 `Admin123` 仍在 1203
    （见 test_segment_shape_rule_keeps_tail_digit_cost_pre_existing）；
  · 该判据的第二个调用点（cookie 名 + 空值）上，base64 带 `=` 填充的真值仍不许被吃。

已知残留（**不在**本次射程，各有对应断言）：
  · 含**纯数字段**的名字（`mt-input__icon-2` / `form-field__error-message-2` /
    `MyPwd__2024`）：数字段与「字母 + 尾数字」的材料形弱口令同形，收它就得交出
    `MyPwd__2024`，故不收（test_digits_only_segment_not_matched /
    test_known_residual_digit_segment_stays_1203）；
  · 连写 3 个以上的分隔符（`aa___bb`）：库内未见，不做无证据的放宽；
  · **混写**的连续分隔符（`aa..bb` / `aa.-bb` …）与属性路径 `that._onHide1`：证据只支持
    `__` / `--`，收窄后回到修复前口径（test_mixed_doubled_separators_not_admitted /
    test_attribute_path_boundary_reverted_to_baseline）；
  · 「字母 + 结尾数字」段族的**多段**写法（`Word__Word9` / `Admin123__pwd`）：fix12 的既有
    口径即为按名字处理，单分隔符孪生写法修复前已是同样结果
    （test_word_word9_residual_note）。

口径不变量（写在实现注释里，也由本文件正面断言）：新判据是旧判据的**严格超集** ——
单分隔符分支原样保留、只多出同字符双写；且命中字符串的每一段仍必须形如
`[A-Za-z]+[0-9]*`，**段的形状不变量才是真阳性保护的实际机制**（数字打头段 / 数字夹在
字母中间段一律不命中，见 test_doubled_separator_material_shapes_still_1203）。

用法: .venv/bin/python -X utf8 unit-tests/test_cloud_password_bem.py
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

CCP = IDT.CLOUD_CRED_PASSWORD
COOKIE = IDT.SERVER_CRED_COOKIE

# 修复前的值形判据（只用于对照：证明「是这个正则造成的」）。
RE_IDENTIFIER_NAME_VALUE_BEFORE = re.compile(
    r"^[A-Za-z]+[0-9]*(?:[.\-_][A-Za-z]+[0-9]*)+$")


def _classify(v, stmt, legacy_regex=False):
    """跑一遍分类；legacy_regex=True 时把值形判据换回修复前的正则，其余逐位不变。"""
    saved = C.RE_IDENTIFIER_NAME_VALUE
    if legacy_regex:
        C.RE_IDENTIFIER_NAME_VALUE = RE_IDENTIFIER_NAME_VALUE_BEFORE
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        C.RE_IDENTIFIER_NAME_VALUE = saved


# =========================================================
# ① BEM 类名（本次唯一射程）
# =========================================================
# 语句都取自「值旁边确有 pwd/password 词」的真实形态（键名位 / 赋值位 / CSS 串）。
BEM_CASES = [
    # mt-input__icon —— BEM 元素写法（双下划线）
    ("mt-input__icon", 'password: "mt-input__icon"'),
    ("mt-input__icon", "t.inputCls = pwd ? 'mt-input__icon' : 'mt-input__icon-active'"),
    ("mt-input__icon", 'orderPwdCls:"mt-input__icon"'),
    ("mt-input__icon", "pwdStyle = '.mt-input__icon{color:#fff}'"),
    # field__error-message —— 双下划线 + 单连字符混用
    ("field__error-message", 'pwd = "field__error-message"'),
    ("field__error-message", 'pwdErrMsg:"field__error-message"'),
    ("field__error-message", "pwdStyle = '.field__error-message{color:#f00}'"),
    # password-component--bank-navbar —— 双连字符修饰符
    ("password-component--bank-navbar", 'password: "password-component--bank-navbar"'),
    ("password-component--bank-navbar", 'pwd = "password-component--bank-navbar"'),
    ("password-component--bank-navbar",
     "getApp().globalData.pwdCls='password-component--bank-navbar'"),
]


def test_bem_css_class_not_cloud_cred_password():
    """三个点名 BEM 类名在 pwd/password 语境下不再判 1203。"""
    for v, stmt in BEM_CASES:
        got = _classify(v, stmt)
        assert CCP not in got, "%r -> %r  (%r)" % (v, got, stmt)


def test_bem_was_the_false_positive_before():
    """对照（诊断用，修复前也通过）：换回修复前的正则，这些值确实回到 1203。

    这一组同时就是 RED 复现：修复前 test_bem_css_class_not_cloud_cred_password 失败、
    本函数通过；修复后两者都通过。
    """
    for v, stmt in BEM_CASES:
        got = _classify(v, stmt, legacy_regex=True)
        assert CCP in got, "%r 修复前竟然不是误报: %r" % (v, got)


BEM_GUARD_HITS = [
    "mt-input__icon",
    "field__error-message",
    "password-component--bank-navbar",
    "password-component__header",
    "bank-navbar--active",
    "pwd__tips--show",
    "mt-input__icon2",          # 尾数字贴在**字母段**里，仍是词形段
    "a--b2",
]


def test_bem_guard_shape_hits():
    """值形判据本身命中 BEM 族（`__` / `--` / 混用 / 段尾数字）。"""
    for v in BEM_GUARD_HITS:
        assert C.is_segmented_identifier_name(v), v


def test_single_separator_range_unchanged():
    """单分隔符的既有射程一个不少（动的是分隔符的**形式**，不是段的形状）。"""
    for v in ("auth.updatePassword", "bathCode.prompt2", "RESET_PASSWORD", "eye-fill",
              "safe-password-time-stamp", "password-view", "enter-whitelist-password-login",
              "register-step3", "v1_step_insu_pwd", "common_icon_line_invisible1"):
        assert C.is_segmented_identifier_name(v), v


# 分隔符口径：**单个** `.` / `-` / `_`，或**同字符双写** `__` / `--`。
# 混写的连续分隔符（`..` / `.-` / `._` / `-_` / `_.` / `-.`）与连写 3 个以上都**不在**射程内
# —— 库内证据只支持 BEM 的 `__`（元素）/ `--`（修饰符），不做无证据的放宽。
SEPARATOR_ADMITTED = ["aa-bb", "aa.bb", "aa_bb", "aa--bb", "aa__bb",
                      "mt-input__icon", "field__error-message",
                      "password-component--bank-navbar"]
SEPARATOR_REJECTED = ["aa..bb", "aa.-bb", "aa._bb", "aa-_bb", "aa_.bb", "aa-.bb",
                      "aa___bb", "that._onHide1"]


def test_separator_forms_admitted():
    """单个分隔符与同字符双写（`__` / `--`）都算「多段词形标识符」。"""
    for v in SEPARATOR_ADMITTED:
        assert C.is_segmented_identifier_name(v), v


def test_mixed_doubled_separators_not_admitted():
    """混写连续分隔符 / 连写 3 个以上**不是**本判据的射程（本次收窄的证据口径）。"""
    for v in SEPARATOR_REJECTED:
        assert not C.is_segmented_identifier_name(v), v


def test_attribute_path_boundary_reverted_to_baseline():
    """边界：`that._onHide1` 是**属性路径**（`._` 混写），有意放回修复前的口径。

    证据只支持 BEM 的 `__` / `--`；`._` 这种混写没有库内依据，故不收。
    这里断的是「与修复前（单分隔符正则）判定逐位相同」= 回到基线。
    已知残留：值形判据够不到它，在 pwd/password 语境下仍判 1203。
    """
    v = "that._onHide1"
    stmt = 'password: "%s"' % v
    assert not C.is_segmented_identifier_name(v), v
    assert _classify(v, stmt) == _classify(v, stmt, legacy_regex=True) == [CCP], v


def test_word_word9_residual_note():
    """显式残留：`Word__Word9` 属「字母 + 结尾数字」段族，判据命中 -> 按名字处理。

    这是 fix12 的既有口径（段允许结尾数字），它的**单分隔符孪生**写法
    `Word-Word9` 修复前就是这个结果，故不是本次收窄新增的损失；
    收窄前后 `Word__Word9` 的行为也不变。真材料形（数字夹在字母中间/数字打头段）
    仍被段的形状不变量挡住，见 test_doubled_separator_material_shapes_still_1203。
    """
    for v, twin in (("Word__Word9", "Word-Word9"), ("Admin123__pwd", "Admin123-pwd")):
        assert C.is_segmented_identifier_name(v), v
        assert C.is_segmented_identifier_name(twin), twin
        assert _classify(v, 'password: "%s"' % v) == [], v
        assert _classify(twin, 'password: "%s"' % twin, legacy_regex=True) == [], twin


# =========================================================
# ② 真阳性保护（fix12 / fix15 / fix16 的反例矩阵）
# =========================================================
CCP_TP = ["password1", "Admin123", "o0IN8wTN50QMxX-V4siq_GSRFuts", "MyPwd__2024",
          "password123", "admin123", "err3241", "emoney5", "mnP7XKDCaWFjINWi",
          "signBoardPassword_S8hY", "pste7JpTWOulCpvf", "video123", "ytx123456",
          "HFG9K23FDHJ09Zm", "Suning@12345", "i38ku3M03iiMTNHPGl9By5TTE3lGMfa5",
          "280c5e0e7dcfbe3e1de718429cf91190fa80ac8d",
          "6BF477EBCC446F54E6512AFC0E976C41",
          "o0IN8wTN50QMxX-V4siq_GSRFuts".lower(), "Zmn666666"]


def test_guard_matrix_no_true_positive_loss():
    """反例矩阵在值形判据上逐位不变（这是 fix12 留下的红线）。"""
    for v in CCP_TP:
        assert not C.is_segmented_identifier_name(v), "值形误吃真阳性: %r" % v
        assert not C.is_single_segment_identifier_name(v), "值形误吃真阳性: %r" % v


def test_named_positive_samples_keep_1203():
    """点名样本在 password 语境下**照旧**判 1203（修复前后一致）。"""
    for v in ("password1", "Admin123", "o0IN8wTN50QMxX-V4siq_GSRFuts", "MyPwd__2024"):
        got = _classify(v, 'password: "%s"' % v)
        assert got == [CCP], "%r -> %r" % (v, got)
        # 对照：修复前的正则下同样是 [CCP]（本次没有碰到它们）
        assert _classify(v, 'password: "%s"' % v, legacy_regex=True) == [CCP], v


def test_digits_only_segment_not_matched():
    """显式保护：**双写分隔符 + 纯数字段**（`MyPwd__2024`）不是「词形标识符」。

    判据要求每段以字母开头，纯数字段（2024 / 123456）不在射程内 ——
    放宽成「段可以是数字」会吃掉这一族材料形弱口令。

    这一条同时定义了本次射程的**已知残留**（都保持修复前行为）：
      · 纯数字段：`MyPwd__2024` / `bank-card__2024` / `mt-input__icon-2` /
        `form-field__error-message-2` / `pwd--input-1`（数字段与「材料形弱口令」
        同形，收它就得交出 MyPwd__2024，本次不收）；
      · 分隔符连写 3 个及以上：`a___b`（库内未见，不做无证据的放宽）。
    """
    for v in ("MyPwd__2024", "field__2024", "bank-card__2024", "login__123456",
              "admin__8888", "pwd__2024", "MyPwd--2024",
              "mt-input__icon-2", "form-field__error-message-2", "pwd--input-1",
              "a___b"):
        assert not C.is_segmented_identifier_name(v), v


def test_doubled_separator_material_shapes_still_1203():
    """放宽的**只是分隔符的重复次数**：段的形状不变量仍挡着材料。

    被挡住的是「段以数字开头」或「数字夹在段中间」这两族（随机材料/哈希/UUID 的形状）：
    双写分隔符不会让它们变得可命中 —— 在 password 语境下照旧判 1203。
    """
    for v in ("o0IN8wTN50QMxX--V4siq", "mnP7XKDCaWFjINWi__x", "pste7JpTWOulCpvf__x",
              "3708d2bc--bc52-45a3", "1Passw0rd__xyz", "2fa__pwd", "MyPwd__2024"):
        assert not C.is_segmented_identifier_name(v), "值形误吃材料: %r" % v
        got = _classify(v, 'password: "%s"' % v)
        assert got == [CCP], "%r -> %r" % (v, got)


def test_segment_shape_rule_keeps_tail_digit_cost_pre_existing():
    """口径说明：段允许「字母 + 结尾数字」，所以 `Admin123__pwd` 这类会被当名字丢掉 ——
    这与它的单分隔符孪生写法**修复前就已经**是这样（不是本次新增的损失）。

    `Admin123`（单段）是 fix12 的点名真阳性、必须留在 1203；一旦它成为多段名的一部分，
    判据自 fix12 起就按名字处理 —— 本次只是把同一条规则覆盖到 `__` / `--` 写法。
    """
    for v in ("Admin123-pwd", "Admin123.pwd", "Admin123_pwd"):
        assert C.is_segmented_identifier_name(v), v
        assert _classify(v, 'password: "%s"' % v, legacy_regex=True) == [], v
    # 双写孪生：行为与上面一致（同一条规则的同一代价）
    assert C.is_segmented_identifier_name("Admin123__pwd")
    assert _classify("Admin123__pwd", 'password: "Admin123__pwd"') == []
    # 而被点名的单段真阳性仍在 1203 —— 两者不冲突
    assert _classify("Admin123", 'password: "Admin123"') == [CCP]


def test_known_residual_digit_segment_stays_1203():
    """已知残留的行为断言：纯数字段在 password 语境下**照旧**判 1203（未收）。"""
    for v in ("MyPwd__2024", "login__123456", "pwd__2024",
              "mt-input__icon-2", "form-field__error-message-2", "pwd--input-1"):
        got = _classify(v, 'password: "%s"' % v)
        assert got == [CCP], "%r -> %r" % (v, got)


# =========================================================
# ③ 射程之外逐位不变
# =========================================================
# （值, 语句）对：修复前的正则与修复后的正则必须给出**完全相同**的判定。
UNCHANGED_CASES = [
    ("auth.updatePassword", 'password: "auth.updatePassword"'),
    ("RESET_PASSWORD", 'password: "RESET_PASSWORD"'),
    ("eye-fill", 'pwd: "eye-fill"'),
    ("safe-password-time-stamp", 'password: "safe-password-time-stamp"'),
    ("register-step3", 'pwd: "register-step3"'),
    ("1Passw0rd!xyz", 'password: "1Passw0rd!xyz"'),
    ("password1", 'password: "password1"'),
    ("Admin123", 'password: "Admin123"'),
    ("o0IN8wTN50QMxX-V4siq_GSRFuts",
     'signup: { password: "o0IN8wTN50QMxX-V4siq_GSRFuts" }'),
    ("3708d2bc-bc52-45a3-8f49-08c62f55f5b3",
     'id: "3708d2bc-bc52-45a3-8f49-08c62f55f5b3"'),
    ("MyPage_6", 'password: "MyPage_6"'),
    ("LmF3LWNvb2tpZS1iYW5uZXI=",
     'Cookie: "session=" + "LmF3LWNvb2tpZS1iYW5uZXI="'),
    ("aXNsYW1pYy1zaWQ=", 'cookie: "sid=" + "aXNsYW1pYy1zaWQ="'),
    ("JSESSIONID=", 'cookie: "JSESSIONID=" + getApp().globalData.sessionId'),
    ("JSESSIONID=abcd1234efg", 'cookie: "JSESSIONID=abcd1234efg"'),
    ("===success", 'password: "===success"'),
    ("#tips_popup", 'pwd: "#tips_popup"'),
    (".page-recharge-wallet-list-balance",
     'password: ".page-recharge-wallet-list-balance"'),
]


def test_out_of_scope_verdicts_identical():
    """射程外的 (值, 语句) 在新旧正则下判定逐位相同。"""
    for v, stmt in UNCHANGED_CASES:
        new = _classify(v, stmt)
        old = _classify(v, stmt, legacy_regex=True)
        assert new == old, "%r: new=%r old=%r  (%r)" % (v, new, old, stmt)


def test_cookie_name_guard_not_widened_for_base64():
    """该判据的第二个调用点（cookie 名 + 空值）不许因此吃到 base64 填充的真值。

    这两个值本身是**桶里的真 cookie 值**（fix16 点名的红线），修复前后都该判 1604：
    要挡的是「被当成 cookie 名挖空」，所以断的是 `_is_cookie_name_without_value`
    为 False，且判定与修复前逐位相同。
    """
    for v in ("LmF3LWNvb2tpZS1iYW5uZXI=", "aXNsYW1pYy1zaWQ="):
        assert not C._is_cookie_name_without_value(v, C.SERVER_COOKIE_NAME_KEYWORDS), v
        stmt = 'cookie: "session=" + "%s"' % v
        assert _classify(v, stmt) == _classify(v, stmt, legacy_regex=True), v
        assert COOKIE in _classify(v, stmt), v
    # `名=<非空值>` 的真 cookie 一律不动
    assert not C._is_cookie_name_without_value("JSESSIONID=abcd1234efg",
                                               C.SERVER_COOKIE_NAME_KEYWORDS)
    # 表内名字 + 空值的既有射程不变
    assert C._is_cookie_name_without_value("JSESSIONID=", C.SERVER_COOKIE_NAME_KEYWORDS)


def _run_standalone():
    """本机 .venv 没有 pytest，所以自带 runner：断言全是纯 assert，两种跑法一致。"""
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
    print("BEM 类名 1203 误报修复验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
