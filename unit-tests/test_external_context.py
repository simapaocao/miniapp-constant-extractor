"""剥值（外部证据）：external_context / has_user_id_context / has_cloud_password_context。

背景
----
语境判据 `has_keyword_*(stmt, ...)` 的 stmt 是值周围的 512 字符窗口，**里面含值本身**：

    值 = auth.updatePassword -> stmt 必含 "updatePassword" -> 命中 "password" -> 通过

值自己给自己开闸。全仓原先只有 has_iv_context 用 `stmt.replace(value, "")` 处理过。

但「全删」会连**键名位置**的出现一起删掉：

    H5PayTradeNo: "H5PayTradeNo"   ->  ': ""'   自赋值常量证据没了
    password:     "password"       ->  ': ""'   真弱口令会因此消失

本文件把决定 1 的规则固化成断言：**值位置的出现删掉，键名位置（后面跳过引号/空白
紧跟 `:`）的出现保留**，并逐条覆盖：

  1) 决定 1 表格的 4 种情形；
  2) 值不在语句里 = 空操作；
  3) 值出现多次（一次键名 + 一次值）；
  4) 空串 / 极短值 / 畸形值不崩；
  5) 值恰好是语句的前缀 / 后缀；
  6) 带引号的键、键与冒号之间有空白；
  7) **位置 0 的键名**（RE 的 `^` 在带 pos 的 match 上不匹配 pos，第一版就踩了这个坑）；
  8) 判据层：自赋值仍检出、值自指不再单独开闸；
  9) 硬约束：同语句多常量**共用窗口、逐个剥值** —— 缓存点不能被预先剥掉（用返回值里的
     source_snippet 观测，它就是缓存窗口本身）。

用法: .venv/bin/python -X utf8 unit-tests/test_external_context.py
（本机 .venv 没装 pytest，断言全是纯 assert，两种跑法一致。）
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import constants_classifier as C  # noqa: E402


# ================= 1. 决定 1 表格的 4 种情形 =================
def test_self_assignment_keeps_key_name_evidence():
    """H5PayTradeNo: "H5PayTradeNo" -> H5PayTradeNo: ""（键名保留 = 行为不变）。"""
    assert C.external_context('H5PayTradeNo: "H5PayTradeNo"', "H5PayTradeNo") \
        == 'H5PayTradeNo: ""'


def test_weak_password_self_assignment_still_yields_context():
    """password: "password" -> password: ""，且判据仍然通过（真弱口令不能消失）。"""
    assert C.external_context('password: "password"', "password") == 'password: ""'
    assert C.has_cloud_password_context('password: "password"', "password") is True


def test_array_element_value_passes_no_evidence():
    """["auth.updatePassword"] -> [""]：值自己不再是证据。"""
    assert C.external_context('["auth.updatePassword"]', "auth.updatePassword") == '[""]'
    assert C.has_cloud_password_context('["auth.updatePassword"]',
                                        "auth.updatePassword") is False


def test_key_name_list_value_passes_no_evidence():
    """signHeaderKeys:["x-expire-timestamp"] -> signHeaderKeys:[""]。"""
    stmt = 'signHeaderKeys:["x-expire-timestamp"]'
    assert C.external_context(stmt, "x-expire-timestamp") == 'signHeaderKeys:[""]'


# ================= 2. 值不在语句里 =================
def test_value_absent_is_noop():
    stmt = 'var a = "somethingElse"; pwd: x;'
    assert C.external_context(stmt, "notInThere") == stmt        # 完全不在
    assert C.external_context(stmt, "SomethingElse") == stmt     # 大小写不同 = 不在
    assert C.external_context(stmt, "somethingElseX") == stmt    # 比语句里的那段长


def test_matching_is_substring_based_not_token_based():
    """**已知口径**：出现按「子串」匹配（与 str.replace 一致），不是整 token。

    于是「值恰好是别的单词的子串」时会把那个单词削掉。对这两条判据的实害有限：
    is_cloud_password / is_identifier 都有长度下限（>=6 / >=8），短值不会走到这里；
    UUID 分支（>=36 字符）更不可能撞上。这里把行为写死，避免日后被误当 bug 修掉。
    """
    assert C.external_context('var a = "somethingElse";', "something") == 'var a = "Else";'
    assert C.external_context('var a = "pwd";', "pw") == 'var a = "d";'


# ================= 3. 值出现多次 =================
def test_value_twice_key_then_value():
    """一次键名 + 一次值：只删值位置那一次。"""
    assert C.external_context('{"password":"password"}', "password") == '{"password":""}'
    assert C.external_context("{'pwd':'pwd'}", "pwd") == "{'pwd':''}"
    assert C.external_context('password: "pwd", pwd: "password"',
                              "password") == 'password: "pwd", pwd: ""'


def test_value_three_occurrences_two_keys_one_value():
    """三次出现：两次键名（一个裸键、一个带引号键）+ 一次值。"""
    stmt = '{ pwd: "x", "pwd": "pwd" }'
    assert C.external_context(stmt, "pwd") == '{ pwd: "x", "pwd": "" }'


def test_value_only_as_values_is_fully_removed():
    """全部都是值位置 -> 全删（这是 fix 的目标形态）。"""
    stmt = 'send("auth.updatePassword"), send("auth.updatePassword")'
    assert C.external_context(stmt, "auth.updatePassword") == 'send(""), send("")'


# ================= 4. 空串 / 极短值 =================
def test_empty_and_degenerate_values_do_not_crash():
    stmt = 'pwd: "x"; length: 1;'
    assert C.external_context(stmt, "") == stmt          # 空值 = 空操作（且不死循环）
    assert C.external_context("", "pwd") == ""           # 空语句
    assert C.external_context("", "") == ""
    assert C.external_context(stmt, "x") == 'pwd: ""; length: 1;'   # 单字符值
    assert C.external_context(":", ":") == ""            # 值就是冒号：它是语句本身
    assert C.external_context(":::", ":") == "::"        # 值 = 冒号：只有末次出现被删
    assert C.external_context('a:"a"', "a") == 'a:""'     # 极短值 + 键名
    # 单字符值出现在键名位置也要保留
    assert C.external_context("x: 1", "x") == "x: 1"


def test_value_equal_to_whole_statement():
    assert C.external_context("pwd", "pwd") == ""
    assert C.external_context("pwd:", "pwd:") == ""       # 值以冒号结尾也不崩


# ================= 5. 边界：值 = 前缀 / 后缀 =================
def test_value_as_statement_prefix():
    assert C.external_context("password: 123456", "password") == "password: 123456"
    assert C.external_context("password=123456", "password") == "=123456"


def test_value_as_statement_suffix():
    assert C.external_context('token: "pwd"', "pwd") == 'token: ""'
    assert C.external_context("obj.pwd", "pwd") == "obj."


# ================= 6. 引号 / 空白形态的键 =================
def test_quoted_and_spaced_key_forms_are_recognized():
    assert C.external_context('"pwd": "pwd"', "pwd") == '"pwd": ""'
    assert C.external_context("'pwd': 'pwd'", "pwd") == "'pwd': ''"
    assert C.external_context('pwd : "pwd"', "pwd") == 'pwd : ""'
    assert C.external_context('pwd\t: "pwd"', "pwd") == 'pwd\t: ""'


def test_value_followed_by_quote_but_not_colon_is_removed():
    """`"pwd" ===` / `["pwd"]` 不是键名位置。"""
    assert C.external_context('if ("pwd" === a)', "pwd") == 'if ("" === a)'
    assert C.external_context("['pwd']", "pwd") == "['']"
    # `pwd:` 后跟的是换行再冒号（跨行）不算键名（刻意的收紧）
    assert C.external_context('x = "pwd"\n: 1', "pwd") == 'x = ""\n: 1'


# ================= 7. 位置 0 的键名（^ + pos 的坑） =================
def test_key_name_at_position_zero_and_later():
    """RE_KEYNAME_TAIL 不能带 `^`：`RE.match(stmt, pos)` 的 `^` 只认字符串开头。"""
    assert C.external_context('pwd: "pwd"', "pwd") == 'pwd: ""'   # 位置 0 的键名
    assert C.external_context('a: 1, pwd: "pwd"', "pwd") == 'a: 1, pwd: ""'  # 非 0 位置
    assert C.external_context("pwd: x, pwd: y", "pwd") == "pwd: x, pwd: y"


# ================= 8. 判据层 =================
def test_cloud_password_context_sees_only_external_text():
    assert C.has_cloud_password_context('"auth.updatePassword"',
                                        "auth.updatePassword") is False
    assert C.has_cloud_password_context('auth.resetPasswordWithToken',
                                        "auth.resetPasswordWithToken") is False
    # 键名/别处仍在 -> 通过（值取 3 字符是为了避开「值恰是键名词子串」的削词，见上一节）
    assert C.has_cloud_password_context('newPassword: rrr, token: n', "rrr") is True
    assert C.has_cloud_password_context('password: "o0IN8wTN50QMxX"',
                                        "o0IN8wTN50QMxX") is True


def test_user_id_context_sees_only_external_text():
    assert C.has_user_id_context('["unionId"]', "unionId") is False
    assert C.has_user_id_context('"openid"', "openid") is False
    assert C.has_user_id_context('adminUnionId: c.isProd ? "A" : "B"', "B") is True
    assert C.has_user_id_context('unionId: "unionId"', "unionId") is True


def test_value_parameter_is_required():
    """value 刻意无默认值：漏改调用点要 TypeError，而不是静默退回旧行为。"""
    try:
        C.has_user_id_context("uid: 1")
    except TypeError:
        pass
    else:
        raise AssertionError("has_user_id_context 应当要求 value 参数")
    try:
        C.has_cloud_password_context("pwd: 1")
    except TypeError:
        pass
    else:
        raise AssertionError("has_cloud_password_context 应当要求 value 参数")


# ================= 9. 硬约束：共用窗口 + 逐个剥值 =================
def test_shared_window_is_not_pre_stripped():
    """同一条语句的多个常量共用同一个 512 窗口，剥值必须在**取缓存之后**逐个进行。

    观测点：perform_constant_classifying 返回的第 4 个元素就是缓存窗口本身
    （source_snippet）。若剥值写在缓存点，这里拿到的会是被第一个常量的值剥过的文本。

    fix21 ④ 口径变更（留痕）：第三个常量 `signHeaderKeys` 现在不再产出 —— 它是驼峰命名的
    键名，原先仅因**窗口里** `H5PayTradeNo` 含 `tradeno` 子串才被判 id_order_identifier，
    正是本轮给 order 分支补命名模式排除时要收掉的误报。窗口共享这一条不受影响：
    剩下两条（`H5PayTradeNo`→2504、`AMAP_ORDER_OVER_TIME`→1401）仍必须各出一条，
    且返回的 snippet 必须等于整条语句；若剥值被提到缓存点，`H5PayTradeNo` 那条会消失、
    snippet 也会是剥过的文本，断言照样会红。
    """
    stmt = ('var a = "H5PayTradeNo"; '
            'var b = "AMAP_ORDER_OVER_TIME"; '
            'var c = "signHeaderKeys";')
    constants = [("H5PayTradeNo", 0, "f.js"),
                 ("AMAP_ORDER_OVER_TIME", 0, "f.js"),
                 ("signHeaderKeys", 0, "f.js")]
    results = C.perform_constant_classifying([stmt], constants)
    assert len(results) == 2, results
    for _slug, _content, _src, snippet in results:
        assert snippet == stmt, "共享窗口被预先剥值了: %r" % (snippet,)


def _run_standalone():
    """本机没装 pytest（.venv 里只有 esprima/PyMySQL），所以自带一个 runner：
    断言全是纯 assert，不依赖 pytest API，两种跑法结果一致。"""
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
    print("剥值（外部证据）验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
