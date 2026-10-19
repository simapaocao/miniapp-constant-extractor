#!/usr/bin/env python3
"""fix16 两处 risk 5 误报的回归验证：① 路径式 password 语境、② cookie 名 + 空值（放宽）。

① cloud_cred_password：`has_cloud_password_context` 的长词走裸子串匹配，于是**页面路径**
   里的 password 段也算密码语境：

       o.disabled=!1,e.index.__f__("log","at pages/login/passwordLogin.vue:484","err3241",t)
       -> 值 err3241（日志 tag）被判 cloud_cred_password(1203, risk5)

   改法：新增 strip_path_password_context —— 只把「被 `/` 夹住」或「落在含 `/` 的引号串里」
   的 password 词挖成空白，**键名/赋值位置（`password:` / `password=`）一律不动**。
   三库实测（test-result/fix16/c_ccp_before_after.py）：语境闸门 T->F 343 对，
   不再落 1203 的 57 个 data_item / 49 值 / 158 次出现，去向全部是路径噪音
   （页面路径 / URL 片段 / chunk 名 / 图片名 / 日志 tag）；fix12 人工核定的 29 个
   在库真阳性**误伤 0**。刻意没有用「值形」去收「字母+尾数字」族（那是 fix12 的红线）。

② server_cred_cookie：fix15 的「cookie 名 + 空值」只认 SERVER_COOKIE_NAME_KEYWORDS 里
   列出的名字，`auth_token=` / `temp_token_auth=` / `ASP.NET_SessionId=` 全在表外。
   改法：名字在表里 **或**（名字含 COOKIE_NAME_WORDS 的 cookie 类词 **且** 是词形标识符）。
   ⚠️ 形态那一半是**红线保护**：`=` 右侧为空并不等于名字 —— base64 的 `=` 填充同形，
   `LmF3LWNvb2tpZS1iYW5uZXI=` 就是桶里的真值（3 个库都有）。本文件用对照组
   （test_shape_guard_is_what_protects_base64）证明「任何 `名=` 空值」确实会吞掉它。

本文件固化的边界（重点仍是**不许命中**的那些）：
  · fix12 的反例矩阵（password1 / password123 / Admin123 / err3241 / emoney5 /
    mnP7XKDCaWFjINWi / o0IN8wTN50QMxX-V4siq_GSRFuts / signBoardPassword_S8hY …）在
    **值形**判据上逐位不变，在**非路径**语境下仍判 1203；
  · `name=<真值>` 形态的真 cookie 一律不动；
  · base64 带 `=` 填充的值一律不动；
  · 名字既不在表里、也不含 cookie 类词的值（`utm_source=`）不动。

标注「实测」的期望值均由 test-result/fix16/ 下的探针对着真分类器跑出来。

用法: .venv/bin/python -X utf8 unit-tests/test_risk5_path_ctx_cookie_name.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

CCP = IDT.CLOUD_CRED_PASSWORD
COOKIE = IDT.SERVER_CRED_COOKIE
OTHER = IDT.OTHER


def _classify(v, stmt, path_rule_off=False, cookie_rule_off=False, naive_cookie=False,
              url_rule_off=False, fix31_off=False):
    """跑一遍分类；各 Off 开关都只关掉一条判据，其余逐位不变。"""
    saved = []
    if path_rule_off:
        saved.append(("strip_path_password_context", C.strip_path_password_context))
        C.strip_path_password_context = lambda s: s
    if url_rule_off:
        saved.append(("is_url_query_or_css_fragment", C.is_url_query_or_css_fragment))
        C.is_url_query_or_css_fragment = lambda s: False
    if fix31_off:
        # fix31 的 1203 三族结构守卫（`&password=` 这种「URL 片段值形」在 fix16 之后
        # 又被它拦了一道）—— 要看到 fix16 之前/之后的落点就得连它一起关掉。
        saved.append(("is_cloud_password_noise", C.is_cloud_password_noise))
        C.is_cloud_password_noise = lambda s, st_: False
    if cookie_rule_off:
        saved.append(("_is_cookie_name_without_value", C._is_cookie_name_without_value))
        C._is_cookie_name_without_value = lambda s, k: False
    if naive_cookie:
        # 对照组：「任何 名= 空值」—— fix15 点名不许用的写法
        saved.append(("_is_cookie_name_without_value", C._is_cookie_name_without_value))
        C._is_cookie_name_without_value = lambda s, k: bool(C.RE_COOKIE_NAME_NO_VALUE.match(s))
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


# =========================================================
# ① 路径式 password 语境
# =========================================================
ERR3241_STMT = ('o.disabled=!1,e.index.__f__("log","at pages/login/passwordLogin.vue:484",'
                '"err3241",t),t.result.data,423!=t.result.status?t.result.data.isBack'
                '&&setTimeout(()=>o.onNavigateBack(1),2e3):o.dongJieShow=!0')


def test_path_password_log_tag_dropped():
    """真实的 err3241 语句（normsib 53 次）：页面路径里的 password 不再是语境。"""
    assert _classify("err3241", ERR3241_STMT) == []


def test_path_rule_is_the_change():
    """对照：只关掉 strip_path_password_context，err3241 立刻回到 1203。"""
    assert _classify("err3241", ERR3241_STMT, path_rule_off=True) == [CCP]


def test_path_password_matrix_dropped():
    """路径式语句的其他真实头部值（三库翻转清单里的原型）。"""
    cases = [
        ("auth_data.auth_set_info.0.auth_type",
         '3 === (0, n.getValue)(a, "auth_data.auth_set_info.0.auth_type") && '
         '(c = "/subPackages/AuthSupport/pages/MemberAuth/password/index"), '
         '(0, n.navigateTo)({ url: "".concat(c, "?") });'),
        ("marketingAgree1",
         'r=["deviceInfo","encrypt","login_name","ajax","test","apply",'
         '"/paicc-core-web/webapi/resetPwdH5View.do","includes","length","code",'
         '"marketingAgree","login"];'),
        ("chunk_50", '__wxCodeSpace__.initializeCodeChunk("chunk_50",["pages/login/password"]);'),
        ("wxRegister2",
         '"pages":["certification/userCert","login","updatePassword/updatePassword",'
         '"wxRegister","wxRegister2","set/about"];'),
    ]
    for v, stmt in cases:
        assert CCP not in _classify(v, stmt), "%r -> %r" % (v, _classify(v, stmt))


def test_grant_type_password_in_url_is_not_context():
    """URL 里的 `grant_type=password`（OAuth grant 名）不再是密码语境。

    值本身由 fix13 的 URL 查询片段拦截丢掉；fix31 的 1203 三族守卫又补了一层
    （`&password=` 是「值形即 URL 片段」那一族）。所以这里要按开关顺序看落点：
    都不关 -> 丢；关掉 URL 拦截 -> other；再关掉 fix31 -> 回到 cloud_cred_password(5)。
    """
    stmt = ("var u = e.default.host + '/oauth/token?grant_type=password&username='"
            " + a + '&password=' + d;")
    assert _classify("&password=", stmt) == []
    assert _classify("&password=", stmt, url_rule_off=True) == [OTHER]
    assert _classify("&password=", stmt, url_rule_off=True, path_rule_off=True) == [OTHER]
    assert _classify("&password=", stmt, url_rule_off=True, path_rule_off=True,
                     fix31_off=True) == [CCP]


def test_assign_and_keyname_forms_still_context():
    """赋值/键名位置必须**照旧**开闸（`f.password = "plat168+."` 这类真口令场景）。"""
    for stmt, v in (
        ('f.password = "plat168+."', "plat168+."),
        ('password: "Admin123"', "Admin123"),
        ('newPassword: "mnP7XKDCaWFjINWi"', "mnP7XKDCaWFjINWi"),
        ('pwd: "pste7JpTWOoulCpvf"', "pste7JpTWOoulCpvf"),
        ('{"password":"Zmn666666","url":"/a/b"}', "Zmn666666"),
        ('signup: { password: "o0IN8wTN50QMxX-V4siq_GSRFuts" }', "o0IN8wTN50QMxX-V4siq_GSRFuts"),
        ('mysql://root:x@h/db?password=s3cret', "s3cret"),
        ('if(x.password&&u=="a/b")', "Suning@12345"),
    ):
        assert _classify(v, stmt) == [CCP], "%r -> %r" % (stmt, _classify(v, stmt))


def test_strip_helper_keeps_offsets_and_nonpath_text():
    """strip_path_password_context 是**等长**挖空，只动路径位置。"""
    src = 'url:"/pages/setPassword/x" + password + "y"'
    out = C.strip_path_password_context(src)
    assert len(out) == len(src), (out, src)
    assert "Password" not in out                      # 路径段被挖
    assert out.endswith('+ password + "y"'), out      # 非路径处不动
    # 赋值位置不挖
    assert C.strip_path_password_context('f.password = "x"') == 'f.password = "x"'
    assert C.strip_path_password_context('password:"x"') == 'password:"x"'
    # `==` 是比较不是赋值，但它不在路径上，也不该被碰
    assert C.strip_path_password_context('a.password==b') == 'a.password==b'
    # 空语句 / 无命中：原样返回（且一定是 str）
    assert C.strip_path_password_context("") == ""
    assert C.strip_path_password_context("var a = 1;") == "var a = 1;"


def test_fix12_counterexample_matrix_value_shape_unchanged():
    """①只动语境侧：fix12 值形红线（与 fix15 的反例矩阵同一份清单）逐位不变。"""
    for v in ("password1", "password123", "admin123", "Admin123", "err3241", "emoney5",
              "passwordTips3", "mnP7XKDCaWFjINWi", "o0IN8wTN50QMxX-V4siq_GSRFuts",
              "signBoardPassword_S8hY", "video123", "ytx123456", "HFG9K23FDHJ09Zm"):
        assert not C.is_single_segment_identifier_name(v), "值形误吃真阳性: %r" % v
        assert not C.is_segmented_identifier_name(v), "值形误吃真阳性: %r" % v


def test_fix12_counterexample_still_ccp_under_nonpath_context():
    """同一批值在**非路径**的密码语境下仍判 1203（①没有拿值形去收它们）。"""
    for v in ("err3241", "emoney5", "Admin123", "mnP7XKDCaWFjINWi",
              "o0IN8wTN50QMxX-V4siq_GSRFuts", "signBoardPassword_S8hY"):
        got = _classify(v, 'password: "%s"' % v)
        assert got == [CCP], "%r -> %r" % (v, got)


# =========================================================
# ② cookie 名 + 空值（放宽到「含 cookie 类词 + 词形标识符」）
# =========================================================
COOKIE_CASES = [
    ("temp_token_auth=",
     'Cookie: o ? "token_auth=" + wx.getStorageSync("token_auth") '
     ': "temp_token_auth=" + getApp().globalData.token'),
    ("ASP.NET_SessionId=", '"Cookie": "ASP.NET_SessionId=" + wx.getStorageSync("sessionId")'),
    ("bujiang_session_id=",
     'cookie: "bujiang_session_id=".concat(v, "; Max-Age=2592000; Expires=Mon")'),
    ("login_token=", 'e.header.Cookie="login_token=".concat(r)'),
    ("auth_token=", 'Cookie: "auth_token=" + cookieStorage.auth_token'),
    ("fsidCount=",
     'reason: "fsidCount=".concat(e.fsids.length, ",hasSessionId=").concat(Boolean(e.session_id))'),
]


def test_cookie_name_words_hits():
    """②的射程：名字含 cookie 类词 + 右侧为空 -> 是名字不是 cookie 值。"""
    for v, stmt in COOKIE_CASES:
        assert C._is_cookie_name_without_value(v, C.SERVER_COOKIE_NAME_KEYWORDS), v
        assert COOKIE not in _classify(v, stmt), "%r -> %r" % (v, _classify(v, stmt))


def test_cookie_name_widen_is_the_change():
    """对照：只关掉这条判据，它们全部回到 1604。"""
    for v, stmt in COOKIE_CASES:
        assert _classify(v, stmt, cookie_rule_off=True) == [COOKIE], v


def test_cookie_name_helper_boundaries():
    """名字判定本身：表内 / 含词 + 词形 / 含词但非词形 / 不含词。"""
    K = C.SERVER_COOKIE_NAME_KEYWORDS
    assert C._is_cookie_name_without_value("JSESSIONID=", K)          # 表内
    assert C._is_cookie_name_without_value("token_auth=", K)          # 含词 + 词形
    assert C._is_cookie_name_without_value("wolfking.jeeplus.session.id=", K)
    assert C._is_cookie_name_without_value("mytoken=", K)             # 单段 + 含词
    assert not C._is_cookie_name_without_value("utm_source=", K)      # 不含 cookie 类词
    assert not C._is_cookie_name_without_value("banner=", K)
    assert not C._is_cookie_name_without_value("LmF3LWNvb2tpZS1iYW5uZXI=", K)   # 非词形
    assert not C._is_cookie_name_without_value("aXNsYW1pYy1zaWQ=", K)           # 含 sid 但非词形
    # 右侧非空：本判据一律不碰（真 cookie 值）
    assert not C._is_cookie_name_without_value("auth_token=abcd1234", K)
    assert not C._is_cookie_name_without_value("JSESSIONID=abcd1234efg", K)


def test_shape_guard_is_what_protects_base64():
    """对照组：「任何 `名=` 空值」（不带形态判据）确实会吞掉 base64 填充真值。

    这正是 fix15 立下的红线，也是本判据必须保留 is_segmented/ is_single_segment
    形态判据的原因 —— 先证明红线断言有效，再证明当前实现没踩。
    """
    base64_val = "LmF3LWNvb2tpZS1iYW5uZXI="
    stmt = ('easyListCookie: [ ".ezmob-footer", ".cc-CookieWarning", '
            't("LmF3LWNvb2tpZS1iYW5uZXI="), ".sygnal24-gdpr-modal-wrap" ]')
    assert _classify(base64_val, stmt) == [COOKIE]                       # 当前实现：不动
    assert _classify(base64_val, stmt, naive_cookie=True) != [COOKIE]    # 对照组：吞掉


def test_base64_padding_values_untouched():
    """②的红线：base64 带 `=` 填充的真值（3 个库都有的真实值）保持 1604。"""
    cases = [
        ("LmF3LWNvb2tpZS1iYW5uZXI=",
         'easyListCookie: [ ".ezmob-footer", ".cc-CookieWarning", '
         't("LmF3LWNvb2tpZS1iYW5uZXI="), ".sygnal24-gdpr-modal-wrap" ]'),
        ("sha1-TnBUPfjEPAxVbAWJjPPUOSdC4Lo=",
         'dependencies/@base/cookie/integrity: "sha1-TnBUPfjEPAxVbAWJjPPUOSdC4Lo="'),
    ]
    for v, stmt in cases:
        got = _classify(v, stmt)
        assert got == [COOKIE], "%r -> %r" % (v, got)
        assert not C._is_cookie_name_without_value(v, C.SERVER_COOKIE_NAME_KEYWORDS), v


def test_real_cookie_values_untouched():
    """②的红线：`name=<真值>` 形态的真 cookie 一律不动。"""
    for v in ("JSESSIONID=abcd1234efg", "auth_token=abcd1234efg", "laravel_session=abc123xyz",
              "curl_cookie=abc123xyz", "sessionKey=9f8e7d6c5b4a3210"):
        got = _classify(v, "cookie: %s" % v)
        assert got == [COOKIE], "%r -> %r" % (v, got)


def test_names_without_cookie_words_remain():
    """②的保守边界（已知残留）：不含 cookie 类词的名字本轮不收。"""
    for v in ("utm_source=", "grayVersion=", "adSourceCode="):
        assert not C._is_cookie_name_without_value(v, C.SERVER_COOKIE_NAME_KEYWORDS), v


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
    print("fix16 路径式 password 语境 + cookie 名空值放宽：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
