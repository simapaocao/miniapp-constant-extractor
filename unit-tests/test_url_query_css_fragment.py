"""URL 查询片段 / CSS 选择器 / CSS 模块类名的结构性拦截（fix13）。

背景
----
把一条 URL 或一段模板编译产物按 `&` / `^` / `-module__` 切开后，切出来的**语法片段**
被当成常量收进库，并被凭证类判定函数接住。三库实测（口径：库内真实 (值,上下文)
重跑当前代码，见 test-result/fix13/a_census.py）：

    A. `&` 开头     cloud_cred_password(5) 164 值/1965 次、cloud_cred_cookie(4) 14 值/74 次
    B. `^` 开头     cloud_cred_password(5)   7 值/58 次
    C. `-module__`  cloud_cred_password(5)  12 值/14 次、saas_map_key(2) 1 值/4 次

本文件固化的边界（本轮真正花力气的地方在**不许命中**的那些）：
  1) 三小类命中即丢弃（不产出任何类型）；
  2) 路径类常量不被碰 —— `&serviceDir=/api/public/index.php?service=X` 是真接口端点
     （miniapp_api_params）；
  3) **查询串里内嵌的真 key 不被丢掉** —— 这是本轮否掉「`&` 开头 / `&名=值` 宽判据」的
     直接原因：实测宽判据会连 `&key=97b588...`（高德 key）、`&key=UBNBZ-...`（腾讯地图 key）
     一起丢，共 136 个去重值 / 163 条（test-result/fix13/f_embedded_secret.py）；
  4) 不含任何 `.`-前缀判据 —— `./components/foo`、`../utils/x` 是合法相对路径，
     按 `.` 开头拦会成片误伤（本轮硬约束）；
  5) 值里含 `=` 右侧内容的片段一律不碰（结构上才可能承载秘密）；
  6) 校验用正则 / semver 不被 `^` 判据吃掉；
  7) 真凭证形态不被吃掉。

标注「实测」的期望值均由 test-result/fix13/g_e2e_probe.py 对着真分类器跑出来后再写死。

用法: .venv/bin/python -X utf8 unit-tests/test_url_query_css_fragment.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

F = C.is_url_query_or_css_fragment


def _classify(v, stmt, interceptor_on=True):
    """跑一遍分类；interceptor_on=False 时 monkeypatch 关掉本轮改动，取「前」判定。"""
    real = C.is_url_query_or_css_fragment
    if not interceptor_on:
        C.is_url_query_or_css_fragment = lambda _s: False
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        C.is_url_query_or_css_fragment = real


# =========================================================
# 1) 三小类正例（判据必须命中）
# =========================================================
def test_url_empty_param_hits():
    """A 类：`&参数名=` —— 整个值就是一个空值参数名。"""
    for v in ("&password=", "&callBack=", "&target=", "&username=", "&newPassword=",
              "&endTime=", "&startTime=", "&custname=", "&componentAppid=", "&currentURL=",
              "&LoginPassword=", "&sessionid=", "&cc_password=", "&resetPwd=", "&act=",
              "&a-b-c="):
        assert F(v), v


def test_css_caret_token_hits():
    """B 类：`^标识符` —— 模板编译产物里的属性/事件选择器名。"""
    for v in ("^navigate", "^stillPassword", "^passwordOutput", "^passwordConfirm",
              "^openLock", "^setPwd", "^toCardDetail", "^seeMoreCoupon", "^show_more",
              "^catchtouchmove", "^selectAll", "^A"):
        assert F(v), v


def test_css_module_class_hits():
    """C 类：CSS Modules 产物类名（`-module__`）。"""
    for v in ("LoginPage-module__pwd-input___nXiLS",
              "LoginPage-module__pwd-form___18wIj",
              "index-module__password___a82Ty",
              "index-module__forgetPasswordContainer___NgzJm",
              "passwordinput-module__pwd___3kueD",
              "index-module__content-wrap___2AMAP",
              "index-module__content-wrap",
              "_503-module__icon___1TM3w",
              "#index-module__title_bar__id",
              "index-module__pwd"):
        assert F(v), v


# =========================================================
# 2) 路径类常量：一律不许碰
# =========================================================
def test_api_path_fragments_survive():
    """`&serviceDir=/api/public/index.php?service=X` 是真接口端点，必须活下来。

    库内实测这类值 31 个在 miniapp_api_params(1)，收窄判据后 31 值/62 次原样不动。
    """
    for v in ("&serviceDir=/api/public/index.php?service=Recommend.getEwmInfo",
              "&serviceDir=api/public/index.php?service=Goods.getcate",
              "&serviceDir=outapi/public/index.php?service=Apporder.getUserIntegralNew",
              "&from=5&to=3&ak=X&url=/a/b?c=d",
              "&next=/pages/index/index"):
        assert not F(v), v


def test_relative_paths_survive():
    """`.` 开头是合法相对路径 —— 本轮明确**不用** `.` 前缀当判据，这里固化成回归。"""
    for v in ("./components/foo", "../utils/x", "./static/logo.png",
              "../../pages/index/index", "./", "@/"):
        assert not F(v), v


def test_module_word_without_marker_survive():
    """`_` 通配符坑的回归：`/login-module/auth/login` 是真接口路径，不得被 C 类吃掉。"""
    for v in ("login-module/auth/login", "/login-module/auth/login",
              "/login-module/auth/bind-phone", "a-module_b", "module__x",
              "-module__", "a-module__", "index-module__x y",
              "./module__a-module__b"):
        assert not F(v), v


# =========================================================
# 3) 查询串里内嵌的真 key：不许丢（否掉宽判据的直接原因）
# =========================================================
def test_embedded_secrets_survive():
    """实测宽判据会丢掉的 163 条内嵌 key —— 本判据必须全部放过。"""
    for v in ("&key=97b588d3e3e852c4acbe118886022078",
              "&key=UBNBZ-PTP3P-TE7DB-LHRTI-Y4YLE-VWBBD",
              "&key=5BZBZ-K4NWX-ZX44C-ZFYBR-PINWO-VAF74",
              "&key=8b650dd596444be8bb603d181591cba6",
              "&key=hxtj201949ba56abbe56e056f29f883e",
              "&key=A52CD3554EEA8895BFA58FAE5A5A44CD",
              "&token=b8e41f749d861dda",
              "&from=5&to=3&ak=lQQjDoRHr0G4YEl4RPyHZ9gCytt8QbBi",
              "&key=e99add94bc19380ce835c5196f6d524d&origin=",
              "&t=0&v=1.0.14&from=wxapp&c=entry&a=wxapp&do=Upload&sign=28c1d189434d29e0",
              "&visitor=prism&signature=2BvfbJKnIou5EGim1IMzVNjbuOuDZkPotcWXHIZK0uE"):
        assert not F(v), v


def test_value_bearing_fragments_survive():
    """`&名=值` 形态一律不碰 —— 值侧可能承载秘密，本判据只认右侧为空。"""
    for v in ("&prevpage=chooseAccount", "&regSuccess=true", "&isBoxQrCode=2",
              "&admin=admin&pwd=admin", "&uin=&skey=", "&modifyType=2&type=5",
              "&act=password", "&key=app_theme", "&LoginType=USER&language=en&ISMD5=0"):
        assert not F(v), v


# =========================================================
# 4) 同族里结构不同的形态：不许碰
# =========================================================
def test_non_fragment_shapes_survive():
    for v in ("&", "&&", "&=x", "&1param=", "&param", "&par am=", "&par=am",
              "&emsp;&emsp;电子邮箱：id@189.cn",      # PII：邮件正文片段
              "&服务="):
        assert not F(v), v


def test_regex_and_semver_survive():
    """`^` 判据不能吃掉校验用正则与 semver。"""
    for v in (r"^1\d{10}$", r"^[a-z]+$", r"^\w+@\w+\.com$", "^1.2.3", "^1.2.3-beta.1",
              "^foo$", "^A^", "^/api", "^A-B$", "^A:.+$"):
        assert not F(v), v


# =========================================================
# 5) 真凭证不得被吞
# =========================================================
def test_real_credentials_survive():
    for v in ("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "EpdnnX4MBpPjdlsZPJBfBJEoywWcXa",
              "x-Kx8mQ2pL9nR4tY6wZ1aB3cD5eF7gH0jM", "1AbCdEfGhIjKlMnOpQrStU==",
              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", "1Passw0rd!xyz",
              "/api/v2/user/detail", "https://api.example.com/v1/login",
              "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg"):
        assert not F(v), v


# =========================================================
# 6) 端到端：命中即丢弃，且「前」判定确实被改掉（实测期望值）
# =========================================================
_PWD_STMT = ("var u = e.default.host + '/oauth/token?grant_type=password&username='"
             " + a + '&password=' + d;")


def test_end_to_end_dropped():
    """命中即丢弃：不产出任何类型（连 other 都不产出）。"""
    assert _classify("&password=", _PWD_STMT) == []
    assert _classify("&password=", _PWD_STMT, interceptor_on=False) == \
        [IDT.CLOUD_CRED_PASSWORD], "实测：关掉拦截时 &password= 被判 cloud_cred_password"

    ctx2 = "Z([[4],[[5],[[4],[[5],[[5],[1,'^stillPassword']]]]]])"
    assert _classify("^stillPassword", ctx2) == []
    assert _classify("^stillPassword", ctx2, interceptor_on=False) == [IDT.OTHER]

    ctx3 = 'var s = { "pwd-input": "LoginPage-module__pwd-input___nXiLS" };'
    assert _classify("LoginPage-module__pwd-input___nXiLS", ctx3) == []
    assert _classify("LoginPage-module__pwd-input___nXiLS", ctx3, interceptor_on=False) == \
        [IDT.CLOUD_CRED_PASSWORD], "实测：关掉拦截时该 CSS 类名被判 cloud_cred_password"


def test_end_to_end_legit_unaffected():
    """同一语境下，真接口 / 内嵌 key / PII 的前后判定必须一致（实测值）。"""
    cases = [
        # (值, 语句, 期望类型)
        ("&serviceDir=/api/public/index.php?service=Goods.getcate",
         'getcate:"&serviceDir=/api/public/index.php?service=Goods.getcate"',
         [IDT.MINIAPP_API_PARAMS]),
        ("/api/user/login?user=",
         'url: "/api/user/login?user=" + a + "&password=" + d',
         [IDT.MINIAPP_API_PARAMS]),
        ("&key=97b588d3e3e852c4acbe118886022078",
         'url:"https://restapi.amap.com/v3/geocode/regeo?output=JSON&location="'
         '.concat(o,",").concat(l,"&key=97b588d3e3e852c4acbe118886022078")',
         [IDT.OTHER]),
        ("&emsp;&emsp;电子邮箱：id@189.cn",
         "Z([3,'\\x26emsp;\\x26emsp;电子邮箱：id@189.cn'])",
         [IDT.PII_EMAIL_NAME]),
        ("/login-module/auth/login", 'url: "/login-module/auth/login"',
         [IDT.SERVER_URL_AUTH]),
        ("^1.2.3", 'dependencies: {"lib": "^1.2.3"}', [IDT.OTHER]),
        (r"^1\d{10}$", 'var re = new RegExp("^1\\\\d{10}$");', [IDT.OTHER]),
    ]
    for v, stmt, want in cases:
        after = _classify(v, stmt)
        before = _classify(v, stmt, interceptor_on=False)
        assert after == want, "%r 后判定 %r != 期望 %r" % (v, after, want)
        assert before == after, "%r 前判定 %r 被本轮改动影响了" % (v, before)


# =========================================================
# 7) 判据本身的自检（防手滑改宽）
# =========================================================
def test_regexes_are_anchored_both_ends():
    for rx in (C.RE_URL_EMPTY_PARAM, C.RE_CSS_CARET_TOKEN, C.RE_CSS_MODULE_CLASS):
        assert rx.pattern.startswith("^"), rx.pattern
        assert rx.pattern.endswith("$"), rx.pattern


def test_no_dot_prefix_criterion():
    """回归：本轮**没有**加入任何 `.` 前缀判据（硬约束）。"""
    for rx in (C.RE_URL_EMPTY_PARAM, C.RE_CSS_CARET_TOKEN, C.RE_CSS_MODULE_CLASS):
        assert not rx.match("./components/foo"), rx.pattern
        assert not rx.match("../utils/x"), rx.pattern


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
    print("URL 查询片段/CSS 选择器/模块类名 拦截验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
