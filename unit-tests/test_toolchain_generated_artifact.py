"""框架 / 编译器 / 运行时产物（`;` / `__` / `@@` 开头）的结构性拦截（fix14）。

背景
----
三个消息库的 other(risk 0) 桶头部整片是工具链吐出来的中间物，不是代码作者写的常量。
三库实测（口径：库内真实 (值,上下文) 重跑当前代码，见 test-result/fix14/a_census.py）：

    A. `;`  开头   29,905 值 / 1,389,145 次   WXSS 被 setCssToHead 内联进 JS 后切碎的样式片段
    B. `__` 开头    6,621 值 /   228,445 次   框架/编译器/运行时内部符号
    C. `@@` 开头      168 值 /    75,675 次   JS well-known symbol 与 redux/taro 等 action 前缀
    合计 36,694 值 / 1,693,265 次 = 三库出现次数的 9.39%

本文件固化的边界（本轮真正花力气的地方在**不许命中**的那些）：
  1) 三族命中即丢弃（不产出任何类型，连 other 都不产出）；
  2) 手写 CSS / SQL / JSON 常量不被碰 —— 判据是**前缀**匹配，`"width:100px"`、
     `"display:none"`、`"SELECT id FROM users"` 本来就不以 `;` 开头；
  3) 库里「含 `;` 但不在首位」的 1,818 + 6,228 + 18,890 个切碎的 CSS 片段（如
     `0;text-align:center;width:`）**一个都不动** —— 本轮只做这一条；
  4) 内嵌 / 独立的真 key 不被丢：`key=8b650dd5…`、`&key=97b588d3…`（fix13 已放行的形态）
     前后判定必须逐位一致；
  5) 邮箱不被 `@@` 吃掉（邮箱 local-part 不能以 `@` 开头）；
  6) 单个下划线、值中间的双下划线（`_private_field` / `a__b` / `my__password`）不被碰 ——
     判据只认**首位**的 `__`；
  7) 全角 `；`(U+FF1B) 开头的中文 UI 文案不被误吞 —— MySQL 的 utf8mb4_unicode_ci 会把
     `LEFT(x,1) = CHAR(59)` 判成同时匹配全角分号（三库各 8/1/9 条），Python 侧
     `startswith(";")` 只认 ASCII，这里固化成回归；
  8) 真凭证形态不被吃掉。

标注「实测」的期望值均由 test-result/fix14/g_e2e_probe.py 对着真分类器跑出来后再写死。

用法: .venv/bin/python -X utf8 unit-tests/test_toolchain_generated_artifact.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

F = C.is_toolchain_generated_artifact


def _classify(v, stmt, interceptor_on=True):
    """跑一遍分类；interceptor_on=False 时 monkeypatch 关掉本轮改动，取「前」判定。"""
    real = C.is_toolchain_generated_artifact
    if not interceptor_on:
        C.is_toolchain_generated_artifact = lambda _s: False
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        C.is_toolchain_generated_artifact = real


# =========================================================
# 1) 三族正例（真实样本，判据必须命中）
# =========================================================
def test_css_fragment_hits():
    """A 族：`;` 开头 —— setCssToHead 内联 WXSS 后切出的样式片段（按出现次数取头部）。"""
    for v in (";height:", ";line-height:", ";padding:", ";margin-top:", ";margin-right:",
              ";padding:0", ";margin-bottom:", ";margin-left:", ";margin:",
              ";text-align:center;width:", ";color:#fff;font-size:",
              ";position:absolute;right:", ";font-weight:500;height:",
              ";-webkit-justify-content:center;justify-content:center;width:",
              ";box-sizing:border-box;height:", ";overflow:hidden;position:relative;width:"):
        assert F(v), v


def test_cookie_fragment_hits():
    """A 族里的另一支：拼到已有 cookie 串尾部的 `;名=` 片段（当前正被判 risk 5）。"""
    for v in (";.ASPXAUTH=", "; _FSESSIONID=", ";XSRF-TOKEN=", ";PHPSESSID=",
              ";refresh_token=", ";grant_type=", ";GARAGE_SESSION_ID=", ";session_id=",
              ";JSESSIONID=", "; gy_mmid=", ";data_bizuin=", ";pubToken=undefined;openid=",
              ";path=/;domain=.ktvme.com", ";charset=utf-8", ";page_size=20;page_index=1"):
        assert F(v), v


def test_framework_internal_symbol_hits():
    """B 族：`__` 开头 —— 框架/编译器/运行时内部符号（B 族按出现次数取头部）。"""
    for v in ("__scopeId", "__set_model", "__wxspec__", "__DC_STAT_UUID", "__static__",
              "__webpack_require_UNI_MP_PLUGIN__", "__v_isMPComponent",
              "__compileDebugInfo__", "__core-js_shared__", "__lodash_hash_undefined__",
              "__wrapped__", "__vInternal", "__v_isReactive", "__set_sync", "__warning__",
              "__wxWebviewId__", "__password", "__sentry_xhr_v3__", "__wj_userid=",
              "__proto__",
              # 编译器注入的插件/内置资源虚拟路径（B 族最大的一块，1,274 值 / 24,139 次）
              "__plugin__/wx2b03c6e691cd7370/pages/live-player-plugin",
              "__plugin__/wxfab2bf944bfc4da6/components/authorize/authorize",
              "__wuBaseWxss__/0.wxss", "__wx__/functional-page.wxml"):
        assert F(v), v


def test_js_wellknown_symbol_hits():
    """C 族：`@@` 开头 —— JS well-known symbol 与各框架 action 前缀。"""
    for v in ("@@iterator", "@@toStringTag", "@@asyncIterator", "@@toPrimitive",
              "@@observable", "@@isConcatSpreadable", "@@WeakMap@@",
              "@@redux/INIT", "@@redux/REPLACE", "@@redux/PROBE_UNKNOWN_ACTION",
              "@@redux-saga/CHANNEL_END", "@@DVA_LOADING/HIDE", "@@dva/UPDATE",
              "@@transducer/step", "@@functional/placeholder", "@@__IMMUTABLE_KEYED__@@",
              "@@__IMMUTABLE_ITERABLE__@@", "@@taro-user-info", "@@taro-wx-user-info"):
        assert F(v), v


# =========================================================
# 2) 手写 CSS / SQL / JSON 常量：一律不许碰（前缀判据的核心边界）
# =========================================================
def test_handwritten_css_survives():
    """手写 CSS 常量不以 `;` 开头 —— 前缀判据结构上就够不到它们。"""
    for v in ("width:100px", "display:none", "user-select:none",
              "background:#fff;color:#333", "font-size:14px",
              "pwdStyle:display:none", "-webkit-touch-callout:none;max-width:100%",
              ":root{--v-brand-color-7:#003a8c}"):
        assert not F(v), v


def test_fragments_not_at_head_survive():
    """库里含 `;` 但**不在首位**的片段一个都不动（本轮只做 `;` 开头这一条）。

    三库这类值有 1,818 + 6,228 + 18,890 个，第 3、4 名是 `!important;width:` /
    `0;text-align:center;width:` —— 本轮明确不碰。
    """
    for v in ("0;width:", "!important;width:", "0;text-align:center;width:",
              "0;position:relative;width:", "!important;position:relative;width:",
              "120rpx;height:", "1;left:0;top:", "-webkit-touch-callout:none;max-width:100%"):
        assert not F(v), v


def test_sql_and_json_survive():
    """SQL / JSON 片段：实测以 `;` 开头的 0 个（三库 `LIKE '%SELECT %FROM%'` 无一在首位）。"""
    for v in ("SELECT id FROM users", "select * from t where a=1",
              "INSERT INTO t (a) VALUES (1)", '{"a":1,"b":2}', '["a","b","c"]',
              "UPDATE t SET a=1 WHERE id=2"):
        assert not F(v), v


# =========================================================
# 3) 内嵌 / 独立的真 key：不许丢（fix13 的教训）
# =========================================================
def test_real_keys_survive():
    for v in ("key=8b650dd596444be8bb603d181591cba6",
              "&key=97b588d3e3e852c4acbe118886022078",
              "&key=UBNBZ-PTP3P-TE7DB-LHRTI-Y4YLE-VWBBD",
              "&token=b8e41f749d861dda",
              "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
              "EpdnnX4MBpPjdlsZPJBfBJEoywWcXa",
              "1AbCdEfGhIjKlMnOpQrStU==",
              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
              "1Passw0rd!xyz"):
        assert not F(v), v


# =========================================================
# 4) `_` / `@` 的近似形态：不许误吞（判据只看**首位**的两个字符）
# =========================================================
def test_single_underscore_survives():
    """单个下划线开头不是框架符号；`__` 在值中间也不算（判据只看首位）。"""
    for v in ("_private_field", "_id", "_abc", "a__b", "my__password",
              "wx__appid", "index-module__pwd___nXiLS", "x___y"):
        assert not F(v), v


def test_double_underscore_head_is_dropped():
    """判据只认首位：`__` 开头丢、`__` 在中间不丢。"""
    assert F("__x") and F("__") and F("___")
    for v in ("x__y", "a__b", "my__password", "_x__y"):
        assert not F(v), v


def test_email_survives():
    """邮箱 local-part 不能以 `@` 开头 —— `@@` 前缀结构上碰不到邮箱。

    三库含 `@`(非首位) 且含 `.` 的值共 13,527 个，**没有一个以 `@@` 开头**。
    """
    for v in ("a@b.com", "service@189.cn", "id@189.cn", "admin@mucfc.com",
              "user.name+tag@example.com.cn", "x@@y"):
        assert not F(v), v


def test_single_at_sign_survives():
    for v in ("@click", "@tap", "@import", "@media", "@keyframes", "@font-face",
              "@miniprogram_npm/weui-miniprogram", "@tarojs/taro", "a@@b"):
        assert not F(v), v


def test_other_guards_own_shapes_survive():
    """fix7 / fix10 / fix12 / fix13 的形态不归本条管（判据互不重叠）。"""
    for v in ("data-v-10bfb526", "v-bind:title.once", "wx:scope-data",
              "data-sid", "X-Expire-Timestamp", "x-cos-copy-source",
              "&password=", "^navigate", "LoginPage-module__pwd-input___nXiLS",
              "--v-brand-color-7", ":data-v-463a5323-default-0"):
        assert not F(v), v


def test_fullwidth_semicolon_survives():
    """全角 `；`(U+FF1B) 开头的中文 UI 文案不许被误吞。

    三库实测各有 8/1/9 条是这种值（MySQL 的 utf8mb4_unicode_ci 会让
    `LEFT(x,1) = CHAR(59)` 同时匹配全角分号，Python 侧只认 ASCII）。
    """
    for v in ("；1707020返回：", "；来自于crm-vip-modal",
              "；如您预约成功的时间为10:30，则您的预约入场时间为10:30~",
              "；（3）如果你是开发者/产品经理/设计师，请联系岂凡超（微信号："):
        assert not F(v), v


# =========================================================
# 5) 端到端：命中即丢弃，且「前」判定确实被改掉（实测期望值）
# =========================================================
def test_end_to_end_css_fragment_dropped():
    ctx = 'setCssToHead(["wx-view{font-size:",[0,28],";line-height:1"]);'
    assert _classify(";height:", ctx) == []
    assert _classify(";height:", ctx, interceptor_on=False) == [IDT.OTHER], \
        "实测：关掉拦截时 ;height: 落 other"


def test_end_to_end_risk5_cookie_fragment_dropped():
    """A 族里当前被判 risk 5 的 cookie 片段 —— 本轮清掉的就是这批误报。"""
    for v, stmt in (
        (";.ASPXAUTH=",
         'o.cookie = "ASP.NET_SessionId=".concat(n.globalData.sessionId, ";.ASPXAUTH=")'
         '.concat(n.globalData.sessionUserId)'),
        ("; _FSESSIONID=", 'h+="; _FSESSIONID="+y'),
        (";PHPSESSID=", 'Cookie:"A362_voucherkey="+a+";PHPSESSID="+t.PHPSESSID'),
    ):
        assert _classify(v, stmt) == [], v
        assert _classify(v, stmt, interceptor_on=False) == [IDT.SERVER_CRED_COOKIE], \
            "实测：关掉拦截时 %r 被判 server_cred_cookie(5)" % v


def test_end_to_end_framework_symbol_dropped():
    for v, stmt, before in (
        ("__scopeId", '["__scopeId","data-v-exO"]', IDT.OTHER),
        ("__set_model", '__set_model: function() {}', IDT.OTHER),
        ("__wxspec__", 'var a = "__wxspec__";', IDT.OTHER),
        # 实测：关掉拦截时 __password 被判 cloud_cred_password(5)（BEM 元素类名误报）
        ("__password", 'password:"".concat(e,"__password")', IDT.CLOUD_CRED_PASSWORD),
        # 实测：关掉拦截时 __sentry_xhr_v3__ 被判 saas_analytics_key(1)
        ("__sentry_xhr_v3__", 'var k = "__sentry_xhr_v3__";', IDT.SAAS_ANALYTICS_KEY),
        ("__wj_userid=", 'o.cookie="".concat(o.cookie,";","__wj_userid=").concat(s)',
         IDT.SERVER_CRED_COOKIE),
        ("@@iterator", 'var k = "@@iterator";', IDT.OTHER),
        ("@@redux/INIT", 'var t = "@@redux/INIT";', IDT.OTHER),
        ("@@__IMMUTABLE_KEYED__@@", 'var k = "@@__IMMUTABLE_KEYED__@@";', IDT.OTHER),
    ):
        assert _classify(v, stmt) == [], v
        assert _classify(v, stmt, interceptor_on=False) == [before], \
            "实测：关掉拦截时 %r 判成 %s" % (v, before)


def test_end_to_end_legit_unaffected():
    """同一批合法常量在前后判定必须逐位一致（实测值）。"""
    cases = [
        # (值, 语句, 期望类型)
        ("0;text-align:center;width:",
         'setCssToHead(["a{margin:0;text-align:center;width:"]);', [IDT.PII_NOISE]),
        ("!important;position:relative;width:",
         'setCssToHead(["a{margin:0!important;position:relative;width:"]);', [IDT.OTHER]),
        ('{"a":1,"b":2}', 'var cfg = "{\\"a\\":1,\\"b\\":2}";', [IDT.OTHER]),
        ("key=8b650dd596444be8bb603d181591cba6",
         'url:"x?key=8b650dd596444be8bb603d181591cba6"', [IDT.PII_NOISE]),
        ("&key=97b588d3e3e852c4acbe118886022078",
         'url:"https://restapi.amap.com/v3/geocode/regeo?output=JSON&location=a'
         '&key=97b588d3e3e852c4acbe118886022078"', [IDT.OTHER]),
        ("a@b.com", 'email: "a@b.com"', [IDT.PII_EMAIL_NAME]),
        ("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
         'appSecret: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"', [IDT.PLATFORM_APP_SECRET]),
        ("_private_field", 'var a = "_private_field";', [IDT.OTHER]),
        ("；如您预约成功的时间为10:30，则您的预约入场时间为10:30~",
         'var a = "；如您预约成功的时间为10:30，则您的预约入场时间为10:30~";', [IDT.OTHER]),
    ]
    for v, stmt, want in cases:
        after = _classify(v, stmt)
        before = _classify(v, stmt, interceptor_on=False)
        assert after == want, "%r 后判定 %r != 期望 %r" % (v, after, want)
        assert before == after, "%r 前判定 %r 被本轮改动影响了" % (v, before)


# =========================================================
# 6) 判据本身的自检（防手滑改宽）
# =========================================================
def test_criteria_are_exactly_three_ascii_prefixes():
    """判据必须是「恰好 `;` / `__` / `@@` 三个 ASCII 前缀」，不能多也不能少。

    尤其：不能把单个 `_`、单个 `@`、全角 `；` 加进来 —— 那会成片误伤
    （`_private_field`、`@click`、`；1707020返回：`）。
    """
    assert tuple(C.TOOLCHAIN_ARTIFACT_PREFIXES) == (";", "__", "@@")
    for p in C.TOOLCHAIN_ARTIFACT_PREFIXES:
        assert p.encode("utf-8").decode("ascii") == p, "前缀必须是 ASCII: %r" % p
    assert not F("_x"), "单个下划线不能命中"
    assert not F("@x"), "单个 @ 不能命中"


def test_guard_is_prefix_only_not_substring():
    """回归：判据是**前缀**，不是子串 —— `x__y` / `a;b` 不许被吞。"""
    for v in ("x__y", "a;b", "abc;height:", "wx__appid", "a@@b", "foo__bar__baz"):
        assert not F(v), v


def test_interceptor_is_ordered_as_a_structural_gate():
    """拦截块必须早于类型判定：命中值不产出任何类型（连 other 都不产出）。"""
    assert _classify(";height:", 'setCssToHead(["a{height:1px;line-height:2"]);') == []
    assert _classify("__scopeId", '["__scopeId","data-v-exO"]') == []
    assert _classify("@@iterator", 'var k = "@@iterator";') == []


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
    print("框架/编译器/运行时产物（; / __ / @@ 开头）拦截验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
