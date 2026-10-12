#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix20 四处噪音修复的回归测试（①URL 凭证 ②敏感关键词死键 ③组件前缀 ④编译器文件身份）。

背景（三库 _v2 实测，口径：出现次数 = SUM(data_item.ref_count+1)，只从 data_item 求和）
-------------------------------------------------------------------------------
① `server_url_with_credentials`(1701, risk5/action=block) 的判据原先只有 `"@" in url_body`，
   三库并集 122 去重值 / 734 次里 120 值 / 728 次是误报（Sentry 遥测 DSN 112 值 / 650 次、
   git 用户名 URL 6 值 / 28 次、拼接模板 2 值 / 50 次），真 `user:password@` 只有 2 值 / 6 次。
   收严为「cred_part 含 ':' 且两侧非空」后：1701 → 2 值 / 6 次，两个真值都保住。
② `URL_SENSITIVE_KEYWORDS` 按插入序 + 裸子串 + 首个命中即 return，"oauth" 被 "auth"、
   "payment" 被 "pay" 挡住 → 三库实测这两个键命中 0 次（死键）。修法是让更专用的词排前面。
   本文件同时守住「最短词仍不许改走整段匹配」：/wxpay/、confirmPayOrder、getAdminClubInfo
   这类真端点必须继续命中（改走 has_keyword_in_context_strict 实测会吃掉 13%~32% 的
   1702/1703 值，见 test-result/fix20/issue2_quantify.out）。
③ 组件引用首段原先只枚举 6 个，/@y/、/mainComponents/、/wigets/、/ext-tee-passport/
   整族漏网直落「敏感关键字」→ server_url_auth(risk4) 头部；项目自建源码根
   /src/、/common/、/usercenter/ 混着真接口与页面路由，改走 usingComponents 语境门；
   分包 /packages/…/components/… 因 `^/package` 被判页面路由，按「组件目录段 + 语境」放行。
④ `miniapp_path_module`(1906) 里 `__wxAppCode__['pages/x/y.wxml']` 这类编译器文件身份
   （.wxml/.wxss/.json）改判 miniapp_noise(1907, risk0)；`.js` 身份刻意不动。

期望值均由 test-result/fix20/ 下的回放脚本对着真分类器跑出后写死。
用法: .venv/bin/python -X utf8 unit-tests/test_fix20_four_noise.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

CRED = IDT.SERVER_URL_WITH_CREDENTIALS
PWD = IDT.SERVER_CRED_PASSWORD
AUTH, PAY, INTERNAL = IDT.SERVER_URL_AUTH, IDT.SERVER_URL_PAYMENT, IDT.SERVER_URL_INTERNAL
PAGE_SENS = IDT.MINIAPP_PAGE_PATH_SENSITIVE
MODULE, NOISE = IDT.MINIAPP_PATH_MODULE, IDT.MINIAPP_NOISE


def classify(v, stmt, gate_on=True):
    """跑一遍分类；gate_on=False 时把 fix20 的四个判据还原成「改动前」行为。

    ① 改动前的 1701 判据是「只要有 userinfo 就算凭证」→ 用 `has_url_userinfo_credential`
       恒 True 模拟（这些用例里值的 cred_part 都不含 '/'、也不是 retina 形态，
       恰好等于改动前 `if not is_npm_scope and not is_retina:` 直接产出的条件）。
    ③ 三个组件前缀常量清空 + 两个 helper 恒 False。
    """
    saved = []
    if not gate_on:
        for name, off in (("has_url_userinfo_credential", lambda *a, **k: True),
                          ("has_usingcomponents_context", lambda *a, **k: False),
                          ("is_compiler_file_identity", lambda *a, **k: False),
                          ("is_subpackage_component_path", lambda *a, **k: False)):
            saved.append((name, getattr(C, name)))
            setattr(C, name, off)
        saved.append(("MINIAPP_COMPONENT_PREFIXES_EXT", C.MINIAPP_COMPONENT_PREFIXES_EXT))
        saved.append(("MINIAPP_COMPONENT_CONTEXT_PREFIXES", C.MINIAPP_COMPONENT_CONTEXT_PREFIXES))
        C.MINIAPP_COMPONENT_PREFIXES_EXT = ()
        C.MINIAPP_COMPONENT_CONTEXT_PREFIXES = ()
    try:
        return {r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, "probe")])}
    finally:
        for name, val in saved:
            setattr(C, name, val)


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"   {detail}" if not cond else ""))


# =========================================================
# ① server_url_with_credentials 收严
# =========================================================
def test_cred_sentry_dsn_not_credentials():
    """Sentry/遥测 DSN（公钥是公开的前端写入键）不再进 risk5。"""
    for v in ("https://733e74645b8e44b7ad81cca10dcaf9a8@sentry.58.com/313",
              "https://46b5a40173ca6ac1a5da97a937d61e9c@rum.17u.cn/317",
              "https://7c78f064520e44baa78aced3351a33d6@report.url.cn/sentry/361",
              "https://0da4f453a12647649b8c3dcd2f7006ea@"):
        for stmt in (f'dsn: "{v}"', f'SENTRY_DSN = "{v}"'):
            got = classify(v, stmt)
            check(f"① DSN 不进 1701: {v[:48]}", CRED not in got and PWD not in got, f"got={got}")
            check(f"① DSN 改动前确实在 1701（判据有效性）: {v[:34]}",
                  CRED in classify(v, stmt, gate_on=False), "前置条件不成立")


def test_cred_git_username_url_not_credentials():
    """git 仓库 URL 只有用户名（无口令）不再进 risk5，但仍按主机分类。"""
    v = "http://suguowei@192.9.180.91/drcBank/credit-applet.git"
    stmt = f'repository/url: "{v}"'
    got = classify(v, stmt)
    check("① git 用户名 URL 不进 1701", CRED not in got, f"got={got}")
    check("① git 用户名 URL 仍判 backend_ip_public（主机分类未被削弱）",
          IDT.BACKEND_IP_PUBLIC in got, f"got={got}")
    check("① git 用户名 URL 改动前在 1701（判据有效性）",
          CRED in classify(v, stmt, gate_on=False))


def test_cred_template_and_npm_and_retina():
    """拼接模板 / npm scope / retina 图片都不算凭证。"""
    for v, stmt in (("https://a@b", '"https://a@b"'),
                    ("https://uni-patient-@tag.zhaoyang120.cn", 'VUE_APP_TAG: "https://uni-patient-@tag.zhaoyang120.cn"'),
                    ("https://registry.npmjs.org/@babel/core", 'reg: "https://registry.npmjs.org/@babel/core"'),
                    ("https://cdn.x.com/icon@2x.png", 'img: "https://cdn.x.com/icon@2x.png"'),
                    ("https://x.com/user@example.com/p", 'p: "https://x.com/user@example.com/p"')):
        got = classify(v, stmt)
        check(f"① 非凭证不进 1701: {v[:44]}", CRED not in got, f"got={got}")


def test_cred_real_userinfo_survives():
    """真 user:password@ 必须保住（1701 + 顺带产出的 1601）。"""
    for v in ("http://zhangxiaoyang:zxy081818@119.191.58.19:10080/web-ui/WechatCredit.git",
              "https://oath2:sps8yaQRN8nCAcLDNRBN@igit.ykbenefit.com/wheatbuy/frontend/wheatbuy-merchant-wechatapp.git"):
        got = classify(v, f'repository/url: "{v}"')
        check(f"① 真凭证保住 1701: {v[:52]}", CRED in got, f"got={got}")
        check(f"① 真凭证同时产出 1601: {v[:52]}", PWD in got, f"got={got}")


def test_cred_userinfo_helper_edges():
    """判据本身的边界：只有含 ':' 且两侧非空才算真凭证。"""
    cases = [("zhangxiaoyang:zxy081818", True), ("oath2:sps8yaQRN8nCAcLDNRBN", True),
             ("733e74645b8e44b7ad81cca10dcaf9a8", False), ("suguowei", False),
             ("uni-patient-", False), ("a", False), (":pass", False), ("user:", False),
             ("user:p:a:ss", True)]
    for cred, want in cases:
        got = C.has_url_userinfo_credential(cred)
        check(f"① has_url_userinfo_credential({cred!r}) == {want}", got == want, f"got={got}")


# =========================================================
# ② 敏感关键词：死键可达 + 短词仍按裸子串命中
# =========================================================
def test_keywords_no_shadowed_entry():
    """没有一个键被更靠前的键包含（= 没有死键）。"""
    keys = list(C.URL_SENSITIVE_KEYWORDS)
    shadowed = [(k, p) for i, k in enumerate(keys) for p in keys[:i] if p in k]
    check("② URL_SENSITIVE_KEYWORDS 无不可达键", not shadowed, f"shadowed={shadowed}")
    check("② 键数仍为 14", len(keys) == 14, f"len={len(keys)}")
    check("② oauth 排在 auth 之前", keys.index("oauth") < keys.index("auth"))
    check("② payment 排在 pay 之前", keys.index("payment") < keys.index("pay"))
    # 可达性自检本身要能抓出死键（用改动前的顺序做反例）
    old = ["webhook/send", "cgi-bin/webhook", "robot/send", "bot/v2/hook", "bot/hook",
           "login", "signin", "auth", "oauth", "pay", "payment", "admin", "internal", "debug"]
    bad = [(k, p) for i, k in enumerate(old) for p in old[:i] if p in k]
    check("② 可达性自检能抓出改动前的两处死键", len(bad) == 2 and {k for k, _ in bad} == {"oauth", "payment"},
          f"bad={bad}")


def test_keywords_true_endpoints_still_hit():
    """短词不许改走整段匹配：这些真端点必须继续命中原类型。"""
    cases = [("/consumerv2/confirmPayOrder", PAY), ("/wxpay/", PAY), ("/alipay/user/bind", PAY),
             ("/cooperator/getAdminClubInfo", INTERNAL), ("/account/login", AUTH),
             ("/v1/sso/oauth2/refresh_token", AUTH), ("/auth/v1/signin/anonymously", AUTH),
             ("https://pay.weixin.qq.com/index", PAY), ("/admin/index", INTERNAL),
             ("/cms_debug/version", INTERNAL), ("/api/member/login_openids", AUTH),
             ("/clientApi/weixinPayIntegralInfo", PAY)]
    for v, want in cases:
        got = classify(v, f'url: "{v}"')
        check(f"② 真端点仍判 {want}: {v}", want in got, f"got={got}")


def test_keywords_webhook_bucket_untouched():
    """webhook 五键不受重排影响。"""
    for v in ("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=1",
              "https://oapi.dingtalk.com/robot/send?access_token=x"):
        got = classify(v, f'url: "{v}"')
        check(f"② webhook 仍判 1501: {v[:46]}", IDT.WEBHOOK_URL in got, f"got={got}")


# =========================================================
# ③ 组件前缀扩族 + 语境门
# =========================================================
def test_component_prefixes_clean_families():
    """四族 100% usingComponents 的前缀：直接判 1906，不再进 auth/payment。"""
    cases = [("/@y/ppt/lib/user-authorize/index", '"a": "/@y/ppt/lib/user-authorize/index"'),
             ("/@y/gc/components/fix-bottom-block/auth-btn/index", 'usingComponents/x: "/@y/gc/components/fix-bottom-block/auth-btn/index"'),
             ("/mainComponents/authPopup/authPopup", '"auth-popup": "/mainComponents/authPopup/authPopup"'),
             ("/MAINCOMPONENTS/authPopup/authPopup", 'usingComponents/auth-popup: "/MAINCOMPONENTS/authPopup/authPopup"'),
             ("/wigets/business/authorize/index", '"ec-authorize": "/wigets/business/authorize/index"'),
             ("/wigets/business/login-mask/longin-mask", '"login-mask": "/wigets/business/login-mask/longin-mask"'),
             ("/ext-tee-passport/extensions/user-authorize/widgets/rt/Main", '"a": "/ext-tee-passport/extensions/user-authorize/widgets/rt/Main"')]
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"③ 组件引用判 1906: {v[:52]}", MODULE in got, f"got={got}")
        check(f"③ 不再进 1702/1703: {v[:52]}",
              not ({AUTH, PAY, INTERNAL} & got), f"got={got}")
        check(f"③ 改动前确实误判（判据有效性）: {v[:52]}",
              bool({AUTH, PAY, INTERNAL} & classify(v, stmt, gate_on=False)), "前置条件不成立")


def test_component_context_gate_only_for_source_roots():
    """自建源码根要语境证据；无 usingComponents 证据时行为不变。"""
    v = "/src/components/auth-area/index"
    check("③ /src/ 有语境证据 → 1906",
          MODULE in classify(v, f'usingComponents/auth-area: "{v}"'))
    got_no_ctx = classify(v, f'url: "{v}"')
    check("③ /src/ 无语境证据 → 仍是 1702（不整族收）", AUTH in got_no_ctx and MODULE not in got_no_ctx,
          f"got={got_no_ctx}")
    v2 = "/common/components/theme-provider/index"
    check("③ /common/ 有语境证据 → 1906",
          MODULE in classify(v2, f'usingComponents/theme-provider: "{v2}"'))
    got2 = classify("/common/getDictData", 'e.miniRequest("/common/getDictData", {})')
    check("③ /common/ 真接口不受影响（仍是 2001）", IDT.MINIAPP_API_PARAMS in got2, f"got={got2}")


def test_component_page_routes_preserved():
    """页面路由必须仍是页面路由。"""
    cases = [("/src/pages/home/index", IDT.MINIAPP_PAGE_PATH),
             ("/src/pages/tabbar/mine.tsx", IDT.MINIAPP_PAGE_PATH),
             ("/common/pages/login/login", IDT.MINIAPP_PAGE_PATH),
             ("/src/pages/common/common-auth/index", IDT.MINIAPP_PAGE_PATH)]
    for v, want in cases:
        got = classify(v, f'usingComponents/x: "{v}"')
        check(f"③ 页面路由仍是页面路径: {v}", want in got and MODULE not in got, f"got={got}")


def test_component_subpackage_component_refs():
    """分包里的组件引用（组件目录段 + 语境）改判 1906；分包里的页面不受影响。"""
    v = "/packages/async-minor/components/shop-pop-manager/index"
    stmt = f'usingComponents/shop-pop-manager: "{v}"'
    check("③ 分包组件引用 → 1906", MODULE in classify(v, stmt))
    check("③ 分包组件引用改动前在 1901（head 误报前置条件）",
          PAGE_SENS in classify(v, stmt, gate_on=False))
    for v2 in ("/packages/user/pages/order/index", "/packages/async-core/pages/index/index"):
        got = classify(v2, f'"a": "{v2}"')
        check(f"③ 分包页面不受影响: {v2}", MODULE not in got, f"got={got}")


def test_component_existing_prefixes_unchanged():
    """原 6 个枚举前缀行为不变。"""
    for v in ("/components/loading", "/component/Common/store-list/index",
              "/wxcomponents/vant/button/index", "/vant/button/index",
              "/components-common/nav/index", "/commpents/loading/index"):
        got = classify(v, f'usingComponents/x: "{v}"')
        check(f"③ 原前缀仍判 1906: {v}", MODULE in got, f"got={got}")


# =========================================================
# ④ 编译器身份串里的模板/样式/配置文件身份
# =========================================================
def test_compiler_file_identity_moves_to_noise():
    """__wxAppCode__ / __wxAppCurrentFile__ / __wxAppFile__ 语境里的 .wxml/.wxss/.json → 1907。"""
    cases = [("pages/account/reserve.json", "__wxAppCode__['pages/account/reserve.json']={}"),
             ("pages/account/login/index.wxml", "__wxAppCurrentFile__='pages/account/login/index.wxml'"),
             ("pages/packageSale/packageSale.wxss", "setCssToHead(...) __wxAppFile__='pages/packageSale/packageSale.wxss'")]
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"④ 编译器文件身份 → 1907: {v}", NOISE in got and MODULE not in got, f"got={got}")
        check(f"④ 改动前是 1906（判据有效性）: {v}",
              MODULE in classify(v, stmt, gate_on=False), "前置条件不成立")


def test_compiler_js_identity_kept_as_module():
    """.js 身份（编译模块 id）刻意留在 1906 —— 本轮不动的边界。"""
    v = "pages/index/index.js"
    stmt = "__wxAppCode__['pages/index/index.js']=function(e,t,n){require('/pages/util/util.js')}"
    got = classify(v, stmt)
    check("④ .js 模块 id 仍是 1906", MODULE in got and NOISE not in got, f"got={got}")


def test_compiler_identity_needs_context():
    """没有编译器语境的同名文件路径行为不变（语境门）。"""
    for v, want in (("pages/account/reserve.json", MODULE),
                    ("pages/account/login/index.wxml", MODULE),
                    ("/pages/index/index", IDT.MINIAPP_PAGE_PATH)):
        got = classify(v, f'pagePath: "{v}"')
        check(f"④ 无语境不改判: {v}", want in got and NOISE not in got, f"got={got}")


def test_compiler_identity_does_not_touch_api_json_paths():
    """带参数的接口 .json 路径不受影响（第 2 步刻意不去查询串的同一理由）。"""
    v = "/api/cms/articles/views.json?"
    got = classify(v, 'url: "/api/cms/articles/views.json?"')
    check("④ 接口 .json? 不进 1907", NOISE not in got, f"got={got}")


# =========================================================
# 跨族红线（本轮不许碰）
# =========================================================
def test_cross_family_red_lines():
    """既有红线：base64 填充 cookie、password1、真公钥 04+128hex、框架产物 ;/__/@@。"""
    cases = [("LmF3LWNvb2tpZS1iYW5uZXI=", 'cookie: "LmF3LWNvb2tpZS1iYW5uZXI="'),
             ("password1", 'password: "password1"'),
             ("04b9c8e0f1a2d3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d",
              'pub: "04b9c8e0f1a2d3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"')]
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"红线值仍被判定（非空）: {v[:32]}", bool(got), f"got={got}")
    for v in ("__wxAppCode__x", "@@iterator", ";function(){}"):
        got = classify(v, f'x = "{v}"')
        check(f"红线：框架产物仍被丢弃: {v[:24]}", not got, f"got={got}")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print("=" * 78)
    print("fix20 四处噪音修复回归（① 1701 ② 死键 ③ 组件前缀 ④ 编译器文件身份）")
    print("=" * 78)
    for t in tests:
        t()
    bad = [n for n, ok, _ in RESULTS if not ok]
    print("=" * 78)
    print(f"fix20 四处噪音修复验证：{len(RESULTS)} 项，通过 {len(RESULTS)-len(bad)}，失败 {len(bad)}")
    for n in bad:
        print(f"  FAILED: {n}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
