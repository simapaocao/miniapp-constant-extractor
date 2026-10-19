#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix25：server_cred_cookie 裸 cookie 出口的「多段标识符名」守卫。

病根
----
`CONTEXT_KEYWORDS_2` 的 `"cookie" -> SERVER_CRED_COOKIE(1604)` 是本链**唯一没有专属判据
把关**的出口：stmt 里出现裸子串 `cookie` 就出口。fix15 ③ 只补了**单段**值形守卫
（`is_single_segment_identifier_name`），够不到「多段」那一族 —— `.` / `-` / `_` 分段的
属性名、i18n key、存储键、常量名整族照样出口。

实测（normal_quarkpan 只读全量普查，1604 桶内 8,535 条链接）：
  · 值 `is_segmented_identifier_name` 为真的 5,153 条链接 / 1,460 个值；
  · 这 1,460 个值**全部**经 CONTEXT_KEYWORDS_2 的裸 cookie 关键词出口进来 ——
    `is_server_cookie` 命中 **0** 条（那个函数要求值含 `=` 且长度 ≥10，够不到名字）；
  · 头部值：`XSRF-TOKEN`(618 链接) / `PAGE_COOKIE`(231) / `Storage.Keys.Cookie`(136) /
    `quick_cookieObj`(87) / `quick_cookieStr`(85) / `punish_test_id`(59) / `user_token`(54) /
    `Platforms_V2`(44) / `keep-alive`(43) / `cookie-info`(38) …全是名字，不是凭证材料。

判据（本轮只动 cookie 出口这一处，两行守卫）
----
  ① 值形：`is_segmented_identifier_name(s)`（复用 fix12 立下、已在 `is_cloud_password` /
     `is_server_cookie` 上证明安全的同一条值形判据）为真 —— 多段词形标识符名。
     极窄的兄弟形态：名字尾随分隔符（`PAGE_COOKIE_` / `mw-cookie-` / `chat-input__`），
     由 `is_segmented_identifier_name_or_prefix` 覆盖（判据 = 去掉尾部分隔符后仍是多段名）。
     三库全量实测额外收 19 / 8 / 3 个值，逐个核对全是名字片段，无一个像材料。
  ② 绑定例外：本值在 stmt 里与真正的 cookie **值**位置绑定时不改判。绑定复用 fix24 的
     `_PAYMENT_VALUE_BINDING_RE`（同一个「紧邻本值左侧的键」口径），键名限定为 cookie 值键
     `COOKIE_VALUE_BINDING_KEYS = ("cookie", "cookies")`：`Cookie: "…"`、`cookie: "…"`、
     `document.cookie = "…"` 都落在这个键上（`Set-Cookie` 被键正则切成 `Cookie`）。

刻意**不**把含 cookie 的复合键（`xsrfCookieName` / `COOKIE_NAME` / `cookieStorageName` /
`loginCookieKey` / `COOKIE_KEY` / `CookiePrefixParamName` …）算作绑定 —— 那些键位坐的是
cookie **名**本身，正是本轮要清的噪音：`xsrfCookieName: "XSRF-TOKEN"` 一条就是 610 条链接。
本文件用 `test_naive_binding_control_group` 证明「键名含 cookie 就算绑定」会让修复失效。

保住的红线（逐条钉住）
---------------------
  · `name=value`：值里含 `=`，而值形判据的字符集没有 `=`，天然不在射程内
    （`PHPSESSID=o4p06s98q17nf6do3osu931ah2`、`session_id=abc123`、base64 填充真值…）；
  · 坐在 cookie 值键上的分段名（真实数据：`tal_token` / `wps_sid` / `user_id` /
    `access_token` / `token_auth` / `B_SESSDATA` / `http_tK_cache`）由绑定例外保留；
  · fix15 ③ 单段守卫、fix16 ②「cookie 名 + 空值」、fix12 值形红线（真口令/编号）一行未改；
  · 只作用于 cookie 出口：同样的分段名在非 cookie 语境下本就不产出，行为不变。

已知残留（刻意不扩大判据）
-------------------------
多段名里**每段都以字母打头**这一条不放宽（`MyPage_6` / `April_2024` / `v1_step2_pwd` 之类
仍留在 1604）；单段残留（`punish` / `cookieObj` 这类）由 fix15 ③ 的既有射程决定，本轮不动。

用法: .venv/bin/python -X utf8 unit-tests/test_server_cookie_segmented_names.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

COOKIE = IDT.SERVER_CRED_COOKIE

_GUARD_ATTRS = ("is_segmented_identifier_name_or_prefix", "_cookie_value_key_bound_to_value")


def _guard_on(v):
    """新值形判据（RED 阶段名字还不存在时按「判据未落地」处理，断言照跑）。"""
    fn = getattr(C, "is_segmented_identifier_name_or_prefix", None)
    return bool(fn(v)) if fn else False


def _classify(v, stmt, guard_off=False, naive_bind=False):
    """跑一遍分类；两个 Off 开关各自只关掉本修复的一条判据，其余逐位不变。

    guard_off：把新守卫还原成改动前（恒不生效）—— 用于「改动前确实在 1604」的前置断言。
    naive_bind：把绑定豁免放宽成「键名含 cookie 即算」—— 对照组：证明
               `xsrfCookieName` 这类复合键若算绑定，本轮修复就失效。
    两个开关都是模块级名字，函数体在调用时才查；名字不存在（RED 阶段）时按「本来就关着」
    处理（与 test_payment_param_placement.py 同一约定）。
    """
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if guard_off and hasattr(C, "is_segmented_identifier_name_or_prefix"):
        C.is_segmented_identifier_name_or_prefix = lambda s: False
    if naive_bind and hasattr(C, "_cookie_value_key_bound_to_value"):
        C._cookie_value_key_bound_to_value = lambda s, stmt_: any(
            "cookie" in k.lower() for k in _all_bound_keys(stmt_, s))
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


def _all_bound_keys(stmt, value):
    """对照组用：本值每个独立出现位置左侧紧邻的键（不限 cookie 值键）。"""
    keys, pos = set(), stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            m = C._PAYMENT_VALUE_BINDING_RE.search(stmt, 0, pos)
            if m:
                keys.add(m.group(1))
        pos = stmt.find(value, pos + 1)
    return keys


# =========================================================
# ① 多段标识符名：unbound -> 不再出口 1604
# =========================================================
# (值, 语境) 均取自 normal_quarkpan 真实 1604 链接（普查数字见文件头）。
UNBOUND_CASES = [
    # 头号来源：610 条链接全绑在配置键 xsrfCookieName 上，值本身是默认 cookie 名。
    ("XSRF-TOKEN", 'xsrfCookieName: "XSRF-TOKEN"'),
    ("XSRF-TOKEN", 'adapter.defaults.xsrfCookieName = "XSRF-TOKEN"'),
    # 存储键三元式（231 条链接）：值是存储前缀，语境里的 cookie 来自 cookieStore。
    ("PAGE_COOKIE", 'f="storage"===s?"PAGE_COOKIE_"+c:"PAGE_COOKIE"'),
    ("PAGE_COOKIE_", 'f="storage"===s?"PAGE_COOKIE_"+c:"PAGE_COOKIE"'),
    ("PAGE_COOKIE", 'g="storage"===this.cookieStore?"PAGE_COOKIE_"+this.$_pageName:"PAGE_COOKIE"'),
    # 属性路径式名字（136 条链接）。
    ("Storage.Keys.Cookie", 'c = "Storage.Keys.Cookie"'),
    # cookie 名数组 / 取名字的字面量（本轮点名的形态）。
    ("auth-token", "cookieNames: ['auth-token','session-id']"),
    ("session-id", "cookieNames: ['auth-token','session-id']"),
    ("auth-token", 't = Ly.http.cookieStore.get("auth-token")'),
    # 其余头部族。
    ("quick_cookieObj", 'n.quick_cookieObj = {}'),
    ("cookie-info", 'cookie: e, url: "/api/cookie-info"'),
    # 真实语境是 CORS 头名数组（含 "cookie" 的是同数组里的头名，与本值无关）。
    ("keep-alive", 'b = [ "connection", "content-length", "cookie", "keep-alive" ]'),
    ("user_token", 'cookie: 1, t.headers["user-token"] = a, k = "user_token"'),
    ("Platforms_V2", 'cookie: 1, T.Platforms_V2 = "Platforms_V2"'),
    ("is_show_pwd_popup", 'cookie: 1, storage.set("is_show_pwd_popup", !0)'),
    ("wx_user_info_phone", 'this.getCookie("wx_user_info_phone".concat(Date.now()))'),
    ("dialog-bind-phone", 'cookie: 1, s = "dialog-bind-phone"'),
    ("cors-token", 'cookie: 1, t = "cors-token"'),
    ("weapp-cookie", 'cookie: 1, require("weapp-cookie")'),
    ("longPoll.query.requestData.cookie.longPollingID",
     'cookie: 1, a = "longPoll.query.requestData.cookie.longPollingID"'),
]


def test_unbound_segmented_names_dropped():
    """本轮射程：上面每个真实 (值, 语境) 都要离开 1604。"""
    for v, stmt in UNBOUND_CASES:
        got = _classify(v, stmt)
        assert COOKIE not in got, "%r in %r -> %r" % (v, stmt, got)


def test_guard_is_the_change():
    """对照：只关掉新守卫，它们全部回到 1604（证明这些失败确由本条判据负责）。"""
    for v, stmt in UNBOUND_CASES:
        got = _classify(v, stmt, guard_off=True)
        assert got == [COOKIE], "%r in %r -> %r" % (v, stmt, got)


def test_value_shape_predicate_is_the_mechanism():
    """机制断言：这批值确实过新的值形判据（父任务给出的口径 is_segmented_identifier_name）。"""
    for v, _ in UNBOUND_CASES:
        assert _guard_on(v), "值形判据没覆盖: %r" % v


def test_seed_examples_from_brief_are_red_before_the_fix():
    """点名三例在改动前确实判 1604（RED 前置条件）。"""
    for v, stmt in (("XSRF-TOKEN", 'adapter.defaults.xsrfCookieName = "XSRF-TOKEN"'),
                    ("PAGE_COOKIE_", 'f="storage"===s?"PAGE_COOKIE_"+c:"PAGE_COOKIE"'),
                    ("auth-token", "cookieNames: ['auth-token','session-id']"),
                    ("session-id", "cookieNames: ['auth-token','session-id']")):
        assert _classify(v, stmt, guard_off=True) == [COOKIE], (v, stmt)


# =========================================================
# ② 绑定在真正 cookie 值键上：一条都不许动
# =========================================================
# 「cookie 值位置」= 紧邻本值的键是 cookie / cookies（`Cookie: "…"`、`cookie:"…"`、
# `document.cookie = "…"` 都落在这个键上）。值/语境取自真实 1604 链接。
BOUND_CASES = [
    ("tal_token", 'cookie: "tal_token=".concat(t.getStorageSync("tal_token") || "", ";")'),
    ("tal_token", 'cookie:"tal_token=".concat(e.getStorageSync("tal_token")||"",";stu_id=")'),
    ("wps_sid", 'Cookie: "wps_sid=" + wx.getStorageSync("wps_sid") + l + f + g'),
    ("user_id", 'cookie: "user_id=" + wx.getStorageSync("user_id") + ";mobile_token="'),
    ("access_token", 'Cookie: "access_token=".concat(wx.getStorageSync("access_token"))'),
    ("http_tK_cache", 'Cookie:"http_tK_cache=".concat(t.index.getStorageSync("http_tK_cache"))'),
    ("token_auth", 'Cookie: "token_auth=" + wx.getStorageSync("token_auth")'),
    ("B_SESSDATA", 'Cookie: "B_SESSDATA=".concat(o.A.get("B_SESSDATA"))'),
]


def test_bound_cookie_context_kept():
    """绑定例外：值坐在 cookie 值位置时，分段名照旧判 1604（不许一刀切）。"""
    for v, stmt in BOUND_CASES:
        got = _classify(v, stmt)
        assert got == [COOKIE], "%r in %r -> %r" % (v, stmt, got)


def test_binding_helper_boundaries():
    """绑定判据本身的边界：只看紧邻本值的键，且只认 cookie 值键。"""
    if not hasattr(C, "_cookie_value_key_bound_to_value"):
        raise AssertionError("绑定判据 _cookie_value_key_bound_to_value 未落地")
    B = C._cookie_value_key_bound_to_value
    assert B("tal_token", 'cookie: "tal_token=".concat(x)') is True
    assert B("wps_sid", 'Cookie: "wps_sid=" + a') is True
    assert B("user_id", 'document.cookie = "user_id=" + a') is True
    assert B("cookies_str", 'cookies: "cookies_str"') is True
    # 复合键（存的是 cookie 名 / 存储键）不算绑定
    assert B("XSRF-TOKEN", 'xsrfCookieName: "XSRF-TOKEN"') is False
    assert B("mina_sts_opt", 'COOKIE_NAME = "mina_sts_opt"') is False
    assert B("zz_wa_cookie", 'cookieStorageName: "zz_wa_cookie"') is False
    assert B("zz_wa_cookie", 'cookieStorageKey:"zz_wa_cookie"') is False
    assert B("beian.cookie", 'COOKIE_KEY: "beian.cookie"') is False
    assert B("Cg_CookiePrefix", 'CookiePrefixParamName: "Cg_CookiePrefix"') is False
    # 无紧邻绑定
    assert B("PAGE_COOKIE", 'f="storage"===s?"PAGE_COOKIE_"+c:"PAGE_COOKIE"') is False
    # 本值只是更长字面量的前缀/后缀时不算绑定（与 fix24 同一条细则）
    assert B("tal", 'cookie: "tal_token="') is False
    assert B("token", 'cookie: "tal_token="') is False
    assert B("cookie", 'x = a_cookie_name') is False


def test_naive_binding_control_group():
    """对照组：把「键名含 cookie」都算绑定，本轮的 XSRF-TOKEN 修复就失效。

    这正是绑定豁免必须收窄到 cookie **值**键的理由 —— 现行实现没踩。
    """
    v, stmt = "XSRF-TOKEN", 'xsrfCookieName: "XSRF-TOKEN"'
    assert _classify(v, stmt) != [COOKIE]                      # 现行：收掉
    assert _classify(v, stmt, naive_bind=True) == [COOKIE]     # 对照组：留 1604


# =========================================================
# ③ 真红线：真 cookie 值 / name=value 一律不动
# =========================================================
REAL_VALUE_CASES = [
    ("PHPSESSID=o4p06s98q17nf6do3osu931ah2", 'Cookie: "PHPSESSID=o4p06s98q17nf6do3osu931ah2"'),
    ("PHPSESSID=e4dk4o2utr3c0n95tp42p745ai", 'cookieKey: "PHPSESSID=e4dk4o2utr3c0n95tp42p745ai"'),
    ("session_id=abc123", "cookie: session_id=abc123"),
    ("session_id=abc123", 'Cookie: "session_id=abc123; path=/"'),
    ("sid=abcdef123456", "cookie: sid=abcdef123456"),
    ("JSESSIONID=abcd1234efg", "cookie: JSESSIONID=abcd1234efg"),
    ("laravel_session=abc123xyz", "cookie: laravel_session=abc123xyz"),
    ("LmF3LWNvb2tpZS1iYW5uZXI=",
     'easyListCookie: [ ".ezmob-footer", ".cc-CookieWarning", t("LmF3LWNvb2tpZS1iYW5uZXI=") ]'),
    ("sha1-TnBUPfjEPAxVbAWJjPPUOSdC4Lo=",
     'dependencies/@base/cookie/integrity: "sha1-TnBUPfjEPAxVbAWJjPPUOSdC4Lo="'),
]


def test_real_cookie_values_kept():
    """`name=value` 与 base64 填充真值：值形判据的字符集里没有 `=`，天然不在射程内。"""
    for v, stmt in REAL_VALUE_CASES:
        got = _classify(v, stmt)
        assert got == [COOKIE], "%r -> %r" % (v, got)
        assert not _guard_on(v), v


def test_fix12_fix15_counterexample_matrix_unchanged():
    """fix12/fix15 的值形红线：真口令/编号一个都不许被这条新判据吃掉。"""
    for v in ("password1", "password123", "admin123", "Admin123", "err3241", "emoney5",
              "passwordTips3", "mnP7XKDCaWFjINWi", "o0IN8wTN50QMxX-V4siq_GSRFuts",
              "signBoardPassword_S8hY", "video123", "ytx123456", "HFG9K23FDHJ09Zm",
              "37984296", "130169571554503755", "7b6d138ebccc865f",
              "4997b4ef-bb57-402b-ae89-103dc93fe7a0", "PHPSESSID"):
        assert not _guard_on(v), "值形误吃真阳性: %r" % v


def test_single_segment_guard_untouched():
    """fix15 ③ 的单段守卫语义一行未改（本判据只加多段那一族 + 尾随分隔符）。"""
    for v in ("WXOFFICIAL", "adapter", "timeout", "requireIdCard", "mobileEmptyTips",
              "recordPsw_", "#tips_popup", ".page-recharge-wallet-list-balance",
              "===success", "_is_enter_password"):
        assert C.is_single_segment_identifier_name(v), v
        # 单段判据只保证「不进 1604」；语法片段（`===success` / `#tips_popup`）另有下游类型，不断言「不产出」。
        assert COOKIE not in _classify(v, 'cookie:"1",a=%s' % v), v
    # 单段守卫**不**吃真口令（fix15 的红线，两族判据都在）
    for v in ("password1", "password123", "Admin123", "mnP7XKDCaWFjINWi"):
        got = _classify(v, 'cookie: 1, x = "%s"' % v)
        assert got == [COOKIE], "%r -> %r" % (v, got)


def test_guard_is_cookie_branch_only():
    """作用面：判据只在 cookie 出口生效，别的桶逐位不变。"""
    # ① 值里不含 cookie 词、语境里也没有 cookie：本来就不产出，改动前后一样。
    for v in ("XSRF-TOKEN", "auth-token"):
        assert _classify(v, 'const x = "%s"' % v) == [], v
    # ② 值自身含 cookie 词（`PAGE_COOKIE` / `Storage.Keys.Cookie`）会**自指**打开 cookie 语境
    #    —— 这正是裸子串出口的病灶之一；修复后它们在普通语句里也不再产出。
    for v in ("PAGE_COOKIE", "Storage.Keys.Cookie"):
        assert _classify(v, 'const x = "%s"' % v) == [], v
    # ③ password 语境（同为 risk5 桶）与本判据无关：开关对结果无影响。
    for v, stmt in (("auth-token", 'password: "auth-token"'),
                    ("err3241", 'password: "err3241"'),
                    ("mnP7XKDCaWFjINWi", 'newPassword: "mnP7XKDCaWFjINWi"')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), (v, stmt)
    assert _classify("err3241", 'password: "err3241"') == [IDT.CLOUD_CRED_PASSWORD]


def test_fix16_cookie_name_without_value_untouched():
    """fix16 ② 的「cookie 名 + 空值」照旧（它与本轮判据互不依赖）。"""
    for v, stmt in (("temp_token_auth=", 'Cookie: "temp_token_auth=" + getApp().globalData.token'),
                    ("auth_token=", 'Cookie: "auth_token=" + cookieStorage.auth_token'),
                    ("JSESSIONID=", '"Cookie": "JSESSIONID=" + wx.getStorageSync("sessionId")')):
        assert C._is_cookie_name_without_value(v, C.SERVER_COOKIE_NAME_KEYWORDS), v
        assert COOKIE not in _classify(v, stmt), v


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
    print("fix25 cookie 多段标识符名守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
