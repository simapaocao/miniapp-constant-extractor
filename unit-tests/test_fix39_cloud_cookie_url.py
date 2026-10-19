#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix39：cloud_cred_cookie(1206) 只收「cookie 文」，URL 查询片段/日志串显式改判 cloud_cred_noise(1207)。

病根
----
`is_cloud_cookie` 是**裸子串闸门**：`长度≥10 + 含 "=" + 小写后含 CLOUD_COOKIE_NAMES 之一`。
里面 `uin=` / `skey=` 是**常见的 URL 查询参数名**（`&skey=` / `?uin=` / `&businessKey=` 都含
`skey=`），于是整条 URL 查询片段被当成会话 Cookie 收进 1206(risk4)。

只读普查（`test-result/fix39/probe_cookie_shapes.py`，normal_quarkpan_v2 + pkgref_v2）：
  · normal_quarkpan_v2：437 条链接 / **134 个去重值**，形态三分 ——
      118 个 URL 查询片段（`?uin=` `?skey=` `?businessKey=` `/path?x=` `mqqapi://…?uin=` `&cuid=…&…`）；
       15 个日志串 / 键名片段（`writeActionReport fail. uin=`、`initAsync: X-WX-Skey=`、
          `accessKey=`、`==busKey====`）；
        1 个真 Set-Cookie 头（`…sid=; Domain=…; Path=/; Expires=…`）；
  · pkgref_v2：42 条链接 / 16 个去重值，**16/16 全是 URL 片段或日志串**（无一条是 cookie 文）。

改法（值侧形态判据，只看值自己）
----
  值含 `?` / `&` / `/`（`://` 必然含 `/`）或**成段文字**（含空白）→ 不是 cookie 文；
  只保留两类**结构上就是 cookie** 的形态：
      · Set-Cookie 头：`name=value;` 后跟 `Path=` / `Domain=` / `Expires=` 等属性；
      · 单个 `name=value` cookie 令牌：无空白、name 与 value 都在 cookie 名字/值字符集里、
        value 非空（`accessKey=` 这类**空值键名片段**不算令牌）。

为什么判据落在 `process_cloud_cookie`（出口）而不是 `is_cloud_cookie`（入口）
----------------------------------------------------------------------------
主链的这一段是 `if is_cloud_cookie(s): process_cloud_cookie(...); continue`。**入口一旦返回
False，值就继续往链下走** —— 实测（本文件第 ③ 组，probe 同口径）会漂进 `server_cred_cookie`
(1604, **risk5**)、`miniapp_api_params` / `miniapp_scene_param` / `pii_noise` / `other`。
那既不是「显式落 risk0」，也会把 risk4 升到 risk5。所以入口粗筛保持原样（**零改动**），
由出口 `process_cloud_cookie` 做形态细分并把不合格的值**显式**改判 `cloud_cred_noise(1207, risk0)`。

归置（红线）
-----------
  · 移出值的落点**只能**是 1207（risk0）：不得继续落到 `server_cred_cookie`(5) 等桶；
  · 受保护真阳性 100% 保留：真 Set-Cookie 头 + `name=value` cookie 令牌；
  · 反向进入 1206 的数量为 0 —— 由构造保证（粗筛一字未动，本判据只能把值**移出** 1206）。

用法: .venv/bin/python -X utf8 unit-tests/test_fix39_cloud_cookie_url.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

COOKIE = IDT.CLOUD_CRED_COOKIE
NOISE = IDT.CLOUD_CRED_NOISE
SERVER_COOKIE = IDT.SERVER_CRED_COOKIE
_GUARD_ATTR = "is_cloud_cookie_literal"
_HERE = os.path.dirname(os.path.abspath(__file__))


def _risks():
    with open(os.path.join(os.path.dirname(_HERE), "constant_types.json"), encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"]] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risks()
_SLUG_OF = {v: k for k, v in vars(IDT).items()
            if isinstance(v, int) and k.isupper() and not k.startswith("CTG_")}


def _classify(v, stmt, guard_off=False):
    """跑一遍分类；`guard_off` 把本轮的形态判据还原成「改动前」（恒真 ⇒ 一律 1206）。

    与 `test_fix33_aksk_value_pairing.py` 同一约定：RED 阶段新名字还不存在时按「本来就关着」
    处理，断言照跑（此时 ① 组必然失败 —— 那就是 RED）。
    """
    saved = getattr(C, _GUARD_ATTR, None)
    if guard_off and saved is not None:
        setattr(C, _GUARD_ATTR, lambda _s: True)
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        if guard_off and saved is not None:
            setattr(C, _GUARD_ATTR, saved)


# =========================================================
# ① 移出组：URL 查询片段 / 协议串 / 日志串 / 空值键名片段
# =========================================================
# 全部是**合成值**，形态与库里那 132 个值逐一对应（真值一律掩码在报告里，测试里不出现）。
# 每个值都必须先过**入口粗筛**（长度≥10、含 `=`、含 CLOUD_COOKIE_NAMES 之一）——
# 这是本方案的前提，由 test_gate_is_the_coarse_sieve_unchanged 钉住。
STMT = 'var u = "/api/v1/config/list?businessType=LOGIN&channel=WXA_HOME";'

MOVED = [
    # URL 查询片段（`?` / `&` / `/`）
    "/c2c/rc/report?uin=",
    "&IS_SIGN=1&SKEY=",
    "./manage_info?owner_uin=",
    "/account/logo?uin=",
    "/api/v1/demo/list?businessKey=DEMO_DOMAIN&businessType=DEMO",
    "/user/common/get_image_captcha?businessType=LOGIN&channel=WXA_HOME&businessKey=",
    "workflow/demo/getNeedToDoTaskCount?businessKey=com.demo.service.api.RemoteDemoService",
    "tencent_demo_video.mp4?v=",
    "&cuid=baidu_demo_voice&cod=2&lan=zh&ctp=1",
    "&needNewCode=1&uin=0&tpl=3&page=detail&platform=h5",
    # 协议串：`mqqapi://` / `mqqwpa://`（`://` 里必然含 `/`）
    "mqqapi://card/show_pslcard?src_type=internal&version=1&uin=1234567890",
    "mqqwpa://im/chat?chat_type=wpa&uin=1234567890",
    # 相对路径 + 查询串
    "pkgOther/pages/qqFindPwdFromFacial/index?receipt=&f_type=0&scene_type=1101&uin=",
    # 日志串（空白分隔的句子）
    "writeActionReport fail. uin=",
    "page: module.js, initAsync: X-WX-Skey=",
    "checkIfH5TestEnv uin=",
    "set owner_uin=",
    "uin is invalid,不出现评论赞入口,uin=",
    # 空值键名片段（无空白、无 URL 标点，但 value 为空 ⇒ 不是 cookie 令牌）
    "accessKey=",
    "businesskey=",
    "demo_qlskey=",
    "huaqi_huin=",
    "refer_share_uin=",
    ",currentUin=",
    "==busKey====",
    "bookex===unitsKey==",
]

# 个别形态的落点依赖语境（关掉闸门后链条往下走），用库内**同形**的合成语境钉住。
SNIPPET_BY_VALUE = {
    # 库内原型：`Cookie: "…qlskey=" + s + ";…openid=" + t` —— 空值键名片段坐在 Cookie 头拼接里。
    "demo_qlskey=": 'Cookie: "demo_qlskey=" + t + ";demo_openid="',
}


def _stmt_of(v):
    return SNIPPET_BY_VALUE.get(v, STMT)

# 保护组：真 cookie 文
KEPT_HEADER = ("qcloud_demo.sid=AbCd1234; Domain=.example.com; Path=/; "
               "Expires=Thu, 01 Jan 2070 00:00:00 GMT")
KEPT = [
    KEPT_HEADER,                                        # Set-Cookie 头（多属性）
    "qcloud_demo.sid=AbCd1234; Path=/; Secure; HttpOnly",   # Set-Cookie 头（无 Domain/Expires）
    "skey=0123456789abcdef0123456789abcdef",            # name=value cookie 令牌
    "qiniu_demo=AbCdEf123456",                          # name=value cookie 令牌
    "bce_demo=Zm9vYmFyMTIzNDU2Nzg5MA==",                # 带 base64 padding 的 value
    "awsalb=AQEB1234",                                  # 短 name=value 令牌
]


def test_gate_is_the_coarse_sieve_unchanged():
    """入口粗筛（`is_cloud_cookie`）一字未动：移出组的值**仍然**命中它。

    这是「出口显式改判」方案的前提 —— 入口一旦改严，值就会漂到链下别的桶（第 ③ 组）。
    """
    for v in MOVED + KEPT:
        assert C.is_cloud_cookie(v) is True, v


def test_moved_values_are_no_longer_cookies():
    """① 移出组：不再是 1206，且落点**只有** cloud_cred_noise(1207, risk0)。"""
    assert len(MOVED) == 26, len(MOVED)
    for v in MOVED:
        got = _classify(v, _stmt_of(v))
        assert got == [NOISE], (v, got)
        assert COOKIE not in got, (v, got)


def test_kept_true_cookies_stay_1206():
    """② 受保护真阳性：Set-Cookie 头与 `name=value` cookie 令牌 100% 保留 1206。"""
    assert len(KEPT) == 6, len(KEPT)
    for v in KEPT:
        assert _classify(v, STMT) == [COOKIE], (v, _classify(v, STMT))
        assert _classify(v, STMT, guard_off=True) == [COOKIE], v     # 开关无关


# =========================================================
# ③ 归置红线：只落 risk0，绝不下漂到 server_cred_cookie(1604, risk5)
# =========================================================
def test_destination_is_risk0_only():
    assert NOISE == 1207 and RISK["cloud_cred_noise"] == 0, (NOISE, RISK["cloud_cred_noise"])
    assert COOKIE == 1206 and RISK["cloud_cred_cookie"] == 4
    assert SERVER_COOKIE == 1604 and RISK["server_cred_cookie"] == 5
    for v in MOVED:
        got = _classify(v, _stmt_of(v))
        assert got == [NOISE], (v, got)
        for label in got:
            assert RISK.get(_SLUG_OF.get(label, "").lower(), 0) == 0, (v, label)


def test_fallthrough_would_drift_into_risk5_hence_explicit_interception():
    """③ 为什么必须是「出口显式改判」而不是「入口返回 False 让值漂下去」。

    实测（probe 同口径）：关掉出口判据 = 让值继续往链下走时，移出组里至少有值落进
    `server_cred_cookie`(risk5)：`Cookie: "…qlskey=" + s + ";…openid=" + t` 这类
    **空值键名片段坐在 Cookie 头拼接里**的现场，会被 `is_server_cookie` 接手 ——
    这正是「risk4 → risk5」的升级路径。所以本轮的拦截发生在出口，落点是显式的 1207。
    这一组把「漂移」钉成回归：一旦有人把判据挪回入口，本组会红。
    """
    drift = {}
    for v in MOVED:
        saved = C.is_cloud_cookie
        C.is_cloud_cookie = lambda _s: False
        try:
            got = [r[0] for r in C.perform_constant_classifying([_stmt_of(v)], [(v, 0, 0)])]
        finally:
            C.is_cloud_cookie = saved
        if got != [NOISE]:
            drift[v] = got
    # 漂下去的形态至少要有：risk5 的 server_cred_cookie（`…qlskey=` 那条实测如此）
    assert SERVER_COOKIE in [lbl for got in drift.values() for lbl in got], drift
    assert len(drift) >= 3, drift
    # 而本轮的口径下这些值一个都不漂：
    for v in MOVED:
        assert _classify(v, _stmt_of(v)) == [NOISE], (v, _classify(v, _stmt_of(v)))


# =========================================================
# ④ 开关对照：`guard_off` == 改动前（一律 1206）
# =========================================================
def test_guard_is_the_change():
    for v in MOVED:
        had = _classify(v, _stmt_of(v), guard_off=True)
        assert had == [COOKIE], (v, had)
        assert _classify(v, _stmt_of(v)) == [NOISE], v
    # 保护组与开关无关
    for v in KEPT:
        assert _classify(v, STMT, guard_off=True) == _classify(v, STMT) == [COOKIE], v


# =========================================================
# ⑤ 判据本身的边界（只看值自己）
# =========================================================
def test_predicate_boundaries():
    """⑤ 形态判据的正反例（RED 阶段新名字不存在 ⇒ 本组直接失败，属预期）。"""
    fn = C.is_cloud_cookie_literal
    # 正例：cookie 文
    assert fn(KEPT_HEADER) is True
    assert fn("qiniu_demo=AbCdEf123456") is True
    assert fn("x-amz-security-token=FQoGAbCdEf") is True          # `-` 在 name 里
    assert fn("acs_demo=AbCdEf.Gh12~34%56") is True               # 值字符集含 . ~ %
    # 反例：URL / 协议 / 日志 / 空值键名 / 非 cookie 形态
    for weak in ("?uin=", "&IS_SIGN=1&SKEY=", "/account/logo?uin=",
                 "mqqapi://card/show_pslcard?uin=1",
                 "writeActionReport fail. uin=", "page: module.js, initAsync: X-WX-Skey=",
                 "accessKey=", "==busKey====", "bookex===unitsKey==",
                 "name=PathologicalReportToWeb&navTitle=报告",
                 "a=b c=d", "qcloud_demo=a;b=c"):
        assert fn(weak) is False, weak
    # 判据不看语境、不看粗筛：只回答「这个值是不是 cookie 文」
    assert fn("skey=0123456789abcdef0123456789abcdef") is True
    assert fn("nothing-to-see") is False


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
    print("fix39 cookie 形态判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
