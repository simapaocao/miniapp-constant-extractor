#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix44：id_ad_identifier(2502, risk3) 的「名字形值」噪音修复的回归测试。

背景（两库 = normal_quarkpan_v2 + unlist_package_reference_v2；口径 = SUM(data_item.ref_count+1)，
详见 test-result/fix44/ 的判读表与回放报告）
-------------------------------------------------------------------------------
病根：`is_identifier` 里判 ID_AD_IDENTIFIER 的两处分支只要求
    has_ad_id_context(stmt, s) 且 长度 ∈ VALID_DEVICE_ID_LENGTHS{12,15,16,32,36} 且 s.isalnum()
（uuid 那一处连长度都不要求）。`has_ad_id_context` 判的是**整段语句的 512 字符窗口**，
于是窗口里只要出现过 adId / ad_id / advertisingId / gaid（或 fix21 ② 收紧后的段对），
窗口里**任何**该长度的字母数字串就判 id_ad —— 与 fix31 的 has_cloud_password_context 同型。

判读（41 个值逐个打开源文件、取值前后 ±300 字符）：
  19 值 / 913 次（95.4%）是误分类，全部是**字段名 / 事件名 / 页面名 / 广告位名 / 类型名 /
  串表 token / 中文上报值**：
    · 字符串表成员   `######XXXXXX`（6 位数字 + 6 位字母）—— 同一源文件的同一个 webpack
                     字符串数组里各有 6~8 个同形成员，编译器生成的模块名映射表
    · 字段名         creativetype / mobileListAdOpen / adrightlabel / videoplayurl / c3ReportData
    · 事件名         adpageshareclick / huodongzhongxin
    · 广告位 / 页面名 paySuccess01 / productDetail01（`adId === "paySuccess01"`）
    · 广告类型名     interstitial
    · 配置字典键名   makevideorunning（`…adid["makevideorunning"].id`，真 id 在 `.id`）
    · 中文上报值     12底部平铺banner
  余下 22 值 / 44 次是**绑在广告键上的真实广告 ID**，形态全是 32 位 hex。

归置：`(True, IDT.ID_NOISE)`（fix21 ① 的写法，一步到位只产出 id_noise），不是 fix22 的
三态 `NAME_CLASS_REJECT = (False, id_noise)` —— 后者只在凭证判据接手时才 consuming，
存在继续往下落到 risk≥4 桶的路径，与本轮「不得继续往下落」的硬约束冲突。

用法: .venv/bin/python -X utf8 unit-tests/test_fix44_id_ad_names.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

AD = IDT.ID_AD_IDENTIFIER
NOISE = IDT.ID_NOISE
USER = IDT.ID_USER_IDENTIFIER
ORDER = IDT.ID_ORDER_IDENTIFIER
DEV = IDT.ID_DEVICE_IDENTIFIER
RISK_HIGH = IDT.RISK_HIGH


def classify(v, stmt):
    return {r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, "probe")])}


def classify_before_fix44(v, stmt):
    """把 fix44 的新值形判据关掉（等价于改动前：ad 臂只看语境 + 长度 + isalnum）。"""
    orig = C.is_ad_identifier_name_like
    C.is_ad_identifier_name_like = lambda s: False
    try:
        return classify(v, stmt)
    finally:
        C.is_ad_identifier_name_like = orig


def risk_of(slug):
    entry = IDT.SLUG_TO_DB.get(slug)
    return None if entry is None else entry[1]


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"   {detail}" if not cond else ""))


# =========================================================
# 0. 前置：id_noise 是既有类型；新判据存在且是「值形」判据
# =========================================================
def test_0_preconditions():
    check("id_noise(2505) 是 fixture 里已有的类型（risk0）",
          NOISE == 2505 and C.IDT.ID_NOISE == 2505, f"NOISE={NOISE}")
    check("id_ad_identifier(2502) 是 risk3（本轮的降噪目标）",
          AD == 2502 and risk_of(AD) == IDT.RISK_ELEVATED, f"{risk_of(AD)}")
    check("fix44 的值形判据存在", callable(C.is_ad_identifier_name_like))
    check("复用只读的既有判据（fix21 ③ / fix12）",
          callable(C.is_name_like_identifier_value) and callable(C.is_segmented_identifier_name))
    check("既有判据本身未被改动（fix21 ③ / fix22 三态口径）",
          C.is_name_like_identifier_value("PASSPORT") is True
          and C.is_name_like_identifier_value("37984296") is False
          and C.is_segmented_identifier_name("auth.updatePassword") is True
          and C.NAME_CLASS_REJECT == (False, IDT.ID_NOISE))


# =========================================================
# ① 广告语境里的「字段名 / 事件名 / 属性名」→ id_noise
# =========================================================
AD_WORD_NAMES = (
    # 真实语句（v2，874 次）：缓存键名，与 adid / creativeid / clickid 并列
    ("creativetype",
     't.cache("adid")&&(l.adid=t.cache("adid")),t.cache("creativeid")&&'
     '(l.creativeid=t.cache("creativeid")),t.cache("creativetype")&&'
     '(l.creativetype=t.cache("creativetype")),t.cache("clickid")&&(l.clickid=t.cache("clickid"))'),
    # 观察者属性名 + setter 名（广告语境由同一窗口里的 n.ad_id 提供）
    ("videoplayurl",
     '(0,r.default)(o,"videoplayurl",""), (0,r.default)(o,"goodmixedinfo",""), n.ad_id = e'),
    # WXML 编译产物的属性名表（真实语句里 adid / adleftlabel / adrightlabel 并列）
    ("adrightlabel",
     "var c=_mz(z,'ad-opt',['adid',3,'adleftlabel',6,'adrightlabel',8,'outClass',9])"),
    # 组件 props 名列表成员（同列表里有 amapAdId）
    ("c3ReportData",
     '["pageId","amapOrderId","exposeHttpReportUrls","c3ReportData","alipayReportData","amapAdId"]'),
    # 事件名（sensors.track）
    ("adpageshareclick",
     'k.sensors.track("adpageshareclick", { landingpageurl: t, bannerid: w, adid: x })'),
    # 事件名（this.report，拼音）
    ("huodongzhongxin",
     'handleAct:function(e){var n=e.trackAdsId,t=e.trackAdId;this.report("huodongzhongxin",'
     '{trackAdsId:n,trackAdId:t})}'),
    # adid 配置字典的**键**（真 id 在 .id 上）
    ("makevideorunning",
     'B(c,d), e[0]["ad_set"], e[0]["adid"], e[0]["makevideorunning"].id'),
)


def test_1_word_names_excluded():
    for v, stmt in AD_WORD_NAMES:
        got = classify(v, stmt)
        check(f"① 字段名/事件名不进 id_ad: {v}", AD not in got and NOISE in got, f"got={got}")
        check(f"① 改动前确实在 id_ad（判据有效性）: {v}",
              AD in classify_before_fix44(v, stmt), "前置条件不成立")


# =========================================================
# ② 广告语境里的「驼峰名 / 广告位名 / 类型名」→ id_noise
# =========================================================
AD_CAMEL_NAMES = (
    ("mobileListAdOpen", "adInfo.mobileListAdOpen, adInfo.mobileListAdId"),
    ("paySuccess01", "adId === 'paySuccess01' && adData.materials[0].adImage"),
    ("productDetail01", "adId === 'productDetail01' && adData.materials[0].adImage"),
    # 广告类型名（adv_type / adType 的取值，同时是路由名 interstitialAdv；
    # 广告语境由同一窗口里的 m.getAdId(m.advertisingId, …) 提供）
    ("interstitial",
     'c = D.ad_type==="banner"||D.ad_type==="feed"?1:D.ad_type==="interstitial"?2:3;'
     ' g = m.getAdId(m.advertisingId, "player", 4, "interstitial")'),
)


def test_2_camel_and_slot_names_excluded():
    for v, stmt in AD_CAMEL_NAMES:
        got = classify(v, stmt)
        check(f"② 驼峰名/广告位名不进 id_ad: {v}", AD not in got and NOISE in got, f"got={got}")
        check(f"② 改动前确实在 id_ad（判据有效性）: {v}",
              AD in classify_before_fix44(v, stmt), "前置条件不成立")


# =========================================================
# ③ 广告语境里的中文（含 CJK）值 → id_noise
# =========================================================
CJK_VALUE = "12底部平铺banner"
CJK_STMT = ('statistics("homepage_adv_resource_expo", { resource_type: "12底部平铺banner",'
            ' ad_id: e.ad_id })')


def test_3_cjk_value_excluded():
    v = CJK_VALUE
    stmt = CJK_STMT
    got = classify(v, stmt)
    check(f"③ 含 CJK 的值不进 id_ad: {v}", AD not in got and NOISE in got, f"got={got}")
    check("③ 改动前确实在 id_ad（判据有效性）", AD in classify_before_fix44(v, stmt),
          "前置条件不成立")


# =========================================================
# ④ webpack 混淆串表 token（6 位数字 + 6 位字母）→ id_noise
# =========================================================
AD_TOKENS = ("740815QwErTy", "913604zXcVbN", "604523PoIuYt")


def test_4_obfuscated_table_tokens_excluded():
    for v in AD_TOKENS:
        stmt = 'function a(){var t=["ad_id","%s","exports","getStorageSync","bannerid"]}' % v
        got = classify(v, stmt)
        check(f"④ 串表 token 不进 id_ad: {v}", AD not in got and NOISE in got, f"got={got}")
        check(f"④ 改动前确实在 id_ad（判据有效性）: {v}",
              AD in classify_before_fix44(v, stmt), "前置条件不成立")
    # 判据本身：这是**形状**判据（6 位数字 + 6 位字母），不是「这一批值」的白名单
    check("④ 值形判据：同形（含未出现在库里的）都命中",
          all(C.is_ad_identifier_name_like(t) for t in AD_TOKENS + ("111111AbCdEf",)))
    check("④ 值形判据：其它长度/分布的同族 token 不在射程内（本轮只收证实的形态）",
          not C.is_ad_identifier_name_like("1234567aBcDeF")
          and not C.is_ad_identifier_name_like("12345aBcDeF"))


# =========================================================
# ⑤ 红线：绑在广告键上的真实广告 ID 必须 100% 保留
# =========================================================
# 全部为**合成值**（照 32 位 hex / uuid 形态自造，不是库内真实 ID）。
AD_TRUE_POSITIVES = (
    ("3f9a1c2d4e5b60718293a4b5c6d7e8f9", 'adId: "3f9a1c2d4e5b60718293a4b5c6d7e8f9"'),
    ("7b2e4d6f8a0c1e3b5d7f9a1c3e5b7d9f", 'adId_2: "7b2e4d6f8a0c1e3b5d7f9a1c3e5b7d9f"'),
    ("1a2b3c4d5e6f708192a3b4c5d6e7f809",
     'H({ ad_id: "1a2b3c4d5e6f708192a3b4c5d6e7f809", ad_name: "x" }, e),'
     ' wx.reportAnalytics("xcx_hl_impr", { ad_id: n.ad_id, ad_name: n.desc })'),
    ("9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f",
     'n.$interstitialAdInstance || (n.$interstitialAdInstance ='
     ' r.createInterstitialAd({ adUnitId: "9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f" })),'
     ' t.setData({ adId: g })'),
    ("2f4e6d8c0a1b3c5d7e9f0a2b4c6d8e0f",
     'VUE_APP_INTERSTITIAL_AD_ID: "2f4e6d8c0a1b3c5d7e9f0a2b4c6d8e0f"'),
    ("5d3c1b0a9e8f7d6c5b4a39281706f5e4",
     'INTERSTITIAL_AD_ID: "5d3c1b0a9e8f7d6c5b4a39281706f5e4"'),
    ("e0f1a2b3c4d5e6f708192a3b4c5d6e7f",
     'REWARDEDVIDEO_AD_ID: "e0f1a2b3c4d5e6f708192a3b4c5d6e7f"'),
    ("a1b2c3d4e5f60718293a4b5c6d7e8f90",
     'adsId: { intersitialAdId: "a1b2c3d4e5f60718293a4b5c6d7e8f90",'
     ' jlVideoAdId: "b2c3d4e5f60718293a4b5c6d7e8f901" }'),
    ("c0ffee1234567890abcdef0011223344",
     'adsId: { bannerAdId: "c0ffee1234567890abcdef0011223344" }'),
    ("4f2a9c1e8b3d4a5f9c0e7d6b5a4c3e2f",
     'vivoEndAdId: "4f2a9c1e8b3d4a5f9c0e7d6b5a4c3e2f"'),
    ("deadbeef00112233445566778899aabb",
     'adSwiperList: [ { adId: "deadbeef00112233445566778899aabb", adDetailName: "x" } ]'),
    # uuid 形态坐在 ad 语境里 → 走另一处 ID_AD_IDENTIFIER 分支，同样保留
    ("4f2a9c1e-8b3d-4a5f-9c0e-7d6b5a4c3e2f",
     'adId: "4f2a9c1e-8b3d-4a5f-9c0e-7d6b5a4c3e2f"'),
)


def test_5_true_ad_ids_survive():
    for v, stmt in AD_TRUE_POSITIVES:
        got = classify(v, stmt)
        check(f"⑤ 真实广告 ID 仍在 id_ad: {v[:12]}…", AD in got and NOISE not in got, f"got={got}")


def test_5_true_ad_ids_uuid_branch_survives():
    """uuid 分支（第二处 ID_AD_IDENTIFIER）也要走同一个守卫，且真 ID 不被收走。"""
    v, stmt = AD_TRUE_POSITIVES[-1]
    check("⑤ uuid 形态的值形判据为假（不被当名字）",
          C.is_ad_identifier_name_like(v) is False, "真 uuid 被误判为名字")
    check("⑤ uuid + 广告语境仍判 id_ad", AD in classify(v, stmt), "红线：真广告 ID 丢了")


# =========================================================
# ⑥ 广告语境之外：行为一行不变
# =========================================================
NO_AD_CONTEXT = (
    ("creativetype", 'o.setData({creative:1,type:"creativetype"})'),
    ("mobileListAdOpen", 'e.mobileListAdOpen = "mobileListAdOpen"'),
    ("interstitial", 't.navigateTo({url:"/pages/interstitial/index"})'),
    ("adrightlabel", "var s = 'adrightlabel'"),
    ("paySuccess01", 'key: "paySuccess01"'),
    ("c3ReportData", '["pageId","c3ReportData"]'),
    ("12底部平铺banner", 'resource_type:"12底部平铺banner"'),
    ("740815QwErTy", 'var t=["740815QwErTy","exports"]'),
)


def test_6_no_ad_context_unchanged():
    for v, stmt in NO_AD_CONTEXT:
        got = classify(v, stmt)
        before = classify_before_fix44(v, stmt)
        check(f"⑥ 广告语境之外判据不生效（分段结果相同）: {v[:20]}", got == before,
              f"got={got} before={before}")
        check(f"⑥ 广告语境之外不产出 id_ad: {v[:20]}", AD not in got, f"got={got}")


def test_6_ad_context_gate_is_required():
    """守卫只在 has_ad_id_context 之后调用 —— 直接判据本身不看语境，但调用点必须先过语境闸门。"""
    check("⑥ 语境闸门：readID / threadId 这类裸子串仍不构成广告语境",
          C.has_ad_id_context('readID: "x"', "") is False
          and C.has_ad_id_context('threadId: "x"', "") is False)
    got = classify("740815QwErTy", 'threadId: "740815QwErTy"')
    check("⑥ 非广告语境（threadId）里的串表 token 不被 fix44 改判",
          NOISE not in got and AD not in got, f"got={got}")
    check("⑥ adId / ad_id / gaId 语境闸门仍成立（fix21 ② 行为未变）",
          C.has_ad_id_context('adId: "x"', "") is True
          and C.has_ad_id_context('"ad_id"', "") is True
          and C.has_ad_id_context('gaId: "x"', "") is True)


# =========================================================
# ⑦ 红线：不得继续往下落
# =========================================================
ALL_EXCLUDED = ([v for v, _ in AD_WORD_NAMES] + [v for v, _ in AD_CAMEL_NAMES]
                + [CJK_VALUE] + list(AD_TOKENS))
ALL_EXCLUDED_STMTS = ([s for _, s in AD_WORD_NAMES] + [s for _, s in AD_CAMEL_NAMES]
                      + [CJK_STMT]
                      + ['function a(){var t = ["ad_id","%s","exports","getStorageSync"]}' % t
                         for t in AD_TOKENS])


def test_7_no_fallthrough():
    for v, stmt in zip(ALL_EXCLUDED, ALL_EXCLUDED_STMTS):
        got = classify(v, stmt)
        check(f"⑦ 只产出 id_noise 一个标签（一步到位，不往下落）: {v[:20]}", got == {NOISE},
              f"got={got}")
        check(f"⑦ 不落入 id_user(risk3): {v[:20]}", USER not in got, f"got={got}")
        check(f"⑦ 不落入 id_order(risk2): {v[:20]}", ORDER not in got, f"got={got}")
        check(f"⑦ 不落入 id_device(risk3): {v[:20]}", DEV not in got, f"got={got}")
        bad = [(s, risk_of(s)) for s in got
               if risk_of(s) is not None and risk_of(s) >= RISK_HIGH]
        check(f"⑦ 无任何 risk>=4 标签: {v[:20]}", not bad, f"bad={bad} got={got}")


def test_7_no_reverse_entry_into_id_ad():
    """反向进入 id_ad 必须为 0：所有被排除的值都不再产出 id_ad。"""
    leaked = [v for v, stmt in zip(ALL_EXCLUDED, ALL_EXCLUDED_STMTS)
              if AD in classify(v, stmt)]
    check("⑦ 反向进入 id_ad_identifier = 0", not leaked, f"leaked={leaked}")


def test_7_other_identifier_buckets_untouched():
    """既有 identifier 桶行为不变：真 uid / 真订单号 / 真设备号 / 真 adId 判定一字未改。"""
    for v, stmt, slug in (("37984296", 'uid: "37984296"', USER),
                          ("trlia1860363804901", 'defaultUserid: "trlia1860363804901"', USER),
                          ("130169571554503755", 'orderNo: "130169571554503755"', ORDER),
                          ("7b6d138ebccc865f", 'deviceId: "7b6d138ebccc865f"', DEV),
                          ("e1b291be4ee65b70d7d6126a9b368945",
                           'AD_ID_INTERRELATION_DETAIL = "e1b291be4ee65b70d7d6126a9b368945"', AD)):
        got = classify(v, stmt)
        check(f"⑦ 既有 identifier 判定不变: {v[:20]}", slug in got, f"got={got}")


# =========================================================
# ⑧ 值形判据的边界（正反例矩阵）
# =========================================================
def test_8_predicate_boundary():
    should_hit = ("creativetype", "mobileListAdOpen", "interstitial", "adrightlabel",
                  "paySuccess01", "productDetail01", "c3ReportData", "videoplayurl",
                  "adpageshareclick", "huodongzhongxin", "makevideorunning",
                  "12底部平铺banner", "740815QwErTy", "auth.updatePassword",
                  "safe-password-time-stamp", "RESET_PASSWORD")
    for v in should_hit:
        check(f"⑧ 判据命中名字形: {v[:24]}", C.is_ad_identifier_name_like(v) is True)
    should_pass = ("3f9a1c2d4e5b60718293a4b5c6d7e8f9",
                   "abcdef0123456789abcdef0123456789",
                   "1234567890abcdef1234567890abcdef",
                   "4f2a9c1e-8b3d-4a5f-9c0e-7d6b5a4c3e2f",
                   "adunit-3f9a1c2d4e5b6071",
                   "Zq0s69UvWxYz0123456789abcdef",
                   "37984296")
    for v in should_pass:
        check(f"⑧ 判据放过标识值形态: {v[:24]}", C.is_ad_identifier_name_like(v) is False)
    check("⑧ 长度闸门：32 位「字母全在前数字全在后」的 hex 不被当名字",
          C.is_ad_identifier_name_like("abcdef0123456789abcdef0123456789") is False)
    check("⑧ 空值安全", C.is_ad_identifier_name_like("") is False)


# =========================================================
# runner（本机 .venv 没装 pytest）
# =========================================================
def _run_standalone():
    cases = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in cases:
        try:
            fn()
        except Exception as exc:  # pylint: disable=broad-except
            import traceback
            failed.append((name, exc))
            print(f"ERROR {name}: {exc}")
            traceback.print_exc()
    bad = [(n, d) for n, ok, d in RESULTS if not ok]
    print("=" * 60)
    print(f"fix44 id_ad_identifier 名字形噪音验证：{len(RESULTS)} 项，通过 "
          f"{len(RESULTS) - len(bad)}，失败 {len(bad)}"
          + (f"；用例异常 {len(failed)}" if failed else ""))
    for n, d in bad[:12]:
        print(f"   FAIL {n}   {d}")
    return 1 if (bad or failed) else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
