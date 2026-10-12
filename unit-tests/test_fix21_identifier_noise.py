#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix21：identifier 类组四处噪音修复的回归测试（①id_device ②id_ad ③id_user ④id_order）。

背景（三库 _v2 实测；口径：出现次数 = SUM(data_item.ref_count+1)，只从 data_item 求和；
详见 test-result/fix21/ 下的回放脚本与报告）
-------------------------------------------------------------------------------
① `is_identifier` 的两条**纯值形臂**（16 位十六进制 android16、17 位 MAC）不看语境就判
   id_device_identifier。三库 id_device 桶 3,807 值 / 47,735 次里五族占 1,761 值 /
   39,285 次（82.3%）：支付宝 ISV appid `^2021\\d{12}$`（474 值/25,473 次）、十六进制字母表
   本体（19/10,895）、组播位 MAC（1,528/3,063，含 macList.js 的 FF:03:00 清单）、DER 编码的
   X.509 扩展 OID（10/249）、连号/整块重复的 16 位十六进制占位（27/984）。
   归置：改判 id_noise(2505, risk0)，拦在纯值形臂之前。
   本文件同时守住**不许**一刀切的部分：随机 16 位十六进制、真 MAC、BLE 服务 UUID、
   非 2021 开头的 16 位十进制（2019 年段支付宝 appid / 2088 起头的 uid）都不许被收掉。
② `AD_ID_KEYWORDS` 含 `adid`，而 has_keyword_in_context 的快速路径是裸子串 ——
   threadId / readID / orgaID / uploadIdCard / subCategoryThreadId 全部命中（pkgref 一库
   35 个 id_ad 值里 30 个是这么来的）。adid / ad_id / gaid 改走「独立词或相邻驼峰段」后，
   `adId:` / `AD_ID_INTERRELATION_DETAIL` / `ad_id` 必须保住。
③ 路径A（`is_identifier` 里的 m_userctx 臂）原只排除「全小写字母」与「小写起头驼峰」，
   于是中文串（`沪ICP备2023016466号` 142+57 次）与全字母常量名/状态名
   （`PASSPORT`/`PROCESSING`/`USERNAME`/`GetUserPhoneNumBerState` 53 次）整族进 id_user。
   收紧为「名字/文案形态」后，真 uid（带数字）不受影响。**路径B（is_openid_format）一行未动**。
④ order 臂原先**一条命名模式排除都没有**（关键词 + 12≤len≤64 + alnum 即判），
   delivererPhone(40+12)、FASTORDERNOLISTS(29+14，值自证含 orderNo)、qianzhudenlai 这类
   调试串、中文文案整族进 id_order。与 id_user 同口径补齐排除后，带订单字段的编号值
   （`orderNo: "130169571554503755"` 等）全部保留。
用法: .venv/bin/python -X utf8 unit-tests/test_fix21_identifier_noise.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

DEV = IDT.ID_DEVICE_IDENTIFIER
AD = IDT.ID_AD_IDENTIFIER
USER = IDT.ID_USER_IDENTIFIER
ORDER = IDT.ID_ORDER_IDENTIFIER
NOISE = IDT.ID_NOISE


def classify(v, stmt):
    return {r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, "probe")])}


def classify_before(v, stmt):
    """把 fix21 ①②③ 的新判据还原成改动前（④ 的驼峰/小写排除是内联的，见各用例的
    「改动前会命中」前置断言）。"""
    saved = (C.is_identifier_shaped_noise, C.has_ad_id_context,
             C.is_name_like_identifier_value)
    C.is_identifier_shaped_noise = lambda s: False
    C.has_ad_id_context = lambda stmt, value: C.has_keyword_in_context(stmt, C.AD_ID_KEYWORDS)
    C.is_name_like_identifier_value = lambda s: False
    try:
        return classify(v, stmt)
    finally:
        (C.is_identifier_shaped_noise, C.has_ad_id_context,
         C.is_name_like_identifier_value) = saved


RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"   {detail}" if not cond else ""))


# =========================================================
# 0. 前置：id_noise 是既有类型（不新增类型）
# =========================================================
def test_id_noise_is_existing_type():
    check("id_noise(2505) 是 fixture 里已有的类型（risk0）",
          NOISE == 2505 and C.IDT.ID_NOISE == 2505, f"NOISE={NOISE}")
    check("noise 判据函数存在", callable(C.is_identifier_shaped_noise))


# =========================================================
# ① id_device：五族噪音改判 id_noise
# =========================================================
def test_1_alipay_isv_appid():
    """支付宝 ISV appid：16 位十进制 2021 开头（474 值 / 25,473 次）。"""
    for v, stmt in (("2021003138687909", 'appid_ali: "2021003138687909"'),
                    ("2021003141607592", 'appid_ali: "2021003141607592"'),
                    ("2021005186688332", 'appId: "2021005186688332"'),
                    ("2021001110676437", 'alipay:"2021001110676437"')):
        got = classify(v, stmt)
        check(f"① 支付宝 ISV appid 不进 id_device: {v}", DEV not in got and NOISE in got, f"got={got}")
        check(f"① 改动前确实在 id_device（判据有效性）: {v}",
              DEV in classify_before(v, stmt), "前置条件不成立")
    # 值形守卫的边界：非 2021 年段不收（证据不足，刻意只收 2021 段）
    for v in ("2019021963241861", "2088631180564424"):
        check(f"① 非 2021 年段不收（保守边界）: {v}", not C.is_identifier_shaped_noise(v))


def test_1_hex_alphabet():
    """十六进制字母表本体（19 值 / 10,895 次）。"""
    for v in ("0123456789abcdef", "0123456789ABCDEF", "1234567890abcdef", "abcdef0123456789"):
        got = classify(v, 'this.hexDigits = "%s"' % v)
        check(f"① 十六进制字母表不进 id_device: {v}", DEV not in got and NOISE in got, f"got={got}")
    check("① 改动前确实在 id_device",
          DEV in classify_before("0123456789abcdef", 't += "0123456789abcdef".charAt(e)'))
    check("① 值形判据本身：随机 16 位十六进制不算字母表",
          not C._is_hex_alphabet_table("7b6d138ebccc865f"))


def test_1_multicast_mac():
    """组播位 MAC（含 macList 的 FF:03:00 清单，1,528 值 / 3,063 次）。"""
    for v in ("FF:03:00:53:97:2D", "FF:03:00:FF:FF:FF", "01:01:01:01:01:01"):
        got = classify(v, '"%s", "%s"' % (v, v))
        check(f"① 组播 MAC 不进 id_device: {v}", DEV not in got and NOISE in got, f"got={got}")
    check("① 值形判据：FF:03:00 是组播", C._is_multicast_mac("FF:03:00:53:97:2D"))
    check("① 值形判据：单播 MAC 不许一刀切（含连字符写法）",
          not C._is_multicast_mac("C0:18:16:43:27:71") and not C._is_multicast_mac("EA:63:A4:6D:AA:57")
          and not C._is_multicast_mac("B8-97-5A-17-AD-4D") and not C._is_multicast_mac("02:00:00:00:00:00"))
    check("① 改动前确实在 id_device",
          DEV in classify_before("FF:03:00:53:97:2D", '"FF:03:00:53:97:2D"'))


def test_1_der_oid_hex():
    """DER 编码的 X.509 扩展 OID（10 值 / 249 次）。"""
    for v in ("2b06010505073001", "2b06010505073002"):
        got = classify(v, 'this.getExtAuthorityInfoAccess=function(t,e){"%s" == ot.getHexOfV_AtObj(t,o)}' % v)
        check(f"① DER OID 不进 id_device: {v}", DEV not in got and NOISE in got, f"got={got}")
        check(f"① 改动前确实在 id_device: {v}",
              DEV in classify_before(v, 'oid = "%s"' % v), "前置条件不成立")
    got = classify("2a86480100000000", 'oid = "2a86480100000000"')
    check("① 既有的 2a8648（1.2.840 弧）仍被 _is_asn1_oid_hex 挡在 is_identifier 之外"
          "（落到 pii_noise，不进 id_device / id_noise）",
          DEV not in got and NOISE not in got and IDT.PII_NOISE in got, f"got={got}")
    check("① 值形判据：随机 16 位十六进制不是 DER OID",
          not C._is_der_oid_hex("7b6d138ebccc865f"))


def test_1_sequential_placeholder():
    """连号 / 整块重复的 16 位十六进制占位（27 值 / 984 次）。"""
    for v in ("1234567890123456", "1234567812345678", "8765432112345678", "1234123412341234"):
        got = classify(v, 'aesPassword: "%s"' % v)
        check(f"① 连号占位不进 id_device: {v}", DEV not in got and NOISE in got, f"got={got}")
    check("① 值形判据：随机 16 位十六进制不算占位",
          not C._is_sequential_hex_placeholder("7b6d138ebccc865f")
          and not C._is_sequential_hex_placeholder("8b3d320b055bfe39"))
    check("① 改动前确实在 id_device（判据有效性）",
          DEV in classify_before("1234567812345678", 'a = "%s"' % "1234567812345678"))


def test_1_true_device_ids_survive():
    """真设备标识必须继续判 id_device（红线）。"""
    cases = (("7b6d138ebccc865f", 'device_id: e.getStorageSync("web_uuid") || "7b6d138ebccc865f"'),
             ("4997b4ef-bb57-402b-ae89-103dc93fe7a0", 'deviceId: "4997b4ef-bb57-402b-ae89-103dc93fe7a0"'),
             ("B8-97-5A-17-AD-4D", 'e.macAddr = "B8-97-5A-17-AD-4D"'),
             ("0000FEE7-0000-1000-8000-00805F9B34FB",
              '-1!="0000FEE7-0000-1000-8000-00805F9B34FB".indexOf(f)&&(e.getBLEDeviceCharacteristics({deviceId:a})'),
             ("02:00:00:00:00:00", 'macValue: "02:00:00:00:00:00"'))
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"① 真设备标识仍在 id_device: {v}", DEV in got, f"got={got}")


# =========================================================
# ② id_ad：adid / gaid 收紧为词或驼峰段
# =========================================================
def test_2_ad_true_positives_survive():
    """adId: / AD_ID_ / ad_id 三份写法必须继续判 id_ad。"""
    for v, stmt in (("e1b291be4ee65b70d7d6126a9b368945", 'adId: "e1b291be4ee65b70d7d6126a9b368945"'),
                    ("0f1ed79601abd56e8b25ad41fc0610c5",
                     'exports.AD_ID_INTERRELATION_DETAIL = "0f1ed79601abd56e8b25ad41fc0610c5"'),
                    ("2bba17fe7a6797f8720cecbf39158de9",
                     'exports.AD_ID_CALENDAR_DETAIL_HORE = "2bba17fe7a6797f8720cecbf39158de9"'),
                    ("374320oTXsZf", '_0x3ffc8b = [ "setting", "2081184QzxuBX", "ad_id", "%s" ]' % "374320oTXsZf")):
        got = classify(v, stmt)
        check(f"② 真 adId 证据仍在 id_ad: {v[:28]}", AD in got, f"got={got}")
    for stmt in ('adId: "x"', 'AD_ID_INTERRELATION_DETAIL = "x"', '"ad_id"', 'gaId: "x"', 'adid: "x"'):
        check(f"② 段匹配直接判据命中: {stmt[:28]!r}", C.has_ad_id_context(stmt, "") is True)


def test_2_ad_false_positives_gone():
    """threadId / readID / orgaID / uploadIdCard 等裸子串误报不再进 id_ad。"""
    cases = (("0000FFE1-0000-1000-8000-00805F9B34FB", 'readID: "0000FFE1-0000-1000-8000-00805F9B34FB"'),
             ("93afacef-3d03-4a3e-a79d-a94289550226", 'subCategoryThreadId: "%s"' % "93afacef-3d03-4a3e-a79d-a94289550226"),
             ("C0B37E1896D27F2B6CF647AAA29B3AF1", 'e.orgaID = "C0B37E1896D27F2B6CF647AAA29B3AF1"'),
             ("uploadIdCard", "Z([3,'uploadIdCard'])"),
             ("uploadIDCard", 'key: "uploadIDCard"'))
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"② 裸子串误报不进 id_ad: {v[:34]}", AD not in got, f"got={got}")
        check(f"② 改动前确实在 id_ad（判据有效性）: {v[:24]}",
              AD in classify_before(v, stmt), "前置条件不成立")
    for stmt in ('readID: "x"', 'threadId: "x"', 'e.orgaID = "x"', 'uploadIdCard',
                 'load_id: "x"', 'mobileListAdOpen'):
        check(f"② 段匹配直接判据不命中: {stmt[:26]!r}", C.has_ad_id_context(stmt, "") is False)
    check("② 长关键词仍走原函数（advertisingid / trackingid 不受影响）",
          C.has_ad_id_context('advertisingId: "x"', "") is True
          and C.has_ad_id_context('tracking_id: "x"', "") is True)


# =========================================================
# ③ id_user：路径A 收紧（中文串 + 全字母名字）；路径B 未动
# =========================================================
def test_3_path_a_name_like_excluded():
    for v, stmt in (("沪ICP备2023016466号", 'g=f(f({},u.default.appConfig||{}),{},(o={openid:"x"}))'),
                    ("PASSPORT", 'o.userid = t.getStorageSync("PASSPORT")'),
                    ("PROCESSING", '"PROCESSING" != a.data.depositState && userid'),
                    # 真实语句（icp 库 x10）：证据来自同一个 512 窗口里的 "USERID"
                    ("USERNAME",
                     'console.log(a), 0 == a.DATA01.length ? (wx.setStorageSync("USERLOGINFLAG", "N"),'
                     ' wx.redirectTo({url: "/pages/standard/login2/login2"})) : "Y" == o ?'
                     ' (wx.setStorageSync("USERID", a.DATA01[0].USERID),'
                     ' wx.setStorageSync("USERNAME", a.DATA01[0].WECHATNAME)) : null'),
                    ("GetUserPhoneNumBerState", '(p=getApp()).globalData.firstLogin=!0,uid'),
                    ("MobileNumberToLoginOrRegistered", 'return h("MobileNumberToLoginOrRegistered"),userId')):
        got = classify(v, stmt)
        check(f"③ 名字/文案不进 id_user: {v[:34]}", USER not in got, f"got={got}")
        check(f"③ 改动前确实在 id_user（判据有效性）: {v[:28]}",
              USER in classify_before(v, stmt), "前置条件不成立")
    for stmt in ('openid = "123456789"', 'uid: "37984296"', 'userid: "AB123456"'):
        check(f"③ 带数字的编号值不受影响（直接跑一遍）: {stmt[:26]!r}",
              USER in classify(stmt.split('"')[1], stmt), stmt)


def test_3_true_user_ids_survive():
    """真 uid / unionid / openid 必须继续判 id_user（红线）。"""
    cases = (("trlia1860363804901", 'defaultUserid: "trlia1860363804901"'),
             ("nyxnc1868688501501", 'wx.setStorageSync("tuserId", "nyxnc1868688501501");'),
             ("37984296", 'a && a.user && l.uid && "37984296" == l.uid'),
             ("UQCkUEU2oo2lgS8c", 'h.sign = t.core.md5("uid=" + h.uid + "UQCkUEU2oo2lgS8c")'))
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"③ 真用户标识仍在 id_user: {v}", USER in got, f"got={got}")
    # 路径B（is_openid_format）一行未动：28 位 o 开头的 unionid 照旧
    check("③ is_openid_format 未改动（28 位 o 开头）",
          C.is_openid_format("orxes6ANWSKBU296OdH4h4lwd6SI") is True
          and C.is_openid_format("0123456789012345678901234567") is False)
    got = classify("orxes6ANWSKBU296OdH4h4lwd6SI", 'unionid: "orxes6ANWSKBU296OdH4h4lwd6SI"')
    check("③ 路径B 的真 unionid 仍是 id_user", USER in got, f"got={got}")


def test_3_name_like_predicate():
    for v, want in (("PASSPORT", True), ("沪ICP备2023016466号", True), ("delivererPhone", True),
                    ("trlia1860363804901", False), ("37984296", False),
                    ("o0IN8wTN50QMxX-V4siq_GSRFuts", False), ("UQCkUEU2oo2lgS8c", False)):
        check(f"③ 值形判据 is_name_like_identifier_value({v[:24]!r})={want}",
              C.is_name_like_identifier_value(v) is want)


# =========================================================
# ④ id_order：与 id_user 同口径补齐命名模式排除
# =========================================================
def test_4_order_names_excluded():
    cases = (("delivererPhone", 'b=_mz(z,\'jn\',[\'allowableActionList\',72,\'orderNo\',1,\'x\'])'),
             ("FASTORDERNOLISTS", 'i.splice(o.data.current,1),o.setData({orderNo:1})'),
             ("qianzhudenlgu", 'console.log("qianzhudenlgu"), r.getUserInfo({outTradeNo: 1})'),
             ("allowOperateBtns123", 's.afterSaleProductInfos=this._checkHasOperateBtns(m.all),orderId'),
             ("android拉起虚拟支付", 'convertPaymentParamsAct:function(t,e,r){var a=t.payment_method,tradeNo}'),
             ("isaddorderno", "Z([[2,'=='],[[7],[3,'isaddorderno']],[1,2]])"))
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"④ 名字/文案不进 id_order: {v[:32]}", ORDER not in got, f"got={got}")
        # 改动前会命中的前置：order 关键词 + 长度 + isalnum（老判据的三个条件）
        check(f"④ 改动前会命中（前置成立）: {v[:24]}",
              C.has_keyword_in_context(stmt, C.ORDER_ID_KEYWORDS)
              and 12 <= len(v) <= 64 and v.isalnum(), "前置条件不成立")


def test_4_true_orders_survive():
    cases = (("130169571554503755", 'orderNo: "130169571554503755"'),
             ("20229485872902", 'orderNo: "20229485872902"'),
             ("4200001144202110287906016575", 'transactionId:"4200001144202110287906016575"'),
             ("PT000000000000001900887305692715", 'outTradeNo:"PT000000000000001900887305692715"'),
             ("202303171637275172", 'dyOrderId:"202303171637275172"'),
             ("d028e0db-08c8-4d7e-a310-4f7d332a6a20", 'orderId: "d028e0db-08c8-4d7e-a310-4f7d332a6a20"'))
    for v, stmt in cases:
        got = classify(v, stmt)
        check(f"④ 真订单号仍在 id_order: {v}", ORDER in got, f"got={got}")


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
    print(f"fix21 identifier 四处噪音验证：{len(RESULTS)} 项，通过 "
          f"{len(RESULTS) - len(bad)}，失败 {len(bad)}"
          + (f"；用例异常 {len(failed)}" if failed else ""))
    for n, d in bad[:12]:
        print(f"   FAIL {n}   {d}")
    return 1 if (bad or failed) else 0


if __name__ == "__main__":
    sys.exit(_run_standalone())
