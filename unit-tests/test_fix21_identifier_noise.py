#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix21：identifier 类组四处噪音修复的回归测试（①id_device ②id_ad ③id_user ④id_order）。

fix22 的断言也加在本文件末尾（"fix22" 小节）：fix21 ③④ 收严后，被排除的名字类值继续往下
走到凭证判据上，14 行由 risk 2~3 升到 risk 5；fix22 把这批值在凭证判据接手时改判
id_noise，并钉住改动面（真 openid / 真订单号 / 「本来不产出」的值 / 既存同类误报都不动）。

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
    「改动前会命中」前置断言）。

    fix44 注：本助手要复现的是**改动前的代码**。fix44 在 ad 臂里又加了一道值形守卫
    （is_ad_identifier_name_like），它比 fix21 ② 更晚生效；只还原 fix21 的三条判据会得到
    一个**从未存在过的中间状态**（pre-fix21 的语境口径 + post-fix44 的值形守卫），
    于是 `uploadIdCard` / `uploadIDCard` 这类全字母值不再落 id_ad，「改动前确实在 id_ad」
    的前置断言会假失败。所以这里把 fix44 的守卫一并关断 —— 只影响本助手，不影响任何用例
    对**当前代码**的断言。
    """
    saved = (C.is_identifier_shaped_noise, C.has_ad_id_context,
             C.is_name_like_identifier_value, C.is_ad_identifier_name_like)
    C.is_identifier_shaped_noise = lambda s: False
    C.has_ad_id_context = lambda stmt, value: C.has_keyword_in_context(stmt, C.AD_ID_KEYWORDS)
    C.is_name_like_identifier_value = lambda s: False
    C.is_ad_identifier_name_like = lambda s: False
    try:
        return classify(v, stmt)
    finally:
        (C.is_identifier_shaped_noise, C.has_ad_id_context,
         C.is_name_like_identifier_value, C.is_ad_identifier_name_like) = saved


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
                    # 本条要钉的是「独立串 token "ad_id" 能开广告语境闸门」，与值的形状无关。
                    # 原用的值（6 位数字 + 6 位字母）正是 fix44 判读为 webpack 混淆串表 token
                    # 的那一形态（见 test-result/fix44/），fix44 已把它在广告语境里收成
                    # id_noise，故这里换成 32 位 hex，避免让本行同时钉住一个已被推翻的形状。
                    ("93c1e0f4a7b25d6819fe30ac47bd5210",
                     '_0x3ffc8b = [ "setting", "2081184QzxuBX", "ad_id", "%s" ]' % "93c1e0f4a7b25d6819fe30ac47bd5210")):
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
# fix22：命名形态落选 → 被下游凭证判据接手时 consuming 成 id_noise
# =========================================================
# 病根（fix21 ③④ 的直接延续）：上面这些「名字/文案形态」的值被 identifier 臂排除后
# **继续往下走**，落到下游的凭证判据上 —— 三库用真实 (值,上下文) 重跑实测 14 行 / 17 次
# （cloud_cred_password 13 行 / 16 次、server_cred_cookie 1 行 / 1 次）由 risk 2~3 升到
# risk 5。归置：改判既有 id_noise(2505, risk0)，**且只在凭证判据真要接手时**（见
# constants_classifier.NAME_CLASS_REJECT 与 perform_constant_classifying 的 fix22 注释）。
#
# 本段守住三件事：
#   ① 这 14 行确实从风险桶回到 id_noise；
#   ② **改动面不外溢** —— 既有的同类误报（不是本轮升级、且由既有排除造成）一律不动，
#      真 openid / 真订单号 / 真凭证一律不动，「本来不产出」的值仍是「不产出」；
#   ③ 三态回报的边界（只回报 fix21 新加的那几条命名排除）。
RISK5 = (IDT.CLOUD_CRED_PASSWORD, IDT.SERVER_CRED_COOKIE)

# 14 行：值 + 复现语境（保留触发机制：既要有 identifier 臂的用户/订单关键词，
# 又要有凭证判据的关键词/裸 cookie 出口）。真实语境见 test-result/fix22/ 的报告与
# m_ctx.out（512 字符窗口版；其中 normsib `在线建档h5需要unionId` 一条用真实全文）。
FIX22_ROWS = (
    ("ByPhoneRegisteredUsers", 'o.ResetPassword="x",userId:"u",t=ByPhoneRegisteredUsers',
     IDT.CLOUD_CRED_PASSWORD),
    ("IdCardOcrAsync", 'o.RetrievePassword="x",userId:"u",t=IdCardOcrAsync',
     IDT.CLOUD_CRED_PASSWORD),
    ("VerifyPhoneRegister", 'o.ResetPassword="x",uid:"u",t=VerifyPhoneRegister',
     IDT.CLOUD_CRED_PASSWORD),
    ("MobileNumberToLoginOrRegistered",
     'havePassword=!1,openId:"x",h("MobileNumberToLoginOrRegistered")', IDT.CLOUD_CRED_PASSWORD),
    ("PhoneNumber", 'invoice:"",openid:"",resetPassword:"",u=PhoneNumber',
     IDT.CLOUD_CRED_PASSWORD),
    ("csairlugtransH5", 'orderNo:"1",resetPassword:"",t={csairlugtransH5:"/p/channelCodeH5/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    ("emallH5Sichuan", 'orderId:"1",passWord:"",t={emallH5Sichuan:"/p/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    ("holidayBocheH5", 'orderNo:"1",pwd:"",t={holidayBocheH5:"/p/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    ("holidayPostScheduleH5", 'tradeno:"1",password:"",t={holidayPostScheduleH5:"/p/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    ("holidayViewTicketH5", 'orderNo:"1",resetPassword:"",t={holidayViewTicketH5:"/p/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    ("rentalcarsH5", 'orderNo:"1",db_pwd:"",t={rentalcarsH5:"/p/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    ("taskCenterModel5", 'orderNo:"1",resetPassword:"",t={taskCenterModel5:"/p/index"}',
     IDT.CLOUD_CRED_PASSWORD),
    # 真实全文（normsib，405 字符）：命中裸关键词出口（stmt 含 authCookie），
    # 而不是 is_server_cookie —— 两条出口都要被闸门覆盖。
    ("在线建档h5需要unionId",
     'console.log("authCookie========="),console.log(a),(S.some((function(e){return t.includes(e)}))'
     '||-1!=t.indexOf("mix/auth/index")&&"lecshop"==n.model)&&(n.openId=v.getStorageSync("openId"),'
     'n.wxAppId=w.wxAppId),-1!=t.indexOf("mix/auth/index")&&"lecshop"==n.model&&'
     '(n.accessToken=r.Base64.encode(a)),t.includes("patient/hosCard/bind")&&'
     '(n.unionId=v.getStorageSync("unionId"),console.log(n,"在线建档h5需要unionId"));',
     IDT.SERVER_CRED_COOKIE),
)


def classify_before_fix22(v, stmt):
    """把 fix22 的三态回报还原成改动前（(False, None)）—— 用于「改动前确实在风险桶」前置断言。"""
    orig = C.is_identifier

    def wrapped(s, stmt_):
        r = orig(s, stmt_)
        if r[0] is False and r[1] == IDT.ID_NOISE:
            return (False, None)
        return r

    C.is_identifier = wrapped
    try:
        return classify(v, stmt)
    finally:
        C.is_identifier = orig


def test_fix22_three_state_contract():
    """`is_identifier` 的三态回报：只有 fix21 **新加**的命名排除回报 id_noise。"""
    check("fix22 回报常量 == (False, id_noise)",
          C.NAME_CLASS_REJECT == (False, IDT.ID_NOISE), str(C.NAME_CLASS_REJECT))
    r = C.is_identifier("PASSPORT", 'o.userid = t.getStorageSync("PASSPORT")')
    check("fix22 user 臂 name-like 排除（fix21 ③）回报 id_noise",
          r == (False, IDT.ID_NOISE), str(r))
    for v, stmt in (("delivererPhone", "b=_mz(z,'jn',['orderNo',1,'x'])"),
                    ("FASTORDERNOLISTS", 'o.setData({orderNo:1})')):
        r = C.is_identifier(v, stmt)
        check(f"fix22 order 臂命名排除（fix21 ④）回报 id_noise: {v}",
              r == (False, IDT.ID_NOISE), str(r))
    r = C.is_identifier("businessCertificateCacheIdBase64", 'userId:"u",a=businessCertificateCacheIdBase64')
    check("fix22 既有的两条 user 臂命名排除**不**回报（刻意边界，见报告 ②残留）",
          r == (False, None), str(r))
    check("fix22 真标识值仍返回 (True, id_user)",
          C.is_identifier("37984296", 'uid:"37984296"') == (True, USER),
          str(C.is_identifier("37984296", 'uid:"37984296"')))
    check("fix22 无 identifier 语境的落选仍是 (False, None)",
          C.is_identifier("abcdefgh", 'x="abcdefgh"') == (False, None))


def test_fix22_risk5_rise_is_consumed():
    """14 行（fix21 收严后从 risk 2~3 升到 risk 5 的名字类噪音）改判 id_noise。"""
    for v, stmt, was in FIX22_ROWS:
        got = classify(v, stmt)
        before = classify_before_fix22(v, stmt)
        check(f"fix22 已不再进风险桶、改判 id_noise: {v[:34]}",
              got == {NOISE}, f"got={got}")
        check(f"fix22 改动前确实在风险桶（复现升级）: {v[:30]}",
              was in before, f"before={before}")


def test_fix22_change_surface_is_bounded():
    """改动面纪律：闸门**只在凭证判据接手时**生效，其余一律不动。"""
    # ① 真 openid（28 位 o 开头、首小写驼峰形状）不能被闸门吃掉 —— 它由下游
    #    is_openid_format 路径接手，必须仍是 id_user。
    for v, stmt in (("obNfG5WWt5foSqPpAgoT9UgrfGpw", 'openid:"obNfG5WWt5foSqPpAgoT9UgrfGpw"'),
                    ("ovKS05JrxKTIZrryu67uJyGoDIxs", 'openId: "ovKS05JrxKTIZrryu67uJyGoDIxs"')):
        got = classify(v, stmt)
        check(f"fix22 真 openid 仍判 id_user（不许降级成 id_noise）: {v[:20]}",
              USER in got and NOISE not in got, f"got={got}")
    # ② 带数字的真编号值：不在命名排除的射程内
    for v, stmt, slug in (("37984296", 'uid:"37984296"', USER),
                          ("130169571554503755", 'orderNo:"130169571554503755"', ORDER)):
        got = classify(v, stmt)
        check(f"fix22 真编号值判定不变: {v}", slug in got and NOISE not in got, f"got={got}")
    # ③ 只被既有命名排除拒掉、且当前不产出任何类型的值：**仍然是「不产出」**，
    #    不许因为本轮改动变成 id_noise（实测那会多改 406 行）。
    for v, stmt in (("pageMyPhoneAuth", 'o.userid="x",u=pageMyPhoneAuth'),
                    ("liveBindPhone", 'uid="x",f=liveBindPhone')):
        got = classify(v, stmt)
        check(f"fix22 「本来不产出」的值仍不产出: {v}", got == set(), f"got={got}")
    # ④ 既有的同类误报（不是 fix21 造成的升级、由既有排除/更早判据造成）一律不动。
    #    逐条钉住，防止后续无意放宽闸门（全量清单见报告 ③）。
    for v, stmt, slug in (
            ("userInfoV1", 'userId:"u",resetPassword:"",u=userInfoV1', IDT.CLOUD_CRED_PASSWORD),
            ("baseUrlV2", 'o.userid="x",resetPassword:"",u=baseUrlV2', IDT.CLOUD_CRED_PASSWORD),
            ("passWord2", 'uid="x",resetPassword:"",u=passWord2', IDT.CLOUD_CRED_PASSWORD),
            ("线下会员cookie信息",
             'console.log("线下会员cookie信息", e), i.globalData.offlineMembers.uid = e.data.uid;',
             IDT.SERVER_CRED_COOKIE)):
        got = classify(v, stmt)
        check(f"fix22 既存同类误报不在本轮改动面内: {v[:24]}", slug in got, f"got={got}")
    # ⑤ 裸关键词出口的**守卫顺序**：被值形守卫 continue 掉的值不许被闸门改成 id_noise。
    got = classify("WXOFFICIAL", 'cookie:"1",userid:"x",a=WXOFFICIAL')
    check("fix22 裸 cookie 出口的值形守卫仍先生效（WXOFFICIAL 不产出）", got == set(), f"got={got}")


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
