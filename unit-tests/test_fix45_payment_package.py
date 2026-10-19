#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix45：payment_package(2403) 的判据要过「值形 = 预支付 ID」闸门；不过闸门的显式落 payment_noise(2407)。

病根
----
`is_payment_param` 的 package 分支只看值前缀：

    if s_lower.startswith(PAYMENT_PACKAGE_PREFIX):      # "prepay_id="
        return (True, IDT.PAYMENT_PACKAGE)

**等号后面是什么完全不看**。于是一切以 `prepay_id=` 开头的字面量都是 2403 ——
包括「左半拼接片段」`"prepay_id=" + x`、判等哨兵 `"prepay_id=null" === pkg`、
以及测试夹具里的占位词。

只读普查（`test-result/fix45/step1_grouping.md`，两库 34 + 1 个去重值逐个打开真实源文件读 ±200 字符：

  · normal_quarkpan_v2  34 值 / 3035 次 / 约 765 应用；
  · unlist_package_reference_v2  1 值 / 229 次 / 113 应用。

分组（掩码值）：
  A 拼接片段：裸前缀 `prepay_id=`（v2 1 值 3009 次 745 应用；pkgref 1 值 229 次 113 应用）。
    全量确定性核验（逐个打开 3009+229 个链接的源文件）：值右侧 6 字符直方图 **100%** 以引号开头
    （`" + t.` 700 / `".conc` 687 / `"+e.mo` 586 …），即等号后紧跟字符串结束引号，写法是
    `package:"prepay_id=".concat(r)` / `package:"prepay_id=" + res.prepay_id`。
  B 判等哨兵：`"prepay_id=null" == t.data.prepay.package`（未绑定商户分支）、`"prepay_id=undefined"`。
  C 测试夹具/占位：`prepay_id=1` / `=2` / `=another` / `=legacy` / `=jqx` / `=upgrade` /
    `=member` / `=member-cancel` / `=recharge` / `=recharge-cancel` / `=calcSingle-0000000000` /
    `=1234567890abcdef`（同一文件里它还当假 appId 用）。
  D `wx` 形态（唯一真形态族，19 值，位置全是 `wx.requestPayment({package:"prepay_id=wx…"})` 的取值位）：
    尾长 34 纯 hex 16 个（微信统一下单返回值形态，即微信官方文档里那个示例串的形态）、
    尾长 17/15 且尾段是占位字母序 2 个、尾长 9 纯数字 1 个。

判据（本文件固化的边界）
------------------------
`prepay_id=` 之后必须**像一个预支付 ID**（`is_prepay_id_shaped`，纯值形、不看语境）：
  ① 等号后非空；
  ② 以 `wx` 开头（微信预支付 ID 的唯一前缀；语料 19 个真形态值 100% 命中，4 个非 wx 体里
     有 1 个正被当假 appId 用）；
  ③ `wx` 之后是 ASCII 字母数字、长度 ≥ 12、且至少含 1 位数字。
  为什么下界取 12：语料里占位族尾部 ≤ 11（`jqx` 3、`1` 1、`131430354` 9），wx 形态 ≥ 15，
     12 落在**空隙**里且远低于真实形态 33–34 ⇒ 只砍明确不是预支付 ID 的形态，不砍任何「像真的」。
     不设上界：语料最大 36，没有需要上界的证据（刻意不加无据规则）。
     要「≥1 位数字」：真值的 wx 后第一段是日期段，语料 19 个 wx 值全部含 8~14 位数字，
     纯字母的 wx 体 0 例（同 fix40 ⑤ 的占位字母表族）。

归置（红线）
------------
不过闸门的值**显式落 payment_noise(2407, risk0)**，而不是让判据返 False 静默下坠：
实测（`test_guard_is_the_change` 的开关对照）改动前这 18 个值里 16 个在关掉前缀分支后**不产出任何标签**，
另 2 个（`prepay_id=1` / `=2`）会平移进 pii_noise(2304)。所以必须显式 `continue`，
与 fix32/fix39/fix40b 的「只摘标签/静默消失」禁令同口径：不新增 risk≥4、不落别的 risk≥4 桶、不留无标签值。

真阳性 100% 保留：`wx` 形态 19 个值里，`is_prepay_id_shaped` 判 True 的 18 个一字不动（`got == had`），
唯一被改判的是尾长 9 的那个纯数字短形态（小程序 setting 页的假值，整值 11 字符）。

用法: .venv/bin/python -X utf8 unit-tests/test_fix45_payment_package.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PACKAGE = IDT.PAYMENT_PACKAGE
NOISE = IDT.PAYMENT_NOISE
PAY_ALL = (IDT.PAYMENT_REQUEST_PARAMS, IDT.PAYMENT_NONCE, IDT.PAYMENT_PAY_SIGN,
           PACKAGE, IDT.PAYMENT_SIGN_TYPE, IDT.PAYMENT_SECRET)
PAY_FAMILY = PAY_ALL + (NOISE,)
_GUARD_ATTR = "is_prepay_id_shaped"


def _risks():
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "constant_types.json"), encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"]] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risks()
_SLUG_OF = {v: k for k, v in vars(IDT).items()
            if isinstance(v, int) and k.isupper() and not k.startswith("CTG_")}


def _slugs(value, stmt, fix_on=True):
    """跑一遍分类；fix_on=False 时只关掉 fix45 的闸门（还原改动前：任何 `prepay_id=` 前缀都判 2403）。

    闸门是模块级名字，函数体在调用时才查 —— 关掉后本文件之外的判定逐位不变。
    RED 阶段名字还不存在时按「本来就关着」处理，断言照跑。
    """
    saved = getattr(C, _GUARD_ATTR, None)
    if not fix_on and saved is not None:
        setattr(C, _GUARD_ATTR, lambda _s: True)
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(value, 0, "test.js")])]
    finally:
        if not fix_on and saved is not None:
            setattr(C, _GUARD_ATTR, saved)


def _rows(value, stmt, fix_on=True):
    return [(r[0], r[1]) for r in
            C.perform_constant_classifying([stmt], [(value, 0, "test.js")])]


def _risk4plus(rows):
    return {(slug, content) for slug, content in rows
            if RISK.get(_SLUG_OF.get(slug, "").lower(), 0) >= 4}


# =========================================================
# 合成值（**不是**任何真实的预支付 ID；形状与语料分组一一对应）
# =========================================================
BARE = "prepay_id="
BARE_CONCAT = 'package: "prepay_id=" + t.data.data.prepay_id'
BARE_CONCAT2 = 'package: "prepay_id=".concat(r)'
BARE_SPLIT = 'u = n.package.split("prepay_id=")[1]'
SN_SENTINEL = 'if ("prepay_id=null" == t.data.prepay.package) return'
SN_SENTINEL2 = 'if ("prepay_id=undefined" === u.package) continue'
SN_FIXTURE = 'package: "prepay_id=jqx"'
SN_FIXTURE2 = 'package: "prepay_id=1"'
SN_FIXTURE3 = 'package: "prepay_id=calcSingle-0000000000"'
SN_FAKE_APPID = 'sa: JSON.stringify({appId:"wx1234567890abcdef",package:"prepay_id=1234567890abcdef"})'

# 占位/夹具族（C 组；这一组照抄语料里的**占位词/夹具**字面量 —— 它们不是凭证，也不是预支付 ID，
# 照抄是为了把分组固定住；wx 形态一律用合成值，绝不与任何真实预支付 ID 相同）
DROPPED = [
    (BARE, BARE_CONCAT, "左半拼接片段（v2 3009 次 / pkgref 229 次的主力）"),
    (BARE, BARE_SPLIT, "同族：split 参数里的片段"),
    (BARE, 't = ("prepay_id=" + o).slice(0)', "同族：括号里的拼接左半"),
    ("prepay_id=null", SN_SENTINEL, "未绑定商户的判等哨兵"),
    ("prepay_id=undefined", SN_SENTINEL2, "同族哨兵"),
    ("prepay_id=1", SN_FIXTURE2, "测试夹具：个位数字"),
    ("prepay_id=2", 'package: "prepay_id=2"', "同族夹具"),
    ("prepay_id=jqx", SN_FIXTURE, "测试夹具：3 字母占位"),
    ("prepay_id=legacy", 'package: "prepay_id=legacy"', "夹具单词"),
    ("prepay_id=upgrade", 'package: "prepay_id=upgrade"', "夹具单词"),
    ("prepay_id=member", 'package: "prepay_id=member"', "夹具单词"),
    ("prepay_id=member-cancel", 'package: "prepay_id=member-cancel"', "夹具：单词-单词"),
    ("prepay_id=recharge", 'package: "prepay_id=recharge"', "夹具单词"),
    ("prepay_id=recharge-cancel", 'package: "prepay_id=recharge-cancel"', "夹具：单词-单词"),
    ("prepay_id=another", 'package: "prepay_id=another"', "夹具单词"),
    ("prepay_id=calcSingle-0000000000", SN_FIXTURE3, "占位：单词-数字"),
    ("prepay_id=1234567890abcdef", SN_FAKE_APPID, "非 wx 体（同文件里还当假 appId 用）"),
    ("prepay_id=wx209901011", 'package: "prepay_id=wx209901011"', "wx + 9 位数字（语料里那个短形态）：过短"),
    ("prepay_id=wx2018000", 'package: "prepay_id=wx2018000"', "边界：wx 后 7 位"),
    ("prepay_id=wxabcdefghijklmnop", 'package: "prepay_id=wxabcdefghijklmnop"', "边界：wx + 16 位纯字母（无数字）"),
    ("prepay_id=wx", 'package: "prepay_id=wx"', "边界：只有前缀+wx"),
]

# wx 形态族（D 组，真形态 + wx 形态里的短体；值一律合成 —— 尾段刻意用**大写**，
# 真值是小写 hex，所以这些合成值形态上不可能与任何真实预支付 ID 相同；值侧判据按小写口径，大小写不影响结果）
KEPT = [
    ("prepay_id=wx20240101123456ABCDEF0123456789", "wx + 32 位（数字段 + hex，官方文档形态）"),
    ("prepay_id=wx20991231235959FEDCBA9876543210", "同族第二个合成值"),
    ("prepay_id=wx20990101abcdefg", "边界：wx 后 15 位（语料里 2 个这种 wx 形态值）"),
    ("prepay_id=wx20991231abcdefghi", "边界：wx 后 17 位"),
    ("prepay_id=wx209901011234", "边界：wx 后**正好 12 位**"),
    ("prepay_id=wx1234567890123456", "边界：wx 后 16 位纯数字（含数字即可）"),
]


# =========================================================
# ① 不过闸门 ⇒ 显式落 payment_noise(2407)，且改动前是 2403
# =========================================================
def test_placeholder_values_are_not_package():
    """① 占位/夹具/哨兵/短体内核：不再判 2403，且**显式**落 2407（不静默、不平移）。"""
    assert len(DROPPED) == 21, len(DROPPED)
    for v, sn, why in DROPPED:
        got = _slugs(v, sn)
        assert PACKAGE not in got, (why, v, got)
        assert NOISE in got, (why, v, got)                      # 显式落点，不是静默消失
        assert PACKAGE in _slugs(v, sn, fix_on=False), (why, v)  # 改动前确实是 2403


def test_dropped_values_gain_no_risk4_and_no_other_bucket():
    """① 被改判的值只留一行 2407：不新增 risk≥4、不落其他支付桶、不留无标签值。"""
    for v, sn, why in DROPPED:
        rows = _rows(v, sn)
        assert not _risk4plus(rows), (why, v, sorted(_risk4plus(rows)))
        assert [slug for slug, _c in rows if slug in PAY_FAMILY] == [NOISE], (why, v, rows)
        assert RISK["payment_noise"] == 0


def test_bare_prefix_is_never_a_package_value():
    """① 裸前缀在**三种真实写法**里都不判 2403（拼接 / split / 括号拼接），一律 2407。"""
    for v, sn, _why in [c for c in DROPPED if c[0] == BARE]:
        assert _slugs(v, sn) == [NOISE], (v, sn, _slugs(v, sn))


# =========================================================
# ② 真形态 100% 保留（wx 形态），改前改后逐位一致
# =========================================================
def test_wx_shaped_ids_are_kept_unchanged():
    """② `wx` 形态（尾长 ≥12 的字母数字体）仍是 2403，且与改动前**逐位一致**。"""
    assert len(KEPT) == 6, len(KEPT)
    for v, why in KEPT:
        sn = 'wx.requestPayment({package: "%s"})' % v
        got = _slugs(v, sn)
        assert got == [PACKAGE], (why, v, got)
        assert got == _slugs(v, sn, fix_on=False), (why, v)


def test_format_position_kept():
    """② 真形态在改动前所在的语法位置（`wx.requestPayment` 的 package 取值位）照旧。"""
    for sn in ('wx.requestPayment({timeStamp:"1",nonceStr:"n",package:"%s",signType:"MD5",paySign:"p"})' % KEPT[0][0],
               'sa: JSON.stringify({package:"%s"})' % KEPT[0][0],
               'package: "%s"' % KEPT[0][0]):
        assert PACKAGE in _slugs(KEPT[0][0], sn), (sn, _slugs(KEPT[0][0], sn))


# =========================================================
# ③ 闸门判据自身的边界（纯值形，不看语境）
# =========================================================
def test_guard_predicate_boundaries():
    fn = getattr(C, _GUARD_ATTR, None)
    assert fn is not None, "fix45 闸门 is_prepay_id_shaped 不存在"
    # 正例：wx + 字母数字、长度 ≥12、含数字
    for ok in ("wx20240101123456ABCDEF0123456789", "wx20990101abcdefg", "wx209901011234",
               "wx1234567890123456", "wxabcdefghijkl0123456"):
        assert fn("prepay_id=" + ok) is True, ok
    # 反例：空体 / 非 wx 体 / 太短 / 纯字母 / 含分隔符 / 大写前缀以外的东西
    for no in ("prepay_id=", "prepay_id=null", "prepay_id=1", "prepay_id=jqx",
               "prepay_id=calcSingle-0000000000", "prepay_id=1234567890abcdef",
               "prepay_id=wx", "prepay_id=wx209901011", "prepay_id=wx2018000",
               "prepay_id=wxabcdefghijklmnop", "prepay_id=wx0123456789-abcdef",
               "prepay_id=wx0123456789_abcdef", "prepay_id=wx0123456789 abcdef",
               "prepay_id=wx0123456789|abcdef", "prepay_id=w x0123456789abcdef",
               "prepay_id=wx0123456789abcdef=", "wx0123456789abcdef", "prepay_id=0123456789abcdef"):
        assert fn(no) is False, no
    # 大小写：值侧前缀与 wx 一律按小写口径（与 is_payment_param 的 s_lower 一致）
    assert fn("PREPAY_ID=WX0123456789ABCDEF") is True
    assert fn("Prepay_Id=Wx0123456789abcdef") is True


def test_guard_is_the_change():
    """③ 开关对照：闸门关掉 ⇒ 回到改动前（全部判 2403）；开 ⇒ 只有 wx 形态留 2403。"""
    for v, sn, why in DROPPED:
        assert PACKAGE in _slugs(v, sn, fix_on=False), (why, v)
        assert PACKAGE not in _slugs(v, sn), (why, v)
    for v, why in KEPT:
        sn = 'package: "%s"' % v
        assert PACKAGE in _slugs(v, sn, fix_on=False), (why, v)
        assert PACKAGE in _slugs(v, sn), (why, v)


# =========================================================
# ④ 归置红线：显式落点、risk0、不通向其他支付桶
# =========================================================
def test_noise_slug_is_the_explicit_landing():
    """④ 2407 是**显式**落点：被改判的每个值都恰好有一行 2407（不新增 risk≥4）。"""
    for v, sn, why in DROPPED:
        rows = _rows(v, sn)
        assert rows == [(NOISE, v)], (why, v, rows)
    # 2407 在本修复前不是任何值的落点（本轮新开的显式落点）
    assert RISK["payment_noise"] == 0


def test_other_payment_buckets_untouched():
    """④ 2401/2402/2404/2405/2406 的判据一行未动：同一批上下文里它们的产出与改动前相同。"""
    for v, sn in (("TIMESTAMP", 'o = "TIMESTAMP"'),
                  ("1755092100", 'timeStamp:"1755092100"'),
                  ("1234", '{signType: "1234", paySign: "abc", timeStamp: t}')):
        assert _slugs(v, sn) == _slugs(v, sn, fix_on=False), (v, sn)
        assert not [s for s in _slugs(v, sn) if s == NOISE], (v, sn)


def test_non_prepay_values_are_unaffected():
    """④ 不以 `prepay_id=` 开头的值与本闸门无关（判据只在原分支内生效）。"""
    for v, sn in (("package", 'o = "package"'), ("prepay_id", 'o = "prepay_id"'),
                  ("foo=bar", 'a = "foo=bar"'), ("wx1234567890abcdef", SN_FAKE_APPID)):
        assert _slugs(v, sn) == _slugs(v, sn, fix_on=False), (v, sn)


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
    print("fix45 payment_package 值形闸门：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
