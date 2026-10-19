#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix36：pii_phone_name(2302) 的**号段**校验。

病根
----
`pii_get_digit_type`（constants_classifier.py 约 L4473）对 11 位值的判据是
「11 位 + 全数字 + 首位 1 + 至少 3 个不同数字」——**没有号段校验**。于是只要形如
`1xxxxxxxxxx` 就出口 2302（risk 4）。工信部《电信网码号资源使用证书》的编号计划里：

  · 公众移动通信网号 = 13x ~ 19x（11 位）；
  · `10x` / `11x` / `12x` 是**服务号段**（100xx 运营商客服、110/119/120/114/123xx
    特种服务、125xx 等），不是公众移动通信网号；
  · `140`~`144` 是**13 位**物联网网号（`^140\\d{10}$` 联通 / `^141\\d{10}$` 电信 /
    `^142\\d{10}$`~`^143\\d{10}$` / `^144\\d{10}$` 移动），也不是 11 位手机号。

只读普查（v2 = normal_quarkpan_v2，pkgref = unlist_package_reference_v2，
见 test-result/fix36/probe_phone.py / probe_phone.out）：

  · v2：2302 桶 5,308 值 / 11,213 链接，其中 **615 值 / 1,809 链接**前两位是
    10/11/12 或三位是 140~144；分族：106（短信端口号）253、113（`113xxx0000`）198、
    103 60、100 25、123 25、140 1、142 4 等；
  · pkgref：701 值 / 2,581 链接，其中 **182 值 / 350 链接**同族，最大一族是
    `144` 97 个值（SDK 占位常量）。
  · 这些值都不是「手机号」，而是短信端口号 / 特种服务号 / 连号 ID / SDK 占位串。

判据（只加号段这条**否定**判据）
--------------------------------
  ① 11 位数字、首位 1、至少 3 个不同数字的形态一律不变；
  ② 只有前两位 ∈ {10, 11, 12} 或前三位 ∈ {140,141,142,143,144} 才**否定**；
  ③ 其余号段（145/146/147/148/149 与 15x~19x）**不收紧**：它们要么是上网卡/物联网
     的 11 位号段，要么本来就是公众移动通信网号，本判据一条都不碰。

归置（本轮的红线）
-----------------
  · 被否定的值**显式**落 pii_noise(2304, risk 0)（走数字开头链的专用出口），不许静默
    落选 —— 落选会让值继续往下走支付/凭证判据，也就是「平移」到别的桶；
  · 合法号段的 11 位号码 100% 保留 2302（回放里逐个核验）；
  · 不许有任何值反向进入 2302（本判据只会让出口更窄，理论上不可能）。

刻意不做（本轮授权之外）
-----------------------
  · 占位号（`13800138000`、尾部大量 0 的连号）属于不确定，本轮**不动** —— 它们过了
    号段判据就照旧留在 2302；
  · 不做「真实号段白名单」（13x~19x 逐段枚举）：会把 195/197/198 这类新号段与将来
    新分配的段一起误伤，而号段表是会变的。

用法: .venv/bin/python -X utf8 unit-tests/test_fix36_phone_prefix.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PHONE = IDT.PII_PHONE_NAME
NOISE = IDT.PII_NOISE

_GUARD_ATTRS = ("is_impossible_phone_segment",)

_HERE = os.path.dirname(os.path.abspath(__file__))


def _risks():
    """slug -> risk（constant_types.json 的 datatype_categories[].items[]）。"""
    with open(os.path.join(os.path.dirname(_HERE), "constant_types.json"),
              encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"].lower()] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risks()


def _guard_off():
    """把本轮新判据还原成「改动前」：号段守卫恒不生效（= 一律不算不可能号段）。

    与 `test_server_cookie_segmented_names.py` / `test_fix33_aksk_value_pairing.py` 同一
    约定 —— RED 阶段名字还不存在时按「本来就关着」处理，断言照跑。
    """
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if hasattr(C, "is_impossible_phone_segment"):
        C.is_impossible_phone_segment = lambda s: False
    return saved


def _guard_restore(saved):
    for name, fn in reversed(saved):
        setattr(C, name, fn)


def _classify(v, stmt, guard_off=False):
    saved = _guard_off() if guard_off else []
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        _guard_restore(saved)


def _digits(v, stmt):
    """按真扫的形状喂常量，返回 (slug, 内容) 对。"""
    return [(r[0], r[1]) for r in C.perform_constant_classifying([stmt], [(v, 0, "test")])]


# =========================================================
# ① 不可能号段：v2 615 值 / pkgref 182 值的代表（值全部合成，形态与库里同族）
# =========================================================
# 每条 = (合成值, 语境类型, 库内该族的规模)。语境按库里的真实形态写：
#   · 短信端口号：语句里是 `smsCode` / 端口号表；
#   · `113xxx0000`：来自某个应用的 constant/const.js 字符串表；
#   · `144` 107 位连号：SDK 占位常量（cms_sdk/RAW/mod.js）。
BAD_CASES = [
    # 106 短信端口号（v2 253 值 / pkgref 45 值，最大一族）
    ("10690300000", 'SMS_PORT_LIST = ["10690300000", "10690300001"]'),
    ("10690700999", 'this.smsSendUrl = "https://sms.example-corp.cn/send?port=10690700999"'),
    # 113xxxx0000（v2 198 值，全部来自一个应用的 constant/const.js；11 位、以 0000 结尾）
    ("11345600000", 'export const CHANNEL_ID = "11345600000"'),
    # 103/100/101/123/120 等 10x-12x 服务号段
    ("10312345678", 'var v = "10312345678"'),
    ("10012345678", 'n = "10012345678"'),
    ("12345678901", 'var v = "12345678901"'),
    ("12012345678", 'var v = "12012345678"'),
    # 140~144（13 位物联网网号，作 11 位手机号使用不可能）
    ("14012345678", 'var v = "14012345678"'),
    ("14212345678", 'var v = "14212345678"'),
    ("14401234567", 'export const DEFAULT_MOBILE = "14401234567"'),
]
# 库内各族的**真实规模**（fix36 只读普查，见 test-result/fix36/probe_phone.out）：
BAD_SCALE = {"normal_quarkpan_v2": (615, 1809), "unlist_package_reference_v2": (182, 350)}


def test_bad_segment_values_leave_2302_and_land_risk0():
    """① 不可能号段的 11 位数字：不再是 2302，且**显式**改判 pii_noise(2304, risk 0)。"""
    assert NOISE == 2304 and RISK["pii_noise"] == 0
    assert PHONE == 2302 and RISK["pii_phone_name"] >= 4
    for v, stmt in BAD_CASES:
        got = _classify(v, stmt)
        assert PHONE not in got, (v, got)
        assert got == [NOISE], (v, got)


def test_demotion_destination_is_risk0_only():
    """归置红线：改判只落 risk0 的 pii_noise，不许平移进别的 risk≥4 桶。"""
    slug_of = {val: name for name, val in vars(IDT).items()
               if isinstance(val, int) and name.isupper()}
    for v, stmt in BAD_CASES:
        got = _classify(v, stmt)
        assert got == [NOISE], (v, got)
        for label in got:
            assert RISK.get(slug_of.get(label, "").lower(), 0) == 0, (v, label)


def test_guard_is_the_change():
    """①/⑥ 关掉号段守卫 = 改动前：这些值全部回到 2302。"""
    for v, stmt in BAD_CASES:
        had = _classify(v, stmt, guard_off=True)
        assert PHONE in had, (v, had)
        assert _classify(v, stmt) == [NOISE], (v, stmt)


# =========================================================
# ② 合法号段 100% 保留（保护集）
# =========================================================
KEEP_CASES = [
    # 13x / 15x / 16x / 17x / 18x / 19x 的常见段
    "13800138000", "13912345678", "13112345678", "13312345678", "13012345678",
    "15112345678", "15812345678", "15912345678", "16612345678", "16712345678",
    "17012345678", "17112345678", "17212345678", "17312345678", "17512345678",
    "17612345678", "17712345678", "17812345678", "18012345678", "18812345678",
    "18912345678", "19012345678", "19112345678", "19512345678", "19612345678",
    "19712345678", "19812345678", "19912345678",
    # 14x 里**已分配**的 11 位号段：145 联通上网卡 / 146 物联网(11位) / 147 移动上网卡
    # / 148 移动 / 149 电信 —— 本轮一条都不收紧
    "14512345678", "14612345678", "14712345678", "14812345678", "14912345678",
]


def test_allocated_segments_all_kept_2302():
    """② 保护集 33 个合法号段的 11 位号码：逐条仍是 2302（不因本轮判据掉队）。"""
    assert len(KEEP_CASES) == 33, len(KEEP_CASES)
    for v in KEEP_CASES:
        got = _classify(v, 'phoneNumber: "%s"' % v)
        assert got == [PHONE], (v, got)
        assert _classify(v, 'phoneNumber: "%s"' % v, guard_off=True) == got, v


def test_placeholder_numbers_stay_2302():
    """② 占位号（尾部大量 0 / 连号）属于不确定，本轮**不动**：照旧 2302。

    `13800138000` 是教科书式的占位号，但它号段合法 —— 本轮的判据只看号段，
    所以它必须逐位不变（这条钉住「不会顺手把占位号一起删掉」）。
    """
    for v in ("13800138000", "13000000000", "13999999999", "13888888888"):
        assert _classify(v, '"%s"' % v) == [PHONE], v


# =========================================================
# ③ 判据本身的边界
# =========================================================
def test_predicate_boundaries():
    """③ `is_impossible_phone_segment` 正反例：只看号段，不看别的。"""
    assert C.is_impossible_phone_segment("10690300000") is True
    assert C.is_impossible_phone_segment("11345600000") is True
    assert C.is_impossible_phone_segment("10312345678") is True
    assert C.is_impossible_phone_segment("12345678901") is True
    assert C.is_impossible_phone_segment("14012345678") is True
    assert C.is_impossible_phone_segment("14401234567") is True
    # 已分配号段一律不是「不可能」
    for v in ("14512345678", "14612345678", "14712345678", "14812345678", "14912345678",
              "13800138000", "19912345678", "17012345678", "16612345678"):
        assert C.is_impossible_phone_segment(v) is False, v
    # 形态不对的值不该由它来判（长度/首位/字符集不满足 → 不是「11 位手机号形态」）
    for v in ("1401234567", "140123456789", "1401234567x", "114", ""):
        assert C.is_impossible_phone_segment(v) is False, v


def test_sfz_and_other_lengths_untouched():
    """③ 号段守卫只作用于 11 位手机号形态：18 位身份证/10 位、13 位数字都不受影响。"""
    # 13 位物联网号本身（140xxxxxxxxxx）不是 2302 出口的对象，开关无差别
    for v in ("1400123456789", "1069030000000"):
        assert _classify(v, '"%s"' % v) == _classify(v, '"%s"' % v, guard_off=True), v


# =========================================================
# ④ URL 查询串出口（第二个出口）同步
# =========================================================
def test_url_query_string_exit_also_demotes():
    """④ `process_url_query_string`（约 L4717，两个调用者）是 2302 的另一个出口。

    这里必须**把查询串本身**当值喂进去（`url_is_query` 只看值里有没有 `=`）：裸数字
    走的是数字开头链那个出口，测不到这一处。
    """
    for key in ("mobile", "phone", "telephone", "tel"):
        v = "%s=10690300000&v=1" % key
        stmt = "https://api.example-corp.cn/sms?%s" % v
        pairs = _digits(v, stmt)
        assert (NOISE, "10690300000") in pairs, (key, pairs)
        assert (PHONE, "10690300000") not in pairs, (key, pairs)
        saved = _guard_off()
        try:
            pairs_off = _digits(v, stmt)
        finally:
            _guard_restore(saved)
        assert (PHONE, "10690300000") in pairs_off, (key, pairs_off)
    # 合法号段在查询串出口照旧 2302
    v = "mobile=13800138000&v=1"
    pairs = _digits(v, "https://api.example-corp.cn/sms?%s" % v)
    assert (PHONE, "13800138000") in pairs, pairs


# =========================================================
# ⑤ 库内规模与族分布（只读普查数字，写死在断言里防止口径漂移）
# =========================================================
def test_corpus_scale_matches_probe():
    """⑤ 普查数字（probe_phone.out）与本判据命中的族一致：v2 615 值 / pkgref 182 值。"""
    assert BAD_SCALE["normal_quarkpan_v2"] == (615, 1809)
    assert BAD_SCALE["unlist_package_reference_v2"] == (182, 350)
    # 普查里 10/11/12 与 140~144 之外一个都不该被这条判据碰到
    assert all(C.is_impossible_phone_segment(v) == (v[:2] in ("10", "11", "12")
                                                    or v[:3] in ("140", "141", "142",
                                                                 "143", "144"))
               for v in KEEP_CASES + [v for v, _s in BAD_CASES])


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
    print("fix36 手机号号段判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
