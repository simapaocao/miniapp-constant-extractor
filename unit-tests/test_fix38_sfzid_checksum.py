#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix38：pii_sfzid_name(2301) 的 GB 11643-1999 校验位 / 省份码 / 日历合法性。

病根
----
`pii_get_digit_type`（constants_classifier.py 约 L4478）对 18 位值的判据只有
「18 位 + 末位数字或 X + 前 17 位全数字 + 至少 4 个不同数字 + 第 7~14 位像日期
（年 1900-2026、月 1-12、日 1-31）」。它**没有校验位、没有省级行政区代码、
也不看日历是否真实存在**（`20260230` 这种不存在的日子照样通过）。于是任何
「18 位数字 + 中间 8 位像日期」的串都被判成身份证并出口 2301（risk 5）。

只读普查（v2 = normal_quarkpan_v2，pkgref = unlist_package_reference_v2，
见 test-result/fix38/probe_sfzid.py / probe_sfzid.out）：

  · v2：2301 桶 129 值 / 275 链接 → GB 11643 三维全过 **96 值 / 197 链接**，
    应否定 **33 值 / 78 链接**（校验位失配 32、校验位+省份码同时失配 1）；
  · pkgref：16 值 / 24 链接 → 全过 9 值 / 15 链接，应否定 **7 值 / 9 链接**
    （校验位失配 5、校验位+省份码 1、仅省份码 1 —— 后一条是本题「有效省级行政区
    代码」这条判据单独带来的，任务书里「6 个」就是只看校验位的口径）。

判据（GB 11643-1999）
---------------------
  ① 校验位：前 17 位加权因子 (7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2)，和模 11 映射
     "10X98765432"；末位 `x` 大小写都接受；
  ② 省级行政区代码：前两位 ∈ GB/T 2260 的省级代码集（11..15 / 21..23 / 31..37 /
     41..46 / 50..54 / 61..65 / 71 / 81 / 82）；
  ③ 出生日期真实存在：含闰年（`20230229` 不存在、`20240229` 存在）。

归置（本轮的红线）
-----------------
  · 被否定的值**显式**落 pii_noise(2304, risk 0)：三维判据任一不过就改判，不许静默
    落选（落选会让 18 位数字继续往下走支付/凭证判据 = 平移）；
  · 校验合法的值 100% 保留 2301（回放里逐个核验保留率）；
  · 不许有值反向进入 2301（本判据只会让出口更窄，理论上不可能）。

刻意不做（本轮授权之外）
-----------------------
  · 示例号（`110101********1234` 这类）属于不确定：**校验通过就保留**，本轮不设
    「示例号名单」；
  · 不做 4~6 位县级行政区代码的复核（GB/T 2260 的子码会变，且大量真号的县级码
    在本库里根本查不到），也不做 15 位老身份证的扩展校验。

用法: .venv/bin/python -X utf8 unit-tests/test_fix38_sfzid_checksum.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

SFZ = IDT.PII_SFZID_NAME
NOISE = IDT.PII_NOISE

_GUARD_ATTRS = ("is_valid_sfz18",)

_HERE = os.path.dirname(os.path.abspath(__file__))

# 仅用**语境形态**（见 test-result/fix38/probe_snippet_shape.py）：库里这些值所在的语句
# 就是 `idCard: "…"` / `certNo: "…"` / `sfzh: "…"` 这类键值对，这里不抄任何真实值。
CTX = 'idCard: "%s"'

# 库内规模（probe_sfzid.out 写死，防止口径漂移）：
# db -> (值数, 链接数, 三维全过值数, 全过链接数, 应否定值数, 应否定链接数)
SFZ_SCALE = {
    "normal_quarkpan_v2": (129, 275, 96, 197, 33, 78),
    "unlist_package_reference_v2": (16, 24, 9, 15, 7, 9),
}

# ---------------------------------------------------------
# 本地生成合成号（**不取自库**）：只为钉住判据本身
# ---------------------------------------------------------
_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_MAP = "10X98765432"

PROVINCES = ("11", "12", "13", "14", "15", "21", "22", "23", "31", "32", "33", "34", "35",
             "36", "37", "41", "42", "43", "44", "45", "46", "50", "51", "52", "53", "54",
             "61", "62", "63", "64", "65", "71", "81", "82")


def _check_digit(body17):
    return _MAP[sum(int(c) * w for c, w in zip(body17, _W)) % 11]


def _synth(area6, year, month, day, seq):
    """按 GB 11643 生成一个**校验位正确**的合成号（末位由公式算出）。

    日期字段允许传不存在的日子（如 2 月 30 日）—— 生成器只算校验位，不做日历检查，
    这正是 ③ 那几条用例要的形态。
    """
    body = "%s%04d%02d%02d%03d" % (area6, year, month, day, seq)
    assert len(body) == 17, body
    return body + _check_digit(body)


def _risks():
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
    """关掉本轮判据 = 改动前：校验位/省份/日历一律不生效（只留旧的宽松日期检查）。

    与 `test_fix33_aksk_value_pairing.py` 同一约定 —— RED 阶段名字还不存在时按
    「本来就关着」处理，断言照跑。
    """
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if hasattr(C, "is_valid_sfz18"):
        C.is_valid_sfz18 = lambda s: True
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


def _bad_cases():
    """（合成值, 语境）：三个维度各来几条，每条只坏一个维度（或按注释说明坏哪几个）。"""
    return [
        # ① 校验位错：合法号末位换掉（其他 17 位一位不动）
        ("110101199003077051", 'idCard: "110101199003077051"'),
        (_synth("440301", 1985, 12, 31, 118)[:17] + "0",
         'certNo: "%s"' % (_synth("440301", 1985, 12, 31, 118)[:17] + "0")),
        # ② 不存在的日历日（校验位按公式算对，只有日历这一维不成立）
        (_synth("110101", 2026, 2, 30, 101), 'idCard: "%s"' % _synth("110101", 2026, 2, 30, 101)),
        (_synth("110101", 2023, 2, 29, 101), 'idCard: "%s"' % _synth("110101", 2023, 2, 29, 101)),
        (_synth("110101", 1988, 4, 31, 101), 'idCard: "%s"' % _synth("110101", 1988, 4, 31, 101)),
        (_synth("110101", 2021, 11, 31, 101), 'sfzh: "%s"' % _synth("110101", 2021, 11, 31, 101)),
        # ③ 无效省级行政区代码（30 / 09 都不在 GB/T 2260 省级码集里）
        (_synth("300101", 1990, 3, 7, 705), 'idCard: "%s"' % _synth("300101", 1990, 3, 7, 705)),
        (_synth("090101", 1990, 3, 7, 705), 'idCard: "%s"' % _synth("090101", 1990, 3, 7, 705)),
    ]


def test_bad_sfz_values_leave_2301_and_land_risk0():
    """① 不合法的 18 位值：不再是 2301，且显式改判 pii_noise(2304, risk 0)。"""
    assert NOISE == 2304 and RISK["pii_noise"] == 0
    assert SFZ == 2301 and RISK["pii_sfzid_name"] >= 4
    cases = _bad_cases()
    assert len(cases) == 8, len(cases)
    for v, stmt in cases:
        assert len(v) == 18 and v[:-1].isdigit() and (v[-1].isdigit() or v[-1] in "Xx"), v
        got = _classify(v, stmt)
        assert SFZ not in got, (v, got)
        assert got == [NOISE], (v, got)


def test_demotion_destination_is_risk0_only():
    """归置红线：改判只落 risk0 的 pii_noise，不许平移进别的 risk≥4 桶。"""
    slug_of = {val: name for name, val in vars(IDT).items()
               if isinstance(val, int) and name.isupper()}
    for v, stmt in _bad_cases():
        got = _classify(v, stmt)
        assert got == [NOISE], (v, got)
        for label in got:
            assert RISK.get(slug_of.get(label, "").lower(), 0) == 0, (v, label)


def test_guard_is_the_change():
    """①/⑥ 关掉三维判据 = 改动前：这些值全部回到 2301。"""
    for v, stmt in _bad_cases():
        had = _classify(v, stmt, guard_off=True)
        assert SFZ in had, (v, had)
        assert _classify(v, stmt) == [NOISE], (v, stmt)


# =========================================================
# ② 校验合法的值 100% 保留（保护集）
# =========================================================
def _keep_cases():
    """33 个省级代码各来一个（合成号，校验位由公式算出）+ 闰年与边界。"""
    out = [_synth(p + "0101", 1980 + (i % 40), 1 + (i % 12), 1 + (i % 28), 100 + i)
           for i, p in enumerate(PROVINCES)]
    out += [
        _synth("110101", 2000, 2, 29, 111),      # 2000 是闰年（被 400 整除）
        _synth("110101", 2024, 2, 29, 111),      # 2024 是闰年
        # 早边界：注意**改动前**就有一条「前 17 位至少 4 个不同数字」的形态闸门（本轮不动），
        # 所以顺序码要选得让 17 位里够 4 个不同数字（1900+0101+111 只有 {0,1,9} 三个，
        # 会被那条旧闸门拦掉 —— 那是既有口径，不是本轮判据）。
        _synth("110101", 1900, 1, 1, 234),
        _synth("110101", 2026, 1, 1, 111),       # 晚边界（旧判据的上界）
        _synth("110101", 1990, 12, 31, 111),
        _synth("820101", 1990, 3, 7, 705),       # 澳门
        _synth("710101", 1990, 3, 7, 705),       # 台湾
    ]
    return out


def test_valid_sfz_all_kept_2301():
    """② 保护集（34 个省/地区级代码 + 7 个边界）逐条仍是 2301，且开关无差别。"""
    cases = _keep_cases()
    assert len(cases) == 41, len(cases)
    for v in cases:
        assert C.is_valid_sfz18(v) is True, v
        got = _classify(v, CTX % v)
        assert got == [SFZ], (v, got)
        assert _classify(v, CTX % v, guard_off=True) == got, v


def test_lowercase_and_uppercase_x_both_accepted():
    """② 末位 `x` 大小写都接受：同一个号的两种写法都必须留在 2301。"""
    bodies = [v for v in _keep_cases() if v.endswith("X")]
    assert bodies, "保护集里要有末位 X 的号"
    for v in bodies:
        for cand in (v, v[:-1] + "x"):
            assert C.is_valid_sfz18(cand) is True, cand
            assert _classify(cand, CTX % cand) == [SFZ], cand


def test_example_like_but_valid_numbers_kept():
    """② 示例号属于不确定：校验通过就保留，本轮不设「示例号名单」。"""
    for v in (_synth("110101", 1990, 3, 7, 705), _synth("110101", 1990, 1, 1, 123),
              _synth("310101", 1990, 1, 1, 1)):
        assert _classify(v, CTX % v) == [SFZ], v


# =========================================================
# ③ 判据本身的边界
# =========================================================
def test_predicate_boundaries():
    """③ `is_valid_sfz18` 正反例：三个维度互不代偿。"""
    valid = _synth("110101", 1990, 3, 7, 705)
    assert C.is_valid_sfz18(valid) is True
    if valid.endswith("X"):
        assert C.is_valid_sfz18(valid[:-1] + "x") is True
    # 校验位错
    assert C.is_valid_sfz18(valid[:17] + "1") is False
    assert C.is_valid_sfz18(valid[:17] + "X") is False
    # 省份码错
    assert C.is_valid_sfz18(_synth("300101", 1990, 3, 7, 705)) is False
    assert C.is_valid_sfz18(_synth("000101", 1990, 3, 7, 705)) is False
    # 日历错（校验位算对也没用）
    assert C.is_valid_sfz18(_synth("110101", 2023, 2, 29, 101)) is False
    assert C.is_valid_sfz18(_synth("110101", 2026, 2, 30, 101)) is False
    assert C.is_valid_sfz18(_synth("110101", 2021, 13, 1, 101)) is False
    assert C.is_valid_sfz18(_synth("110101", 2021, 0, 1, 101)) is False
    # 形态不对的输入不该由它放行
    for bad in ("", "11010119900307705", "1101011990030770521", "11010119900307705y",
                "11010119900307a052", "11010119900307705 "):
        assert C.is_valid_sfz18(bad) is False, bad


def test_only_the_three_dimensions_are_used():
    """③ 判据只看校验位/省份/日历：顺序码、县区码一律不看。"""
    assert C.is_valid_sfz18(_synth("110101", 1990, 3, 7, 705)) is True
    assert C.is_valid_sfz18(_synth("110101", 1990, 3, 7, 1)) is True
    assert C.is_valid_sfz18(_synth("110101", 1990, 3, 7, 999)) is True
    # 县区码（第 5~6 位）不复核：110199 这种县码在本库里查不到，也不判负
    assert C.is_valid_sfz18(_synth("110199", 1990, 3, 7, 705)) is True


def test_loose_shape_checks_still_gate_first():
    """③ 旧的宽松形态检查仍是前置闸门：它判不出「18 位形态」的值**不**由本轮改判。

    这些值改动前返回的是「空」（继续往下走别的判据），本轮把判据挂在形态检查**之后**，
    所以它们的去向逐位不变（开关无差别）。
    """
    for v in ("202602301010123456",            # 第 7~10 位是 3010 → 年 > 2026
              "11010129900307705X",            # 年 2990 > 2026
              "110101199013077052",            # 月 13
              "110101199003327052",            # 日 32
              "111111111111111111",            # 不同数字 < 4
              "1101011990030770xx"):           # 非数字体
        assert _classify(v, '"%s"' % v) == _classify(v, '"%s"' % v, guard_off=True), v


# =========================================================
# ④ 与其他判据的边界
# =========================================================
def test_phone_and_email_paths_unaffected():
    """④ 18 位判据只作用于 18 位形态：11 位手机号与邮箱开关无差别。"""
    for v, stmt in (("13800138000", 'phone: "13800138000"'),
                    ("zhangsan@qq.com", 'email: "zhangsan@qq.com"')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), v


def test_corpus_scale_matches_probe():
    """⑤ 普查数字（probe_sfzid.out）写死：口径漂移时这条会先响。"""
    assert SFZ_SCALE["normal_quarkpan_v2"] == (129, 275, 96, 197, 33, 78)
    assert SFZ_SCALE["unlist_package_reference_v2"] == (16, 24, 9, 15, 7, 9)


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
    print("fix38 身份证 GB 11643 判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
