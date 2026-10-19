#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix41：cloud_cred_token(1205) 的**前缀命中**不再等于 token —— 体形（字符集 + 最短长度）不合格的落 1207。

病根
----
`is_cloud_token` = `startswith(前缀) + 长度 20..200`（只有 `npm_` 另有体形正则）。
前缀表里 `pk_test_` / `sk_test_` 这类「普通词 + 下划线」的写法会撞上 **CSS 类名列表**：
库内唯一一个 1205 值是 `pk_test_paper_title flex-c`（`pk_test_` + 单词 + 空格 + CSS 类），
它不是密钥，是模板里的类名串。

只读普查（`test-result/fix41/probe_token_prefixes.py`，7 个库的 data_item 全表按前缀 LIKE 扫）：
  · normal_quarkpan(_v2)：1205 桶 1 个值 / 1 条链接 —— 就是这条 CSS 类名列表；
  · pkgref_v2 / sibling_v2 / icp_v2 / unlist1：1205 桶 0 值，也**没有**任何值命中前缀表；
  · unlist2_miniapp：1205 桶 191 个值**全是 `npm_`**，且 191/191 已被既有 `npm_` 体形正则挡下
    （旧版本残留，当前代码不再产出）；
  · 除 `pk_test_` 外，**没有任何**前缀命中的值体形不是 token（同类问题在语料上只有这一处）。

改法（前缀命中后加两道体形判据，只看值自己）
----
  ① 字符集：前缀之后的**体**必须匹配 token 可见字符 `[A-Za-z0-9_\\-./+=:~]`（**含空格即否**）；
  ② 最短体长：按前缀族给「合理最短」——Stripe 密钥（`pk_/sk_/rk_ × live/test_`）的体
     至少 24 位字母数字（Stripe 的真密钥就是这个形状），用既有的
     `CLOUD_TOKEN_BODY_PATTERNS` 同款机制（前缀 → 体形正则）承载。

为什么判据落在 `process_cloud_token`（出口）而不是 `is_cloud_token`（入口）
----------------------------------------------------------------------------
主链这一段是 `if is_cloud_token(s)[0]: process_cloud_token(...); continue`。入口一旦返回
False，值就继续往链下走：本值的体含空格 ⇒ 落到 `process_generic_spaced_constant`，而它
是 `pass`（**不产出任何标签 = 静默丢弃**，fix32 已把这种「只摘标签」列为禁止项）。
所以入口粗筛（`is_cloud_token`）保持原样，形态细分与**显式**改判在出口完成：
不合格 → `cloud_cred_noise(1207, risk0)`。

归置（红线）
-----------
  · 去向只能是 1207(risk0)：不得升级到任何 risk≥4 桶；
  · 真 token 100% 保留 —— 由 `test_real_tokens_survive` 逐前缀钉住（含既有的
    `test_risk5_struct_fp.py` 断言口径：`is_cloud_token` 的返回值语义一字未改）。

用法: .venv/bin/python -X utf8 unit-tests/test_fix41_cloud_token_charset.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

TOKEN = IDT.CLOUD_CRED_TOKEN
NOISE = IDT.CLOUD_CRED_NOISE
_GUARD_ATTR = "is_cloud_token_value"
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

# 库内现场（同形合成值）：`pk_test_` + 单词 + 空格 + CSS 类名，坐在模板字符串里。
STMT = 'var s = { "panel-title": "pk_test_panel_title flex-c" };'


def _classify(v, stmt=STMT, guard_off=False):
    """跑一遍分类；`guard_off` 把本轮体形判据还原成「改动前」（恒真 ⇒ 一律 1205）。"""
    saved = getattr(C, _GUARD_ATTR, None)
    if guard_off and saved is not None:
        setattr(C, _GUARD_ATTR, lambda _s: True)
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        if guard_off and saved is not None:
            setattr(C, _GUARD_ATTR, saved)


# =========================================================
# ① 移出组：CSS 类名列表 / 体里有空白
# =========================================================
MOVED = [
    "pk_test_panel_title flex-c",          # 库内那一条的同形合成值
    "pk_test_demo_title flex-c",
    "sk_test_demo_card flex-row",
    "ghp_abcdefgh ijklmnopqrst",           # 别的前缀同样不许带空白
    "xoxb-1234 5678-abcdefghijkl",
]


def test_moved_values_are_no_longer_tokens():
    """① 前缀命中但体形不是 token：不再是 1205，且显式落 1207(risk0)。"""
    assert len(MOVED) == 5, len(MOVED)
    for v in MOVED:
        got = _classify(v)
        assert got == [NOISE], (v, got)
        assert TOKEN not in got, (v, got)


def test_destination_is_risk0_only():
    assert NOISE == 1207 and RISK["cloud_cred_noise"] == 0
    assert TOKEN == 1205 and RISK["cloud_cred_token"] == 5
    for v in MOVED:
        for label in _classify(v):
            assert RISK.get(_SLUG_OF.get(label, "").lower(), 0) == 0, (v, label)


def test_no_silent_drop():
    """① 归置必须是**显式**标签：链尾的 `process_generic_spaced_constant` 是 `pass`，
    入口返回 False 会让这个值**无声消失**（fix32 明确禁止「只摘标签」）。"""
    assert C.process_generic_spaced_constant.__doc__ is not None
    for v in MOVED:
        assert _classify(v) != [], v


# =========================================================
# ② 保护组：真 token 逐前缀 100% 保留
# =========================================================
REAL = [
    "ghp_" + "a" * 36,                     # github
    "gho_" + "a" * 36,
    "glpat-" + "b" * 20,                   # gitlab
    "xoxb-1234-5678-abcdefghijkl",         # slack
    "sk_live_" + "0" * 24,                 # stripe（体长正好 24）
    "pk_test_" + "AbCdEf0123456789AbCdEf01",   # stripe
    "rk_test_" + "AbCdEf0123456789AbCdEf01",   # stripe
    "npm_" + "d" * 36,                     # npm（36 位 Base62，既有体形正则）
    "pypi-" + "A" * 40,                    # pypi
    "hrku-" + "1" * 36,                    # heroku
    "SG." + "c" * 22,                      # sendgrid
    "shpat_" + "9" * 30,                   # shopify
    "oauth:" + "f" * 30,                   # twitch
    "dop_v1_" + "0" * 40,                  # digitalocean
    "sl." + "e" * 30,                      # dropbox
]


def test_real_tokens_survive():
    """② 真 token 一律保持 1205（形态合法的前缀族逐个钉住）。"""
    assert len(REAL) == 15, len(REAL)
    for v in REAL:
        assert C.is_cloud_token(v)[0] is True, v
        assert C.is_cloud_token_value(v) is True, v
        assert _classify(v) == [TOKEN], (v, _classify(v))
        assert _classify(v, guard_off=True) == [TOKEN], v      # 开关无关


def test_coarse_gate_contract_unchanged():
    """② 入口粗筛 `is_cloud_token` 的**返回值契约**一字未改（既有测试口径）。"""
    assert C.is_cloud_token("npm_" + "x" * 36) == (True, "npm")
    assert C.is_cloud_token("ghp_" + "a" * 36) == (True, "github")
    assert C.is_cloud_token("glpat-" + "b" * 20) == (True, "gitlab")
    assert C.is_cloud_token("SG." + "c" * 22) == (True, "sendgrid")
    assert C.is_cloud_token("ghp_" + "a" * 300) == (False, None)
    # 粗筛对 CSS 值仍然命中（出口才做形态细分）—— 这是「显式改判」方案的前提
    assert C.is_cloud_token("pk_test_panel_title flex-c")[0] is True


# =========================================================
# ③ Stripe 前缀的最短体长（24 位字母数字）
# =========================================================
def test_stripe_min_body_length():
    """③ 体长不足 24 的 Stripe 串不判 token；恰好 24 判。"""
    short = "pk_test_" + "a" * 23
    exact = "pk_test_" + "a" * 24
    assert len(short) == 31
    assert C.is_cloud_token_value(short) is False, short
    assert _classify(short) == [NOISE], _classify(short)
    assert C.is_cloud_token_value(exact) is True, exact
    assert _classify(exact) == [TOKEN], _classify(exact)
    # 其他前缀族不设这条最短体长（只加了 Stripe 族），gitlab 20 位体照旧
    assert C.is_cloud_token_value("glpat-" + "b" * 14) is True
    # 体形正则用同一套机制承载（前缀 → 体形正则），与 npm_ 一致
    assert C.CLOUD_TOKEN_VALUE_BODY_PATTERNS["pk_test_"].match("a" * 23) is None
    assert C.CLOUD_TOKEN_VALUE_BODY_PATTERNS["pk_test_"].match("a" * 24) is not None


# =========================================================
# ④ 字符集判据本身
# =========================================================
def test_charset_predicate_boundaries():
    assert C.is_cloud_token_value("pk_test_panel_title flex-c") is False
    assert C.is_cloud_token_value("ghp_" + "a" * 36) is True
    assert C.is_cloud_token_value("dop_v1_" + "0123456789abcdef" * 2) is True
    assert C.is_cloud_token_value("sl.abcdefghijklmnopqrstuvwxyz0") is True
    for weak in ("ghp_abc defghijklmnopqrst", "ghp_abc\tdefghijklmnopqrst",
                 "ghp_abc\ndefghijklmnopqrst", "SG." + "c" * 10 + " " + "d" * 10):
        assert C.is_cloud_token_value(weak) is False, weak
    # 粗筛没命中（长度/体形）时，值判据也必须是 False
    assert C.is_cloud_token_value("ghp_short") is False
    assert C.is_cloud_token_value("nothing") is False


# =========================================================
# ⑤ 开关对照：`guard_off` == 改动前
# =========================================================
def test_guard_is_the_change():
    for v in MOVED:
        assert _classify(v, guard_off=True) == [TOKEN], v
        assert _classify(v) == [NOISE], v
    for v in REAL:
        assert _classify(v, guard_off=True) == _classify(v) == [TOKEN], v


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
    print("fix41 cloud token 体形判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
