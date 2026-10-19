#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix33：cloud_cred_ak_sk_pair(1201) 裸关键词出口的「值侧配对」判据。

病根
----
1201 有**两个**出口：
  · 正规出口 `process_ak_sk_pair` —— 产出的值**本身就是一对** `AK=<ak>, SK=<sk>`；
  · `CONTEXT_KEYWORDS` 的裸关键词出口（`secret_key` / `secretkey` / `secretid` →
    1201，只对**数字开头**的通用链生效，见 `process_generic_digit_prefixed_constant`）——
    语句里出现这三个子串就出口，**从不问这个值自己是不是一对**。

只读普查（normal_quarkpan，1201 桶 959 条链接 / 362 个值）：
  · 340 个值是正规出口产出的 `AK=…, SK=…`（AK 16-40 alnum、SK 16-64 [A-Za-z0-9+/=]）；
  · 其余 **22 个裸值**（34 条链接）**全部**经裸关键词出口进来 —— 用 append_result 的调用者
    钉过（test-result/fix33/probe_exit.py）：22/22 都出自 `process_generic_digit_prefixed_constant`，
    主链的 AK/SK 配对检测与 `process_ak_sk_pair` 一条都没碰过它们；
  · 这 22 个里，**14 个值 / 15 条链接**曾被当作安全可删的噪音（原 SAFE_CASES）：每个链接的
    语句里 `secretkey`/`secret_key` **只是更长标识符的一部分**（`merchantContactSecretKey` /
    `secretkeyDefault` / `javaApiSecretKey` / `signSecretKey` / `secretKeyp`），独立的
    `secret_key` 一次都没有、`akid` 也没有，值的长度 7~36 且都够不上密钥材料形态；典型现场
    是一串**配置名清单**（`["1495550TJAxsg","log","283196TJBFPR",
    "merchantContactSecretKey","app_key",…]`）与几处 UUID/时间戳；
    **fix33b（review 缺陷 2）重测后是 11 个值 / 11 条链接**：其中 3 个是 UUID 形态的真密钥
    材料（`secretKey:` 键上），当初被删是两条判据缺陷造成的 —— 见下面第 ⑦ 组；
  · 6 个值是**密钥材料形态**（16-19 字符、b64 字母表，其中 `16RYPX678OQDGKH6` 一条值 8 条链接）
    —— 有歧义，**本轮不删**，只钉成已知残渣；
  · 2 个值所在语句里**看得见真配对**（`u.secret_key=(…)concat("40D*da3farOjdOpKBD370f")`
    里独立成词的 `secret_key`；BAIDU/TX 凭据表里出现 `AKID…` 这样的 AK 令牌）
    —— **本轮不删**，只钉成已知残渣。

fix33b（review 缺陷 2，两处 true-positive-loss）
-----------------------------------------------
  ① 材料形判据只认「16-40 alnum / 16-64 b64」，**分隔符形态**（UUID：`861E3648-B028-4B01-
     9A61-246B6082464B`，base64url）一律命不中 —— 坐在 `secretKey:` / `javaApiSecretKey:` /
     `SecretKey:` 键上的 UUID 真密钥被判成 pii_noise；
  ② `_has_standalone_word` 把**窗口左边界**当作「没有字符可判」而不是边界，于是
     `secretKey: "<uuid>"`（关键词正好落在窗口起点）判不出独立成词、被删，而在前面加一个
     `;` 又变成独立成词、保住 1201 —— 同一个 (值, 键) 只因窗口外多一个字符就换标签。
  修法：`is_credential_material_shape` 增加分隔符支（≥16 字符、含分隔符、含字母与数字）；
  `_has_standalone_word` 把窗口起点当作左边界（起点即满足左侧条件）。两处都只会让裸值**留下**
  （1201），不会删更多：11 个噪音值仍然删（第 ① 组）、6 个材料形态（第 ② 组）与 2 个看得见
  配对（第 ③ 组）仍然保持 1201，组合对零丢失（第 ④ 组）不变。

判据（只动这一个出口，两行守卫 + 一个不变量）
----
  ① 值侧配对要求（本轮的判据本体）：1201 只允许「值本身就是一对」的形态。
     正规出口的产出天然满足（下面 `is_ak_sk_pair_value` 与它逐字同源，长度与字符集口径
     直接复用 `is_access_key` / `is_sk_format`，**不看语境**），所以对 340 个组合值零影响；
  ② 裸关键词出口的裸值自己不是一对，于是只有两条豁免能把它留在 1201：
       · 值够得上**密钥材料形态** `is_credential_material_shape`（AK 形 16-40 alnum /
         SK 形 16-64 b64 字母表）—— 可能是被截断或没配成对的真材料，留着给人看；
       · 语句里**看得见真配对** `has_visible_ak_sk_pair_evidence`（独立的
         `secret_key`/`secretkey`/`secret_id`/`secretid`/`akid` 词，或 `AKID…`/`LTAI…`
         这类 AK 前缀令牌）—— 这一段文本自己就说明旁边有配对，值可能只是其中一半；
     两条都不满足 → **显式改判** `pii_noise(2304, risk 0)`（本函数对「无标签」的值本来就落
     这个桶，所以这就是「拿掉这个值凭关键词白得的 risk5 标签」，不是新造行、也不是静默丢弃）。

归置（本轮的红线）
-----------------
  · 只作用于**裸关键词出口**：`process_ak_sk_pair` 的 340 个组合值、LTAI/AKID 前缀配对、
    `isolated` AK 邻位配对逐位不变 —— 由「组合对不丢」那组钉住（回放同样是 0 对丢失）；
  · 不许把裸值**平移**进别的 risk≥4 桶（`session_key`/`password`/`cookie` 都不许）
    —— 由「归置只落 risk0」那组钉住；
  · 6 个材料形态裸值与 2 个「看得见真配对」裸值保持 1201 不动，钉成已知残渣 —— 这就是
    本轮搬走的是 **14 项 / 15 条链接**（而不是 16 项 / 19 条）的原因。

刻意不做（本轮授权之外）
-----------------------
  · **不做**语境式删除（探针口径）：任何「AK 有已知前缀 **或** 语境里同时出现 secretid 与
    secret_key 才留下」这类规则都不在本轮 —— DB 可见证据里那会把已验真的配对关系一起丢掉
    （前缀族占组合值的大头：normal_quarkpan 340 个组合值里 LTAI 136 个、AKID 59 个），
    与「值侧配对」这条安全口径的方向相反；
  · 不碰 `CONTEXT_KEYWORDS_2`（字母开头那条链）与 `secretid` 之外的任何关键词；
  · 不动 `process_ak_sk_pair` 的**配对搜索**口径（邻居窗口、is_sk_format 兜底），只在它出口
    加一条值侧不变量；
  · 不用 DB 顺序重建回放：本文件与回放脚本都只做 (值, 语境) 逐条重分类。

用法: .venv/bin/python -X utf8 unit-tests/test_fix33_aksk_value_pairing.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PAIR = IDT.CLOUD_CRED_AK_SK_PAIR
NOISE = IDT.PII_NOISE

_GUARD_ATTRS = ("is_ak_sk_pair_value", "is_credential_material_shape",
                "has_visible_ak_sk_pair_evidence")

_HERE = os.path.dirname(os.path.abspath(__file__))


def _risks():
    """slug -> risk（constant_types.json 的 datatype_categories[].items[]）。"""
    with open(os.path.join(os.path.dirname(_HERE), "constant_types.json"), encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"]] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risks()


def _classify(v, stmt, guard_off=False):
    """跑一遍分类；`guard_off` 把本轮三个新名字还原成「改动前」（恒不生效）。

    改动前的等效开关：豁免判据恒真（一律当材料形态 → 裸值照旧出口 1201），
    与 `test_server_cookie_segmented_names.py` / `test_fix30_hex_token_id_binding.py`
    同一约定 —— RED 阶段名字还不存在时按「本来就关着」处理，断言照跑。
    """
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if guard_off and hasattr(C, "is_credential_material_shape"):
        C.is_credential_material_shape = lambda s: True
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


def _classify_constants(stmt, consts):
    """按真扫的形状喂常量（邻位配对看的是 constants 列表的下标）。"""
    return [(r[0], r[1]) for r in
            C.perform_constant_classifying([stmt], [(v, 0, "test") for v in consts])]


# =========================================================
# ① SAFE：fix33b 重测后 **11 个值 / 11 条链接** —— 裸值 + 关键词只是更长标识符的一部分
# =========================================================
# (值, 语境, 该值在 normal_quarkpan 的链接数)。语境全部取自库里真实的 source_snippet
# （就是分类器看到的那个 512 字符窗口），未做任何「为通过判据」的改写。
# fix33b 说明：原 SAFE_CASES 是 14 个值 / 15 条链接，其中 3 个 UUID 形态的**真密钥材料**
# （`secretKey:` / `javaApiSecretKey:` / `SecretKey:` 键上）已按 review 缺陷 2 移到第 ⑦ 组
# 保留 1201；这里剩 11 个「关键词只是更长标识符的一部分、值也不是材料」的噪音。
SAFE_CASES = [
    # `merchantContactSecretKey` 只是字符串表里的一个**名字**：这一条链接住着 9 个值。
    ("1495550TJAxsg", 1), ("283196TJBFPR", 1), ("377248AEKmyR", 1), ("174002xOhbdf", 1),
    ("522QJpiAn", 1), ("5duCuwo", 1), ("893967EdmrjZ", 1), ("424482yxcXMh", 1),
    ("147104amowFt", 1),
    # `secretKeyp`（拼写错误的自造键）上是 12 位编号。
    ("356976257751", 1),
    # `signSecretKey` 上是日期串。
    ("2026-04-10-1407", 1),
]
SAFE_STMT = ('t = [ "1495550TJAxsg", "log", "283196TJBFPR", "merchantContactSecretKey", '
             '"app_key", "377248AEKmyR", "ws://192.168.0.13:8919/ws", "174002xOhbdf", '
             '"522QJpiAn", "5duCuwo", "qujing", "app_secret", "wx_appId", "contact_unit", '
             '"893967EdmrjZ", "424482yxcXMh", "147104amowFt", "project_name" ]')
SAFE_STMT_BY_VALUE = {
    "356976257751": 'n.globalData.driverdate.secretKeyp = "356976257751"',
    "2026-04-10-1407": 'signSecretKey: "2026-04-10-1407"',
}


def _safe_stmt(v):
    return SAFE_STMT_BY_VALUE.get(v, SAFE_STMT)


def test_safe_bare_values_no_longer_1201_and_land_risk0():
    """① 11 个 SAFE 值：不再是 1201，且显式改判到 pii_noise(2304, risk 0)。"""
    assert len(SAFE_CASES) == 11, len(SAFE_CASES)
    assert sum(n for _v, n in SAFE_CASES) == 11, SAFE_CASES      # 11 条链接（fix33b 重测）
    for v, _links in SAFE_CASES:
        stmt = _safe_stmt(v)
        got = _classify(v, stmt)
        assert PAIR not in got, (v, got)
        assert got == [NOISE], (v, got)


def test_demotion_destination_is_risk0_only():
    """归置红线：改判只落 risk0 的 pii_noise，不许平移进别的 risk≥4 桶。"""
    assert NOISE == 2304 and RISK["pii_noise"] == 0, (NOISE, RISK["pii_noise"])
    assert PAIR == 1201 and RISK["cloud_cred_ak_sk_pair"] == 5
    for v, _links in SAFE_CASES:
        got = _classify(v, _safe_stmt(v))
        assert got == [NOISE], (v, got)
        for label in got:
            slug = {val: name for name, val in vars(IDT).items()
                    if isinstance(val, int) and name.isupper()}.get(label, "")
            assert RISK.get(slug.lower(), 0) == 0, (v, label, slug)


# =========================================================
# ② 6 个密钥材料形态的裸值：保持 1201（已知歧义残渣）
# =========================================================
KEYLIKE_CASES = [
    # `secretKey: "16RYPX678OQDGKH6"` —— 8 条链接，最长的一条。
    ("16RYPX678OQDGKH6", 'secretKey: "16RYPX678OQDGKH6"', 8),
    # 独立的 `secret_key` 键（键名独立成词），值是 16 字符 b64。
    ("3TNLzhs4kDWs1kRU", 't.secret_key="3TNLzhs4kDWs1kRU"', 2),
    # appId 上是 19 位数字串（同语句另有真 secretKey 与 appKey）。
    ("1962478884650426437",
     'i || (o.default.init({\n            appKey: "Dg3oNfga6fB5AfOcS/hoTzUNinDID08W/w/fVvp2AtQ=",'
     '\n            secretKey: "3bd0fc46085e40fa9739b7f69c1b1f45",'
     '\n            appId: "1962478884650426437",\n            uuid: (0, r.getCommonParam)()'
     '.uuid,\n            sceneToken: "",\n            isStream: !0,\n            mode: 1\n        })', 2),
    ("01oP3Iq751443D45", 'secretkeyDefault: "01oP3Iq751443D45"', 1),
    ("1INTEMY6200JC1P1", 'secretKey: "1INTEMY6200JC1P1"', 1),
    ("3568034F9936C92A19",
     'g = (0, c.rsaEncrypt)("channelId=".concat(s, "&timestamp=").concat(p, '
     '"&channelSecretKey=").concat("3568034F9936C92A19"))', 1),
]


def test_keylike_bare_values_stay_1201_as_known_residual():
    """② 材料形态的裸值有歧义：本轮**不删**，保持 1201（钉成已知残渣）。"""
    assert len(KEYLIKE_CASES) == 6, len(KEYLIKE_CASES)
    assert sum(n for _v, _s, n in KEYLIKE_CASES) == 15, KEYLIKE_CASES
    for v, stmt, _links in KEYLIKE_CASES:
        got = _classify(v, stmt)
        assert got == [PAIR], (v, got)
        assert _classify(v, stmt, guard_off=True) == got, v      # 开关对本组无影响


# =========================================================
# ③ 2 个「看得见真配对」的裸值：保持 1201（14/15 而不是 16/19 的边界）
# =========================================================
# 合成 AKID：**拼接构造**，源码里不出现完整的 AK 令牌形态 —— GitHub 的
# push protection 按腾讯云 `AKID` + 长字母数字的形态拦截，写成完整字面量会被拒。
AKID = "AKID" + "Synthetic" + "FakeKey0123456" + "789Synthe"
SYN_SK = "FakeTencentSecret0123456789FakeT"

EVIDENCE_CASES = [
    # 独立的 `secret_key` 键，右侧是 concat 出来的秘密（本值只是其中一段）。
    ("40D*da3farOjdOpKBD370f",
     'u.secret_key = (0, r.default)("".concat(e, "-").concat(i).concat(l)'
     '.concat("40D*da3farOjdOpKBD370f"))', 2),
    # BAIDU/TX 凭据表：同一语句里有 AK 令牌 `AKID…`（真配对的一半）。
    ("46398026",
     'p.OCRRequest=Q,(0,o.default)(Q,"BAIDU_APP_ID","46398026"),'
     '(0,o.default)(Q,"BAIDU_API_KEY","FakeBaiduApiKey012345678"),'
     '(0,o.default)(Q,"BAIDU_SECRET_KEY","FakeBaiduSecretKey0123456789Fake"),'
     '(0,o.default)(Q,"TX_SECRET_ID","' + AKID + '"),'
     '(0,o.default)(Q,"TX_SECRET_KEY","' + SYN_SK + '")', 2),
]


def test_visible_pair_evidence_bare_values_kept():
    """③ 语句里看得见真配对（独立词 / AK 前缀令牌）→ 保持 1201，本轮不删。"""
    assert len(EVIDENCE_CASES) == 2, len(EVIDENCE_CASES)
    assert sum(n for _v, _s, n in EVIDENCE_CASES) == 4, EVIDENCE_CASES
    for v, stmt, _links in EVIDENCE_CASES:
        got = _classify(v, stmt)
        assert got == [PAIR], (v, got)
        assert _classify(v, stmt, guard_off=True) == got, v


# =========================================================
# ④ 组合对（正式出口）逐位不变：LTAI / AKID / 纯语境配对，一对都不许丢
# =========================================================
PAIR_CASES = [
    # LTAI（阿里云 AK 前缀）：normal_quarkpan 340 个组合值里 136 个是这一族。
    ('var o={ak:"LTAI5tAbCdEfGhIjKlMnOpQr", sk:"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/="}',
     ("LTAI5tAbCdEfGhIjKlMnOpQr", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=")),
    # AKID（腾讯云 AK 前缀）：同库 59 个组合值是这一族。
    ('var o={ak:"' + AKID + '", sk:"' + SYN_SK + '"}',
     (AKID, SYN_SK)),
    # 无前缀、纯语境（accessKeyId 是 AK 语境词）：探针口径里最容易被语境规则误伤的一族。
    ('var o={accessKeyId:"9q7Wx2AbCdEfGhIjKlMn", sk:"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/="}',
     ("9q7Wx2AbCdEfGhIjKlMn", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=")),
]


def test_combined_pairs_unchanged_zero_pair_loss():
    """④ 正规出口的组合对：值形态、标签、开关敏感性全部逐位不变（0 对丢失）。"""
    for stmt, (ak, sk) in PAIR_CASES:
        want = "AK=%s, SK=%s" % (ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        assert (PAIR, want) in got, (want, got)
        assert _classify_constants(stmt, [ak, sk]) == got
        assert C.is_ak_sk_pair_value(want) is True, want            # 值侧要求天然满足


def test_pair_exit_guard_is_invariant_not_a_filter():
    """正规出口加的是**不变量**：真配对（含只有一半过不了值侧格式的合成串）不受影响，
    而合成串一旦不是一对就不出口 —— 这条只在 `process_ak_sk_pair` 一处生效。"""
    for stmt, (ak, sk) in PAIR_CASES:
        res = []
        C.process_ak_sk_pair(ak, stmt, sk, stmt, "test", "test", 0, res)
        assert res and res[0][0] == PAIR, res
    # 合成串：SK 只有 8 字符（过不了值侧格式）→ 不变量拦下，不产出 1201
    res = []
    C.process_ak_sk_pair("LTAI5tAbCdEfGhIjKlMnOpQr", "x", "AbCd1234", "x", "aliyun",
                         "test", 0, res)
    assert res == [], res


# =========================================================
# ⑤ 值侧判据本身的边界（三条判据都是值/语句的**形态**问题，不看别的）
# =========================================================
def test_value_side_predicate_boundaries():
    """⑤ `is_ak_sk_pair_value` / `is_credential_material_shape` 的正反例。

    `is_ak_sk_pair_value` 与正规出口**同源**：长度与字符集直接复用
    `is_access_key` / `is_sk_format` 的口径（Python 的 `str.isalnum()` 含 CJK 字母），
    所以库里那个 `AK=刷新阿里云sls的临时token, SK=/recommend/mygift` 也算一对 —— 刻意
    保持同源，避免判据比产出更严而把真行判成丢对。
    """
    ak, sk = "LTAI5tAbCdEfGhIjKlMnOpQr", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/="
    assert C.is_ak_sk_pair_value("AK=%s, SK=%s" % (ak, sk)) is True
    assert C.is_ak_sk_pair_value("AK=刷新阿里云sls的临时token, SK=/recommend/mygift") is True
    for bad in ("", "AK=%s" % ak, "SK=%s" % sk, "AK=%s, SK=%s" % ("short", sk),
                "AK=%s, SK=%s" % (ak, "has space in it 0123456"),
                "AK=%s,SK=%s" % (ak, sk), "AK=%s, SK=%s " % (ak, sk),
                "AK=%s, SK=%s" % (ak, "x" * 65)):
        assert C.is_ak_sk_pair_value(bad) is False, bad
    # 材料形态：AK 形（16-40 alnum；结尾 `=` / 含 `*` 的不算）
    assert C.is_credential_material_shape("16RYPX678OQDGKH6") is True
    assert C.is_credential_material_shape("3568034F9936C92A19") is True
    assert C.is_credential_material_shape("1962478884650426437") is True
    assert C.is_credential_material_shape("01oP3Iq751443D45") is True
    # fix33b：分隔符形态（UUID / base64url）也是材料 —— review 缺陷 2 的第一处
    assert C.is_credential_material_shape("5cb55d91-07e5-46cc-84f8-92189ecded5e") is True
    assert C.is_credential_material_shape("861E3648-B028-4B01-9A61-246B6082464B") is True
    assert C.is_credential_material_shape("8dd7913b-c4fe-4182-b1aa-af498ac9d69d") is True
    assert C.is_credential_material_shape("AbCd-EfGh_IjKl.Mn0p-QrSt") is True
    # 不够材料形态：太短、日期串（无字母）、含 `*`、纯数字 8 位、词形短名
    for weak in ("356976257751", "5duCuwo", "522QJpiAn", "2026-04-10-1407",
                 "40D*da3farOjdOpKBD370f", "46398026", "merchant-contact-key",
                 "2026-04-10-1407-1234", "ab-cd-ef-1234"):
        assert C.is_credential_material_shape(weak) is False, weak
    # 看得见真配对：独立词 vs 更长标识符内部的子串
    assert C.has_visible_ak_sk_pair_evidence('u.secret_key="x"') is True
    assert C.has_visible_ak_sk_pair_evidence('p.secretKey="x"') is True
    assert C.has_visible_ak_sk_pair_evidence(
        '"TX_SECRET_ID","' + AKID + '"') is True
    assert C.has_visible_ak_sk_pair_evidence('"TX_SECRET_ID","AKIDSyntAbc"') is False  # 尾巴太短
    assert C.has_visible_ak_sk_pair_evidence('"TX_SECRET_ID"') is False
    assert C.has_visible_ak_sk_pair_evidence('a.secretKeyp="x"') is False
    assert C.has_visible_ak_sk_pair_evidence('"merchantContactSecretKey"') is False
    assert C.has_visible_ak_sk_pair_evidence('javaApiSecretKey: "x"') is False
    assert C.has_visible_ak_sk_pair_evidence('secretkeyDefault: "x"') is False
    # fix33b：窗口**起点当作左边界**（review 缺陷 2 的第二处）。原先起点处「没有字符可判」
    # 被当作「判不出独立成词」，于是同一个 (值, 键) 只因窗口外多一个字符就换标签：
    #   `secretKey: "<uuid>"`（关键词落在 512 字符切片起点）→ PII_NOISE；
    #   `;secretKey: "<uuid>"`               → 1201。
    # 现在起点即满足左侧条件：两条一律判独立成词（= 有证据 → 保留 1201）。
    assert C.has_visible_ak_sk_pair_evidence('secretKey: "x"') is True
    assert C.has_visible_ak_sk_pair_evidence('SecretKey: "x"') is True
    assert (C.has_visible_ak_sk_pair_evidence('secretKey: "x"')
            == C.has_visible_ak_sk_pair_evidence(';secretKey: "x"') is True)
    assert (C.has_visible_ak_sk_pair_evidence('secret_key="x"')
            == C.has_visible_ak_sk_pair_evidence('x.secret_key="x"') is True)
    # 起点边界只管左侧：右侧仍须看得见非词字符（关键词后面还接着更长标识符 ⇒ 不是独立词）
    assert C.has_visible_ak_sk_pair_evidence('secretKeyp: "x"') is False
    assert C.has_visible_ak_sk_pair_evidence('secretkeyDefault="x"') is False
    # 普通词里的 AK 前缀不算令牌（`ASIA` 后面紧跟的不是 AK 形态字符）
    assert C.has_visible_ak_sk_pair_evidence('region:"asia-southeast-1"') is False
    # 独立成词的 `akid` 本身就是证据（键名 `"AKID"` / `akId: "…"` 都算「这段文本在命名 AK」）
    assert C.has_visible_ak_sk_pair_evidence('"AKID"') is True
    assert C.has_visible_ak_sk_pair_evidence('{akId: "x"}') is True
    assert C.has_visible_ak_sk_pair_evidence('x.akidKey="y"') is False     # 更长标识符内部


# =========================================================
# ⑥ 对照与作用面：搬走这件事**就是**这条判据干的；别的出口一行未改
# =========================================================
def test_guard_is_the_change():
    """⑥ 关掉豁免判据 = 改动前：① 组的值回到 1201；③ 组与 ④ 组不受开关影响。"""
    for v, _links in SAFE_CASES:
        had = _classify(v, _safe_stmt(v), guard_off=True)
        assert had == [PAIR], (v, had)
        assert _classify(v, _safe_stmt(v)) == [NOISE], v


def test_exit_scope_is_the_bare_keyword_exit_only():
    """⑥ 只有裸关键词出口求值：`bucket` / `region` / `secretid` 之外的语境逐位不变。"""
    # 同一条语句里带 bucket 的短值：仍走桶名出口的既有口径（与本轮判据无关）
    v = "5duCuwo"
    stmt = 'ossBucket:"my-bucket-name", names:["5duCuwo","log"]'
    assert _classify(v, stmt) == _classify(v, stmt, guard_off=True)
    # 值本身带 `/` 时关键词出口本来就不出口（既有守卫），开关无差别
    v2 = "147104/amow"
    stmt2 = '"merchantContactSecretKey","147104/amow"'
    assert _classify(v2, stmt2) == _classify(v2, stmt2, guard_off=True)


# =========================================================
# ⑦ fix33b（review 缺陷 2）：分隔符形态的密钥材料 + 窗口左边界确定性
# =========================================================
# 病根一（材料形判据）：`is_credential_material_shape` 只认「16-40 alnum」或「16-64 b64
# 字母表」，带连字符的 UUID 一律命不中 —— 坐在 `secretKey:` / `javaApiSecretKey:` /
# `SecretKey:` 键上的真密钥被判成 pii_noise(2304)。
# 病根二（窗口边界）：`_has_standalone_word` 要求关键词左右**都看得见**非词字符，关键词落在
# 512 字符切片起点时左边没有字符，于是判不出「独立成词」→ 没有真配对证据 → 同样被删；
# 而在同一个键前面加一个 `;`（无关字符）就变成 1201 —— 同一个 (值, 键) 换标签。
SEPARATED_MATERIAL_CASES = [
    # 库内两条窗口整段就是 `secretKey: "<uuid>"` / `SecretKey: "<uuid>"`（关键词落在窗口起点）
    # —— 病根二 + 病根一同时命中：修复前 PII_NOISE。
    ("5cb55d91-07e5-46cc-84f8-92189ecded5e",
     'secretKey: "5cb55d91-07e5-46cc-84f8-92189ecded5e"', 2),
    ("8dd7913b-c4fe-4182-b1aa-af498ac9d69d",
     'SecretKey: "8dd7913b-c4fe-4182-b1aa-af498ac9d69d"', 1),
    # 同一个 (值, 键) 只多一个 `;` —— 修复前后必须**同标签**（窗口外字符不影响判定）
    ("5cb55d91-07e5-46cc-84f8-92189ecded5e",
     ';secretKey: "5cb55d91-07e5-46cc-84f8-92189ecded5e"', 2),
    # 窗口中部、关键词只是更长标识符的一部分（`javaApiSecretKey`）—— 病根一单独命中：
    # 独立词证据拿不到，只能靠材料形留下。
    ("861E3648-B028-4B01-9A61-246B6082464B",
     'javaApiSecretKey: "861E3648-B028-4B01-9A61-246B6082464B"', 1),
]


def test_separated_material_values_kept_1201():
    """⑦ 分隔符形态（UUID）的真密钥材料：不再是 pii_noise，保持 1201。"""
    assert len(SEPARATED_MATERIAL_CASES) == 4, len(SEPARATED_MATERIAL_CASES)
    for v, stmt, _links in SEPARATED_MATERIAL_CASES:
        assert C.is_credential_material_shape(v) is True, v
        assert _classify(v, stmt) == [PAIR], (v, _classify(v, stmt))


def test_window_edge_does_not_flip_label():
    """⑦ 同一个 (值, 键)：窗口起点与前面多一个无关字符，判定必须一致（都留 1201）。"""
    for key in ("secretKey", "SecretKey"):
        for v in ("5cb55d91-07e5-46cc-84f8-92189ecded5e",):
            a = _classify(v, '%s: "%s"' % (key, v))
            b = _classify(v, ';%s: "%s"' % (key, v))
            assert a == b == [PAIR], (key, a, b)


def test_separated_branch_is_not_a_blanket_keep():
    """⑦ 分隔符支只放行材料形：日期串 / 全数字段 / 短词形名一律仍然删（第 ① 组已钉）。"""
    for weak in ("2026-04-10-1407", "2026-04-10-1407-1234", "ab-cd-ef-1234",
                 "merchant-contact-key"):
        assert C.is_credential_material_shape(weak) is False, weak
    assert _classify("2026-04-10-1407", 'signSecretKey: "2026-04-10-1407"') == [NOISE]


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
    print("fix33 AK/SK 值侧配对判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
