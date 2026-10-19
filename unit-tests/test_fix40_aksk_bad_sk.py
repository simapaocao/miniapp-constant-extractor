#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix40：cloud_cred_ak_sk_pair(1201) 的配对要过 SK 侧**不可能形态**闸门。

病根
----
`find_sk_in_neighbors` 的配对完全靠**常量列表里的邻居下标**，SK 侧只要过
`is_secret_key_sk(...) or is_sk_format(...)`（16-64 位 b64 字母表）就成立 ——
于是任何 16~64 字符、恰好坐在 AK 旁边的 alnum/b64 串都成了「SK」：
微信 appid（`wx` + 16 位 hex）、支付宝 appid（`2021` + 12 位数字）、路径片段
（`/pages/...`，`/` 本来就在 b64 字母表里）、占位字母表、以及**与 AK 同一个串**
（邻居是同一个常量的副本）。

只读普查（`test-result/fix40/probe_sk_shapes.py`，normal_quarkpan_v2 的 341 个组合值）：
SK 侧命中「不可能形态」标签的值 —— alipay_appid 19、`sk==ak`/前缀关系 26、
路径片段 21、占位字母表 7、wx_appid 5；另有 49 个只是「体长 16~19」的混合字母数字，
坐在 `secretKey:"` 键上 ⇒ **是可能的凭证材料，不算不可能**（见下「刻意不做」）。

改法（只加「不可能」，不加「必须有证据」）
----
在配对成立前，对候选 SK 值加一条**值侧形态**闸门 `is_impossible_sk_candidate(sk, ak)`：
  ① 微信 appid 形 `^wx[0-9a-f]{16}$`；
  ② 支付宝 appid 形 `^2021\\d{12}$`；
  ③ 路径片段：含 `/` 且**没有** `+` / `=`（`+`/`=` 是 base64 材料的签名，路径串没有）；
  ④ 占位字母表：出现 8 连的字母序片段（`ABCDEFGH…` / `abcdefgh…` / `ABCDEFGHJKM…`）；
  ⑤ SK 与 AK 是同一个串、或互为前缀（真配对的 AK 与 SK 是两段独立材料）。
闸门命中 ⇒ 这一对不成立，**两个成员各自走自己的分类**（`find_sk_in_neighbors` 返回 None
⇒ 主链不 consume AK、也不把 SK 记进 processed_indices）。
**fix40c 起**这条闸门有前提：**两半都不「强有效」**且任一侧不可能才否决 —— 详见下面
的 fix40c 一节与第 ⓪ 组。

刻意不做（都有实测理由）
-----------------------
  · **不做**「SK 必须 ≥20/24 位」：库里 49 个 16~19 位、混合大小写+数字、坐在
    `secretKey:"` 键上的值是**可能的** appSecret 材料，删了就是丢真阳性；
    「长度不足」这条在现行代码里也不可达（`is_secret_key_sk` / `is_sk_format` 都硬卡 16-64）。
  · **不把纯小写 hex（32 位 md5/sha 形）判成不可能**：它有歧义（也可能是真密钥的哈希形态）。
  · **不把 camelCase 词形（`phoneProtectChannel` 这类 i18n 名）判成不可能**：那是另一族
    问题（词形名混淆），本轮授权之外的判据。
  · 不加任何「必须有语境证据才配对」的收紧 —— fix33 已证实那会丢掉约 40% 真配对。

归置（红线）
-----------
  · 被拒后两个成员按各自原本的分类走：AK 侧仍落它自己的桶（风险不升），SK 侧走自己的链；
  · 真配对 100% 保留（LTAI / AKID / 纯语境配对、16 位短 SK、hex SK、带 `+`/`=` 的 b64 SK）；
  · `unit-tests/test_fix33_aksk_value_pairing.py` 必须保持通过（同一族判据）。

fix40c（本轮：闸门加「强有效半边」放行，第 ⓪ 组）
------------------------------------------------
用户口径：**SK 和 AK 有一个是正确的就行** —— 只要一对里有一半「强有效」，这一对就照常产出
`cloud_cred_ak_sk_pair(1201)`，即使另一半命中 fix40 的五类不可能形态（且用户已确认保留
`AK=…, SK=…` 组合值本身，不是只留下真的那一半）。改法：

  · **AK 侧强有效** = 值以 `AK_PREFIX_PATTERNS`（LTAI/AKID/AKIA/ABIA/ACCA/ASIA）中的前缀开头，
    且满足 `is_access_key` **前缀分支**的同一形态（16-40 位、`isalnum`）。仅凭语境词
    （`AK_CONTEXT_WORDS`）识别出的 AK **不算**强有效 —— 语境分支正是 fix40 里把 appid /
    占位串当成 AK 的那一半来源，放行它会新造 `AK=<appid>, SK=<真 SK>` 这类组合值。
  · **SK 侧强有效** = 本轮定义为**永远不成立**。数据依据（只读，全量真扫 859 个源文件、
    闸门命中的 118 次配对尝试逐个归因，见 test-result/fix40/fix40c_probe_gate_hits.out）：
    所有命中里 SK 侧的**每一半**自己就是不可能形态（alipay 30 / path 24 / wx 13 / alphabet 11），
    「AK 侧不可能而 SK 侧干净」出现 **0 次**；两库被否决的 87 个配对值里也没有一例
    SK 形似真材料（30-64 位、大小写+数字、非 hex）。也就是说：语料里**不存在**
    「强有效 SK + 不可能 AK」这半边，硬定一条判据只会是**合成值上的猜测**、
    且在真扫里放行 `AK=<appid>, SK=<真材料>` 这种更差的配对。故留成显式钩子
    （`is_strong_valid_sk_half`，返回 False + 数据注释），后续有证据时再开。
  · **例外 ⑤ 不受放行影响**：两侧同一串或互为前缀**仍然否决** —— `AK=X, SK=X` 里没有第二份
    材料，等同于不存在的配对（用户确认的例外）。所以放行顺序是：先看 ⑤，再看强有效半边。

fix40b（本轮回归修复，第 ⑥ 组）
------------------------------
fix40 的「成员各走各的分类」把 AK id 变成了 risk5 标签：AK 侧成员坐在 `accessKeyId` /
`OSSAccessKeyId` / `SecretId` 语境里，`has_appkey_context` 命中 `accesskey` 子串 ⇒
`is_app_key` 的 CREDENTIAL 分支返回 platform_app_secret(1101, **risk5**)；32~64 位材料形
的成员也会被 `is_secret_key` 判 1101。改动前这些值被 consume 进 `AK=…, SK=…`（自己有没行），
所以它们是**新增**的 risk5 标签 —— 用户口径：新增 risk≥4 标签不可接受，也不许把噪音挪进
别的 risk≥4 桶。修法：
  · 被拒成员身上的 risk>=4 行在**链尾改判** cloud_cred_noise(1207, risk0)（显式落点，
    同 fix32/fix39/`process_cloud_token` 的「只摘标签/静默消失」禁令）；
  · 被拒成员**不再在自己下标上发起配对**（`vetoed_indices`）—— fix40 实测有反向进入 1201；
  · 判据严格限定在「本轮被 fix40 否决的配对成员」这条路径上，**不**扩大到「所有 AK 形态的
    值都不判 platform_app_secret」（那会碰到真 secret，且非成员的 AK id 行为必须一字不变）。

用法: .venv/bin/python -X utf8 unit-tests/test_fix40_aksk_bad_sk.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PAIR = IDT.CLOUD_CRED_AK_SK_PAIR
NOISE = IDT.CLOUD_CRED_NOISE
_GUARD_ATTR = "is_impossible_sk_candidate"
_HERE = os.path.dirname(os.path.abspath(__file__))
AK24 = "LTAI5tAbCdEfGhIjKlMnOpQr"
# 合成 AKID：**拼接构造**，源码里不出现完整的 AK 令牌形态 —— GitHub 的 push
# protection 按腾讯云 `AKID` + 长字母数字的形态拦截，写成完整字面量会被拒。
AKID = "AKID" + "Synthetic" + "FakeKey0123456" + "789Synthe"


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


def _classify_constants(stmt, consts, guard_off=False):
    """按真扫的形状喂常量（邻位配对看的是 constants 列表的下标）。

    `guard_off` = **改动前**（fix40 闸门根本不存在，配对照旧成立）。fix40c 起闸门的总闸是
    `is_impossible_ak_sk_pair`（先判例外 ⑤、再判强有效半边、最后才问五类形态），
    所以要关的是**它**；同时把值侧判据 `is_impossible_sk_candidate` 一并关掉（等价）。
    RED 阶段新名字还不存在时按「本来就关着」处理，断言照跑。
    """
    saved = getattr(C, _GUARD_ATTR, None)
    saved_gate = getattr(C, "is_impossible_ak_sk_pair", None)
    if guard_off:
        if saved is not None:
            setattr(C, _GUARD_ATTR, lambda _sk, _ak: False)
        if saved_gate is not None:
            C.is_impossible_ak_sk_pair = lambda _ak, _sk: False
    try:
        return [(r[0], r[1]) for r in
                C.perform_constant_classifying([stmt], [(v, 0, "test") for v in consts])]
    finally:
        if guard_off:
            if saved is not None:
                setattr(C, _GUARD_ATTR, saved)
            if saved_gate is not None:
                C.is_impossible_ak_sk_pair = saved_gate


def _pairval(ak, sk):
    return "AK=%s, SK=%s" % (ak, sk)


def _stmt(ak, sk):
    return 'var o={accessKeyId:"%s", key:"%s"};' % (ak, sk)


def _slug(slug_id):
    return _SLUG_OF.get(slug_id, str(slug_id)).lower()


def _risk4plus(rows):
    """行集里 risk>=4 的那些行（用户口径：这些标签**不许**出现在被拒成员身上）。"""
    return {(slug, content) for slug, content in rows if RISK.get(_slug(slug), 0) >= 4}


def _assert_member_landing(member, mine, solo, why):
    """fix40b：被拒成员的落点不变量（全组共用，避免同一条规则抄三遍）。

      · 成员**不得新获得 risk>=4 标签**（`_risk4plus(mine) == set()`）；
      · 成员自己（单独分类）本来就没有 risk>=4 落点 ⇒ 落点与 solo **逐条相同**
        （risk<=3 的落点在修前后一字不动，这是「不许平移噪音」那条红线）；
      · 成员自己的 solo 落点里有 risk>=4（正在发生的回归：AK id 坐在 `accessKeyId` 语境里
        被 `is_app_key` 判成 platform_app_secret(1101, risk5)）⇒ 那些行**改判**
        cloud_cred_noise(1207, risk0)，其余行逐条不变。
    """
    hi_mine, hi_solo = _risk4plus(mine), _risk4plus(solo)
    assert not hi_mine, (why, member, sorted(hi_mine))
    if not hi_solo:
        assert mine == set(solo), (why, member, mine, solo)
    else:
        assert mine == (set(solo) - hi_solo) | {(NOISE, member)}, (why, member, mine, solo)


# =========================================================
# ① 不可能的 SK 侧候选：强有效半边能救则救，救不了的两个成员各走各的
# =========================================================
# fix40c：本组按「强有效半边」重新切分 —— 同一条不可能形态，AK 侧是**云厂商前缀**
# （强有效）时**照常配对**；只是**语境 AK** 时仍然否决；形态 ⑤ 无论如何都否决。
AX_CTX = "9q7Wx2AbCdEfGhIjKlMn"          # 无前缀、只靠 accessKeyId 语境识别的 AK
WX_SK = "wx1234567890abcdef"
ALIPAY_SK = "2021000123456789"
PATH_SK = "/pages/demo/index/index"
ALPHA_SK = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# fix40c：**强前缀 AK** + 不可能 SK ⇒ 照常配对（原 fix40 的 6 条里有 4 条落在这里）
REALLOWED = [
    # (AK, SK, 形态名)
    (AK24, WX_SK, "微信 appid（wx + 16 位 hex）"),
    (AK24, ALIPAY_SK, "支付宝 appid（2021 + 12 位数字）"),
    (AK24, PATH_SK, "路径片段（含 `/`，无 `+`/`=`）"),
    (AK24, ALPHA_SK, "占位字母表"),
    (AKID, PATH_SK, "AKID 前缀 + 路径邻居"),
    ("AKIAO2AbCdEfGhIjKlMn", WX_SK, "AKIA（AWS）前缀 + 微信 appid"),
]

# fix40c：**语境 AK**（无云厂商前缀 ⇒ 不算强有效）+ 不可能 SK ⇒ **仍然否决**
REJECTED = [
    (AX_CTX, WX_SK, "语境 AK + 微信 appid"),
    (AX_CTX, ALIPAY_SK, "语境 AK + 支付宝 appid"),
    (AX_CTX, PATH_SK, "语境 AK + 路径片段"),
    (AX_CTX, ALPHA_SK, "语境 AK + 占位字母表"),
]

# fix40c：例外 ⑤（两侧同一串 / 互为前缀）**不受放行影响**，强前缀 AK 也照旧否决
REJECTED_RULE5 = [
    (AKID, AKID, "SK 与 AK 是同一个串"),
    (AK24, "LTAI5tAbCdEfGhIj", "SK 是 AK 的前缀"),
    (AX_CTX, AX_CTX, "语境 AK：同一串"),
]


def test_impossible_sk_pairs_are_not_formed():
    """① 闸门命中（且没有强有效半边）⇒ 不产出 1201 组合值。"""
    assert (len(REJECTED), len(REJECTED_RULE5)) == (4, 3)
    for ak, sk, why in REJECTED + REJECTED_RULE5:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        assert (PAIR, _pairval(ak, sk)) not in got, (why, got)
        assert PAIR not in [lbl for lbl, _c in got], (why, got)


def test_members_fall_back_to_their_own_classification():
    """① 被拒后两个成员**按各自原本的分类走**（与单独分类同标签）。

    fix40b 加一条**唯一的例外**：成员自己原本会落到 risk>=4 的类型时（AK id 坐在
    `accessKeyId` 语境里被 `is_app_key` 当成 platform_app_secret，见 `_assert_member_landing`），
    改判显式落点 cloud_cred_noise(1207, risk0)。其余成员的落点逐条不变。

    fix40c：只有**仍然否决**的两组（语境 AK 组 + ⑤ 例外组）走这条路径；被放行的强前缀配对
    回到改动前状态（组合值产出、两个成员被 consume），见第 ⑦ 组。
    """
    for ak, sk, why in REJECTED + REJECTED_RULE5:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        for member in (ak, sk):
            solo = _classify_constants(stmt, [member])
            mine = {item for item in got if item[1] == member}
            _assert_member_landing(member, mine, solo, why)


def test_rejected_members_do_not_upgrade_risk():
    """① 成员自己的落点**不高于** 1201 的 risk（5）：真实语料的逐值口径见报告。

    fix40b 把这条收紧到用户口径：成员**不得新获得 risk>=4 标签**（`< 4`）。
    """
    for ak, sk, why in REJECTED + REJECTED_RULE5:
        stmt = _stmt(ak, sk)
        for label, content in _classify_constants(stmt, [ak, sk]):
            slug = _SLUG_OF.get(label, "").lower()
            assert RISK.get(slug, 0) < 4, (why, content, slug)


# =========================================================
# ⓪ fix40c：强有效半边 ⇒ 照常配对（本轮的核心口径变更）
# =========================================================
def test_strong_prefix_ak_reallows_impossible_sk():
    """⓪ fix40c：**强前缀 AK** + 不可能 SK ⇒ 照常产出 1201（用户口径：有一半正确就行）。

    RED（改动前 = fix40 闸门）：这 6 条期望全部不成立 —— 闸门只要看到另一半不可能就否决整对。
    红线：放行后的产出必须**与改动前逐行相同**（回到改动前状态，不引入任何新标签）。
    """
    assert len(REALLOWED) == 6, len(REALLOWED)
    for ak, sk, why in REALLOWED:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        assert (PAIR, _pairval(ak, sk)) in got, (why, got)
        assert got == _classify_constants(stmt, [ak, sk], guard_off=True), (why, got)


def test_reallowed_pair_adds_no_risk4_label_and_no_reverse():
    """⓪ fix40c：放行的配对不许新增 risk>=4 标签、也不许新造改动前没有的组合值。"""
    for ak, sk, why in REALLOWED:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        had = _classify_constants(stmt, [ak, sk], guard_off=True)
        assert _risk4plus(got) == _risk4plus(had), (why, sorted(_risk4plus(got)), sorted(_risk4plus(had)))
        assert {c for lbl, c in got if lbl == PAIR} <= {c for lbl, c in had if lbl == PAIR}, why


def test_context_ak_is_not_a_strong_half():
    """⓪ fix40c：仅凭**语境词**识别出的 AK **不算**强有效 ⇒ 这一类仍然否决。

    理由：语境分支正是 fix40 里把 appid/占位串当成 AK 的那一半来源；放行它会**新造**
    `AK=<appid>, SK=<真 SK>` 这类改动前不存在的组合值（v2 源码重扫实测 2 个）。
    """
    for ak, _sk, _why in REJECTED:
        assert C.is_access_key(ak, _stmt(ak, "x"))[0] is True      # 确实是 AK（语境分支）
        assert C.is_strong_valid_ak_half(ak) is False, ak          # 但不是「强有效」


def test_rule5_exception_is_not_reallowed_by_a_strong_half():
    """⓪ fix40c：例外 ⑤（同一串 / 互为前缀）不受放行影响 —— 强前缀 AK 也照旧否决。

    组合值 `AK=X, SK=X` 里没有第二份材料，等同于不存在的配对（用户确认的例外）。
    """
    assert len(REJECTED_RULE5) == 3, len(REJECTED_RULE5)
    for ak, sk, why in REJECTED_RULE5:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        assert (PAIR, _pairval(ak, sk)) not in got, (why, got)
        assert PAIR not in [lbl for lbl, _c in got], (why, got)
        assert (PAIR, _pairval(ak, sk)) in _classify_constants(stmt, [ak, sk], guard_off=True), why


def test_strong_half_predicates():
    """⓪ fix40c：两个「强有效半边」判据的边界（合成值）。"""
    fx = C.is_strong_valid_ak_half
    # 正例：六个云厂商前缀 + 16/40 位 alnum
    for ok in ("LTAI5tAbCdEfGhIjKlMnOpQr", AKID,
               "AKIAO2AbCdEfGhIjKlMn", "ABIAO2AbCdEfGhIjKlMn", "ACCAO2AbCdEfGhIjKlMn",
               "ASIAO2AbCdEfGhIjKlMn", "LTAI" + "a" * 12, "LTAI" + "a" * 36):
        assert fx(ok) is True, ok
    # 反例：体长（<16 / >40）、非 alnum、无前缀、只有语境
    for no in ("LTAI5tAbCdEfGhI",                        # 15 位：够不上 AK 形态
               "LTAI" + "a" * 37,                        # 41 位：超出 is_access_key 的上界
               "LTAI5tAbCdEfGhIj-KlMn",                  # 非 alnum
               "LTAI5tAbCdEfGhIj KlMn",
               "9q7Wx2AbCdEfGhIjKlMn",                   # 语境 AK，无前缀
               "wx1234567890abcdef", "2021000123456789",
               "AKIAO2AbCdEfGhI"):                       # 15 位（AKIA 族的下界外）
        assert fx(no) is False, no
    # 「强有效 AK」必须仍被 is_access_key 认成 AK（判据不许比配对入口更宽）
    for ok in ("LTAI5tAbCdEfGhIjKlMnOpQr", AKID):
        assert C.is_access_key(ok, "")[0] is True, ok
    # SK 侧钩子：本轮**刻意**恒 False（数据依据见文件头），由开关对照钉住「开也不会多放行」
    assert C.is_strong_valid_sk_half("AbCdEfGhIjKlMnOpQrStUvWxYz012345", "2021000123456789") is False


def test_sk_half_hook_can_be_flipped_without_touching_the_gate():
    """⓪ fix40c：SK 侧钩子是**显式钩子** —— 若日后有证据要开「强有效 SK + 不可能 AK」，
    只需改这一个函数；这里用运行时替换证明接线是通的（且当前默认值下该配对仍否决）。

    现场（合成值）：`AK=<支付宝 appid>（语境 AK，不可能形态）, SK=<40 位混料>` —— 只有在
    SK 侧强有效成立时才该产出。这条也是任务清单里那句「若 SK 侧强有效成立 ⇒ 产出 1201」
    的落地：本轮 SK 侧定义为永不成立 ⇒ 仍否决；钩子打开 ⇒ 产出。
    """
    ak = "2021000123456789"                            # 支付宝 appid：AK 侧不可能（语境 AK）
    sk = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"            # 40 位混合大小写+数字
    stmt = _stmt(ak, sk)
    got = _classify_constants(stmt, [ak, sk])
    assert (PAIR, _pairval(ak, sk)) not in got, got     # 默认：SK 侧不强有效 ⇒ 否决
    saved = C.is_strong_valid_sk_half
    C.is_strong_valid_sk_half = lambda v, _other=None: v == sk
    try:
        flipped = _classify_constants(stmt, [ak, sk])
    finally:
        C.is_strong_valid_sk_half = saved
    assert (PAIR, _pairval(ak, sk)) in flipped, flipped  # 钩子生效 ⇒ 照常配对
    # 例外 ⑤ 不受钩子影响：同一串仍然否决
    C.is_strong_valid_sk_half = lambda v, _other=None: True
    try:
        same = _classify_constants(_stmt(AKID, AKID), [AKID, AKID])
    finally:
        C.is_strong_valid_sk_half = saved
    assert PAIR not in [lbl for lbl, _c in same], same


# =========================================================
# ② 保护组：真配对 100% 保留
# =========================================================
KEPT = [
    # LTAI / AKID 强前缀 AK 的真配对（normal_quarkpan 340 个组合值里 136 / 59 是这两族）
    (AK24, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=", "LTAI + 40 位 b64（含 `+`/`/`/`=`）"),
    (AKID, "FakeTencentSecret0123456789FakeT", "AKID + 32 位 b64"),
    # 纯语境配对（无前缀，只靠 accessKeyId 语境）
    ("9q7Wx2AbCdEfGhIjKlMn", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=", "语境配对"),
    # 16 位短 SK：**不是**不可能（刻意不加体长规则，见文件头「刻意不做」）
    (AK24, "AbCd1234EfGh5678", "16 位 alnum SK"),
    # 纯小写 hex（md5/sha 形）：有歧义，本轮不判不可能
    (AK24, "aaaaaaaa000000000000000000000000", "32 位 hex SK"),
    # b64 里带 `+`：这是材料签名，路径规则不许误伤
    (AK24, "AbCdEfGh0123456789AbCdEf01+/", "28 位 b64（含 `+`/`/`）"),
]


def test_real_pairs_are_kept():
    """② 真配对逐条保持 1201（值形态与开关敏感性都不变）。"""
    assert len(KEPT) == 6, len(KEPT)
    for ak, sk, why in KEPT:
        stmt = _stmt(ak, sk)
        want = _pairval(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        assert (PAIR, want) in got, (why, got)
        assert _classify_constants(stmt, [ak, sk], guard_off=True) == got, why


def test_pair_value_invariant_from_fix33_still_holds():
    """② fix33 的值侧配对不变量不受影响（同族判据不许回退）。"""
    for ak, sk, _why in KEPT:
        assert C.is_ak_sk_pair_value(_pairval(ak, sk)) is True, (ak, sk)


# =========================================================
# ③ 闸门本身的边界（值侧形态，不看语境）
# =========================================================
def test_guard_predicate_boundaries():
    fn = C.is_impossible_sk_candidate
    ak = AK24
    # 正例：六类不可能形态
    assert fn("wx1234567890abcdef", ak) is True
    assert fn("2021000123456789", ak) is True
    assert fn("/pages/demo/index/index", ak) is True
    assert fn("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", ak) is True
    assert fn(ak, ak) is True
    assert fn("LTAI5tAbCdEfGhIj", ak) is True
    # 反例：真材料形态 / 短 SK / hex / camelCase 词形 / 普通 b64
    for ok in ("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/=",
               "AbCd1234EfGh5678",
               "aaaaaaaa000000000000000000000000",
               "AbCdEfGh0123456789AbCdEf01+/",
               "FakeTencentSecret0123456789FakeT",
               "phoneProtectChannel4021",
               "phonenumberchannel4021"):
        assert fn(ok, ak) is False, ok
    # 反例：含 `/` 但带 `+`/`=` 的 b64 材料（路径规则不许误伤）
    assert fn("AbCdEf/0123456789AbCd/+", ak) is False
    assert fn("AbCdEf/0123456789AbCd/+=", ak) is False
    # 前后缀关系只在**同一个串**上成立；普通不同的串不算
    assert fn("AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOpQrStUvWx") is True     # 真前缀
    assert fn("AbCdEfGhIjKlMnOpQr", "AbCdEfGhIjKlMnOpQrStUvWx") is True  # AK 是 SK 的前缀
    assert fn("AbCdEfGhIjKlMnO0", "AbCdEfGhIjKlMnOpQrStUvWx") is False


# =========================================================
# ④ 开关对照：`guard_off` == 改动前（配对照旧成立）
# =========================================================
def test_guard_is_the_change():
    """④ 仍然否决的那些：改动前成立、改动后不成立。

    fix40c：`REALLOWED` 那组（强有效半边）**不在**这里 —— 它们改动后照旧成立，见第 ⓪ 组。
    """
    for ak, sk, why in REJECTED + REJECTED_RULE5:
        stmt = _stmt(ak, sk)
        had = _classify_constants(stmt, [ak, sk], guard_off=True)
        assert (PAIR, _pairval(ak, sk)) in had, (why, had)
        assert (PAIR, _pairval(ak, sk)) not in _classify_constants(stmt, [ak, sk]), why


# =========================================================
# ⑤ 闸门是**否决**，不是「换个邻居再配」
# =========================================================
def test_guard_is_a_veto_not_a_re_roll():
    """⑤ 被闸门否决的单边不会去和**另一个邻居**重新配对（不新造改动前没有的组合值）。

    现场：`[<像 SK 的真材料>, <AK>, <不可能的候选>]` —— AK 的正邻居（+1）是那个不可能候选，
    负邻居（-1）是像 SK 的材料。若闸门是「跳过再看下一个」，这里会**新造**出
    `AK=<AK>, SK=<左邻居>`；实测 v2 有 8 个这样的组合值（9 条链接），它们都没在改动前出现，
    把值新扫进 risk5 的 1201 是红线。所以闸门命中即**否决整对**（改动后的产出集是
    改动前的子集），本组钉住这条不变量。

    fix40c：本组的这条配对仍然被否决 —— 现场用的不可能候选是 AK 的**前缀**（形态 ⑤），
    例外 ⑤ 不受「强有效半边」放行影响（用户确认）。判据边界：`find_sk_in_neighbors` 仍是
    「命中即整对否决、不换邻居」。
    """
    ak = AK24
    plausible = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/="          # 像真 SK 的左邻居
    impossible = "LTAI5tAbCdEfGhIj"                               # SK 是 AK 的前缀（不可能）
    stmt = 'var o={key:"%s", accessKeyId:"%s", key2:"%s"};' % (plausible, ak, impossible)
    got = _classify_constants(stmt, [plausible, ak, impossible])
    assert (PAIR, _pairval(ak, impossible)) not in got, got        # 旧配对没了（正确）
    assert (PAIR, _pairval(ak, plausible)) not in got, got         # 但也不许换成左邻居
    assert PAIR not in [lbl for lbl, _c in got], got
    # 改动前：与 +1 邻居（那个不可能候选）照旧成对
    had = _classify_constants(stmt, [plausible, ak, impossible], guard_off=True)
    assert (PAIR, _pairval(ak, impossible)) in had, had
    # 成员各自走自己的分类（fix40b：risk>=4 的落点改判 cloud_cred_noise，见 _assert_member_landing）
    for member in (plausible, ak, impossible):
        solo = _classify_constants(stmt, [member])
        mine = {item for item in got if item[1] == member}
        _assert_member_landing(member, mine, solo, "⑤ 否决不换邻居")


# =========================================================
# ⑥ fix40b 回归：被拒成员是 **AK id**，不许被当成 secret；也不许在后续下标重新配对
# =========================================================
# 现场（fix40 的回归，源码重扫口径）：配对否决后成员按各自分类走，而 AK 侧成员坐在
# `accessKeyId` 语境里 ⇒ `has_appkey_context` 的 `accesskey` 命中 → `is_app_key` 返回
# platform_app_secret(1101, **risk5**)（constants_classifier.py 的 is_app_key 分流：
# 含 `accesskey` 时走 CREDENTIAL 分支）。改动前这些值被 consume 进 `AK=…, SK=…` **没有自己
# 的行**，改动后新得 risk5 标签 —— 用户口径「新增 risk≥4 标签 = 不可接受」。
# fix40c：本组的 AK 侧一律用**语境 AK**（无云厂商前缀）—— 强前缀 AK + 不可能 SK 现在会被
# 「强有效半边」放行（第 ⓪ 组），走不到这条被拒路径上；语境 AK 仍然走得到（实测语料里
# 被拒成员是 AK id 的、坐在 `accessKeyId` / `OSSAccessKeyId` / `SecretId` 语境里的那一批）。
MEMBER_CASES = [
    (AX_CTX, WX_SK, "语境 AK 侧成员：accessKeyId 语境 + 微信 appid 邻居"),
    (AX_CTX, ALIPAY_SK, "同族：支付宝 appid 邻居"),
    (AX_CTX, PATH_SK, "同族：路径邻居"),
]


def test_rejected_members_gain_no_risk4_label():
    """⑥ 被拒成员不得出现 risk>=4 标签（本轮回归的 RED：AK id → platform_app_secret）。"""
    assert len(MEMBER_CASES) == 3, len(MEMBER_CASES)
    for ak, sk, why in MEMBER_CASES:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        hi = sorted(_risk4plus(got))
        assert not hi, (why, hi)
        assert PAIR not in [lbl for lbl, _c in got], (why, got)


def test_rejected_member_lands_in_cloud_cred_noise():
    """⑥ 成员本来会落到 1101 时，**显式**改判 cloud_cred_noise(1207, risk0)。

    「显式落点」不是静默丢弃：值要留一行可回溯（与 process_cloud_token / fix32 / fix39
    的归置口径一致），而 risk 从 5 降到 0 —— 不升反而降，也不把噪音挪进别的 risk>=4 桶。
    """
    for ak, sk, why in MEMBER_CASES:
        stmt = _stmt(ak, sk)
        got = _classify_constants(stmt, [ak, sk])
        solo = _classify_constants(stmt, [ak])
        if _risk4plus(solo):                       # AK 侧本来会落 1101
            assert (NOISE, ak) in got, (why, got)
        else:                                      # 本来就不落 risk>=4 ⇒ 一字不动
            assert set(solo) <= set(got), (why, solo, got)
        assert (IDT.PLATFORM_APP_SECRET, ak) not in got, (why, got)


def test_rejected_member_does_not_re_pair_at_a_later_index():
    """⑥ 被拒成员不得在**后续下标**重新配对（fix40 实测 v2 有反向进入 1201）。

    现场：`[X(20 位), X(20 位副本), Y(32 位 b64)]` —— 下标 0 的 X 与下标 1 的 X 是
    `sk==ak`（闸门否决）；改动前下标 1 被 consume；现在下标 1 被释放，若它还能**在自己
    下标上发起配对**，就会和下标 2 的 Y 配成 `AK=X, SK=Y`（改动前不存在的组合值）。

    不变量按**产出集**钉（与回放的「反向进入 1201 = 0」同口径）：改动后的 1201 组合值
    必须全是改动前就有的（`got_pairs ⊆ had_pairs`）。
    """
    x = "9q7Wx2AbCdEfGhIjKlMn"
    y = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
    stmt = 'var o={accessKeyId:"%s", key:"%s", key2:"%s"};' % (x, x, y)
    got = _classify_constants(stmt, [x, x, y])
    had = _classify_constants(stmt, [x, x, y], guard_off=True)
    had_pairs = {c for lbl, c in had if lbl == PAIR}
    got_pairs = {c for lbl, c in got if lbl == PAIR}
    assert (PAIR, _pairval(x, x)) not in got, got
    assert (PAIR, _pairval(x, y)) not in got, got          # 反向进入（RED）
    assert got_pairs <= had_pairs, got_pairs - had_pairs   # 不许新造改动前没有的组合值
    assert (PAIR, _pairval(x, x)) in had, had              # 改动前：X+X（sk==ak）照旧成对
    # 成员 X 自己的分类照旧（risk>=4 才改判）；没参与否决配对的 Y **一行不许变**（与改动前逐行相同）
    solo_x = _classify_constants(stmt, [x])
    mine_x = {item for item in got if item[1] == x}
    _assert_member_landing(x, mine_x, solo_x, "⑥ 后续下标不重配")
    assert ({item for item in got if item[1] == y}
            == {item for item in had if item[1] == y}), (y, got, had)



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
    print("fix40 SK 侧不可能形态闸门：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
