#!/usr/bin/env python3
"""fix17：process_Regex_crypto_key 的「无证据默认判定」回归验证。

病根（与 fix15 ① / fix16 ① 同一模式）：这条路径原先只有两个**排除**分支
（椭圆曲线预计算点表、曲线关键词）+ 一个私钥分支，**没有「要语境」的闸门**：

    if 私钥语境:  -> crypto_private_key(2102, risk5)
    else:        -> crypto_public_key(2103, risk2)     ← 无任何证据也判

三库回放（口径：值×source_snippet；出现次数 = SUM(data_item.ref_count+1)）：
该路径接住 1,379 值 / 40,738 次，其中 **44,923 条 pair 的语句里一个 public/private
类词都没有**（v2 库：476 值里 393 个、2,084 次里 1,763 次）。典型是曲线常量与
`s = new r("FFFFFFFE…", 16)` / `g: [...]` 这类语句就是值本身的赋值。

改法（形态分档 + 证据收严，其余逐位不动）：
  ① `04`+128 位是**未压缩点编码**（ECDSA/SM2 公钥的合法前缀形态）——形态本身即强证据，
     照旧出口。三库 152 个该形态的值里 46 个语句无任何关键词，逐个看过**全是真公钥**
     （`export.PUBLICKEY=…` / `certPublicKey:…` / `M?"04659827…":"04727940…"` 开发/生产
     双密钥选择），所以这条**不能**一起要求语境（候选 R3 会误伤这 46 个）。
  ② 48/64 位 hex（24/32 字节）无语境时**不出口**，回落到通用分流。三库 48 位那 14 个值里
     真公钥 0 个（曲线常量 P-192 的 p/n、流水号、protobuf 片段）。
  ③ 证据词分两档：3 字母的 pub/priv 走「独立词或驼峰段」边界，复合词/长词保持子串语义。
     依据：裸子串 `pub` 会命中 isPublished / ecpubhex / publish*，实测把 SM2 n（446 次）
     与 P-256 n（98 次）两个曲线常量重新放回桶里。

量化（三库，回放口径）：桶内 1,379 值 / 40,738 次 -> 155 值 / 919 次；
离开 1,224 值（64hex 1,206 + 48hex 18），pair 级翻转 44,931 条，其中 44,810 条去向是
**无产出**。落进 risk>=4 的 30 个值单独核过（见 test-result/fix17/h_r2_risk.out）：
  26 个 apikey/DingTalk access_token 类真凭证 -> server_cred_token(5)（其中 5 个
  userToken 值在库里本来就已经是 1602，另 2 个原是 pii_noise(0)）；
  3 个 PBKDF2 **测试向量** -> cloud_cred_password(5)（已知残留，见文件末尾注）。
`04`+128 值离开桶：0 个。

用法: .venv/bin/python -X utf8 unit-tests/test_crypto_pubkey_evidence.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PUB = IDT.CRYPTO_PUBLIC_KEY
PRIV = IDT.CRYPTO_PRIVATE_KEY
TOKEN = IDT.SERVER_CRED_TOKEN
CCP = IDT.CLOUD_CRED_PASSWORD
PII = IDT.PII_NOISE

# ---- 实测材料值（全部取自三库真值与人工核定表） ----
SM2_N = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
SM2_GX = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
SECP_GX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
ED25519_GY = "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"
P256_N = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
CURVE_TABLE = "4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9"
P192_N_48 = "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"
H48 = "30F1338B04B10DD4DFC1B11BFB19E638DCB32F8442EAF167"
APIKEY_64 = "f77370130381064450e51d3501a5529e0ac9743458e9bc959e2e0abdef431b89"
USERTOKEN_64 = "2DDDC0689C23CC70F0BCE3C0A819B95F3F0D04F68EA2608F6783B874E4F50EEF"
# `04`+128：真·未压缩公钥（一个无语境、一个 publicKey 键名）
PUB04_PLAIN = ("04a9e1d2b39a224811a20bb85ea4b302e2aab74a31e662a474f4378b4d0716588"
               "40612894c0ebff53dd75158316df0df97b966f70e74a4b4f29d85fe947b4fc73c")
PUB04_KEYNAME = ("04d039480fe678b84899ee1e404d664bdf8db982916fd5ed42b924fd229a44b4d"
                 "3aa1e4b90350b7f79151e7fe914fda8c25ac825819030c5726ce43cf39bd569fc")


def _old_process_Regex_crypto_key(s, stmt, src, sid, res, raw_stmt=None):
    """改动前的函数体（逐字复刻 git 版本），用来做「关掉本轮改动」的对照。"""
    check_stmt = raw_stmt if raw_stmt else stmt
    ctx_lower = check_stmt.lower()
    if "point" in ctx_lower or "points" in ctx_lower or (
            "doubles" in ctx_lower and "naf" in ctx_lower):
        return
    if C.has_keyword_substring(ctx_lower, C.ELLIPTIC_CURVE_KEYWORDS):
        return
    if not C.has_min_unique_chars(s.upper(), 6):
        return
    private_keywords = ("private", "priv", "secret", "secretkey", "privatekey")
    public_keywords = ("public", "pub", "publickey")
    is_private = C.has_keyword_substring(ctx_lower, private_keywords)
    is_public = C.has_keyword_substring(ctx_lower, public_keywords)
    slug = PRIV if is_private and not is_public else PUB
    C.append_result(res, slug, s, src, sid)


def _classify(v, stmt, changed=True):
    """跑一遍分类；changed=False 时只换回改动前的 process_Regex_crypto_key。"""
    saved = C.process_Regex_crypto_key
    if not changed:
        C.process_Regex_crypto_key = _old_process_Regex_crypto_key
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, "probe")])]
    finally:
        C.process_Regex_crypto_key = saved


def _direct(v, stmt, raw_stmt=None):
    """直接调本函数，返回产出类型（不经过整条流水线）。"""
    r = []
    C.process_Regex_crypto_key(v, stmt, 0, 0, r, raw_stmt)
    return [x[0] for x in r]


# =========================================================
# ① 无语境的 48/64 位 hex 不再被判成公钥
# =========================================================
def test_noctx_curve_constants_not_public_key():
    """语句就是值本身的曲线常量：一个都不许再进 crypto_public_key(2)。"""
    for v in (SM2_N, SM2_GX, SECP_GX, ED25519_GY, P256_N, CURVE_TABLE, P192_N_48, H48):
        got = _classify(v, '"%s"' % v)
        assert PUB not in got, "%r -> %r" % (v, got)


def test_noctx_was_the_old_behaviour():
    """对照：关掉本轮改动后，同一个值确实落 crypto_public_key（证明是本改动在起作用）。"""
    for v in (SM2_N, ED25519_GY, H48):
        assert _classify(v, '"%s"' % v, changed=False) == [PUB], v


def test_noctx_direct_call_produces_nothing():
    """无语境时本函数产出为空（三条出口只剩有证据的两条）。"""
    assert _direct(SM2_N, 's = new r("%s", 16)' % SM2_N) == []
    assert _direct(H48, 'I="%s"' % H48) == []


def test_sm2_regist_statement_no_longer_public_key():
    """真语句形态：`a.regist("sm2", 256, "<p>", "<a>", "<b>", "<n>", …)`。"""
    stmt = ('x=a.regist("sm2", 256, "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000'
            'FFFFFFFFFFFFFFFF", "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000'
            'FFFFFFFFFFFFFFFC", "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBC'
            'BD414D940E93", "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF409'
            '39D54123")')
    assert PUB not in _classify(SM2_N, stmt), _classify(SM2_N, stmt)


def test_48hex_falls_through_not_dropped():
    """48/64 位 hex 的去向是**回落**（不是丢弃）：`I="<48hex>"` 落 pii_noise(0)。"""
    got = _classify(H48, 'I="%s"' % H48)
    assert got == [PII], got


# =========================================================
# ② `04`+128 未压缩公钥形态必须全部保住（误伤红线）
# =========================================================
def test_uncompressed_pubkey_without_context_survives():
    """形态本身即强证据：`c = "04…"` 无语境也必须仍是 crypto_public_key(2)。"""
    assert _classify(PUB04_PLAIN, 'c = "%s"' % PUB04_PLAIN) == [PUB]


def test_uncompressed_pubkey_uppercase_and_keyname_survive():
    """大小写不敏感（库里有大写 `04C339…`），键名形态照旧。"""
    for stmt in ('c = "%s"', 'publicKey: "%s"', 'exports.PUBLICKEY="%s"',
                 'certPublicKey: "%s"', 'cloudConfig/publicKey: "%s"'):
        got = _classify(PUB04_KEYNAME, stmt % PUB04_KEYNAME)
        assert got == [PUB], "%r -> %r" % (stmt, got)
    got = _classify(PUB04_KEYNAME.upper(), 'c = "%s"' % PUB04_KEYNAME.upper())
    assert got == [PUB], got


def test_uncompressed_pubkey_dev_prod_pair():
    """实测材料：`M?"04659827…":"04727940…"`（dev/prod 双密钥选择，无语境）。"""
    dev = ("046598273bfed3454720e21028815c22ce3b8a013bb4892f588d5e9a12e9206b58f386"
           "26e4e35ab49258cdec7b7cf559ba2b44b87135adab91ba931c4c31379b27")
    prod = ("0472794092350ff6888d053588508124314d627eac111d05288c33445da68762fa00f6"
            "413d9dc8d77c4de8d073cb212163cc8f93d5fb3160e09e191f0390836764")
    stmt = ('t=r||(M=!i.default.isProduction(),console.warn("x",M),M?"%s":"%s")' % (dev, prod))
    assert _classify(dev, stmt) == [PUB], _classify(dev, stmt)
    assert _classify(prod, stmt) == [PUB], _classify(prod, stmt)


def test_uncompressed_pubkey_private_context_still_private():
    """③ 不许改「私钥语境优先」这条既有口径。"""
    assert _classify(PUB04_KEYNAME, 'privateKey: "%s"' % PUB04_KEYNAME) == [PRIV]


# =========================================================
# ③ 短词证据边界：pub/priv 走段匹配，复合词与长词保持子串
# =========================================================
def test_leaky_short_words_are_not_evidence():
    """`pub` 裸子串的两个实测泄漏：字符串表里的 "ecpubhex"、`isPublished`。"""
    ecpub = '"ecpubhex", "SM2Cipher", "%s"' % SM2_N
    assert PUB not in _classify(SM2_N, ecpub), _classify(SM2_N, ecpub)
    ispub = 'getApp().globalData.isPublished||d()||("%s"==t.userToken)' % USERTOKEN_64
    assert PUB not in _classify(USERTOKEN_64, ispub), _classify(USERTOKEN_64, ispub)
    assert _classify(USERTOKEN_64, 'a.publish("%s")' % USERTOKEN_64) == [], \
        _classify(USERTOKEN_64, 'a.publish("%s")' % USERTOKEN_64)
    assert PUB not in _classify(USERTOKEN_64,
                                '"user_privilege_list","%s"' % USERTOKEN_64)


def test_real_short_word_keynames_still_evidence():
    """真键名一个都不许丢：pubKey / pubkey / PUBKEY / privKey / privkey / privateKey。"""
    for stmt, want in ((  'pubKey: "%s"', PUB), ('pubkey="%s"', PUB),
                       ('PUBKEY="%s"', PUB), ('privKey: "%s"', PRIV),
                       ('privkey="%s"', PRIV), ('privateKey: "%s"', PRIV),
                       ('publicKey: "%s"', PUB)):
        got = _classify(SM2_N, stmt % SM2_N)
        assert got == [want], "%r -> %r" % (stmt, got)


def test_evidence_matcher_is_shared_directly():
    """crypto_key_evidence 的两个出口各钉一发（含 raw_stmt 覆盖 stmt 的分支）。"""
    assert C.crypto_key_evidence('publicKey: "x"') == (False, True)
    assert C.crypto_key_evidence('privateKey: "x"') == (True, False)
    assert C.crypto_key_evidence('secretKey: "x"') == (True, False)
    assert C.crypto_key_evidence('isPublished||x') == (False, False)
    assert C.crypto_key_evidence('"ecpubhex"') == (False, False)
    assert _direct(SM2_N, 'publicKey: "x"', raw_stmt='publicKey: "%s"' % SM2_N) == [PUB]


# =========================================================
# ④ 两个**排除**分支原样保留（point/points/doubles+naf、曲线关键词、低区分度）
# =========================================================
def test_point_exclusion_unchanged():
    """防椭圆曲线预计算点表的排除分支：不能因为加了闸门就把它当守卫去掉。"""
    assert _direct(ED25519_GY, 'points: ["%s", "6666…"]' % ED25519_GY) == []
    assert _direct(ED25519_GY, 'point = "%s"' % ED25519_GY) == []
    assert _direct(SECP_GX, 'doubles: naf "%s"' % SECP_GX) == []


def test_curve_keyword_exclusion_unchanged():
    assert _direct(SECP_GX, 'curve: secp256k1, g: "%s"' % SECP_GX) == []
    assert _direct(SM2_GX, 'p256 = "%s"' % SM2_GX) == []


def test_low_diversity_exclusion_unchanged():
    zeros = "0" * 64
    assert _direct(zeros, 'publicKey: "%s"' % zeros) == []


# =========================================================
# ⑤ 回落去向（改动把值推向哪里）
# =========================================================
def test_fallthrough_to_token_bucket():
    """带 token 语境的真凭证：离开本路径后由 is_hex_token 接住 -> server_cred_token(5)。"""
    url = 'exports.DING_API = "https://oapi.dingtalk.com/robot/send?access_token=%s"' % APIKEY_64
    assert _classify(APIKEY_64, url) == [TOKEN], _classify(APIKEY_64, url)
    assert _classify(APIKEY_64, 'apikey: "%s"' % APIKEY_64) == [TOKEN]


def test_hardcoded_usertoken_relabelled_not_noise():
    """`"2DDDC068…"==t.userToken`：真值是硬编码 token，应落 1602 而不是被判公钥。"""
    stmt = ('("2DDDC0689C23CC70F0BCE3C0A819B95F3F0D04F68EA2608F6783B874E4F50EEF"==t.userToken'
            '||"170054A50BDF416BE7071D0ED8B85BE3CCCB578FFE9820E7F43A1807648A85D9"==t.userToken)')
    assert _classify(USERTOKEN_64, stmt) == [TOKEN], _classify(USERTOKEN_64, stmt)


def test_apikey_statement_not_public_key():
    """`apikey: "<64hex>"` 不许再判公钥（去向 1602，非本文件职责但钉住落点）。"""
    got = _classify(APIKEY_64, 'apikey: "%s"' % APIKEY_64)
    assert PUB not in got, got


# =========================================================
# ⑥ 已知残留（记录在案，不在本轮射程）
# =========================================================
def test_known_residual_pbkdf2_test_vector():
    """PBKDF2 测试向量：语句里的**测试输入串** `PBKDF2("password", …)` 会开
    cloud_cred_password(5) 的闸。三库 3 个值 / 9 条 pair，改动前是 crypto_public_key(2)
    —— 两种口径都错，本轮不处理（值形守卫会撞 fix12 的「hex 口令」红线）。

    这条断言是**现状记录**而非期望：一旦将来有人修掉它，这里会红，提示更新报告。
    """
    vec = "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837"
    stmt = 'X.strictEqual(a.PBKDF2("password", "ATHENA.MIT.EDUraeburn", 32), "%s")' % vec
    assert _classify(vec, stmt) == [CCP], _classify(vec, stmt)


def _run_standalone():
    """本机 .venv 没有 pytest，所以自带 runner：断言全是纯 assert，两种跑法一致。"""
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
    print("fix17 crypto_public_key 证据闸门验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
