#!/usr/bin/env python3
r"""fix42：cloud_cred_password(1203) 的**五族结构噪音**窄口守卫 + 受保护位置矩阵。

背景：fix31（含 fix31b/fix31c）收掉三族**值形/位置**噪音（日志 callee 实参 / `+` 连接的 URL
片段 / 值形即 URL 片段）之后，1203 桶里仍混着五族「值本身是别的东西」的结构噪音。它们与
fix31 三族的关键差别是：**判据不靠值的形态，而靠值在语句里的位置**，所以 fix31c 的「材料形
豁免」不该挡它们（`pkcs5PBKDF2` / `1055120GWJCQi` 这类值按 fix31c 的材料形判据都是 True）。

五族（证据 = v2 两库只读判读；每个都只统计**窗口内可判定**的值，见下「判定窗口」）：

  P1 i18n 字典键（is_cloud_password_i18n_key）
     值是字符串字面量实参，其后紧跟 `,` 与一个含中日韩字符的字符串字面量 ——
     「ASCII 键, CJK 值」对里的键侧：
       `(0,a.default)(o,"SellCenterText588","元/件/天")`
     值还必须是键形（`^[A-Za-z][A-Za-z0-9_.\-]{3,48}$`，纯 ASCII），把「材料形 + 恰好后跟
     中文」的巧合挡在外面。

  P2 密码学 OID / 算法名（is_cloud_password_crypto_algorithm_name）
     值的字面量与一个 OID 形态字面量（`"1.2.840.113549.1.1.5"`）**同属一个调用**：
       `a("1.2.840.113549.2.8","hmacWithSHA224")`
     或值本身是标准算法名（ASN.1 签名算法名 / hmacWith… / rsaEncryption / RSAES-OAEP /
     mgf1 / pSpecified / PBKDF2 / scrypt / ecdsa-with-…）。

  P3 webpack/混淆 chunk id（is_cloud_password_obfuscated_chunk_id）
     形态 `^\d{5,8}[A-Za-z]{5,7}$`（`3758445RfzdXY` / `1055120GWJCQi`）**且**坐在字符串表
     数组元素位：同一条字面量串 ≥6 个字面量、其中 ≥2 个是同形或混淆形（`2oiKOVL` /
     `328XYgkqW` / `44OxMZUC` 这类 javascript-obfuscator 串表成员）。只判形态不够 ——
     `setPwd("3758445RfzdXY")` 这种孤立出现不删。

  P4 事件码 / 日志 tag（is_cloud_password_event_tag）
     · 值是 `beforeLog` / `afterLog` / `writeLog` / `reportLog` / `logEvent` 这类日志 callee
       的实参（fix31 ① 的严格表只认得 `console.*` / `__f__` / `log` / `track` / `report` /
       `error`）；
     · 或值是 `===` / `!==` / `==` / `!=` 的比较运算数，**且形态是全大写事件码**
       （`^\d*[A-Z0-9_.\-]*$` 里 ≥2 连大写 + ≥1 位数字：`CCCD003852` / `BLPS1206` /
       `LOAN_IN_360`）。
     比较运算数一侧**必须**加形态闸门，证据（v2 只读实测）：
       `"admin123", "admin123" === r ? …`（管理端硬编码口令，fix12 红线值）
       `if("a123456"==e.detail.value.password) …`（系统初始化口令）
     这两条都是已核实的真阳性；不加形态闸门就会被这一族一起吃掉。而 fix42 回放里被这一族
     拿走的 32 个值全部命中事件码形态（`CCCD003852` / `BFF004087` / `UM_2013` /
     `FE03150001127` …）。

  P5 密码学测试向量（is_cloud_password_kdf_test_vector）
     值是十六进制摘要形态（`^[0-9a-f]{16,128}$`），且它所在的**同一个调用**里既有 KDF 调用
     （`PBKDF2(` / `pbkdf2(` / `scrypt(`），又有 `"password"` / `"salt"` 盐字面量 ——
     RFC 6070 / 3962 测试向量：
       `X.strictEqual(a.PBKDF2("password","ATHENA.MIT.EDUraeburn",16),"cdedb5281bb2…")`

判定窗口（**本任务不改窗口**）：is_cloud_password 拿到的 stmt 是
perform_constant_classifying 以语句**第一个常量**为锚算出的 `extract_context(snippet, s, 512)`
窗口，不一定包含当前值。五族一律以「当前值在 stmt 中的独立出现」为依据；值不在窗口里时
`is_cloud_password_noise` 早就返回 False，本族判据自然也不得判噪音（同 fix31 的
snippet-absent 口径）。回放里按家族分别统计「窗口内可判定」与「窗口内不可判定」。

三条保护（fix31 已有，五族一律排在其后；任一命中 → 永不判噪音）：
  · 值绑在任何键上（`_bound_value_keys`）；· 值处于键名位（右侧跳过引号/空白紧跟 `:`）；
  · 值是 password/pwd/passwd 名 callee 的实参。

用法: .venv/bin/python -X utf8 unit-tests/test_fix42_ccp_structural.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

CCP = IDT.CLOUD_CRED_PASSWORD
CCP_NAME = "CLOUD_CRED_PASSWORD"
GUARD = "is_cloud_password_fix42_family_noise"      # 本轮**唯一**新入口
_ID_TO_SLUG = {v: k for k, v in vars(IDT).items()
               if isinstance(v, int) and k.isupper() and not k.startswith("CTG_")}

FAMILY_FUNCS = (
    "is_cloud_password_i18n_key",
    "is_cloud_password_crypto_algorithm_name",
    "is_cloud_password_obfuscated_chunk_id",
    "is_cloud_password_event_tag",
    "is_cloud_password_kdf_test_vector",
)


def _guard():
    fn = getattr(C, GUARD, None)
    if fn is None:
        raise AssertionError("constants_classifier.%s 尚未实现（RED）" % GUARD)
    return fn


def _fam(name):
    fn = getattr(C, name, None)
    if fn is None:
        raise AssertionError("constants_classifier.%s 尚未实现（RED）" % name)
    return fn


def _classify_ids(v, stmt, guard_off=False):
    """跑一遍分类，返回标签 **id** 集合；guard_off=True 时把本轮新判据换成恒 False
    （= fix42 之前的代码路径；fix31 的三族照旧生效，本轮只 monkeypatch 新家族）。"""
    saved = getattr(C, GUARD, None)
    if saved is None:
        raise AssertionError("constants_classifier.%s 尚未实现（RED）" % GUARD)
    if guard_off:
        setattr(C, GUARD, lambda _v, _s: False)
    try:
        return sorted({r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])})
    finally:
        setattr(C, GUARD, saved)


def _classify(v, stmt, guard_off=False):
    return sorted(_ID_TO_SLUG.get(i, str(i)) for i in _classify_ids(v, stmt, guard_off))


# =========================================================
# P1 i18n 字典键
# =========================================================
P1_CASES = [
    # [12681428] (0,a.default)(o,"IncorrecormatofIDcard","身份证格式不正确") —— 同一文件
    # （app wx96e224d197ca3b8f / appservice.app.js）的 i18n 串表；这里用合成键。
    ("HomeBannerLabel7",
     't.setData({showPassWord: !1}), (0,a.default)(o,"HomeBannerLabel7","元/件/天"), '
     'this.checkPwd(this.data.pwd);'),
    ("OrderDetailLabel2",
     'if(t.pwdOk)(0,a.default)(o,"OrderDetailLabel2","订单详情"),this.setPwdState(!0);'),
    ("UnbindCardTip9",
     'u.unbind=function(t){return(0,a.default)(o,"UnbindCardTip9","解绑"),o.password};'),
]

# 同形但不构成「键, CJK 值」对 —— 不是噪音
P1_NEGATIVE_CASES = [
    # 后一个实参不是字面量 / 不含 CJK
    ("HomeBannerLabel7",
     't.setData({showPassWord: !1}), (0,a.default)(o,"HomeBannerLabel7","Home Banner"), '
     'this.checkPwd(this.data.pwd);'),
    # 值是 CJK 侧（键侧不是 ASCII）
    ("HomeBannerLabel7",
     't.setData({showPassWord: !1}), (0,a.default)(o,"首页横幅","HomeBannerLabel7"), '
     'this.checkPwd(this.data.pwd);'),
    # 值的右邻是 `:`（键名位）—— 由 fix31 保护，不看 P1
    ("HomeBannerLabel7",
     'this.hasSetPwd?"HomeBannerLabel7":"元/件/天", t.password&&t.checkPwd();'),
]


# =========================================================
# P2 密码学 OID / 算法名
# =========================================================
P2_CASES = [
    # [687634] a("1.2.840.113549.1.1.1","rsaEncryption"),a("…","md5WithRSAEncryption"),…
    ("hmacWithSHA224",
     'this.setData({passWord: e}), a("1.2.840.113549.2.8","hmacWithSHA224"), '
     'a("1.2.840.113549.2.9","hmacWithSHA256");'),
    ("sha256WithRSAEncryption",
     'a("1.2.840.113549.1.1.11","sha256WithRSAEncryption"), this.setData({pwd: t.pwd});'),
    ("pkcs8ShroudedKeyBag",
     'a("1.2.840.113549.1.12.10.1.2","pkcs8ShroudedKeyBag"), this.loadPassword(t.pwd);'),
]
# 算法名形态但既不在表里、也不邻接 OID → 不是噪音
P2_NEGATIVE_CASES = [
    # 算法名的**近似形**（既不在标准算法名表里，也不邻接 OID）
    ("customWithRSAWrapper",
     'this.setData({passWord: t}), setAlgo("customWithRSAWrapper");'),
    ("fooWithRSAEncryptionX",
     'this.setData({passWord: t}), this.loadPwd("fooWithRSAEncryptionX");'),
]


# =========================================================
# P3 webpack / 混淆 chunk id
# =========================================================
P3_CASES = [
    # [780861] t = [ "1055120GWJCQi", "260097VhsWmj", "2oiKOVL", "tap", … ]
    ("4829106KzWqLm",
     't = [ "10WciNmo", "271528DowfjB", "4829106KzWqLm", "18hgDLaF", "输入密码", '
     '"countDown", "78254iRFYbd", "1699335bewfHC" ], this.setData({pwd: e});'),
    # [44647] e=[…,"3758445RfzdXY","基本信息","then",…]
    ("3753465LvTNMB",
     'e = [ "camera", "66cjQJNk", "pageStatus", "3753465LvTNMB", "detail", "bindInfo", '
     '"2992160ZGRBTL", "then", "bind" ], t.setData({showPassWord: !1});'),
]
P3_NEGATIVE_CASES = [
    # 同形，但孤立出现（不在字符串表数组里）
    ("4829106KzWqLm", 't.setData({pwd: e}), t.verify("4829106KzWqLm");'),
    # 在数组里但同表没有第二个同形/混淆形元素
    ("4829106KzWqLm",
     't = [ "alpha", "beta", "gamma", "4829106KzWqLm", "delta", "epsilon" ], '
     'this.checkPwd(t.pwd);'),
]


# =========================================================
# P4 事件码 / 日志 tag
# =========================================================
P4_CASES = [
    # [12077837] "CCCH000001"==e.retMsgCode||"CCCD009003"===e.retMsgCode||…
    ("KXHC004271",
     '"KXHC004271"===e.retMsgCode?this.setPwdRandom():t.setData({pwdErr: 1});'),
    # [1084974] "BFF005122042"!=i.code …… 
    ("BFF005122043",
     'if("BFF005122043"!=i.code){var a=i.message||i.msg;t.setData({showPassword:!0});}'),
    # [2099852] u.beforeLog("XLRPTJKSQ2025060317","XLRPTXXSQ2025060317",[])
    ("XLRPTJKSQ2025060317",
     'u.beforeLog("XLRPTJKSQ2025060317", "XLRPTXXSQ2025060317", []), '
     'a.setData({isPassword: !0});'),
]
P4_NEGATIVE_CASES = [
    # [6299669] "admin123", "admin123" === r ? …（硬编码口令，fix12 红线值）
    ("admin123", '"admin123", "admin123" === r ? this.setData({adminPassword: ""}) : 0;'),
    # [7818686] if("a123456"==e.detail.value.password) …（系统初始化口令）
    ("a123456",
     'formSubmit:function(e){if("a123456"==e.detail.value.password)'
     'wx.showModal({content:"当前登录密码为系统初始化密码"});}'),
    # 事件码形态但不在比较位 / 不在日志 callee 实参位
    ("KXHC004271", 't.setData({pwd: e}), t.setCode("KXHC004271");'),
]


# =========================================================
# P5 密码学测试向量
# =========================================================
P5_CASES = [
    # [823587] X.strictEqual(a.PBKDF2("password","ATHENA.MIT.EDUraeburn",16),"cdedb5281bb2…")
    ("3b1f0c9d8e7a64521f0b3c9d8e7a6452",
     'X.strictEqual(a.PBKDF2("password", "salt", 16), '
     '"3b1f0c9d8e7a64521f0b3c9d8e7a6452"), this.setData({passWord: t});'),
    # [823588] 32 字节摘要（RFC 6070 形态）
    ("4b007901b765489abead49d926f721d065a429c1",
     'X.strictEqual(u.pbkdf2("password", "salt", 4096, 20), '
     '"4b007901b765489abead49d926f721d065a429c1"), this.checkPwd(this.data.pwd);'),
]
P5_NEGATIVE_CASES = [
    # 同样的 hex 值，但同一调用里没有 KDF / 盐字面量
    ("3b1f0c9d8e7a64521f0b3c9d8e7a6452",
     'this.setData({pwd: t}), t.checkSource("3b1f0c9d8e7a64521f0b3c9d8e7a6452");'),
    # 有 KDF 与盐，但值不是 hex 摘要（是口令盐本身）—— P5 不碰它
    ("QwErTy&2024",
     'X.strictEqual(a.PBKDF2("password", "QwErTy&2024", 16), this.sign), '
     'this.setData({passWord: t});'),
]


# =========================================================
# 受保护位置：五族形态 + fix31 三条保护 → 判定逐位不变，仍在 1203
# =========================================================
PROTECTED_CASES = [
    # 直键绑定（值本身是五族形态）
    ("HomeBannerLabel7", 'password: "HomeBannerLabel7", "元/件/天"'),
    ("hmacWithSHA224", 'passWord: "hmacWithSHA224"'),
    ("4829106KzWqLm", 'pwd: "4829106KzWqLm"'),
    ("KXHC004271", 'password = "KXHC004271"'),
    ("3b1f0c9d8e7a64521f0b3c9d8e7a6452", 'pwd: "3b1f0c9d8e7a64521f0b3c9d8e7a6452"'),
    # 密码族后缀键绑定
    ("4829106KzWqLm", 'multiShareMessagePasswordHint: "4829106KzWqLm"'),
    # 键名位（三元分支 / 右侧紧跟 `:`）
    ("HomeBannerLabel7", 't = this.hasSetPwd ? "HomeBannerLabel7" : "元/件/天"'),
    ("KXHC004271", 't = this.isPwd ? "KXHC004271" : "BLPS1206"'),
    # 值绑在**非密码键**上（保护口径是「有键即不动」）
    ("hmacWithSHA224",
     'algorithm: "hmacWithSHA224", t.password = e.pwd;'),
    ("4829106KzWqLm",
     'chunkId: "4829106KzWqLm", this.checkPassword(t.pwd);'),
    # password 名 callee 的实参（含非首参）
    ("KXHC004271", 'r.loginWithPassword("demo", "KXHC004271"), t.pwd = 1;'),
    ("3b1f0c9d8e7a64521f0b3c9d8e7a6452", 'e.pwdSetSk("3b1f0c9d8e7a64521f0b3c9d8e7a6452");'),
]

# fix12 红线值（弱口令/材料形）：三种语境下判定逐位不变
REDLINE_VALUES = [
    "password1", "password123", "admin123", "Admin123", "emoney5", "video123",
    "Nihao123", "1Passw0rd!xyz", "jia23xia4kaoshi5t2", "123456a",
    "o0IN8wTN50QMxX-V4siq_GSRFuts", "mnP7XKDCaWFjINWi", "signBoardPassword_S8hY",
]
REDLINE_STMTS = ['passWord: "%s"', 'pwd = "%s"', 'loginWithPassword("demo", "%s")']

# fix31 三族真删掉的值（材料形豁免的既有不变量）：本轮不许让它们回到 1203
FIX31_STILL_DROPPED = [
    ("=passWord==", 'this.setData({passWord:t}), console.log("=passWord==", t);'),
    ("passwd=", 'a = o.baseUrl + "/usr/" + o.user + "/passwd=" + n.pwd'),
    ("&toRoot=1",
     'url: "../login/login?phone=" + o.phone + "&password=" + o.form.passWord1 + "&toRoot=1"'),
]

# fix31c 的受保护材料（fix42 不许把它们带走）
FIX42_PROTECTED_MATERIAL = [
    "vPYkA3HAAviBMiXnWQUxWdoPKPs=",
    "Zq0s69O6YrvG090LgOg19z1l8RW99993=",
    "2019userperm=", "cndcarezIUAGNu5=", "xXxxx9xXX9XxXXx9X9x=",
    "Admin@123:456", "QwErTy&2024", "s3cr3tSalt&pepper", "MyPwd__2024",
    "67884E9%^&*67899A26C18DC28",
]
FIX42_MATERIAL_TPL = 'function chk(){if(pwdOk()){return someFn("%s")}}'

# 控制组：值不在窗口里 / 别的桶 / 形态不带结构证据
CONTROL_CASES = [
    ("4829106KzWqLm", 'this.setData({pwd:"other"}), t.verify("x");'),      # 值不在语句里
    ("/pages/index/index", 'url: "/pages/index/index"'),                    # 别的桶
    ("1Passw0rd!xyz", 'passWord: "1Passw0rd!xyz"'),                         # 红线值
]


def _assert_dropped(cases, family):
    """五族成员：fix42 前判 1203，fix42 后不判 1203，且**只**少 1203 这一个标签。"""
    for v, stmt in cases:
        before, after = _classify(v, stmt, guard_off=True), _classify(v, stmt)
        assert CCP_NAME in before, "[%s] fix42 前本应判 1203: %r (%r)" % (family, v, before)
        assert CCP_NAME not in after, "[%s] fix42 后仍判 1203: %r (%r)" % (family, v, after)
        lost = [n for n in before if n not in after]
        assert lost == [CCP_NAME], "[%s] 作用面不止 1203: %r -> %r" % (family, before, after)


def _assert_unchanged(cases, family):
    """受保护位置 / 反例：前后**逐位相同**，且仍在 1203。"""
    for v, stmt in cases:
        before, after = _classify(v, stmt, guard_off=True), _classify(v, stmt)
        assert before == after, "[%s] 判定被改动: %r (%r -> %r)" % (family, v, before, after)
        assert CCP_NAME in after, "[%s] 应保持 1203: %r (%r)" % (family, v, after)


# =========================================================
# 五族断言
# =========================================================
def test_fix42_p1_i18n_key_dropped():
    _assert_dropped(P1_CASES, "p1_i18n")


def test_fix42_p1_needs_cjk_pair():
    _assert_unchanged(P1_NEGATIVE_CASES, "p1_negative")


def test_fix42_p2_crypto_algo_dropped():
    _assert_dropped(P2_CASES, "p2_algo")


def test_fix42_p2_needs_oid_or_name_set():
    _assert_unchanged(P2_NEGATIVE_CASES, "p2_negative")


def test_fix42_p3_chunk_id_dropped():
    _assert_dropped(P3_CASES, "p3_chunk")


def test_fix42_p3_needs_string_table():
    _assert_unchanged(P3_NEGATIVE_CASES, "p3_negative")


def test_fix42_p4_event_tag_dropped():
    _assert_dropped(P4_CASES, "p4_event")


def test_fix42_p4_weak_password_comparand_kept():
    """比较运算数一侧的形态闸门：fix12 红线值 / 初始化口令不得被这一族吃掉。"""
    _assert_unchanged(P4_NEGATIVE_CASES, "p4_negative")


def test_fix42_p5_test_vector_dropped():
    _assert_dropped(P5_CASES, "p5_vector")


def test_fix42_p5_needs_kdf_and_salt():
    _assert_unchanged(P5_NEGATIVE_CASES, "p5_negative")


# =========================================================
# 判据本身（正反例）
# =========================================================
def test_fix42_family_predicates_one_by_one():
    """五族判据各自的直接正反例（不经整条分类链，避免别的规则掩盖判据本身）。"""
    p1 = _fam("is_cloud_password_i18n_key")
    assert p1("HomeBannerLabel7", '(0,a.default)(o,"HomeBannerLabel7","元/件/天")')
    assert p1("SellCenterText588", '(0,a.default)(o,"SellCenterText588","元/件/天"),x.pwd;')
    assert not p1("HomeBannerLabel7", '(0,a.default)(o,"HomeBannerLabel7","Home Banner")')
    assert not p1("HomeBannerLabel7", '"HomeBannerLabel7"')
    assert not p1("P@ssw0rd!2024", 'x.f("P@ssw0rd!2024","密码"),x.pwd;')   # 非键形
    assert not p1("元/件/天", 'x.f("元/件/天","元/件/天"),x.pwd;')          # 非 ASCII

    p2 = _fam("is_cloud_password_crypto_algorithm_name")
    assert p2("hmacWithSHA224", 'a("1.2.840.113549.2.8","hmacWithSHA224")')
    assert p2("rsaEncryption", 'a("1.2.840.113549.1.1.1","rsaEncryption")')
    assert p2("PBKDF2", "x.pwd=y;")            # 名称表（同一调用里不需要 OID）
    assert not p2("fooWithRSAEncryptionX", 'x.f("fooWithRSAEncryptionX")')  # 近似形不在表里
    assert not p2("customWithRSAWrapper", 'x.f("customWithRSAWrapper")')
    assert not p2("hmacWithSHA224X", 'x.f("hmacWithSHA224X")')

    p3 = _fam("is_cloud_password_obfuscated_chunk_id")
    assert p3("1055120GWJCQi",
              't=["1055120GWJCQi","260097VhsWmj","2oiKOVL","300nenSyN","15370xCyRGH",'
              '"4fKmdZj"]')
    assert not p3("1055120GWJCQi", 'x.pwd=y;x.f("1055120GWJCQi");')
    assert not p3("2oiKOVL",
                  't=["2oiKOVL","alpha","beta","gamma","delta","epsilon"]')  # 形态不匹配

    p4 = _fam("is_cloud_password_event_tag")
    assert p4("KXHC004271", '"KXHC004271"===e.retMsgCode')
    assert p4("KXHC004271", 'u.beforeLog("KXHC004271", e.pwd)')
    assert not p4("KXHC004271", 'x.f("KXHC004271")')            # 不在比较位/日志位
    assert not p4("admin123", '"admin123"===e.detail.value.password')   # 弱口令形态
    assert not p4("a123456", '"a123456"==e.detail.value.password')
    assert not p4("qrcode_19_noPowerError", '"qrcode_19_noPowerError"===e.retMsgCode')

    p5 = _fam("is_cloud_password_kdf_test_vector")
    assert p5("3b1f0c9d8e7a64521f0b3c9d8e7a6452",
              'X.strictEqual(a.PBKDF2("password","salt",16),'
              '"3b1f0c9d8e7a64521f0b3c9d8e7a6452")')
    assert not p5("3b1f0c9d8e7a64521f0b3c9d8e7a6452", 'x.f("3b1f0c9d8e7a64521f0b3c9d8e7a6452")')
    assert not p5("QwErTy&2024", 'X.strictEqual(a.PBKDF2("password","QwErTy&2024",16),x)')


# =========================================================
# 受保护位置矩阵 / 既有行为不动
# =========================================================
def test_fix42_protected_positions_kept():
    _assert_unchanged(PROTECTED_CASES, "protected")


def test_fix42_fix12_redline_values_kept():
    for v in REDLINE_VALUES:
        for tmpl in REDLINE_STMTS:
            stmt = tmpl % v
            before = _classify(v, stmt, guard_off=True)
            after = _classify(v, stmt)
            assert before == after, (v, stmt, before, after)
            assert CCP_NAME in after, (v, stmt, after)


def test_fix42_fix31_families_still_dropped():
    """fix31 三族照旧被拿走，且本轮**不改变**它们的判定（前后逐位相同）。"""
    for v, stmt in FIX31_STILL_DROPPED:
        before = _classify(v, stmt, guard_off=True)
        after = _classify(v, stmt)
        assert before == after, (v, stmt, before, after)
        assert CCP_NAME not in after, (v, stmt, before)


def test_fix42_fix31c_protected_material_kept():
    """fix31c 的 10 条受保护材料仍是 1203，且 fix42 前/后逐位相同。"""
    for v in FIX42_PROTECTED_MATERIAL:
        stmt = FIX42_MATERIAL_TPL % v
        before = _classify(v, stmt, guard_off=True)
        after = _classify(v, stmt)
        assert before == after, (v, before, after)
        assert CCP_NAME in after, (v, after)


def test_fix42_control_group_unchanged():
    for v, stmt in CONTROL_CASES:
        before = _classify(v, stmt, guard_off=True)
        assert before == _classify(v, stmt), (v, stmt, before)


def test_fix42_guard_only_reachable_from_cloud_password():
    """五族判据只在 is_cloud_password 链上被调用（别的桶不许经它改判）。"""
    import inspect
    # is_cloud_password → is_cloud_password_noise → 五族入口（fix31 的 `is_cloud_password_noise`
    # 同样是唯一调用点）
    assert "is_cloud_password_noise" in inspect.getsource(C.is_cloud_password)
    assert GUARD in inspect.getsource(C.is_cloud_password_noise)
    for name in FAMILY_FUNCS:
        callers = [fn for fn in (C.is_secret_key, C.is_server_cookie, C.is_payment_param,
                                 C.is_hex_token, C.is_analytics_key)
                   if name in inspect.getsource(fn)]
        assert not callers, (name, callers)
    # 五族之间不得互相调用（各自只看本值与它在语句里的位置）
    for name in FAMILY_FUNCS:
        body = inspect.getsource(_fam(name))
        for other in FAMILY_FUNCS:
            if other != name:
                assert other + "(" not in body, (name, other)


def test_fix42_value_absent_from_window_is_never_noise():
    """值不在 stmt 里 → 五族一律不判噪音（fix31 的 snippet-absent 口径）。"""
    guard = _guard()
    stmt = 'this.setData({pwd: "other"}), t.verify("x");'
    for v in ("4829106KzWqLm", "KXHC004271", "HomeBannerLabel7",
              "3b1f0c9d8e7a64521f0b3c9d8e7a6452", "hmacWithSHA224"):
        assert guard(v, stmt) is False, v


def _risk_by_name():
    import json
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "constant_types.json")
    with open(path, encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"].upper()] = it.get("risk", cat.get("default_risk"))
    return out


def test_fix42_no_label_at_risk_4_or_higher_added():
    """五族被拿走时只少 1203：不许搬进任何 risk>=4 的桶。"""
    risk = _risk_by_name()
    assert risk.get(CCP_NAME) == 5, risk.get(CCP_NAME)
    for cases in (P1_CASES, P2_CASES, P3_CASES, P4_CASES, P5_CASES):
        for v, stmt in cases:
            before = _classify(v, stmt, guard_off=True)
            after = _classify(v, stmt)
            added = [n for n in after if n not in before]
            bad = [n for n in added if (risk.get(n) or 0) >= 4]
            assert not bad, (v, bad, before, after)


def test_fix42_reverse_into_1203_is_zero():
    """反方向：五族判据只增不减 1203 的排除面，不可能把值推进 1203。"""
    for cases in (P1_CASES, P2_CASES, P3_CASES, P4_CASES, P5_CASES,
                  P1_NEGATIVE_CASES, P2_NEGATIVE_CASES, P3_NEGATIVE_CASES,
                  P4_NEGATIVE_CASES, P5_NEGATIVE_CASES, CONTROL_CASES):
        for v, stmt in cases:
            before = _classify(v, stmt, guard_off=True)
            after = _classify(v, stmt)
            if CCP_NAME not in before:
                assert CCP_NAME not in after, (v, stmt)


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
    print("fix42 cloud_cred_password 五族结构守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
