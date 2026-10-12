#!/usr/bin/env python3
"""risk 5 结构性误报四处修复（fix15 ① ② ③ ④）的回归验证。

四处都是「值形/语境的**结构性**误报」：判据本身没错，是它被用在了够不到的地方。

① `process_hex_token` 的无语境兜底
     去掉 `else -> server_cred_session_key`；并把 HEX_SESSION_CONTEXT_WORDS 里的
     裸子串 `sid` 改走「独立词/驼峰段」边界。
     三库实测：1603 桶 125,923 次出现里 124,868 次（99.16%）走的就是这条兜底
     （`5d41402abc4b2a76b9719d911017c592` = MD5("hello")，单库 578 次）。
② `CLOUD_TOKEN_PREFIXES` 里裸的 `npm_`
     is_cloud_token 原先只做 startsWith + 长度，路径/命令行全部命中。
     三库实测：cloud_cred_token(1205) 桶 582 值 **100% 是 npm_**，真 token 数为 0。
③ `cloud_cred_password` / `server_cred_cookie` 的单段标识符
     新增 is_single_segment_identifier_name（纯小写词 / 纯大写词 / 无数字驼峰 /
     尾部下划线 / `#`·`.`·`===`·`_` 前缀），外加「cookie 名 + 空值」。
④ `crypto_private_key` 的纯 PEM BEGIN 行
     它是拼接 PEM 的**分隔符字面量**，按构造不含密钥材料。
     三库实测：该桶 70.7% 的出现次数是这个形态。

本文件固化的边界（重点在**不许命中**的那些）：
  · ① 不许碰有语境的出口（token 语境仍 -> server_cred_token，session 语境仍 -> 1603）；
  · ① 的 `sid` 收紧不许把真 sid 键名（`sid:` / `storeSid`）一起挡掉；
  · ② 不许碰真 npm token（`npm_` + 36 位 Base62）与其它前缀（ghp_/glpat-/…）；
  · ③ 的**反例矩阵**：fix12 人工核定的弱口令与材料值一个都不许被吃掉
    （`password1` / `password123` / `Admin123` / `err3241` / `emoney5` /
     `mnP7XKDCaWFjINWi` / `o0IN8wTN50QMxX-V4siq_GSRFuts` / `signBoardPassword_S8hY` …），
    这是 fix12 明确留下的红线（「更宽的判据会丢掉这两个材料值」）；
  · ③ 不许碰 `name=<真值>` 形态的真 cookie；
  · ④ 不许碰完整 PEM、也不许碰**无头部的裸 base64 体**（可能是真密钥）。

标注「实测」的期望值均由 test-result/risk5_struct/ 下的探针脚本对着真分类器跑出来。

用法: .venv/bin/python -X utf8 unit-tests/test_risk5_struct_fp.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

SESSION_KEY = IDT.SERVER_CRED_SESSION_KEY
TOKEN = IDT.SERVER_CRED_TOKEN
CCP = IDT.CLOUD_CRED_PASSWORD
COOKIE = IDT.SERVER_CRED_COOKIE
CLOUD_TOKEN = IDT.CLOUD_CRED_TOKEN
PRIV = IDT.CRYPTO_PRIVATE_KEY
PUB = IDT.CRYPTO_PUBLIC_KEY


def _old_process_hex_token(s, stmt, src, sid, res):
    """修复前的 process_hex_token：带无语境兜底、sid 走裸子串。"""
    stmt_lower = stmt.lower() if stmt else ""
    if C.has_keyword_substring(stmt_lower, C.HEX_TOKEN_CONTEXT_WORDS):
        C.append_result(res, TOKEN, s, src, sid)
    elif C.has_keyword_substring(
            stmt_lower, ("session", "sessionid", "session_id", "sid", "credential")):
        C.append_result(res, SESSION_KEY, s, src, sid)
    else:
        C.append_result(res, SESSION_KEY, s, src, sid)


def _classify(v, stmt, interceptor_on=True):
    """跑一遍分类；interceptor_on=False 时**只关掉本轮这四条**，取「前」判定。"""
    saved = {}
    for name in ("is_single_segment_identifier_name", "_is_cookie_name_without_value",
                 "is_pem_header_fragment"):
        saved[name] = getattr(C, name)
        if not interceptor_on:
            setattr(C, name, lambda *a, **kw: False)
    saved["process_hex_token"] = C.process_hex_token
    if not interceptor_on:
        # ① 是「去掉 else 分支」，没法用恒 False 的开关表达，直接换回修复前的函数体。
        C.process_hex_token = _old_process_hex_token
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in saved.items():
            setattr(C, name, fn)


# =========================================================
# ① hex token 的无语境兜底
# =========================================================
MD5_HELLO = "5d41402abc4b2a76b9719d911017c592"
CURVE_POLY = "FFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"


def test_hex_noctx_no_longer_session_key():
    """无语境的 hex 不再被兜底成 server_cred_session_key(5)。"""
    for v in (MD5_HELLO, CURVE_POLY,
              "3086d221a7d46bcde86c90e49284eb15",
              "bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13"):
        got = _classify(v, '"%s"' % v)
        assert SESSION_KEY not in got, "无语境 hex 仍进 1603: %r -> %r" % (v, got)
        assert TOKEN not in got, "%r -> %r" % (v, got)


def test_hex_noctx_was_the_old_behaviour():
    """对照：关掉本轮改动后，同一个值确实回到 1603（证明是本改动在起作用）。"""
    assert _classify(MD5_HELLO, '"%s"' % MD5_HELLO,
                     interceptor_on=False) == [SESSION_KEY]


def test_hex_with_context_still_exits():
    """① 不许碰两条**有语境**的出口。"""
    r = []
    C.process_hex_token(MD5_HELLO, 'accessToken: "%s"' % MD5_HELLO, 0, 0, r)
    assert [x[0] for x in r] == [TOKEN], r
    r = []
    C.process_hex_token(MD5_HELLO, 'sessionKey: "%s"' % MD5_HELLO, 0, 0, r)
    assert [x[0] for x in r] == [SESSION_KEY], r
    r = []
    C.process_hex_token(MD5_HELLO, 'credential: "%s"' % MD5_HELLO, 0, 0, r)
    assert [x[0] for x in r] == [SESSION_KEY], r


def test_whole_function_of_process_hex_token_is_the_change():
    """无语境时 process_hex_token 产出为空（三条出口去掉一条 = 只剩两条）。"""
    r = []
    C.process_hex_token(MD5_HELLO, '"%s"' % MD5_HELLO, 0, 0, r)
    assert r == [], r


def test_sid_is_word_boundary_not_substring():
    """`sid` 裸子串收紧：canvasId / goodsId / transid / bxksid 里的 sid 不算语境。"""
    for stmt in ('canvasId: "%s"', 'goodsId: "%s"', 'transid: "%s"',
                 'cateRecommendWindowsId: "%s"', 'checkinsId: "%s"'):
        r = []
        C.process_hex_token(MD5_HELLO, stmt % MD5_HELLO, 0, 0, r)
        assert r == [], "裸 sid 子串仍开闸: %r -> %r" % (stmt, r)


def test_sid_real_keynames_still_count():
    """真 sid 键名必须仍然开闸：`sid:` / `storeSid` / `SID`。"""
    for stmt in ('sid: "%s"', 'storeSid = "%s"', 'SID:"%s"'):
        r = []
        C.process_hex_token(MD5_HELLO, stmt % MD5_HELLO, 0, 0, r)
        assert [x[0] for x in r] == [SESSION_KEY], "%r -> %r" % (stmt, r)


# =========================================================
# ② npm_ 前缀的体形守卫
# =========================================================
REAL_NPM_TOKEN = "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def test_npm_path_and_cmdline_not_cloud_token():
    """路径 / 命令行不再进 cloud_cred_token(5)。"""
    for v in ("npm_components/@ali/kobex-component/miniprogram_dist/lib/barcode/i",
              "npm_components/@alife/saas-mini/es/alert/index",
              "npm_config_report=true npm run task build plugin zhaoshang trade"):
        got = _classify(v, 'var a = "%s";' % v)
        assert CLOUD_TOKEN not in got, "%r -> %r" % (v, got)


def test_npm_real_token_still_hits():
    """真 npm token（npm_ + 36 位 Base62）必须仍然命中 1205。"""
    assert C.is_cloud_token(REAL_NPM_TOKEN) == (True, "npm")
    got = _classify(REAL_NPM_TOKEN, 'npmToken: "%s"' % REAL_NPM_TOKEN)
    assert CLOUD_TOKEN in got, got


def test_npm_guard_is_the_change():
    """对照：关掉体形守卫后路径确实回到 1205。"""
    v = "npm_components/@alife/saas-mini/es/alert/index"
    real = C.CLOUD_TOKEN_BODY_PATTERNS
    C.CLOUD_TOKEN_BODY_PATTERNS = {}
    try:
        got = _classify(v, 'var a = "%s";' % v)
    finally:
        C.CLOUD_TOKEN_BODY_PATTERNS = real
    assert CLOUD_TOKEN in got, got


def test_other_cloud_token_prefixes_unaffected():
    """② 只动 npm_，其它前缀行为逐位不变。"""
    assert C.is_cloud_token("ghp_" + "a" * 36) == (True, "github")
    assert C.is_cloud_token("glpat-" + "b" * 20) == (True, "gitlab")
    assert C.is_cloud_token("SG." + "c" * 22) == (True, "sendgrid")
    # 长度窗口 20..200 仍然生效
    assert C.is_cloud_token("ghp_" + "a" * 300) == (False, None)


# =========================================================
# ③ 单段标识符守卫
# =========================================================
def test_single_segment_guard_hits():
    """③ 的射程（三库真实头部值）。"""
    for v in ("WXOFFICIAL", "adapter", "timeout", "storage", "globalmemory",
              "requireIdCard", "mobileEmptyTips", "backFromPhone",
              "recordPsw_", "#tips_popup", ".page-recharge-wallet-list-balance",
              "===success", "_is_enter_password", "_submit", "#passwordBox"):
        assert C.is_single_segment_identifier_name(v), v


def test_single_segment_guard_counterexample_matrix():
    """③ 的反例矩阵：fix12 人工核定的真阳性 + 点名的弱口令形态，一个都不许命中。

    这一组是本轮最重要的边界 —— fix12 报告写明「更宽的判据会丢掉
    o0IN8wTN50QMxX-V4siq_GSRFuts 与 signBoardPassword_S8hY」，且
    `password1` / `password123` 这类弱口令与「字母+尾数字」的代码名同形。
    """
    for v in ("password1", "password123", "admin123", "qwerty123", "abc123",
              "Admin123", "video123", "ytx123456", "jdf123456", "dib20180606",
              "Nihao123", "Zmn666666", "123456a", "1a@genius", "Suning@12345",
              "HFG9K23FDHJ09Zm", "JE98DHGHI909375D", "A70702000008000803",
              "err3241", "emoney5", "passwordTips3", "currentTempStyle2",
              "o0IN8wTN50QMxX-V4siq_GSRFuts", "signBoardPassword_S8hY",
              "pste7JpTWOulCpvf", "mnP7XKDCaWFjINWi",
              "i38ku3M03iiMTNHPGl9By5TTE3lGMfa5",
              "280c5e0e7dcfbe3e1de718429cf91190fa80ac8d",
              "6BF477EBCC446F54E6512AFC0E976C41"):
        assert not C.is_single_segment_identifier_name(v), "误吃真阳性: %r" % v


def test_ccp_named_noise_goes_away():
    """③ cloud_cred_password：点名噪音值不再判 1203，真密码仍判 1203。"""
    for v in ("WXOFFICIAL", "requireIdCard", "===success", "#tips_popup",
              "_is_enter_password", ".page-recharge-wallet-list-balance"):
        got = _classify(v, 'password: "%s"' % v)
        assert CCP not in got, "%r -> %r" % (v, got)
    for v, stmt in (("Admin123", 'password: "%s"' % "Admin123"),
                    ("signBoardPassword_S8hY",
                     'signBoardPassword:"%s"' % "signBoardPassword_S8hY"),
                    ("o0IN8wTN50QMxX-V4siq_GSRFuts",
                     'password: "%s"' % "o0IN8wTN50QMxX-V4siq_GSRFuts")):
        got = _classify(v, stmt)
        assert got == [CCP], "%r -> %r" % (v, got)


def test_ccp_guard_is_the_change():
    """对照：关掉 ③ 的守卫后 WXOFFICIAL 确实回到 1203。"""
    v = "WXOFFICIAL"
    assert _classify(v, 'password: "%s"' % v, interceptor_on=False) == [CCP]


def test_cookie_single_word_noise_goes_away():
    """③ server_cred_cookie：代码标识符不再判 1604。"""
    for v in ("adapter", "timeout", "storage", "globalmemory", "cookies",
              "decompress", "transport"):
        got = _classify(v, 'var a = ["cookie", "%s"];' % v)
        assert COOKIE not in got, "%r -> %r" % (v, got)


def test_cookie_name_without_value_goes_away():
    """③ cookie 名 + 空值：`JSESSIONID=` 是拼接用的名字，不是 cookie 值。

    只覆盖 cookie_name_keywords 里已列出的名字 —— 判据要求「名字在关键词表里」
    是有意的保守边界：放宽成「任何 `名=` 空值」会把 base64 带 `=` 填充的真值
    （如 `LmF3LWNvb2tpZS1iYW5uZXI=`）一起吞掉。
    已知残留（不在关键词表，本轮不收）：`SessionWsid=`(32 次) / `_FSESSIONID=`(15 次)。

    ⚠️ fix16 ② 把「名字」那一半从「在关键词表里」放宽成
    「在表里 **或** 名字含 cookie 类词（token/session/sid/auth/…）**且** 是词形标识符」。
    因此下面 `mytoken=` 一行由「True（不许碰）」改成「命中（该收）」—— 它是 cookie 名不是
    值；`LmF3LWNvb2tpZS1iYW5uZXI=` 仍必须**不命中**（形态判据挡住，这是本轮红线）。
    新的完整边界在本文件末尾的 fix16 段与 unit-tests/test_risk5_path_ctx_cookie_name.py。
    """
    for v in ("JSESSIONID=", "PHPSESSID=", "sessionid=", "SessionId="):
        assert C._is_cookie_name_without_value(v, C.SERVER_COOKIE_NAME_KEYWORDS), v
        assert not C.is_server_cookie(v, "cookie: %s" % v), v
    # 右侧非空 = 真 cookie，不许被这条判据碰
    assert not C._is_cookie_name_without_value("JSESSIONID=abcd1234efg",
                                               C.SERVER_COOKIE_NAME_KEYWORDS)
    assert C.is_server_cookie("JSESSIONID=abcd1234efg", "cookie: JSESSIONID=abcd1234efg")
    # fix16 ②：名字含 cookie 类词 + 词形标识符 -> 命中（`mytoken` 是名不是值）
    assert C._is_cookie_name_without_value("mytoken=", C.SERVER_COOKIE_NAME_KEYWORDS)
    # 名字既不在表里、也不含 cookie 类词的，不许被碰
    assert not C._is_cookie_name_without_value("banner=", C.SERVER_COOKIE_NAME_KEYWORDS)
    assert not C._is_cookie_name_without_value("utm_source=", C.SERVER_COOKIE_NAME_KEYWORDS)
    # base64 带 `=` 填充的真值（含 cookie 类词的形态也没用，形态判据挡住）
    assert not C._is_cookie_name_without_value("LmF3LWNvb2tpZS1iYW5uZXI=",
                                               C.SERVER_COOKIE_NAME_KEYWORDS)
    assert not C._is_cookie_name_without_value("aXNsYW1pYy1zaWQ=",
                                               C.SERVER_COOKIE_NAME_KEYWORDS)


# =========================================================
# ④ 纯 PEM BEGIN 行
# =========================================================
def test_pem_header_only_is_not_a_key():
    """只有 BEGIN 行的 PEM 分隔符不再进 2102 / 2101。"""
    for v in ("-----BEGIN RSA PRIVATE KEY-----",
              "-----BEGIN RSA PRIVATE KEY-----\n",
              "-----BEGIN RSA PRIVATE KEY-----\r\n",
              "-----BEGIN PRIVATE KEY-----",
              "-----BEGIN PRIVATE KEY-----\n"):
        assert C.is_pem_header_fragment(v), v
        got = _classify(v, 'd="%s".concat(k);' % v.replace("\n", "\\n"))
        assert got == [], "%r -> %r" % (v, got)


def test_pem_public_header_only_covered_too():
    """同一形态在公钥桶里也存在（`-----BEGIN PUBLIC KEY-----`），一并收掉。"""
    for v in ("-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----\n"):
        got = _classify(v, 'd="%s".concat(k);' % v.replace("\n", "\\n"))
        assert PUB not in got, "%r -> %r" % (v, got)


def test_pem_guard_is_the_change():
    """对照：关掉 ④ 后纯头确实回到 2102。"""
    v = "-----BEGIN RSA PRIVATE KEY-----"
    got = _classify(v, 'd="%s".concat(k);' % v, interceptor_on=False)
    assert got == [PRIV], got


def test_complete_pem_key_still_hits():
    """④ 不许碰完整 PEM 密钥（有头有尾、体很长）。"""
    body = "MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQCKBk5YHVml" * 12
    key = "-----BEGIN PRIVATE KEY-----" + body + "-----END PRIVATE KEY-----"
    assert not C.is_pem_header_fragment(key)
    got = _classify(key, 'KEYUTIL.getKey("%s")' % key)
    assert got == [PRIV], got


def test_bare_base64_private_key_survives():
    """④ 裸 base64 体（无 PEM 头）**可能是真密钥的一部分**，不许动。"""
    bare = ("MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJ1VmeIz3nN//ZSn"
            * 6)
    assert not C.is_pem_header_fragment(bare)
    assert C.is_base64_private_key(bare)
    got = _classify(bare, 'exports.privateKey="%s"' % bare)
    assert got == [PRIV], got


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
    print("risk5 结构性误报四处修复验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
