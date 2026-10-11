"""剥值第 1 批：has_secret_context / has_appkey_context / has_session_key_context /
has_aes_key_context 的签名收紧与剥值接线。

背景见 unit-tests/test_external_context.py（第 0 批）。第 1 批把同样的口径推广到
4 个「干净的 has_*_context 包装函数」，每个都：

  1) 多一个 `value` 形参，且**无默认值** —— 漏改一个调用点就 TypeError，
     而不是静默退回旧行为（这是本轮刻意选择的失败方式）；
  2) 函数体改走 external_context(stmt, value)：只删**值位置**的出现，保留键名位置。

覆盖：
  1) 4 个判据都要求 value（少传就 TypeError）；
  2) 值自证不再单独开闸（`["getSecretTest"]` / `appKey: "appKey"` / `aesKey: "aesKey"`
     / `sessionKey: "sessionKey"`）；
  3) 键名位置的出现**仍**提供语境（自赋值密钥不被误剥）；
  4) 真语境不受影响（防漏报，核心）；
  5) 流水线级：4 个判据各自对应的类型，真值必须仍然落进原桶；
  6) 空值 / 空语句 / 值不在窗口 = 空操作，不崩。

用法: .venv/bin/python -X utf8 unit-tests/test_external_context_b1.py
（本机 .venv 没装 pytest，断言全是纯 assert，两种跑法一致。）
"""

import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402


# ================= 1. value 无默认值：少传就 TypeError =================
def test_all_four_require_value():
    for fn in (C.has_secret_context, C.has_appkey_context,
               C.has_session_key_context, C.has_aes_key_context):
        try:
            fn('secretKey: "x"')
        except TypeError:
            pass
        else:
            raise AssertionError("%s 应当要求 value 参数（无默认值）" % fn.__name__)


# ================= 2. 值自证不再单独开闸 =================
def test_secret_self_reference_no_longer_opens_gate():
    # 值本身含 secret，但语句里它只是一个数组元素 —— 没有别的 secret 语境
    assert C.has_secret_context('["getSecretTest"]', "getSecretTest") is False
    # 对照：有真键名时仍然通过
    assert C.has_secret_context('secretKey: "getSecretTest"', "getSecretTest") is True


def test_appkey_self_reference_no_longer_opens_gate():
    assert C.has_appkey_context('["appKey"]', "appKey") is False
    assert C.has_appkey_context('appKey: "x"', "x") is True


def test_aes_key_self_reference_no_longer_opens_gate():
    # 值 == 键名 → 键名位保留 → 仍然通过（自赋值密钥不能误剥）
    assert C.has_aes_key_context('aesKey: "aesKey"', "aesKey") is True
    # 值只是数组元素 → 剥掉后没有 aes 语境
    assert C.has_aes_key_context('["aesKey"]', "aesKey") is False


def test_session_key_self_reference_no_longer_opens_gate():
    assert C.has_session_key_context('["sessionKey"]', "sessionKey") is False
    assert C.has_session_key_context('sessionKey: "sessionKey"', "sessionKey") is True


# ================= 3. 键名位置保留 =================
def test_keyname_occurrence_is_kept():
    assert C.external_context('secretKey: "secretKey"', "secretKey") == 'secretKey: ""'
    assert C.has_secret_context('secretKey: "secretKey"', "secretKey") is True
    stmt = 'appKey:"appKey"'
    assert C.external_context(stmt, "appKey") == 'appKey:""'
    assert C.has_appkey_context(stmt, "appKey") is True


# ================= 4. 真语境不受影响 =================
def test_real_contexts_still_hit():
    assert C.has_secret_context('appSecret: "SOMEVALUE1234567890"', "SOMEVALUE1234567890")
    assert C.has_secret_context('app_secret: "SOMEVALUE1234567890"', "SOMEVALUE1234567890")
    assert C.has_secret_context('client_secret="x"', "x")
    assert C.has_appkey_context('access_key: "AKIAIOSFODNN7EXAMPLE"', "AKIAIOSFODNN7EXAMPLE")
    assert C.has_aes_key_context('encrypt_key: "0123456789abcdef"', "0123456789abcdef")
    assert C.has_aes_key_context('sm4_key = "ab"', "ab")
    assert C.has_session_key_context('e.session_key = "x"', "x")
    assert C.has_session_key_context('SessionKey: "x"', "x")


# ================= 5. 空值 / 空语句 = 空操作 =================
def test_empty_is_noop():
    for fn in (C.has_secret_context, C.has_appkey_context,
               C.has_session_key_context, C.has_aes_key_context):
        assert fn("", "") is False                      # 空语句
        assert fn('whatever: "x"', "notInThere") is False   # 值不在窗口里
    # value="" → external_context 是空操作 → 等价于旧行为（这条是 has_iv_context 的默认值
    # 所依赖的性质：4 个判据本轮**不给**默认值，但传空串必须仍然是「不剥」而不是「剥掉全部」）
    for fn, stmt in ((C.has_secret_context, 'secretKey: "x"'),
                     (C.has_appkey_context, 'appKey: "x"'),
                     (C.has_session_key_context, 'sessionKey: "x"'),
                     (C.has_aes_key_context, 'aesKey: "x"')):
        assert fn(stmt, "") is True, (fn.__name__, stmt)


# ================= 6. 流水线级：真值仍落进原桶 =================
def _slugs(value, stmt):
    out = C.perform_constant_classifying([stmt], [(value, 0, "src")])
    return [r[0] for r in out]


def test_pipeline_keeps_real_positives():
    hex32 = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
    assert IDT.PLATFORM_APP_SECRET in _slugs(hex32, 'appSecret: "%s"' % hex32)
    # appKey 上下文 → 公开 AppKey 分流到 saas_analytics_key
    apikey = "EpdnnX4MBpPjdlsZPJBfBJEoywWcXa"
    assert IDT.SAAS_ANALYTICS_KEY in _slugs(apikey, 'appKey: "%s"' % apikey)
    # AES KEY：is_static_aes_key 与 is_static_iv 共用 process_static_iv，
    # 所以两者都归 crypto_static_iv。
    aes = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
    assert IDT.CRYPTO_STATIC_IV in _slugs(aes, 'aesKey: "%s"' % aes)


def test_pipeline_drops_self_referential_identifier():
    # 值只是个函数名，靠自身含 secret 混进 1101 —— 剥值后应丢
    out = _slugs("getSecretTest", '["getSecretTest"]')
    assert IDT.PLATFORM_APP_SECRET not in out, out


def _run_standalone():
    """本机没装 pytest（.venv 里只有 esprima/PyMySQL），自带 runner。"""
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
    print("剥值第 1 批验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
