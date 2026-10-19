"""crypto_static_iv 的「值位置」门（fix28）：数组字面量元素不再靠窗口里的 iv 词进 IV 桶。

背景（根因，只读普查见 test-result/fix28/probe_bindings.py）
----------------------------------------------------------------
`is_static_iv` / `is_static_aes_key` 的语境判定走的是**窗口**（值周围 512 字符里找
`iv` / `nonce` / `vector` / `sm4Iv` / `aesKey` …），与值是不是真坐在加密入口无关。于是
webpack 分包名表、文案表、路由表这类**数组字面量**里的元素，只要同一条语句窗口里出现过
iv/aesKey，就整批被判 crypto_static_iv(2104)。normal_quarkpan 实测：

  crypto_static_iv 全量 3602 链接 / 1630 值（其中 3463 链接在当前代码下重放仍判 IV）
  · 直接绑定在 crypto 族键上的       674 链接 / 255 值   ← 必须全保留
  · 数组/列表元素                    2344 链接 / 1159 值 ← 噪音主体
  · 非数组未绑定                     348 链接 / 153 值   ← 混合族，行为不变
  7 库普查里「数组自身绑定在 iv/aes 键上」= 0 例。

判据（本文件固化的契约）
------------------------
门放在 **链接产出点 `process_static_iv`**，不放在两个值形判据里：至少一个**独立出现**满足
  (1) 紧邻左侧的键（键与值之间不得出现 `, ; { }`）是 crypto 族
      （iv / aes / encrypt / decrypt / sm4 / des / nonce / vector）；或
  (2) 该出现不在数组字面量里；或
  (3) 所在数组是「加密材料形态列表」：数组绑定在 crypto 族键上，或 ≤5 个顶层元素且
      ≥n-1 个是加密材料形态（fix28b 后 = IV 形 16/24/32 hex、16/22/24 base64，加
      AES KEY 材料形 48/64 hex 与 32 位非驼峰单词串 alnum，见 `_iv_is_shaped_element`）
  → 产 crypto_static_iv；三条都不满足（数组噪音）→ **消费成 id_noise(2505, risk 0)**。

为什么必须放在产出点、且必须消费：判据返回 False 会让值**继续往下走**，落到既存的
窗口误报判据上。实测 normal_quarkpan 有 3 个值 / 6 条链接（BYD 车机 app-service.js 的
扁平配置数组）会因此从 risk 2(IV) 升到 risk 5(platform_app_secret) —— 正是 fix21
`625ea27` 修过的同一种「收严一处，让下游既存误报显形」。消费成 id_noise 与 fix21 的
处置同一模式（`NAME_CLASS_REJECT`）。
边界（刻意保留，不隐藏）：本值在窗口里没有独立出现（只是更长字面量的一部分 / 窗口截断）
→ 保留原判定（仍产 IV），按「不误伤」处理。

与 fix24/25/26 的 `_bound_value_keys` 同口径：值必须**自成字面量**（前/后紧邻标识符
字符的出现不算），键取**值左侧最近**的一个；本门只把「键与值之间」的放行字符放宽到
「没有 , ; { }」。

本文件固化的边界：
---------------------------------------------------------------
  1) 3 个真实形状的数组噪音（分包名大数组 / 短混合数组 / 嵌套数组）修复后不再判 IV，
     而是**消费成 id_noise**（risk 0），且不再掉进下游的高风险判据；
  2) 真阳性一个不许掉：`iv:` / `ivData` / `aesKey:` / `nonceStr:` 直接绑定的值、
     数组外的函数实参、对象字面量里的值、绑定在 crypto 键上的数组、短 IV 形态列表都保留；
  3) 同一值「一处进数组、另一处直接绑定」按「至少一个出现成立」保留；
  4) 键不是 crypto 族（`keys:` / `a`）时数组元素照样按 (2)(3) 判——判据不是「出现某个词就放行」；
  5) `is_static_iv` / `is_static_aes_key` 两个判据本身**不改**（门不在判据里），
     直接调用的既有契约（直接绑定真、标识符形假、数组噪音判据结果不变）保持原样。

值的形状均按真实语料替换成同长度同大小写的合成值；真实 (值, 语句) 只在未入库的
test-result/fix28/*.tsv 里，不写进本文件。

用法: .venv/bin/python -X utf8 unit-tests/test_fix28_iv_value_binding.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

IV = IDT.CRYPTO_STATIC_IV
NOISE = IDT.ID_NOISE

_FIX_ATTRS = ("_iv_value_position_kept",)


def _slugs(value, stmt, fix_on=True):
    """跑一遍分类；fix_on=False 时只关掉 fix28 的门（还原改动前行为）。

    开关是模块级名字，函数体在调用时才查——关掉后本文件之外的判定逐位不变。
    名字不存在时（fix28 未落地，即 RED 阶段）按「本来就关着」处理，断言照跑。
    """
    saved = [(n, getattr(C, n)) for n in _FIX_ATTRS if hasattr(C, n)]
    if not fix_on:
        if hasattr(C, "_iv_value_position_kept"):
            C._iv_value_position_kept = lambda *a, **k: True
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(value, 0, "test.js")])]
    finally:
        for name, fn in saved:
            setattr(C, name, fn)


# =========================================================
# 语料形状（值合成；语句取 real snippet 形状）
# =========================================================
V16 = "1a2B3c4D5e6F7a8b"          # 16 hex（真 IV 形态）
V16B = "2bC3d4E5f6G7h8I9"         # 16 base64 字符（列表兄弟值）
V24 = "e6kd2hklzrxyrlx1u1zpgzvz"  # 24 小写（AES KEY 形态，落进 appSecret 窗口）
AES32 = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"   # 32 alnum（AES KEY 形态）
AES32B = "QwErTyUiOpAsDfGhJkLzXcVbNm098765"  # 32 alnum（配对兄弟值）
H48 = "0123456789abcdef0123456789abcdef0123456789abcdef"          # 48 hex（AES KEY 形态）
H48B = "fedcba9876543210fedcba9876543210fedcba9876543210"         # 48 hex
H64 = ("0123456789abcdef0123456789abcdef0123456789abcdef"
       "0123456789abcdef")                                        # 64 hex
H64B = ("fedcba9876543210fedcba9876543210fedcba9876543210"
        "fedcba9876543210")                                       # 64 hex

# webpack 分包名大数组（真实来源：t=[...]，窗口里另有 l.iv）
SN_CHUNKS = ('l.iv=n,t=["abctoast","setData","1275804fysKdu","serpntId","#3CC51F",'
             '"eLPsW","detail","1a2B3c4D5e6F7a8b","EZNMJ","URPkD","redirectTo","code"]')
# 短混合数组（3 元素，只有 1 个 IV 形态）
SN_MIX3 = 'l.iv=n,e=["hello","1a2B3c4D5e6F7a8b","world"]'
# 嵌套数组（内层 3 元素，只有 1 个 IV 形态）
SN_NESTED = 'l.iv=n,e=[["hello","world"],["1a2B3c4D5e6F7a8b","x","y"]]'
# 数组绑定在**非** crypto 键上（keys:），元素仍是噪音
SN_KEYS = 'l.iv=n,keys=["1a2B3c4D5e6F7a8b","x","y"]'
# BYD 车机 app-service.js 的扁平配置数组形状：窗口里有 appSecret / aes_key，
# 值本身是数组元素（真实语料里这批值会掉进 platform_app_secret，见文件头「为什么」）。
SN_APPSECRET_TABLE = ('a=["https://commonminaapiuat.example.com:2443/denza","carMall",'
                      '"upDominHeadImg","trial","K7zTzPygAt3pjgznw3u5pkNS64jleAsu7uPyRL1x1e4",'
                      '"appSecret","26389250SlHbrF","wcAppid","afterSaleMall",'
                      '"7KAwahL9frKWj0HSYlArs0oQ5WsOvitQ3yT2tHzqczM","aes_key",'
                      '"e6kd2hklzrxyrlx1u1zpgzvz","domain","encrypt_kb","extension"]')


# =========================================================
# 1. 数组噪音：不再判 crypto_static_iv，消费成 id_noise(risk 0)
# =========================================================
def _assert_noise(value, stmt, fix_on=True):
    got = _slugs(value, stmt)
    assert IV not in got, got
    assert NOISE in got, got


def test_webpack_chunk_array_not_iv():
    _assert_noise(V16, SN_CHUNKS)


def test_short_mixed_array_not_iv():
    _assert_noise(V16, SN_MIX3)


def test_nested_array_not_iv():
    _assert_noise(V16, SN_NESTED)


def test_non_crypto_key_array_not_iv():
    """键 `keys` 不是 crypto 族 → 数组元素照判（不是「窗口里有 iv 就放行」）。"""
    _assert_noise(V16, SN_KEYS)


def test_appsecret_window_array_consumed_not_high_risk():
    """数组元素就算窗口里有 appSecret/aes_key，也只消费成 id_noise，不掉进 risk5 桶。

    这是本门放「产出点」而不是放判据里的原因：判据级放行会让值继续往下走，被
    is_app_key/is_secret_key 的窗口判定接手（实测 3 值 / 6 链接 risk 2 → 5）。
    """
    got = _slugs(V24, SN_APPSECRET_TABLE)
    assert IV not in got, got
    assert IDT.PLATFORM_APP_SECRET not in got, got
    assert got == [NOISE], got


# =========================================================
# 2. 真阳性保留：直接绑定 / 数组外 / 列表例外
# =========================================================
def test_direct_iv_key_kept():
    assert IV in _slugs(V16, 'iv: "1a2B3c4D5e6F7a8b"')


def test_direct_camel_iv_key_kept():
    assert IV in _slugs(V16, 'o.ivData="1a2B3c4D5e6F7a8b"')


def test_direct_aes_key_kept():
    assert IV in _slugs(AES32, 'aesKey: "AbCdEfGhIjKlMnOpQrStUvWxYz012345"')


def test_direct_nonce_key_kept():
    assert IV in _slugs(V16, 'nonceStr: "1a2B3c4D5e6F7a8b"')


def test_non_array_call_arg_kept():
    assert IV in _slugs(V16, 'l.iv=n,e.decrypt("1a2B3c4D5e6F7a8b",n)')


def test_object_literal_value_kept():
    """`{}` 不是数组字面量 → 值位置照旧。"""
    assert IV in _slugs(V16, 'l.iv=n,t={key:"1a2B3c4D5e6F7a8b"}')


def test_crypto_key_bound_array_kept():
    """数组自身绑定在 crypto 键上 → IV 形态列表例外（真 IV 数组）。"""
    assert IV in _slugs(V16, 'iv:["1a2B3c4D5e6F7a8b","2bC3d4E5f6G7h8I9"]')


def test_shaped_list_exception_kept():
    """≤5 个顶层元素且 ≥n-1 个 IV 形态 → 保留。"""
    assert IV in _slugs(V16, 'l.iv=n,e=["1a2B3c4D5e6F7a8b","2bC3d4E5f6G7h8I9"]')


# =========================================================
# 2b. fix28b：AES KEY 材料形的配对数组不再被当成数组噪音
# =========================================================
# 病根（真阳性损失）：`_iv_is_shaped_element` 原先只认 IV 形（16/24/32 hex 与 16/22/24 base64），
# 而 `is_static_aes_key` 还接受 32 位 alnum 与 48/64 位 hex。于是「数组元素全是 AES KEY 材料」
# 的合法数组一个元素都不算形态 → 列表例外不成立 → 值与它的兄弟一起被消费成 id_noise(2505, risk0)。
# 更糟的是结论取决于数组**变量名**：变量叫 `aesKeys` 时走「数组绑在 crypto 族键上」出口保留，
# 叫 `t` 时丢失 —— 变量的拼写不该决定一个真 AES KEY 的生死。
# 本组把「32 alnum 对 / 48 hex 对 / 64 hex 对」都钉住（变量名两种写法都测），
# 并把「>5 元素的同形数组仍是噪音」这条主数组噪音的边界一起钉住。
AES_KEY_PAIR_STMTS = [
    ('l.aesKey=k,t=["%s","%s"]' % (AES32, AES32B), AES32),
    ('l.aesKey=k,t=["%s","%s"]' % (H48, H48B), H48),
    ('l.aesKey=k,t=["%s","%s"]' % (H64, H64B), H64),
]


def test_aes_key_material_pair_array_kept():
    """两个 AES KEY 材料形元素（32 alnum / 48 hex / 64 hex）绑在**非** crypto 键名上也要保留。"""
    for stmt, value in AES_KEY_PAIR_STMTS:
        got = _slugs(value, stmt)
        assert IV in got, (value, stmt, got)
        assert NOISE not in got, (value, stmt, got)


def test_aes_key_material_pair_array_name_independent():
    """同一形状换成 `aesKeys=[...]`（crypto 族键名，改动前就走列表例外）→ 结论必须一致。"""
    for stmt, value in AES_KEY_PAIR_STMTS:
        named = stmt.replace("t=[", "aesKeys=[")
        assert IV in _slugs(value, named), (value, named)
        assert IV in _slugs(value, stmt), (value, stmt)


def test_aes_key_pair_gate_is_the_change():
    """对照：只关掉本门，这三对本来就是 IV（证明 RED 的差别确实来自这道门）。"""
    for stmt, value in AES_KEY_PAIR_STMTS:
        assert IV in _slugs(value, stmt, fix_on=False), (value, stmt)


def test_big_aes_key_material_table_still_noise():
    """六元同形数组仍按主数组噪音消费（>5 元素上限不许被本组放宽）——防「顺带把大表放行」。"""
    stmt = 'l.aesKey=k,t=["%s"]' % '","'.join(
        [AES32, AES32B] + [c * 32 for c in "abcdef"] )
    assert NOISE in _slugs(AES32, stmt), stmt
    assert IV not in _slugs(AES32, stmt), stmt


def test_iv_shape_list_boundary_unchanged():
    """IV 形列表的既有边界一行未动：3 元素里只有 1 个 IV 形 → 仍是噪音。"""
    assert NOISE in _slugs(V16, 'l.iv=n,e=["1a2B3c4D5e6F7a8b","x","y"]')
    assert IV not in _slugs(V16, 'l.iv=n,e=["1a2B3c4D5e6F7a8b","x","y"]')


def test_mixed_occurrence_kept():
    """同一值一处进大数组、另一处直接绑定在 crypto 键上 → 至少一个出现成立即保留。"""
    stmt = ('l.iv=n,t=["hello","world","1a2B3c4D5e6F7a8b","x","y","z"],'
            'o.sm4Iv="1a2B3c4D5e6F7a8b"')
    assert IV in _slugs(V16, stmt)


def test_no_independent_occurrence_kept():
    """边界：本值只是更长字面量的一部分（无独立出现）→ 保留原判定。"""
    assert IV in _slugs(V16, 'l.iv=n,e="xx1a2B3c4D5e6F7a8byy"')


# =========================================================
# 3. fix_on/off 开关：噪音行在改动前确实是 IV（证明门是唯一差别）
# =========================================================
def test_toggle_off_reproduces_pre_fix_behavior():
    for value, stmt in ((V16, SN_CHUNKS), (V16, SN_MIX3), (V16, SN_NESTED), (V16, SN_KEYS),
                        (V24, SN_APPSECRET_TABLE)):
        assert IV in _slugs(value, stmt, fix_on=False), (value, stmt)


def test_toggle_off_keeps_positives_too():
    for value, stmt in ((V16, 'iv: "1a2B3c4D5e6F7a8b"'),
                        (AES32, 'aesKey: "AbCdEfGhIjKlMnOpQrStUvWxYz012345"')):
        assert IV in _slugs(value, stmt, fix_on=False)


# =========================================================
# 4. 既有 is_static_iv / is_static_aes_key 契约（直接调用）不变
# =========================================================
def test_predicates_direct_calls_unchanged():
    assert C.is_static_iv(V16, 'iv: "%s"' % V16) is True
    assert C.is_static_aes_key(AES32, 'aesKey: "%s"' % AES32) is True
    # 标识符形护栏（既有）不受值位置门影响
    assert C.is_static_iv("noMobileFallback", 'iv: "noMobileFallback"') is False
    assert C.is_static_aes_key("noMobileFallback", 'aesKey: "noMobileFallback"') is False
    # 数组里的标识符形值本来就不判 IV，门之后也不判
    assert C.is_static_iv("noMobileFallback", 'l.iv=n,e=["noMobileFallback","x","y"]') is False


def test_gate_is_not_inside_predicates():
    """门在产出点、不在判据里：数组噪音的**判据**结果保持原样（由 process 消费）。

    若日后有人把门搬回 `is_static_iv`，这条会红 —— 那正是要提醒的回归：判据级放行
    会让值继续往下走，落进 is_app_key/is_secret_key 的窗口误报（risk 2 → 5）。
    """
    assert C.is_static_iv(V16, SN_CHUNKS) is True
    assert C.is_static_aes_key(V24, SN_APPSECRET_TABLE) is True


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
    print("fix28 IV 值位置绑定门：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
