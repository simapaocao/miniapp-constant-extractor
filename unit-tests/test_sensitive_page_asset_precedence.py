#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""敏感页面路径(1901) 与「资源/模块后缀」的优先级回归。

根因
-------------------------------------------------------------------------------
`url_process_path` 原先的判定顺序是
    PLUGIN → **SENSITIVE** → PARAM → ASSET → MODULE → PAY/LOGIN
而 SENSITIVE 判据 `has_keyword_substring(rel_path.lower(), SENSITIVE_PAGE_KEYWORDS)`
是**裸子串**（("admin", "test", "debug", "config", "internal", "manage")）。于是凡是
路径里出现 "manage"/"test"/"config" 这类**词干巧合**的带后缀值，都被抢进 1901：

    `pages/images/management.png`   （management ⊃ manage）→ 1901，真身是静态资源 1905
    `pages/test/test.js`            （目录名 test）        → 1901，真身是模块引用 1906

`pages/test/test.js` 还会连带得到「模块引用」的宽义标签（risk>0），而它只是编译产物的
模块 id —— 本文件同时守住 `.js` 身份**不进 1907**（那条是刻意留下的残余，见
MINIAPP_COMPILER_NONMODULE_EXTENSIONS 的注释）。

修法（只动 url_process_path：把后缀判据提前，并给它加 `?` 门）
-------------------------------------------------------------------------------
把 ASSET/MODULE 两条后缀判据挪到 PLUGIN 之后、SENSITIVE 之前，条件是
`"?" not in rel_path`：不带 `?` 的值命中资源/模块后缀即定性为 ASSET/MODULE，不再进
SENSITIVE 的裸子串猜；带 `?` 的值保持原顺序（PARAM 门）—— `/xxx.png?t=` 这类缓存串资源
必须继续落 1904，「敏感页面 + 查询串」也必须继续落 1901。原位那两条后缀判据因此不可达，已删。
`#` 片段**不剥**（只有 api_params 那一族的 `slash_path_body` 剥 `#`）：`...png#frag` 仍落
1901；要动 `#` 得另开一次带测量的改动，本文件只把它钉住。

`url_process_path` 的两种入参形态（本次改动对两者语义一致）
-------------------------------------------------------------------------------
`rel_path` 有两种来源，两种都要能定性：
  ① **剥掉 `pages/` / `/pages/` 前缀**后的值 —— 链首命中 MINIAPP_PAGES_PREFIX_WORDS 后以
     `offset=len(pattern)` 调用（perform_constant_classifying 的 miniapp pages 分支）；
  ② **整条斜杠路径**（`offset=0`）—— 斜杠类处理器（process_generic_slash_prefixed_constant
     的「敏感路由词」/「页面路由」两步）与带参页面路由处理器（process_miniapp_api_params）
     复用同一分发函数时传的是整值。
后缀判据与 `?` 门看的都是**整个** `rel_path`，所以两种形态下语义相同；本文件两形态各钉一组
用例（见 test_both_rel_path_shapes）。

红线（数字来自父任务的**只读基线回放**，不是本文件的本地实测）
-------------------------------------------------------------------------------
该回放在本仓库**没有落任何产物文件**（已核对：仓库内除本文件外没有这些数字的来源），所以
下面把它当「外部报告」引用、不作断言依据；本文件的期望值全部是逐值对着当前分类器跑出来的
（本机可复跑）。外部只读回放的报告口径：允许移动的只有「带后缀的伪敏感值」，其中
4,109 个值落 1906、415 个值落 1905，**0 行数变化**；真路由（`pages/test/index`、
`/pages/admin/detail/index?id=1` → 1901）与编译产物身份（`.wxml`/`.wxss`/`.json` → 1907）
一个都不许动。

本文件自带 runner（本机 .venv 没有 pytest）；「改动前」判定沿用 test_fix20_four_noise 的
gate 约定：只把被改的 `url_process_path` 换成改动前的顺序快照，链上其它判据跑真的，
所以改动前 `...wxml` 仍会被链尾改判成 1907（这正是要守住的边界）。

用法: .venv/bin/python -X utf8 unit-tests/test_sensitive_page_asset_precedence.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

SENS = IDT.MINIAPP_PAGE_PATH_SENSITIVE   # 1901
ASSET = IDT.MINIAPP_PATH_ASSET           # 1905
MODULE = IDT.MINIAPP_PATH_MODULE         # 1906
NOISE = IDT.MINIAPP_NOISE                # 1907
PARAM = IDT.MINIAPP_SCENE_PARAM          # 1904
PLUGIN = IDT.MINIAPP_PLUGIN_URL          # 1903


def classify(v, stmt):
    """跑一遍真分类器，返回产出的 {类型 id}。"""
    return {r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, "probe")])}


def _url_process_path_before(rel_path):
    """改动前的 url_process_path 顺序快照（SENSITIVE 先于 ASSET/MODULE）—— 仅测试用。"""
    s_lower = rel_path.lower()
    if rel_path.startswith("plugin"):
        return "PLUGIN"
    if C.has_keyword_substring(s_lower, C.SENSITIVE_PAGE_KEYWORDS):
        return "SENSITIVE"
    if "?" in rel_path:
        return "PARAM"
    if any(s_lower.endswith(ext) for ext in C.MINIAPP_ASSET_EXTENSIONS):
        return "ASSET"
    if any(s_lower.endswith(ext) for ext in C.MINIAPP_MODULE_EXTENSIONS):
        return "MODULE"
    if "pay.php" in s_lower:
        return "PAY"
    if "login.php" in s_lower:
        return "LOGIN"
    return "UNKNOWN"


def classify_before_fix(v, stmt):
    """只替换被改的 url_process_path，取「前」判定（复现修复前落 1901 的那个事实）。"""
    real = C.url_process_path
    C.url_process_path = _url_process_path_before
    try:
        return classify(v, stmt)
    finally:
        C.url_process_path = real


# =========================================================
# 1) 资源后缀先于「裸子串敏感」：management.png / logo.png
# =========================================================
def test_asset_extension_beats_sensitive_substring():
    """带资源后缀的伪敏感值退出 1901，落 1905（1901 里不该有静态资源）。"""
    cases = [("pages/images/management.png", 'imageSrc = "pages/images/management.png"'),
             ("/pages/admin/logo.png", 'imageSrc = "/pages/admin/logo.png"'),
             ("pages/test/images/icon.png", 'imageSrc = "pages/test/images/icon.png"')]
    for v, stmt in cases:
        assert classify_before_fix(v, stmt) == {SENS}, "%r 改动前应落 1901（根因复现）" % v
        after = classify(v, stmt)
        assert after == {ASSET}, "%r 后判定 %r != {1905}" % (v, after)


# =========================================================
# 2) 模块后缀先于「裸子串敏感」：test.js / config.json
# =========================================================
def test_module_extension_beats_sensitive_substring():
    """带模块后缀的伪敏感值退出 1901，落 1906。"""
    cases = [("pages/test/test.js", '__wxAppCode__["pages/test/test.js"] = function(){}'),
             ("pages/debug/config.json", 'url: "pages/debug/config.json"')]
    for v, stmt in cases:
        assert classify_before_fix(v, stmt) == {SENS}, "%r 改动前应落 1901（根因复现）" % v
        after = classify(v, stmt)
        assert after == {MODULE}, "%r 后判定 %r != {1906}" % (v, after)


def test_js_compiler_identity_stays_module():
    """`.js` 的编译器身份刻意不进 1907（MINIAPP_COMPILER_NONMODULE_EXTENSIONS 不含 .js）。"""
    v = "pages/test/test.js"
    stmt = "__wxAppCode__['pages/test/test.js'] = function(){}"
    after = classify(v, stmt)
    assert after == {MODULE}, "%r 后判定 %r != {1906}" % (v, after)
    assert NOISE not in after, "%r 不应被改判成 1907" % v


# =========================================================
# 2b) 后缀大小写 / `#` 片段 / PLUGIN 先行 / 两种入参形态
# =========================================================
def test_mixed_case_extension_is_asset():
    """后缀判据走 `rel_path.lower()`：`.PNG` / `.Png` 同样先于敏感关键词。"""
    cases = [("pages/test/test.PNG", 'imageSrc = "pages/test/test.PNG"'),
             ("pages/images/management.Png", 'imageSrc = "pages/images/management.Png"')]
    for v, stmt in cases:
        assert classify_before_fix(v, stmt) == {SENS}, "%r 改动前应落 1901（根因复现）" % v
        after = classify(v, stmt)
        assert after == {ASSET}, "%r 后判定 %r != {1905}" % (v, after)


def test_fragment_suffix_is_not_stripped():
    """`#` 片段**不在**本次改动范围：`...png#frag` 仍落 1901，且改动前后一致。"""
    v = "pages/images/management.png#frag"
    stmt = 'imageSrc = "pages/images/management.png#frag"'
    after = classify(v, stmt)
    assert after == {SENS}, "%r 后判定 %r != {1901}（`#` 被本改动顺手剥了）" % (v, after)
    assert classify_before_fix(v, stmt) == after, "%r 被本轮改动影响了" % v
    assert C.url_process_path("images/management.png#frag") == "SENSITIVE"


def test_plugin_prefix_still_wins():
    """PLUGIN 仍在最前：带后缀 + 敏感词的 plugin 路径不许被后缀判据抢走。"""
    assert C.url_process_path("plugin/test/x.js") == "PLUGIN"
    v, stmt = "pages/plugin/test/x.js", 'url: "pages/plugin/test/x.js"'
    after = classify(v, stmt)
    assert after == {PLUGIN}, "%r 后判定 %r != {1903}" % (v, after)
    assert classify_before_fix(v, stmt) == after, "%r 被本轮改动影响了" % v


def _captured_rel_paths(v, stmt):
    """把 url_process_path 包一层记录器，返回链上真正喂进来的 rel_path（连同产出）。"""
    seen = []
    real = C.url_process_path

    def spy(rel_path):
        seen.append(rel_path)
        return real(rel_path)

    C.url_process_path = spy
    try:
        got = classify(v, stmt)
    finally:
        C.url_process_path = real
    return seen, got


def test_both_rel_path_shapes():
    """两种入参形态：① 剥掉 `pages/` / `/pages/` 前缀；② 整条斜杠路径（offset=0）。

    这条用例不靠推断：用记录器证明链上喂进来的确实是这两种形态。
    """
    # ① 链首命中 MINIAPP_PAGES_PREFIX_WORDS 后以 offset=len(pattern) 调用 → 传剥过前缀的值
    assert _captured_rel_paths("pages/test/test.js", 'url: "pages/test/test.js"') \
        == (["test/test.js"], {MODULE})
    assert _captured_rel_paths("/pages/admin/config.json", 'url: "/pages/admin/config.json"') \
        == (["admin/config.json"], {MODULE})
    assert _captured_rel_paths("pages/images/management.png",
                              'imageSrc = "pages/images/management.png"') \
        == (["images/management.png"], {ASSET})
    # ② 斜杠类处理器以 offset=0 调用 → 传整条路径（本形态本轮也一并适用同一条后缀规则）
    assert _captured_rel_paths("/packageI/pages/test/index", 'url: "/packageI/pages/test/index"') \
        == (["/packageI/pages/test/index"], {SENS})
    # 同一条后缀规则对两种形态语义一致（函数直接契约）
    assert C.url_process_path("test/test.js") == C.url_process_path("/packageI/pages/test/test.js") \
        == "MODULE"
    # 剥前缀形态确实被本轮挪出 1901（`/pages/` 前缀来自链首，喂进去的是 `admin/config.json`）
    assert classify_before_fix("/pages/admin/config.json", 'url: "/pages/admin/config.json"') == {SENS}
    assert classify("/pages/admin/config.json", 'url: "/pages/admin/config.json"') == {MODULE}
    # 整条斜杠路径里带后缀的 .js/.png 由更早的处理器直接出口（记录器捕获为空）→ 本轮对它们是恒等
    for v in ("/packageI/pages/test/test.js", "/packageI/pages/images/management.png"):
        stmt = 'url: "%s"' % v
        assert _captured_rel_paths(v, stmt)[0] == [], "%r 不应走到 url_process_path" % v
        assert classify(v, stmt) == classify_before_fix(v, stmt), "%r 被本轮改动影响了" % v


# =========================================================
# 3) 真敏感页面（无后缀）仍落 1901 —— 收窄不削弱这条出口
# =========================================================
def test_extension_free_sensitive_paths_unchanged():
    """真路由：`pages/test/index`、`/pages/admin/detail/index` 前后都是 1901。"""
    cases = [("pages/test/index", 'url: "pages/test/index"'),
             ("/pages/admin/detail/index", 'url: "/pages/admin/detail/index"'),
             ("pages/config/settings", 'url: "pages/config/settings"'),
             ("pages/internal/manage/index", 'url: "pages/internal/manage/index"')]
    for v, stmt in cases:
        after = classify(v, stmt)
        assert after == {SENS}, "%r 后判定 %r != {1901}" % (v, after)
        assert classify_before_fix(v, stmt) == after, "%r 被本轮改动影响了" % v


# =========================================================
# 4) `?` 门：PARAM 优先级与「敏感 + 查询串」都不许变
# =========================================================
def test_query_string_keeps_param_and_sensitive_order():
    """带 `?` 的值一律走原顺序：后缀判据不许抢在 PARAM 前（否则 1904 → 1905）。"""
    v, stmt = "pages/images/logo.png?t=1", 'imageSrc = "pages/images/logo.png?t=1"'
    after = classify(v, stmt)
    assert after == {PARAM}, "%r 后判定 %r != {1904}（PARAM 门被后缀判据抢走）" % (v, after)
    assert classify_before_fix(v, stmt) == after, "%r 被本轮改动影响了" % v


def test_query_string_sensitive_paths_unchanged():
    """带查询串的敏感页面仍落 1901（后缀判据只对无 `?` 的值生效）。"""
    cases = [("/pages/admin/detail/index?id=1", 'url: "/pages/admin/detail/index?id=1"'),
             ("pages/images/management.png?t=1", 'imageSrc = "pages/images/management.png?t=1"'),
             ("pages/config/logo.png?t=1", 'imageSrc = "pages/config/logo.png?t=1"')]
    for v, stmt in cases:
        after = classify(v, stmt)
        assert after == {SENS}, "%r 后判定 %r != {1901}" % (v, after)
        assert classify_before_fix(v, stmt) == after, "%r 被本轮改动影响了" % v


# =========================================================
# 5) 编译产物身份（fix20 ④ / fix23 的链尾改判）仍落 1907
# =========================================================
def test_compiler_file_identity_stays_noise():
    """`.wxml`/`.wxss` 身份：后判定仍是 1907，且改动前后一致（不许退回 risk 桶）。"""
    cases = [("pages/admin/x/hotspots-admin.wxml",
              "__wxAppCode__['pages/admin/x/hotspots-admin.wxml'] = "
              "$gwx_XC_10('./admin/x/hotspots-admin.wxml')"),
             ("pages/internal/module.wxss",
              '__wxAppCode__["pages/internal/module.wxss"] = setCssToHead([])'),
             ("pages/debug/config.json", "__wxAppCode__['pages/debug/config.json']={}")]
    for v, stmt in cases:
        after = classify(v, stmt)
        assert after == {NOISE}, "%r 后判定 %r != {1907}" % (v, after)
        assert SENS not in after, "%r 退回 1901（risk 桶被加回噪音）" % v
        assert classify_before_fix(v, stmt) == after, "%r 被本轮改动影响了" % v


# =========================================================
# 6) 被改函数的直接契约（rel_path 视角）
# =========================================================
def test_url_process_path_precedence_contract():
    """PLUGIN 仍最前；无 `?` 时后缀先于 SENSITIVE；PAY/LOGIN 仍归自己；`?` 落 PARAM。"""
    assert C.url_process_path("plugin/list/list.wxml") == "PLUGIN"
    assert C.url_process_path("test/test.js") == "MODULE"
    assert C.url_process_path("images/management.png") == "ASSET"
    assert C.url_process_path("test/index") == "SENSITIVE"
    assert C.url_process_path("admin/detail/index?id=1") == "SENSITIVE"
    assert C.url_process_path("images/logo.png?t=1") == "PARAM"
    assert C.url_process_path("pay/pay.php") == "PAY"
    assert C.url_process_path("login/login.php") == "LOGIN"


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
    print("敏感页面路径/资源后缀优先级验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
