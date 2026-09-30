import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

import extract_js_consts
from extract_js_consts import extract_from_js_text
from extract_js_consts import StatementStore


def _strings(constants):
    # constants: Set[Tuple[str, int, str]]
    return {s for (s, _stmt_id, _stmt) in constants}


def test_extracts_some_known_strings():
    js = """
    var a = "hello";
    const b = "WEIXINAD";
    obj.url = "applyFormDataConfig";
    """
    extract_js_consts.JS_FILE_CONTENT = js
    store = StatementStore()
    out = extract_from_js_text(0, len(js), store)

    strings = _strings(out)
    print(strings)
    assert "hello" in strings
    assert "WEIXINAD" in strings
    assert "applyFormDataConfig" in strings


# ---------------------------------------------------------------------------
# 新增用例：esprima 4.x 不认识的语法要有兜底（计划 3.3）
# ---------------------------------------------------------------------------


def _extract(code):
    """在独立的 JSParseContext 里跑一遍，避免污染模块级全局变量。"""
    ctx = extract_js_consts.JSParseContext(code)
    store = StatementStore()
    out = extract_from_js_text(0, len(code), store, ctx=ctx)
    return _strings(out)


def test_nullish_coalescing_url():
    js = 'const u = opt ?? "https://api.example.com/v1/login";'
    assert "https://api.example.com/v1/login" in _extract(js)


def test_class_field_url():
    js = 'class A { url = "https://a.example.com/x" }'
    assert "https://a.example.com/x" in _extract(js)


def test_logical_assignment_url():
    js = 'x ||= "https://b.example.com/y";'
    assert "https://b.example.com/y" in _extract(js)


def test_async_generator_url():
    js = 'async function* g(){ yield "https://c.example.com/z" }'
    assert "https://c.example.com/z" in _extract(js)


def test_short_chunk_that_fails_to_parse_still_yields_strings():
    """覆盖 consumed 判断的 bug：短 chunk 解析失败时也必须走兜底。"""
    js = 'const a = b ?? "https://f.example.com/m";'
    assert len(js) < extract_js_consts.MINI_FUNC_SIZE
    assert "https://f.example.com/m" in _extract(js)


def test_es5_regression_unchanged():
    """原来就能提取的 ES5 用例，结果不变。"""
    js = """
    var a = "hello";
    const b = "WEIXINAD";
    obj.url = "applyFormDataConfig";
    """
    strings = _extract(js)
    assert "hello" in strings
    assert "WEIXINAD" in strings
    assert "applyFormDataConfig" in strings


def test_function_strings_via_ast_reports_parse_ok():
    """返回值改成 (found, parse_ok)，调用方才能区分"解析失败"和"没有字符串"。"""
    from extract_js_consts import FileSlice, extract_function_strings_via_ast

    ok_code = 'var a = "xy";'
    found, parse_ok = extract_function_strings_via_ast(
        FileSlice(0, len(ok_code), ok_code), StatementStore()
    )
    assert parse_ok is True
    assert "xy" in {s for s, _sid in found}

    bad_code = 'const a = b ?? "https://f.example.com/m";'
    found, parse_ok = extract_function_strings_via_ast(
        FileSlice(0, len(bad_code), bad_code), StatementStore()
    )
    assert parse_ok is False
    assert found == set()


def test_generic_regex_skips_interpolated_template():
    """通用兜底正则：模板字符串带 ${} 就整体跳过，但其中的普通字面量仍要提取。"""
    from extract_js_consts import FileSlice, extract_generic_strings_regex

    code = 'a = `plain`; b = `has${x}interp`; c = "https://g.example.com/p";'
    vals = {
        s
        for s, _sid in extract_generic_strings_regex(
            FileSlice(0, len(code), code), StatementStore()
        )
    }
    assert "plain" in vals
    assert "https://g.example.com/p" in vals
    assert not any("has" in v for v in vals)


# ---------------------------------------------------------------------------
# 新增用例：兜底白名单 + 编译样式文件关闭兜底（计划第二节 / 第三、四节 / 5.1）
# ---------------------------------------------------------------------------


# (期望类名, 样例)。按 FALLBACK_RULES 的顺序挑，样例都不能被排在前面的类先截走。
FALLBACK_POSITIVE_CASES = [
    ("url", "https://api.example.com/v1/login"),
    ("abs_path", "/api/v2/order"),
    ("abs_path", "/api/v2/order?page=1&size=20"),  # 路径带查询串
    ("rel_path", "./utils/util.js"),
    ("bare_path", "api/user.js"),
    ("wx_appid", "wx062880c35584f6cc"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123_-xyz"),
    ("cloud_ak", "LTAI5tAbCdEfGhIjKlMnOp"),
    ("token_prefix", "ghp_0123456789abcdefghij"),
    ("auth_header", "Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghijkl"),
    ("google_key", "AIzaSyA1234567890abcdefghijklmnopqrstuv"),
    ("tmap_key", "ABCDE-12345-FGHIJ-67890-KLMNO-12345"),
    (
        "pem",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    ),
    (
        "der_key_b64",
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyz0123456789AbCdEfGhIjKl",
    ),
    ("hex_secret", "0123456789abcdef0123456789abcdef"),
    ("email", "user.name+tag@example.com"),
    ("ipv4", "192.168.1.100:8080"),
    ("cn_mobile", "13812345678"),
    ("cn_id18", "110101190001010000"),
]

FALLBACK_NEGATIVE_CASES = [
    ";color:#fff;display:flex;",
    "#FF0066",
    "HH:mm:ss",
    "sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
    "!==e.charAt(0)&&(e=",
    "商品破损/少件",
    "escapeSpecialCharsWithinTagAttributes",
    "http:",
    "/0/1",
    "0" * 32,
]


def test_fallback_value_kind_positive_all_18_classes():
    """18 个类每类至少 1 个会命中的样例，另加 1 个路径带查询串的样例。"""
    from extract_js_consts import FALLBACK_RULES, fallback_value_kind

    hit = {}
    for expected, sample in FALLBACK_POSITIVE_CASES:
        got = fallback_value_kind(sample)
        assert got == expected, f"{sample!r}: 期望 {expected}，实际 {got}"
        hit[expected] = hit.get(expected, 0) + 1

    all_kinds = {kind for kind, _rx in FALLBACK_RULES}
    assert all_kinds - set(hit) == set(), f"未覆盖的类: {all_kinds - set(hit)}"


def test_fallback_value_kind_negative_all_none():
    """CSS / 颜色 / 时间格式 / SRI / 代码碎片 / 中文 / 函数名 / 协议头残片等一律不收。"""
    from extract_js_consts import fallback_value_kind, js_unescape

    for sample in FALLBACK_NEGATIVE_CASES:
        assert fallback_value_kind(sample) is None, f"{sample!r} 不应被收"

    # 转义后的版本号不是路径
    assert fallback_value_kind(js_unescape(r"\x3e\x3d0.4.0")) is None


def test_js_unescape_basics():
    from extract_js_consts import js_unescape

    assert js_unescape(r"https://a.b/c?x\x3d1") == "https://a.b/c?x=1"
    # 越界码点保留原文，且不抛异常
    assert js_unescape(r"\u{110000}") == r"\u{110000}"
    # 非法转义：反斜杠被去掉，得到 uZZZZ
    assert js_unescape(r"\uZZZZ") == "uZZZZ"
    # 没有反斜杠时原样返回
    assert js_unescape("plain text") == "plain text"


def test_end_to_end_unconsumed_chunk_keeps_url_drops_css():
    """未消费 chunk：URL 靠通用正则拿到，函数参数形式的 CSS 过不了白名单。

    CSS 必须写成函数参数 f(";color:#fff;...")；写成 var c = "..." 或
    key: "..." 会被保留的旧 global 正则捞到，测试就没有区分度了。
    """
    js = 'const u = opt ?? "https://api.example.com/v1/login"; f(";color:#fff;display:flex;");'
    strings = _extract(js)
    assert "https://api.example.com/v1/login" in strings
    assert not any("color" in s for s in strings), sorted(strings)


def test_end_to_end_failed_function_body_keeps_path_drops_css():
    """失败函数体：global 正则捞到的 /api/v2/order 过白名单，CSS 丢弃。"""
    js = 'function f(){ var u = opt ?? 1; return {css: ";color:#fff;", path: "/api/v2/order"}; }'
    strings = _extract(js)
    assert "/api/v2/order" in strings
    assert not any("color" in s for s in strings), sorted(strings)


def test_old_global_regex_on_unconsumed_chunk_is_unchanged():
    """未消费 chunk 上的 extract_global_strings_regex 行为不变：不反转义、不过白名单。"""
    js = 'var c = ";color:#fff;display:flex;";'
    assert ";color:#fff;display:flex;" in _extract(js)


def test_compiled_style_file_disables_new_fallback(tmp_path):
    """app-wxss.js：URL 只能靠通用正则拿到，兜底被关闭 → 提取不到。"""
    from extract_js_consts import extract_from_js_file, is_compiled_style_file

    assert is_compiled_style_file("app-wxss.js") is True
    assert is_compiled_style_file("pages/index/index.wxss.js") is True
    assert is_compiled_style_file("components/a/index-wxss.js") is True
    assert is_compiled_style_file("util.js") is False
    assert is_compiled_style_file("app-wxss.js.map") is False

    code = 'const u = opt ?? "https://x.example.com/a";'
    style_file = tmp_path / "app-wxss.js"
    style_file.write_text(code, encoding="utf-8")
    normal_file = tmp_path / "util.js"
    normal_file.write_text(code, encoding="utf-8")

    style_vals = {s for s, _sid, _src in extract_from_js_file(str(style_file))["constants"]}
    normal_vals = {s for s, _sid, _src in extract_from_js_file(str(normal_file))["constants"]}

    assert "https://x.example.com/a" not in style_vals
    assert "https://x.example.com/a" in normal_vals


# ---------------------------------------------------------------------------
# 新增用例：第三方依赖路径不收（按路径段匹配）
# ---------------------------------------------------------------------------

THIRD_PARTY_PATH_CASES = [
    "@babel/runtime/helpers/typeof.js",
    "../../@babel/runtime/helpers/objectSpread2",
    "miniprogram_npm/@vant/weapp/button/index",
    "/node_modules/x/y.js",
    "../../miniprogram_npm/foo/index?x=1",
]

NOT_THIRD_PARTY_PATH_CASES = [
    ("api/babel/list", "bare_path"),
    ("/pages/my-babel/index", "abs_path"),
    ("components/npm-info/index", "bare_path"),
    ("./utils/node_modules_helper", "rel_path"),
]


def test_fallback_value_kind_third_party_paths_rejected():
    """第三方依赖路径（@babel / miniprogram_npm / node_modules 段）整条不收。"""
    from extract_js_consts import fallback_value_kind

    for sample in THIRD_PARTY_PATH_CASES:
        assert fallback_value_kind(sample) is None, f"{sample!r} 不应被收"


def test_fallback_value_kind_partial_segment_names_kept():
    """段名不完全相等（babel / my-babel / npm-info / node_modules_helper）不排除。"""
    from extract_js_consts import fallback_value_kind

    for sample, expected in NOT_THIRD_PARTY_PATH_CASES:
        got = fallback_value_kind(sample)
        assert got == expected, f"{sample!r}: 期望 {expected}，实际 {got}"


def test_end_to_end_third_party_path_dropped_normal_path_kept():
    """端到端：第三方路径被丢弃，普通路径仍然提取。"""
    js = (
        'const u = opt ?? "@babel/runtime/helpers/typeof.js";'
        ' const v = opt ?? "/api/v2/order";'
    )
    strings = _extract(js)
    assert not any("@babel" in s for s in strings), sorted(strings)
    assert "/api/v2/order" in strings


if __name__ == "__main__":
    test_extracts_some_known_strings()
