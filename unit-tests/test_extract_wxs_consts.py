import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from extract_wxs_consts import extract_from_wxs_text
from extract_wxs_consts import StatementStore


def _strings(constants):
    return {s for (s, _stmt_id, _stmt) in constants}


def test_extracts_literals_and_template_chunks():
    code = """
    var a = "hello";
    var b = 'world';
    var c = `prefix_${x}_suffix`;
    """
    store = StatementStore()
    out = extract_from_wxs_text(code, store)

    strings = _strings(out)
    assert "hello" in strings
    assert "world" in strings
    assert "prefix_" in strings
    assert "_suffix" in strings


# ---------------------------------------------------------------------------
# 新增用例：解析失败时走通用字符串字面量兜底（计划 3.3）
# ---------------------------------------------------------------------------


def test_extracts_strings_from_nullish_code():
    """esprima 4.x 不认识 `??`，解析失败时要靠兜底正则把字符串捞出来。"""
    code = 'var u = opt ?? "https://api.example.com/v1/login";'
    store = StatementStore()
    out = extract_from_wxs_text(code, store)

    strings = _strings(out)
    assert "https://api.example.com/v1/login" in strings
    # 不能再写入 "<parse error: ...>" 这种假 statement
    assert not any(stmt.startswith("<parse error") for stmt in store.statements)


def test_parse_failure_source_is_still_wxs():
    code = 'var v = a?.b; var w = "https://d.example.com/q";'
    store = StatementStore()
    out = extract_from_wxs_text(code, store)

    sources = {src for s, _sid, src in out if s == "https://d.example.com/q"}
    assert sources == {"wxs"}


# ---------------------------------------------------------------------------
# 新增用例：解析失败的兜底输出要过白名单（计划第四节 4.3 / 5.1）
# ---------------------------------------------------------------------------


def test_fallback_keeps_url_drops_css_on_parse_failure():
    """含 `??` 的代码解析失败时：URL 能兜底提取到，函数参数形式的 CSS 片段不会。"""
    code = 'var u = opt ?? "https://w.example.com/v1/login"; f(";color:#fff;display:flex;");'
    store = StatementStore()
    out = extract_from_wxs_text(code, store)

    strings = _strings(out)
    assert "https://w.example.com/v1/login" in strings
    assert not any("color" in s for s in strings), sorted(strings)


def test_fallback_unescapes_before_whitelisting():
    """入库的是反转义后的值（\\x3d -> =），否则 URL 过不了白名单。"""
    code = 'var u = opt ?? "https://e.example.com/a?x\\x3d1";'
    store = StatementStore()
    out = extract_from_wxs_text(code, store)

    assert "https://e.example.com/a?x=1" in _strings(out)
