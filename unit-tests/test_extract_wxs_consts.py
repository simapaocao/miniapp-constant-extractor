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
