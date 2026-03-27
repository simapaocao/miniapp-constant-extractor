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


if __name__ == "__main__":
    test_extracts_some_known_strings()
