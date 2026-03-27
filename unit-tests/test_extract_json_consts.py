import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from extract_json_consts import extract_from_json_text
from extract_json_consts import StatementStore


def _strings(constants):
    return {s for (s, _stmt_id, _stmt) in constants}


def test_extracts_strings_from_app_json():
    json_text = r"""
    {
      "pages": ["pages/home/home", "pages/logs/logs"],
      "window": { "navigationStyle": "custom" }
    }
    """
    store = StatementStore()
    out = extract_from_json_text(json_text, store)

    strings = _strings(out)
    assert "pages/home/home" in strings
    assert "pages/logs/logs" in strings
    assert "custom" in strings


def test_ignores_non_string_values():
    json_text = r"""
    { "a": 1, "b": true, "c": null, "d": "ok" }
    """
    store = StatementStore()
    out = extract_from_json_text(json_text, store)

    strings = _strings(out)
    assert strings == {"ok"}


def test_invalid_json_raises():
    bad = "{ this is not json }"
    store = StatementStore()

    try:
        extract_from_json_text(bad, store)
        assert False, "Expected JSON parsing failure"
    except Exception as e:
        assert e is not None
