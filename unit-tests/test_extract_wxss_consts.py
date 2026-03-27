import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from extract_wxss_consts import extract_from_wxss_text
from extract_wxss_consts import StatementStore


def _strings(constants):
    return {s for (s, _stmt_id, _stmt) in constants}


def test_extracts_url_and_strings():
    wxss = """
    /* comment */
    .a {
      background-image: url("/images/bg.png");
      content: "Order Now";
    }
    """
    store = StatementStore()
    out = extract_from_wxss_text(wxss, store)

    strings = _strings(out)
    assert "/images/bg.png" in strings
    assert "Order Now" in strings


def test_multiline_declaration():
    wxss = """
    @font-face {
      src:
        url("data:font/woff2;base64,AAAA")
        format("woff2");
    }
    """
    store = StatementStore()
    out = extract_from_wxss_text(wxss, store)

    strings = _strings(out)
    assert "data:font/woff2;base64,AAAA" in strings
    assert "woff2" in strings
