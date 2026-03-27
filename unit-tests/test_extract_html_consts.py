import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from extract_html_consts import extract_from_html_text
from extract_html_consts import StatementStore


def _strings(constants):
    """
    constants: Set[Tuple[str, int, str]]
    Returns the set of extracted strings.
    """
    return {s for (s, _stmt_id, _stmt) in constants}


def test_script_strings_extracted_from_wechat_wrapper():
    html = """<style> </style>
    <page></page>
    <script>
      __wxAppCode__['pages/pageApply/pageApply.wxss']();
      var gf = $gwx_XC_58('./pages/pageApply/pageApply.wxml');
      document.dispatchEvent(new CustomEvent("generateFuncReady", {}));
    </script>
    """
    store = StatementStore()
    constants = extract_from_html_text(html, store)

    strings = _strings(constants)
    assert "pages/pageApply/pageApply.wxss" in strings
    assert "./pages/pageApply/pageApply.wxml" in strings
    assert "generateFuncReady" in strings


def test_html_attributes_and_text_extracted():
    html = """<div>
        <img src="/images/logo.png" alt="Logo">
        <p>Order Now</p>
    </div>"""
    store = StatementStore()
    constants = extract_from_html_text(html, store)

    strings = _strings(constants)
    assert "/images/logo.png" in strings
    assert "Logo" in strings
    assert "Order Now" in strings


def test_dynamic_bindings_skipped():
    html = """<div title="{{x}}"><span>{{ hello }}</span></div>"""
    store = StatementStore()
    constants = extract_from_html_text(html, store)

    # Return type is Set[...] now, so empty should be an empty set.
    assert constants == set()
