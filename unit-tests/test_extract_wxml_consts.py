import os
import sys
import json

# Add the project root (parent directory) to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from extract_wxml_consts import extract_from_wxml_text
from extract_wxml_consts import StatementStore


def _strings(constants):
    return {s for (s, _stmt_id, _stmt) in constants}


def test_extract_attr_and_text():
    wxml = """
    <view>
      <image src="/images/logo.png"></image>
      <text>Order Now</text>
    </view>
    """
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    strings = _strings(out)
    assert "/images/logo.png" in strings
    assert "Order Now" in strings


def test_skip_bindings():
    wxml = """
    <view>
      <text>{{title}}</text>
      <image src="{{imgUrl}}"></image>
    </view>
    """
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    assert out == set()
