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


# ---------------------------------------------------------------------------
# 新增用例：WXML 解析失败不能再让整个文件归零（计划 3.3）
# ---------------------------------------------------------------------------


def test_wx_if_and_bind_tap_attributes():
    """`:` 属性名（wx:if / bind:tap）不能导致整份文件解析失败。"""
    wxml = '<view wx:if="{{show}}" bind:tap="onTap">hello</view>'
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    strings = _strings(out)
    assert "onTap" in strings
    assert "hello" in strings
    # statement 里应该还原成开发者写的属性名（内部用的是 bind__tap）
    assert any("bind:tap" in stmt for stmt in store.statements)
    assert not any("bind__tap" in stmt for stmt in store.statements)


def test_wx_for_and_wx_key_attributes():
    wxml = '<view wx:for="{{list}}" wx:key="id" class="card"></view>'
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    strings = _strings(out)
    assert "id" in strings
    assert "card" in strings
    assert any("wx:key" in stmt for stmt in store.statements)


def test_valueless_boolean_attribute():
    """`<view hidden>` 这种没有值的属性不能把解析搞崩。"""
    wxml = '<view hidden data-role="hero">tap me</view>'
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    strings = _strings(out)
    assert "hero" in strings
    assert "tap me" in strings


def test_bare_ampersand_in_text():
    """文本里的裸 `&`（不是合法实体）要能提取到。"""
    wxml = "<text>Tom & Jerry</text>"
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    assert "Tom & Jerry" in _strings(out)


def test_comparison_operator_inside_binding():
    """`{{a<b}}` 里的 `<` 不能让整份文件归零，静态属性值仍要提取到。"""
    wxml = '<view title="{{a<b}}" data-role="card">body text</view>'
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    strings = _strings(out)
    assert "card" in strings
    assert "body text" in strings
    # 绑定表达式本身仍然是动态值，不提取
    assert not any("{{" in s for s in strings)


def test_unclosed_tag_does_not_raise():
    """标签没有闭合时要走宽松解析，不能抛异常。"""
    wxml = '<view class="foo"><text>hi there</text>'
    store = StatementStore()
    out = extract_from_wxml_text(wxml, store)

    strings = _strings(out)
    assert "foo" in strings
    assert "hi there" in strings


def test_garbage_input_returns_set_without_raising():
    """两种解析方式都处理不了时返回空集，绝不抛 RuntimeError。"""
    for wxml in ("<><<{{{{", "&&&", "<!-- unterminated", "<view "):
        store = StatementStore()
        out = extract_from_wxml_text(wxml, store)
        assert isinstance(out, set)
