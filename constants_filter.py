#!/usr/bin/env python3
"""
常量过滤模块 - 过滤噪音字符串和重复项

用法:
    python constants_filter.py <input.json> [output.json] [--smart]

选项:
    --smart: 启用智能过滤 (使用 smart_filter 模块的额外过滤规则)
"""
from __future__ import annotations

import re
import sys
import json
from pathlib import Path
from statistics import median
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, NamedTuple, Tuple, Set

# 可选: 智能过滤模块
try:
    from smart_filter import should_keep_value as smart_filter_check
    SMART_FILTER_AVAILABLE = True
except ImportError:
    SMART_FILTER_AVAILABLE = False
    smart_filter_check = None


# -------------------------
# Types
# -------------------------
ConstRd = NamedTuple("ConstRd", [("ST", str), ("ID", int), ("SRC", str)])

# Adaptive near-duplicate filtering:
NEAR_THRESHOLD_MIN = 10
NEAR_THRESHOLD_MAX = 120
NEAR_THRESHOLD_FALLBACK = 30
# Keep at most this many occurrences per (string, source) if it's extremely frequent
MAX_KEEP_PER_STRING = 25
# If a string appears more than this many times, it is considered "very frequent"
VERY_FREQUENT_N = 120

MIN_STRING_LEN = 6
MIN_DIGIT_LEN = 6


# ---------------------------------------------------------
# Black list: Unwanted-string heuristics
# ---------------------------------------------------------
# fmt: off

# ---------------------------------------------------------
# White list: 直接跳过过滤的字符串 (如加密算法名称)
# ---------------------------------------------------------
WHITELIST_STRINGS = {
    # 加密算法名称 (type_id: 2101 crypto_algorithm_name)
    "MD5", "md5", "SHA1", "sha1", "SHA256", "sha256", "SHA384", "sha384", "SHA512", "sha512",
    "SHA-1", "sha-1", "SHA-256", "sha-256", "SHA-384", "sha-384", "SHA-512", "sha-512",
    "AES", "aes", "AES128", "aes128", "AES256", "aes256", "AES-128", "aes-128", "AES-256", "aes-256",
    "AES-CBC", "aes-cbc", "AES-GCM", "aes-gcm", "AES-ECB", "aes-ecb",
    "DES", "des", "3DES", "3des", "DES3", "des3", "TRIPLE-DES", "triple-des",
    "RSA", "rsa", "RSA1024", "rsa1024", "RSA2048", "rsa2048", "RSA4096", "rsa4096",
    "RSA-1024", "rsa-1024", "RSA-2048", "rsa-2048", "RSA-4096", "rsa-4096",
    "ECDSA", "ecdsa", "ED25519", "ed25519", "ECDH", "ecdh",
    "SM2", "sm2", "SM3", "sm3", "SM4", "sm4",
    "HMAC", "hmac", "HMAC-SHA256", "HMAC-sha256", "hmac-sha256", "HMAC-SHA1", "hmac-sha1", "HMAC-MD5", "hmac-md5",
}

BAD_QUOTES = {"'", '"', "`"}
BAD_BRACKETS = {"<", ">", "(", ")", "[", "]", "{", "}"}

# General common keys that are usually not meaningful "constants"
COMMON_HTML_STOP_WORDS = {
    "value", "values", "key", "keys", "label", "name", "title", "id", "type", "data",
    "item", "items", "list", "info", "detail", "class", "style", "width", "height",
    "url", "path", "success", "fail", "message", "msg", "status", "code",
    "object", "array", "string", "number", "boolean",
    # mini program common bindings
    "bindtap", "bindinput", "bindchange", "bindblur", "bindfocus",
    "catchtap", "catchtouchmove", "catchtouchstart", "catchtouchend",
}

# UI and Mini-Program specific common terms (often extremely frequent)
COMMON_UI_STOP_WORDS = {
    "view", "text", "image", "button", "input", "form", "scroll-view",
    "swiper", "swiper-item", "navigator", "picker", "icon", "canvas",
    "class", "style", "id",
    "bindtap", "bindinput", "bindchange", "bindblur", "bindfocus",
    "catchtap", "catchtouchstart", "catchtouchmove", "catchtouchend",
}

# Very common JS identifiers
COMMON_JS_STOP_WORDS = {
    "index", "length", "floor", "map", "filter", "reduce", "push", "pop",
    "slice", "splice", "join", "split", "keys", "values", "name", "value",
    "id", "type", "default", "null", "undefined", "none", "test", "demo",
    "true", "false"
}

COMMON_PROTOCOL_HOT_WORDS = {
    "authPhoneSwitch", "authStyle", "avatarUrl", "base64Path", "bindanimationfinish", 
    "bindgetuserinfo", "bindscrolltolower", "brochureCurrentIndex", "cardListItem", 
    "cdeSqn", "compare", "computed", "current", "cursor", "cursorSpacing", "customClass", 
    "email", "empBusiCardPicTbls", "foldSwitch", "fontColor", "holdKeyboard", "imageName", 
    "infoSummary", "maltNameItem", "matlId", "matlListItem2", "modal", "pictureIndex", 
    "selectionEnd", "selectionStart", "selectModule", "shareParams", "showgwDialog", 
    "showSubMsgModal", "showTitle", "showType", "target", "templetIndex", "textarea", 
    "workBadge", "adjustPosition", "autoFocus", "binderror", "border", "center", 
    "confirmType", "currentOptionDateIndex", "customStyle", "empBusiCardTbls", "error", 
    "headerText", "hoverClass", "inputAlign", "inputValue", "isShow", "lang", "loginHeight", 
    "loginName", "lotteryConfigFlag", "modalTitle", "navHeight", "needAuthNick", 
    "officeAddress", "orgCode", "protocolParam", "quantity", "searchFocus", "shareGwParams", 
    "showDate", "showDialog", "showLayer", "showNewInfo", "templateId", "authNickModal", 
    "bindconfirm", "bindtouchend", "bindtouchstart", "brief", "btnName", "decode", "fixed", 
    "lable", "lev4Item", "newInfo", "newsId", "range", "refresherEnabled", "selectArr", 
    "showChooseAvatar", "span", "userInfo", "userSelect", "chkSts", "dailyNews",
    "enhanced", "hidden", "indicatorActiveColor", "indicatorColor", "indicatorDots", 
    "informationId", "isProgress", "position", "qrCode", "showMenuByLongpress", 
    "showNormalNews", "showScrollbar", "showTopNews", "actId", "active", "baseImgUrl", 
    "bubInfo", "count", "indexTemp", "orgName", "scrollX", "shareCount", "showShare", 
    "avatar", "circular", "color", "currentIndex", "date", "employee", "interval", "lev3Item", 
    "matlMapList2", "modules", "quickNews", "size", "actInfoList", "showNickAuthModal", 
    "showSwitchBox", "space", "userFlag", "cName", "mainNavbar", "moduleId", "placeholderClass", 
    "placeholderStyle", "showBtnType", "uploadConfig", "userCode", "scrollY", "autoplay", 
    "handleAbnormalData", "infoFlag", "item1", "focus", "nodes", "positionsOrgName", 
    "cardBgId", "matlMapList", "placeholder", "maxlength", "openType", "disabled", "resFld1", 
    "matlTempTyp", "matlListItem", "slot", "utils", "euifBcInfo", "imgUrl", "mode","white","function","Function",
    "minute","minutes","Minutes","Minute","render","result","return","right","horizontal"
    ,"primary","process","product","onLoad","navigateTo","month","months","columns",
    "warning","Month","u-icon","__esModule","throw"
    }

BEGIN_WITH_PREFIX = (
    "filter", "card", "form", "handle", "img", "modal", "position", "remark", 
    "search", "send", "swiper", "switch", "picture", "close", "show", "title", "upload", 
    "view", "resFld", "manager", "loading", "get", "disable", "content", "confirm", "click", 
    "cancle", "button", "block", "bind", "width:", "status", "stop",
    # Date format patterns
    "YYYY", "yyyy", "dddd", "DDDD", "MM-DD", "mm-dd", "HH:mm", "hh:mm","D MMM",
    "font-size:","fontSize", "fontWeight","%d ","%s ","leave-","-leave-","color:","border-color:","border: ","background-color:",
    "Cannot ","van-","Jan_Feb","nv_","uicon-","Januar",
)
# fmt: on


def _is_cjk_char(ch: str) -> bool:
    """Check if character is CJK (Chinese/Japanese/Korean)"""
    code = ord(ch)
    # CJK Unified Ideographs and common ranges
    return (
        0x4E00 <= code <= 0x9FFF or      # CJK Unified Ideographs
        0x3400 <= code <= 0x4DBF or      # CJK Unified Ideographs Extension A
        0x3000 <= code <= 0x303F or      # CJK Symbols and Punctuation
        0xFF00 <= code <= 0xFFEF or      # Halfwidth and Fullwidth Forms
        0x3040 <= code <= 0x309F or      # Hiragana
        0x30A0 <= code <= 0x30FF         # Katakana
    )


def filter_non_ascii_rule(s: str) -> bool:
    """
    Return True if string should be filtered out by the non-ASCII rule.

    Rule:
      - If string has some ASCII letters/digits but < 6 => filter out
      - If string has non-ASCII chars that are not CJK => filter out
      - Otherwise keep (mixed strings with enough ASCII or CJK)
    """
    ascii_count = sum(1 for ch in s if ch.isascii() and ch.isalnum())

    # Check for non-ASCII, non-CJK characters (e.g., Vietnamese, Thai, Arabic)
    for ch in s:
        if not ch.isascii() and not _is_cjk_char(ch):
            return True  # Filter out non-CJK foreign text

    # Mixed but too little ASCII signal
    if ascii_count < MIN_STRING_LEN:
        return True
    return False


def is_unwanted_string(s: str) -> bool:
    """Return True if s should be removed as noise."""
    # 容错处理：去除前后空格
    s = s.strip() if isinstance(s, str) else str(s)
    if not s:
        return True

    # remove obvious garbage
    if any(ch in s for ch in BAD_QUOTES):
        return True
    if any(ch in s for ch in BAD_BRACKETS):
        return True

    # non-ASCII filtering rule (your intended rule)
    if filter_non_ascii_rule(s):
        return True

    if s.isdigit():
        if len(s) < MIN_DIGIT_LEN:
            # digits-only but too short
            return True
        if len(s) == 6:
            # China admin code-like heuristic
            if int(s[2]) < 3 and int(s[4]) < 3:
                return True
            else:
                return False

    # Specialized hot-words and prefixes
    if s in COMMON_PROTOCOL_HOT_WORDS:
        return True
    if BEGIN_WITH_PREFIX and s.startswith(BEGIN_WITH_PREFIX):
        return True

    # WXSS/CSS-like values
    if s.endswith("rpx"):
        return True

    # CSS color values: #RGB, #RRGGBB, #RRGGBBAA
    if re.match(r'^#[0-9a-fA-F]{3,8}$', s):
        return True

    # npm integrity hash (SRI): sha256-xxx, sha384-xxx, sha512-xxx
    if re.match(r'^sha(256|384|512)-[A-Za-z0-9+/]+=*$', s):
        return True

    # Pure camelCase/PascalCase identifiers (e.g., businessId, getUserInfo)
    # Only letters, starts with letter, has mixed case
    if s.isalpha() and s[0].isalpha():
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        if has_upper and has_lower:
            return True

    low = s.lower()
    if low in COMMON_HTML_STOP_WORDS:
        return True
    if low in COMMON_UI_STOP_WORDS:
        return True
    if low in COMMON_JS_STOP_WORDS:
        return True

    # 截断的 UUID/ID 格式: xxxxxxxx-n 或 xxxxxxxx-nn- (8位十六进制 + 短横线 + 数字 + 可选短横线结尾)
    # 示例: 4d2c863e-0, 01c0b5ed-1, 6ea12a64-7, 48501690-13, 3c154e10-56-, 69525030-5-
    if re.match(r"^[0-9a-f]{8}-\d+-?$", s):
        return True

    return False


# ---------------------------------------------------------
# White list: Wanted-string heuristics
# ---------------------------------------------------------
# fmt: off

PII_KEYS = {"patientname", "iccardno", "idcard", "身份证", "phone", "mobile"}

# fmt: on


def is_wanted_string(s: str) -> bool:
    """A white list for preserving all wanted strings"""
    # 白名单直接保留
    if s in WHITELIST_STRINGS:
        return True
    low = s.lower()
    if any(k in low for k in PII_KEYS):
        return True  # filter PII query strings
    return False  # otherwise keep


# -------------------------
# Smarter near-duplicate filtering
# -------------------------
def _adaptive_threshold(sorted_ids: List[int]) -> int:
    """
    Compute an adaptive near-threshold based on the median gap.
    Clamp between [NEAR_THRESHOLD_MIN, NEAR_THRESHOLD_MAX].
    """
    if len(sorted_ids) < 3:
        return NEAR_THRESHOLD_FALLBACK

    gaps = [sorted_ids[i] - sorted_ids[i - 1] for i in range(1, len(sorted_ids))]
    # gaps could contain zeros if duplicates; ignore them for stats
    gaps = [g for g in gaps if g > 0]
    if not gaps:
        return NEAR_THRESHOLD_FALLBACK

    m = median(gaps)

    # Heuristic:
    # - If median gap is very small, use a small threshold (avoid spamming)
    # - If median gap is larger, allow a larger threshold so we still drop only truly near duplicates
    # - Use ~1.5x median (reasonable)
    thr = int(round(m * 1.5))

    if thr < NEAR_THRESHOLD_MIN:
        thr = NEAR_THRESHOLD_MIN
    if thr > NEAR_THRESHOLD_MAX:
        thr = NEAR_THRESHOLD_MAX
    return thr


def _subsample_evenly(items: List[ConstRd], k: int) -> List[ConstRd]:
    """
    Keep k items evenly spread across the sorted list.
    Always keeps first and last when possible.
    """
    if k <= 0 or not items:
        return []
    if len(items) <= k:
        return items

    # Evenly spaced indices
    step = (len(items) - 1) / (k - 1)
    chosen: List[ConstRd] = []
    used: Set[int] = set()
    for i in range(k):
        idx = int(round(i * step))
        if idx in used:
            continue
        used.add(idx)
        chosen.append(items[idx])
    # Ensure deterministic
    chosen.sort(key=lambda x: x.ID)
    return chosen


def filter_near_duplicates(records: Iterable[ConstRd]) -> List[ConstRd]:
    """
    Smart filtering:
      1) group by (string, source)
      2) adaptive near-threshold per group
      3) near-duplicate suppression (keep first, then keep only if far enough)
      4) if extremely frequent -> subsample evenly
    """
    buckets: Dict[Tuple[str, str], List[ConstRd]] = defaultdict(list)

    for s, sid, src in records:
        buckets[(s, src)].append(ConstRd(s, sid, src))

    kept: List[ConstRd] = []

    for items in buckets.values():
        items.sort(key=lambda x: x.ID)
        ids = [x.ID for x in items]

        thr = _adaptive_threshold(ids)

        # Near-duplicate suppression
        group_kept: List[ConstRd] = []
        last_id: Optional[int] = None
        for it in items:
            if last_id is None:
                group_kept.append(it)
                last_id = it.ID
                continue
            if (it.ID - last_id) <= thr:
                continue
            group_kept.append(it)
            last_id = it.ID

        # If still very frequent, keep only representative samples
        if len(group_kept) > VERY_FREQUENT_N:
            group_kept = _subsample_evenly(group_kept, MAX_KEEP_PER_STRING)
        elif len(group_kept) > MAX_KEEP_PER_STRING:
            # mild cap: still reduce, but less aggressively
            group_kept = _subsample_evenly(group_kept, MAX_KEEP_PER_STRING)

        kept.extend(group_kept)

    #kept.sort(key=lambda x: (x.ST, x.SRC, x.ID))
    # 按扫描顺序 (ID) 排序
    kept.sort(key=lambda x: x.ID)
    return kept


# -------------------------
# End-to-end pipeline
# -------------------------
def perform_constant_filtering(
    statements: List[str],
    constants: Iterable[ConstRd],
    use_smart_filter: bool = False
) -> Dict[str, Any]:
    """
    Filter out unwanted strings or frequently duplicated strings

    Args:
        statements: 语句列表
        constants: 常量记录
        use_smart_filter: 是否启用智能过滤 (需要 smart_filter 模块)
    """
    cleaned: List[ConstRd] = []
    for s, sid, src in constants:
        if len(s) <= MIN_STRING_LEN:
            continue

        if is_wanted_string(s):
            cleaned.append(ConstRd(s, sid, src))
            continue

        if is_unwanted_string(s):
            continue

        # 智能过滤 (可选)
        if use_smart_filter and SMART_FILTER_AVAILABLE and smart_filter_check:
            if not smart_filter_check(s):
                continue

        cleaned.append(ConstRd(s, sid, src))

    filtered = filter_near_duplicates(cleaned)
    return {"statements": statements, "constants": filtered}


# -------------------------
# I/O helpers / CLI
# -------------------------
def load_extractor_json(path: str) -> Tuple[List[str], List[ConstRd]]:
    """
    Load JSON: {"statements": [...], "constants": [[s, sid, src], ...]}
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    statements = data.get("statements", [])
    constants = data.get("constants", [])

    parsed: List[Tuple] = []
    for s, sid, src in constants:
        parsed.append((s, sid, src))

    return statements, parsed


def main_a1539d8f(argv: List[str]) -> int:
    """For testing"""
    # 解析参数
    use_smart = "--smart" in argv
    args = [a for a in argv if not a.startswith("--")]

    if len(args) < 2 or not args[1].endswith((".json", ".txt")):
        print(f"Usage: python {args[0]} <input.json> [output.json] [--smart]")
        print("\n选项:")
        print("  --smart: 启用智能过滤 (需要 smart_filter 模块)")
        if SMART_FILTER_AVAILABLE:
            print("           [已安装]")
        else:
            print("           [未安装 - 请确保 smart_filter.py 在同目录下]")
        return 2

    input_path = args[1]

    try:
        statements, constants = load_extractor_json(input_path)
    except FileNotFoundError:
        print(f"Error: File '{input_path}' not found.")
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON: {e}")
        return 1

    if use_smart and not SMART_FILTER_AVAILABLE:
        print("Warning: --smart 选项需要 smart_filter 模块，但未找到。")
        print("请确保 smart_filter.py 在同目录下。")
        return 1

    out = perform_constant_filtering(statements, constants, use_smart_filter=use_smart)
    result = json.dumps(out, ensure_ascii=False, indent=2)

    if len(args) >= 3:
        # 自动创建输出目录
        output_path = Path(args[2])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(args[2], "w", encoding="utf-8") as f:
            f.write(result)
        print(f"Saved to {args[2]}")
        if use_smart:
            print("(使用智能过滤)")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main_a1539d8f(sys.argv))
