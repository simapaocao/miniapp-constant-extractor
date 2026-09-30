#!/usr/bin/env python3
import sys
import json
import re
import hashlib
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Any, Dict, List, Set, NamedTuple, Tuple

ConstRd = NamedTuple("ConstRd", [("ST", str), ("ID", int), ("STMT", str)])
MIN_STRING_LEN = 4


class StatementStore:
    """Deduplicate statement strings by hash and assign stable integer ids."""

    def __init__(self) -> None:
        self._idx_by_hash: Dict[str, int] = {}  # hash -> statement_id
        self.statements: List[str] = []

    @staticmethod
    def _hash_stmt(stmt: str) -> str:
        # SHA-1 is plenty for dedupe
        return hashlib.sha1(stmt.encode("utf-8", errors="surrogatepass")).hexdigest()

    def add(self, stmt: str) -> int:
        """Stores the statement and return its index in storage"""
        stmt = (stmt or "").strip()
        if not stmt:
            stmt = "<unknown statement>"

        h = self._hash_stmt(stmt)
        if h in self._idx_by_hash:
            return self._idx_by_hash[h]

        idx = len(self.statements)
        self._idx_by_hash[h] = idx
        self.statements.append(stmt)
        return idx


# ---------------------------------------------------------------------------
# Pre-processing
#
# WXML is *not* XML: attribute names may contain ':' (wx:if, bind:tap, ...),
# binding expressions may contain raw '<', '>' and '&', and bare '&' appears in
# plain text.  ElementTree chokes on all of that, so the text is normalised
# before parsing and the original attribute names are restored when a
# statement is emitted.
# ---------------------------------------------------------------------------

# XML predefined entities plus numeric character references.
_XML_ENTITY_RE = re.compile(r"&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|amp|lt|gt|quot|apos);")

_TAG_NAME_RE = re.compile(r"<\s*([A-Za-z_][\w.\-]*)")


def _escape_mustache_regions(text: str) -> str:
    """Escape `<`, `>` and `&` inside every ``{{ ... }}`` region.

    ``{{ a < b }}`` is not valid XML text.  ``&`` is escaped first so the
    entities introduced here are not escaped a second time.
    """
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        s = text.find("{{", i)
        if s == -1:
            out.append(text[i:])
            break
        out.append(text[i:s])
        e = text.find("}}", s + 2)
        if e == -1:
            region = text[s:]
            i = n
        else:
            region = text[s : e + 2]
            i = e + 2
        out.append(
            region.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
    return "".join(out)


def _escape_bare_ampersands(text: str) -> str:
    """Turn every `&` that does not start a valid entity into `&amp;`."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "&":
            out.append(text[i])
            i += 1
            continue
        m = _XML_ENTITY_RE.match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
        else:
            out.append("&amp;")
            i += 1
    return "".join(out)


def _process_open_tag(tag: str, attr_map: Dict[str, str]) -> str:
    """Rewrite `a:b` attribute names to `a__b` and give bare attributes a value.

    ``attr_map`` receives ``rewritten -> original`` so the emitted statement can
    show the name the developer actually wrote.
    """
    m = _TAG_NAME_RE.match(tag)
    if not m:
        return tag

    name = m.group(1)
    rest = tag[m.end() :]

    suffix = ""
    if rest.endswith(">"):
        rest = rest[:-1]
        suffix = ">"
    if rest.endswith("/"):
        rest = rest[:-1]
        suffix = "/" + suffix

    parts: List[str] = ["<" + name]
    i = 0
    n = len(rest)
    while i < n:
        c = rest[i]
        if c.isspace():
            parts.append(c)
            i += 1
            continue

        start = i
        while i < n and (not rest[i].isspace()) and rest[i] not in "=/":
            i += 1
        attr_name = rest[start:i]
        if not attr_name:
            parts.append(rest[i])
            i += 1
            continue

        if ":" in attr_name:
            rewritten = attr_name.replace(":", "__")
            attr_map.setdefault(rewritten, attr_name)
            parts.append(rewritten)
        else:
            parts.append(attr_name)

        k = i
        while k < n and rest[k].isspace():
            k += 1
        if k < n and rest[k] == "=":
            parts.append(rest[i : k + 1])
            i = k + 1
            while i < n and rest[i].isspace():
                parts.append(rest[i])
                i += 1
            if i < n and rest[i] in "\"'":
                quote = rest[i]
                j = i + 1
                while j < n and rest[j] != quote:
                    j += 1
                j = j + 1 if j < n else n
                parts.append(rest[i:j])
                i = j
            else:
                j = i
                while j < n and not rest[j].isspace():
                    j += 1
                parts.append(rest[i:j])
                i = j
        else:
            # valueless attribute such as `<view hidden>`
            parts.append('=""')

    parts.append(suffix)
    return "".join(parts)


def _preprocess_wxml(text: str) -> Tuple[str, Dict[str, str]]:
    """Normalise WXML so ElementTree can parse it.

    Returns the rewritten text plus a ``rewritten attr name -> original`` map.
    """
    text = _escape_mustache_regions(text)
    text = _escape_bare_ampersands(text)

    attr_map: Dict[str, str] = {}
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "<":
            out.append(text[i])
            i += 1
            continue

        if text.startswith("<!--", i):
            k = text.find("-->", i + 4)
            if k == -1:
                out.append(text[i:])
                break
            out.append(text[i : k + 3])
            i = k + 3
            continue

        if text.startswith("<!", i) or text.startswith("<?", i):
            k = text.find(">", i)
            if k == -1:
                out.append(text[i:])
                break
            out.append(text[i : k + 1])
            i = k + 1
            continue

        if text.startswith("</", i):
            k = text.find(">", i)
            if k == -1:
                out.append(text[i:])
                break
            out.append(text[i : k + 1])
            i = k + 1
            continue

        m = _TAG_NAME_RE.match(text, i)
        if not m:
            out.append(text[i])
            i += 1
            continue

        # Walk to the closing '>' while respecting quoted attribute values.
        k = m.end()
        while k < n and text[k] != ">":
            if text[k] in "\"'":
                quote = text[k]
                k += 1
                while k < n and text[k] != quote:
                    k += 1
            k += 1
        end = k + 1 if k < n else n
        out.append(_process_open_tag(text[i:end], attr_map))
        i = end

    return "".join(out), attr_map


# ---------------------------------------------------------------------------
# Lenient fallback parser
# ---------------------------------------------------------------------------


class _LenientWxmlParser(HTMLParser):
    """Very forgiving WXML reader, used when ElementTree cannot parse a file."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attrs: List[Tuple[str, str, str]] = []  # (tag, attr, value)
        self.texts: List[Tuple[str, str]] = []  # (tag, text)
        self._stack: List[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        self._stack.append(tag)
        self._record(tag, attrs)

    def handle_startendtag(self, tag, attrs) -> None:
        self._record(tag, attrs)

    def _record(self, tag, attrs) -> None:
        for name, value in attrs:
            if value is None:
                continue
            self.attrs.append((tag, name, value))

    def handle_endtag(self, tag) -> None:
        for idx in range(len(self._stack) - 1, -1, -1):
            if self._stack[idx] == tag:
                del self._stack[idx:]
                break

    def handle_data(self, data) -> None:
        tag = self._stack[-1] if self._stack else ""
        self.texts.append((tag, data))


def extract_from_wxml_text(
    wxml_text: str, store: StatementStore
) -> Set[Tuple[str, int, str]]:
    """
    Pure function: extract string constants from WXML text.

    Extracts two types:
      - Attribute values (source="wxml-attr")
      - Direct text content of elements (source="wxml-text")

    ElementTree is tried first on pre-processed text; if that still fails the
    file is re-read with a lenient HTML parser.  Only if *both* fail is an empty
    set returned -- this function never raises.

    Output format:
      {"statements": [...], "constants": [{"string","statement_id","source"}, ...]}
    """
    constants: Set[Tuple[str, int, str]] = set()

    def looks_dynamic(s: str) -> bool:
        """Heuristic: skip WXML binding expressions like {{ ... }}."""
        return "{{" in s or "}}" in s

    def emit(value: str, stmt: str, source: str) -> None:
        v = (value or "").strip()
        if not v:
            return
        if looks_dynamic(v):
            return
        sid = store.add(stmt)
        constants.add((v, sid, source))

    def visit(elem: ET.Element) -> None:
        # 1) Attribute values
        for attr, value in (elem.attrib or {}).items():
            val = (value or "").strip()
            if not val or looks_dynamic(val):
                continue
            display = attr_map.get(attr, attr)
            stmt = f'<{elem.tag} {display}="{val}">'
            emit(val, stmt, "wxml-attr")

        # 2) Direct text content
        if elem.text:
            text = elem.text.strip()
            if text and not looks_dynamic(text):
                stmt = f"<{elem.tag}>{text}</{elem.tag}>"
                emit(text, stmt, "wxml-text")

        for child in list(elem):
            visit(child)

    # end def visit()

    def try_etree(text: str) -> bool:
        """Parse with ElementTree; return True when the document was walked."""
        root = None
        try:
            root = ET.fromstring(text)
        except Exception:
            try:
                root = ET.fromstring("<__wxml_root__>\n" + text + "\n</__wxml_root__>")
            except Exception:
                return False
        visit(root)
        return True

    def try_html_parser(text: str) -> bool:
        """Lenient fallback: pull attribute values and text nodes out of the raw text."""
        try:
            parser = _LenientWxmlParser()
            parser.feed(text)
            parser.close()
        except Exception:
            return False

        for tag, attr, value in parser.attrs:
            val = (value or "").strip()
            if not val or looks_dynamic(val):
                continue
            stmt = f'<{tag} {attr}="{val}">'
            emit(val, stmt, "wxml-attr")

        for tag, data in parser.texts:
            val = (data or "").strip()
            if not val or looks_dynamic(val):
                continue
            stmt = f"<{tag}>{val}</{tag}>"
            emit(val, stmt, "wxml-text")

        return True

    raw = wxml_text or ""

    attr_map: Dict[str, str] = {}
    pre = raw
    try:
        pre, attr_map = _preprocess_wxml(raw)
    except Exception:
        pre, attr_map = raw, {}

    if not try_etree(pre):
        # The pre-processed text still is not valid XML -- fall back to the
        # lenient parser over the *original* text so attribute names keep their
        # original spelling.
        try_html_parser(raw)

    # Optional: deterministic order for snapshot tests
    return constants


def extract_from_wxml_file(path: str) -> Dict[str, Any]:
    """Thin I/O wrapper (also usable in tests)."""
    store = StatementStore()
    res = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        res = extract_from_wxml_text(f.read(), store)
    if not res:
        return {"statements": [], "constants": []}

    constants = [
        ConstRd(s, sid, src)
        for (s, sid, src) in res
        if isinstance(s, str) and len(s) > MIN_STRING_LEN
    ]
    constants.sort(key=lambda x: (x[0], x[2], x[1]))
    return {"statements": store.statements, "constants": constants}


def main_00aac784(argv: List[str]) -> int:
    """For testing"""
    if len(argv) != 2 or not argv[1].endswith(".wxml"):
        print(f"Usage: python {argv[0]} <file.wxml>")
        return 2

    try:
        result = extract_from_wxml_file(argv[1])
    except FileNotFoundError:
        print(f"Error: File '{argv[1]}' not found.")
        return 1
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_00aac784(sys.argv))
