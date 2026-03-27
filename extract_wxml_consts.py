#!/usr/bin/env python3
import sys
import json
import hashlib
import xml.etree.ElementTree as ET
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


def extract_from_wxml_text(
    wxml_text: str, store: StatementStore
) -> Set[Tuple[str, int, str]]:
    """
    Pure function: extract string constants from WXML text.

    Extracts two types:
      - Attribute values (source="attr")
      - Direct text content of elements (source="text")

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
            stmt = f'<{elem.tag} {attr}="{val}">'
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

    # Parse XML. WXML may be a fragment (multiple roots), so wrap if needed.
    try:
        root = ET.fromstring(wxml_text)
    except ET.ParseError:
        wrapped = "<__wxml_root__>\n" + wxml_text + "\n</__wxml_root__>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError as e:
            raise RuntimeError(f"Failed to parse WXML text: {e}")

    visit(root)

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
