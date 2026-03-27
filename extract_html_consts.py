#!/usr/bin/env python3
"""
Extract string constants from ONE .html file:
- HTML attribute values
- HTML text content
- <script> JavaScript string literals (option B)

Output format:
{
  "statements": [...],
  "constants": [
    ["string", statement_id, "source"],
    ...
  ]
}
"""
from __future__ import annotations

import sys
import json
import hashlib
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, NamedTuple, Tuple, Set

ConstRd = NamedTuple("ConstRd", [("ST", str), ("ID", int), ("STMT", str)])
MIN_STRING_LEN = 4


class StatementStore:
    """Deduplicate statement strings by hash and assign stable integer ids."""

    def __init__(self) -> None:
        self._idx_by_hash: Dict[str, int] = {}  # hash -> statement_id
        self.statements: List[str] = []

    @staticmethod
    def _hash_stmt(stmt: str) -> str:
        # SHA-1 is plenty for dedupe;
        return hashlib.sha1(stmt.encode("utf-8", errors="surrogatepass")).hexdigest()

    def add(self, stmt: str) -> int:
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


# -----------------------
# JS string scanner (for <script> blocks)
# -----------------------
def extract_js_strings_with_line_context(js_text: str) -> List[Tuple[int, str]]:
    """
    Extract JS/TS-like string literals from js_text.
    Returns list of (start_line_1based, string_value).
    - Handles '...', "...", and template literals `...${}...` (constant chunks only)
    - Skips // and /* */ comments
    """
    n = len(js_text)
    i = 0
    line = 1
    out: List[Tuple[int, str]] = []

    def peek(off: int = 0) -> str:
        j = i + off
        return js_text[j] if 0 <= j < n else ""

    def advance(k: int = 1) -> None:
        nonlocal i, line
        for _ in range(k):
            if i >= n:
                return
            ch = js_text[i]
            i += 1
            if ch == "\n":
                line += 1

    def skip_line_comment() -> None:
        while i < n and peek() != "\n":
            advance(1)

    def skip_block_comment() -> None:
        advance(2)  # /*
        while i < n:
            if peek() == "*" and peek(1) == "/":
                advance(2)
                return
            advance(1)

    def read_quoted(q: str) -> Tuple[int, str]:
        start_line = line
        advance(1)  # opening quote
        buf: List[str] = []
        while i < n:
            ch = peek()
            if ch == "\\":
                advance(1)
                if i < n:
                    buf.append(peek())
                    advance(1)
                continue
            if ch == q:
                advance(1)
                break
            buf.append(ch)
            advance(1)
        return start_line, "".join(buf)

    def skip_template_expr() -> None:
        depth = 1
        while i < n and depth > 0:
            ch = peek()

            if ch in ("'", '"'):
                _sl, _ = read_quoted(ch)
                continue
            if ch == "`":
                _sl, _ = read_template()
                continue

            if ch == "/" and peek(1) == "/":
                advance(2)
                skip_line_comment()
                continue
            if ch == "/" and peek(1) == "*":
                skip_block_comment()
                continue

            if ch == "{":
                depth += 1
                advance(1)
                continue
            if ch == "}":
                depth -= 1
                advance(1)
                continue

            advance(1)

    def read_template() -> Tuple[int, List[str]]:
        start_line = line
        advance(1)  # `
        chunk: List[str] = []
        chunks: List[str] = []
        while i < n:
            ch = peek()
            if ch == "\\":
                advance(1)
                if i < n:
                    chunk.append(peek())
                    advance(1)
                continue
            if ch == "`":
                advance(1)
                s = "".join(chunk)
                if s:
                    chunks.append(s)
                return start_line, chunks
            if ch == "$" and peek(1) == "{":
                s = "".join(chunk)
                if s:
                    chunks.append(s)
                chunk = []
                advance(2)  # ${
                skip_template_expr()
                continue

            chunk.append(ch)
            advance(1)

        s = "".join(chunk)
        if s:
            chunks.append(s)
        return start_line, chunks

    while i < n:
        ch = peek()

        if ch == "/" and peek(1) == "/":
            advance(2)
            skip_line_comment()
            continue
        if ch == "/" and peek(1) == "*":
            skip_block_comment()
            continue

        if ch in ("'", '"'):
            sl, s = read_quoted(ch)
            if s:
                out.append((sl, s))
            continue

        if ch == "`":
            sl, chunks = read_template()
            for s in chunks:
                if s:
                    out.append((sl, s))
            continue

        advance(1)

    return out


# -----------------------
# HTML parser that also scans script bodies
# -----------------------
class HTMLConstExtractor(HTMLParser):
    def __init__(self, stmt_store: StatementStore) -> None:
        super().__init__(convert_charrefs=True)
        self.store = stmt_store
        self.constants: Set[Tuple[str, int, str]] = set()
        self.tag_stack: List[str] = []

        # We keep style ignored; script is *captured* and scanned.
        self.in_style = 0
        self.in_script = 0
        self.script_buf: List[str] = []

        # Track line numbers for statement context
        self._last_data_line: Optional[int] = None

    def _looks_dynamic(self, s: str) -> bool:
        """Heuristic: treat template/binding strings as non-constant."""
        return ("{{" in s and "}}" in s) or ("${" in s and "}" in s)

    def _emit(self, value: str, statement: str, source: str) -> None:
        v = (value or "").strip()
        if not v or self._looks_dynamic(v):
            return
        sid = self.store.add(statement)
        self.constants.add((v, sid, source))

    def handle_starttag(self, tag: str, attrs) -> None:
        self.tag_stack.append(tag)
        if tag == "style":
            self.in_style += 1
        if tag == "script":
            self.in_script += 1
            self.script_buf = []

        # Attribute constants (skip Vue-style bound attrs is optional; for plain HTML keep all)
        for k, v in attrs:
            if v is None:
                continue
            val = v.strip()
            if not val:
                continue
            # Optional: skip template/binding-like attrs
            if self._looks_dynamic(val):
                continue
            stmt = f'<{tag} {k}="{val}">'
            self._emit(val, stmt, "html-attr")

    def handle_endtag(self, tag: str) -> None:
        if tag == "style" and self.in_style > 0:
            self.in_style -= 1

        if tag == "script" and self.in_script > 0:
            self.in_script -= 1
            js_text = "".join(self.script_buf)

            # Build statement context from the first line of the script tag if possible
            script_lines = js_text.splitlines()
            # Extract JS strings and map them to script line -> statement (script line)
            for sl, s in extract_js_strings_with_line_context(js_text):
                # statement = the actual JS line where it starts (best effort)
                stmt = ""
                if 1 <= sl <= len(script_lines):
                    stmt = script_lines[sl - 1].strip()
                if not stmt:
                    # fallback: identify it's from script
                    stmt = "<script>...</script>"
                self._emit(s, stmt, "html-script")

        if self.tag_stack:
            self.tag_stack.pop()

    def handle_data(self, data: str) -> None:
        # Track current parser line for potential future use
        try:
            self._last_data_line = self.getpos()[0]
        except Exception:
            self._last_data_line = None

        if self.in_style > 0:
            return

        if self.in_script > 0:
            # Collect script content verbatim; parsed later
            self.script_buf.append(data)
            return

        # Text constants
        text = (data or "").strip()
        if not text or self._looks_dynamic(text):
            return

        tag = self.tag_stack[-1] if self.tag_stack else None
        stmt = f"<{tag}>{text}</{tag}>" if tag else f'text: "{text}"'
        self._emit(text, stmt, "html-text")


def extract_from_html_text(
    html_text: str, store: StatementStore
) -> Set[Tuple[str, int, str]]:
    """
    Pure function: extract constants from an HTML string.
    Suitable for unit tests.
    """
    parser = HTMLConstExtractor(store)
    parser.feed(html_text)
    parser.close()
    return parser.constants


def extract_from_html_file(path: str) -> Dict[str, Any]:
    """Convenience wrapper: read file and extract."""
    store = StatementStore()
    res = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        res = extract_from_html_text(f.read(), store)
    if not res:
        return {"statements": [], "constants": []}

    constants = [
        ConstRd(s, sid, src)
        for (s, sid, src) in res
        if isinstance(s, str) and len(s) > MIN_STRING_LEN
    ]
    constants.sort(key=lambda x: (x[0], x[2], x[1]))
    return {"statements": store.statements, "constants": constants}


def main_a4dc44a8(argv: List[str]) -> int:
    """For testing"""
    if len(argv) != 2 or not argv[1].endswith(".html"):
        print(f"Usage: python {argv[0]} <file.html>")
        return 2

    try:
        result = extract_from_html_file(argv[1])
    except FileNotFoundError:
        print(f"Error: File '{argv[1]}' not found.")
        return 1
    except OSError as e:
        print(f"Error reading file: {e}")
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_a4dc44a8(sys.argv))
