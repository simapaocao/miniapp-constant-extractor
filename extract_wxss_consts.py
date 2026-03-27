#!/usr/bin/env python3
import sys
import json
import re
import hashlib
from typing import Any, Dict, List, Set, NamedTuple, Tuple


ConstRd = NamedTuple("ConstRd", [("ST", str), ("ID", int), ("STMT", str)])
# Strip C-style comments /* ... */
COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
# Optional: strip // comments (not standard CSS, but sometimes present)
LINE_COMMENT_RE = re.compile(r"//.*?$", re.M)
# Extract either url(...) target or quoted string
TOKEN_RE = re.compile(
    r"""
    url\(\s*(['"]?)([^'")]+)\1\s*\)     # url(...) possibly quoted
    |
    (['"])(.*?)\3                       # "..." or '...'
    """,
    re.X,
)
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


def extract_from_wxss_text(
    text: str, store: StatementStore
) -> Set[Tuple[str, int, str]]:
    """
    Pure function: Extract string constants from WXSS text.

    Extracts:
      - quoted strings: "..." / '...'
      - url(...) values: url("..."), url('...'), url(...)

    Output:
      {
        "statements": [...],
        "constants": [(string, statement_id, "wxss"), ...]
      }

    Statement context is the (rough) declaration chunk containing the string,
    derived by splitting on ';' after removing comments. This is more robust
    than line-by-line parsing for multi-line declarations.
    """
    constants: Set[Tuple[str, int, str]] = set()

    # 1) remove comments
    text = COMMENT_RE.sub("", text)
    text = LINE_COMMENT_RE.sub("", text)  # optional, safe

    # 2) Split into semicolon-terminated chunks (good enough for statement context)
    chunks: List[str] = []
    buf: List[str] = []

    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        buf.append(s)
        if ";" in s:
            chunks.append(" ".join(buf))
            buf = []
    if buf:
        chunks.append(" ".join(buf))

    # 3) Extract tokens from each chunk
    for stmt in chunks:
        if "url(" not in stmt and '"' not in stmt and "'" not in stmt:
            continue

        sid = store.add(stmt)

        for m in TOKEN_RE.finditer(stmt):
            val: str | None = None
            if m.group(2) is not None:
                val = m.group(2).strip()  # url(...)
            elif m.group(4) is not None:
                val = m.group(4)  # quoted string

            if not val:
                continue

            constants.add((val, sid, "wxss"))
        # end for m
    # end for stmt

    return constants


def extract_from_wxss_file(path: str) -> Dict[str, Any]:
    """Thin I/O wrapper for production/CLI usage (also usable in tests)."""
    store = StatementStore()
    res = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        res = extract_from_wxss_text(f.read(), store)
    if not res:
        return {"statements": [], "constants": []}

    constants = [
        ConstRd(s, sid, src)
        for (s, sid, src) in res
        if isinstance(s, str) and len(s) > MIN_STRING_LEN
    ]
    constants.sort(key=lambda x: (x[0], x[2], x[1]))
    return {"statements": store.statements, "constants": constants}


def main_c7a4c4c4(argv: List[str]) -> int:
    """For testing"""
    if len(argv) != 2 or not argv[1].endswith(".wxss"):
        print(f"Usage: python {argv[0]} <file.wxss>")
        return 2

    try:
        result = extract_from_wxss_file(argv[1])
    except FileNotFoundError:
        print(f"Error: File '{argv[1]}' not found.")
        return 1
    except OSError as e:
        print(f"Error reading file: {e}")
        return 1

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_c7a4c4c4(sys.argv))
