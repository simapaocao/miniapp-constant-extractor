#!/usr/bin/env python3
import sys
import json
import hashlib
from typing import Any, Dict, List, NamedTuple, Tuple, Set

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


def extract_string_constants_indexed(
    data: Any, store: StatementStore, dedup: bool
) -> List[Tuple[str, int]]:
    """
    Traverse JSON-like data and return constants as a list of:
      (string_value, statement_id)

    Statements are stored in StatementStore as: '<path>: "value"'
    Only string values are extracted. bool/int/float/null are ignored.

    dedup:
      - False: include every occurrence
      - True: dedupe globally by string
    """
    results: List[Tuple[str, int]] = []
    seen_strings: Set[str] = set()

    def value_to_compact_json(v: Any) -> str:
        """Compact, human-readable JSON for values (preserves unicode)."""
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))

    def display_path(tokens: List[str]) -> str:
        """Human-friendly path. Does NOT JSON-pointer-escape '/'."""
        if not tokens:
            return ""
        return "/".join(tokens)

    def walk(node: Any, tokens: List[str]) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, tokens + [str(k)])
            return

        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, tokens + [str(i)])
            return

        if not isinstance(node, str):
            return

        if dedup:
            if node in seen_strings:
                return
            seen_strings.add(node)

        path = display_path(tokens)
        stmt = f"{path}: {value_to_compact_json(node)}"
        stmt_id = store.add(stmt)
        results.append((node, stmt_id))

    walk(data, [])
    return results


def extract_from_json_obj(
    data: Any,
    store: StatementStore,
    dedup: bool = False,
) -> Dict[str, Any]:
    """
    Pure function: given a parsed JSON object, return:
      { "statements": [...], "constants": [...] }
    """
    return extract_string_constants_indexed(data, store, dedup=dedup)


def extract_from_json_text(
    text: str, store: StatementStore
) -> Set[Tuple[str, int, str]]:
    """
    Pure function: given JSON text, parse and extract constants.
    Handles malformed JSON gracefully.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # 尝试只解析第一个 JSON 对象（处理 Extra data 情况）
        try:
            decoder = json.JSONDecoder()
            data, _ = decoder.raw_decode(text)
        except json.JSONDecodeError:
            return set()
    
    res = extract_from_json_obj(data, store, True)

    # Build output triples with source tag
    results: Set[Tuple[str, int, str]] = set()
    for s, sid in res:
        results.add((s, sid, "json"))
    return results


def extract_from_json_file(path: str) -> Dict[str, Any]:
    """Convenience wrapper: read file and extract (unit-test friendly)."""
    store = StatementStore()
    res = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        res = extract_from_json_text(f.read(), store)
    if not res:
        return {"statements": [], "constants": []}

    constants = [
        ConstRd(s, sid, src)
        for (s, sid, src) in res
        if isinstance(s, str) and len(s) > MIN_STRING_LEN
    ]
    constants.sort(key=lambda x: (x[0], x[2], x[1]))
    return {"statements": store.statements, "constants": constants}


def main_7c1ab9f9(argv: List[str]) -> int:
    """For testing"""
    if len(argv) < 2 or not argv[1].endswith(".json"):
        print(f"Usage: python {argv[0]} <file.json>")
        return 2

    try:
        output = extract_from_json_file(argv[1])
    except FileNotFoundError:
        print(f"Error: File '{argv[1]}' not found.")
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON. {e}")
        return 1

    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_7c1ab9f9(sys.argv))
