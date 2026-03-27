#!/usr/bin/env python3
import sys
import json
import esprima
import hashlib
from typing import Any, Dict, List, Optional, Set, NamedTuple, Tuple

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


def extract_from_wxs_text(
    code: str, store: StatementStore
) -> Set[Tuple[str, int, str]]:
    """
    Pure function: Extract constant *string* literals from WXS code text.

    Returns:
      {
        "statements": [...],
        "constants": [(string, statement_id, "wxs"), ...]
      }
    """

    def safe_slice(src: str, node: Any) -> str:
        """Slice original code by esprima node.range if present and valid."""
        r = getattr(node, "range", None)
        if (
            isinstance(r, (list, tuple))
            and len(r) == 2
            and isinstance(r[0], int)
            and isinstance(r[1], int)
            and 0 <= r[0] <= r[1] <= len(src)
        ):
            return src[r[0] : r[1]]
        return ""

    def best_statement(src: str, parents: List[Any], fallback_node: Any) -> str:
        """
        Choose a human-meaningful statement context by walking up the parent chain.
        """
        preferred = {
            "VariableDeclarator",
            "Property",
            "AssignmentExpression",
            "ExpressionStatement",
            "VariableDeclaration",
        }
        for p in reversed(parents):
            ptype = getattr(p, "type", None)
            if ptype in preferred:
                s = safe_slice(src, p).strip()
                if s:
                    return s
        s = safe_slice(src, fallback_node).strip()
        return s if s else "<unknown statement>"

    def walk(node: Any, parents: List[Any]) -> None:
        if node is None:
            return

        node_type = getattr(node, "type", None)

        # 1) String literals
        if node_type == "Literal":
            val = getattr(node, "value", None)
            if isinstance(val, str) and val:
                stmt = best_statement(code, parents, node)
                sid = store.add(stmt)
                constants.add((val, sid, "wxs"))

        # 2) Template literals: emit static chunks only
        if node_type == "TemplateLiteral":
            quasis = getattr(node, "quasis", None) or []
            stmt = best_statement(code, parents, node)
            sid = store.add(stmt)
            for q in quasis:
                qval = getattr(q, "value", None)
                cooked = getattr(qval, "cooked", None) if qval is not None else None
                if isinstance(cooked, str) and cooked.strip():
                    constants.add((cooked, sid, "wxs"))

        # Walk children defensively (vars(node) can fail for some objects)
        try:
            items = vars(node).items()
        except Exception:
            items = []

        for _, v in items:
            if isinstance(v, list):
                for child in v:
                    if getattr(child, "type", None):
                        walk(child, parents + [node])
            else:
                if getattr(v, "type", None):
                    walk(v, parents + [node])
        # end for _

    # def walk()

    constants: Set[Tuple[str, int, str]] = set()
    try:
        ast = esprima.parseScript(code, loc=True, range=True, tolerant=True)
    except Exception as e:
        # For unit tests, failing fast is often better; but for CLI we want a nice error.
        # Here we return a structured result to avoid crashing.
        store.add(f"<parse error: {e}>")
        return constants

    walk(ast, [])
    return constants


def extract_from_wxs_file(path: str) -> Dict[str, Any]:
    """Unit-test friendly wrapper around file I/O."""
    store = StatementStore()
    res = None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        res = extract_from_wxs_text(f.read(), store)
    if not res:
        return {"statements": [], "constants": []}

    constants = [
        ConstRd(s, sid, src)
        for (s, sid, src) in res
        if isinstance(s, str) and len(s) > MIN_STRING_LEN
    ]
    constants.sort(key=lambda x: (x[0], x[2], x[1]))
    return {"statements": store.statements, "constants": constants}


def main_10ddf070(argv: List[str]) -> int:
    """For testing"""
    if len(argv) != 2 or not argv[1].endswith(".wxs"):
        print(f"Usage: python {argv[0]} <file.wxs>")
        return 2

    try:
        result = extract_from_wxs_file(argv[1])
    except FileNotFoundError:
        print(f"Error: File '{argv[1]}' not found.")
        return 1
    except OSError as e:
        print(f"Error reading file: {e}")
        return 1

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main_10ddf070(sys.argv))
