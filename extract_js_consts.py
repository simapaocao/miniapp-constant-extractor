#!/usr/bin/env python3
import sys
import json
import re
import bisect
import hashlib
import threading
from typing import Any, Dict, List, Optional, Set, NamedTuple, Tuple
import esprima


# Name of class first, then list of (name, type) tuples
FileSlice = NamedTuple("FileSlice", [("S", int), ("E", int), ("C", str)])
ConstRd = NamedTuple("ConstRd", [("ST", str), ("ID", int), ("STMT", str)])
MINI_FUNC_SIZE = 60  # Small function: Minified: ~80–400 bytes; Gzipped: ~60–250 bytes
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


# Function locations regex
FUNC_RE = re.compile(
    r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{", re.MULTILINE
)


class JSParseContext:
    """
    线程/进程安全的解析上下文，避免全局变量在多进程环境下的竞争问题。
    每次解析一个文件时创建一个新的上下文实例。
    """
    def __init__(self, content: str):
        self.content = content
        self.func_locs = self._locate_functions_regex(content)
    
    @staticmethod
    def _locate_functions_regex(js: str) -> List[int]:
        """Locate all possible named functions by regex and store their start positions."""
        locs = [m.start() for m in FUNC_RE.finditer(js)]
        locs.sort()
        return locs
    
    def find_func_pos_between(self, min_pos: int, max_pos: int) -> Optional[int]:
        """
        Returns the first function-start *position* in func_locs such that:
          min_pos < pos < max_pos
        """
        index = bisect.bisect_right(self.func_locs, min_pos)
        if index < len(self.func_locs):
            candidate = self.func_locs[index]
            if candidate < max_pos:
                return candidate
        return None


# ============ 兼容旧代码的全局变量（仅用于单进程场景或测试） ============
# 注意：多进程环境下应使用 JSParseContext
_thread_local = threading.local()

def _get_context() -> Optional[JSParseContext]:
    """获取当前线程的解析上下文"""
    return getattr(_thread_local, 'context', None)

def _set_context(ctx: JSParseContext) -> None:
    """设置当前线程的解析上下文"""
    _thread_local.context = ctx

# 保留旧的全局变量名以兼容可能的外部调用
FUNC_LOCS: List[int] = []
JS_FILE_CONTENT: Optional[str] = None


def locate_functions_regex(js: str) -> List[int]:
    """Locate all possible named functions by regex and store their start positions.
    
    注意：此函数保留用于兼容，多进程环境下应使用 JSParseContext
    """
    global FUNC_LOCS
    FUNC_LOCS = [m.start() for m in FUNC_RE.finditer(js)]
    FUNC_LOCS.sort()
    return FUNC_LOCS


def find_func_pos_between(min_pos: int, max_pos: int, ctx: Optional[JSParseContext] = None) -> Optional[int]:
    """
    Returns the first function-start *position* such that:
      min_pos < pos < max_pos
    
    如果提供了 ctx，使用 ctx 中的 func_locs；否则使用全局 FUNC_LOCS（兼容模式）
    """
    if ctx is not None:
        return ctx.find_func_pos_between(min_pos, max_pos)
    
    # 兼容模式：使用全局变量
    index = bisect.bisect_right(FUNC_LOCS, min_pos)
    if index < len(FUNC_LOCS):
        candidate = FUNC_LOCS[index]
        if candidate < max_pos:
            return candidate
    return None


def get_function_bodies(
    start: int, end: int, content: Optional[str] = None
) -> Tuple[List[FileSlice], List[FileSlice]]:
    """
    Heuristic method to find function bodies.

    Scans content[start:end] and returns:
      - function_bodies: slices that are likely {...} blocks belonging to functions
      - not_func_chunks: everything else between those blocks
    
    参数:
      content: JS文件内容，如果为None则使用全局 JS_FILE_CONTENT（兼容模式）
    """
    global JS_FILE_CONTENT
    if content is None:
        content = JS_FILE_CONTENT
    if content is None:
        return [], []
    sub = content[start:end]

    function_bodies: List[FileSlice] = []
    not_func_chunks: List[FileSlice] = []

    i = 0
    n = len(sub)
    nf_start = 0  # relative start of current non-function chunk

    while i < n:
        c = sub[i]

        if c == "{":
            lookback = sub[max(0, i - 80) : i].strip()

            is_candidate = False
            if lookback.endswith("=>"):
                is_candidate = True
            elif re.search(r"\bfunction\b", lookback):
                is_candidate = True
            elif re.search(r"\)\s*$", lookback):
                # method shorthand / function call followed by block
                is_candidate = True

            if is_candidate:
                depth = 0
                body_start_rel = i
                j = i

                in_str: Optional[str] = None
                esc = False

                while j < n:
                    ch = sub[j]

                    # --- inside string/template ---
                    if in_str:
                        if esc:
                            esc = False
                        elif ch == "\\":
                            esc = True
                        elif ch == in_str:
                            in_str = None
                        j += 1
                        continue

                    # --- handle regex literal naively ---
                    if ch == "/" and j + 1 < n and sub[j + 1] != " ":
                        k = j + 1
                        while k < n and sub[k] != "/":
                            k += 1
                        j = k + 1
                        continue

                    # --- string starts ---
                    if ch in ('"', "'", "`"):
                        in_str = ch
                        j += 1
                        continue

                    # --- brace tracking ---
                    if ch == "{":
                        depth += 1
                        j += 1
                        continue

                    if ch != "}":
                        j += 1
                        continue

                    # handle "}"
                    depth -= 1
                    if depth != 0:
                        j += 1
                        continue

                    # Find a function
                    body_end_rel = j + 1

                    abs_s = start + body_start_rel
                    abs_e = start + body_end_rel
                    function_bodies.append(
                        FileSlice(abs_s, abs_e, content[abs_s:abs_e])
                    )

                    # capture non-function content before this function
                    nf_end_rel = body_start_rel
                    if nf_end_rel > nf_start + 5:
                        abs_nf_s = start + nf_start
                        abs_nf_e = start + nf_end_rel
                        not_func_chunks.append(
                            FileSlice(abs_nf_s, abs_nf_e, content[abs_nf_s:abs_nf_e])
                        )

                    i = body_end_rel
                    nf_start = i
                    break
                # end while j < n
            # end if is_candidate
        i += 1
    # end while i < n

    # trailing non-function chunk
    if n > nf_start + 5:
        abs_nf_s = start + nf_start
        abs_nf_e = start + n
        not_func_chunks.append(
            FileSlice(abs_nf_s, abs_nf_e, content[abs_nf_s:abs_nf_e])
        )

    return function_bodies, not_func_chunks


def extract_function_strings_via_ast(
    file_slice: FileSlice, store: StatementStore
) -> Set[Tuple[str, int]]:
    """Parse a code block and extract (string_value, statement_id)."""
    code_block = file_slice.C

    def push_child(stack: List[Any], v: Any) -> None:
        if v is None:
            return
        if isinstance(v, list):
            for item in v:
                push_child(stack, item)
            return
        if isinstance(v, dict):
            for item in v.values():
                push_child(stack, item)
            return
        if hasattr(v, "__dict__") or hasattr(v, "type"):
            stack.append(v)

    def node_type(n: Any) -> Optional[str]:
        if isinstance(n, dict):
            return n.get("type")
        return getattr(n, "type", None)

    def node_range(n: Any) -> Optional[List[int]]:
        if isinstance(n, dict):
            return n.get("range")
        return getattr(n, "range", None)

    def snippet_for_node(n: Any) -> str:
        rng = node_range(n)
        if not rng or len(rng) != 2:
            return ""
        a, b = rng
        if not (isinstance(a, int) and isinstance(b, int)):
            return ""
        if a < 0 or b > len(code_block) or a >= b:
            return ""
        return code_block[a:b].strip()

    def find_defining_statement(n: Any, parent_map: Dict[int, Any]) -> str:
        preferred = {
            "VariableDeclarator",
            "Property",
            "AssignmentExpression",
            "VariableDeclaration",
            "ExpressionStatement",
        }

        cur: Any = n
        while cur is not None:
            t = node_type(cur)
            if t in preferred:
                snip = snippet_for_node(cur)
                if snip:
                    return snip
            cur = parent_map.get(id(cur))

        cur = n
        while cur is not None:
            snip = snippet_for_node(cur)
            if snip:
                return snip
            cur = parent_map.get(id(cur))

        return "<unknown statement>"

    found: Set[Tuple[str, int]] = set()

    try:
        tree = esprima.parseScript(
            code_block, options={"range": True, "tolerant": True}
        )
    except Exception:
        return found

    parent_map: Dict[int, Any] = {}

    # Build parent map
    nodes: List[Any] = [tree]
    while nodes:
        node = nodes.pop()

        if isinstance(node, dict):
            for v in node.values():
                if isinstance(v, list):
                    for item in v:
                        if hasattr(item, "__dict__") or isinstance(item, dict):
                            parent_map[id(item)] = node
                elif hasattr(v, "__dict__") or isinstance(v, dict):
                    parent_map[id(v)] = node
                push_child(nodes, v)
        else:
            try:
                items = vars(node).items()
            except Exception:
                items = []
            for _, v in items:
                if isinstance(v, list):
                    for item in v:
                        if hasattr(item, "__dict__") or isinstance(item, dict):
                            parent_map[id(item)] = node
                elif hasattr(v, "__dict__") or isinstance(v, dict):
                    parent_map[id(v)] = node
                push_child(nodes, v)

    # Walk tree and collect string literals + template quasis
    nodes = [tree]
    seen: Set[int] = set()
    while nodes:
        node = nodes.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))

        t = node_type(node)

        if t == "Literal":
            val = (
                node.get("value")
                if isinstance(node, dict)
                else getattr(node, "value", None)
            )
            if isinstance(val, str) and val:
                stmt = find_defining_statement(node, parent_map)
                found.add((val.strip(), store.add(stmt)))

        if t == "TemplateLiteral":
            quasis = (
                node.get("quasis", [])
                if isinstance(node, dict)
                else (getattr(node, "quasis", []) or [])
            )
            for q in quasis:
                v = q.get("value") if isinstance(q, dict) else getattr(q, "value", None)
                cooked = None
                if isinstance(v, dict):
                    cooked = v.get("cooked")
                else:
                    cooked = getattr(v, "cooked", None) if v else None
                if isinstance(cooked, str) and cooked:
                    stmt = find_defining_statement(node, parent_map)
                    found.add((cooked.strip(), store.add(stmt)))

        if isinstance(node, dict):
            for v in node.values():
                push_child(nodes, v)
        else:
            try:
                items = vars(node).items()
            except Exception:
                items = []
            for _, v in items:
                push_child(nodes, v)

    return found


def extract_chunk_strings_via_ast(
    file_slice: FileSlice, store: StatementStore
) -> Tuple[Set[Tuple[str, int]], bool]:
    """Parse semi-colon terminated chunks and extract strings."""
    size = 0
    start = 0
    code_block = file_slice.C
    nextp = code_block.find(";", start)
    found: Set[Tuple[str, int]] = set()

    while nextp != -1:
        blk = code_block[start : nextp + 1]

        blk_slice = FileSlice(0, len(blk), blk)
        ast_res = extract_function_strings_via_ast(blk_slice, store)
        if ast_res:
            found.update(ast_res)
            size += len(blk)

        start = nextp + 1
        nextp = code_block.find(";", start)

    return found, (len(code_block) - size) < MINI_FUNC_SIZE


def _extract_from_long_line(line: str, store: StatementStore) -> Set[Tuple[str, int]]:
    """对超长行使用简化的不回溯正则提取，避免卡住。"""
    found: Set[Tuple[str, int]] = set()

    # 键名支持: 标识符、带-的键(data-id)、带.的键(a.b)
    regex_simple_double = re.compile(r'([\w$][\w$.\-]*)\s*:\s*"([^"]*)"')
    regex_simple_single = re.compile(r"([\w$][\w$.\-]*)\s*:\s*'([^']*)'")

    for m in regex_simple_double.finditer(line):
        key, val = m.group(1), m.group(2)
        found.add((val.strip(), store.add(f'{key}: "{val}"')))

    for m in regex_simple_single.finditer(line):
        key, val = m.group(1), m.group(2)
        found.add((val.strip(), store.add(f"{key}: '{val}'")))

    return found


def extract_global_strings_regex(
    file_slice: FileSlice, store: StatementStore
) -> Set[Tuple[str, int]]:
    """Regex extraction for variable declarations and property assignments."""
    found: Set[Tuple[str, int]] = set()
    content = file_slice.C

    # 预处理：分离正常行和超长行
    MAX_LINE_LENGTH = 10000  # 10KB=10000 - 超过此长度的行使用简化正则
    lines = content.split('\n')
    normal_lines = []
    long_lines = []
    
    for line in lines:
        if len(line) <= MAX_LINE_LENGTH:
            normal_lines.append(line)
        else:
            normal_lines.append('')  # 占位保持行号
            long_lines.append(line)
    
    # 对超长行使用简化的不回溯正则
    for line in long_lines:
        found.update(_extract_from_long_line(line, store))
    
    # 对正常行使用完整的正则
    content = '\n'.join(normal_lines)

    regex_vars = re.compile(
        r'((?:var|let|const)\s+(?:[\w$]+\.)?[\w$]+\s*=\s*)(["\'])(.*?)\2\s*;?',
        re.MULTILINE,
    )

    # 逗号分隔的多变量声明: var a = "x", b = "y", c = "z"
    # 匹配 , 后面的 identifier = "string" 模式
    regex_comma_vars = re.compile(
        r',\s*([\w$]+)\s*=\s*(["\'])((?:(?!\2).)*)\2',
        re.MULTILINE,
    )

    regex_props_dot = re.compile(
        r'([\w$]+\.[\w$]+\s*=\s*)(["\'])(.*?)\2\s*;?', re.MULTILINE
    )

    regex_props_bracket = re.compile(
        r'([\w$]+\s*\[\s*(["\'])[^"\']+\2\s*\]\s*=\s*)(["\'])(.*?)\3\s*;?', re.MULTILINE
    )

    # 对象属性值: key: "value" 或 "key": "value" 或 'key': 'value'
    # 使用不回溯的正则避免灾难性回溯
    # 原正则 r'(["\']?)([^"\':\s][^"\':\n]*?)\1\s*:\s*(["\'])(.*?)\3\s*[,}\n]' 会在大文本上卡住
    # 改用否定字符类 [^"] 和 [^'] 替代 .*? 实现线性时间匹配
    # 键名支持: 标识符、带-的键(data-id)、带.的键(a.b)
    regex_obj_props_double = re.compile(
        r'([\w$][\w$.\-]*)\s*:\s*"([^"]*)"', re.MULTILINE
    )
    regex_obj_props_single = re.compile(
        r"([\w$][\w$.\-]*)\s*:\s*'([^']*)'", re.MULTILINE
    )
    # 带引号的键: "key": "value" 或 "key": 'value'
    regex_obj_props_quoted_double = re.compile(
        r'"([^"]+)"\s*:\s*"([^"]*)"', re.MULTILINE
    )
    regex_obj_props_quoted_single = re.compile(
        r"'([^']+)'\s*:\s*'([^']*)'", re.MULTILINE
    )
    # 混合引号: "key": 'value' 或 'key': "value"
    regex_obj_props_mixed1 = re.compile(
        r'"([^"]+)"\s*:\s*\'([^\']*)\'', re.MULTILINE
    )
    regex_obj_props_mixed2 = re.compile(
        r"'([^']+)'\s*:\s*\"([^\"]*)\"", re.MULTILINE
    )

    for m in regex_vars.finditer(content):
        prefix = m.group(1)
        quote = m.group(2)
        s = m.group(3)
        stmt = (prefix + quote + s + quote).strip()
        found.add((s.strip(), store.add(stmt)))

    # 处理逗号分隔的多变量声明
    for m in regex_comma_vars.finditer(content):
        var_name = m.group(1)
        quote = m.group(2)
        s = m.group(3)
        stmt = f"{var_name} = {quote}{s}{quote}"
        found.add((s.strip(), store.add(stmt)))

    for m in regex_props_dot.finditer(content):
        prefix = m.group(1)
        quote = m.group(2)
        s = m.group(3)
        stmt = (prefix + quote + s + quote).strip()
        found.add((s.strip(), store.add(stmt)))

    for m in regex_props_bracket.finditer(content):
        prefix = m.group(1)
        quote = m.group(3)
        s = m.group(4)
        stmt = (prefix + quote + s + quote).strip()
        found.add((s.strip(), store.add(stmt)))

    for m in regex_obj_props_double.finditer(content):
        key, val = m.group(1), m.group(2)
        stmt = f'{key}: "{val}"'
        found.add((val.strip(), store.add(stmt)))

    for m in regex_obj_props_single.finditer(content):
        key, val = m.group(1), m.group(2)
        stmt = f"{key}: '{val}'"
        found.add((val.strip(), store.add(stmt)))

    for m in regex_obj_props_quoted_double.finditer(content):
        key, val = m.group(1), m.group(2)
        stmt = f'"{key}": "{val}"'
        found.add((val.strip(), store.add(stmt)))

    for m in regex_obj_props_quoted_single.finditer(content):
        key, val = m.group(1), m.group(2)
        stmt = f"'{key}': '{val}'"
        found.add((val.strip(), store.add(stmt)))

    for m in regex_obj_props_mixed1.finditer(content):
        key, val = m.group(1), m.group(2)
        stmt = f'"{key}": \'{val}\''
        found.add((val.strip(), store.add(stmt)))

    for m in regex_obj_props_mixed2.finditer(content):
        key, val = m.group(1), m.group(2)
        stmt = f"'{key}': \"{val}\""
        found.add((val.strip(), store.add(stmt)))

    return found


def extract_from_js_text(
    start: int,
    end: int,
    store: StatementStore,
    visited: Optional[Set[Tuple[int, int]]] = None,
    ctx: Optional[JSParseContext] = None,
) -> Set[Tuple[str, int, str]]:
    """
    Extract string constants from JS text.
    
    参数:
      ctx: JSParseContext 实例，包含文件内容和函数位置信息
           如果为 None，使用全局变量（兼容模式，不推荐在多进程环境使用）
    """
    if visited is None:
        visited = set()

    key = (start, end)
    if key in visited:
        return set()
    visited.add(key)

    # 获取文件内容
    content = ctx.content if ctx else JS_FILE_CONTENT
    
    bodies, chunks = get_function_bodies(start, end, content)

    results: Set[Tuple[str, int, str]] = set()

    for b in bodies:
        ast_res = extract_function_strings_via_ast(b, store)
        if ast_res:
            for s, sid in ast_res:
                results.add((s, sid, "js-ast"))
        else:
            func_pos = find_func_pos_between(b.S, b.E, ctx)
            if func_pos is not None and b.S < func_pos < b.E:
                results.update(extract_from_js_text(func_pos, b.E, store, visited, ctx))

    data_blocks: List[FileSlice] = []
    for c in chunks:
        found, consumed = extract_chunk_strings_via_ast(c, store)
        for s, sid in found:
            results.add((s, sid, "js-ast"))
        if not consumed:
            data_blocks.append(c)

    for d in data_blocks:
        for s, sid in extract_global_strings_regex(d, store):
            results.add((s, sid, "js-regex"))

    return results


def extract_from_js_file(path: str) -> Dict[str, Any]:
    """
    从 JS 文件提取字符串常量。
    
    使用 JSParseContext 确保多进程安全，避免全局变量竞争。
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # 创建独立的解析上下文，避免多进程环境下的全局变量竞争
    ctx = JSParseContext(content)

    store = StatementStore()
    res = extract_from_js_text(0, len(content), store, ctx=ctx)

    constants = [
        ConstRd(s, sid, src)
        for (s, sid, src) in res
        if isinstance(s, str) and len(s) > MIN_STRING_LEN
    ]
    constants.sort(key=lambda x: x[1])  # 按 statement_id 排序，保持源码出现顺序
    return {"statements": store.statements, "constants": constants}


def main_fb6b990d(argv: List[str]) -> int:
    """For testing"""
    if len(argv) < 2 or not argv[1].endswith(".js"):
        print(f"Usage: python {argv[0]} <file.js> [output.json]")
        return 2

    try:
        output = extract_from_js_file(argv[1])
    except FileNotFoundError:
        print(f"Error: File '{argv[1]}' not found.")
        return 1
    except OSError as e:
        print(f"Error reading file: {e}")
        return 1

    result = json.dumps(output, ensure_ascii=False, indent=2)

    # 如果指定了输出路径，直接写文件
    if len(argv) >= 3:
        with open(argv[2], "w", encoding="utf-8") as f:
            f.write(result)
        print(f"Saved to {argv[2]}")
    else:
        # 强制 UTF-8 输出到 stdout
        sys.stdout.reconfigure(encoding="utf-8")
        print(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main_fb6b990d(sys.argv))
