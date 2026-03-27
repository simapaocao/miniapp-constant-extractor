#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
import pymysql
from pymysql import err as pymysql_err
from constants_type2id import assign_types_with_ids

# ================= CONFIGURATION & PATHS =================
TASK_PATH: Optional[Path] = None
DB_CONFIG: Dict[str, Any] = {}
DATA_TYPES_JSON_PATH: Optional[Path] = None
DATABASE_SCHEMA_PATH: Optional[Path] = None


# ================= UTILS =================
def _load_json(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            raise ValueError(f"{path} must be a JSON object at top level.")
        return obj
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e


def initialize_config(cli_task_path: Optional[str]) -> None:
    """
    Load database configuration from config.json and resolve paths.
    Priority: CLI Args > config.json > prompt.
    Returns: DB_CONFIG dict.
    """
    global TASK_PATH, DB_CONFIG, DATA_TYPES_JSON_PATH, DATABASE_SCHEMA_PATH

    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    config_path = project_root / "config.json"

    config: Dict[str, Any] = {}
    if config_path.exists():
        config = _load_json(config_path)

    # Resolve Task Path (kept for consistency with the rest of the project)
    raw_value = config.get("task_workspace_name")
    if cli_task_path:
        task_dir_name = cli_task_path
    elif isinstance(raw_value, str) and raw_value.strip():
        task_dir_name = raw_value
    else:
        task_dir_name = input("Enter task folder name: ").strip()

    TASK_PATH = project_root / task_dir_name
    TASK_PATH.mkdir(parents=True, exist_ok=True)

    db_cfg = config.get("constant_db")
    if not isinstance(db_cfg, dict):
        raise ValueError(
            "config.json must contain an object 'constant_db' (see provided config.json)."
        )
    DB_CONFIG = db_cfg

    # These files are expected next to this script (same as your original intent)
    DATA_TYPES_JSON_PATH = script_dir / "constant_types.json"
    DATABASE_SCHEMA_PATH = script_dir / "database_schema.sql"

    if not DATA_TYPES_JSON_PATH.exists():
        raise FileNotFoundError(f"Data Types file not found: {DATA_TYPES_JSON_PATH}")

    if not DATABASE_SCHEMA_PATH.exists():
        raise FileNotFoundError(f"SQL template not found: {DATABASE_SCHEMA_PATH}")


def load_datatypes() -> Dict[str, Any]:
    """Load the simplified constant types definition."""
    assert DATA_TYPES_JSON_PATH is not None
    return _load_json(DATA_TYPES_JSON_PATH)


# ================= EXPANSION LOGIC =================
def expand_datatypes(simplified_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Expands the nested 2-level structure (Groups -> Items) into
    flat records for the 'data_item_type' table.
    """
    flat_records: List[Dict[str, Any]] = []
    global_id = 1

    # 支持两种字段名: groups 或 datatype_categories
    groups = simplified_data.get("groups") or simplified_data.get("datatype_categories", [])
    if not isinstance(groups, list):
        raise ValueError("constant_types.json: 'groups' or 'datatype_categories' must be a list")

    for group in groups:
        if not isinstance(group, dict):
            continue
        group_category = group.get("category", "other")
        default_risk = group.get("default_risk", 0)
        start_index = group.get("start_index", global_id)  # 使用 start_index

        items = group.get("items", [])
        if not isinstance(items, list):
            continue

        item_index = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            if "slug" not in item:
                raise ValueError("constant_types.json: each item must include 'slug'")

            # Resolve Risk Level (Item specific > Group default)
            risk = item.get("risk", default_risk)

            # Resolve Category (Item specific > Group default)
            category = item.get("category", group_category)

            item_index += 1  # 先自增，ID 从 start_index + 1 开始
            record = {
                "id": start_index + item_index,  # 使用 start_index + 偏移 (1101, 1102, ...)
                "slug": item["slug"],
                "category": category,
                "risk_level": risk,
                "description": item.get("desc", ""),
            }
            flat_records.append(record)
            global_id = max(global_id, start_index + item_index)

    return flat_records


def generate_insert_sql(table_name: str, data_list: List[Dict[str, Any]]) -> str:
    """
    Generates a single bulk INSERT statement.
    Uses ON DUPLICATE KEY UPDATE so the script is re-runnable.
    """
    if not data_list:
        return ""

    # Union of columns across all rows (safer than only using the first row)
    columns = sorted({k for row in data_list for k in row.keys()})
    col_names = ", ".join([f"`{c}`" for c in columns])

    values_list: List[str] = []
    for item in data_list:
        row_vals: List[str] = []
        for col in columns:
            val = item.get(col)
            if val is None:
                row_vals.append("NULL")
            elif isinstance(val, str):
                safe_val = val.replace("\\", "\\\\").replace("'", "''")
                row_vals.append(f"'{safe_val}'")
            elif isinstance(val, bool):
                row_vals.append("1" if val else "0")
            else:
                row_vals.append(str(val))
        values_list.append(f"({', '.join(row_vals)})")

    # Make it idempotent (requires PRIMARY KEY/UNIQUE)
    update_expr = ", ".join([f"`{c}`=VALUES(`{c}`)" for c in columns if c != "id"])
    sql = (
        f"INSERT INTO `{table_name}` ({col_names}) VALUES\n"
        + ",\n".join(values_list)
        + (f"\nON DUPLICATE KEY UPDATE {update_expr};" if update_expr else ";")
    )
    return sql


# ================= SQL SPLITTING =================
def split_sql_statements(sql: str) -> List[str]:
    """
    Split SQL script into statements by ';' while respecting:
    - single quotes, double quotes, backticks
    - line comments: -- ... and # ...
    - block comments: /* ... */
    """
    stmts: List[str] = []
    buf: List[str] = []

    in_single = False
    in_double = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False

    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        # End line comment
        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        # End block comment
        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        # Start comments (only if not in quotes)
        if not (in_single or in_double or in_backtick):
            if ch == "-" and nxt == "-":
                # treat '-- ' as comment start (SQL standard)
                # also accept '--\n'
                third = sql[i + 2] if i + 2 < n else ""
                if third in (" ", "\t", "\r", "\n"):
                    in_line_comment = True
                    buf.append(ch)
                    buf.append(nxt)
                    i += 2
                    continue
            if ch == "#":
                in_line_comment = True
                buf.append(ch)
                i += 1
                continue
            if ch == "/" and nxt == "*":
                in_block_comment = True
                buf.append(ch)
                buf.append(nxt)
                i += 2
                continue

        # Toggle quote states (handle escapes for ' and ")
        if not (in_double or in_backtick) and ch == "'":
            # if escaped quote inside single string, keep it
            if in_single and nxt == "'":  # SQL '' escape
                buf.append(ch)
                buf.append(nxt)
                i += 2
                continue
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue

        if not (in_single or in_backtick) and ch == '"':
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if not (in_single or in_double) and ch == "`":
            in_backtick = not in_backtick
            buf.append(ch)
            i += 1
            continue

        # Statement terminator
        if ch == ";" and not (in_single or in_double or in_backtick):
            stmt = "".join(buf).strip()
            if stmt:
                stmts.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)

    return stmts


# ================= DATABASE EXECUTION =================
def execute_script(sql_script: str, create_db: bool = True) -> None:
    """Connect to MySQL and execute the generated SQL script."""
    global DB_CONFIG
    db_config = DB_CONFIG
    host = str(db_config["host"])
    port = int(db_config.get("port", 3306))
    user = str(db_config["user"])
    password = str(db_config["password"])
    charset = str(db_config.get("charset", "utf8mb4"))
    db_name = str(db_config["db_name"])

    print(f"🔌 Connecting to {host}:{port} as {user}...")

    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        charset=charset,
        autocommit=False,
    )

    try:
        cursor = conn.cursor()

        if create_db:
            print(f"🔨 Creating database `{db_name}` if not exists...")
            try:
                cursor.execute(
                    f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET {charset}"
                )
            except pymysql_err.OperationalError as e:
                # 1044: Access denied to database
                if e.args and int(e.args[0]) == 1044:
                    print(
                        f"⚠️  No privilege to CREATE DATABASE as {user}. "
                        f"Will try to use existing `{db_name}` instead."
                    )
                else:
                    raise

        # Use database (will fail if it doesn't exist)
        try:
            cursor.execute(f"USE `{db_name}`")
        except pymysql_err.OperationalError as e:
            if e.args and int(e.args[0]) == 1049:  # Unknown database
                raise RuntimeError(
                    f"Database `{db_name}` does not exist, and the current user "
                    f"does not have privileges to create it. Create it with a privileged "
                    f"account and grant permissions, then rerun."
                ) from e
            raise

        print("🚀 Executing schema statements...")
        for stmt in split_sql_statements(sql_script):
            s = stmt.strip()
            if not s:
                continue
            cursor.execute(s)

        conn.commit()
        print("✅ Database initialized successfully!")
    except Exception as e:
        conn.rollback()
        raise
    finally:
        conn.close()


# ================= MAIN =================
def main() -> None:
    """
    Initialize database tables and generate some configuration files
    """
    parser = argparse.ArgumentParser(description="MiniApp Database Initializer")
    parser.add_argument(
        "--taskpath", help="Task folder name (e.g. test-workspace)", default=None
    )
    args = parser.parse_args()

    # 1) Load config + paths
    initialize_config(args.taskpath)

    # 2) Load type definitions
    data_type = load_datatypes()

    # 3) Expand structures
    assert DATA_TYPES_JSON_PATH is not None
    print(f"🔹 Expanding types from {DATA_TYPES_JSON_PATH.name}...")
    expanded_types = expand_datatypes(data_type)
    attribute_defs = data_type.get("attribute_defs", [])
    if not isinstance(attribute_defs, list):
        attribute_defs = []

    # 4) Generate SQL inserts
    print("🔹 Generating INSERT statements...")
    sql_insert_types = generate_insert_sql("data_item_type", expanded_types)
    sql_insert_attrs = generate_insert_sql("attribute_def", attribute_defs)

    # 5) Load schema template and replace placeholders
    assert DATABASE_SCHEMA_PATH is not None
    full_sql = DATABASE_SCHEMA_PATH.read_text(encoding="utf-8")

    full_sql = full_sql.replace("-- {{ INSERT_DATA_ITEM_TYPE }}", sql_insert_types)
    full_sql = full_sql.replace("-- {{ INSERT_ATTRIBUTE_DEF }}", sql_insert_attrs)

    # 6) Execute against DB
    execute_script(full_sql)

    # 7) Generate configuration file for constant classifier
    assign_types_with_ids("constant_types.json", "constant_ids.py")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"❌ init_database failed: {exc}", file=sys.stderr)
        sys.exit(1)
