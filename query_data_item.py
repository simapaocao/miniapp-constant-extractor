#!/usr/bin/env python3
"""
根据 data_item 表的 id 查询源文件信息，打开源文件并复制值到剪贴板

用法:
    python query_data_item.py <data_item_id>
    python query_data_item.py 16981
    python query_data_item.py --db mydb 16981
    python query_data_item.py -H 192.168.1.100 -P 3306 -u root -p pass -d mydb 16981
"""
import sys
import os
import json
import argparse
import subprocess
from pathlib import Path

import pymysql


def load_db_config(cli_args: argparse.Namespace = None) -> dict:
    """从 config.json 或命令行参数加载数据库配置"""
    # 优先使用命令行参数
    if cli_args and cli_args.host:
        return {
            "host": cli_args.host,
            "port": cli_args.port,
            "user": cli_args.user,
            "password": cli_args.password,
            "db_name": cli_args.database,
            "charset": "utf8mb4",
        }

    script_dir = Path(__file__).resolve().parent
    config_path = script_dir.parent / "config.json"

    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    db_cfg = config.get("constant_db")
    if not db_cfg:
        raise ValueError("config.json 中缺少 constant_db 配置")

    # 命令行只指定了 --db 覆盖数据库名
    if cli_args and cli_args.database:
        db_cfg["db_name"] = cli_args.database

    return db_cfg


def copy_to_clipboard(text: str) -> bool:
    """复制文本到剪贴板 (Windows)"""
    try:
        # Windows: 使用 clip 命令
        process = subprocess.Popen(
            ["clip"],
            stdin=subprocess.PIPE,
            shell=True
        )
        process.communicate(text.encode("utf-8"))
        return True
    except Exception as e:
        print(f"[!] 复制到剪贴板失败: {e}")
        return False


def open_file_in_editor(file_path: str) -> bool:
    """在默认编辑器中打开文件"""
    try:
        # Windows: 使用 start 命令
        os.startfile(file_path)
        return True
    except Exception as e:
        print(f"[!] 打开文件失败: {e}")
        return False


def query_by_data_item_id(data_item_id: int, db_cfg: dict):
    """根据 data_item_id 查询并显示信息"""
    conn = pymysql.connect(
        host=str(db_cfg["host"]),
        port=int(db_cfg["port"]),
        user=str(db_cfg["user"]),
        password=str(db_cfg["password"]),
        database=str(db_cfg["db_name"]),
        charset=str(db_cfg.get("charset", "utf8mb4")),
        cursorclass=pymysql.cursors.DictCursor,
    )
    
    try:
        cursor = conn.cursor()
        
        # 查询 data_item 基本信息
        cursor.execute("""
            SELECT d.id, d.type_id, d.raw_value, d.hash_sha256, d.ref_count,
                   t.slug, t.category, t.risk_level, t.description
            FROM data_item d
            LEFT JOIN data_item_type t ON d.type_id = t.id
            WHERE d.id = %s
        """, (data_item_id,))
        
        data_item = cursor.fetchone()
        if not data_item:
            print(f"[!] 未找到 data_item_id = {data_item_id}")
            return
        
        # 查询关联的 miniapp 和源文件信息
        cursor.execute("""
            SELECT m.id as relation_id, m.source_file, m.source_snippet,
                   m.detector_source, ma.appid
            FROM miniapp_to_dataitem m
            JOIN miniapp_meta ma ON m.miniapp_id = ma.id
            WHERE m.data_item_id = %s
            LIMIT 10
        """, (data_item_id,))
        
        occurrences = cursor.fetchall()
        
        # 显示信息
        print("=" * 70)
        print(f"Data Item ID: {data_item['id']}")
        print(f"Type ID: {data_item['type_id']} ({data_item.get('slug', 'N/A')})")
        print(f"Category: {data_item.get('category', 'N/A')}")
        print(f"Risk Level: {data_item.get('risk_level', 'N/A')}")
        print(f"Description: {data_item.get('description', 'N/A')}")
        print(f"Ref Count: {data_item['ref_count']}")
        print("-" * 70)
        print(f"Raw Value: {data_item['raw_value']}")
        print("=" * 70)
        
        if occurrences:
            print(f"\n找到 {len(occurrences)} 个出现位置:\n")
            for i, occ in enumerate(occurrences, 1):
                print(f"[{i}] AppID: {occ['appid']}")
                print(f"    Source File: {occ['source_file']}")
                print(f"    Detector: {occ['detector_source']}")
                print(f"    Snippet: {occ['source_snippet'][:200] if occ['source_snippet'] else 'N/A'}...")
                print()
            
            # 复制 raw_value 到剪贴板
            raw_value = data_item['raw_value']
            if copy_to_clipboard(raw_value):
                print(f"✓ 已复制 raw_value 到剪贴板: {raw_value[:50]}...")
            
            # 打开第一个源文件
            first_file = occurrences[0]['source_file']
            if first_file and os.path.exists(first_file):
                print(f"\n正在打开文件: {first_file}")
                open_file_in_editor(first_file)
            else:
                print(f"\n[!] 源文件不存在或路径无效: {first_file}")
        else:
            print("\n[!] 未找到关联的出现记录")
            
            # 仍然复制 raw_value
            raw_value = data_item['raw_value']
            if copy_to_clipboard(raw_value):
                print(f"✓ 已复制 raw_value 到剪贴板: {raw_value[:50]}...")
    
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="根据 data_item_id 查询源文件信息",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python query_data_item.py 16981                    # 使用 config.json 配置
  python query_data_item.py --db mydb 16981          # 覆盖数据库名
  python query_data_item.py -H 127.0.0.1 -d mydb 123 # 完整指定连接参数
        """
    )
    parser.add_argument("data_item_id", type=int, help="data_item 表的 ID")
    parser.add_argument("-H", "--host", help="数据库主机地址")
    parser.add_argument("-P", "--port", type=int, default=3306, help="数据库端口 (默认 3306)")
    parser.add_argument("-u", "--user", default="root", help="数据库用户名 (默认 root)")
    parser.add_argument("-p", "--password", default="", help="数据库密码")
    parser.add_argument("-d", "--database", "--db", help="数据库名称")

    args = parser.parse_args()

    try:
        db_cfg = load_db_config(args)
        query_by_data_item_id(args.data_item_id, db_cfg)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        print("请使用 -H/-d 等参数指定数据库连接信息")
        sys.exit(1)
    except Exception as e:
        print(f"[!] 错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
