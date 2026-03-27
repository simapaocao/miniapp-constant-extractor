"""
Scanner Engine - 多进程扫描引擎 (UI 修复版)
Finder (生产者) -> Scanners (中间处理) -> Writer (最终消费者)
"""
import argparse
import hashlib
import json
import os
import queue
import signal
import sqlite3
import time
import traceback
import multiprocessing
import sys
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple
import pymysql

# 假设这些模块在你本地存在
from extract_js_consts import extract_from_js_file  # pylint: disable=import-error
from extract_json_consts import extract_from_json_file  # pylint: disable=import-error
from extract_wxml_consts import extract_from_wxml_file  # pylint: disable=import-error
from extract_wxs_consts import extract_from_wxs_file  # pylint: disable=import-error
from extract_wxss_consts import extract_from_wxss_file  # pylint: disable=import-error
from constants_filter import perform_constant_filtering  # pylint: disable=import-error
from constants_classifier import perform_constant_classifying  # pylint: disable=import-error
from constant_ids import SLUG_TO_DB, CTG_OTHERS, RISK_IGNORE  # pylint: disable=import-error


# ================= CONFIG LOADING =================
TASK_PATH: Optional[Path] = None
UNPACKED_PKG_PATH: Optional[Path] = None
DB_CONFIG: Dict[str, object] = {}
LOGDB_PATH: Optional[Path] = None
USE_SMART_FILTER: bool = False

# 哨兵常量
STOP_SENTINEL = "__STOP__"

# ================= UI / MONITORING SYSTEM =================

class StatusMonitor:
    def __init__(self):
        # 结构: { pkg_name: {'total': int, 'done': int, 'ts': float} }
        self.active_tasks = {}
        self.writer_backlog = 0
        self.total_processed_files = 0
        self.total_files_found = 0
        self.start_time = time.time()

    def process_messages(self, status_queue: multiprocessing.Queue):
        """处理消息队列中的状态更新"""
        while True:
            try:
                # 非阻塞获取消息
                msg = status_queue.get_nowait()
                msg_type = msg[0]

                if msg_type == 'INIT':
                    # ('INIT', pkg_name, total_files)
                    pkg_name, total = msg[1], msg[2]
                    # 使用当前时间戳，保证FIFO顺序
                    self.active_tasks[pkg_name] = {'total': total, 'done': 0, 'ts': time.time()}
                    self.total_files_found += total

                elif msg_type == 'PROGRESS':
                    # ('PROGRESS', pkg_name)
                    pkg_name = msg[1]
                    if pkg_name in self.active_tasks:
                        self.active_tasks[pkg_name]['done'] += 1
                        self.total_processed_files += 1

                elif msg_type == 'WRITER_STATUS':
                    # ('WRITER_STATUS', backlog_size)
                    self.writer_backlog = msg[1]
            
            except queue.Empty:
                break
    
    def cleanup_finished(self):
        """清理已完成的任务"""
        to_remove = []
        now = time.time()
        for pkg, data in self.active_tasks.items():
            if data['done'] >= data['total']:
                # 完成超过 3 秒则移除，以便腾出位置显示新的
                if now - data.get('finish_ts', now) > 3: 
                   to_remove.append(pkg)
                elif 'finish_ts' not in data:
                    data['finish_ts'] = now
        
        for pkg in to_remove:
            del self.active_tasks[pkg]

    def draw(self):
        """绘制控制台界面"""
        # 清屏 (ANSI escape code)
        sys.stdout.write("\033[H\033[J")
        
        elapsed = time.time() - self.start_time
        speed = self.total_processed_files / elapsed if elapsed > 0 else 0
        
        # 头部统计
        print(f"=== 扫描引擎监控 (Running: {elapsed:.1f}s) ===")
        print(f"总文件进度: {self.total_processed_files}/{self.total_files_found} | 速度: {speed:.1f} file/s | 写入堆积: {self.writer_backlog}")
        print("-" * 65)

        # 获取活跃任务列表
        tasks = list(self.active_tasks.items())
        
        # --- 关键修改：优化排序逻辑 ---
        # 我们希望能看到正在动的任务。
        # 优先级 1: 正在进行中 (0 < done < total)
        # 优先级 2: 等待中 (done == 0)
        # 优先级 3: 已完成 (done == total)
        def sort_key(item):
            data = item[1]
            if data['done'] >= data['total']:
                return 3  # 已完成放最后 (或者被cleanup清除)
            if data['done'] > 0:
                return 1  # 正在跑的放最前！
            return 2      # 还没开始的放中间
            
        tasks.sort(key=sort_key)

        # 只显示前15个
        display_limit = 15
        count = 0
        
        for pkg, data in tasks:
            if count >= display_limit:
                break
            
            total = data['total']
            done = data['done']
            percent = (done / total * 100) if total > 0 else 0
            
            # 进度条绘制
            bar_len = 25
            filled_len = int(bar_len * done // total) if total > 0 else 0
            # 确保不会溢出
            filled_len = min(filled_len, bar_len)
            
            bar = '█' * filled_len + '-' * (bar_len - filled_len)
            
            if done >= total:
                status_str = "DONE"
            elif done > 0:
                status_str = "RUN"
            else:
                status_str = "WAIT"

            print(f"[{status_str:^4}] {pkg:<32} |{bar}| {percent:>3.0f}% ({done}/{total})")
            count += 1
            
        if len(tasks) == 0:
            print("等待任务或所有任务已完成...")
        elif len(tasks) > display_limit:
            print(f"... 还有 {len(tasks) - display_limit} 个后台任务正在运行")

        sys.stdout.flush()

def monitor_process_loop(status_queue: multiprocessing.Queue, stop_event: multiprocessing.Event):
    """监控进程主循环"""
    # 忽略子进程中的 SIGINT
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    monitor = StatusMonitor()
    
    # 初始等待，防止一开始就刷屏
    time.sleep(1)
    
    # 记录完成状态的持续时间
    all_done_since = None
    
    while not stop_event.is_set():
        monitor.process_messages(status_queue)
        monitor.cleanup_finished()
        monitor.draw()
        
        # 检测是否所有任务都完成了
        all_done = (monitor.total_files_found > 0 and 
                    monitor.total_processed_files >= monitor.total_files_found)
        
        if all_done:
            if all_done_since is None:
                all_done_since = time.time()
            elif time.time() - all_done_since > 5:
                # 完成状态持续 5 秒，停止刷新
                print("\n\n=== 所有文件处理完成，Monitor 退出 ===")
                sys.stdout.flush()
                return  # 直接退出
        else:
            all_done_since = None
        
        # 1秒刷新频率
        for _ in range(10):
            if stop_event.is_set():
                return
            time.sleep(0.1)
    
    print("\n监控进程收到停止信号，退出。")
    
    # 最后绘制一次
    monitor.process_messages(status_queue)
    monitor.draw()
    print("\n监控进程已退出。")


# ================= SQLITE CACHE MANAGER =================
def init_sqlite_log2db(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scanned_files (
                file_path TEXT PRIMARY KEY,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def load_scanned_log2db(db_path: Path) -> Set[str]:
    if not db_path.exists():
        return set()

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        cur.execute("SELECT file_path FROM scanned_files")
        rows = cur.fetchall()
        return {row[0] for row in rows}
    finally:
        conn.close()


def mark_sqlite_scanned(conn: sqlite3.Connection, wxapkg_name: str) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO scanned_files(file_path, scanned_at) VALUES (?, CURRENT_TIMESTAMP)",
        (wxapkg_name,),
    )


# ================= STAGE 3: CONSUMER (DB WRITER) =================
TASK_MINIAPP_META = "MINIAPP_META"

def db_writer_process(
    result_queue: multiprocessing.Queue,
    status_queue: multiprocessing.Queue,
    db_config: Dict[str, object],
    max_retries: int = 3
) -> None:
    # 忽略子进程中的 SIGINT
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    conn = None
    cursor = None

    def connect_db() -> Tuple[pymysql.Connection, pymysql.cursors.Cursor]:
        for attempt in range(max_retries):
            try:
                _conn = pymysql.connect(
                    host=str(db_config["host"]),
                    port=int(db_config["port"]),
                    user=str(db_config["user"]),
                    password=str(db_config["password"]),
                    database=str(db_config["db_name"]),
                    charset=str(db_config.get("charset", "utf8mb4")),
                    autocommit=False,
                    connect_timeout=10,
                )
                _cursor = _conn.cursor()
                return _conn, _cursor
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        return None, None # 让后面处理

    try:
        conn, cursor = connect_db()
        if not conn:
            return
    except Exception:
        return

    appid_cache: Dict[str, int] = {}
    buffer: List[Tuple] = []
    last_flush_time = time.time()
    batch_size = 1000

    sql_miniapp_meta = (
        "INSERT INTO miniapp_meta (appid) VALUES (%s) "
        "ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP"
    )

    try:
        while True:
            # 报告队列大小给 Monitor
            if time.time() % 2 < 0.2: # 降低频率
                try:
                    qsize = result_queue.qsize()
                    status_queue.put(('WRITER_STATUS', qsize))
                except NotImplementedError:
                    pass

            try:
                item = result_queue.get(timeout=0.5)
            except queue.Empty:
                if buffer and time.time() - last_flush_time > 5:
                    _flush_data_items(cursor, conn, buffer, appid_cache)
                    buffer.clear()
                    last_flush_time = time.time()
                continue

            if item == STOP_SENTINEL:
                break

            if isinstance(item, tuple) and len(item) >= 2 and item[0] == TASK_MINIAPP_META:
                appid = item[1]
                try:
                    cursor.execute(sql_miniapp_meta, (appid,))
                    conn.commit()
                    cursor.execute("SELECT id FROM miniapp_meta WHERE appid = %s", (appid,))
                    row = cursor.fetchone()
                    if row:
                        appid_cache[appid] = row[0]
                except Exception:
                    conn.rollback()
            else:
                buffer.append(item)
                now = time.time()
                if len(buffer) >= batch_size or (buffer and now - last_flush_time > 5):
                    _flush_data_items(cursor, conn, buffer, appid_cache)
                    buffer.clear()
                    last_flush_time = now

        if buffer:
            _flush_data_items(cursor, conn, buffer, appid_cache)

    finally:
        try:
            if cursor: cursor.close()
            if conn: conn.close()
        except Exception:
            pass


def _flush_data_items(cursor, conn, buffer, appid_cache):
    if not buffer:
        return
    try:
        data_items = []
        hash_to_meta = {}

        for appid, _kind_id, slug_id, _risk_level, content, source_file, detector_source, source_snippet in buffer:
            type_id = slug_id
            raw_value = content[:1000] if len(content) > 1000 else content
            hash_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()

            data_items.append((type_id, raw_value, hash_sha256))
            if hash_sha256 not in hash_to_meta:
                hash_to_meta[hash_sha256] = []
            hash_to_meta[hash_sha256].append((appid, source_file, detector_source, source_snippet))

        sql_data_item = (
            "INSERT INTO data_item (type_id, raw_value, hash_sha256) "
            "VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE ref_count = ref_count + 1"
        )
        cursor.executemany(sql_data_item, data_items)
        conn.commit()

        hashes = list(hash_to_meta.keys())
        if not hashes:
            return

        placeholders = ",".join(["%s"] * len(hashes))
        cursor.execute(
            f"SELECT id, hash_sha256 FROM data_item WHERE hash_sha256 IN ({placeholders})",
            hashes,
        )
        hash_to_id = {row[1]: row[0] for row in cursor.fetchall()}

        relations = []
        for hash_val, meta_list in hash_to_meta.items():
            data_item_id = hash_to_id.get(hash_val)
            if not data_item_id:
                continue
            for appid, source_file, detector_source, source_snippet in meta_list:
                miniapp_id = appid_cache.get(appid)
                if miniapp_id:
                    snippet = source_snippet[:65000] if source_snippet else ""
                    relations.append((miniapp_id, data_item_id, source_file, detector_source, snippet))

        if relations:
            sql_relation = (
                "INSERT INTO miniapp_to_dataitem "
                "(miniapp_id, data_item_id, source_file, detector_source, source_snippet) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON DUPLICATE KEY UPDATE id = id"
            )
            cursor.executemany(sql_relation, relations)
            conn.commit()

    except Exception:
        conn.rollback()


# ================= STAGE 2: File Scanner (SCANNER WORKER) =================
def file_scanner_process(
    file_queue,  # JoinableQueue
    result_queue: multiprocessing.Queue,
    status_queue: multiprocessing.Queue,
    source_root: Path,
    use_smart_filter: bool = False,
    stop_event: multiprocessing.Event = None,
) -> None:
    # 忽略子进程中的 SIGINT，让主进程处理
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    while True:
        try:
            # 使用超时的 get，这样可以定期检查停止信号
            task = file_queue.get(timeout=1.0)
        except queue.Empty:
            # 检查是否应该退出（队列为空且收到停止信号）
            if stop_event and stop_event.is_set():
                return
            continue

        # 收到停止哨兵
        if task is None:
            file_queue.task_done()
            return

        appid = None
        try:
            appid, rel_path, file_type = task
            full_path = source_root / rel_path

            if full_path.exists():
                findings = perform_scan(str(full_path), file_type, use_smart_filter)
                for item in findings:
                    try:
                        result_queue.put((appid,) + item, timeout=30)
                    except Exception:
                        pass  # 队列满，跳过

        except Exception:
            pass
        finally:
            # 汇报进度：非常重要，放在finally确保即使扫描出错也会更新进度
            if appid:
                try:
                    status_queue.put_nowait(('PROGRESS', appid))
                except Exception:
                    pass

            # task_done 必须在 finally 中调用，确保即使出错也会标记任务完成
            try:
                file_queue.task_done()
            except Exception:
                pass


def perform_scan(
    file_path: str, file_ext: str, use_smart_filter: bool = True, timeout_seconds: int = 360
) -> List[Tuple[int, int, int, str, str, str, str]]:
    """Scan logic with timeout protection."""
    import concurrent.futures
    
    def _do_extract():
        if file_ext == "js":
            return extract_from_js_file(file_path)
        elif file_ext == "json":
            return extract_from_json_file(file_path)
        elif file_ext == "wxml":
            return extract_from_wxml_file(file_path)
        elif file_ext == "wxs":
            return extract_from_wxs_file(file_path)
        elif file_ext == "wxss":
            return extract_from_wxss_file(file_path)
        return None
    
    res = None
    try:
        # 使用线程池执行提取，带超时保护
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_do_extract)
            res = future.result(timeout=timeout_seconds)
    except concurrent.futures.TimeoutError:
        # 超时，跳过此文件
        return []
    except Exception:
        return []

    if not res:
        return []

    filtered = perform_constant_filtering(
        res["statements"], res["constants"], use_smart_filter=use_smart_filter
    )
    statements = filtered["statements"]
    
    classified = perform_constant_classifying(statements, filtered["constants"])
    
    db_results = []
    for (slug_id, content, src, source_snippet) in classified:
        kind_id, risk_level = SLUG_TO_DB.get(slug_id, (CTG_OTHERS, RISK_IGNORE))
        db_results.append((kind_id, slug_id, risk_level, content, file_path, src, source_snippet))
    
    return db_results


# ================= STAGE 1: File Finder (FILE FINDER) =================
SCANNING_EXCLUDED_FOLDERS: Set[str] = {
    "@babel", "miniprogram_npm", "npm", "unpackage",
    "node_modules", "uni_modules", "external", "uview-ui",
    "third_party", "third-party", "vendor",
    "dist", "build", "out",
    "static", "assets", "images", "img", "fonts", "icons",
    "media", "audio", "video",
}
SCAN_EXTS: Set[str] = {"js", "json", "wxml", "wxs", "wxss"}


def file_finder_process(
    file_queue,
    result_queue: multiprocessing.Queue,
    status_queue: multiprocessing.Queue,
    unpacked_dir: Path,
    num_workers: int,
    sqlite_path: Path,
    stop_gathering_event: multiprocessing.Event,
    pkg_done_queue: multiprocessing.Queue,
) -> None:
    # 读历史
    scanned_history = load_scanned_log2db(sqlite_path)

    try:
        packages = sorted(
            [d for d in os.listdir(unpacked_dir) if (unpacked_dir / d).is_dir()]
        )
    except FileNotFoundError:
        packages = []

    completed_packages: List[str] = []

    try:
        for pkg_name in packages:
            if stop_gathering_event.is_set():
                break

            if pkg_name in scanned_history:
                continue

            pkg_path = unpacked_dir / pkg_name
            
            # 先收集该包的所有待扫描文件
            pkg_files_buffer = []
            
            for root, dirs, files in os.walk(pkg_path):
                dirs[:] = [d for d in dirs if d not in SCANNING_EXCLUDED_FOLDERS]
                root_path = Path(root)
                for filename in files:
                    ext = Path(filename).suffix.lower().lstrip(".")
                    if ext not in SCAN_EXTS:
                        continue
                    if ext == "js" and "game" in filename.lower():
                        continue
                    
                    full_path = root_path / filename
                    rel_path = str(full_path.relative_to(unpacked_dir))
                    pkg_files_buffer.append((pkg_name, rel_path, ext))

            total_files = len(pkg_files_buffer)
            
            # 只有当包里有有效文件时才处理
            if total_files > 0:
                # 1. 注册 MINIAPP_META 任务
                result_queue.put(("MINIAPP_META", pkg_name))
                
                # 2. 通知 Monitor 注册新任务 (total_files)
                status_queue.put(('INIT', pkg_name, total_files))

                # 3. 将文件推入处理队列（带超时，避免永久阻塞）
                for item in pkg_files_buffer:
                    if stop_gathering_event.is_set():
                        break
                    try:
                        file_queue.put(item, timeout=60)  # 最多等60秒
                    except Exception:
                        # 队列满且超时，跳过这个文件
                        pass
                
                # 4. 记录将要完成的包
                completed_packages.append(pkg_name)
            else:
                # 空包也算处理完，记录一下防止重复扫
                completed_packages.append(pkg_name)

    finally:
        for pkg_name in completed_packages:
            pkg_done_queue.put(pkg_name)
        pkg_done_queue.put(None)


# ================= DB INIT =================
def init_constant_db(db_config: Dict[str, object]) -> None:
    conn = pymysql.connect(
        host=str(db_config["host"]),
        port=int(db_config["port"]),
        user=str(db_config["user"]),
        password=str(db_config["password"]),
        charset=str(db_config.get("charset", "utf8mb4")),
        autocommit=True,
    )
    try:
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_config['db_name']}")
    finally:
        conn.close()


# ================= CONFIGURATION =================
def initialize_config(cli_task_path: Optional[str], cli_source_path: Optional[str] = None) -> None:
    global TASK_PATH, UNPACKED_PKG_PATH, DB_CONFIG, LOGDB_PATH, USE_SMART_FILTER

    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    config_path = project_root / "config.json"

    config: Dict[str, object] = {}
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

    raw_value = config.get("task_workspace_name")
    if cli_task_path:
        task_dir_name = cli_task_path
    elif isinstance(raw_value, str) and raw_value.strip():
        task_dir_name = raw_value
    else:
        # 输入还是保留，仅在初始化时出现一次
        task_dir_name = input("Enter task folder name: ").strip()

    TASK_PATH = project_root / task_dir_name
    TASK_PATH.mkdir(parents=True, exist_ok=True)

    unpacked_dir = config.get("pkg_unpacked_dir", "wxpkg-unpacked")
    if not isinstance(unpacked_dir, str) or not unpacked_dir:
        unpacked_dir = "wxpkg-unpacked"

    DB_CONFIG = config.get("constant_db") # type: ignore
    USE_SMART_FILTER = bool(config.get("use_smart_filter", False))

    if cli_source_path:
        UNPACKED_PKG_PATH = Path(cli_source_path)
    else:
        UNPACKED_PKG_PATH = TASK_PATH / unpacked_dir
    
    LOGDB_PATH = TASK_PATH / "scanned_wxpkg.db"

    init_sqlite_log2db(LOGDB_PATH)
    init_constant_db(DB_CONFIG)


# ================= MAIN CONTROLLER =================
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--taskpath", default=None)
    parser.add_argument("--source", default=None)
    parser.add_argument("--workers", "-w", type=int, default=None)
    args = parser.parse_args()

    initialize_config(args.taskpath, args.source)

    if args.workers is not None and args.workers > 0:
        num_scanners = args.workers
    else:
        num_scanners = max(1, multiprocessing.cpu_count() // 2)

    # 队列定义
    file_queue = multiprocessing.JoinableQueue(maxsize=10000)
    result_queue: multiprocessing.Queue = multiprocessing.Queue(maxsize=10000)
    status_queue: multiprocessing.Queue = multiprocessing.Queue()
    pkg_done_queue: multiprocessing.Queue = multiprocessing.Queue()

    stop_gathering_event = multiprocessing.Event()

    def signal_handler(_sig, _frame):
        stop_gathering_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    # 1. 启动 Monitor 进程
    monitor_stop_event = multiprocessing.Event()
    monitor = multiprocessing.Process(
        target=monitor_process_loop,
        args=(status_queue, monitor_stop_event)
    )
    monitor.start()

    # 2. 启动 Writer
    writer = multiprocessing.Process(
        target=db_writer_process, 
        args=(result_queue, status_queue, DB_CONFIG)
    )
    writer.start()

    # 3. 启动 Scanners
    scanners = []
    for _ in range(num_scanners):
        p = multiprocessing.Process(
            target=file_scanner_process,
            args=(file_queue, result_queue, status_queue, UNPACKED_PKG_PATH, USE_SMART_FILTER, stop_gathering_event),
        )
        p.start()
        scanners.append(p)

    # 4. 启动 Finder
    finder = multiprocessing.Process(
        target=file_finder_process,
        args=(
            file_queue,
            result_queue,
            status_queue,
            UNPACKED_PKG_PATH,
            num_scanners,
            LOGDB_PATH,
            stop_gathering_event,
            pkg_done_queue,
        ),
    )
    finder.start()

    # 不在这里等待 Finder，让它在后台运行
    # 主进程等待 Monitor 退出（Monitor 会在检测到所有文件处理完成后自动退出）
    print("扫描进行中，等待 Monitor 检测完成...")
    monitor.join()  # Monitor 会在 total_processed >= total_found 后自动退出
    print("Monitor 已退出，开始清理...")

    # 获取完成包名（Finder 应该已经完成了）
    completed_packages: List[str] = []
    
    # 先检查 Finder 是否还在运行
    if finder.is_alive():
        finder.join(timeout=10)
        if finder.is_alive():
            print("警告: Finder 仍在运行，强制终止")
            finder.terminate()
    
    # 获取完成的包名
    while True:
        try:
            pkg = pkg_done_queue.get_nowait()
            if pkg is None:
                break
            completed_packages.append(str(pkg))
        except queue.Empty:
            break
    print(f"完成包数量: {len(completed_packages)}")

    # 等待处理完成 - 不使用 file_queue.join()，因为它可能永远阻塞
    # 改用简单的等待策略：等待一小段时间让队列清空
    import time as time_module
    
    print("\n等待处理完成...")
    time_module.sleep(5)  # 给 Scanner 一点时间完成最后的任务
    
    # 先停止 Monitor
    monitor_stop_event.set()
    monitor.join(timeout=3)
    if monitor.is_alive():
        monitor.terminate()
    
    print("正在清理进程...")

    # 设置停止事件，让 Scanner 退出循环
    stop_gathering_event.set()

    # 发送停止信号给所有 Scanner（双重保险）
    for _ in scanners:
        try:
            file_queue.put_nowait(None)
        except Exception:
            pass

    # 等待 Scanners 退出
    for p in scanners:
        p.join(timeout=5)
        if p.is_alive():
            p.terminate()

    # 记录扫描历史
    if completed_packages:
        conn = sqlite3.connect(str(LOGDB_PATH))
        try:
            for pkg_name in completed_packages:
                mark_sqlite_scanned(conn, pkg_name)
            conn.commit()
        finally:
            conn.close()

    # 停止 Writer
    result_queue.put(STOP_SENTINEL)
    writer.join(timeout=30)
    if writer.is_alive():
        writer.terminate()
    
    print("扫描完成!")

if __name__ == "__main__":
    main()
