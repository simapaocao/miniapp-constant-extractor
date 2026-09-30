"""
Scanner Engine - 多进程扫描引擎

拓扑：
    Finder (生产者) -> file_queue -> Scanners (中间处理, 每个 Scanner 自带一个提取沙箱子进程)
                                            -> result_queue -> Writer (最终消费者) -> MySQL
    主进程：读 control_queue / event_queue / ack_queue，维护 RunLedger，
            把"包已完成"写进 sqlite（只有数据真正提交进库之后才会写）。

设计要点（见修复计划 2.1 - 2.8）：
- 所有队列消息都带标签，不再靠"第一个元素是不是 MINIAPP_META"来区分类型。
- 单文件超时通过"每个 worker 一个长驻提取沙箱子进程 + 私有 Pipe"实现，
  worker 以 0.5 秒为间隔 poll，并每轮检查 stop_event；超时/崩溃只杀沙箱，不杀 worker。
- 主进程只在 worker 进程本身退出、且满足崩溃判定时才算崩溃并补位。
- 提取器 / 过滤器 / 分类器 / constant_ids 全部在 perform_scan 内部延迟 import，
  import scanner_engine 时不会加载它们。
"""

import argparse
import hashlib
import json
import os
import queue
import signal
import sqlite3
import sys
import time
import multiprocessing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import pymysql


# ================= 模块常量 =================
MAX_APPID_LEN = 32                 # miniapp_meta.appid 是 VARCHAR(32)
MAX_HTML_BYTES = 2 * 1024 * 1024   # 超过 2MB 的 html 不扫
DEFAULT_FILE_TIMEOUT = 360         # 单文件超时秒数（--file-timeout）
DEFAULT_BATCH_SIZE = 1000          # Writer 每批 DATA 条数
DEFAULT_BATCH_INTERVAL = 2.0       # Writer 最长攒批时间（秒）
FILE_DONE_FLUSH_DELAY = 2.0        # 收到 FILE_DONE 后最多等多久必须 flush
MAX_WORKER_RESTARTS = 20           # Scanner 崩溃补位上限
WORKER_STALL_GRACE = 120           # 同一文件停留超过 file_timeout + 该值只告警
FINDER_JOIN_TIMEOUT = 30           # 收尾时 join Finder 的超时
SCANNER_EXIT_GRACE = 30            # 收尾时 join Scanner 的额外超时
MONITOR_JOIN_TIMEOUT = 5           # 收尾时 join Monitor 的超时
WRITER_DRAIN_BASE_TIMEOUT = 60     # 收尾时等 Writer 排空的基础超时
WRITER_DRAIN_MAX_TIMEOUT = 600     # 收尾时等 Writer 排空的上限
QUEUE_MAXSIZE = 10000
EXIT_INTERRUPTED = 1
EXIT_FORCED = 130

# 文件级状态：文件本身的问题，包可以标记完成，scan_failures.kind = 'file'
STATUS_OK = "ok"
STATUS_EMPTY = "empty"
STATUS_TIMEOUT = "timeout"
STATUS_SKIPPED_TOO_LARGE = "skipped_too_large"
STATUS_MISSING = "missing"
STATUS_SANDBOX_CRASH = "error:sandbox_crash"

# 基础设施类状态：包不能标记完成，下次重扫，scan_failures.kind = 'infra'
STATUS_RESULT_QUEUE_FULL = "error:result_queue_full"
STATUS_WORKER_CRASH = "error:worker_crash"
STATUS_COMMIT_FAILED = "error:commit_failed"
STATUS_MINIAPP_META_FAILED = "error:miniapp_meta_failed"
STATUS_WRITER_DEAD = "error:writer_dead"
STATUS_ABORTED = "aborted"

INFRA_STATUSES = frozenset({
    STATUS_RESULT_QUEUE_FULL,
    STATUS_WORKER_CRASH,
    STATUS_COMMIT_FAILED,
    STATUS_MINIAPP_META_FAILED,
    STATUS_WRITER_DEAD,
    STATUS_ABORTED,
})

# 文件级但不"干净"的状态（要写 scan_failures，kind='file'）
FILE_FAILURE_STATUSES = frozenset({
    STATUS_TIMEOUT,
    STATUS_SKIPPED_TOO_LARGE,
    STATUS_MISSING,
    STATUS_SANDBOX_CRASH,
})


def is_infra_status(status: str) -> bool:
    """基础设施类状态（包不能标记完成）。"""
    return status in INFRA_STATUSES


def is_pkg_completable_status(status: str) -> bool:
    """文件级状态（包可以标记完成）。"""
    return not is_infra_status(status)


def is_worker_crash(
    stop_set: bool,
    shutting_down: bool,
    got_worker_exit: bool,
    exitcode: Optional[int],
) -> bool:
    """Scanner worker 崩溃判定（纯函数，方便单测）。

    必须同时满足：没有收到停止信号、还没进入收尾阶段、没有收到该 worker 的
    WORKER_EXIT、且进程退出码不是 0。收尾时 worker 正常退出是预期行为。
    """
    if stop_set or shutting_down or got_worker_exit:
        return False
    if exitcode is None:
        return False
    return exitcode != 0


def _ignore_signals() -> None:
    """子进程入口第一件事：忽略中断信号（Windows 下 Ctrl+C 会发给整个进程组）。"""
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        pass
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, signal.SIG_IGN)
        except (ValueError, OSError):
            pass


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ================= UI / MONITORING SYSTEM =================

class StatusMonitor:
    def __init__(self) -> None:
        # 结构: { pkg_name: {'total': int, 'done': int, 'ts': float} }
        self.active_tasks: Dict[str, Dict[str, float]] = {}
        self.writer_backlog = 0
        self.total_processed_files = 0
        self.total_files_found = 0
        self.start_time = time.time()

    def process_messages(self, status_queue: multiprocessing.Queue) -> None:
        """处理消息队列中的状态更新（只用于显示，允许丢消息）。"""
        while True:
            try:
                msg = status_queue.get_nowait()
            except (queue.Empty, OSError, EOFError, ValueError):
                break
            try:
                msg_type = msg[0]
            except (TypeError, IndexError):
                continue

            if msg_type == "INIT":
                # ('INIT', pkg_name, total_files)
                pkg_name, total = msg[1], msg[2]
                self.active_tasks[pkg_name] = {
                    "total": total, "done": 0, "ts": time.time(),
                }
                self.total_files_found += total
            elif msg_type == "PROGRESS":
                pkg_name = msg[1]
                if pkg_name in self.active_tasks:
                    self.active_tasks[pkg_name]["done"] += 1
                self.total_processed_files += 1
            elif msg_type == "WRITER_STATUS":
                self.writer_backlog = msg[1]

    def cleanup_finished(self) -> None:
        """清理已完成的任务。"""
        to_remove = []
        now = time.time()
        for pkg, data in self.active_tasks.items():
            if data["done"] >= data["total"]:
                if now - data.get("finish_ts", now) > 3:
                    to_remove.append(pkg)
                elif "finish_ts" not in data:
                    data["finish_ts"] = now
        for pkg in to_remove:
            del self.active_tasks[pkg]

    def draw(self) -> None:
        """绘制控制台界面。"""
        sys.stdout.write("\033[H\033[J")

        elapsed = time.time() - self.start_time
        speed = self.total_processed_files / elapsed if elapsed > 0 else 0

        print(f"=== 扫描引擎监控 (Running: {elapsed:.1f}s) ===")
        print(
            f"总文件进度: {self.total_processed_files}/{self.total_files_found} | "
            f"速度: {speed:.1f} file/s | 写入堆积: {self.writer_backlog}"
        )
        print("-" * 65)

        tasks = list(self.active_tasks.items())

        def sort_key(item):
            data = item[1]
            if data["done"] >= data["total"]:
                return 3
            if data["done"] > 0:
                return 1
            return 2

        tasks.sort(key=sort_key)

        display_limit = 15
        count = 0
        for pkg, data in tasks:
            if count >= display_limit:
                break
            total = data["total"]
            done = data["done"]
            percent = (done / total * 100) if total > 0 else 0

            bar_len = 25
            filled_len = int(bar_len * done // total) if total > 0 else 0
            filled_len = min(filled_len, bar_len)
            bar = "#" * filled_len + "-" * (bar_len - filled_len)

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


def monitor_process_loop(
    status_queue: multiprocessing.Queue,
    stop_event: multiprocessing.Event,
) -> None:
    """监控进程主循环：只负责显示，一直读到主进程设置 stop_event 才退出。"""
    _ignore_signals()

    monitor = StatusMonitor()
    time.sleep(1)

    while not stop_event.is_set():
        monitor.process_messages(status_queue)
        monitor.cleanup_finished()
        monitor.draw()
        for _ in range(2):
            if stop_event.is_set():
                break
            time.sleep(0.5)

    monitor.process_messages(status_queue)
    monitor.draw()
    print("\n监控进程已退出。")


# ================= SQLITE 记账 =================
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_failures (
                pkg_name TEXT,
                rel_path TEXT,
                status TEXT,
                kind TEXT,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


class RunLedger:
    """主进程侧的记账（不依赖多进程，方便单测）。

    - 每个包记录"已经有结果的 rel_path -> status"字典（不用计数器，避免同一文件被
      ACK 和 worker_crash 各记一次导致重复计数）。
    - 同一个 rel_path 多次上报：只要有一次是基础设施类状态就以基础设施类为准，
      不会被后来的 ok 覆盖；都是文件级状态时保留第一次的。
    - 完成条件：已收到 PKG_DISPATCHED、有结果的 rel_path 数 == 派发数、
      且没有基础设施类状态、且不是 PKG_PARTIAL / PKG_SKIPPED。
    """

    def __init__(self, conn: sqlite3.Connection, log_fn: Callable[[str], None] = _log) -> None:
        self.conn = conn
        self.log_fn = log_fn
        self.packages: Dict[str, Dict[str, Any]] = {}
        self.completed: Set[str] = set()
        self.skipped: List[Tuple[str, str]] = []
        self.frozen = False
        self._dirty = False

    def mark_freeze(self) -> None:
        """本次运行之后不再标记任何包（例如 Scanner 被强杀，result_queue 可能已损坏）。"""
        self.frozen = True

    # ---------- 内部 ----------
    def _entry(self, pkg: str) -> Dict[str, Any]:
        entry = self.packages.get(pkg)
        if entry is None:
            entry = {
                "dispatched": None,
                "empty": False,
                "partial": False,
                "skipped": None,
                "results": {},
                "completed": False,
            }
            self.packages[pkg] = entry
        return entry

    def _record_failure(self, pkg: str, rel_path: str, status: str,
                        kind: Optional[str] = None) -> None:
        if kind is None:
            kind = "infra" if is_infra_status(status) else "file"
        self.conn.execute(
            "DELETE FROM scan_failures WHERE pkg_name = ? AND rel_path = ?",
            (pkg, rel_path),
        )
        self.conn.execute(
            "INSERT INTO scan_failures(pkg_name, rel_path, status, kind) VALUES (?, ?, ?, ?)",
            (pkg, rel_path, status, kind),
        )
        self._dirty = True

    def _mark_completed(self, pkg: str, entry: Dict[str, Any]) -> None:
        mark_sqlite_scanned(self.conn, pkg)
        # 删掉这个包以前遗留的 kind='infra' 失败记录
        self.conn.execute(
            "DELETE FROM scan_failures WHERE pkg_name = ? AND kind = 'infra'", (pkg,)
        )
        entry["completed"] = True
        self.completed.add(pkg)
        self._dirty = True

    def _unmark_completed(self, pkg: str, entry: Dict[str, Any]) -> None:
        entry["completed"] = False
        self.completed.discard(pkg)
        self.conn.execute("DELETE FROM scanned_files WHERE file_path = ?", (pkg,))
        self._dirty = True

    # ---------- 外部接口 ----------
    def note_pkg_dispatched(self, pkg: str, n_files: int) -> None:
        entry = self._entry(pkg)
        prev = entry["dispatched"] or 0
        entry["dispatched"] = max(prev, int(n_files))

    def note_pkg_empty(self, pkg: str) -> None:
        entry = self._entry(pkg)
        entry["empty"] = True
        entry["dispatched"] = 0

    def note_pkg_partial(self, pkg: str, n_put: int) -> None:
        entry = self._entry(pkg)
        entry["partial"] = True
        entry["dispatched"] = max(entry["dispatched"] or 0, int(n_put))

    def note_pkg_skipped(self, pkg: str, reason: str) -> None:
        entry = self._entry(pkg)
        entry["skipped"] = reason
        self.skipped.append((pkg, reason))
        self._record_failure(pkg, "", reason, kind="infra")

    def note_result(self, pkg: str, rel_path: str, status: str) -> str:
        """记一个文件的结果，返回该文件最终的合并状态。"""
        entry = self._entry(pkg)
        results = entry["results"]
        prev = results.get(rel_path)
        if prev is not None:
            if is_infra_status(prev):
                return prev
            if not is_infra_status(status):
                return prev
        results[rel_path] = status
        if (is_infra_status(status) or status in FILE_FAILURE_STATUSES
                or status.startswith("error:extract:")):
            self._record_failure(pkg, rel_path, status)
        if is_infra_status(status) and entry["completed"]:
            # 之前误判完成，撤销
            self._unmark_completed(pkg, entry)
        return status

    def unresolved(self, started: Set[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """已经开工但还没有结果的 (pkg, rel_path)，用于 writer_dead 之类的兜底。"""
        out: List[Tuple[str, str]] = []
        for pkg, rel_path in sorted(started):
            entry = self.packages.get(pkg)
            if entry is None or entry["completed"] or entry["skipped"] is not None:
                continue
            if rel_path in entry["results"]:
                continue
            out.append((pkg, rel_path))
        return out

    def is_settled(self) -> bool:
        """所有已派发的文件是否都已有结果（正常结束条件之一）。"""
        for entry in self.packages.values():
            if entry["skipped"] is not None:
                continue
            dispatched = entry["dispatched"]
            if dispatched is None:
                return False
            if len(entry["results"]) < dispatched:
                return False
        return True

    def process(self) -> List[str]:
        """把可以标记完成的包立即写进 sqlite，返回本次新完成的包名。"""
        newly: List[str] = []
        for pkg, entry in self.packages.items():
            if self.frozen:
                break
            if entry["completed"] or entry["skipped"] is not None or entry["partial"]:
                continue
            dispatched = entry["dispatched"]
            if dispatched is None:
                continue
            results = entry["results"]
            if len(results) != dispatched:
                continue
            if any(is_infra_status(s) for s in results.values()):
                continue
            self._mark_completed(pkg, entry)
            newly.append(pkg)
        if self._dirty:
            self.conn.commit()
            self._dirty = False
        return newly

    def flush(self) -> None:
        if self._dirty:
            self.conn.commit()
            self._dirty = False

    # ---------- 汇总 ----------
    def file_status_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for entry in self.packages.values():
            for status in entry["results"].values():
                counts[status] = counts.get(status, 0) + 1
        return counts

    def incomplete_reasons(self) -> Dict[str, int]:
        reasons: Dict[str, int] = {}
        for entry in self.packages.values():
            if entry["completed"] or entry["skipped"] is not None:
                continue
            reason = None
            if entry["partial"]:
                reason = "partial_dispatched"
            else:
                for status in entry["results"].values():
                    if is_infra_status(status):
                        reason = status
                        break
            if reason is None:
                dispatched = entry["dispatched"]
                if dispatched is None:
                    reason = "never_dispatched"
                elif len(entry["results"]) < dispatched:
                    reason = "waiting_for_results"
                else:
                    reason = "unknown"
            reasons[reason] = reasons.get(reason, 0) + 1
        return reasons


# ================= STAGE 3: CONSUMER (DB WRITER) =================
class WriterFatalError(RuntimeError):
    """Writer 连续重连失败，必须退出（退出码非 0）。"""


class DbAdapter:
    """数据库访问封装：任何 OperationalError / InterfaceError 先重连再重做一次。"""

    RECONNECT_ERRORS = (pymysql.err.OperationalError, pymysql.err.InterfaceError)

    def __init__(
        self,
        conn,
        cursor,
        log_fn: Callable[[str], None] = _log,
        max_reconnect: int = 5,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.conn = conn
        self.cursor = cursor
        self.log_fn = log_fn
        self.max_reconnect = max_reconnect
        self.sleep_fn = sleep_fn
        self.reconnect_count = 0
        self.consecutive_reconnect_failures = 0

    def rollback_silent(self) -> None:
        """rollback 本身抛异常也要吞掉。"""
        try:
            self.conn.rollback()
        except Exception as exc:  # pylint: disable=broad-except
            self.log_fn(f"[Writer] rollback 失败(已忽略): {exc}")

    def _reconnect(self, err: Exception) -> bool:
        self.rollback_silent()
        for attempt in range(self.max_reconnect):
            try:
                self.conn.ping(reconnect=True)
            except Exception as exc:  # pylint: disable=broad-except
                self.consecutive_reconnect_failures += 1
                self.log_fn(
                    f"[Writer] 重连失败 {attempt + 1}/{self.max_reconnect}: {exc}"
                )
                self.sleep_fn(min(2 ** attempt, 8))
                continue
            try:
                self.cursor = self.conn.cursor()
            except Exception as exc:  # pylint: disable=broad-except
                self.log_fn(f"[Writer] 重连后重建 cursor 失败: {exc}")
            self.reconnect_count += 1
            self.consecutive_reconnect_failures = 0
            self.log_fn(f"[Writer] 重连成功(第 {self.reconnect_count} 次)，重做本批")
            return True
        self.log_fn(f"[Writer] 连续重连失败 {self.max_reconnect} 次，放弃: {err}")
        return False

    def run(self, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except self.RECONNECT_ERRORS as exc:
            self.log_fn(f"[Writer] 数据库错误: {exc}；重连后重做")
            if not self._reconnect(exc):
                raise WriterFatalError(f"连续重连失败: {exc}") from exc
            return fn()

    # ---- 具体操作 ----
    def execute(self, sql: str, args: Sequence = ()) -> Any:
        return self.run(lambda: self.cursor.execute(sql, tuple(args)))

    def executemany(self, sql: str, seq: Sequence) -> Any:
        return self.run(lambda: self.cursor.executemany(sql, list(seq)))

    def fetchall(self, sql: str, args: Sequence = ()) -> List[Tuple]:
        def _op():
            self.cursor.execute(sql, tuple(args))
            return self.cursor.fetchall()

        return self.run(_op)

    def fetchone(self, sql: str, args: Sequence = ()) -> Optional[Tuple]:
        def _op():
            self.cursor.execute(sql, tuple(args))
            return self.cursor.fetchone()

        return self.run(_op)

    def commit(self) -> None:
        self.run(lambda: self.conn.commit())


class WriterCore:
    """Writer 的消息处理 / 批量提交 / ACK 生成（不依赖多进程，可单测）。

    消息格式：
        ('DATA', pkg, kind_id, slug_id, risk_level, content, source_file,
                 detector_source, source_snippet)
        ('FILE_DONE', pkg, rel_path, source_file, status)
        ('STOP',)
    返回：需要发出去的 ACK 列表，元素为
        ('ACK', pkg, rel_path, status, committed: bool, reason: str)
    """

    SQL_MINIAPP_META = (
        "INSERT INTO miniapp_meta (appid) VALUES (%s) "
        "ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP"
    )
    SQL_SELECT_MINIAPP_ID = "SELECT id FROM miniapp_meta WHERE appid = %s"
    SQL_DATA_ITEM = (
        "INSERT INTO data_item (type_id, raw_value, hash_sha256) "
        "VALUES (%s, %s, %s) "
        "ON DUPLICATE KEY UPDATE ref_count = ref_count + 1"
    )
    SQL_RELATION = (
        "INSERT INTO miniapp_to_dataitem "
        "(miniapp_id, data_item_id, source_file, detector_source, source_snippet) "
        "VALUES (%s, %s, %s, %s, %s) "
        "ON DUPLICATE KEY UPDATE id = id"
    )

    def __init__(
        self,
        db: Optional[DbAdapter],
        *,
        dry_run: bool = False,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_interval: float = DEFAULT_BATCH_INTERVAL,
        file_done_delay: float = FILE_DONE_FLUSH_DELAY,
        log_fn: Callable[[str], None] = _log,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self.db = db
        self.dry_run = dry_run
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        self.file_done_delay = file_done_delay
        self.log_fn = log_fn
        self.now_fn = now_fn
        self.buffer: List[Tuple] = []
        self.appid_cache: Dict[str, int] = {}
        # (appid, source_file) -> reason
        self.failures: Dict[Tuple[str, str], str] = {}
        # (pkg, rel_path, source_file, status)
        self.pending_files: List[Tuple[str, str, str, str]] = []
        self.pending_since: Optional[float] = None
        self.last_flush = self.now_fn()
        self.stats: Dict[str, int] = {
            "data_seen": 0,
            "written": 0,
            "batches": 0,
            "acks": 0,
            "retry_failed": 0,
            "miniapp_meta_failed": 0,
            "reconnects": 0,
        }

    # ---------- 消息处理 ----------
    def handle_message(self, msg: Any, now: Optional[float] = None) -> List[Tuple]:
        if not isinstance(msg, tuple) or not msg:
            return []
        tag = msg[0]
        if tag == "DATA":
            return self._handle_data(msg, now)
        if tag == "FILE_DONE":
            return self._handle_file_done(msg, now)
        if tag == "STOP":
            return self.finish(now)
        self.log_fn(f"[Writer] 收到未知消息，已忽略: {msg!r}")
        return []

    def _handle_data(self, msg: Tuple, now: Optional[float]) -> List[Tuple]:
        self.stats["data_seen"] += 1
        if self.dry_run:
            return []
        self.buffer.append(tuple(msg[1:]))
        if len(self.buffer) >= self.batch_size:
            return self.flush(now)
        return []

    def _handle_file_done(self, msg: Tuple, now: Optional[float]) -> List[Tuple]:
        if len(msg) < 5:
            self.log_fn(f"[Writer] FILE_DONE 字段不足，已忽略: {msg!r}")
            return []
        _, pkg, rel_path, source_file, status = msg[:5]
        self.pending_files.append((pkg, rel_path, source_file, status))
        if self.pending_since is None:
            self.pending_since = self.now_fn() if now is None else now
        return []

    def tick(self, now: Optional[float] = None) -> List[Tuple]:
        """定时器驱动：按批大小 / 攒批时间 / FILE_DONE 延迟决定是否 flush。"""
        now = self.now_fn() if now is None else now
        need_flush = False
        if self.buffer and (
            len(self.buffer) >= self.batch_size
            or now - self.last_flush >= self.batch_interval
        ):
            need_flush = True
        if (
            self.pending_files
            and self.pending_since is not None
            and now - self.pending_since >= self.file_done_delay
        ):
            need_flush = True
        if need_flush:
            return self.flush(now)
        return []

    # ---------- 提交 ----------
    def flush(self, now: Optional[float] = None) -> List[Tuple]:
        now = self.now_fn() if now is None else now
        if self.dry_run:
            self.buffer.clear()
            self.last_flush = now
            return self._emit_acks()
        if self.buffer:
            batch = list(self.buffer)
            self.buffer.clear()
            self._write_batch(batch)
            self.stats["batches"] += 1
        self.last_flush = now
        return self._emit_acks()

    def finish(self, now: Optional[float] = None) -> List[Tuple]:
        acks = self.flush(now)
        acks += self._emit_acks()
        return acks

    def _emit_acks(self) -> List[Tuple]:
        acks: List[Tuple] = []
        for pkg, rel_path, source_file, status in self.pending_files:
            reason = self.failures.pop((pkg, source_file), "")
            committed = not reason
            acks.append(("ACK", pkg, rel_path, status, committed, reason))
            self.stats["acks"] += 1
        self.pending_files = []
        self.pending_since = None
        if self.db is not None:
            self.stats["reconnects"] = self.db.reconnect_count
        return acks

    def _write_batch(self, rows: Sequence[Tuple]) -> None:
        if not rows:
            return
        data_items: List[Tuple[int, str, str]] = []   # (type_id, raw_value, hash_sha256)
        hash_to_meta: Dict[str, List[Tuple]] = {}
        for row in rows:
            if len(row) < 8:
                self.log_fn(f"[Writer] DATA 字段不足，已丢弃: {row!r}")
                continue
            appid, _kind_id, slug_id, _risk, content, source_file, detector_source, snippet = row[:8]
            content = content if isinstance(content, str) else str(content)
            raw_value = content[:1000] if len(content) > 1000 else content
            hash_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
            data_items.append((slug_id, raw_value, hash_sha256))
            hash_to_meta.setdefault(hash_sha256, []).append(
                (appid, source_file, detector_source, snippet)
            )

        if not data_items:
            return

        failed_hashes: Set[str] = set()
        try:
            self.db.executemany(self.SQL_DATA_ITEM, data_items)
            self.db.commit()
            self.stats["written"] += len(data_items)
        except WriterFatalError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self.db.rollback_silent()
            self.log_fn(f"[Writer] data_item 批量写入失败({exc})，逐条重试")
            saved = 0
            for item in data_items:
                try:
                    self.db.execute(self.SQL_DATA_ITEM, item)
                    self.db.commit()
                    saved += 1
                except WriterFatalError:
                    raise
                except Exception:  # pylint: disable=broad-except
                    self.db.rollback_silent()
                    failed_hashes.add(item[2])
                    self.stats["retry_failed"] += 1
            self.stats["written"] += saved
            if failed_hashes:
                self.log_fn(
                    f"[Writer] data_item 逐条重试仍有 {len(failed_hashes)} 条失败，"
                    f"成功 {saved}/{len(data_items)}"
                )

        for hash_val in failed_hashes:
            for meta in hash_to_meta.get(hash_val, []):
                self.failures[(meta[0], meta[1])] = "commit_failed"

        hashes = list(hash_to_meta.keys())
        try:
            placeholders = ",".join(["%s"] * len(hashes))
            rows2 = self.db.fetchall(
                f"SELECT id, hash_sha256 FROM data_item WHERE hash_sha256 IN ({placeholders})",
                tuple(hashes),
            )
            hash_to_id = {row[1]: row[0] for row in (rows2 or [])}
        except WriterFatalError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self.log_fn(f"[Writer] data_item hash 查询失败({exc})，跳过关联写入")
            for hash_val in hashes:
                for meta in hash_to_meta.get(hash_val, []):
                    self.failures[(meta[0], meta[1])] = "commit_failed"
            return

        relations: List[Tuple] = []
        relation_meta: List[Tuple[str, str]] = []
        for hash_val, meta_list in hash_to_meta.items():
            data_item_id = hash_to_id.get(hash_val)
            if not data_item_id:
                for meta in meta_list:
                    self.failures[(meta[0], meta[1])] = "commit_failed"
                continue
            for appid, source_file, detector_source, snippet in meta_list:
                miniapp_id = self._ensure_miniapp_id(appid)
                if not miniapp_id:
                    self.failures[(appid, source_file)] = "miniapp_meta_failed"
                    continue
                snippet = snippet[:65000] if snippet else ""
                relations.append(
                    (miniapp_id, data_item_id, source_file, detector_source, snippet)
                )
                relation_meta.append((appid, source_file))

        if not relations:
            return

        try:
            self.db.executemany(self.SQL_RELATION, relations)
            self.db.commit()
        except WriterFatalError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self.db.rollback_silent()
            self.log_fn(f"[Writer] 关联写入批量失败({exc})，逐条重试")
            saved = 0
            for rel, meta in zip(relations, relation_meta):
                try:
                    self.db.execute(self.SQL_RELATION, rel)
                    self.db.commit()
                    saved += 1
                except WriterFatalError:
                    raise
                except Exception:  # pylint: disable=broad-except
                    self.db.rollback_silent()
                    self.failures[meta] = "commit_failed"
                    self.stats["retry_failed"] += 1
            if saved < len(relations):
                self.log_fn(
                    f"[Writer] 关联逐条重试 {saved}/{len(relations)} 成功"
                )

    def _ensure_miniapp_id(self, appid: str) -> Optional[int]:
        cached = self.appid_cache.get(appid)
        if cached:
            return cached
        try:
            self.db.execute(self.SQL_MINIAPP_META, (appid,))
            self.db.commit()
            row = self.db.fetchone(self.SQL_SELECT_MINIAPP_ID, (appid,))
        except WriterFatalError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            self.db.rollback_silent()
            self.stats["miniapp_meta_failed"] += 1
            self.log_fn(f"[Writer] miniapp_meta 处理失败(appid={appid}): {exc}")
            return None
        if not row:
            self.stats["miniapp_meta_failed"] += 1
            self.log_fn(f"[Writer] 拿不到 miniapp_id(appid={appid})，对应文件不标记完成")
            return None
        self.appid_cache[appid] = row[0]
        return row[0]


def _connect_db(db_config: Dict[str, object], max_retries: int = 3):
    last_err: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            conn = pymysql.connect(
                host=str(db_config["host"]),
                port=int(db_config["port"]),
                user=str(db_config["user"]),
                password=str(db_config["password"]),
                database=str(db_config["db_name"]),
                charset=str(db_config.get("charset", "utf8mb4")),
                autocommit=False,
                connect_timeout=10,
            )
            return conn, conn.cursor()
        except Exception as exc:  # pylint: disable=broad-except
            last_err = exc
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    _log(f"[Writer] 数据库连接失败: {last_err}")
    return None, None


def _send_acks(ack_queue: multiprocessing.Queue, acks: Sequence[Tuple]) -> None:
    for ack in acks:
        try:
            ack_queue.put(ack, timeout=5)
        except Exception as exc:  # pylint: disable=broad-except
            _log(f"[Writer] ACK 入队失败: {exc}")


def db_writer_process(
    result_queue: multiprocessing.Queue,
    ack_queue: multiprocessing.Queue,
    status_queue: multiprocessing.Queue,
    db_config: Optional[Dict[str, object]],
    dry_run: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
    batch_interval: float = DEFAULT_BATCH_INTERVAL,
    max_retries: int = 3,
) -> None:
    _ignore_signals()
    # status_queue 只用于显示，丢最后几条可以接受
    status_queue.cancel_join_thread()
    # 注意：ack_queue 不能 cancel_join_thread，否则退出时缓冲里的最后一批 ACK
    # 会被丢掉，导致已经提交进库的包不被标记完成。

    db: Optional[DbAdapter] = None
    if not dry_run:
        conn, cursor = _connect_db(db_config or {}, max_retries)
        if conn is None:
            _log("[Writer] 无法连接数据库，Writer 退出（本次运行不会标记任何包）")
            try:
                ack_queue.put(("WRITER_STATS", {"fatal": True, "reason": "connect_failed"}),
                              timeout=5)
            except Exception as exc:  # pylint: disable=broad-except
                _log(f"[Writer] WRITER_STATS 上报失败: {exc}")
            sys.exit(1)
        db = DbAdapter(conn, cursor)

    core = WriterCore(
        db,
        dry_run=dry_run,
        batch_size=batch_size,
        batch_interval=batch_interval,
    )

    fatal = False
    last_status_report = 0.0
    try:
        while True:
            msg = None
            try:
                msg = result_queue.get(timeout=0.5)
            except queue.Empty:
                msg = None
            except (OSError, EOFError, ValueError) as exc:
                _log(f"[Writer] result_queue 读取失败，退出: {exc}")
                fatal = True
                break

            if msg is None:
                try:
                    acks = core.tick()
                except WriterFatalError as exc:
                    _log(f"[Writer] 致命错误: {exc}")
                    fatal = True
                    break
                _send_acks(ack_queue, acks)
            elif isinstance(msg, tuple) and msg and msg[0] == "STOP":
                try:
                    acks = core.finish()
                except WriterFatalError as exc:
                    _log(f"[Writer] 致命错误: {exc}")
                    fatal = True
                    break
                _send_acks(ack_queue, acks)
                break
            else:
                try:
                    acks = core.handle_message(msg)
                    # 消息不断时也要走定时 flush，保证 FILE_DONE 后 2 秒内一定 ACK
                    acks += core.tick()
                except WriterFatalError as exc:
                    _log(f"[Writer] 致命错误: {exc}")
                    fatal = True
                    break
                _send_acks(ack_queue, acks)

            now = time.time()
            if now - last_status_report >= 1.0:
                last_status_report = now
                try:
                    status_queue.put_nowait(("WRITER_STATUS", len(core.buffer)))
                except Exception:  # pylint: disable=broad-except
                    pass
    except Exception as exc:  # pylint: disable=broad-except
        _log(f"[Writer] 未预期异常，退出: {type(exc).__name__}: {exc}")
        fatal = True
    finally:
        try:
            conn_obj = db.conn if db is not None else None
            if db is not None and db.cursor is not None:
                try:
                    db.cursor.close()
                except Exception as exc:  # pylint: disable=broad-except
                    _log(f"[Writer] 关闭 cursor 失败: {exc}")
            if conn_obj is not None:
                try:
                    conn_obj.close()
                except Exception as exc:  # pylint: disable=broad-except
                    _log(f"[Writer] 关闭连接失败: {exc}")
        except Exception as exc:  # pylint: disable=broad-except
            _log(f"[Writer] 清理连接异常: {exc}")
        stats = dict(core.stats)
        stats["fatal"] = fatal
        try:
            ack_queue.put(("WRITER_STATS", stats), timeout=5)
        except Exception as exc:  # pylint: disable=broad-except
            _log(f"[Writer] WRITER_STATS 上报失败: {exc}")

    if fatal:
        sys.exit(1)


# ================= STAGE 2: SCANNER (含提取沙箱) =================
def sandbox_process(conn, scan_fn: Callable) -> None:
    """提取沙箱：只通过私有 Pipe 与 worker 通信，不碰任何共享队列。

    被杀掉是安全的（不持有 Queue 的写端），所以超时/中止时可以放心 terminate。
    """
    _ignore_signals()
    try:
        while True:
            try:
                task = conn.recv()
            except (EOFError, OSError):
                return
            if task is None:
                return
            try:
                file_path, ext, smart = task
            except (TypeError, ValueError):
                return
            try:
                findings, status = scan_fn(file_path, ext, smart)
            except Exception as exc:  # pylint: disable=broad-except
                findings, status = [], f"error:extract:{type(exc).__name__}"
            try:
                conn.send((list(findings or []), status))
            except (BrokenPipeError, EOFError, OSError):
                return
    finally:
        try:
            conn.close()
        except Exception:  # pylint: disable=broad-except
            pass


class SandboxHandle:
    """worker 私有的提取沙箱子进程句柄。"""

    def __init__(self, scan_fn: Callable, file_timeout: int) -> None:
        self.scan_fn = scan_fn
        self.file_timeout = file_timeout
        self.conn = None
        self.proc: Optional[multiprocessing.Process] = None
        self.start()

    def start(self) -> None:
        parent_conn, child_conn = multiprocessing.Pipe(duplex=True)
        proc = multiprocessing.Process(
            target=sandbox_process,
            args=(child_conn, self.scan_fn),
            name="sandbox",
            daemon=True,
        )
        proc.start()
        try:
            child_conn.close()
        except Exception:  # pylint: disable=broad-except
            pass
        self.conn = parent_conn
        self.proc = proc

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.is_alive()

    def shutdown(self) -> None:
        conn, proc = self.conn, self.proc
        self.conn, self.proc = None, None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # pylint: disable=broad-except
                pass
        if proc is not None:
            if proc.is_alive():
                proc.terminate()
            try:
                proc.join(timeout=5)
            except Exception:  # pylint: disable=broad-except
                pass
            if proc.is_alive():
                try:
                    proc.kill()
                    proc.join(timeout=5)
                except Exception:  # pylint: disable=broad-except
                    pass

    def restart(self) -> None:
        self.shutdown()
        self.start()


def _scan_one_file(
    sandbox: SandboxHandle,
    full_path: Path,
    ext: str,
    use_smart_filter: bool,
    stop_event: multiprocessing.Event,
    writer_dead_event: multiprocessing.Event,
    file_timeout: int,
) -> Tuple[List[Tuple], str]:
    """在沙箱里扫一个文件；返回 (findings, status)。绝不抛异常。

    超时/崩溃只杀沙箱；stop_event 置位时一律返回 aborted。
    """
    if not full_path.exists():
        return [], STATUS_MISSING

    if not sandbox.is_alive():
        sandbox.restart()

    try:
        sandbox.conn.send((str(full_path), ext, use_smart_filter))
    except (BrokenPipeError, EOFError, OSError):
        sandbox.restart()
        return [], (STATUS_ABORTED if stop_event.is_set() else STATUS_SANDBOX_CRASH)

    deadline = time.time() + max(1, int(file_timeout))
    while True:
        if stop_event.is_set():
            sandbox.shutdown()
            return [], STATUS_ABORTED
        if writer_dead_event is not None and writer_dead_event.is_set():
            sandbox.shutdown()
            return [], STATUS_ABORTED

        remaining = deadline - time.time()
        if remaining <= 0:
            sandbox.restart()
            return [], (STATUS_ABORTED if stop_event.is_set() else STATUS_TIMEOUT)

        try:
            ready = sandbox.conn.poll(min(0.5, remaining))
        except (OSError, EOFError):
            ready = None

        if ready is None:
            sandbox.restart()
            return [], (STATUS_ABORTED if stop_event.is_set() else STATUS_SANDBOX_CRASH)

        if ready:
            try:
                findings, status = sandbox.conn.recv()
            except (EOFError, OSError):
                sandbox.restart()
                return [], (STATUS_ABORTED if stop_event.is_set() else STATUS_SANDBOX_CRASH)
            if not isinstance(status, str) or not status:
                status = STATUS_OK
            return list(findings or []), status

        if not sandbox.is_alive():
            sandbox.restart()
            return [], (STATUS_ABORTED if stop_event.is_set() else STATUS_SANDBOX_CRASH)


def _put_retry(
    q,
    item,
    stop_event: Optional[multiprocessing.Event],
    writer_dead_event: Optional[multiprocessing.Event] = None,
    timeout: float = 1.0,
    max_wait: Optional[float] = None,
) -> bool:
    """带重试的 put：每轮检查 stop_event / writer 是否已死，可选总等待上限。"""
    deadline = None if max_wait is None else time.time() + max_wait
    while True:
        if stop_event is not None and stop_event.is_set():
            return False
        if writer_dead_event is not None and writer_dead_event.is_set():
            return False
        if deadline is not None and time.time() >= deadline:
            return False
        try:
            q.put(item, timeout=timeout)
            return True
        except queue.Full:
            continue
        except (OSError, EOFError, ValueError, AssertionError) as exc:
            _log(f"[Scanner] 队列写入失败: {exc}")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            _log(f"[Scanner] 队列写入异常: {exc}")
            return False


def _put_event(event_queue, item, attempts: int = 5) -> bool:
    for _ in range(attempts):
        try:
            event_queue.put(item, timeout=1.0)
            return True
        except queue.Full:
            continue
        except Exception as exc:  # pylint: disable=broad-except
            _log(f"[Scanner] event_queue 写入失败: {exc}")
            return False
    _log(f"[Scanner] event_queue 写入超时，丢弃事件: {item!r}")
    return False


def _put_status(status_queue, item) -> None:
    try:
        status_queue.put_nowait(item)
    except Exception:  # pylint: disable=broad-except
        pass


def file_scanner_process(
    worker_id: int,
    file_queue,
    result_queue: multiprocessing.Queue,
    event_queue: multiprocessing.Queue,
    status_queue: multiprocessing.Queue,
    source_root: Path,
    use_smart_filter: bool,
    stop_event: multiprocessing.Event,
    writer_dead_event: multiprocessing.Event,
    file_timeout: int = DEFAULT_FILE_TIMEOUT,
    scan_fn: Callable = None,
) -> None:
    """Scanner worker：非 daemon（要再起沙箱子进程），每个文件都带超时保护。"""
    _ignore_signals()
    status_queue.cancel_join_thread()

    if scan_fn is None:
        scan_fn = perform_scan

    sandbox = SandboxHandle(scan_fn, file_timeout)

    try:
        while True:
            if stop_event.is_set():
                break
            try:
                task = file_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            except (OSError, EOFError, ValueError) as exc:
                _log(f"[Scanner#{worker_id}] file_queue 读取失败: {exc}")
                break

            if task is None:
                break

            try:
                pkg, rel_path, ext = task
            except (TypeError, ValueError):
                _log(f"[Scanner#{worker_id}] 非法任务: {task!r}")
                continue

            full_path = source_root / rel_path
            _put_event(event_queue, ("FILE_START", worker_id, pkg, rel_path, time.time()))

            findings: List[Tuple] = []
            status = STATUS_EMPTY
            try:
                findings, status = _scan_one_file(
                    sandbox, full_path, ext, use_smart_filter,
                    stop_event, writer_dead_event, file_timeout,
                )
            except Exception as exc:  # pylint: disable=broad-except
                # 兜底：不静默吞掉，记为文件级失败（包仍可完成）
                status = f"error:extract:{type(exc).__name__}"
                findings = []

            if is_infra_status(status):
                # 基础设施状态：不发 FILE_DONE，只通过 event_queue 上报
                _put_event(event_queue, ("FILE_END", worker_id, pkg, rel_path, status))
                if stop_event.is_set() or writer_dead_event.is_set():
                    break
                continue

            pushed = True
            for item in findings:
                if not _put_retry(
                    result_queue, ("DATA", pkg) + tuple(item), stop_event, writer_dead_event
                ):
                    pushed = False
                    break

            if not pushed:
                abandon_status = (
                    STATUS_ABORTED if stop_event.is_set() else STATUS_RESULT_QUEUE_FULL
                )
                _put_event(
                    event_queue, ("FILE_END", worker_id, pkg, rel_path, abandon_status)
                )
                break

            sent = _put_retry(
                result_queue,
                ("FILE_DONE", pkg, rel_path, str(full_path), status),
                stop_event,
                writer_dead_event,
            )
            if not sent:
                abandon_status = (
                    STATUS_ABORTED if stop_event.is_set() else STATUS_RESULT_QUEUE_FULL
                )
                _put_event(
                    event_queue, ("FILE_END", worker_id, pkg, rel_path, abandon_status)
                )
                break

            _put_event(event_queue, ("FILE_END", worker_id, pkg, rel_path, status))
            _put_status(status_queue, ("PROGRESS", pkg))
    finally:
        sandbox.shutdown()
        if stop_event.is_set() or writer_dead_event.is_set():
            # 消费者可能已经没了，别卡在 feeder 线程上
            try:
                result_queue.cancel_join_thread()
            except Exception:  # pylint: disable=broad-except
                pass
        _put_event(event_queue, ("WORKER_EXIT", worker_id))


def perform_scan(
    file_path: str, file_ext: str, use_smart_filter: bool = True
) -> Tuple[List[Tuple], str]:
    """提取 -> 过滤 -> 分类。返回 (db_results, status)，任何异常都不向上抛。

    提取器 / 过滤器 / 分类器 / constant_ids 全部在这里延迟 import，
    import scanner_engine 时不会加载它们。
    """
    try:
        if file_ext == "html":
            try:
                if os.path.getsize(file_path) > MAX_HTML_BYTES:
                    return [], STATUS_SKIPPED_TOO_LARGE
            except OSError:
                return [], STATUS_MISSING

        if file_ext == "js":
            from extract_js_consts import extract_from_js_file as _extract
        elif file_ext == "json":
            from extract_json_consts import extract_from_json_file as _extract
        elif file_ext == "wxml":
            from extract_wxml_consts import extract_from_wxml_file as _extract
        elif file_ext == "wxs":
            from extract_wxs_consts import extract_from_wxs_file as _extract
        elif file_ext == "wxss":
            from extract_wxss_consts import extract_from_wxss_file as _extract
        elif file_ext == "html":
            from extract_html_consts import extract_from_html_file as _extract
        else:
            return [], STATUS_EMPTY

        res = _extract(file_path)
        if not res:
            return [], STATUS_EMPTY

        from constants_filter import perform_constant_filtering
        from constants_classifier import perform_constant_classifying
        from constant_ids import SLUG_TO_DB, CTG_OTHERS, RISK_IGNORE

        filtered = perform_constant_filtering(
            res["statements"], res["constants"], use_smart_filter=use_smart_filter
        )
        classified = perform_constant_classifying(
            filtered["statements"], filtered["constants"]
        )

        db_results: List[Tuple] = []
        for slug_id, content, src, source_snippet in classified:
            kind_id, risk_level = SLUG_TO_DB.get(slug_id, (CTG_OTHERS, RISK_IGNORE))
            db_results.append(
                (kind_id, slug_id, risk_level, content, file_path, src, source_snippet)
            )
        return db_results, (STATUS_OK if db_results else STATUS_EMPTY)
    except Exception as exc:  # pylint: disable=broad-except
        return [], f"error:extract:{type(exc).__name__}"


# ================= STAGE 1: FILE FINDER =================
SCANNING_EXCLUDED_FOLDERS: Set[str] = {
    "@babel", "miniprogram_npm", "npm", "unpackage",
    "node_modules", "uni_modules", "external", "uview-ui",
    "third_party", "third-party", "vendor",
    "dist", "build", "out",
    "static", "assets", "images", "img", "fonts", "icons",
    "media", "audio", "video",
}
SCAN_EXTS: Set[str] = {"js", "json", "wxml", "wxs", "wxss", "html"}


def _collect_pkg_files(unpacked_dir: Path, pkg_name: str) -> List[Tuple[str, str, str]]:
    pkg_path = unpacked_dir / pkg_name
    out: List[Tuple[str, str, str]] = []
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
            try:
                rel_path = str(full_path.relative_to(unpacked_dir))
            except ValueError:
                continue
            out.append((pkg_name, rel_path, ext))
    out.sort(key=lambda item: item[1])
    return out


def file_finder_process(
    file_queue,
    control_queue: multiprocessing.Queue,
    status_queue: multiprocessing.Queue,
    unpacked_dir: Path,
    sqlite_path: Path,
    stop_event: multiprocessing.Event,
) -> None:
    _ignore_signals()
    status_queue.cancel_join_thread()

    n_dispatched = 0
    stopped = False

    try:
        try:
            scanned_history = load_scanned_log2db(sqlite_path)
        except Exception as exc:  # pylint: disable=broad-except
            scanned_history = set()
            _log(f"[Finder] 读取扫描历史失败(忽略): {exc}")

        try:
            packages = sorted(
                d for d in os.listdir(unpacked_dir) if (unpacked_dir / d).is_dir()
            )
        except FileNotFoundError:
            packages = []

        for pkg_name in packages:
            if stop_event.is_set():
                stopped = True
                break
            if pkg_name in scanned_history:
                continue
            if len(pkg_name) > MAX_APPID_LEN:
                control_queue.put(("PKG_SKIPPED", pkg_name, "appid_too_long"))
                continue

            files = _collect_pkg_files(unpacked_dir, pkg_name)
            if not files:
                control_queue.put(("PKG_EMPTY", pkg_name))
                n_dispatched += 1
                continue

            _put_status(status_queue, ("INIT", pkg_name, len(files)))

            n_put = 0
            for item in files:
                if stop_event.is_set():
                    break
                if _put_retry(file_queue, item, stop_event):
                    n_put += 1
                else:
                    break

            if n_put == len(files) and not stop_event.is_set():
                control_queue.put(("PKG_DISPATCHED", pkg_name, len(files)))
                n_dispatched += 1
            else:
                control_queue.put(("PKG_PARTIAL", pkg_name, n_put))
                stopped = True
                break
    except Exception as exc:  # pylint: disable=broad-except
        _log(f"[Finder] 异常退出: {type(exc).__name__}: {exc}")
        try:
            control_queue.put(("FINDER_ERROR", f"{type(exc).__name__}: {exc}"))
        except Exception as exc2:  # pylint: disable=broad-except
            _log(f"[Finder] FINDER_ERROR 上报失败: {exc2}")
    finally:
        if stop_event.is_set() or stopped:
            # 消费者可能已经没了，别卡在 feeder 线程上
            try:
                file_queue.cancel_join_thread()
            except Exception as exc:  # pylint: disable=broad-except
                _log(f"[Finder] cancel_join_thread 失败: {exc}")
        try:
            control_queue.put(("FINDER_DONE", n_dispatched))
        except Exception as exc:  # pylint: disable=broad-except
            _log(f"[Finder] FINDER_DONE 上报失败: {exc}")


# ================= DB INIT / CONFIG =================
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


def initialize_config(
    cli_task_path: Optional[str],
    cli_source_path: Optional[str] = None,
    dry_run_writer: bool = False,
) -> None:
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
        task_dir_name = input("Enter task folder name: ").strip()

    TASK_PATH = project_root / task_dir_name
    TASK_PATH.mkdir(parents=True, exist_ok=True)

    unpacked_dir = config.get("pkg_unpacked_dir", "wxpkg-unpacked")
    if not isinstance(unpacked_dir, str) or not unpacked_dir:
        unpacked_dir = "wxpkg-unpacked"

    USE_SMART_FILTER = bool(config.get("use_smart_filter", False))

    if cli_source_path:
        UNPACKED_PKG_PATH = Path(cli_source_path)
    else:
        UNPACKED_PKG_PATH = TASK_PATH / unpacked_dir

    LOGDB_PATH = TASK_PATH / "scanned_wxpkg.db"
    init_sqlite_log2db(LOGDB_PATH)

    if dry_run_writer:
        # dry-run 不连库：不要求配置里有 constant_db，也不建库
        DB_CONFIG = config.get("constant_db") or {}
    else:
        db_config = config.get("constant_db")
        if not isinstance(db_config, dict) or not db_config:
            raise RuntimeError("config.json 缺少 constant_db 配置（或用 --dry-run-writer 运行）")
        DB_CONFIG = db_config
        init_constant_db(DB_CONFIG)


# ================= MAIN CONTROLLER =================
class ScanOrchestrator:
    """主进程：启停子进程、记账、收尾、汇总。"""

    def __init__(
        self,
        num_workers: int,
        file_timeout: int,
        dry_run_writer: bool,
        unpacked_dir: Path,
        logdb_path: Path,
        db_config: Optional[Dict[str, object]],
        use_smart_filter: bool,
    ) -> None:
        self.num_workers = max(1, num_workers)
        self.file_timeout = file_timeout
        self.dry_run_writer = dry_run_writer
        self.unpacked_dir = unpacked_dir
        self.logdb_path = logdb_path
        self.db_config = db_config
        self.use_smart_filter = use_smart_filter

        self.file_queue = multiprocessing.Queue(maxsize=QUEUE_MAXSIZE)
        self.result_queue: multiprocessing.Queue = multiprocessing.Queue(maxsize=QUEUE_MAXSIZE)
        self.ack_queue: multiprocessing.Queue = multiprocessing.Queue()
        self.control_queue: multiprocessing.Queue = multiprocessing.Queue()
        self.event_queue: multiprocessing.Queue = multiprocessing.Queue()
        self.status_queue: multiprocessing.Queue = multiprocessing.Queue()

        self.stop_event = multiprocessing.Event()
        self.writer_dead_event = multiprocessing.Event()
        self.monitor_stop_event = multiprocessing.Event()
        self.force_exit_event = multiprocessing.Event()

        self.monitor_proc: Optional[multiprocessing.Process] = None
        self.writer_proc: Optional[multiprocessing.Process] = None
        self.finder_proc: Optional[multiprocessing.Process] = None
        self.worker_procs: Dict[int, multiprocessing.Process] = {}

        # 运行期状态
        self.worker_files: Dict[int, Tuple[str, str, float]] = {}
        self.worker_exited: Set[int] = set()
        self.started_files: Set[Tuple[str, str]] = set()
        self.warned_stalled: Set[int] = set()
        self.finder_done = False
        self.finder_error: Optional[str] = None
        self.writer_dead = False
        self.writer_stats: Dict[str, Any] = {}
        self.restart_count = 0
        self.interrupted = False
        self.shutdown_issues: List[str] = []
        self._next_worker_id = 0

    # ---------- 进程管理 ----------
    def _all_procs(self) -> List[multiprocessing.Process]:
        procs = []
        for proc in (self.finder_proc, self.monitor_proc, self.writer_proc):
            if proc is not None:
                procs.append(proc)
        procs.extend(self.worker_procs.values())
        return procs

    def _start_scanner(self, worker_id: int) -> multiprocessing.Process:
        proc = multiprocessing.Process(
            target=file_scanner_process,
            args=(
                worker_id,
                self.file_queue,
                self.result_queue,
                self.event_queue,
                self.status_queue,
                self.unpacked_dir,
                self.use_smart_filter,
                self.stop_event,
                self.writer_dead_event,
                self.file_timeout,
                perform_scan,
            ),
            name=f"scanner-{worker_id}",
        )
        proc.start()
        self.worker_procs[worker_id] = proc
        return proc

    def _register_signals(self) -> None:
        def handler(signum, frame):  # pylint: disable=unused-argument
            if not self.stop_event.is_set():
                self.interrupted = True
                self.stop_event.set()
                print(
                    "\n[主进程] 收到中断信号，正在收尾；再按一次 Ctrl+C 强制退出。",
                    flush=True,
                )
                return
            self.interrupted = True
            self.force_exit_event.set()
            print("\n[主进程] 再次收到中断信号，强制终止所有子进程。", flush=True)
            for proc in self._all_procs():
                _terminate(proc)

        try:
            signal.signal(signal.SIGINT, handler)
        except (ValueError, OSError):
            pass
        if hasattr(signal, "SIGBREAK"):
            try:
                signal.signal(signal.SIGBREAK, handler)
            except (ValueError, OSError):
                pass

    # ---------- 队列读取 ----------
    def _drain_control(self, ledger: RunLedger) -> None:
        while True:
            try:
                msg = self.control_queue.get_nowait()
            except (queue.Empty, OSError, EOFError, ValueError):
                return
            if not isinstance(msg, tuple) or not msg:
                continue
            tag = msg[0]
            try:
                if tag == "PKG_EMPTY":
                    ledger.note_pkg_empty(msg[1])
                elif tag == "PKG_DISPATCHED":
                    ledger.note_pkg_dispatched(msg[1], msg[2])
                elif tag == "PKG_PARTIAL":
                    ledger.note_pkg_partial(msg[1], msg[2])
                elif tag == "PKG_SKIPPED":
                    ledger.note_pkg_skipped(msg[1], msg[2])
                elif tag == "FINDER_DONE":
                    self.finder_done = True
                elif tag == "FINDER_ERROR":
                    self.finder_error = str(msg[1])
                else:
                    _log(f"[主进程] 未知 control 消息: {msg!r}")
            except (IndexError, TypeError) as exc:
                _log(f"[主进程] control 消息字段错误 {msg!r}: {exc}")

    def _drain_events(self, ledger: RunLedger) -> None:
        while True:
            try:
                msg = self.event_queue.get_nowait()
            except (queue.Empty, OSError, EOFError, ValueError):
                return
            if not isinstance(msg, tuple) or not msg:
                continue
            tag = msg[0]
            try:
                if tag == "FILE_START":
                    _, worker_id, pkg, rel_path, ts = msg[:5]
                    self.worker_files[worker_id] = (pkg, rel_path, float(ts))
                    self.started_files.add((pkg, rel_path))
                elif tag == "FILE_END":
                    _, worker_id, pkg, rel_path, status = msg[:5]
                    self.worker_files.pop(worker_id, None)
                    if is_infra_status(status):
                        ledger.note_result(pkg, rel_path, status)
                elif tag == "WORKER_EXIT":
                    self.worker_exited.add(msg[1])
                else:
                    _log(f"[主进程] 未知 event 消息: {msg!r}")
            except (IndexError, TypeError, ValueError) as exc:
                _log(f"[主进程] event 消息字段错误 {msg!r}: {exc}")

    def _drain_acks(self, ledger: RunLedger) -> None:
        while True:
            try:
                msg = self.ack_queue.get_nowait()
            except (queue.Empty, OSError, EOFError, ValueError):
                return
            if not isinstance(msg, tuple) or not msg:
                continue
            tag = msg[0]
            if tag == "ACK":
                try:
                    _, pkg, rel_path, status, committed, reason = msg[:6]
                except (IndexError, TypeError) as exc:
                    _log(f"[主进程] ACK 字段错误 {msg!r}: {exc}")
                    continue
                if committed:
                    ledger.note_result(pkg, rel_path, status)
                else:
                    if reason == "miniapp_meta_failed":
                        mapped = STATUS_MINIAPP_META_FAILED
                    else:
                        mapped = STATUS_COMMIT_FAILED
                    ledger.note_result(pkg, rel_path, mapped)
            elif tag == "WRITER_STATS":
                try:
                    self.writer_stats.update(msg[1] or {})
                except (IndexError, TypeError):
                    pass
            else:
                _log(f"[主进程] 未知 ack 消息: {msg!r}")

    def _drain_file_queue(self) -> None:
        while True:
            try:
                self.file_queue.get_nowait()
            except (queue.Empty, OSError, EOFError, ValueError):
                return

    def _drain_all(self, ledger: RunLedger) -> None:
        self._drain_control(ledger)
        self._drain_events(ledger)
        self._drain_acks(ledger)
        ledger.process()

    # ---------- 主循环 ----------
    def _main_loop(self, ledger: RunLedger) -> None:
        while True:
            self._drain_all(ledger)
            self._check_finder()
            self._check_scanners(ledger)
            self._check_writer(ledger)
            self._warn_stalled_workers()

            if self.force_exit_event.is_set():
                return
            if self.stop_event.is_set():
                return
            if self.finder_done and ledger.is_settled():
                return
            try:
                time.sleep(0.2)
            except InterruptedError:
                continue

    def _check_finder(self) -> None:
        proc = self.finder_proc
        if proc is None or proc.is_alive():
            return
        if not self.finder_done and self.finder_error is None and not self.stop_event.is_set():
            self.finder_error = f"Finder 异常退出 (exitcode={proc.exitcode})"
            _log(f"[主进程] {self.finder_error}")
            self.stop_event.set()
        proc.join(timeout=0)

    def _check_scanners(self, ledger: RunLedger) -> None:
        for worker_id in list(self.worker_procs.keys()):
            proc = self.worker_procs[worker_id]
            if proc.is_alive():
                continue
            got_exit = worker_id in self.worker_exited
            if is_worker_crash(
                self.stop_event.is_set(), False, got_exit, proc.exitcode
            ):
                info = self.worker_files.pop(worker_id, None)
                if info is not None:
                    ledger.note_result(info[0], info[1], STATUS_WORKER_CRASH)
                    _log(
                        f"[主进程] Scanner#{worker_id} 崩溃 (exitcode={proc.exitcode})，"
                        f"文件 {info[1]} 记为 {STATUS_WORKER_CRASH}"
                    )
                else:
                    _log(
                        f"[主进程] Scanner#{worker_id} 崩溃 (exitcode={proc.exitcode})"
                    )
                proc.join(timeout=1)
                del self.worker_procs[worker_id]
                self.restart_count += 1
                if self.restart_count > MAX_WORKER_RESTARTS:
                    _log(
                        f"[主进程] Scanner 重启次数超过 {MAX_WORKER_RESTARTS}，进入中止流程"
                    )
                    self.shutdown_issues.append("too_many_worker_restarts")
                    self.stop_event.set()
                    return
                self._next_worker_id += 1
                new_id = self._next_worker_id
                _log(f"[主进程] 拉起新 Scanner#{new_id} 补位")
                self._start_scanner(new_id)
            else:
                proc.join(timeout=0)
                del self.worker_procs[worker_id]

    def _check_writer(self, ledger: RunLedger) -> None:
        proc = self.writer_proc
        if proc is None or proc.is_alive():
            return
        if self.writer_dead or self.stop_event.is_set():
            return
        self.writer_dead = True
        _log(f"[主进程] Writer 意外退出 (exitcode={proc.exitcode})，进入中止流程")
        self.shutdown_issues.append("writer_dead")
        self.writer_dead_event.set()
        self.stop_event.set()
        for pkg, rel_path in ledger.unresolved(self.started_files):
            ledger.note_result(pkg, rel_path, STATUS_WRITER_DEAD)
        ledger.process()

    def _warn_stalled_workers(self) -> None:
        now = time.time()
        limit = self.file_timeout + WORKER_STALL_GRACE
        for worker_id, info in self.worker_files.items():
            if now - info[2] <= limit or worker_id in self.warned_stalled:
                continue
            self.warned_stalled.add(worker_id)
            _log(
                f"[主进程] 告警: Scanner#{worker_id} 在文件 {info[1]} 上停留超过 "
                f"{limit} 秒（只告警，不杀进程）"
            )

    # ---------- 收尾 ----------
    def _shutdown(self, ledger: RunLedger) -> int:
        forced = self.force_exit_event.is_set()
        if forced:
            _log("[主进程] 强制退出：终止所有子进程")
            for proc in self._all_procs():
                _terminate(proc)
            self._drain_all(ledger)
            return EXIT_FORCED

        # 1. stop_event（中止时把 file_queue 读空）
        self.stop_event.set()
        aborting = self.interrupted or bool(self.shutdown_issues) or self.finder_error
        if aborting:
            self._drain_file_queue()

        # 2. join Finder
        if self.finder_proc is not None:
            if not _join_with_drain(
                self.finder_proc, FINDER_JOIN_TIMEOUT, ledger, self,
                drain_file_queue=aborting,
            ):
                _log("[主进程] Finder 未在超时内退出，强制终止")
                _terminate(self.finder_proc)
                self.shutdown_issues.append("finder_terminated")
            if aborting:
                self._drain_file_queue()
        if self.force_exit_event.is_set():
            return EXIT_FORCED

        # 3. join Scanners
        scanner_grace = self.file_timeout + SCANNER_EXIT_GRACE
        for worker_id, proc in list(self.worker_procs.items()):
            if not _join_with_drain(proc, scanner_grace, ledger, self, drain_file_queue=aborting):
                _log(
                    f"[主进程] Scanner#{worker_id} 未在 {scanner_grace} 秒内退出，强制终止；"
                    "result_queue 可能已损坏，本次运行之后不再标记任何包"
                )
                _terminate(proc)
                self.shutdown_issues.append("scanner_terminated")
                ledger.mark_freeze()
            del self.worker_procs[worker_id]
        if aborting:
            self._drain_file_queue()
        if self.force_exit_event.is_set():
            return EXIT_FORCED

        # 4. 所有 Scanner 都退出后才发 STOP，保证 STOP 排在最后
        stop_sent = _put_retry(
            self.result_queue, ("STOP",), None, self.writer_dead_event,
            timeout=1.0, max_wait=60.0,
        )
        if not stop_sent:
            _log("[主进程] 无法把 STOP 送入 result_queue")
            self.shutdown_issues.append("stop_not_sent")

        if self.writer_proc is not None:
            backlog = self.writer_stats.get("data_seen", 0)
            drain_timeout = min(
                WRITER_DRAIN_MAX_TIMEOUT,
                WRITER_DRAIN_BASE_TIMEOUT + (int(backlog) // 1000) * 10,
            )
            if not _join_with_drain(self.writer_proc, drain_timeout, ledger, self):
                _log(f"[主进程] Writer 未在 {drain_timeout} 秒内退出，强制终止")
                _terminate(self.writer_proc)
                self.shutdown_issues.append("writer_terminated")
                self.writer_dead_event.set()
        if self.force_exit_event.is_set():
            return EXIT_FORCED

        # 5. 最后把 ack_queue 读空，能标记的包都标记上
        self._drain_all(ledger)
        self._drain_all(ledger)
        ledger.flush()

        # 6. 停 Monitor
        self.monitor_stop_event.set()
        if self.monitor_proc is not None:
            self.monitor_proc.join(timeout=MONITOR_JOIN_TIMEOUT)
            if self.monitor_proc.is_alive():
                _terminate(self.monitor_proc)

        # 7. 汇总
        self._print_summary(ledger)

        if self.force_exit_event.is_set():
            return EXIT_FORCED
        if self.interrupted:
            return EXIT_INTERRUPTED
        if self.shutdown_issues or self.finder_error or self.writer_dead:
            return EXIT_INTERRUPTED
        return 0

    def _print_summary(self, ledger: RunLedger) -> None:
        total_pkgs = len(ledger.packages)
        completed = len(ledger.completed)
        skipped = ledger.skipped
        print("\n" + "=" * 60)
        print("=== 扫描汇总 ===")
        print(f"包总数(本次参与): {total_pkgs}")
        print(f"已标记完成: {completed}")
        print(f"未完成: {total_pkgs - completed - len(skipped)}")
        for reason, count in sorted(ledger.incomplete_reasons().items()):
            print(f"    {reason}: {count}")
        if skipped:
            print(f"跳过(超长 appid, >{MAX_APPID_LEN}): {len(skipped)}")
            for pkg, reason in skipped[:20]:
                print(f"    {pkg} ({reason})")
            if len(skipped) > 20:
                print(f"    ... 还有 {len(skipped) - 20} 个")
        counts = ledger.file_status_counts()
        print("文件状态统计: " + ", ".join(
            f"{k}={v}" for k, v in sorted(counts.items())
        ) if counts else "文件状态统计: (无)")
        stats = self.writer_stats or {}
        print(
            "Writer 统计: "
            f"成功写入={stats.get('written', 0)}, "
            f"逐条重试失败={stats.get('retry_failed', 0)}, "
            f"miniapp_id 拿不到={stats.get('miniapp_meta_failed', 0)}, "
            f"重连次数={stats.get('reconnects', 0)}, "
            f"批次数={stats.get('batches', 0)}, "
            f"ACK 数={stats.get('acks', 0)}"
        )
        if stats.get("fatal"):
            print("Writer: 致命错误退出")
        if self.shutdown_issues:
            print("收尾问题: " + ", ".join(self.shutdown_issues))
        if self.finder_error:
            print(f"Finder 错误: {self.finder_error}")
        if self.restart_count:
            print(f"Scanner 补位次数: {self.restart_count}")
        print("=" * 60, flush=True)

    # ---------- 入口 ----------
    def run(self) -> int:
        conn = sqlite3.connect(str(self.logdb_path))
        ledger = RunLedger(conn)
        try:
            self.monitor_proc = multiprocessing.Process(
                target=monitor_process_loop,
                args=(self.status_queue, self.monitor_stop_event),
                name="monitor",
            )
            self.monitor_proc.start()

            self.writer_proc = multiprocessing.Process(
                target=db_writer_process,
                args=(
                    self.result_queue,
                    self.ack_queue,
                    self.status_queue,
                    self.db_config,
                    self.dry_run_writer,
                    DEFAULT_BATCH_SIZE,
                    DEFAULT_BATCH_INTERVAL,
                ),
                name="writer",
            )
            self.writer_proc.start()

            for idx in range(self.num_workers):
                self._next_worker_id = idx + 1
                self._start_scanner(idx + 1)

            self.finder_proc = multiprocessing.Process(
                target=file_finder_process,
                args=(
                    self.file_queue,
                    self.control_queue,
                    self.status_queue,
                    self.unpacked_dir,
                    self.logdb_path,
                    self.stop_event,
                ),
                name="finder",
            )
            self.finder_proc.start()

            self._register_signals()
            _log(
                f"[主进程] 启动完成: {self.num_workers} 个 Scanner（每个带 1 个沙箱）+ "
                f"Finder + Writer + Monitor，共约 {2 * self.num_workers + 3} 个进程；"
                f"单文件超时 {self.file_timeout}s；"
                f"{'dry-run（不连数据库）' if self.dry_run_writer else '写入数据库'}"
            )

            self._main_loop(ledger)
            return self._shutdown(ledger)
        finally:
            try:
                conn.close()
            except Exception:  # pylint: disable=broad-except
                pass


def _terminate(proc: Optional[multiprocessing.Process]) -> None:
    if proc is None:
        return
    try:
        if proc.is_alive():
            proc.terminate()
        proc.join(timeout=5)
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=5)
    except Exception:  # pylint: disable=broad-except
        pass


def _join_with_drain(
    proc: multiprocessing.Process,
    timeout: float,
    ledger: RunLedger,
    engine: ScanOrchestrator,
    drain_file_queue: bool = False,
) -> bool:
    """join 一个子进程，一边等一边把控制/事件/回执队列读空。"""
    deadline = time.time() + max(0.0, float(timeout))
    while True:
        if not proc.is_alive():
            proc.join(timeout=1)
            return True
        if time.time() >= deadline:
            return False
        engine._drain_control(ledger)  # pylint: disable=protected-access
        engine._drain_events(ledger)   # pylint: disable=protected-access
        engine._drain_acks(ledger)     # pylint: disable=protected-access
        ledger.process()
        if drain_file_queue:
            engine._drain_file_queue()  # pylint: disable=protected-access
        if engine.force_exit_event.is_set():
            return False
        try:
            proc.join(timeout=0.2)
        except InterruptedError:
            continue


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="微信小程序常量扫描引擎")
    parser.add_argument("--taskpath", default=None)
    parser.add_argument("--source", default=None)
    parser.add_argument("--workers", "-w", type=int, default=None)
    parser.add_argument(
        "--file-timeout", type=int, default=DEFAULT_FILE_TIMEOUT,
        help=f"单文件提取超时秒数（默认 {DEFAULT_FILE_TIMEOUT}）",
    )
    parser.add_argument(
        "--dry-run-writer", action="store_true",
        help="Writer 不连数据库，只消费消息并回 ACK（用于冒烟测试）",
    )
    args = parser.parse_args(argv)

    initialize_config(args.taskpath, args.source, dry_run_writer=args.dry_run_writer)

    if args.workers is not None and args.workers > 0:
        num_scanners = args.workers
    else:
        num_scanners = max(1, multiprocessing.cpu_count() // 2)

    file_timeout = args.file_timeout if args.file_timeout and args.file_timeout > 0 \
        else DEFAULT_FILE_TIMEOUT

    engine = ScanOrchestrator(
        num_workers=num_scanners,
        file_timeout=file_timeout,
        dry_run_writer=args.dry_run_writer,
        unpacked_dir=UNPACKED_PKG_PATH,
        logdb_path=LOGDB_PATH,
        db_config=DB_CONFIG,
        use_smart_filter=USE_SMART_FILTER,
    )
    return engine.run()


if __name__ == "__main__":
    sys.exit(main())
