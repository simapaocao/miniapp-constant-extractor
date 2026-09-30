"""scanner_engine 单测（对应修复计划 2.9 的 11 个场景）。

- 不连 MySQL、不跑真实提取器（扫描函数由 _engine_test_helpers 注入）。
- 所有临时文件都放 pytest 的 tmp_path（系统临时目录下），用完自动清理。
- 每个用例结束都确保子进程被 join / terminate，不留孤儿。
"""

import multiprocessing
import os
import queue
import sqlite3
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import scanner_engine as E  # noqa: E402
import _engine_test_helpers as H  # noqa: E402


# ================= 通用工具 =================
def _child_pids(ppid):
    """返回 ppid 的所有子孙进程 pid（没有 psutil 时返回 None）。"""
    try:
        import psutil  # pylint: disable=import-outside-toplevel
    except ImportError:
        return None
    try:
        return [c.pid for c in psutil.Process(ppid).children(recursive=True)]
    except Exception:  # pylint: disable=broad-except
        return []


def _alive_pids(pids):
    try:
        import psutil  # pylint: disable=import-outside-toplevel
    except ImportError:
        return None
    alive = []
    for pid in pids:
        try:
            if psutil.pid_exists(pid):
                proc = psutil.Process(pid)
                if proc.status() != psutil.STATUS_ZOMBIE:
                    alive.append(pid)
        except Exception:  # pylint: disable=broad-except
            pass
    return alive


class ScannerHarness:
    """起一个真实的 Scanner worker 进程（含沙箱子进程）。"""

    def __init__(self, source_root, tasks, scan_fn, file_timeout=2, worker_id=1):
        self.source_root = source_root
        self.file_queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.event_queue = multiprocessing.Queue()
        self.status_queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()
        self.writer_dead_event = multiprocessing.Event()
        for task in tasks:
            self.file_queue.put(task)
        self.proc = multiprocessing.Process(
            target=E.file_scanner_process,
            args=(
                worker_id,
                self.file_queue,
                self.result_queue,
                self.event_queue,
                self.status_queue,
                source_root,
                False,
                self.stop_event,
                self.writer_dead_event,
                file_timeout,
                scan_fn,
            ),
            name=f"test-scanner-{worker_id}",
        )
        self.proc.start()
        self.seen_events = []

    def wait_event(self, tag, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = self.event_queue.get(timeout=0.2)
            except queue.Empty:
                if not self.proc.is_alive():
                    # 进程已退出，把管道里剩下的读干净
                    try:
                        msg = self.event_queue.get_nowait()
                    except queue.Empty:
                        continue
                else:
                    continue
            self.seen_events.append(msg)
            if msg and msg[0] == tag:
                return msg
        raise AssertionError(
            f"等待事件 {tag} 超时；已收到 {self.seen_events!r}"
        )

    def drain_results(self):
        out = []
        while True:
            try:
                out.append(self.result_queue.get_nowait())
            except queue.Empty:
                return out

    def shutdown(self, timeout=10.0):
        """确保 worker 退出；返回 True 表示干净退出。"""
        self.stop_event.set()
        self.proc.join(timeout=timeout)
        if self.proc.is_alive():
            self.proc.terminate()
            self.proc.join(timeout=5)
            return False
        return True


# ================= 场景 1: 沙箱超时 =================
def test_sandbox_timeout_then_recovers(tmp_path):
    (tmp_path / "a_slow.js").write_text("x", encoding="utf-8")
    (tmp_path / "b_fast.js").write_text("x", encoding="utf-8")
    harness = ScannerHarness(
        tmp_path,
        [("pkg1", "a_slow.js", "js"), ("pkg1", "b_fast.js", "js")],
        H.scan_slow_for_slow_names,
        file_timeout=2,
    )
    try:
        started = time.time()
        first = harness.wait_event("FILE_END", timeout=25)
        first_elapsed = time.time() - started
        second = harness.wait_event("FILE_END", timeout=25)
        assert first[3] == "a_slow.js"
        assert first[4] == "timeout", first
        assert 1.5 <= first_elapsed <= 6.0, f"超时响应耗时异常: {first_elapsed:.2f}s"
        # 超时之后沙箱被重启，下一个文件能正常处理
        assert second[3] == "b_fast.js"
        assert second[4] == "ok", second
        results = harness.drain_results()
        done = [m for m in results if m[0] == "FILE_DONE"]
        assert ("FILE_DONE", "pkg1", "b_fast.js", str(tmp_path / "b_fast.js"), "ok") in done
        # 超时的文件只回 FILE_DONE(timeout)，不产生 DATA
        assert any(
            m == ("FILE_DONE", "pkg1", "a_slow.js", str(tmp_path / "a_slow.js"), "timeout")
            for m in done
        )
    finally:
        assert harness.shutdown(), "Scanner worker 未退出"


# ================= 场景 2: 卡在持有 GIL 的正则上 =================
def test_sandbox_timeout_on_catastrophic_regex(tmp_path):
    (tmp_path / "a_regex.js").write_text("x", encoding="utf-8")
    (tmp_path / "b_fast.js").write_text("x", encoding="utf-8")
    harness = ScannerHarness(
        tmp_path,
        [("pkg1", "a_regex.js", "js"), ("pkg1", "b_fast.js", "js")],
        H.scan_catastrophic_regex,
        file_timeout=2,
    )
    try:
        started = time.time()
        first = harness.wait_event("FILE_END", timeout=25)
        elapsed = time.time() - started
        second = harness.wait_event("FILE_END", timeout=25)
        assert first[3] == "a_regex.js"
        assert first[4] == "timeout", first
        assert elapsed <= 6.0, f"正则回溯超时响应耗时异常: {elapsed:.2f}s"
        assert second[3] == "b_fast.js"
        assert second[4] == "ok", second
    finally:
        assert harness.shutdown(), "Scanner worker 未退出"


# ================= 场景 3: 中止响应 =================
def test_stop_event_aborts_running_file_and_reaps_sandbox(tmp_path):
    (tmp_path / "a_slow.js").write_text("x", encoding="utf-8")
    harness = ScannerHarness(
        tmp_path,
        [("pkg1", "a_slow.js", "js")],
        H.scan_always_slow,
        file_timeout=360,
    )
    try:
        harness.wait_event("FILE_START", timeout=20)
        sandbox_pids = _child_pids(harness.proc.pid) or []
        started = time.time()
        harness.stop_event.set()
        end = harness.wait_event("FILE_END", timeout=10)
        assert end[3] == "a_slow.js"
        assert end[4] == "aborted", end

        harness.proc.join(timeout=6)
        exit_elapsed = time.time() - started
        assert not harness.proc.is_alive(), "stop_event 置位后 worker 没有退出"
        assert exit_elapsed < 2.0, f"中止响应太慢: {exit_elapsed:.2f}s"

        # 沙箱子进程已经被回收
        if sandbox_pids:
            time.sleep(0.5)
            still_alive = _alive_pids(sandbox_pids)
            assert still_alive == [], f"沙箱进程没有被回收: {still_alive}"
        assert harness.drain_results() == []
    finally:
        assert harness.shutdown(), "Scanner worker 未退出"


# ================= 场景 4: RunLedger 记账 =================
@pytest.fixture(name="ledger_env")
def ledger_env_fixture(tmp_path):
    db_path = tmp_path / "scanned_wxpkg.db"
    E.init_sqlite_log2db(db_path)
    conn = sqlite3.connect(str(db_path))
    ledger = E.RunLedger(conn, log_fn=lambda _m: None)
    try:
        yield db_path, conn, ledger
    finally:
        conn.close()


def _query(db_path, sql, params=()):
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def test_run_ledger_500_packages_completed(ledger_env):
    db_path, _conn, ledger = ledger_env
    for i in range(500):
        pkg = f"wx{i:016x}"
        ledger.note_pkg_dispatched(pkg, 2)
        ledger.note_result(pkg, "pages/p0.js", "ok")
        ledger.note_result(pkg, "pages/p1.js", "empty")
    ledger.process()
    ledger.flush()

    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(500,)]
    assert _query(db_path, "SELECT COUNT(*) FROM scan_failures") == [(0,)]
    assert len(ledger.completed) == 500
    assert ledger.is_settled() is True


def test_run_ledger_timeout_marks_file_failure_but_completes(ledger_env):
    db_path, _conn, ledger = ledger_env
    ledger.note_pkg_dispatched("pkgA", 2)
    ledger.note_result("pkgA", "a.js", "ok")
    ledger.note_result("pkgA", "b.js", "timeout")
    ledger.process()
    ledger.flush()

    assert _query(db_path, "SELECT file_path FROM scanned_files") == [("pkgA",)]
    assert _query(
        db_path, "SELECT pkg_name, rel_path, status, kind FROM scan_failures"
    ) == [("pkgA", "b.js", "timeout", "file")]


def test_run_ledger_extract_error_recorded_but_completes(ledger_env):
    """error:extract:* 是文件级失败：包照常完成，但要写进 scan_failures 便于排查。"""
    db_path, _conn, ledger = ledger_env
    ledger.note_pkg_dispatched("pkgX", 2)
    ledger.note_result("pkgX", "a.js", "ok")
    ledger.note_result("pkgX", "big.js", "error:extract:MemoryError")
    ledger.process()
    ledger.flush()

    assert _query(db_path, "SELECT file_path FROM scanned_files") == [("pkgX",)]
    assert _query(
        db_path, "SELECT pkg_name, rel_path, status, kind FROM scan_failures"
    ) == [("pkgX", "big.js", "error:extract:MemoryError", "file")]


def test_run_ledger_commit_failed_blocks_package(ledger_env):
    db_path, _conn, ledger = ledger_env
    ledger.note_pkg_dispatched("pkgB", 1)
    ledger.note_result("pkgB", "a.js", E.STATUS_COMMIT_FAILED)
    ledger.process()
    ledger.flush()

    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]
    assert _query(
        db_path, "SELECT pkg_name, rel_path, status, kind FROM scan_failures"
    ) == [("pkgB", "a.js", "error:commit_failed", "infra")]
    assert "pkgB" not in ledger.completed


def test_run_ledger_ack_reason_mapping(ledger_env):
    db_path, _conn, ledger = ledger_env
    # 主进程收到 ACK(committed=False, reason='miniapp_meta_failed')
    ledger.note_pkg_dispatched("pkgMeta", 1)
    ledger.note_result("pkgMeta", "a.js", E.STATUS_MINIAPP_META_FAILED)
    # 其它 reason 一律记 commit_failed
    ledger.note_pkg_dispatched("pkgCommit", 1)
    ledger.note_result("pkgCommit", "a.js", E.STATUS_COMMIT_FAILED)
    ledger.process()
    ledger.flush()

    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]
    rows = dict(
        (r[0], (r[1], r[2]))
        for r in _query(db_path, "SELECT pkg_name, status, kind FROM scan_failures")
    )
    assert rows["pkgMeta"] == ("error:miniapp_meta_failed", "infra")
    assert rows["pkgCommit"] == ("error:commit_failed", "infra")


@pytest.mark.parametrize("order", ["ack_first", "crash_first"])
def test_run_ledger_duplicate_relpath_infra_wins(ledger_env, order):
    db_path, _conn, ledger = ledger_env
    pkg = f"pkg-{order}"
    ledger.note_pkg_dispatched(pkg, 2)
    if order == "ack_first":
        ledger.note_result(pkg, "a.js", "ok")
        ledger.note_result(pkg, "a.js", E.STATUS_WORKER_CRASH)
    else:
        ledger.note_result(pkg, "a.js", E.STATUS_WORKER_CRASH)
        ledger.note_result(pkg, "a.js", "ok")

    # 同一个 rel_path 只算一个文件，且最终是基础设施类
    assert ledger.packages[pkg]["results"] == {"a.js": E.STATUS_WORKER_CRASH}
    ledger.process()
    ledger.flush()

    # 另一个文件还没有结果 -> 包不能被判为完成
    assert ledger.is_settled() is False
    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]
    assert _query(
        db_path, "SELECT COUNT(*) FROM scan_failures WHERE pkg_name = ?", (pkg,)
    ) == [(1,)]

    # 补齐第二个文件后依然不能完成（有基础设施问题）
    ledger.note_result(pkg, "b.js", "ok")
    ledger.process()
    ledger.flush()
    assert ledger.is_settled() is True
    assert pkg not in ledger.completed
    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]


def test_run_ledger_infra_status_not_overwritten_by_late_ok(ledger_env):
    db_path, _conn, ledger = ledger_env
    ledger.note_pkg_dispatched("pkgLate", 1)
    ledger.note_result("pkgLate", "a.js", E.STATUS_WRITER_DEAD)
    ledger.note_result("pkgLate", "a.js", "ok")
    ledger.note_result("pkgLate", "a.js", "empty")
    ledger.process()
    ledger.flush()
    assert ledger.packages["pkgLate"]["results"] == {"a.js": E.STATUS_WRITER_DEAD}
    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]


def test_run_ledger_partial_package_not_completed(ledger_env):
    db_path, _conn, ledger = ledger_env
    ledger.note_pkg_partial("pkgPartial", 3)
    for i in range(3):
        ledger.note_result("pkgPartial", f"f{i}.js", "ok")
    ledger.process()
    ledger.flush()
    assert ledger.is_settled() is True          # 入队的部分都出结果了
    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]
    assert "pkgPartial" not in ledger.completed
    assert ledger.incomplete_reasons() == {"partial_dispatched": 1}


def test_run_ledger_skipped_package_not_completed(ledger_env):
    db_path, _conn, ledger = ledger_env
    long_pkg = "w" * 40
    ledger.note_pkg_skipped(long_pkg, "appid_too_long")
    ledger.process()
    ledger.flush()

    assert _query(db_path, "SELECT COUNT(*) FROM scanned_files") == [(0,)]
    assert _query(
        db_path, "SELECT pkg_name, rel_path, status, kind FROM scan_failures"
    ) == [(long_pkg, "", "appid_too_long", "infra")]
    assert ledger.skipped == [(long_pkg, "appid_too_long")]
    assert ledger.is_settled() is True
    assert long_pkg not in ledger.completed


def test_run_ledger_empty_package_completed_immediately(ledger_env):
    db_path, _conn, ledger = ledger_env
    ledger.note_pkg_empty("pkgEmpty")
    newly = ledger.process()
    ledger.flush()
    assert newly == ["pkgEmpty"]
    assert _query(db_path, "SELECT file_path FROM scanned_files") == [("pkgEmpty",)]
    assert _query(db_path, "SELECT COUNT(*) FROM scan_failures") == [(0,)]


def test_run_ledger_completion_clears_stale_infra_failure(ledger_env):
    db_path, _conn, ledger = ledger_env
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO scan_failures(pkg_name, rel_path, status, kind) VALUES (?,?,?,?)",
            ("pkgStale", "old.js", E.STATUS_WRITER_DEAD, "infra"),
        )
        conn.commit()
    finally:
        conn.close()

    ledger.note_pkg_dispatched("pkgStale", 1)
    ledger.note_result("pkgStale", "a.js", "ok")
    ledger.process()
    ledger.flush()
    assert _query(db_path, "SELECT file_path FROM scanned_files") == [("pkgStale",)]
    assert _query(db_path, "SELECT COUNT(*) FROM scan_failures") == [(0,)]


# ================= 场景 5: Finder 跳过超长包名 =================
def _collect_control(control_queue, proc, timeout=25.0):
    msgs = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            msg = control_queue.get(timeout=0.2)
        except queue.Empty:
            if not proc.is_alive():
                time.sleep(0.2)
                try:
                    while True:
                        msgs.append(control_queue.get_nowait())
                except queue.Empty:
                    pass
                break
            continue
        msgs.append(msg)
        if msg and msg[0] == "FINDER_DONE":
            break
    return msgs


def test_finder_skips_appid_too_long(tmp_path):
    root = tmp_path / "wxpkg-unpacked"
    long_pkg = "w" * 40
    (root / long_pkg).mkdir(parents=True)
    (root / long_pkg / "a.js").write_text("x", encoding="utf-8")
    ok_pkg = "wx1234567890abcdef"
    (root / ok_pkg).mkdir()
    (root / ok_pkg / "b.js").write_text("x", encoding="utf-8")

    file_queue = multiprocessing.Queue(maxsize=100)
    control_queue = multiprocessing.Queue()
    status_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    proc = multiprocessing.Process(
        target=E.file_finder_process,
        args=(
            file_queue, control_queue, status_queue, root,
            tmp_path / "nonexistent.db", stop_event,
        ),
    )
    proc.start()
    try:
        msgs = _collect_control(control_queue, proc)
        proc.join(timeout=10)
        assert not proc.is_alive(), "Finder 没有退出"

        assert ("PKG_SKIPPED", long_pkg, "appid_too_long") in msgs, msgs
        assert not any(
            m[0] == "PKG_DISPATCHED" and m[1] == long_pkg for m in msgs
        ), msgs

        queued = []
        while True:
            try:
                queued.append(file_queue.get_nowait())
            except queue.Empty:
                break
        assert all(item[0] != long_pkg for item in queued), queued
        assert any(item[0] == ok_pkg for item in queued), queued
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)


# ================= 场景 6: worker 正常退出不算崩溃（纯函数） =================
@pytest.mark.parametrize(
    "stop_set,shutting_down,got_exit,exitcode,expected",
    [
        (True, False, False, 1, False),      # 停止中退出
        (False, True, False, 1, False),      # 收尾阶段退出
        (False, False, True, 1, False),      # 发了 WORKER_EXIT
        (False, False, False, 0, False),     # 正常退出
        (False, False, False, None, False),  # 还在跑
        (False, False, False, 1, True),      # 真崩溃
        (False, False, False, -15, True),    # 被信号杀死
    ],
)
def test_is_worker_crash(stop_set, shutting_down, got_exit, exitcode, expected):
    assert E.is_worker_crash(stop_set, shutting_down, got_exit, exitcode) is expected


# ================= 场景 7: Writer 重连 =================
def test_writer_reconnects_after_disconnect_and_retries_batch():
    db, conn = H.make_fake_db()
    db.fail_executemany_once = True
    db.rollback_raises = True          # rollback 自己也炸，必须被吞掉
    adapter = E.DbAdapter(conn, H.FakeCursor(db), log_fn=lambda _m: None,
                          sleep_fn=lambda _s: None)
    core = E.WriterCore(adapter, batch_size=100, log_fn=lambda _m: None)

    content = "https://api.example.com/v1/login"
    core.handle_message(H.make_data_msg("wxapp", content, "/tmp/app.js"))
    core.handle_message(H.make_file_done("wxapp", "app.js", "/tmp/app.js"))

    acks = core.finish()          # 不允许向外抛异常
    assert len(acks) == 1
    ack = acks[0]
    assert ack[0] == "ACK" and ack[1] == "wxapp" and ack[2] == "app.js"
    assert ack[4] is True, ack
    assert ack[5] == ""

    assert H.sha256(content) in db.data_items
    assert db.pings == 1, "应当调用过 ping(reconnect=True)"
    assert db.rollbacks >= 1, "断线时应当尝试过 rollback"
    assert adapter.reconnect_count == 1
    assert db.relations, "关联行也应该写进去了"


# ================= 场景 8: Writer ACK 顺序 + 写失败 =================
def test_writer_ack_order_and_failed_row():
    db, conn = H.make_fake_db()
    adapter = E.DbAdapter(conn, H.FakeCursor(db), log_fn=lambda _m: None,
                          sleep_fn=lambda _s: None)
    core = E.WriterCore(adapter, batch_size=2, log_fn=lambda _m: None)

    c_a1 = "https://a1.example.com/x"
    c_a2 = "https://a2.example.com/x"
    c_bad = "https://bad.example.com/x"
    db.fail_hashes.add(H.sha256(c_bad))

    # DATA, DATA, FILE_DONE(A), DATA, FILE_DONE(B)
    assert core.handle_message(H.make_data_msg("pkgA", c_a1, "/t/a.js")) == []
    assert core.handle_message(H.make_data_msg("pkgA", c_a2, "/t/a.js")) == []
    # 第二条 DATA 触发批满 -> 提交 A 的两条（此时还没有 FILE_DONE，不发 ACK）
    assert db.commit_index_containing(H.sha256(c_a1)) >= 0
    assert db.ack_index("a.js") == -1

    assert core.handle_message(H.make_file_done("pkgA", "a.js", "/t/a.js")) == []
    assert core.handle_message(H.make_data_msg("pkgB", c_bad, "/t/b.js")) == []
    assert core.handle_message(H.make_file_done("pkgB", "b.js", "/t/b.js")) == []
    # FILE_DONE 不会立刻产生 ACK
    assert db.ack_index("a.js") == -1
    assert db.ack_index("b.js") == -1

    acks = core.finish()
    for ack in acks:
        db.log_ack(ack[2])
    by_rel = {ack[2]: ack for ack in acks}

    assert set(by_rel) == {"a.js", "b.js"}
    assert by_rel["a.js"][4] is True, by_rel["a.js"]
    assert by_rel["b.js"][4] is False, by_rel["b.js"]
    assert by_rel["b.js"][5] == "commit_failed"
    assert by_rel["b.js"][3] == "ok"          # 文件级状态原样带回

    # 两个文件的 ACK 都在各自批次提交之后才发出
    a_commit = db.commit_index_containing(H.sha256(c_a1))
    assert a_commit >= 0
    assert db.ack_index("a.js") > a_commit
    bad_fail = db.op_log.index(f"fail:data_item:{H.sha256(c_bad)}")
    assert bad_fail < db.ack_index("b.js")
    assert H.sha256(c_bad) not in db.data_items


def test_writer_ack_for_file_without_data():
    db, conn = H.make_fake_db()
    adapter = E.DbAdapter(conn, H.FakeCursor(db), log_fn=lambda _m: None,
                          sleep_fn=lambda _s: None)
    core = E.WriterCore(adapter, batch_size=10, log_fn=lambda _m: None)
    core.handle_message(H.make_file_done("pkgT", "slow.js", "/t/slow.js", "timeout"))
    acks = core.finish()
    assert len(acks) == 1
    assert acks[0][3] == "timeout"
    assert acks[0][4] is True      # 没有数据要写，等价于全部写成功
    assert acks[0][5] == ""


def test_writer_miniapp_meta_failed_reports_reason():
    db, conn = H.make_fake_db()
    adapter = E.DbAdapter(conn, H.FakeCursor(db), log_fn=lambda _m: None,
                          sleep_fn=lambda _s: None)
    core = E.WriterCore(adapter, batch_size=10, log_fn=lambda _m: None)
    long_appid = "w" * 40
    db.fail_appids.add(long_appid)
    core.handle_message(H.make_data_msg(long_appid, "https://x.example.com/y", "/t/a.js"))
    core.handle_message(H.make_file_done(long_appid, "a.js", "/t/a.js"))
    acks = core.finish()
    assert len(acks) == 1
    assert acks[0][4] is False
    assert acks[0][5] == "miniapp_meta_failed"


# ================= 场景 9: dry-run Writer =================
def test_writer_dry_run_acks_without_db():
    core = E.WriterCore(None, dry_run=True, log_fn=lambda _m: None)
    assert core.handle_message(H.make_data_msg("pkg1", "https://a.example.com/x", "/t/a.js")) == []
    assert core.handle_message(H.make_file_done("pkg1", "a.js", "/t/a.js", "ok")) == []
    acks = core.finish()
    assert len(acks) == 1
    assert acks[0] == ("ACK", "pkg1", "a.js", "ok", True, "")

    core.handle_message(H.make_file_done("pkg2", "b.js", "/t/b.js", "timeout"))
    core.handle_message(H.make_file_done("pkg2", "c.js", "/t/c.js", "empty"))
    acks = core.finish()
    assert {a[2]: a[3] for a in acks} == {"b.js": "timeout", "c.js": "empty"}
    assert all(a[4] is True for a in acks)
    assert core.stats["data_seen"] == 1
    assert core.stats["acks"] == 3


def test_initialize_config_dry_run_does_not_require_constant_db(tmp_path, monkeypatch):
    """--dry-run-writer 时 initialize_config 跳过 init_constant_db。"""
    called = {"init_db": 0}

    def fake_init_constant_db(_cfg):
        called["init_db"] += 1

    monkeypatch.setattr(E, "init_constant_db", fake_init_constant_db)
    E.initialize_config(str(tmp_path), str(tmp_path), dry_run_writer=True)
    assert called["init_db"] == 0
    assert E.LOGDB_PATH is not None and Path(E.LOGDB_PATH).exists()


# ================= 场景 10: 队列生命周期 =================
def test_finder_exits_on_stop_with_partial(tmp_path):
    root = tmp_path / "wxpkg-unpacked"
    pkg = root / "wx1234567890abcdef"
    pkg.mkdir(parents=True)
    for i in range(300):
        (pkg / f"f{i:03d}.js").write_text("x", encoding="utf-8")

    # 故意用很小的队列并且不消费，Finder 会阻塞在 put 上
    file_queue = multiprocessing.Queue(maxsize=5)
    control_queue = multiprocessing.Queue()
    status_queue = multiprocessing.Queue()
    stop_event = multiprocessing.Event()
    proc = multiprocessing.Process(
        target=E.file_finder_process,
        args=(
            file_queue, control_queue, status_queue, root,
            tmp_path / "nonexistent.db", stop_event,
        ),
    )
    started = time.time()
    proc.start()
    try:
        time.sleep(1.0)
        stop_event.set()
        msgs = _collect_control(control_queue, proc, timeout=10)
        proc.join(timeout=10)
        elapsed = time.time() - started

        assert not proc.is_alive(), "停止后 Finder 没有退出"
        assert elapsed < 10.0, f"Finder 退出耗时 {elapsed:.1f}s"
        assert any(m[0] == "PKG_PARTIAL" for m in msgs), msgs
        assert any(m[0] == "FINDER_DONE" for m in msgs), msgs
    finally:
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)


def test_put_retry_gives_up_when_stop_set():
    q = multiprocessing.Queue(maxsize=1)
    stop_event = multiprocessing.Event()
    assert E._put_retry(q, ("x",), stop_event) is True
    stop_event.set()
    assert E._put_retry(q, ("y",), stop_event) is False


# ================= 场景 11: html 分派 =================
def test_perform_scan_dispatches_html(monkeypatch, tmp_path):
    import extract_html_consts
    import constants_filter
    import constants_classifier

    html = tmp_path / "page.html"
    html.write_text("<html><script>var a=1</script></html>", encoding="utf-8")

    called = []

    def fake_extract(path):
        called.append(path)
        return {"statements": ["stmt"], "constants": [("https://h.example.com/x", 0, "html")]}

    def fake_filter(statements, constants, use_smart_filter=False):
        return {"statements": statements, "constants": constants}

    def fake_classify(statements, constants):
        return [(7, "https://h.example.com/x", "html-script", "snippet")]

    monkeypatch.setattr(extract_html_consts, "extract_from_html_file", fake_extract)
    monkeypatch.setattr(constants_filter, "perform_constant_filtering", fake_filter)
    monkeypatch.setattr(constants_classifier, "perform_constant_classifying", fake_classify)

    findings, status = E.perform_scan(str(html), "html", False)
    assert called == [str(html)]
    assert status == "ok"
    assert len(findings) == 1
    assert findings[0][4] == str(html)
    assert "html" in E.SCAN_EXTS


def test_perform_scan_html_too_large_skipped(monkeypatch, tmp_path):
    import extract_html_consts

    big = tmp_path / "big.html"
    big.write_bytes(b"<html></html>" + b" " * (E.MAX_HTML_BYTES + 10))

    called = []

    def fake_extract(path):  # pragma: no cover - 不应被调用
        called.append(path)
        return {"statements": [], "constants": []}

    monkeypatch.setattr(extract_html_consts, "extract_from_html_file", fake_extract)
    findings, status = E.perform_scan(str(big), "html", False)
    assert status == "skipped_too_large"
    assert findings == []
    assert called == []


def test_perform_scan_missing_file(tmp_path):
    """文件不存在时直接返回 missing（html 分支的 size 检查，不触发任何提取器 import）。"""
    missing = tmp_path / "not-here.html"
    findings, status = E.perform_scan(str(missing), "html", False)
    assert status == "missing"
    assert findings == []


# ================= 其它：状态分类 =================
def test_process_targets_are_picklable():
    """spawn 下所有进程入口和注入的扫描函数都必须能被 pickle。"""
    import pickle

    for fn in (
        E.perform_scan,
        E.file_scanner_process,
        E.db_writer_process,
        E.file_finder_process,
        E.monitor_process_loop,
        E.sandbox_process,
        H.scan_always_ok,
        H.scan_slow_for_slow_names,
        H.scan_catastrophic_regex,
    ):
        assert pickle.loads(pickle.dumps(fn)) is fn


def test_status_classification():
    for status in (
        E.STATUS_RESULT_QUEUE_FULL,
        E.STATUS_WORKER_CRASH,
        E.STATUS_COMMIT_FAILED,
        E.STATUS_MINIAPP_META_FAILED,
        E.STATUS_WRITER_DEAD,
        E.STATUS_ABORTED,
    ):
        assert E.is_infra_status(status) is True
        assert E.is_pkg_completable_status(status) is False
    for status in (
        E.STATUS_OK,
        E.STATUS_EMPTY,
        E.STATUS_TIMEOUT,
        E.STATUS_SKIPPED_TOO_LARGE,
        E.STATUS_MISSING,
        E.STATUS_SANDBOX_CRASH,
        "error:extract:ValueError",
    ):
        assert E.is_infra_status(status) is False
        assert E.is_pkg_completable_status(status) is True
