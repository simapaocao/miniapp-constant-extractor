"""scanner_engine 单测用的辅助模块。

这里的扫描函数必须是**模块级函数**（multiprocessing spawn 下要能被 pickle），
测试通过注入它们来验证沙箱超时 / 中止逻辑，不调用真实提取器。

FakeDb 是极简的假 MySQL，只认识 WriterCore 用到的那几条 SQL，
用来在没有数据库的情况下验证 Writer 的重连、批量提交和 ACK 顺序。
"""

import hashlib
import os
import re
import time

import pymysql


# ================= 注入用的扫描函数（模块级，可被 spawn pickle） =================
def scan_slow_for_slow_names(file_path, ext, use_smart_filter):
    """文件名里带 "slow" 的睡 30 秒；其它文件立刻返回一条 finding。"""
    if "slow" in os.path.basename(file_path):
        time.sleep(30)
        return [], "ok"
    content = "https://fast.example.com/" + os.path.basename(file_path)
    return [(1, 2, 3, content, str(file_path), "js", "snippet")], "ok"


def scan_catastrophic_regex(file_path, ext, use_smart_filter):
    """文件名里带 "regex" 的触发 re 灾难性回溯（持有 GIL，线程 join 等不到）。"""
    if "regex" in os.path.basename(file_path):
        re.match(r"(a+)+$", "a" * 40 + "!")
        return [], "ok"
    return [(1, 2, 3, "https://fast.example.com/ok", str(file_path), "js", "snippet")], "ok"


def scan_always_ok(file_path, ext, use_smart_filter):
    return [], "ok"


def scan_always_slow(file_path, ext, use_smart_filter):
    time.sleep(30)
    return [], "ok"


def scan_raises(file_path, ext, use_smart_filter):
    raise ValueError("boom")


# ================= 假数据库 =================
class FakeCursor:
    def __init__(self, db):
        self.db = db

    def execute(self, sql, args=None):
        return self.db.execute(sql, args)

    def executemany(self, sql, seq):
        return self.db.executemany(sql, seq)

    def fetchall(self):
        return self.db.fetchall()

    def fetchone(self):
        return self.db.fetchone()

    def close(self):
        pass


class FakeConn:
    def __init__(self, db):
        self.db = db

    def cursor(self):
        return FakeCursor(self.db)

    def commit(self):
        return self.db.commit()

    def rollback(self):
        return self.db.rollback()

    def ping(self, reconnect=False):
        return self.db.ping(reconnect=reconnect)

    def close(self):
        pass


class FakeDb:
    """极简假 MySQL：建模 miniapp_meta / data_item / miniapp_to_dataitem。"""

    def __init__(self):
        self.miniapp_meta = {}      # appid -> id
        self.data_items = {}        # hash -> dict
        self.relations = []         # list of tuple
        self.op_log = []            # 事务/回执事件序列
        self.fail_hashes = set()    # 这些 hash 的 data_item 写入永远失败
        self.fail_appids = set()    # 这些 appid 的 miniapp_meta 处理失败
        self.fail_executemany_once = False
        self.rollback_raises = False
        self.ping_raises = False
        self.commits = 0
        self.rollbacks = 0
        self.pings = 0
        self._next_data_item_id = 1
        self._next_miniapp_id = 1
        self._staged = []
        self._result = []
        self._one = None

    # ---------- 内部 ----------
    def _fail(self, msg="fake failure"):
        raise pymysql.err.OperationalError(2006, msg)

    def _stage(self, tag):
        self._staged.append(tag)

    def _insert_data_item(self, args):
        type_id, raw_value, hash_sha256 = args[0], args[1], args[2]
        if hash_sha256 in self.fail_hashes:
            self.op_log.append(f"fail:data_item:{hash_sha256}")
            self._fail(f"data_item 写入失败: {hash_sha256[:8]}")
        item = self.data_items.get(hash_sha256)
        if item is None:
            item = {
                "id": self._next_data_item_id,
                "type_id": type_id,
                "raw_value": raw_value,
                "ref_count": 1,
            }
            self._next_data_item_id += 1
            self.data_items[hash_sha256] = item
        else:
            item["ref_count"] += 1
        self._stage(f"data_item:{hash_sha256}")

    def _insert_relation(self, args):
        miniapp_id, data_item_id, source_file, detector_source, snippet = args[:5]
        self.relations.append(tuple(args[:5]))
        self._stage(f"relation:{miniapp_id}:{data_item_id}:{source_file}")

    # ---------- 假 DB 接口 ----------
    def execute(self, sql, args=None):
        s = " ".join(sql.split())
        args = tuple(args or ())
        if s.startswith("INSERT INTO data_item"):
            self._insert_data_item(args)
            return 1
        if s.startswith("SELECT id, hash_sha256 FROM data_item"):
            wanted = set(args)
            self._result = [
                (v["id"], h) for h, v in self.data_items.items() if h in wanted
            ]
            return len(self._result)
        if s.startswith("INSERT INTO miniapp_meta"):
            appid = args[0]
            if appid in self.fail_appids:
                self._fail(f"miniapp_meta 失败: {appid}")
            if appid not in self.miniapp_meta:
                self.miniapp_meta[appid] = self._next_miniapp_id
                self._next_miniapp_id += 1
            self._stage(f"miniapp_meta:{appid}")
            return 1
        if s.startswith("SELECT id FROM miniapp_meta"):
            appid = args[0]
            mid = self.miniapp_meta.get(appid)
            self._one = (mid,) if mid else None
            return 1 if mid else 0
        if s.startswith("INSERT INTO miniapp_to_dataitem"):
            self._insert_relation(args)
            return 1
        raise AssertionError(f"FakeDb 不认识的 SQL: {sql}")

    def executemany(self, sql, seq):
        rows = list(seq)
        s = " ".join(sql.split())
        if s.startswith("INSERT INTO data_item") and self.fail_executemany_once:
            self.fail_executemany_once = False
            self._fail("第一次 executemany 断线")
        for row in rows:
            self.execute(sql, row)
        return len(rows)

    def fetchall(self):
        return list(self._result)

    def fetchone(self):
        return self._one

    def commit(self):
        self.commits += 1
        self.op_log.append("commit:" + ",".join(self._staged))
        self._staged = []

    def rollback(self):
        self.rollbacks += 1
        self.op_log.append("rollback")
        if self.rollback_raises:
            raise RuntimeError("rollback 也炸了")
        self._staged = []

    def ping(self, reconnect=False):
        self.pings += 1
        if self.ping_raises:
            raise pymysql.err.OperationalError(2003, "ping 失败")
        return None

    # ---------- 断言辅助 ----------
    def commit_index_containing(self, token):
        """返回第一个包含 token 的 commit 事件下标。"""
        for idx, entry in enumerate(self.op_log):
            if entry.startswith("commit:") and token in entry:
                return idx
        return -1

    def log_ack(self, rel_path):
        self.op_log.append(f"ack:{rel_path}")

    def ack_index(self, rel_path):
        for idx, entry in enumerate(self.op_log):
            if entry == f"ack:{rel_path}":
                return idx
        return -1


def make_fake_db():
    """返回 (FakeDb, FakeConn)，FakeConn 与 FakeDb 共享同一份状态。"""
    db = FakeDb()
    return db, FakeConn(db)


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_data_msg(pkg, content, source_file, slug_id=1, kind_id=1, risk=1):
    """构造一条 ('DATA', ...) 消息（tag + 8 元组 finding）。"""
    return (
        "DATA",
        pkg,
        kind_id,
        slug_id,
        risk,
        content,
        source_file,
        "js",
        "snippet",
    )


def make_file_done(pkg, rel_path, source_file, status="ok"):
    return ("FILE_DONE", pkg, rel_path, source_file, status)
