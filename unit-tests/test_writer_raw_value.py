"""Writer 的 raw_value / hash_sha256 一致性验证（fix11 问题②）。

背景
----
WriterCore._write_batch 原先存 `content[:1000]`（按**字符**截断）却用 `sha256(全文)`
算 hash —— 库里存的 raw_value 与它自己的 hash_sha256 对不上，且 >1000 的真值被砍成
残缺串（PEM 私钥实测最长 4220 字符）。修复：放宽到 TEXT 列的**字节**上限
（scanner_engine.TEXT_COLUMN_SAFE_BYTES），且只截 raw_value、**绝不**用截断值算 hash。

本文件把「去重仍然正确」固化成断言：
  1) 相同值必须合并成一条 data_item（ref_count 累加）；
  2) 不同值绝不能被合并成一条 —— 尤其「前 1000 字符相同、只有尾部不同」的值对
     （库里实测有 56 个这种值；若按截断值算 hash 就会被错误合并）；
  3) raw_value 与 hash_sha256 的对应关系：
        · 值 <= 上限       -> raw_value == 全文 且 hash == sha256(全文)
        · 值 > 上限        -> raw_value 是全文前缀，hash 仍是 sha256(全文)
  4) 上限按**字节**收口（utf8mb4 下 `s[:65000]` 对多字节内容是 195000 字节，仍会撑爆 TEXT）。

用法: python -X utf8 -m pytest unit-tests/test_writer_raw_value.py -q
"""

import hashlib
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import scanner_engine as E  # noqa: E402
import _engine_test_helpers as H  # noqa: E402


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _core():
    """建一个接了假 DB 的 WriterCore（不连真库）。"""
    db, conn = H.make_fake_db()
    adapter = E.DbAdapter(conn, H.FakeCursor(db), log_fn=lambda _m: None,
                          sleep_fn=lambda _s: None)
    return db, E.WriterCore(adapter, batch_size=100, log_fn=lambda _m: None)


def _write(core, rows):
    """直接驱动写入路径（绕过攒批），返回 (db,) 由调用方断言"""
    core._write_batch(rows)   # pylint: disable=protected-access


def _row(content, appid, src):
    return (appid, 1, 7, 3, content, src, "js", "snippet")


# ================= 1. 相同值必须合并 =================
def test_same_value_merges_into_one_data_item():
    db, core = _core()
    v = "https://api.example.com/v1/login"
    _write(core, [_row(v, "pkgA", "/a.js"), _row(v, "pkgB", "/b.js")])

    assert list(db.data_items) == [_sha(v)], "同一全文只应有一条 data_item"
    assert db.data_items[_sha(v)]["ref_count"] == 2, "重复出现应累加 ref_count"
    assert len(db.relations) == 2, "两条出现各写一条关联"
    assert db.data_items[_sha(v)]["raw_value"] == v


# ================= 2. 不同值绝不能被合并 =================
def test_values_sharing_first_1000_chars_are_not_merged():
    """前 1000 字符相同、只有尾部不同的两个值 —— 按截断值算 hash 会把它们合并。"""
    head = "A" * 1000
    v1 = head + "END-ONE"
    v2 = head + "END-TWO"
    assert v1[:1000] == v2[:1000]
    assert _sha(v1) != _sha(v2)

    db, core = _core()
    _write(core, [_row(v1, "pkgA", "/a.js"), _row(v2, "pkgA", "/b.js")])

    assert len(db.data_items) == 2, "不同全文必须是两条 data_item"
    assert _sha(v1) in db.data_items and _sha(v2) in db.data_items
    # 两者 raw_value 现在都是全文（不再被砍到 1000），所以前缀相同而全文不同
    assert db.data_items[_sha(v1)]["raw_value"] == v1
    assert db.data_items[_sha(v2)]["raw_value"] == v2
    assert db.data_items[_sha(v1)]["raw_value"] != db.data_items[_sha(v2)]["raw_value"]


# ================= 3. 上限以内：raw_value == 全文 =================
def test_pem_sized_value_is_stored_in_full():
    """PEM 私钥量级（实测最长 4220 字符）必须全文入库，不再是残缺串。"""
    body = "\n".join("MII" + "B" * 60 for _ in range(24))
    pem = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
    assert 1000 < len(pem) < E.TEXT_COLUMN_SAFE_BYTES

    db, core = _core()
    _write(core, [_row(pem, "pkgA", "/key.js")])

    item = db.data_items[_sha(pem)]
    assert item["raw_value"] == pem, "值未超上限就必须原样存全文"
    assert item["raw_value"].endswith("-----END PRIVATE KEY-----"), "尾部不能丢"


# ================= 4. 上限按字节，不按字符 =================
def test_multibyte_value_is_capped_by_bytes_not_chars():
    """30000 个汉字 = 90000 字节：s[:65000] 会留 65000 字符 = 195000 字节，仍撑爆 TEXT。"""
    v = "汉" * 30000
    assert len(v.encode("utf-8")) == 90000
    assert len(v) == 30000                 # 字符数其实没超 65000 —— 按字符切根本不动它

    db, core = _core()
    _write(core, [_row(v, "pkgA", "/a.js")])

    item = db.data_items[_sha(v)]
    kept = item["raw_value"]
    assert len(kept.encode("utf-8")) <= E.TEXT_COLUMN_SAFE_BYTES, "必须按字节收口"
    assert len(kept.encode("utf-8")) > E.TEXT_COLUMN_SAFE_BYTES - 4, "收口后应贴住上限"
    assert v.startswith(kept), "保留的必须是全文前缀"
    assert item["raw_value"] != v
    assert list(db.data_items) == [_sha(v)], "hash 仍然按全文算（不是按截断值）"


def test_oversized_ascii_value_keeps_full_hash():
    v = "x" * 90000
    assert len(v) > E.TEXT_COLUMN_SAFE_BYTES

    db, core = _core()
    _write(core, [_row(v, "pkgA", "/a.js")])

    item = db.data_items[_sha(v)]
    assert item["raw_value"] == "x" * E.TEXT_COLUMN_SAFE_BYTES
    assert _sha(v) in db.data_items and _sha("x" * 1000) not in db.data_items


def test_cap_for_text_column_is_a_noop_below_limit():
    s = "普通字符串"
    assert E.cap_for_text_column(s) is s or E.cap_for_text_column(s) == s


# ================= 5. 其它值形态 =================
def test_empty_value_and_short_values_are_hashed_as_is():
    db, core = _core()
    _write(core, [_row("", "pkgA", "/a.js"), _row("abcd", "pkgA", "/b.js")])

    assert _sha("") in db.data_items
    assert db.data_items[_sha("")]["raw_value"] == ""
    assert db.data_items[_sha("abcd")]["raw_value"] == "abcd"


def test_non_str_content_is_stringified_before_hash_and_store():
    db, core = _core()
    _write(core, [_row(12345678, "pkgA", "/a.js")])
    assert _sha("12345678") in db.data_items
    assert db.data_items[_sha("12345678")]["raw_value"] == "12345678"


# ================= 6. 逐条重试分支不被破坏 =================
def test_per_item_retry_branch_still_works():
    """整批 executemany 失败 -> 逐条重试分支：仍应全部落地，且 raw_value 是新口径。"""
    db, core = _core()
    db.fail_executemany_once = True
    v1 = "https://a1.example.com/x"
    v2 = "https://a2.example.com/x"
    _write(core, [_row(v1, "pkgA", "/a.js"), _row(v2, "pkgA", "/b.js")])

    assert set(db.data_items) == {_sha(v1), _sha(v2)}, "逐条重试应把两条都救回来"
    assert db.data_items[_sha(v1)]["raw_value"] == v1
    assert db.data_items[_sha(v2)]["raw_value"] == v2
    assert len(db.relations) == 2, "重试成功后关联行照写"


def test_permanently_failing_row_is_recorded_as_commit_failed():
    """逐条重试仍失败的行：不进 data_item，并把该文件标成 commit_failed（原逻辑不变）。"""
    db, core = _core()
    bad = "https://bad.example.com/x"
    db.fail_hashes.add(_sha(bad))
    _write(core, [_row(bad, "pkgA", "/a.js")])

    assert _sha(bad) not in db.data_items
    assert core.failures[("pkgA", "/a.js")] == "commit_failed"
    assert not db.relations, "没有 data_item 就不该有关联行"


def test_oversized_value_lands_in_one_piece_through_retry_branch():
    """逐条重试分支下，放宽后的 raw_value 仍要按同一口径写入（不因重试回退到旧截断）。"""
    db, core = _core()
    db.fail_executemany_once = True
    pem = "-----BEGIN PRIVATE KEY-----\n" + "M" * 1700 + "\n-----END PRIVATE KEY-----"
    _write(core, [_row(pem, "pkgA", "/key.js")])

    assert db.data_items[_sha(pem)]["raw_value"] == pem


def _run_standalone():
    """本机没装 pytest（.venv 里只有 esprima/PyMySQL），所以自带一个 runner：
    断言全是纯 assert，不依赖 pytest API，两种跑法结果一致。"""
    import traceback
    cases = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in cases:
        try:
            fn()
            print("PASS %s" % name)
        except Exception:  # pylint: disable=broad-except
            failed.append(name)
            print("FAIL %s" % name)
            traceback.print_exc()
    print("=" * 60)
    print("raw_value/hash 去重验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
