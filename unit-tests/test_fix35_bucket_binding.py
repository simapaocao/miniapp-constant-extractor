#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix35：cloud_bucket_name(1301) 的「窗口裸子串」判据 → 证据必须**绑定在本值位置**上。

病根
----
`is_bucket_name` 的第一行是

    if not has_keyword_substring(stmt, BUCKET_CONTEXT_WORDS):   # stmt = 值周围 512 字符窗口
        return False

即：**只要窗口里出现过 `bucket` 子串**、值形又符合（6~63 字符、全小写 [a-z0-9-]、含 `-` 或数字），
就判 cloud_bucket_name —— 从不问这个 `bucket` 是**谁**的。三个库的实例：

  · pkgref 96 个值里 62 个是 `logo-*`：它们来自同一个图标数组
    `"logo-bitbucket", "logo-bitcoin", "logo-buffer", …` —— 数组元素 `logo-bitbucket`
    **自身**含 "bucket"，于是**同语句所有元素**的窗口都含 "bucket"，60 多个图标名整片被判成桶名；
  · v2 约 12 值 / 58 次是编译模板标签或组件名（`_mz(z,'<tag>',[…,'bucketInfo',…])`、
    `"<name>":"../components/…"`，同语句里恰好有 `bucketInfo` 属性），例如 topic-layout、
    header-bar、*-bucket-detail、order-module-bucket、skeleton-rect 这类组件/类名；
  · S3 POST policy 的**条件算子词** `starts-with`（v2 11 次）—— 它是 policy 语法关键词，
    窗口里有 `"$bucket"` 就被当成桶名；
  · 32 位 hex（3 个，其中 `c92670eda122434ab234b7132dae4c73` 就坐在 `bucket_access_sec:` 键上）；
  · 日志串 2 个。

fix35（本文件钉住的判据）
------------------------
  ① 上下文证据必须是**绑定在该值位置**的键（口径 = 只读复用 fix24 的 `_bound_value_keys`：
     值须自成字面量、键须紧邻在值左侧），**不是窗口里的裸子串**；键名（lower）含 `bucket`
     即算桶键族（语料 44 个键逐个核过：bucket/Bucket/bucketName/bucket_name/mfBucketName/
     cosBucket/ossBucket/REACT_APP_OSS_BUCKET/BUCKET_NAME/content_bucket_name/… 都是桶名
     字段；见 test-result/fix35/）—— 与 fix24 的「族内复合键名放行」同一套写法；
  ② **值自身或同语句其它字面量里的 `bucket` 字样不算证据**：这正是 🄰 组（图标数组）
     与组件名那几组的病根；
  ③ 硬否决（优先于任何键绑定）：S3 policy 算子词 `starts-with` / `eq` / `content-length-range`、
     32 位 hex —— 它们不可能是桶名，坐在桶键上也不是；
  ④ 豁免：腾讯 COS 桶名形态 `<name>-<10 位数字 appid>` **本身就是证据**（
     `avatar-1302652390`、`static-1258033895` 这类值常出现在三目/`||` 表达式里，紧邻键
     拿不到绑定），可以不要绑定；
  ⑤ 归置：移出后落 **risk 0** 的既有出口（pii_noise 2304 / id_noise 2505 / other 9901），
     不许升级 —— 由第 ④ 组钉住。

用法: .venv/bin/python -X utf8 unit-tests/test_fix35_bucket_binding.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

BUCKET = IDT.CLOUD_BUCKET_NAME
_GUARD_ATTRS = ("has_bucket_name_evidence",)

_HERE = os.path.dirname(os.path.abspath(__file__))


def _risks():
    """slug -> risk（constant_types.json 的 datatype_categories[].items[]）。"""
    with open(os.path.join(os.path.dirname(_HERE), "constant_types.json"), encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"]] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risks()
SLUG_BY_ID = {v: k.lower() for k, v in vars(IDT).items() if isinstance(v, int) and k.isupper()}


def _labels(value, stmt, guard_off=False):
    """跑一遍分类。`guard_off` 把本轮新判据还原成「改动前」（窗口裸子串就够）。"""
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if guard_off and hasattr(C, "has_bucket_name_evidence"):
        C.has_bucket_name_evidence = lambda s, stmt: True
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(value, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


def _risk_of(label):
    return RISK.get(SLUG_BY_ID.get(label, ""), 99)


# =========================================================
# ① 移出：窗口里有 bucket 字样，但证据没绑定在这个值上
# =========================================================
# (值, 语句, 说明)。语句形态逐条取自库里真实的 source_snippet（值换成同形态的合成值）。
MOVE_CASES = [
    # pkgref 62 值的那一条：数组元素 `logo-bitbucket` 自己含 bucket，同语句所有元素被连坐
    ("logo-github",
     'var a=["logo-bitbucket","logo-github","logo-apple","logo-android"]', "图标数组连坐"),
    ("logo-apple",
     'var a=["logo-bitbucket","logo-github","logo-apple","logo-android"]', "图标数组连坐"),
    # v2 编译模板标签：`_mz(z,'<tag>',[…,'bucketInfo',…])`
    ("topic-layout",
     "cgHB=_mz(z,'topic-layout',['pageName',1,'bucketInfo',2,'class',3],[],e,s,gg)", "模板标签"),
    ("header-bar",
     "eXDB=_mz(z,'header-bar',['address',441,'baInfo',1,'bind:topicEvent',2,'bucketInfo',3,"
     "'cell',4],[]，e,s,gg)".replace("，", ","), "模板标签"),
    # v2 组件名：同语句里有 bucketInfo 属性
    ("topic-layout",
     'children:(0,B.jsx)("topic-layout",{pageName:"",id:p,bucketInfo:o,onPopupData:Math.random})',
     "组件名"),
    # v2 编译后的 class 数组：`order-module-bucket` 自己含 bucket，把同数组的类名连坐
    ("skeleton-rect", 'className:(0,w.Z)("orderModule","skeleton-rect","order-module-bucket")',
     "class 数组连坐"),
    ("reserve-car-body", 'className:(0,a.Z)("reserve-car-body","reserve-car-body-bucket")',
     "class 数组连坐"),
    # S3 POST policy 的算子词（窗口里 `"$bucket"` / `bucket:` 都在）
    ("starts-with",
     'conditions:[["eq","$bucket","my-bucket-test"],["content-length-range",1,1024],'
     '["starts-with","$key","upload/"]]', "policy 算子词"),
    # 32 位 hex 坐在 bucket 键上（键名含 bucket 也不算桶名）
    ("c92670eda122434ab234b7132dae4c73", 'bucket_access_sec: "c92670eda122434ab234b7132dae4c73"',
     "32 位 hex"),
    # 值绑定在**非桶键**上：窗口里的 bucketInfo 只是同一个对象的另一个字段
    ("release-tag-2024", '{bucketInfo:1,deployTag:"release-tag-2024",env:"prod"}', "绑定在非桶键"),
    # 值绑定在另一个**值的键**上（值是对象字面量的键，不是桶名）
    ("paint-bucket", 'icons:{"paint-bucket":"<path d=\\"M11 7 6 2\\" />","arrow-up":"<path d=\\"M1 2\\"/>"}'
     ',bucket:"my-bucket-test"', "值是图标表的键"),
]


def test_window_only_substring_no_longer_1301():
    """① 窗口里有 bucket 字样、但值没绑定在桶键上 → 不再是 1301。"""
    assert len(MOVE_CASES) == 11, len(MOVE_CASES)
    for v, stmt, note in MOVE_CASES:
        got = _labels(v, stmt)
        assert BUCKET not in got, (v, note, got)


def test_move_out_destination_is_risk0_only():
    """① 归置红线：移出只落 risk 0 的既有出口，不许平移到别的风险桶。"""
    for v, stmt, note in MOVE_CASES:
        got = _labels(v, stmt)
        assert got, (v, note)
        for label in got:
            assert _risk_of(label) == 0, (v, note, label, SLUG_BY_ID.get(label))


# =========================================================
# ② 保留：绑定在桶键上的值 100% 保留（保护对象）
# =========================================================
KEEP_CASES = [
    ('bucket:"my-bucket-1300000000"', "my-bucket-1300000000", "bucket"),
    ('Bucket: "my-bucket-1300000000"', "my-bucket-1300000000", "Bucket"),
    ('bucketName:"my-bucket-prod"', "my-bucket-prod", "bucketName"),
    ('bucket_name:"my-bucket-test"', "my-bucket-test", "bucket_name"),
    ('ossBucket:"my-bucket-alpha"', "my-bucket-alpha", "ossBucket"),
    ('cosBucket:"my-bucket-beta"', "my-bucket-beta", "cosBucket"),
    ('s3Bucket:"my-bucket-gamma"', "my-bucket-gamma", "s3Bucket"),
    ('storage_bucket:"my-bucket-delta"', "my-bucket-delta", "storage_bucket"),
    # 族内复合键名（语料里真实存在的 44 个桶键形态）
    ('BUCKET_NAME:"my-bucket-name1"', "my-bucket-name1", "BUCKET_NAME"),
    ('mfBucketName:"my-bucket-esf"', "my-bucket-esf", "mfBucketName"),
    ('content_bucket_name = "my-bucket-content"', "my-bucket-content", "content_bucket_name"),
    ('REACT_APP_OSS_BUCKET:"my-bucket-react"', "my-bucket-react", "REACT_APP_OSS_BUCKET"),
    ('actualBucket:"my-bucket-actual"', "my-bucket-actual", "actualBucket"),
    ('AVATAR_BUCKET:"my-bucket-avatar"', "my-bucket-avatar", "AVATAR_BUCKET"),
    # 键与值之间有默认值写法（`bucket: x || "字面量"`，与 _bound_value_keys 的口径一致）
    ('bucket: c.bucket || "my-bucket-default"', "my-bucket-default", "|| 默认值"),
]


def test_bucket_key_bound_values_kept_1301():
    """② 绑定在桶键（键名含 bucket）上的值 100% 保留 1301。"""
    assert len(KEEP_CASES) == 15, len(KEEP_CASES)
    for stmt, v, key in KEEP_CASES:
        got = _labels(v, stmt)
        assert got == [BUCKET], (v, key, got)


def test_bound_value_kept_even_if_window_full_of_noise():
    """② 保护只看绑定：窗口里塞满图标名/组件名/算子词，绑在桶键上的值仍是 1301。"""
    stmt = ('var a=["logo-bitbucket","logo-github"];'
            '_mz(z,"topic-layout",["bucketInfo",1]);'
            'conditions:[["starts-with","$key",""]];'
            'config:{bucket:"my-bucket-1300000000"}')
    assert _labels("my-bucket-1300000000", stmt) == [BUCKET]


# =========================================================
# ③ COS 形态 <name>-<10 位 appid> 豁免绑定要求
# =========================================================
COS_SHAPE_CASES = [
    # 三目表达式：值紧邻左侧是 `?` / `:`，_bound_value_keys 拿不到键 —— 靠形态豁免
    ("avatar-1300000000",
     'avatorBucket:"release"===v.b||"prelease"===e.env.NODE_BUILD?"avatar-1300000000":'
     '"avatar-1250000000"', "三目"),
    ("avatar-1250000000",
     'avatorBucket:"release"===v.b||"prelease"===e.env.NODE_BUILD?"avatar-1300000000":'
     '"avatar-1250000000"', "三目"),
    # 完全无绑定，只靠 COS 形态（窗口里有 bucketInfo）
    ("static-1258033895", '{bucketInfo:{},name:"static-1258033895",host:"https://x.example.com"}',
     "无绑定"),
    ("doc-import-prod-1331936397",
     'k.postObject({Bucket:"doc-import-prod-1331936397",Region:"ap-shanghai"})'
     .replace("Bucket:", "bucketInfo:{} , Bucket:"), "复合语句"),
]


def test_cos_shape_exempt_from_binding():
    """③ 腾讯 COS 桶名形态 <name>-<10 位 appid>：本身就是证据，豁免绑定要求。"""
    assert len(COS_SHAPE_CASES) == 4, len(COS_SHAPE_CASES)
    for v, stmt, note in COS_SHAPE_CASES:
        got = _labels(v, stmt)
        assert got == [BUCKET], (v, note, got)


# =========================================================
# ④ 判据本体：三条证据来源的边界
# =========================================================
def test_evidence_predicate_boundaries():
    """④ `has_bucket_name_evidence` 的正反例（全部用合成值）。"""
    # 绑定键含 bucket → 有证据
    assert C.has_bucket_name_evidence("my-bucket-prod", 'bucket:"my-bucket-prod"') is True
    assert C.has_bucket_name_evidence("my-bucket-prod", 'x.bucketName="my-bucket-prod"') is True
    assert C.has_bucket_name_evidence("my-bucket-prod", '"bucket_name": "my-bucket-prod"') is True
    assert C.has_bucket_name_evidence("my-bucket-prod", 'bucket: c.bucket || "my-bucket-prod"') is True
    # 绑定在非桶键 / 值是数组元素 / 值自身含 bucket 字样 → 无证据
    assert C.has_bucket_name_evidence("logo-github", 'var a=["logo-bitbucket","logo-github"]') is False
    assert C.has_bucket_name_evidence("logo-bitbucket", 'var a=["logo-bitbucket"]') is False
    assert C.has_bucket_name_evidence("topic-layout", 'bucketInfo:1,tag:"topic-layout"') is False
    assert C.has_bucket_name_evidence("topic-layout",
                                      '_mz(z,"topic-layout",["bucketInfo",1])') is False
    # 值的**前缀**是更长**标识符字面量**时不算独立出现（口径同 _bound_value_keys：
    # 只有字母数字/`_`/`$` 才算「更长字面量」，`-` 不是 —— 所以 `my-bucket` 在
    # `"my-bucket-prod"` 里仍算独立出现，这一点沿用共用扫描器，不在本轮改口径）
    assert C.has_bucket_name_evidence("mybucket", 'bucket:"mybucketprod"') is False
    assert C.has_bucket_name_evidence("my-bucket", 'bucket:"my-bucket-prod"') is True
    # 硬否决优先于键绑定
    assert C.has_bucket_name_evidence("starts-with", 'conditions:[["starts-with","$key",""]]') is False
    assert C.has_bucket_name_evidence("eq", 'conditions:[["eq","$bucket","x-bucket"]]') is False
    assert C.has_bucket_name_evidence("content-length-range", 'bucket:"a",x:"content-length-range"') is False
    assert C.has_bucket_name_evidence(
        "c92670eda122434ab234b7132dae4c73", 'bucket_access_sec:"c92670eda122434ab234b7132dae4c73"') is False
    # COS 形态豁免
    assert C.has_bucket_name_evidence("avatar-1300000000", 'avatorBucket:x?"avatar-1300000000":"y"') is True
    assert C.has_bucket_name_evidence("static-1258033895", 'bucketInfo:{},"static-1258033895"') is True
    # 形态不正的（appid 不是 10 位）不豁免
    assert C.has_bucket_name_evidence("avatar-13000000", 'bucketInfo:{},"avatar-13000000"') is False
    assert C.has_bucket_name_evidence("avatar-abc0000000", 'bucketInfo:{},"avatar-abc0000000"') is False


def test_hex32_uses_the_lowercased_value():
    """④ 32 位 hex 的否决按小写（is_bucket_name 已先要求全小写，这里钉住口径）。"""
    assert C.has_bucket_name_evidence("c92670eda122434ab234b7132dae4c73", "x:1") is False
    assert C.has_bucket_name_evidence("C92670EDA122434AB234B7132DAE4C73", "x:1") is False
    # 31/33 位 hex 不是 32 位 hex
    assert C.has_bucket_name_evidence("c92670eda122434ab234b7132dae4c7", "x:1") is False  # 不是桶名只因无绑定
    assert C.has_bucket_name_evidence("c92670eda122434ab234b7132dae4c73a", 'bucket:"c92670eda122434ab234b7132dae4c73a"') is True


def test_is_bucket_name_keeps_its_old_shape_preconditions():
    """④ 形态前提一条不动：长度 6~63、全小写、字符集、含 `-` 或数字、区域让位、黑名单。"""
    # 无 bucket 字样的窗口 → 依旧 False（窗口前提保留）
    assert C.is_bucket_name("my-bucket-prod", 'x:"my-bucket-prod"') is False
    # 大写 / 带点 / 太短 / 纯数字 → 依旧 False
    assert C.is_bucket_name("My-Bucket-Prod", 'bucket:"My-Bucket-Prod"') is False
    assert C.is_bucket_name("my.bucket.prod", 'bucket:"my.bucket.prod"') is False
    assert C.is_bucket_name("short", 'bucket:"short"') is False
    assert C.is_bucket_name("1234567890", 'bucket:"1234567890"') is False
    # 区域名让位（仍 False）
    assert C.is_bucket_name("cn-hangzhou", 'bucket:"cn-hangzhou"') is False
    # 黑名单首段（仍 False）
    assert C.is_bucket_name("bucket-name", 'bucket:"bucket-name"') is False
    # 绑在桶键上的合法桶名 → True
    assert C.is_bucket_name("my-bucket-prod", 'bucket:"my-bucket-prod"') is True


# =========================================================
# ⑤ 对照：搬走这件事**就是**这条判据干的
# =========================================================
def test_guard_is_the_change():
    """⑤ 关掉新判据（= 窗口裸子串就够）= 改动前：移出组回到 1301；保留组不受开关影响。"""
    for v, stmt, note in MOVE_CASES:
        had = _labels(v, stmt, guard_off=True)
        assert had == [BUCKET], (v, note, had)
        assert BUCKET not in _labels(v, stmt), (v, note)
    for stmt, v, key in KEEP_CASES + [(s, v, n) for v, s, n in COS_SHAPE_CASES]:
        assert _labels(v, stmt, guard_off=True) == _labels(v, stmt) == [BUCKET], (v, key)


def test_other_window_keywords_unchanged():
    """⑤ 只动桶名出口：同一条语句里的 region / timestamp 等其它关键词出口逐位不变。"""
    v = "cn-hangzhou"
    stmt = 'bucketInfo:1,region:"cn-hangzhou"'
    assert _labels(v, stmt) == _labels(v, stmt, guard_off=True)
    v2 = "my-bucket-prod"
    stmt2 = 'timestamp:1,bucket:"my-bucket-prod"'
    assert BUCKET in _labels(v2, stmt2)


# =========================================================
# runner（本机 .venv 没装 pytest）
# =========================================================
def _run_standalone():
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
    print("fix35 桶名绑定判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
