#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix34：cloud_storage_path(1303) 的「整条 URL 裸子串」判据 → host 必须命中真实存储端点。

病根
----
`process_prefixed_url` 的云存储分支是

    cloud_domains = ("oss-", "cos.", "s3.", "cdn.", "aliyuncs.com", "myqcloud.com")
    if has_keyword_substring(url_lower, cloud_domains):   # 整条 URL，含路径与查询串

裸子串匹配，**不看位置也不看边界**。于是：

  · `cdn.` 命中量最大：v2 cloud_storage_path 14,595 值 / 54,111 次里，http(s) 值
    11,075 个，其中只因 `cdn.` 进来的就有 **4,546 值 / 25,359 次（占全桶 47%）**：
    字体文件（`at.alicdn.com/t/font_*.ttf`）、图片 CDN（`img.dmallcdn.com`、
    `img01.yzcdn.cn`、`si.geilicdn.com`）、`cdn.51yanpu.com` 等；
  · `s3.` 把 `images3.c-ctrip.com`（379 值）整段当成 S3；
  · 路径/查询串里的字样同样算证据（`…/fetch?target=oss-cn-hangzhou`）；
  · 真正指向对象存储的 host 反而是少数：v2 里匹配
    `<bucket>.oss-<region>.aliyuncs.com` 等真实端点形态的只有 4,106 值。

fix34（本文件钉住的判据）
------------------------
  ① 解析 URL 的 **host**（`process_prefixed_url` 里已有的 `server_name`），只有 host 命中
     真实对象存储端点才判 1303；**路径与查询串里的子串不再作为证据**；
  ② 端点表按服务域判定（每一条都在 v2 语料里逐 host 核过，见 test-result/fix34/）：
       · 阿里云 OSS：`<bucket>.oss-<region>.aliyuncs.com`、`<bucket>.oss.aliyuncs.com`、
         `oss[-<region>].aliyuncs.com`（路径式，含 `oss-accelerate`）；
       · 腾讯云 COS：`<bucket-APPID>.cos.<region>.myqcloud.com`、`cos.<region>.myqcloud.com`、
         `<bucket-APPID>.file.myqcloud.com`（默认 CDN 加速域）、
         `<bucket-APPID>.image.<region>.myqcloud.com` / `.ci.<region>.myqcloud.com`（图片处理域）、
         历史省写域 `.cossh./.cosgz./.picsh.myqcloud.com`；
       · AWS S3：`<bucket>.s3[.<region>].amazonaws.com[.cn]`、`s3[.<region>].amazonaws.com[.cn]`；
       · 华为云 OBS：`<bucket>.obs.<region>.myhuaweicloud.com`；
       · 百度 BOS：`*.bcebos.com`（该域为 BOS 专用，含 `<bucket>.cdn.bcebos.com`）；
       · 京东云 OSS（S3 兼容）：`<bucket>.s3.<region>.jdcloud-oss.com`；
       · Bitiful（S3 兼容）：`<bucket>.s3.bitiful.net`。
     `aliyuncs.com` / `myqcloud.com` 下的**非存储服务**因此被一并收紧：
     SLS 日志（`*.log.aliyuncs.com`）、ARMS/RUM 上报（`arms-retcode.aliyuncs.com`、
     `*.rum.aliyuncs.com`）、智能语音网关（`nls-gateway.aliyuncs.com`）、DashScope
     （`dashscope.aliyuncs.com`）、API 网关（`*.apigateway.myqcloud.com`）、点播
     （`*.liveplay/vod2.myqcloud.com`）—— 语料逐 host 对照见 test-result/fix34/。
  ③ 归置：移出后落**既有**出口 server_url_static(1706)/server_url_api_plain(1705)，都是 risk 1
     —— 归置红线由第 ⑤ 组钉住（静态资源判定与敏感路径判定都在云存储判定**之前**，
     所以不会有值顺着改动「往下掉」进 1702/1703 这些 risk≥4 桶）。
  ④ 非存储 host 但带 `x-oss-process` 的一支是**不确定**（形如 OSS 图片处理参数，
     但 host 不是存储端点）：按任务要求**保持现行为不变**，只报数量（v2 1,324 值 / 3,444 次）。
  ⑤ `cloud://` / `cos://` / `oss://` / `s3://` 走 `process_prefixed_cloud_url`，与本判据无关，
     完全不受影响（第 ④ 组钉住）。

用法: .venv/bin/python -X utf8 unit-tests/test_fix34_storage_host.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

STORAGE = IDT.CLOUD_STORAGE_PATH
STATIC = IDT.SERVER_URL_STATIC
API_PLAIN = IDT.SERVER_URL_API_PLAIN
RISK1_URLS = (STATIC, API_PLAIN)
RISK4_URLS = (IDT.SERVER_URL_WITH_CREDENTIALS, IDT.SERVER_URL_AUTH, IDT.SERVER_URL_PAYMENT,
              IDT.SERVER_URL_INTERNAL)

_GUARD_ATTRS = ("is_object_storage_host", "is_cloud_storage_url")

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
SLUG_BY_ID = {v: k for k, v in vars(IDT).items() if isinstance(v, int) and k.isupper()}


def _labels(url, guard_off=False):
    """跑一遍分类，返回标签列表（按常量列表的第一个值取）。"""
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if guard_off and hasattr(C, "is_cloud_storage_url"):
        # 改动前的等效开关：整条 URL 的裸子串匹配（与改动前的代码逐字同源）
        C.is_cloud_storage_url = lambda url_lower, host: C.has_keyword_substring(
            url_lower, C.CLOUD_STORAGE_DOMAIN_SUBSTRINGS)
    try:
        return [r[0] for r in C.perform_constant_classifying([url], [(url, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


# =========================================================
# ① 移出：只因裸子串进来的 CDN / 非存储 host（v2 语料里逐 host 存在）
# =========================================================
# (URL, 命中的裸子串)。路径全部合成，host 取自 v2 语料（就是判据要处理的那些 host）。
MOVE_CASES = [
    # `cdn.` 命中：字体文件（.ttf/.woff 不在 STATIC_EXTENSIONS 里，真的会走到云存储分支）
    ("https://at.alicdn.com/t/font_0000000_abcdefgh.ttf", "cdn."),
    ("https://s3.meituan.net/static-prod01/pkg/AvenirLTPro-Heavy.woff", "s3."),
    # `cdn.` 命中：图片 CDN（.webp 同样不在 STATIC_EXTENSIONS 里）
    ("https://img.dmallcdn.com/dshop/202107/602893fe-1eac-4ea1.webp", "cdn."),
    ("https://img01.yzcdn.cn/upload_files/2024/11/08/search-a1b2c3.webp", "cdn."),
    ("https://si.geilicdn.com/img-745200000184e04206e90a2313c4.webp", "cdn."),
    # `s3.` 命中：`images3.c-ctrip.com` 是 v2 里 379 个值的同一形态
    ("https://images3.c-ctrip.com/ztrip/train.song/gonggong/icon_tx3.webp", "s3."),
    # `cdn.` 命中：目录型 URL（不以静态后缀结尾）
    ("https://cdn.51yanpu.com/vue-customer/static/images/", "cdn."),
    # 路径/查询串里的字样（不是 host）：`oss-` 出现在 query 里
    ("https://api.example.com/v1/fetch?target=oss-cn-hangzhou", "oss-"),
    # `cos.` 出现在路径里（不是 host）
    ("https://static.example.com/assets/cos.ap-shanghai/myfile.bin", "cos."),
    # `aliyuncs.com` 下的非存储服务：智能语音网关 / ARMS 上报（不是对象存储）
    ("https://nls-gateway.cn-shanghai.aliyuncs.com/stream/v1/tts", "aliyuncs.com"),
    ("https://arms-retcode.aliyuncs.com/r.webp", "aliyuncs.com"),
    ("https://srs-frontend-log.cn-shanghai.log.aliyuncs.com/api/link", "aliyuncs.com"),
    ("https://dashscope.aliyuncs.com/api/v1/services/aigc/text", "aliyuncs.com"),
    # `myqcloud.com` 下的非存储服务：点播 / API 网关 / 品牌自建 host（不是 COS 端点）
    ("https://20706.liveplay.myqcloud.com/live/stream.webp", "myqcloud.com"),
    ("https://svc-gog9g6q2-1258561025.ap-guangzhou.apigateway.myqcloud.com/api/x.webp",
     "myqcloud.com"),
    ("https://cos.blemon.net/json/animatedEmojiData.json", "cos."),
]


def test_cdn_substring_values_move_out_of_1303():
    """① 只因裸子串进来的值不再是 1303。"""
    assert len(MOVE_CASES) == 16, len(MOVE_CASES)
    for url, hit in MOVE_CASES:
        got = _labels(url)
        assert STORAGE not in got, (url, hit, got)


def test_move_out_destination_is_risk1_only():
    """① 归置红线：移出后只落 server_url_static(1706) / server_url_api_plain(1705)，都是 risk 1；
    不许落到 server_url_auth / server_url_payment / with_credentials（risk≥4）等更高风险桶。"""
    assert RISK["server_url_static"] == 1 and RISK["server_url_api_plain"] == 1
    assert RISK["server_url_auth"] == 4 and RISK["server_url_payment"] == 4
    for url, hit in MOVE_CASES:
        got = _labels(url)
        assert got, (url, hit)
        assert set(got) <= set(RISK1_URLS), (url, hit, got)
        for label in got:
            assert label not in RISK4_URLS, (url, hit, label)
            slug = SLUG_BY_ID.get(label, "").lower()
            assert RISK.get(slug, 99) <= 1, (url, hit, label, slug)


# =========================================================
# ①b 看起来像存储、但**不入端点表**的 host：只减不增的结构性保证
# =========================================================
# 这四类 host 在语料里都指向真实对象存储，但它们的 host 形态**不蕴含**改动前的任何裸子串
# （`*.obs.<region>.myhuaweicloud.com`、`<bucket>.<region>.bcebos.com`、品牌自建
# oss/cos 前缀域）。把它们写进端点表 = 让一批改动前不是 1303 的值**反向进入**目标桶
# （v2 语料横向统计：`myhuaweicloud.com` 139 值在 1705、1,241 值在 1706；
# `bcebos.com` 48 值在 1705、1,058 值在 1706），与任务「反向进入目标桶必须 0」冲突。
# 本轮只做「只减不增」的真子集判据：这些形态一律不入表。
LOOKS_LIKE_STORAGE_NOT_IN_TABLE = [
    ("华为云 OBS", "https://bucket-test1.obs.cn-south-1.myhuaweicloud.com/upload/x.webp"),
    ("百度 BOS 非 CDN 域", "https://bucket-test1.bj.bcebos.com/upload/x.webp"),
    ("阿里云 OSS 自定义域", "https://oss.example-brand.cn/Feimayi_s/upload/x.webp"),
]
# 另外，品牌自建 `cos.` 前缀域（`cos.blemon.net`）与腾讯点播域（`20706.liveplay.myqcloud.com`）
# 本来就因 host 里含 `cos.` / `myqcloud.com` 而命中旧判据 —— 它们在下面第 ① 组（MOVE_CASES）里。


def test_looks_like_storage_hosts_never_enter_1303():
    """①b 这些形态**改动前后都不是 1303** —— 本判据只减不增，一条也拉不进来。"""
    assert len(LOOKS_LIKE_STORAGE_NOT_IN_TABLE) == 3
    for note, url in LOOKS_LIKE_STORAGE_NOT_IN_TABLE:
        assert STORAGE not in _labels(url), (note, url)
        assert STORAGE not in _labels(url, guard_off=True), (note, url)


# =========================================================
# ② 保留：host 命中真实存储端点的值 100% 保留（保护对象）
# =========================================================
KEEP_CASES = [
    # 阿里云 OSS：<bucket>.oss-<region>.aliyuncs.com / 路径式 / 加速端点
    "https://bucket-test1.oss-cn-hangzhou.aliyuncs.com/upload/a1b2c3.webp",
    "https://bucket-test1.oss-cn-shanghai.aliyuncs.com/dir/file.woff",
    "https://oss-cn-hangzhou.aliyuncs.com/bucket-test1/upload/a1b2c3.webp",
    "https://oss.aliyuncs.com/bucket-test1/upload/a1b2c3.webp",
    "https://bucket-test1.oss-accelerate.aliyuncs.com/upload/a1b2c3.webp",
    # 腾讯云 COS：默认域 / 路径式 / 默认 CDN 加速域 / 图片处理域 / 历史省写域
    "https://bucket-test1-1317426693.cos.ap-shanghai.myqcloud.com/upload/x.webp",
    "https://cos.ap-shanghai.myqcloud.com/bucket-test1-1317426693/upload/x.webp",
    "https://bucket-test1-1258344699.file.myqcloud.com/upload/x.webp",
    "https://bucket-test1-1258344699.image.myqcloud.com/upload/x.webp",
    "https://bucket-test1-1251015109.cossh.myqcloud.com/upload/x.webp",
    "https://bucket-test1-1251015109.picsh.myqcloud.com/upload/x.webp",
    # AWS S3：虚拟主机式（含 region / 中国区）与路径式
    "https://bucket-test1.s3.amazonaws.com/upload/x.webp",
    "https://bucket-test1.s3.us-east-1.amazonaws.com/upload/x.webp",
    "https://s3.us-east-1.amazonaws.com/bucket-test1/upload/x.webp",
    "https://bucket-test1.s3.cn-north-1.amazonaws.com.cn/upload/x.webp",
    # 华为云 OBS / 百度 BOS（CDN 域）/ 京东云 OSS / Bitiful
    "https://bucket-test1.cdn.bcebos.com/upload/x.webp",
    "https://bucket-test1.s3.cn-north-1.jdcloud-oss.com/upload/x.webp",
    "https://bucket-test1.s3.bitiful.net/upload/x.webp",
]


def test_real_storage_endpoints_are_kept():
    """② host 为真实 OSS/COS/S3 端点的值 100% 保留 1303。"""
    assert len(KEEP_CASES) == 18, len(KEEP_CASES)
    for url in KEEP_CASES:
        got = _labels(url)
        assert got == [STORAGE], (url, got)


def test_real_endpoint_kept_even_with_hostile_path():
    """② 保护不看路径：真实端点 + 路径里塞满别的云字样仍然是 1303。"""
    url = ("https://bucket-test1.oss-cn-hangzhou.aliyuncs.com/"
           "cdn.images3.c-ctrip.com/cos.foo/myqcloud.com/x.webp")
    assert _labels(url) == [STORAGE]


# =========================================================
# ③ 不确定支：非存储 host 但带 x-oss-process（保持现行为不变）
# =========================================================
XOSS_CASES = [
    # v2 语料里的形态：自建 CDN host + OSS 图片处理参数（1,324 值 / 3,444 次）
    "https://prod.example-cdn.cn/m/other/1718158757315_801374.webp?x-oss-process=image/resize,w_750",
    "https://media-image1.example.com/storage/abc.def.webp?x-oss-process=image/format,webp",
]


def test_x_oss_process_branch_unchanged():
    """③ 不确定支保持现行为：仍判 1303（本轮只报数量，不改判）。"""
    for url in XOSS_CASES:
        assert _labels(url) == [STORAGE], url


# =========================================================
# ④ cloud:// 分支完全不受影响
# =========================================================
CLOUD_URL_CASES = [
    "cloud://env-abc123.6565-env-abc123-1300000000/upload/x.webp",
    "cloud://env-abc123.6565-env-abc123-1300000000/dir/font.ttf",
    "cos://env-abc123/upload/x.webp",
    "oss://env-abc123/upload/x.webp",
    "s3://env-abc123/upload/x.webp",
]


def test_cloud_scheme_branch_untouched():
    """④ cloud:// 等 scheme 分支是真云存储，两库都干净 —— 完全不受本判据影响。"""
    for url in CLOUD_URL_CASES:
        got = _labels(url)
        assert STORAGE in got, (url, got)
        off = _labels(url, guard_off=True)
        assert off == got, (url, got, off)


# =========================================================
# ⑤ 判据本体：host 判定与「整条 URL」判定的分工
# =========================================================
def test_is_object_storage_host_boundaries():
    """⑤ host 端点表的正反例（大小写不敏感，含端口由调用方剥掉）。"""
    for host in ("bucket-test1.oss-cn-hangzhou.aliyuncs.com",
                 "OSS-CN-HANGZHOU.ALIYUNCS.COM",
                 "oss-cn-hangzhou.aliyuncs.com",
                 "oss.aliyuncs.com",
                 "bucket-test1-1317426693.cos.ap-shanghai.myqcloud.com",
                 "cos.ap-shanghai.myqcloud.com",
                 "bucket-test1-1258344699.file.myqcloud.com",
                 "bucket-test1.s3.amazonaws.com",
                 "bucket-test1.s3.us-east-1.amazonaws.com",
                 "s3.us-east-1.amazonaws.com",
                 "bucket-test1.s3.cn-north-1.amazonaws.com.cn",
                 "cf-abc-bucket-cn-north-1.s3.cn-north-1.amazonaws.com.cn",
                 "bucket-test1.cdn.bcebos.com",
                 "bucket-test1.s3.cn-north-1.jdcloud-oss.com",
                 "bucket-test1.s3.bitiful.net"):
        assert C.is_object_storage_host(host.lower()) is True, host
    for host in ("img.dmallcdn.com",                 # cdn. 裸子串
                 "images3.c-ctrip.com",              # s3. 裸子串
                 "at.alicdn.com",
                 "img01.yzcdn.cn",
                 "cdn.51yanpu.com",
                 "s3.meituan.net",                   # 品牌自建 s3. host，不是 S3 端点
                 "cos.blemon.net",                   # 品牌自建 cos. host
                 "oss.fmy90.cn",                     # 品牌自建 oss 前缀
                 "hxsupload-oss.hxsapp.com",
                 "dashscope.aliyuncs.com",           # 阿里非存储服务
                 "nls-gateway.cn-shanghai.aliyuncs.com",
                 "arms-retcode.aliyuncs.com",
                 "sls-log.cn-hangzhou.log.aliyuncs.com",
                 "20706.liveplay.myqcloud.com",      # 腾讯非存储服务
                 "svc-1258561025.ap-guangzhou.apigateway.myqcloud.com",
                 "fe-static.ima.myqcloud.com",
                 # ①b：看起来像存储、但不蕴含旧裸子串的形态，本轮刻意不入表
                 "bucket-test1.obs.cn-south-1.myhuaweicloud.com",
                 "bucket-test1.bj.bcebos.com",
                 "bucket-test1.bcebos.com",
                 "static.example.com",
                 "api.example.com",
                 "bucket-test1.oss-cn-hangzhou.aliyuncs.com.evil.example.com",
                 ""):
        assert C.is_object_storage_host(host) is False, host


def test_url_level_predicate_uses_host_not_whole_url():
    """⑤ URL 级判据 = host 命中端点 **或** 非存储 host 的 x-oss-process 不确定支。"""
    assert C.is_cloud_storage_url(
        "https://bucket-test1.oss-cn-hangzhou.aliyuncs.com/x.webp",
        "bucket-test1.oss-cn-hangzhou.aliyuncs.com") is True
    # 路径里的字样不是证据
    assert C.is_cloud_storage_url(
        "https://static.example.com/assets/cos.ap-shanghai/x.bin",
        "static.example.com") is False
    assert C.is_cloud_storage_url(
        "https://api.example.com/v1/fetch?target=oss-cn-hangzhou",
        "api.example.com") is False
    # 唯一保留的整条 URL 证据：不确定支 x-oss-process
    assert C.is_cloud_storage_url(
        "https://prod.example-cdn.cn/a.webp?x-oss-process=image/resize,w_750",
        "prod.example-cdn.cn") is True
    # 旧口径的裸子串表仍是模块常量（回放开关要用它复现改动前）
    assert C.CLOUD_STORAGE_DOMAIN_SUBSTRINGS == ("oss-", "cos.", "s3.", "cdn.",
                                                 "aliyuncs.com", "myqcloud.com")


# =========================================================
# ⑥ 对照：搬走这件事**就是**这条判据干的
# =========================================================
def test_guard_is_the_change():
    """⑥ 关掉新判据（还原成整条 URL 的裸子串匹配）= 改动前：移出组回到 1303，
    保留组与不确定支不受开关影响。"""
    for url, hit in MOVE_CASES:
        had = _labels(url, guard_off=True)
        assert had == [STORAGE], (url, hit, had)
        assert STORAGE not in _labels(url), (url, hit)
    for url in KEEP_CASES + XOSS_CASES:
        assert _labels(url, guard_off=True) == _labels(url) == [STORAGE], url


def test_query_string_processing_unchanged():
    """⑥ 查询串处理在云存储判定之前，独立于本判据：开关前后一致（无云字样的 query）。"""
    url = "https://static.example.com/assets/app.bin?v=1&file=a1b2c3"
    assert _labels(url) == _labels(url, guard_off=True)
    assert STORAGE not in _labels(url)


def test_every_endpoint_pattern_implies_old_substring_evidence():
    """⑥ 结构性不变量（「只减不增」的根据）：端点表每一条 pattern 的**字面**里都含旧六个
    裸子串之一 —— 去掉正则转义后逐个查。host 命中端点 ⇒ host 含旧子串 ⇒ 整条 URL 含旧子串
    ⇒ 改动前也是 1303。于是「反向进入目标桶」为 0 是结构保证，不依赖抽样。"""
    for name, pattern in C.CLOUD_STORAGE_HOST_PATTERNS:
        literal = pattern.pattern.replace("\\", "")
        assert any(sub in literal for sub in C.CLOUD_STORAGE_DOMAIN_SUBSTRINGS), \
            (name, pattern.pattern)
    # x-oss-process 支同理：它本身就含 `oss-`
    assert any(sub in "x-oss-process" for sub in C.CLOUD_STORAGE_DOMAIN_SUBSTRINGS)


def test_positive_hosts_all_contain_old_substring():
    """⑥ 端点表命中的 host（合成样本 + 语料里的全部正例）都含旧裸子串。"""
    hosts = [u.split("//", 1)[1].split("/", 1)[0] for u in KEEP_CASES]
    for host in hosts:
        assert C.is_object_storage_host(host) is True, host
        assert C.has_keyword_substring(host, C.CLOUD_STORAGE_DOMAIN_SUBSTRINGS), host


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
    print("fix34 云存储 host 判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
