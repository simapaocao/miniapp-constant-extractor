#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix26：saas_map_key(1401)「通用语境分支」的标识符名守卫。

病根
----
`is_any_map_key_format` 有三支出口：
  ① 格式自证 `XXXBZ-…`（腾讯）→ 任何语境都放行；
  ② 格式自证 `AIzaSy…`（Google）→ 任何语境都放行；
  ③ **通用语境分支**：窗口里出现地图关键词 **且** 值通过 `is_valid_api_key_format`。
第三支的两个条件都太松：

  · `is_valid_api_key_format` 只要求「长度 ≥16 / 非纯数字 / 非全小写单词 / 字符集 ⊆
    `[A-Za-z0-9_-]`」—— kebab 形态的路由名、页面名、模块名（`user-medicine-edit`、
    `mobx-miniprogram-bindings`、`MINIPROGRAM-ALIPAY`）与混合大小写的 snake 常量名
    （`SET_TASK_TYPE_MAP_KEY`、`over_pay_no_amapOrderId`）整族通过；
  · 语境是**裸子串**匹配 `MAP_KEY_CONTEXT_WORDS`，只要窗口（值周围 512 字符）里任何位置
    出现 `amap` / `mapKey` / `bmap`… 就算地图语境 —— `require("~/utils/amap-fn")`、
    `e.mapKey`、`businessCfgMapKey = i.configs.sq_mmmm_sec_key`、`isAmap ?` 全算。

实测（normal_quarkpan 全量 saas_map_key 链接，只读普查脚本
`test-result/fix26/probe_map_key_branch.py`）：
  · 桶内 12,390 条链接 = 通用语境支 7,974 / 腾讯格式支 4,387 / Google 格式支 2 / 其余 27；
  · 通用语境支里「多段词形标识符名 且 未绑定在地图 Key 值位置」= **6,337 条链接 / 691 个值**
    —— 头号族是页面名数组、枚举分支、i18n key、常量名、`el-amap-*` 组件名；
  · 同支里非标识符形的值（32 位 hex 高德 Key、`return "…"` 里未绑定的真 Key）一律不在射程内。

判据（本轮只动第三支，两行）
----
值形是多段词形标识符名（复用 fix12 立下、已在 1203/1604 上验证的
`is_segmented_identifier_name`）**且**本值没有坐在「地图 Key 值位置」→ 不是地图 Key。

  · **格式自证优先**：①②两支在进入守卫之前就已 `return True`，因此无绑定的腾讯 BZ Key
    （含恰好每段都是「字母+尾数字」、会被 `is_segmented_identifier_name` 命中的那一小批 BZ 值，
    实测 43 条链接）与 Google Key 完全不受影响；本文件用 `guard_always` 对照组钉住这一点；
  · **值位置绑定**= 紧邻本值左侧的键名（口径复用 fix24 的 `_PAYMENT_VALUE_BINDING_RE`）在
    `MAP_KEY_VALUE_BINDING_KEYS` 里 —— 即键名**本身就叫**地图 Key（`mapKey` / `amapKey` /
    `amap_key` / `qqmapKey` / `bmapKey` / `googleMapKey` / `gdmapKey` …）。键名含 map 但语义
    不是「地图 Key 值位置」的复合键**不算**绑定：`MAPKEY_ENCRYPT_PUBLIC_KEY`、
    `over_pay_no_amapOrderId`、`businessCfgMapKey = i.configs.sq_mmmm_sec_key`、`key:` 都留给
    守卫处理（对照组 `naive_bind` 证明「任何键都算绑定」会让本轮修复失效）；
  · **不要求「必须绑定」**：真 Key 也会坐在 `return "…"` / 数组 / URL 查询串里，非标识符形的值
    一律照旧 —— 母任务明确不许「无差别收掉所有未绑定候选」。

保住的红线（逐条钉住）
---------------------
  · 腾讯 BZ 格式（绑定 / 未绑定 / 数组 / URL 查询串）与 `AIzaSy` 前缀一律留在 1401；
  · 32 位 hex 高德 Key（`AMAP_KEY:` 绑定、`t.amap_key = function() { return "…" }` 未绑定…）；
  · 坐在供应商键位上的标识符形值（`gdmapKey: "…"`）由绑定例外保留；
  · `is_map_secret_key` / `is_map_secret_key_by_neighbor` 一行未改（本文件做谓词级钉住；
    全库回放里这两条路一条链接都没变）。

已知残留（刻意不扩大判据，本文件钉住它们**保持**原判）
-----------------------------------------------------
  · 单段名字（`noMobileFallback` / `punish` 之类）：不在多段判据射程内；
  · 守卫之外的下游类型：语料里**根本没有**「只靠 `is_map_secret_key` 出口」的行
    （全库回放 0 条），地图 SecretKey 的真接口在更早的 app_key 支；
  · 前导分隔符的名字（`_ADDRESS_MAP_KEY_`）：`RE_IDENTIFIER_NAME_VALUE` 要求首字符是字母；
  · 未绑定但**非**标识符形的窄名（`noMobileFallback` 之外还有一批 133 值）：本轮不动。

用法: .venv/bin/python -X utf8 unit-tests/test_saas_map_key_identifier_names.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

MAP = IDT.SAAS_MAP_KEY

_GUARD = "is_unbound_identifier_name_map_candidate"
_BIND = "is_map_key_value_bound"


def _guard_on(v, stmt=""):
    """守卫判据（RED 阶段名字还不存在时按「判据未落地」处理，断言照跑）。"""
    fn = getattr(C, _GUARD, None)
    return bool(fn(v, stmt)) if fn else False


def _all_bound_keys(stmt, value):
    """对照组用：本值每个独立出现位置左侧紧邻的键（不限地图 Key 键表）。"""
    keys, pos = set(), stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            m = C._PAYMENT_VALUE_BINDING_RE.search(stmt, 0, pos)
            if m:
                keys.add(m.group(1))
        pos = stmt.find(value, pos + 1)
    return keys


def _classify(v, stmt, guard_off=False, guard_always=False, naive_bind=False):
    """跑一遍分类；三个开关各自只关掉本修复的一条判据，其余逐位不变。

    guard_off     ：守卫恒不生效（= 改动前行为）—— 用于「改动前确实在 1401」的前置断言。
    guard_always  ：守卫对**任何值**都说「未绑定的标识符名」—— 对照组：证明格式自证的两支
                    绕开守卫，腾讯/Google Key 不因守卫而掉出 1401。
    naive_bind    ：绑定豁免放宽成「任何键都算绑定」—— 对照组：证明键表收窄是修复的机制。
    三个开关都是模块级名字，函数体在调用时才查；名字不存在（RED 阶段）时按「本来就关着」处理
    （与 test_payment_param_placement.py / test_server_cookie_segmented_names.py 同一约定）。
    """
    saved = [(n, getattr(C, n)) for n in (_GUARD, _BIND) if hasattr(C, n)]
    if guard_off and hasattr(C, _GUARD):
        C.is_unbound_identifier_name_map_candidate = lambda s, stmt_="": False
    if guard_always and hasattr(C, _GUARD):
        C.is_unbound_identifier_name_map_candidate = lambda s, stmt_="": True
    if naive_bind and hasattr(C, _BIND):
        C.is_map_key_value_bound = lambda s, stmt_: bool(_all_bound_keys(stmt_, s))
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


# =========================================================
# ① 通用语境支：未绑定的多段标识符名 -> 不再出口 1401
# =========================================================
# (值, 语境) 取自 normal_quarkpan 真实 1401 链接（链接号写在注释里，普查数字见文件头）。
UNBOUND_CASES = [
    # 模块路径名：语境只是同语句里 require 了一个名字含 amap 的工具模块。
    ("mobx-miniprogram-bindings",
     'z=(require("~/utils/amap-fn"),require("mobx-miniprogram-bindings"))'),          # #51616
    # 枚举分支名：语境来自同一函数体里的 `o.isAmap ?`。
    ("MINIPROGRAM-ALIPAY",
     's = function() {\n            return o.isUC ? "MINIPROGRAM-UC" : o.isQuark ? '
     '"MINIPROGRAM-QUARK" : o.isAmap ? "MINIPROGRAM-AMAP" : o.isAlipay ? "MINIPROGRAM-ALIPAY" '
     ': o.isWeapp ? "MINIPROGRAM-WECHAT";\n        }'),                                # #194315
    # 常量名（值是常量自己的名字，语境来自 `e.mapKey`）。
    ("SET_TASK_TYPE_MAP_KEY",
     'r && r.forEach(function(e) {\n                                o[e.mapId] = e.mapValue, '
     'i[e.mapKey] = e.mapId, a[e.mapId] = e.mapKey;\n                            }), '
     't("SET_TASK_TYPE_MAP_KEY", i),'),                                                # #657717
    # 页面路由名（语料里整族 78 条链接的值长这样）。
    ("user-medicine-edit",
     'pages = ["memberManage__index", "user-medicine-edit", "membership-rights"]; '
     '// qqmapKey_release'),
    # 自赋值 i18n key：键名含 amap 但键位坐的是**名字**，不是地图 Key 值。
    ("over_pay_no_amapOrderId", 'over_pay_no_amapOrderId:"over_pay_no_amapOrderId"'),  # #16548899
    # 绑定在通用 `key:` 上的名字（键名不在地图 Key 键表里）。
    ("wm_bMapTransqqMap", 'key: "wm_bMapTransqqMap"'),                                 # #7461469
    # 同族：全大写 snake 的存储键，同样绑在通用 `key:` 上。
    ("TABBAR_GIF_RETREAT_MAP_KEY", 'key:"TABBAR_GIF_RETREAT_MAP_KEY"'),                # #516192
]


def test_unbound_identifier_names_dropped():
    """本轮射程：上面每个真实 (值, 语境) 都要离开 1401。"""
    for v, stmt in UNBOUND_CASES:
        got = _classify(v, stmt)
        assert MAP not in got, "%r in %r -> %r" % (v, stmt, got)


def test_guard_is_the_change():
    """对照：只关掉新守卫，它们全部回到 1401（证明这些失败确由本条判据负责）。"""
    for v, stmt in UNBOUND_CASES:
        got = _classify(v, stmt, guard_off=True)
        assert got == [MAP], "%r in %r -> %r" % (v, stmt, got)


def test_value_shape_predicate_is_the_mechanism():
    """机制断言：这批值确实过新判据（口径 = fix12 的 is_segmented_identifier_name）。"""
    for v, stmt in UNBOUND_CASES:
        assert C.is_segmented_identifier_name(v), "值形判据没覆盖: %r" % v
        assert _guard_on(v, stmt), "守卫没有对未绑定名生效: %r" % v


def test_guard_is_not_triggered_without_map_context():
    """作用面：守卫只在**地图语境**里起作用；同样的名字在别处本来就不产出，改动前后一样。"""
    for v, stmt in (("user-medicine-edit", 'pages = ["user-medicine-edit"]'),
                    ("mobx-miniprogram-bindings", 't = require("mobx-miniprogram-bindings")')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), (v, stmt)


# =========================================================
# ② 格式自证的两支一行未改：腾讯 BZ / Google 一条都不许丢
# =========================================================
# (值, 语境) 均取自真实 1401 链接；BZ 值里有几个恰好每段都是「字母+尾数字」，
# 会被 is_segmented_identifier_name 命中 —— 正是必须靠「格式支优先」保护的那批。
FORMAT_CASES = [
    # 未绑定（URL 查询串里拼出来的 6 段 BZ）。
    ("L5NBZ-GBGWQ-SZ75E-4BVOA-ZY6H6-4EBP2",
     'url: "https://apis.map.qq.com/ws/geocoder/v1/?location=".concat(o.latitude, ",")'
     '.concat(o.longitude, "&key=").concat("L5NBZ-GBGWQ-SZ75E-4BVOA-ZY6H6-4EBP2")'),  # #218461
    # 绑定在 mapKey 上的 BZ（该值被 is_segmented_identifier_name 命中）。
    ("BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE",
     'mapKey: "BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE"'),                                 # #3109108
    # 未绑定、坐在数组里的 BZ。
    ("BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE",
     'var c = [ "2AWBZ-2JLWT-CVNXX-LK6LK-OX3BV-AYFNX", '
     '"BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE" ]'),                                       # #7242086
    # Google 前缀（绑定在 googleMapKey 上）。
    ("AIzaSyDQtTDHBwTwgEAPgtcz2OLzj9kPPx9JB08",
     'googleMapKey: "AIzaSyDQtTDHBwTwgEAPgtcz2OLzj9kPPx9JB08"'),                       # #9019267
    # Google 前缀 + 未绑定（数组 / 普通字面量）。
    ("AIzaSyC-abcdefghijklmnopqrstuvwxyz012345",
     'var keys = [ "AIzaSyC-abcdefghijklmnopqrstuvwxyz012345" ]; // google map'),
]


def test_tencent_and_google_keys_kept():
    """格式自证值一律留在 1401（含未绑定、数组、URL 里拼出来的）。"""
    for v, stmt in FORMAT_CASES:
        got = _classify(v, stmt)
        assert got == [MAP], "%r in %r -> %r" % (v, stmt, got)


def test_format_paths_bypass_the_guard():
    """对照组：把守卫强行对**所有值**生效，腾讯/Google Key 仍必须留在 1401。

    这是「不许把守卫放到格式支上」的直接回归 —— 若有人把守卫上移到
    `is_any_map_key_format` 开头（或写进 `is_tencent_map_key_format` / Google 前缀判断里），
    这个用例立刻变红。
    """
    for v, stmt in FORMAT_CASES:
        got = _classify(v, stmt, guard_always=True)
        assert got == [MAP], "格式支被守卫吃掉: %r -> %r" % (v, got)


def test_tencent_shape_predicate_untouched():
    """腾讯/Google 的格式判据逐位不变。"""
    for v in ("L5NBZ-GBGWQ-SZ75E-4BVOA-ZY6H6-4EBP2", "BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE",
              "4Q5BZ-HGC6W-MDRRJ-R6KUU-I7KHS-5GBFQ", "2AWBZ-2JLWT-CVNXX-LK6LK-OX3BV-AYFNX"):
        assert C.is_tencent_map_key_format(v), v
    assert C.MAP_KEY_PREFIX_GOOGLE == "AIzaSy"
    assert C.is_any_map_key_format("AIzaSyDQtTDHBwTwgEAPgtcz2OLzj9kPPx9JB08") is True


# =========================================================
# ③ 通用语境支的真阳性：非标识符形的值一律照旧
# =========================================================
REAL_KEY_CASES = [
    # 32 位 hex 高德 Key：返回语句里，**未**绑定在地图 Key 键位上（"不要求必须绑定"）。
    ("3278cab2b6109454f583a8a256ca4eb8",
     't.amap_key = function() {\n                return "3278cab2b6109454f583a8a256ca4eb8";\n            }'),
    # 32 位 hex 高德 Key：绑定在 AMAP_KEY 上。
    ("daa94043c39c600e49f34d01b16fbd17", 'AMAP_KEY: "daa94043c39c600e49f34d01b16fbd17"'),
    # 24 位百度 AK（绑定在 bmapLocationKey 上）。
    ("Lb97YzuxwWGLIDYv8eOBVAn0G5xasQMG",
     'exports.bmapLocationKey = "Lb97YzuxwWGLIDYv8eOBVAn0G5xasQMG"'),
    # 32 位 hex 高德 Key：绑定在 amapKey 上。
    ("261de298e5bc9e33f9a34fa57c42b64d", 'p.amapKey=e.data||"261de298e5bc9e33f9a34fa57c42b64d"'),
    # 标识符形**但**坐在供应商键位上：绑定例外保留（键表 = 键名本身叫地图 Key）。
    ("gd-map-service-key-abc", 'gdmapKey: "gd-map-service-key-abc"'),
]


def test_real_map_keys_kept():
    """真 Key（hex/AK/绑定例外）一条都不许丢，且开关对它们无影响。"""
    for v, stmt in REAL_KEY_CASES:
        got = _classify(v, stmt)
        assert MAP in got, "%r in %r -> %r" % (v, stmt, got)
        assert got == _classify(v, stmt, guard_off=True), (v, stmt)


def test_guard_requires_identifier_shape():
    """守卫的射程：非标识符形的值（hex / 单段 / 数字段）一律不命中。"""
    for v in ("3278cab2b6109454f583a8a256ca4eb8", "Lb97YzuxwWGLIDYv8eOBVAn0G5xasQMG",
              "daa94043c39c600e49f34d01b16fbd17", "AIzaSyDQtTDHBwTwgEAPgtcz2OLzj9kPPx9JB08",
              "L5NBZ-GBGWQ-SZ75E-4BVOA-ZY6H6-4EBP2", "85b3-d912bf02d1d9",
              "noMobileFallback", "_ADDRESS_MAP_KEY_", "3f8a1c9d0e2b4a6f8c1d3e5b7a9c0d2e"):
        assert not C.is_segmented_identifier_name(v), v


# =========================================================
# ④ 值位置绑定：只认「键名本身叫地图 Key」的键
# =========================================================
def test_binding_helper_boundaries():
    """绑定判据本身的边界：只看紧邻本值的键，且只认地图 Key 键表。"""
    if not hasattr(C, _BIND):
        raise AssertionError("绑定判据 %s 未落地" % _BIND)
    B = C.is_map_key_value_bound
    assert B("gd-map-service-key-abc", 'gdmapKey: "gd-map-service-key-abc"') is True
    assert B("gd-map-service-key-abc", 'gdmapKey="gd-map-service-key-abc"') is True
    assert B("BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE",
             'mapKey: "BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE"') is True
    assert B("my-key-abcdef", 'amapKey: "my-key-abcdef"') is True
    assert B("my-key-abcdef", 'AMAP_KEY: "my-key-abcdef"') is True
    assert B("my-key-abcdef", 'map_key = "my-key-abcdef"') is True
    # 键名含 map 但语义不是「地图 Key 值位置」的复合键 -> 不算绑定
    assert B("crawler-public-key-id", 't.MAPKEY_ENCRYPT_PUBLIC_KEY = "crawler-public-key-id"') is False
    assert B("over_pay_no_amapOrderId", 'over_pay_no_amapOrderId:"over_pay_no_amapOrderId"') is False
    assert B("user-medicine-edit", 'businessCfgMapKey = i.configs.sq_mmmm_sec_key') is False
    assert B("wm_bMapTransqqMap", 'key: "wm_bMapTransqqMap"') is False
    assert B("el-amap-polyline", 'name: "el-amap-polyline"') is False
    assert B("amap-aos-order-bill-web", 'paySource:"amap-aos-order-bill-web"') is False
    # 无紧邻绑定
    assert B("user-medicine-edit", 'pages = ["user-medicine-edit"]') is False
    # 本值只是更长字面量的前缀/后缀时不算绑定（与 fix24 同一条细则：边界 = 字母数字 / `_` / `$`）
    assert B("map-key", 'gdmapKey: "mapkey_map-key"') is False
    assert B("map-key", 'gdmapKey: "map-key_suffix"') is False
    # 后缀是 `-` / `.` 时按 fix24 的同一口径仍算独立出现（本修复不单方面收紧这条细则，
    # 免得与 fix24/fix25 的绑定语义分叉；代价 = 少数「长连字符字面量的片段」被保留）。
    assert B("map-key", 'gdmapKey: "map-key-value"') is True


def test_binding_key_table_is_narrow():
    """键表是**小集合**：语料实测的地图 Key 键名在表内，通用键名（key / name / tag）在表外。"""
    K = getattr(C, "MAP_KEY_VALUE_BINDING_KEYS", None)
    assert K, "键表 MAP_KEY_VALUE_BINDING_KEYS 未落地"
    assert {"mapkey", "map_key", "amapkey", "amap_key", "qqmapkey",
            "bmapkey", "googlemapkey", "gdmapkey"} <= set(K)
    for generic in ("key", "name", "tag", "eventid", "serviceid", "interface", "classname"):
        assert generic not in K, generic


def test_naive_binding_control_group():
    """对照组：把「任何键都算绑定」当豁免，本轮修复立刻失效。

    这正是绑定豁免必须收窄到「键名本身叫地图 Key」的理由 —— 现行实现没踩。
    """
    v, stmt = "wm_bMapTransqqMap", 'key: "wm_bMapTransqqMap"'
    assert _classify(v, stmt) != [MAP]                        # 现行：收掉
    assert _classify(v, stmt, naive_bind=True) == [MAP]       # 对照组：留 1401
    v2, stmt2 = "over_pay_no_amapOrderId", 'over_pay_no_amapOrderId:"over_pay_no_amapOrderId"'
    assert MAP not in _classify(v2, stmt2)
    assert _classify(v2, stmt2, naive_bind=True) == [MAP]


# =========================================================
# ⑤ 地图 SecretKey 路径一行未改（谓词级钉住）
# =========================================================
SECRET_VALUE = "3f8a1c9d0e2b4a6f8c1d3e5b7a9c0d2e"
SECRET_STMT = ('a = { mapKey: "BMCBZ-WIICB-XBCU7-JGICI-NUVZ7-ZCBAE", '
               'secretKey: "3f8a1c9d0e2b4a6f8c1d3e5b7a9c0d2e" };')


def test_map_secret_key_predicates_untouched():
    """is_map_secret_key / is_map_secret_key_by_neighbor 的语义与守卫无关。"""
    assert C.is_map_secret_key(SECRET_VALUE, SECRET_STMT) is True
    assert C.is_map_secret_key(SECRET_VALUE, 'secretKey: "%s"' % SECRET_VALUE) is False
    # 守卫对 SecretKey 形的值不命中（字符集里没有分隔符 -> 单段）
    assert _guard_on(SECRET_VALUE, SECRET_STMT) is False
    # 守卫开关对这条路径的值逐位无影响
    for v, stmt in ((SECRET_VALUE, SECRET_STMT),
                    ("n3HCSO0JEBluIw9nmxc3AimBTLb963mV", 'SECRET_KEY: "n3HCSO0JEBluIw9nmxc3AimBTLb963mV"'),
                    ("7y1LQIaY0sf7GhbyApmB6fltzquaQtoH",
                     'mapKey: "RKRBZ-RCFEU-RMXVC-BXBPH-WADPJ-QHFIU", '
                     'secretKey: "7y1LQIaY0sf7GhbyApmB6fltzquaQtoH"')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), (v, stmt)


def test_real_secret_context_rows_unchanged():
    """真实 1401 桶里「语境含 secretKey」的行：守卫开关对它们逐位无影响。"""
    for v, stmt in (("1grnACaoguMXKxyU4kTNDqoWpbwfbBlL",
                     '(0, a.default)(this, t), (0, c.default)(this, "key", '
                     '"Q2JBZ-WJSC4-Z6TUO-FBGST-ODGIK-VBBKJ"), \n                    '
                     '(0, c.default)(this, "secretKey", "1grnACaoguMXKxyU4kTNDqoWpbwfbBlL");'),
                    ("85b3-d912bf02d1d9", 'key: "85b3-d912bf02d1d9"')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), (v, stmt)


# =========================================================
# ⑥ 已知残留：刻意不扩大判据，逐条钉住「保持原判」
# =========================================================
RESIDUAL_CASES = [
    # 单段名（多段判据的射程外，fix15 的同类残留）。
    ("noMobileFallback", 's = false, t = "noMobileFallback", qqmapKey = "x"'),
    # 前导分隔符的名字（RE_IDENTIFIER_NAME_VALUE 要求首字符是字母）。
    ("_ADDRESS_MAP_KEY_", '(0,s.$c)("_ADDRESS_MAP_KEY_",De)'),
]


def test_known_residuals_kept():
    """残留保持原判 —— 若有人放宽守卫（单段/前导分隔符/任意未绑定名），这里会变红。"""
    for v, stmt in RESIDUAL_CASES:
        assert _classify(v, stmt) == [MAP], "%r -> %r" % (v, _classify(v, stmt))
        assert not C.is_segmented_identifier_name(v), v


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
    print("fix26 saas_map_key 标识符名守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
