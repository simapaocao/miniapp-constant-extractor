#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix30：server_cred_token(1602) 十六进制出口的「标识符族键绑定」守卫。

病根
----
`process_hex_token` 的 token 出口是**裸子串**判据 —— `HEX_TOKEN_CONTEXT_WORDS`
（"token" / "auth" / "authorization" / "bearer" / "apikey" …）在值周围 512 字符窗口里出现即出口，
不管这个值坐在谁的键位、也无论窗口里那个词是不是它的。于是**绑在标识符键上的十六进制
ID**（文档 / 关系 / 文件 / 包摘要）整族被拽进 risk5 的凭证桶。

只读普查（normal_quarkpan，1602 桶全部 2,073 条链接 / 655 个值）：
  · 值的**每个**独立出现都绑在标识符族键（`id` / `target_id` / `source_id` / `_shasum` /
    `docId` / `objectId` / `uid` / `card_id`）= 183 条链接 / 42 个值；
    其中 168 条链接的值确实是 hex token（`_shasum` 35 / `id` 63 / `target_id` 58 /
    `source_id` 12），另 15 条是 `card_id` 上的 JWT（非 hex，走的是别的出口，本判据碰不到）；
  · 这 42 个值**没有一个**同时绑定 token/session 键（MIXED = 0）—— 标识符族键与凭证键在
    十六进制值上从不同时出现，「全绑标识符族」与「不绑凭证」是同一件事的两面；
  · 头部来源是真实的数据库导出片段与 npm 包锁：
      `"target_id":"dacfba484d601430cee54e19f3f08c1d"`（WIKI_ITEM → CODE_SNIPPET 关系表）
      `"source_id":"11d510058a1c1a62c026e58a90be2a3e"`（SOURCE_FILE → CODE_SNIPPET）
      `{"id":"dacfba…","path":"utils/auth.js"}`（代码片段清单）
      `"_shasum":"2904ab2677a9d042856a2ea2ef80de92e4a36dcc"`（npm 包锁里的 tarball sha1）
    它们进 1602 的路径都一样：窗口里恰好有 "token" / "auth"（`utils/auth.js`、`"author"`…）
    这类子串，而出口从不问「这个值是谁的值」。

判据（本轮只动 token 出口这一处）
----
  ① 本值每个**独立出现**左侧紧邻的键（口径 = 既有 `_bound_value_keys`，不新造扫描器）**全部**
     落在标识符族键表 `HEX_TOKEN_ID_BINDING_KEYS` 内，且**至少有一次绑定** → 值坐在 ID 位置，
     不是凭证 token，`process_hex_token` 直接返回（**不出口**）。
  ② 键表里**没有**任何一个 token/session 键（`token` / `auth*` / `apikey` / `session*` / `sid` /
     `credential` …），所以「全部键都在表内」本身就蕴含「没有任何一次出现绑在凭证键上」；
     任何一次出现绑在 `token:` / `authToken:` / `Authorization:` 上都会让本判据为假 ——
     这是 fix30 保护真凭证的那条线，由下面的保留组逐条钉住。
  ③ 只在 token 出口求值：本值没有 token 语境（只有 session 语境）时判据不参与，session 出口
     一行未改（本轮**不做** session 侧的正向绑定，见「刻意不做」）。
  ④ fix30b（真阳性损失修复）：`_PAYMENT_VALUE_BINDING_RE` 只要求「键 + 引号/空白 + `:`/`=` +
     引号/空白」的**邻接**，分不出 `:` 是成员分隔符还是三元/switch 分隔符。于是
     `const token=data.id?data.id:"<hex>"` 的候选键是三元真分支里的 `data.id`、`case id:` 的
     候选键是标签 —— 两者都在标识符族键表里 → 真 token 被静默消费。fix30b 在键归属上收严：
     真绑定位置（`=`、或左侧同一成员段里没有 `?` 的成员 `:`）才产出候选键；三元/`case` 的
     分隔符不产出，改归因到宿主键（`{token:x?y:"v"}` → `token`），且宿主键**只洗清、不定罪**
     （宿主键在标识符族键表内时不产出），最后一条保证归因修正只会减少误消费、不会新增消费。
     共用正则与 `_bound_value_keys` 一字未动（fix24/25/26/31/33 的调用面不受影响）。

归置（本轮的红线）
-----------------
  · 命中即**不出口**（无标签 = risk 0），与 `process_hex_token` 原有的「无语境不出口」同一种
    归置；`return` 而不是「放任落到下面的 elif」是刻意的 —— 若落到 `has_hex_session_context`
    分支，这批值会**平移进 risk5 的 server_cred_session_key**，那是把噪音从左口袋挪到右口袋
    （普查里双语境同时成立的链接为 0，但这是判据不变量，不是语料巧合）；
  · 保留组（绑在 token/session 键上、无绑定、混合绑定、`card_id` 上的 JWT）一条都不许动；
  · 只作用于 hex 出口：`process_prefixed_token`（JWT/前缀 token）与 session 出口逐位不变。

刻意不做（本轮授权之外）
-----------------------
  · session 侧的正向绑定（值绑在 `session`/`sid`/`credential` 键上）与 token 侧的正向绑定
    （值绑在 token 键上「必须出口」）都不在本轮 —— 探针不能干净区分这两族，留给后续轮次；
    本文件第 ④ 组把这两条边界钉成测试，避免下一轮误以为本判据已经覆盖它们。

用法: .venv/bin/python -X utf8 unit-tests/test_fix30_hex_token_id_binding.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

TOKEN = IDT.SERVER_CRED_TOKEN
SESSION = IDT.SERVER_CRED_SESSION_KEY

_GUARD_ATTRS = ("is_hex_token_id_bound",)


def _guard_on(v, stmt):
    """新判据（RED 阶段名字还不存在时按「判据未落地」处理，断言照跑）。"""
    fn = getattr(C, "is_hex_token_id_bound", None)
    return bool(fn(v, stmt)) if fn else False


def _classify(v, stmt, guard_off=False, naive_bind=False):
    """跑一遍分类；两个 Off 开关各自只关掉本修复的一条细则，其余逐位不变。

    guard_off：把新守卫还原成改动前（恒不生效）—— 用于「改动前确实在 1602」的前置断言。
    naive_bind：对照组：把「全部独立出现都绑标识符族键」放宽成「任一次出现绑标识符族键」
               —— 证明混合绑定（同一值既是 target_id 又是 token）会因此丢标签。
    两个开关都是模块级名字，函数体在调用时才查；名字不存在（RED 阶段）时按「本来就关着」
    处理（与 test_server_cookie_segmented_names.py 同一约定）。
    """
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if guard_off and hasattr(C, "is_hex_token_id_bound"):
        C.is_hex_token_id_bound = lambda s, st: False
    if naive_bind and hasattr(C, "is_hex_token_id_bound"):
        family = getattr(C, "HEX_TOKEN_ID_BINDING_KEYS", frozenset())
        C.is_hex_token_id_bound = lambda s, st: any(
            k.lower() in family for k in C._bound_value_keys(s, st))
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


# =========================================================
# ① 标识符族键上的十六进制值：不再出口 1602
# =========================================================
# (值, 语境) 全部取自 normal_quarkpan 真实 1602 链接（普查数字见文件头）；
# 长语句按原样保留键与值的一小段上下文，未做任何「为通过判据」的改写。
ID_BOUND_CASES = [
    # i18n/文案表里的 `id`（63 条链接族）：窗口里的 "token" 来自同语句的 eventCenter 触发对象。
    ("06b4efa22aaa49c1bed8fe4d038c5af8",
     'y.a.showToast({icon:"none",title:$.formatMessage({id:"06b4efa22aaa49c1bed8fe4d038c5af8",'
     'defaultMessage:"小红书不支持0元单"}),icon:"none"}),Be=function(){Fe()&&'
     'y.a.eventCenter.trigger(M["f"],{token:w&&w.token})'),
    # 代码片段清单里的 `id`：窗口里的 "auth" 来自同一条记录的 path `utils/auth.js`。
    ("dacfba484d601430cee54e19f3f08c1d",
     '{"id":"dacfba484d601430cee54e19f3f08c1d","path":"utils/auth.js","line_range":"1-9",'
     '"gmt_create":"2026-05-20T03:26:00.385752+08:00","gmt_modified":"2026-05-20T03:26:00.385752+08:00"}'),
    # 关系表里的 `target_id`（58 条链接族）。
    ("dacfba484d601430cee54e19f3f08c1d",
     '{"id":982,"source_id":"ae2d4ada-f55a-4429-8c8a-2085e2bf53b1",'
     '"target_id":"dacfba484d601430cee54e19f3f08c1d","source_type":"WIKI_ITEM",'
     '"target_type":"CODE_SNIPPET","relationship_type":"CONTAINS",'
     '"extra":"Wiki contains code snippet: utils/auth.js#1-9"}'),
    # 关系表里的 `source_id`（12 条链接族）。
    ("11d510058a1c1a62c026e58a90be2a3e",
     '{"id":983,"source_id":"11d510058a1c1a62c026e58a90be2a3e",'
     '"target_id":"dacfba484d601430cee54e19f3f08c1d","source_type":"SOURCE_FILE",'
     '"target_type":"CODE_SNIPPET","extra":"Source file contains code snippet: utils/auth.js#1-9"}'),
    # npm 包锁里的 `_shasum`（35 条链接族）：窗口里的 "auth" 来自同一个对象里的 `"author"`。
    ("2904ab2677a9d042856a2ea2ef80de92e4a36dcc",
     '"crypto-js","escapedName":"crypto-js","fetchSpec":"latest"},"_requiredBy":["#USER","/"],'
     '"_resolved":"http://r.tnpm.oa.com/crypto-js/download/crypto-js-4.0.0.tgz",'
     '"_shasum":"2904ab2677a9d042856a2ea2ef80de92e4a36dcc","_spec":"crypto-js",'
     '"author":{"name":"Evan Vosberg","url":"http://github.com/evanvosberg"}'),
]


def test_id_bound_hex_dropped():
    """本轮射程：上面每个真实 (值, 语境) 都要离开 1602。"""
    for v, stmt in ID_BOUND_CASES:
        got = _classify(v, stmt)
        assert TOKEN not in got, "%r in %r -> %r" % (v, stmt, got)


def test_guard_is_the_change():
    """对照：只关掉新守卫，它们全部回到 1602（证明这些失败确由本条判据负责）。"""
    for v, stmt in ID_BOUND_CASES:
        assert _classify(v, stmt, guard_off=True) == [TOKEN], (v, stmt)


def test_id_bound_cases_reach_the_hex_exit():
    """机制断言：这批值确实走 `is_hex_token` 这条路（否则本判据根本没机会生效）。"""
    for v, stmt in ID_BOUND_CASES:
        assert C.is_hex_token(v), v
        assert C.has_keyword_substring(stmt.lower(), C.HEX_TOKEN_CONTEXT_WORDS), stmt
        assert _guard_on(v, stmt), "判据没覆盖: %r in %r" % (v, stmt)


def test_guard_helper_boundaries():
    """判据本身的边界：只看紧邻本值的键、只认标识符族键、且要求**全部**出现都是这种绑定。"""
    if not hasattr(C, "is_hex_token_id_bound"):
        raise AssertionError("判据 is_hex_token_id_bound 未落地")
    G = C.is_hex_token_id_bound
    assert G("dacfba484d601430cee54e19f3f08c1d",
             '{"target_id":"dacfba484d601430cee54e19f3f08c1d"}') is True
    assert G("2904ab2677a9d042856a2ea2ef80de92e4a36dcc",
             '"_shasum":"2904ab2677a9d042856a2ea2ef80de92e4a36dcc"') is True
    assert G("11d510058a1c1a62c026e58a90be2a3e",
             '{"source_id":"11d510058a1c1a62c026e58a90be2a3e"}') is True
    assert G("dacfba484d601430cee54e19f3f08c1d", '{"id":"dacfba484d601430cee54e19f3f08c1d"}') is True
    # 大小写不敏感（键表按小写查表）：`TARGET_ID` / `_SHASUM` 同样认
    assert G("dacfba484d601430cee54e19f3f08c1d",
             '{"TARGET_ID":"dacfba484d601430cee54e19f3f08c1d"}') is True
    # 无绑定 -> 不放行（判据要求「至少一次绑定」）
    assert G("dacfba484d601430cee54e19f3f08c1d", 'x = "dacfba484d601430cee54e19f3f08c1d"') is False
    # 任一次出现绑在凭证键上 -> 整值不放行（本值必须**全部**出现都在标识符族键上）
    assert G("dacfba484d601430cee54e19f3f08c1d",
             'p={target_id:"dacfba484d601430cee54e19f3f08c1d"},t={token:"dacfba484d601430cee54e19f3f08c1d"}'
             ) is False
    assert G("dacfba484d601430cee54e19f3f08c1d",
             'p={target_id:"dacfba484d601430cee54e19f3f08c1d"},s={sessionId:"dacfba484d601430cee54e19f3f08c1d"}'
             ) is False
    # 非标识符族键（哪怕是「键名含 id」的复合键）不放行：`targetId` / `card_id_token` 都不在表内
    assert G("dacfba484d601430cee54e19f3f08c1d",
             '{"targetId":"dacfba484d601430cee54e19f3f08c1d"}') is False
    assert G("dacfba484d601430cee54e19f3f08c1d",
             '{"card_id_token":"dacfba484d601430cee54e19f3f08c1d"}') is False
    # 本值只是更长字面量的前缀/后缀时不算绑定（与 fix24/fix25/fix26 同一条细则）
    assert G("id", 'target_id: "x_id"') is False
    assert G("dacfba484d601430cee54e19f3f08c1d",
             'target_id: "xdacfba484d601430cee54e19f3f08c1d"') is False


# =========================================================
# ①b fix30b：三元 `? :` 与 switch `case` 的分隔符冒号不是绑定位置
# =========================================================
# 病根（真阳性损失）：`_PAYMENT_VALUE_BINDING_RE` 只要求「键 + 引号/空白 + `:`/`=` + 引号/空白」
# 的**邻接**，分不出这个 `:` 是成员分隔符还是三元/switch 分隔符。于是三元分支里的 `id`、
# `case id:` 的标签被当成「本值的绑定键」，而它们恰好都在标识符族键表里 → 真 token 静默丢弃：
#     const token=data.id?data.id:"<hex>"    ← 真正的绑定是 `token =`，不是三元真分支的 data.id
#     x={token:cfg.id?cfg.id:"<hex>"}         ← 同上（三元冒号）
#     switch(x){case id:"<hex>"}              ← `case id:` 是标签，不是成员绑定
# 三条在改动前都是「守卫为真 → 无标签」，而关掉守卫都是 1602（= 改动前的代码路径）。
_TC_MISPARSE_HEX = "3f9a1c7d4b2e8065aa17ff34c2de9015"
TERNARY_CASE_MISPARSE_CASES = [
    ("const token=data.id?data.id:\"%s\"" % _TC_MISPARSE_HEX, "三元真分支里的 `id`"),
    ('x={token:cfg.id?cfg.id:"%s"}' % _TC_MISPARSE_HEX, "对象成员上的三元冒号"),
    ('switch(x){case id:"%s",token:t}' % _TC_MISPARSE_HEX, "switch 的 `case id:` 标签"),
]


def test_ternary_and_case_misparse_kept():
    """三元 / case 标签里的标识符族键不是绑定 → 真 token 照旧出口 1602。"""
    for stmt, why in TERNARY_CASE_MISPARSE_CASES:
        assert _guard_on(_TC_MISPARSE_HEX, stmt) is False, (why, stmt)
        got = _classify(_TC_MISPARSE_HEX, stmt)
        assert got == [TOKEN], (why, stmt, got)


def test_misparse_guard_off_matches_on():
    """修复后守卫开关对这三条不再有差别（改动前：守卫开着就丢标签）。"""
    for stmt, why in TERNARY_CASE_MISPARSE_CASES:
        assert _classify(_TC_MISPARSE_HEX, stmt) == _classify(_TC_MISPARSE_HEX, stmt,
                                                              guard_off=True), (why, stmt)
        assert TOKEN in _classify(_TC_MISPARSE_HEX, stmt, guard_off=True), (why, stmt)


def test_ternary_case_are_not_id_bound_but_plain_case_key_is():
    """边界：`case` 只作为**标签**时不算绑定；作为键名/标识符时不受影响。"""
    G = C.is_hex_token_id_bound
    # case 标签：不产出 ID 键
    assert G(_TC_MISPARSE_HEX, 'switch(x){case id:"%s",token:t}' % _TC_MISPARSE_HEX) is False
    # `case` 作为普通键名（不在 case 关键字位）→ 键表外，照样不放行
    assert G(_TC_MISPARSE_HEX, '{"case":"%s"}' % _TC_MISPARSE_HEX) is False
    # `obj.case` 这种成员名带点：`case` 前面的 `.` 不是 switch 关键字位
    assert G(_TC_MISPARSE_HEX, '{"obj.case":"%s"}' % _TC_MISPARSE_HEX) is False
    # 真绑定照旧：`id:` 直接绑定仍然算 ID 位
    assert G(_TC_MISPARSE_HEX, '{"id":"%s"}' % _TC_MISPARSE_HEX) is True


def test_ternary_branch_of_token_key_blocks_guard():
    """混合归因：三元分支属于**凭证键**时，这次出现照样让整值不放行（不许新增消费）。

    若把「三元里的键一律忽略」写成「这次出现没有绑定」，同一值另一处 `id:` 绑定就会让整值
    被判 ID 位 —— 那个分支确实是 token 的值，所以宿主键必须参与。"""
    v = "dacfba484d601430cee54e19f3f08c1d"
    stmt = ('const p={id:"dacfba484d601430cee54e19f3f08c1d"};'
            'const q={token:a?b:"dacfba484d601430cee54e19f3f08c1d"}')
    assert _guard_on(v, stmt) is False
    assert _classify(v, stmt) == [TOKEN], _classify(v, stmt)


def test_ternary_branch_host_key_only_exonerates():
    """宿主键**只洗清、不定罪**：三元分支的宿主键本身是标识符族键时不产出（不新增消费）。

    `{"id":cond?a:"<hex>",token:t}` 里 `a` 是三元的真分支、`id` 是宿主键；改动前它走的是
    「候选键 `a` 不在表内 → 不放行」，修复后必须保持一致（不能让归因修正顺手多消费一个值）。"""
    v = "dacfba484d601430cee54e19f3f08c1d"
    stmt = '{"id":cond?a:"%s",token:t}' % v
    assert _guard_on(v, stmt) is False
    assert _classify(v, stmt) == [TOKEN], _classify(v, stmt)
    assert _classify(v, stmt) == _classify(v, stmt, guard_off=True)


def test_mongo_style_id_keys_covered():
    """fix30c：Mongo/导出式拼写的 `_id` / `doc_id` 与 `id` 同族（零实测影响的补齐）。"""
    for stmt in ('{"_id":"dacfba484d601430cee54e19f3f08c1d"}',
                 '{"doc_id":"dacfba484d601430cee54e19f3f08c1d"}'):
        assert _guard_on("dacfba484d601430cee54e19f3f08c1d", stmt) is True, stmt
    # 大小写不敏感与「全部键都在表内」两条规则不变
    assert C.is_hex_token_id_bound("dacfba484d601430cee54e19f3f08c1d",
                                   '{"_ID":"dacfba484d601430cee54e19f3f08c1d"}') is True
    assert C.is_hex_token_id_bound("dacfba484d601430cee54e19f3f08c1d",
                                   '{"_id":"dacfba484d601430cee54e19f3f08c1d",'
                                   '"token":"dacfba484d601430cee54e19f3f08c1d"}') is False


# =========================================================
# ② 真凭证：绑在 token/session 键上的十六进制值一条都不许动
# =========================================================
# 值/语境取自真实 1602 链接；`authToken` / `Bearer` / `targetId` 三例是按同一形态补的白盒边界。
TOKEN_BOUND_CASES = [
    ("14cbedd99fa469cab80c5ee6eb05c111", 'token:"14cbedd99fa469cab80c5ee6eb05c111"'),
    ("1561f014bb013bbf84003eaa5a251bb6", 't.authToken = "1561f014bb013bbf84003eaa5a251bb6"'),
    ("4b3ec9c2661e68956fb5bd160b953d9b", 'Authorization:"4b3ec9c2661e68956fb5bd160b953d9b"'),
    ("4b3ec9c2661e68956fb5bd160b953d9b",
     'config.headers.Authorization = "Bearer 4b3ec9c2661e68956fb5bd160b953d9b"'),
    ("D4A3E7BA9409ECF946F243714510F81B", 'authKey: "D4A3E7BA9409ECF946F243714510F81B"'),
    ("1561f014bb013bbf84003eaa5a251bb6", '"jwt_token":"1561f014bb013bbf84003eaa5a251bb6"'),
]


def test_token_bound_hex_kept():
    """保护组：绑在 token 键上（含 `Bearer` 前缀写法）照旧判 1602。"""
    for v, stmt in TOKEN_BOUND_CASES:
        got = _classify(v, stmt)
        assert got == [TOKEN], "%r in %r -> %r" % (v, stmt, got)
        assert not _guard_on(v, stmt), (v, stmt)


def test_mixed_binding_kept():
    """混合绑定：同一个值既绑 target_id 又绑 token -> 不放行（普查 MIXED = 0 的那条线）。"""
    v = "dacfba484d601430cee54e19f3f08c1d"
    stmt = ('const p={target_id:"dacfba484d601430cee54e19f3f08c1d"};'
            'const t={token:"dacfba484d601430cee54e19f3f08c1d"}')
    assert _classify(v, stmt) == [TOKEN], _classify(v, stmt)
    assert not _guard_on(v, stmt)


def test_unbound_hex_with_token_window_kept():
    """无绑定：窗口里有 "token" 但本值没坐在任何键位 -> 照旧判 1602（本判据不要求「必须绑定」）。"""
    v = "c01e37eb5aa94329a313c61e35f4050f"
    stmt = ('y.a.showToast({title:ee("c01e37eb5aa94329a313c61e35f4050f","请同意")}),'
            'Fe()&&y.a.eventCenter.trigger(M["f"],{token:w&&w.token})')
    assert _classify(v, stmt) == [TOKEN], _classify(v, stmt)
    assert not _guard_on(v, stmt)


def test_prefixed_jwt_token_untouched():
    """`card_id` 上的 JWT（非 hex，走的是前缀 token 出口）：本判据碰不到，照旧 1602。"""
    v = ("eyJtb2R1bGVfbmFtZSI6InNlY2tpbGxfdjI2NDNkNWRhZWQyNzgyIiwiY291cG9uX2NvZGUiOjQs"
         "InF0Ijoic2hhdW5nc2hpeWljYXIiLCJpc19wcmV2IjowLCJyIjoxNzE2MjAyNjU2fQ==")
    stmt = 'card_id: "%s"' % v
    assert not C.is_hex_token(v)
    assert _classify(v, stmt) == [TOKEN], _classify(v, stmt)


def test_naive_any_binding_control_group():
    """对照组：把判据放宽成「任一次出现绑标识符族键」，混合绑定的真 token 就丢了。

    这正是判据必须写成「**全部**出现都在标识符族键上」的理由 —— 现行实现没踩。
    """
    v = "dacfba484d601430cee54e19f3f08c1d"
    stmt = ('const p={target_id:"dacfba484d601430cee54e19f3f08c1d"};'
            'const t={token:"dacfba484d601430cee54e19f3f08c1d"}')
    assert _classify(v, stmt) == [TOKEN]                       # 现行：留住
    assert TOKEN not in _classify(v, stmt, naive_bind=True)     # 对照组：丢掉


# =========================================================
# ③ 作用面：只动 token 出口，且归置是 risk 0
# =========================================================
def test_destination_is_risk0_not_session_key():
    """命中后的归置：既不出口 1602，也**不许**平移进 risk5 的 session 桶。

    双语境（窗口里同时有 token 与 session 词）在普查里 0 条，但判据写成 `return` 而不是
    「放任落到 elif」，就是为了让这条不变量不依赖语料巧合。
    """
    v = "dacfba484d601430cee54e19f3f08c1d"
    stmt = ('const p={target_id:"dacfba484d601430cee54e19f3f08c1d"};'
            'e.sessionId=p.target_id;e.token=t')
    assert _classify(v, stmt, guard_off=True) == [TOKEN]     # 改动前：token 出口先命中
    got = _classify(v, stmt)
    assert got == [], got                                    # 改动后：无标签（risk 0）
    assert SESSION not in got, got


def test_session_exit_untouched():
    """本轮**不做** session 侧的正向绑定：只有 session 语境时判据不参与，出口逐位不变。"""
    v = "dacfba484d601430cee54e19f3f08c1d"
    stmt = 'const p={target_id:"dacfba484d601430cee54e19f3f08c1d"};e.sessionId=p.target_id'
    assert not C.has_keyword_substring(stmt.lower(), C.HEX_TOKEN_CONTEXT_WORDS)
    assert _classify(v, stmt) == [SESSION], _classify(v, stmt)
    assert _classify(v, stmt) == _classify(v, stmt, guard_off=True)


def test_guard_is_token_branch_only():
    """作用面：本判据不留任何窗口外的副作用 —— 别的桶与别的出口逐位不变。"""
    # ① ObjectID 形态（入口就拦掉）与幂等性无关：开关对结果无影响
    for v, stmt in (("05e6a3b3d0e0c0e1e2e3e4e5", '{"id":"05e6a3b3d0e0c0e1e2e3e4e5",'
                                               'token:"05e6a3b3d0e0c0e1e2e3e4e5"}'),):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), (v, stmt)
    # ② 非 hex 值（含 `=` 的 base64 / 短串）本就不过 hex 出口：开关对结果无影响
    for v, stmt in (("dacfba484d601430cee54e19f3f08c1d=", '{"id":"dacfba484d601430cee54e19f3f08c1d="}'),
                    ("dacfba", '{"id":"dacfba","token":"x"}')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), (v, stmt)


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
    print("fix30 hex token 标识符族绑定守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
