"""支付 timestamp 误报（fix24）：支付关键词必须**绑定到本值**，裸窗口关键词不再出口。

背景（根因）
------------
噪音不在支付判据 `is_payment_param`（fix11 已把值侧收严成「值 == 参数名」），而在
**数字开头链** `process_generic_digit_prefixed_constant` 末尾那条通用语境词循环
（`for keyword, slug_id in CONTEXT_KEYWORDS.items()`）：

  · CONTEXT_KEYWORDS 里 `"timestamp" → PAYMENT_REQUEST_PARAMS(2401)` 是**裸子串**出口，
    窗口（值周围 512 字符）里只要出现过 timestamp 子串就出口，与值是不是支付参数无关；
  · dict 顺序把 `paysign`(2405)/`noncestr`(2402) 排在 `timestamp` 之前，于是**真实支付对象**里
    `timeStamp` 的值反而落到 2405/2402（错 slug）——只有当窗口里没有 paysign/noncestr 时才对。

只读回放实测（`test-result/fix24/replay_payment_timestamp.py`，样本 = 两库支付桶全量 +
非支付桶前 40000 行，按 m.id 确定性排序；库 = normal_quarkpan / unlist_package_reference_v2）：

  payment_request_params   qk 561 值 / 774 链接、pkgref 26 值 / 37 链接；
  其中 qk 409 值与 pkgref 5 值紧邻绑定在**小写通用** `timestamp:` 上，窗口里**没有任何**
  支付证据词；qk 另 49 值是驼峰规范写法 `timeStamp:`（本文件要求保留）。
  噪音形态（source_snippet 原文摘录）：
    `{"chatItemType":"x","timestamp":"2025-01-02T03:04:05.678Z"}`  聊天 ISO 时间（qk 332 去重值）
    `timestamp: "1594869381185"` / `B.timestamp="1642664673"`       普通聊天/业务时间戳
    `ReportTimestamp:"20220617012706"` / `cTimeStamp:"1701304105774"`  前缀式键名（不是 timeStamp）
    `e=["1a2B3c4D5e6F","timestamp"]`                                与前一个值无关的数组元素
    `t=["690222OIsqLk",…,"_$uCountDownTimestamp",…]`                webpack 分包名数组（pkgref）
    `o="…&timestamp=".concat(new Date().getTime(),"94wSot…")`       URL 查询串拼接
    `"userinfo","pay/addapppay","nonceStr",`                        分包名数组撞上 nonceStr
    `n="appKey=".concat("123456789012345",…)`                       appKey 被窗口里的 timestamp 牵连

修法（只动数字开头链，两处）
----------------------------
  ① 值位置绑定 `_payment_param_slug_bound_to_value`：只看紧邻本值的 `键:` / `键=` / `"键":`
     （键与值之间只允许引号/空格），额外允许 `键: 表达式 || "字面量"` 这种默认值写法。
     本值每次出现都必须**自成字面量**：前/后紧邻标识符字符（字母数字 `_` `$`）的出现不算
     —— 否则「本值只是更长字面量的前缀/后缀」时会把那个字面量的键算到本值头上。
     绑定的键先按 PAYMENT_PARAM_NAMES **精确拼写**（大小写敏感）查表：
       · `timeStamp`（驼峰规范写法）→ 2401，不要求别的证据（保留既有真阳性契约）；
       · `timestamp` / `time_stamp` 等通用写法 → 必须同窗口出现支付证据词才判 2401，
         否则**只跳过这一次出现**、继续扫描本值的其余出现（不能直接否定整个值）；
       · `nonceStr` / `paySign` / `signType` → 2402 / 2405 / 2404（值位置口径）。
     精确拼写查不到时，再按**族内复合键名**放行：键名含 paysign / pay_sign / noncestr /
     nonce_str 之一 → 2405 / 2402（`alipaySignAsac`、`X-PA-NONCESTR` 一族，是真阳性）；
     **timestamp 族绝不参与**这种复合放行（ReportTimestamp / cTimeStamp / BUILD_TIMESTAMP
     / dumpEventTimeStamp / couponTimeStamp* / webtimestamp 一律不判支付）。
  ② `CONTEXT_KEYWORDS` 的三条支付关键词（paysign/noncestr/timestamp）不再作为裸窗口出口，
     即在数字开头链的通用循环里跳过（其余关键词 cookie/appsecret/region/bucket 一律不变）。

本文件固化的边界：
  1) ①里 9 个噪音形态不再判任何支付类型（去向 = 本链既有兜底 pii_noise，不新增类型产出）；
  2) 真阳性一个不许掉：`timeStamp:` 的值仍 2401（含 timeStamp 排在 nonceStr/paySign **之后**
     的真实支付对象 —— 那正是 dict 顺序造成的错 slug）、nonceStr/paySign 的值仍 2402/2405、
     `TIMESTAMP` 参数名与 `prepay_id=` 一律不动；
  3) 判据不是「出现支付词就放行」也不是「出现就拒」：**同窗口有支付词但本值绑在别的键上**
     （orderId / code / appKey）仍不判支付；
  4) 复合键名（alipaySignAsac / X-PA-NONCESTR 一族）**按族内规则保留**，不再当噪音丢弃
     （见 ④ 的两条正向断言）；边界仍是：timestamp 族的复合键名一律不放行。
  5) 已知代价显式记录（test_known_cost_* 一处）：`…&timestamp=".concat("1666231449")` 这类
     **URL 查询参数**的时间值不再有支付标签（它确实是时间戳参数，但不是微信 requestPayment
     参数；2401 的语义是后者；改动前它靠窗口里的 `&nonceStr=` 落到 2402）。
  5) 不确定的片段按「保留既有分类」之外的保守方向处理：只要本值没有紧邻支付键绑定，
     就绝不因为窗口里出现支付词而**新增**支付标签（宁可漏，不可错标）。

标注「实测」的期望值由 test-result/fix24/ 下的只读回放对着两库真实 (值, source_snippet) 跑出来。
值里凡是凭证形态（nonceStr/paySign/复合签名值）一律按形状替换成同长度同大小写的合成值，
原始值只在未入库的 test-result/fix24/*.tsv 里，不写进本文件。

用法: .venv/bin/python -X utf8 unit-tests/test_payment_param_placement.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PRP = IDT.PAYMENT_REQUEST_PARAMS
NONCE = IDT.PAYMENT_NONCE
PAYSIGN = IDT.PAYMENT_PAY_SIGN
PACKAGE = IDT.PAYMENT_PACKAGE
SIGNTYPE = IDT.PAYMENT_SIGN_TYPE
NOISE = IDT.PII_NOISE
PAY_ALL = (PRP, NONCE, PAYSIGN, PACKAGE, SIGNTYPE, IDT.PAYMENT_SECRET)


_FIX_ATTRS = ("_PAYMENT_VALUE_ONLY_SLUGS", "_payment_param_slug_bound_to_value")


def _slugs(value, stmt, fix_on=True):
    """跑一遍分类；fix_on=False 时只关掉 fix24 的两处判据（还原改动前行为）。

    两个开关都是模块级名字，函数体在调用时才查——关掉后本文件之外的判定逐位不变。
    名字不存在时（fix24 未落地，即 RED 阶段）按「本来就关着」处理，断言照跑。
    """
    saved = [(n, getattr(C, n)) for n in _FIX_ATTRS if hasattr(C, n)]
    if not fix_on:
        if hasattr(C, "_PAYMENT_VALUE_ONLY_SLUGS"):
            C._PAYMENT_VALUE_ONLY_SLUGS = ()
        if hasattr(C, "_payment_param_slug_bound_to_value"):
            C._payment_param_slug_bound_to_value = lambda *a, **k: None
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(value, 0, "test.js")])]
    finally:
        for name, fn in saved:
            setattr(C, name, fn)


# =========================================================
# 两库真实上下文（source_snippet 原文摘录，值按形状合成）
# =========================================================
SN_CHAT_ISO = '{"chatItemType":"x","timestamp":"2025-01-02T03:04:05.678Z"}'
SN_CHAT_EPOCH = '{"conversation":{"timestamp":"1709632449000"}}'
SN_REPORT = 'ReportTimestamp:"20220617012706"'
SN_ARRAY = 'e=["1a2B3c4D5e6F","timestamp"]'
SN_QK_LOWER = 'timestamp: "1594869381185"'                       # qk 561 值的主力形态
SN_QK_LOWER2 = 'timestamp:"1600162856204"'
SN_PKGREF_DOT = 'B.timestamp="1642664673"'                       # pkgref：成员赋值的小写 timestamp
SN_ICP_PREFIX = 'cTimeStamp: "1701304105774"'                    # icp：前缀式键名
SN_WEBPACK = ('t=["690222OIsqLk","$createElement","checkKeepRunning","_$uCountDownTimestamp",'
              '"secNum","13315352xOHzoG","start","createComponent"]')
SN_LIST_NONCE = '"userinfo", "pay/addapppay", "nonceStr",'
SN_QUERY_CONCAT = ('o = "bar=2&baz=3&foo=1&timestamp=".concat(new Date().getTime(), "94wSotw")')
SN_APPKEY = 'n = "appKey=".concat("123456789012345", "&nonceStr=").concat(e, "&timestamp=")'
SN_PHP_SIGN = ('t = "https://x/#/a?appId=".concat("wx1", "&signature=")'
               '.concat("0a1b2c3d4e5f60718293a4b5c6d7e8f901234567", "&nonceStr=")'
               '.concat("1f2e3d4c5b6a7988071625344352617089abcdef", "&timestamp=").concat("1666231449", "&access_token=")')
SYN_NONCE = "7Q9375KNVLD27ER4724UN9BPOQV9XY"     # 形状同真实 nonceStr 值
SYN_PAYSIGN = "5A17B2C9D4E6F8A3C5E7"             # 形状同真实 paySign 值
SYN_ALIPAY_SIGN = "4C31E27YII9ZJJZOD8UB5C"       # 形状同真实 alipaySignAsac 值
SN_ALIPAY_HDR = 'alipaySignAsac:"4C31E27YII9ZJJZOD8UB5C"'


# =========================================================
# ① 噪音不再判支付（改动前全部判支付，见每条的 fix_on=False 对照）
# =========================================================
def test_chat_iso_timestamp_not_payment():
    """聊天 ISO 时间戳（{"chatItemType":…,"timestamp":"2025-…Z"}）：不是 requestPayment 参数。"""
    got = _slugs("2025-01-02T03:04:05.678Z", SN_CHAT_ISO)
    assert not [s for s in got if s in PAY_ALL], got
    assert PRP in _slugs("2025-01-02T03:04:05.678Z", SN_CHAT_ISO, fix_on=False)


def test_chat_epoch_generic_timestamp_not_payment():
    """普通会话里的毫秒时间戳（小写通用 timestamp 键 + 无支付证据）不再判 2401。

    这是本修复里**最保守**的一条：通用写法没有支付证据就不出口。代价见文件头第 4 条 ——
    若某个真实支付流程只用小写 `timestamp` 且同一窗口里没有 requestPayment/prepay_id/
    nonceStr/paySign/signType/package 任一证据词，该值会漏。驼峰 `timeStamp`（微信写法）
    不受影响（见 ② 的保留组）。
    """
    got = _slugs("1709632449000", SN_CHAT_EPOCH)
    assert not [s for s in got if s in PAY_ALL], got
    assert PRP in _slugs("1709632449000", SN_CHAT_EPOCH, fix_on=False)


def test_report_prefixed_key_not_payment():
    """前缀式键名 ReportTimestamp 不是支付键 timeStamp（qk 6 行）。"""
    got = _slugs("20220617012706", SN_REPORT)
    assert PRP not in got, got
    assert PRP in _slugs("20220617012706", SN_REPORT, fix_on=False)


def test_unbound_array_element_not_payment():
    """`e=["1a2B3c4D5e6F","timestamp"]`：本值在数组里，与 timestamp 字符串元素无关。"""
    got = _slugs("1a2B3c4D5e6F", SN_ARRAY)
    assert not [s for s in got if s in PAY_ALL], got
    assert PRP in _slugs("1a2B3c4D5e6F", SN_ARRAY, fix_on=False)


def test_plain_lowercase_timestamp_not_payment():
    """qk 主力噪音：`timestamp: "<epoch>"`（无支付证据）不再判 2401（两个真实片段）。"""
    for v, sn in (("1594869381185", SN_QK_LOWER), ("1600162856204", SN_QK_LOWER2)):
        got = _slugs(v, sn)
        assert PRP not in got, (v, got)
        assert PRP in _slugs(v, sn, fix_on=False), v


def test_member_assign_lowercase_timestamp_not_payment():
    """pkgref：`B.timestamp="<epoch>"` 成员赋值同样不再判 2401。"""
    got = _slugs("1642664673", SN_PKGREF_DOT)
    assert PRP not in got, got
    assert PRP in _slugs("1642664673", SN_PKGREF_DOT, fix_on=False)


def test_prefixed_key_names_not_payment():
    """前缀式键名（cTimeStamp / dumpEventTimeStamp / couponTimeStampStart 一族）不是支付键。"""
    got = _slugs("1701304105774", SN_ICP_PREFIX)
    assert PRP not in got, got
    assert PRP in _slugs("1701304105774", SN_ICP_PREFIX, fix_on=False)


def test_webpack_chunk_array_not_payment():
    """pkgref：webpack 分包名数组撞上 `_$uCountDownTimestamp` 子串，不再判 2401。"""
    got = _slugs("690222OIsqLk", SN_WEBPACK)
    assert PRP not in got, got
    assert PRP in _slugs("690222OIsqLk", SN_WEBPACK, fix_on=False)


def test_chunk_name_list_beside_nonce_keyword_not_nonce():
    """qk：`"userinfo","pay/addapppay","nonceStr",` 里的分包名不再判 2402。"""
    for v in ("12304kiFHVi", "45689DJpjnC"):
        got = _slugs(v, SN_LIST_NONCE)
        assert NONCE not in got, (v, got)
        assert NONCE in _slugs(v, SN_LIST_NONCE, fix_on=False), v


def test_query_concat_timestamp_not_payment():
    """pkgref：`"…&timestamp=".concat(new Date().getTime(),"94wSot…")` 里的签名值不判 2401。"""
    got = _slugs("94wSotw", SN_QUERY_CONCAT)
    assert PRP not in got, got
    assert PRP in _slugs("94wSotw", SN_QUERY_CONCAT, fix_on=False)


def test_unrelated_value_in_payment_window_not_payment():
    """同窗口有支付键也不放行：本值绑在别的键上（orderId / code / appKey）一律不判支付。"""
    for v, sn, before in (("1755092100", 'wx.requestPayment({timeStamp:"1234567890",orderId:"1755092100"})', PRP),
                          ("123456", '{timestamp: t, code: "123456"}', PRP),
                          ("123456789012345", SN_APPKEY, NONCE)):
        got = _slugs(v, sn)
        assert not [s for s in got if s in PAY_ALL], (v, got)
        assert before in _slugs(v, sn, fix_on=False), v


# =========================================================
# ② 真阳性保留（驼峰规范写法 + 值位置口径）
# =========================================================
def test_canonical_timestamp_value_kept():
    """`timeStamp:"<epoch>"` 的值仍是 2401（既有真阳性契约，不要求别的证据）。"""
    for v, sn in (("1755092100", 'timeStamp:"1755092100"'),
                  ("1755092100", 'e.timeStamp = "1755092100"'),
                  ("1745408094", 'timeStamp: "1745408094"')):
        got = _slugs(v, sn)
        assert PRP in got, (sn, got)


def test_canonical_timestamp_json_key_kept():
    """`"timeStamp": "<epoch>"`（JSON 引号键）仍是 2401。"""
    got = _slugs("1727336873184", '"timeStamp": "1727336873184"')
    assert PRP in got, got


def test_timestamp_binding_beats_earlier_payment_keys():
    """真实支付对象里 timeStamp 排在 nonceStr/paySign **之后**：值必须归 2401。

    改动前这里按 CONTEXT_KEYWORDS 的 dict 顺序落到 2405（paysign 在前），即**错 slug**；
    `fix_on=False` 的对照把这一点固化下来。
    """
    for sn in ('wx.requestPayment({nonceStr:"n",paySign:"p",timeStamp:"1755092100"})',
               'e.data={nonceStr:n,package:g,signType:"MD5",paySign:s,timeStamp:"1755092100"}'):
        got = _slugs("1755092100", sn)
        assert PRP in got, (sn, got)
        assert PAYSIGN in _slugs("1755092100", sn, fix_on=False), sn


def test_generic_timestamp_with_payment_evidence_kept():
    """小写 `timestamp` 绑定 + 同窗口有支付证据（package / prepay_id / requestPayment）仍判 2401。"""
    for sn in ('wx.requestPayment({timestamp: "1755092100", package: "prepay_id=wx1"})',
               'wx.requestPayment({timestamp: "1755092100", package: p, prepay_id: q})'):
        got = _slugs("1755092100", sn)
        assert PRP in got, (sn, got)


def test_param_name_value_unchanged():
    """`TIMESTAMP` 作为**值**（参数名）走的是 is_payment_param，一律不动。"""
    for sn in ('o = "TIMESTAMP"', 'o="TIMESTAMP"'):
        got = _slugs("TIMESTAMP", sn)
        assert PRP in got, (sn, got)
    assert _slugs("TIMESTAMP", 'o = "TIMESTAMP"') == _slugs("TIMESTAMP", 'o = "TIMESTAMP"', fix_on=False)


def test_prepay_id_package_unchanged():
    """`prepay_id=` 值（2403）与改前逐位一致。

    fix45 起判据多了一道「等号后必须像一个预支付 ID」的值形闸门（见 constants_classifier 的
    `is_prepay_id_shaped` 与 unit-tests/test_fix45_payment_package.py），本用例随之调整：
      · 夹具换成**真形态**的合成值（`wx` + 日期段 + 随机段，wx 后 ≥12 位字母数字），
        本用例钉的契约不变 —— 真形态值仍是 2403，且与 fix24 关断时逐位一致；
      · 原来的短夹具 `prepay_id=wx0123abc`（wx 后 7 位）在 fix45 下**不再是** 2403，而是显式落
        payment_noise(2407)；这一条在本用例里留一个字面量断言，免得后人以为夹具是随手换的。
    """
    v = "prepay_id=wx20240101123456abcdef0123456789"
    got = _slugs(v, 'wx.requestPayment({package:"%s"})' % v)
    assert PACKAGE in got, got
    assert got == _slugs(v, 'wx.requestPayment({package:"%s"})' % v, fix_on=False)
    # fix45：短 wx 体（wx 后不足 12 位）不再是 2403，显式落 2407 —— 判据见 test_fix45_payment_package.py
    short = "prepay_id=wx0123abc"
    assert PACKAGE not in _slugs(short, 'wx.requestPayment({package:"%s"})' % short)
    assert 2407 in _slugs(short, 'wx.requestPayment({package:"%s"})' % short)


def test_nonce_bound_value_kept():
    """`nonceStr:` / `noncestr:` 绑定的值仍是 2402（值位置口径，不再靠裸子串）。"""
    for v, sn in (("1584298173534", 'nonceStr: "1584298173534"'),
                  ("4072798428", 'noncestr: "4072798428"')):
        got = _slugs(v, sn)
        assert NONCE in got, (v, got)


def test_nonce_snake_spelling_recovered():
    """`nonce_str:` 的值：改动前因为它不含子串 noncestr 而落到 pii_noise，现在按绑定的键判 2402。"""
    v = SYN_NONCE
    sn = 'nonce_str:"%s"' % v
    got = _slugs(v, sn)
    assert NONCE in got, got
    assert NONCE not in _slugs(v, sn, fix_on=False)


def test_default_fallback_value_kept():
    """`key: 表达式 || "字面量"` 默认值写法里的字面量仍按该键判（qk 真实片段，键仍是绑定的键）。"""
    got = _slugs(SYN_NONCE, 'nonceStr: t.nonceStr || "%s"' % SYN_NONCE)
    assert NONCE in got, got
    got = _slugs(SYN_PAYSIGN, 'paySign: o.paySign || "%s"' % SYN_PAYSIGN)
    assert PAYSIGN in got, got


def test_paysign_bound_value_kept():
    """`paySign:` 绑定的值仍是 2405。"""
    got = _slugs(SYN_PAYSIGN, 'paySign: "%s"' % SYN_PAYSIGN)
    assert PAYSIGN in got, got


# =========================================================
# ③ 同一函数的其他关键词出口不受影响（护栏）
# =========================================================
def test_other_context_keywords_unchanged():
    """cookie / appsecret / region / bucket 四条出口与改前逐位一致。"""
    cases = (("1234567890", 'a = {cookie: "1234567890", timestamp: t}'),
             ("10035607", 'regionId: "10035607"'),
             ("201~300", 'duration_region: r(n, [ "1~100", "101~200", "201~300" ])'),
             ("1d85-checkin-9ac42-1253808531", 'bucket: "1d85-checkin-9ac42-1253808531"'),
             ("cn-east", 'o = [ "cn-south", "cn-north", "cn-east" ].indexOf(i) >'))
    for v, sn in cases:
        assert _slugs(v, sn) == _slugs(v, sn, fix_on=False), (v, sn)


def test_region_bucket_guards_still_apply():
    """fix19 的云区域/云桶守卫仍在（本函数同一条末尾循环，改动不许回退它们）。"""
    assert IDT.CLOUD_REGION in _slugs("cn-east", 'o = [ "cn-south", "cn-east" ].indexOf(i) >')
    assert IDT.CLOUD_BUCKET_NAME in _slugs("1d85-checkin-9ac42-1253808531",
                                           'bucket: "1d85-checkin-9ac42-1253808531"')
    assert IDT.CLOUD_REGION not in _slugs("201~300", 'duration_region: r(n, [ "201~300" ])')


def test_no_payment_slug_without_binding():
    """不变量：修复后，任何「窗口里有支付词」的值都不再**新增**支付标签。"""
    cases = (("1755092100", 'wx.requestPayment({timeStamp:"1234567890",orderId:"1755092100"})'),
             ("123456", '{timestamp: t, code: "123456"}'),
             ("123456789012345", SN_APPKEY),
             ("94wSotw", SN_QUERY_CONCAT),
             ("12304kiFHVi", SN_LIST_NONCE))
    for v, sn in cases:
        got = _slugs(v, sn)
        assert not [s for s in got if s in PAY_ALL], (v, got)


# =========================================================
# ④ 复合键名（族内放行）与边界守卫
# =========================================================
def test_compound_signature_key_kept():
    """复合键名里的**支付族词**仍出口：`alipaySignAsac:"…"` → 2405（键名含 paysign）。

    这是真阳性，不许当噪音删掉：支付宝那套支付流里的签名键名就是这种「前缀 + paySign」写法。
    """
    got = _slugs(SYN_ALIPAY_SIGN, SN_ALIPAY_HDR)
    assert PAYSIGN in got, got


def test_hyphenated_header_nonce_key_kept():
    """`"X-PA-NONCESTR": "…"`（支付宝支付头名，值模板来自 qk 真实片段）→ 2402。"""
    v = "1xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    for sn in ('"X-PA-NONCESTR": "%s".replace(/[xy]/g, fn)' % v,
               '"X-PA-NONCESTR":"%s".replace(/[xy]/g,fn)' % v):
        got = _slugs(v, sn)
        assert NONCE in got, (sn, got)


def test_compound_key_family_excludes_timestamp():
    """族内放行**不包含 timestamp 族**：ReportTimestamp / cTimeStamp / BUILD_TIMESTAMP 仍不判支付。"""
    for v, sn in (("20220617012706", SN_REPORT),
                  ("1701304105774", SN_ICP_PREFIX),
                  ("20251128180037", 'BUILD_TIMESTAMP: "20251128180037"')):
        got = _slugs(v, sn)
        assert not [s for s in got if s in PAY_ALL], (v, sn, got)


def test_generic_occurrence_skipped_then_canonical_found():
    """本值一处绑在小写通用 timestamp（无证据）、另一处绑在驼峰 timeStamp → 判 2401。

    通用写法那一处只跳过**这一次出现**，不能直接返回「不是支付」，否则后面的规范写法永远看不到。
    """
    for sn in ('a={timestamp:"1755092100"},b={timeStamp:"1755092100"}',
               'x=JSON.parse(\'{"timestamp":"1755092100"}\'),y={timeStamp:"1755092100"}'):
        got = _slugs("1755092100", sn)
        assert PRP in got, (sn, got)


def test_value_prefix_or_suffix_of_longer_literal_not_bound():
    """本值只是**更长字面量**的前缀/后缀时不算绑定（否则会把别的值的键算到本值头上）。"""
    for v, sn in (("1755092100", 'timeStamp:"17550921001"'),
                  ("1755092100", 'timeStamp:"91755092100"')):
        got = _slugs(v, sn)
        assert not [s for s in got if s in PAY_ALL], (v, sn, got)


def test_signtype_bound_value_kept():
    """`signType:` 绑定的值 → 2404（值位置口径补齐 signType 一族）。"""
    got = _slugs("1234", '{signType: "1234", paySign: "abc", timeStamp: t}')
    assert SIGNTYPE in got, got


# =========================================================
# ⑤ 已知代价（显式记录，不隐藏；见文件头第 4 条）
# =========================================================


def test_known_cost_url_query_timestamp_dropped():
    """`…&timestamp=".concat("1666231449")`：URL 查询参数时间值不再有支付标签 —— 已知。

    改动前它靠窗口里的 `&nonceStr=` 落到 2402（既不是它的键、也不是 2401）。
    """
    got = _slugs("1666231449", SN_PHP_SIGN)
    assert not [s for s in got if s in PAY_ALL], got
    assert NONCE in _slugs("1666231449", SN_PHP_SIGN, fix_on=False)


def _run_standalone():
    """本机 .venv 没有 pytest，所以自带 runner：断言全是纯 assert，两种跑法一致。"""
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
    print("fix24 支付 timestamp 值位置绑定：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
