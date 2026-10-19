#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix32：统计分析 SDK Key 出口（1402）的「命名报送 callee 实参」守卫（SAFE GB）。

病根
----
`is_analytics_key` 的语境闸门是**裸子串**：`ANALYTICS_KEY_CONTEXT_WORDS` 里的
`sensors` / `sensorsdata` / `mixpanel` / `sentry` … 在值周围 512 字符窗口里出现即成立。
而报送类 callee 的名字本身就把这个闸门打开了 ——
`getApp().sensors.track("h5_click", …)` 里的 `sensors.track` 让**事件名** `h5_click`
以 `saas_analytics_key(1402)` 出口。也就是说：**谁被喂给报送函数，谁就变成「统计分析 Key」**，
哪怕这个值坐在 callee 的实参位上、左侧没有任何键名。

只读普查（normal_quarkpan，1402 桶全部 7,383 条链接 / 2,537 个值；
   脚本 test-result/fix32/probe_analytics_callee.py，TSV 同目录）
  · 值的**每次独立出现**都「未绑定 + 是命名报送 callee 的实参」= 496 条链接 / 184 个值
    （父任务探针口径 501 / 181，差 5 条是白名单边界的 `etc.` 条目，见「刻意不做」）；
    其中 174 个值的全部链接都在这一族里（整值离开 1402）；
  · 这 496 条里**没有一条**走公开 AppKey 路由（`is_app_key -> 1402`）—— 公开 AppKey 在
    分类器里比 analytics 出口**更早**判定，本判据碰不到它们（普查 appkey_route=0）；
  · 值形是事件名（`h5_click` / `AyhH5Click` / `NXPT_O00000175` /`chart2View` …），
    头部来源：`SENSORSCLICK.send` / `sensors.track` / `$track.clickEvent` / `$saEvent` …
  · 被喂给**工具类** callee 的值（`wx.getStorageSync` / `.concat` / `console.log`）
    不在这一族里，本判据一律不碰。

判据（本轮只动 analytics 出口这一处）
----
  ① 值含**至少一个字母**；② 窗口里**至少有一次**独立出现；③ 每一次独立出现都满足
     「左侧紧邻没有键绑定」（口径 = 既有 `_bound_value_keys` 那台 `_PAYMENT_VALUE_BINDING_RE`）
     且「最内层包住它的调用是命名报送 callee」（callee 链归一化后按**尾部段**查显式白名单，
     见 `ANALYTICS_REPORTING_CALLEE_TAIL2 / _TAIL1`）→ 判据为真。
  归一化 = 去 `$` + 小写 + 去前导点：语料里的接收者被压缩器加过前缀
  （`.globaldata.sensors.track` / `c.sensors.track` / `e.sensorsClick.send`），
  所以按尾部段匹配；这不是「宽松匹配」，是**同一张显式白名单**在压缩器下的唯一可行写法。

归置（本轮红线）
--------------
  · 命中即**显式**写既有的 risk0 噪音标签 `id_noise(2505)`，不清高、不落空；
  · **不许**只把 1402 摘掉就放任往下走：实测把 `is_analytics_key` 整个关掉，
    1402 桶有 1,179 条链接会平移进 `cloud_cred_password(1203, risk5)`（父任务点名的红线，
    数字同族）。本判据的归置写在 `append_result` 里，落不到下面的凭证判据上；
  · 保留组：公开 AppKey 路由（`appKey:`/`appkey:` 命中的 2,618 条链接）、
    绑在键上的值（1309 值 / 3005 链接那一族）、`sensorsdata` 存储键这类**非报送 callee 实参**
    的 SDK 标识、被工具类 callee 喂的值 —— 一条都不许动。

刻意不做（本轮授权之外）
-----------------------
  · 不碰 `is_app_key` / 公开 AppKey 路由（父任务点名）；不碰 AppKey 侧的 1402 归置；
  · 不做纯十六进制抑制、不做事件名模板（父任务点名禁止）—— 白名单是**callee 名**，
    不是事件名模式；
  · 不做「值里含 sensors/mixpanel 等厂商词就收掉」这类值侧收严（那是别的判据的射程）；
  · `removeObserverByClassName` 只认父任务白名单里那个 `Exposure.` 门面写法；
    `u.Sensors.removeObserverByClassName([...])`（数组实参、14 条链接）**不在**射程内，
    照旧 1402 —— 白名单是显式的，不靠「名字像」扩。

用法: .venv/bin/python -X utf8 unit-tests/test_fix32_analytics_callee_guard.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

ANALYTICS = IDT.SAAS_ANALYTICS_KEY
NOISE = IDT.ID_NOISE

_GUARD_ATTRS = ("is_analytics_callee_argument", "is_analytics_reporting_callee",
                "_analytics_bound_key_at")


def _guard_on(v, stmt):
    """新判据（RED 阶段名字还不存在时按「判据未落地」处理，断言照跑）。"""
    fn = getattr(C, "is_analytics_callee_argument", None)
    return bool(fn(v, stmt)) if fn else False


def _classify(v, stmt, guard_off=False, any_callee=False, ignore_binding=False):
    """跑一遍分类；三个开关各自只放宽本判据的一条细则，其余逐位不变。

    guard_off      ：判据还原成改动前（恒不生效）—— 前置断言用（改动前确实在 1402）。
    any_callee     ：对照组 ①：把「callee 必须在白名单内」放宽成「任何 callee 都算」
                     —— 证明白名单是承重的（否则工具类 callee 的值会被收掉）。
    ignore_binding ：对照组 ②：把「左侧没有键绑定」这条闸门拆掉 —— 证明绑定闸门是承重的
                     （否则绑在值位上的 analytics/appkey 键会被顺手收掉）。
    三个开关都是模块级名字，函数体在调用时才查；名字不存在（RED 阶段）时按「本来就关着」
    处理（与 test_fix30_hex_token_id_binding.py 同一约定）。
    """
    saved = [(n, getattr(C, n)) for n in _GUARD_ATTRS if hasattr(C, n)]
    if hasattr(C, "is_analytics_reporting_callee"):
        if any_callee:
            C.is_analytics_reporting_callee = lambda name: True
    if hasattr(C, "_analytics_bound_key_at") and ignore_binding:
        C._analytics_bound_key_at = lambda stmt, pos: None
    if guard_off and hasattr(C, "is_analytics_callee_argument"):
        C.is_analytics_callee_argument = lambda s, st: False
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


def _risk_of(slug):
    return IDT.SLUG_TO_DB[slug][1]


# =========================================================
# ① 报送 callee 的实参：不再出口 1402，且**显式**写 risk0 噪音
# =========================================================
# 前 6 条取自 normal_quarkpan 真实 1402 链接（普查见文件头；窗口就是分类器看到的那份
# `extract_context(snippet, value, 512)`，仅把换行按 TSV 口径压成空格）；
# 后 11 条是同一形态的**白盒**用例（父任务给的显式白名单里、语料里没直接命中候选的那几个
# callee 名 —— 与 fix30 的 `authToken` / `Bearer` 白盒边界同一约定）：全部保持
# 「接收者带压缩前缀 + 窗口里有 analytics 语境词」的真实形状。
CALLEE_ARG_CASES = [
    # --- 真实 ---
    ("AyhH5Click",
     'l.SENSORSCLICK.send("AyhH5Click", {                     element_name: "首页",'
     '                     element_text: "首页",                     event_type: "click",'
     '                     current_page: "首页"                 });'),
    ("h5_click",
     'getApp().sensors.track("h5_click", e(e({}, t), {}, {'
     '                 $element_content: r             }));'),
    ("sc_step1_load",
     't.sensors.track("sc_step1_load",{}),this.setData({stayTime:Date.parse(new Date)})'),
    ("NXPT_O00000175",
     'getApp().sensors.track("NXPT_O00000175", o.data.trackData), a.next = 13;'),
    ("NXPT_O00000176",
     'wx.navigateBack(), getApp().sensors.track("NXPT_O00000176", this.data.trackData);'),
    # 窗口里同时有 `i.getStorageSync("userInfo")`（工具类 callee）—— 那是**别**的值的实参，
    # 不影响本值：本值自己坐在 `ue.sensors.track(` 的实参位上。
    ("member_interest_privileges_click",
     'ue.sensors.track("member_interest_privileges_click",{prod_name:e.rightsName,'
     'button_name:a.vipHavePlus?"立即领取":"开通即享"}),s?i.navigateTo({url:"/pages/'
     'newPackages/lifeRightDetail/index?isVip=".concat(a.vipHavePlus?1:0,"&goodsId=")'
     '.concat(e.id)}):(0,m.x4)({options:{vip:"vip",vipqr:$i.current.vipqr||"",'
     'rwbUserIdH5:Xi.current||"",ewmId:ue.globalData.ewmId||""}}).then((function(){'
     'var e=uo();be((0,n.Z)((0,n.Z)({},i.getStorageSync("userInfo")||{}),{},{phone:e})),'
     'Ro()})).catch((function(){}))'),
    # --- 白盒：父任务白名单里的 callee 名各来一条（形状取自真实用法）---
    ("track_click_event_01",
     't.$track.clickEvent("track_click_event_01","分享页点击",{ty_status:t.globalData.vipSensors.buyStatus})'),
    ("page_show_event_01",
     'this.$track.pageShowEvent("page_show_event_01","分享页曝光",{ty_status:t.globalData.vipSensors.buyStatus})'),
    ("satrack_event_01",
     'e.gd?r.saTrack("satrack_event_01",{from:"scan"}):(0,o.sensorsData).track("x")'),
    ("sensorstrack_event_01",
     'F()&&e.sensorsTrack("sensorstrack_event_01",{page:"home",d:t.vipSensors.status})'),
    ("sensorstrackclick_event_01",
     'd.sensorsTrackClick("sensorstrackclick_event_01",{btn:"submit"}),n.globalData.sensors.track("x")'),
    ("saevent_event_01",
     'r.getSensors().$saEvent("saevent_event_01",{jf_feed_type:a.dataType||""}),a.next=3'),
    ("sentry_event_01",
     'h.sentryCaptureEvent("sentry_event_01",{level:"warn"}),e.sensors.track("page_view")'),
    ("emotional_event_01",
     'i.emotionalRuleReport("emotional_event_01",{rule:id}),t.sensors.track("page_view")'),
    ("mixpanel_event_01",
     'p._mixpanel.send("mixpanel_event_01",{distinct_id:u}),t.sensors.track("page_view")'),
    ("xjsensors_event_01",
     'l.xjSensorsTrack("xjsensors_event_01",{channel:"wx"}),l.sensors.track("page_view")'),
    ("ehi_event_01",
     'g.ehiSensors.track("ehi_event_01",{type:"view"}),g.sensors.track("page_view")'),
    ("exposure_cls_01",
     'u.Exposure.removeObserverByClassName("exposure_cls_01"),u.Sensors.track("page_view")'),
]


def test_callee_args_dropped():
    """本轮射程：上面每个 (值, 语境) 都不再出口 1402。"""
    for v, stmt in CALLEE_ARG_CASES:
        got = _classify(v, stmt)
        assert ANALYTICS not in got, "%r in %r -> %r" % (v, stmt, got)


def test_callee_args_go_to_explicit_risk0_noise():
    """归置：不是「无标签」，而是**显式**写既有 risk0 噪音标签（父任务点名的归置）。"""
    for v, stmt in CALLEE_ARG_CASES:
        got = _classify(v, stmt)
        assert got == [NOISE], "%r in %r -> %r" % (v, stmt, got)
        assert _risk_of(NOISE) == IDT.RISK_IGNORE, "id_noise 不是 risk0"


def test_guard_is_the_change():
    """对照：只关掉新守卫，它们全部回到 1402（证明这些失败确由本条判据负责）。"""
    for v, stmt in CALLEE_ARG_CASES:
        assert _classify(v, stmt, guard_off=True) == [ANALYTICS], (v, stmt)


def test_callee_arg_cases_reach_the_analytics_exit():
    """机制断言：这批值确实走 `is_analytics_key` 这条路（否则本判据根本没机会生效）。"""
    for v, stmt in CALLEE_ARG_CASES:
        assert C.is_analytics_key(v, stmt), (v, stmt)
        assert _guard_on(v, stmt), "判据没覆盖: %r in %r" % (v, stmt)


# =========================================================
# ② 保留组：公开 AppKey 路由 / 键绑定 / 非报送 callee 的 SDK 标识 / 工具类 callee
# =========================================================
# 公开 AppKey 路由（值绑在 appkey 上，走 `is_app_key -> 1402`，比 analytics 出口更早）。
# 第三条是「公开 AppKey 的返回串」形态（三元表达式里的 AppKey 分支，真实链接）。
APPKEY_PROTECTED = [
    ("5bGFopGjwCxEVicoGe8EapTYaqulwVPh", 'appkey: "5bGFopGjwCxEVicoGe8EapTYaqulwVPh"'),
    ("61849d2be014255fcb6bf704", 'appKey: "61849d2be014255fcb6bf704"'),
    ("68a44bb1ec2b5b6f8821c555",
     'appKey: "prod" === c.default._ENV ? "68a44bb1ec2b5b6f8821c555"'
     ' : "68a44c04e563686f4282fa58"'),
]
# 工具类 / 存储类 callee 的实参：`wx.getStorageSync` / `concat` / `console.log`
# （第一条真实：`console.log("----sensorSubscribeExposureEvent", e);`；
#  第二条真实：`r._.getStorageSync("sensorsdata2015_wechat")`）
UTILITY_CALLEE_PROTECTED = [
    ("sensorsdata2015_wechat",
     'this.storageInfo = r._.getStorageSync("sensorsdata2015_wechat") || ""'),
    ("----sensorSubscribeExposureEvent",
     'console.log("----sensorSubscribeExposureEvent", e);'),
    ("sensorsdata_2015_wx",
     'var a=wx.getStorageSync("sensorsdata_2015_wx")||{};t.sensors.track("x_click_01")'),
    ("track_event_console_1",
     'a=[].concat(t(n),"track_event_console_1"),s.sensors.track("page_view_01")'),
    ("track_event_logonly_1",
     'console.log("track_event_logonly_1",u),s.sensors.track("page_view_01")'),
]
# 值位绑定：同一个窗口里绑在键上的值（`event_name:` / `$element_name:`）不许被顺手收掉
BOUND_PROTECTED = [
    ("event_name_bound_01",
     't.sensors.track({event_name:"event_name_bound_01"},t.globalData.sensors.params)'),
    ("element_name_bound_01",
     't.sensors.track("page_view_01",{$element_name:"element_name_bound_01"})'),
]
# 其余保留组：值不是报送 callee 的实参 / 纯数字页 ID
OTHER_PROTECTED = [
    ("other_callee_event_01",
     'if(i.getSensors().$saEvent("mp_zo_scene_begin"),u.scene){t.next=17;}'
     'return v("other_callee_event_01")'),
    ("1732848546",
     'this.triggerEvent("cancel"),"vip"===this.properties.source&&t.$track.clickEvent('
     '"1732848546","直供会员页协议弹窗点击",{ty_information_contain:"取消",'
     'ty_status:t.globalData.vipSensors.buyStatus})'),
    ("1732848545",
     '"vip"===this.properties.source&&t.$track.pageShowEvent("1732848545",'
     '"直供会员页协议弹窗曝光",{ty_status:t.globalData.vipSensors.buyStatus})'),
]
PROTECTED_CASES = (APPKEY_PROTECTED + UTILITY_CALLEE_PROTECTED
                   + BOUND_PROTECTED + OTHER_PROTECTED)


def test_protected_values_kept():
    """保留组：照旧判 1402，且新判据对它们恒为假。"""
    for v, stmt in PROTECTED_CASES:
        got = _classify(v, stmt)
        assert got == [ANALYTICS], "%r in %r -> %r" % (v, stmt, got)
        assert not _guard_on(v, stmt), (v, stmt)


def test_public_appkey_route_untouched():
    """公开 AppKey 路由本身：命中即 `saas_analytics_key`，且**不经过**本守卫。

    机制断言：`is_app_key` 返回 1402 的分流在 analytics 出口之前（分类器里先判 appKey）。
    """
    for v, stmt in APPKEY_PROTECTED:
        assert C.is_app_key(v, stmt) == (True, ANALYTICS), (v, stmt)
        assert not _guard_on(v, stmt), (v, stmt)
        assert _classify(v, stmt) == [ANALYTICS], (v, stmt)


# =========================================================
# ③ 对照组：白名单 / 绑定闸门都是承重的
# =========================================================
def test_callee_allowlist_is_required():
    """对照组 ①：把白名单放宽成「任何 callee 都算」，工具类 callee 的值就被误收。

    这正是判据必须写成「callee 名在白名单内」的理由 —— 现行实现没踩（上面②逐条钉住）。
    """
    for v, stmt in UTILITY_CALLEE_PROTECTED:
        assert _classify(v, stmt) == [ANALYTICS], (v, stmt)         # 现行：留住
        got = _classify(v, stmt, any_callee=True)
        assert ANALYTICS not in got, (v, stmt, got)                 # 对照组：丢掉


def test_binding_gate_is_required():
    """对照组 ②：拆掉「左侧没有键绑定」这条闸门，绑在值位上的值就被顺手收掉。"""
    for v, stmt in BOUND_PROTECTED:
        assert _classify(v, stmt) == [ANALYTICS], (v, stmt)         # 现行：留住
        got = _classify(v, stmt, ignore_binding=True)
        assert ANALYTICS not in got, (v, stmt, got)                 # 对照组：丢掉


# =========================================================
# ④ 判据本身的边界（白盒）
# =========================================================
def test_guard_helper_boundaries():
    """只看紧邻的绑定、只看**最内层**调用、只认显式白名单、且要求**全部**出现都成立。"""
    if not hasattr(C, "is_analytics_callee_argument"):
        raise AssertionError("判据 is_analytics_callee_argument 未落地")
    G = C.is_analytics_callee_argument
    # 成立：首实参 / 对象字面量之后的实参 / 数组实参 / 对象字面量里的值（未绑定）
    assert G("event_a_01", 'sensors.track("event_a_01",{})') is True
    assert G("event_b_01", 'sensors.track({a:1},"event_b_01")') is True
    assert G("event_c_01", 'sensors.track(["event_c_01"])') is True
    assert G("event_d_01", 'sensors.track({params:["event_d_01"]})') is True
    # 成立：`$` 与压缩前缀按尾部段归一
    assert G("event_e_01", 't.$track.clickEvent("event_e_01")') is True
    assert G("event_f_01", 'a.b.c.sensorsClick.send("event_f_01")') is True
    # 不成立：白名单外的 callee（工具类是父任务点名的排除项）
    assert G("event_g_01", 'foo("event_g_01")') is False
    assert G("event_g_01", 'a.send("event_g_01")') is False       # 裸 `send` 不算
    assert G("event_g_01", 'console.log("event_g_01")') is False
    assert G("event_g_01", 'a.concat("event_g_01")') is False
    assert G("event_g_01", 'wx.getStorageSync("event_g_01")') is False
    assert G("event_g_01", 'u.Sensors.removeObserverByClassName("event_g_01")') is False
    assert G("event_g_01", 'sa.track("event_g_01")') is False     # 白名单里只有 sensors.track
    # 不成立：值含字母这条硬化（纯数字的页 ID 保留）
    assert G("1234567890", 'sensors.track("1234567890")') is False
    assert G("1732848545", 't.$track.pageShowEvent("1732848545")') is False
    # 不成立：左侧紧邻有键绑定
    assert G("event_h_01", 'sensors.track(e={event_name:"event_h_01"})') is False
    assert G("event_h_01", 'sensors.track({event_name:"event_h_01"})') is False
    # 不成立：**任一次**出现不成立即整值不成立（绑定 / 非 callee 位置各一例）
    assert G("event_i_01", 'sensors.track("event_i_01"),x={k:"event_i_01"}') is False
    assert G("event_i_01", 'sensors.track("event_i_01"),foo("event_i_01")') is False
    # 不成立：窗口里没有本值 / 不在调用实参里
    assert G("event_j_01", 'sensors.track("other")') is False
    assert G("event_j_01", 'x="event_j_01"') is False
    assert G("event_j_01", 'x=["event_j_01"') is False           # 未闭合的括号栈
    # 不成立：本值只是更长字面量的前缀/后缀时不算独立出现（与 `_bound_value_keys` 同一细则）
    assert G("event", 'sensors.track("event_k_01")') is False
    assert G("event_k_01", 'sensors.track("xevent_k_01")') is False


def test_reporting_callee_allowlist_shape():
    """白名单本身：显式、尾部段匹配、且**不含**工具类 callee 的尾部段。"""
    if not hasattr(C, "is_analytics_reporting_callee"):
        raise AssertionError("白名单判据 is_analytics_reporting_callee 未落地")
    M = C.is_analytics_reporting_callee
    for good in ("sensors.track", ".globaldata.sensors.track", "c.sensors.track",
                 "e.sensorsClick.send", "$saEvent", "s.SENSORSCLICK.send",
                 "t.$track.clickEvent", "t.$track.pageShowEvent", "r.saTrack",
                 "i.sensorsTrack", "l.sensorsTrackClick", "h.sentryCaptureEvent",
                 "i.emotionalRuleReport", "p._mixpanel.send", "l.xjSensorsTrack",
                 "g.ehiSensors.track", "u.Exposure.removeObserverByClassName"):
        assert M(good) is True, good
    for bad in ("wx.getStorageSync", "getStorageSync", "a.concat", "console.log",
                "a.send", "t.track", "wx.setStorageSync", "t.setData", "sa.track.foo"):
        assert M(bad) is False, bad
    tail1, tail2 = C.ANALYTICS_REPORTING_CALLEE_TAIL1, C.ANALYTICS_REPORTING_CALLEE_TAIL2
    for util in ("getstoragesync", "setstoragesync", "concat", "log", "send"):
        assert util not in tail1 and util not in tail2, util


def test_guard_does_not_touch_other_exits():
    """作用面：非 1402 的值、以及非 analytics 出口的值，开关对结果无影响。"""
    for v, stmt in (("event_z_01", 'console.log("event_z_01")'),
                    ("event_z_01", 'x="event_z_01"'),
                    ("dacfba484d601430cee54e19f3f08c1d", '{"target_id":"dacfba484d601430cee54e19f3f08c1d"}'),
                    ("wx1234567890abcdef", 'appId:"wx1234567890abcdef"')):
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
    print("fix32 analytics 报送 callee 实参守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
