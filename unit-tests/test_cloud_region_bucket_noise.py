"""cloud_storage 类组两处噪音：cloud_region 的「语境词命中即出口」与 cloud_bucket_name 的文件名（fix19）。

背景（根因，三库 = unlist_icp_filing_v2 / unlist_package_reference_v2 / unlist_normal_sibling_v2）
--------------------------------------------------------------------------------------------
两处噪音都**不在各自的判据里**，而在**数字开头链** `process_generic_digit_prefixed_constant`
末尾那条通用语境词循环上（`for keyword, slug_id in CONTEXT_KEYWORDS.items()`）：

    CONTEXT_KEYWORDS 里 "bucket"→CLOUD_BUCKET_NAME、"region"→CLOUD_REGION，
    循环只对 4 个凭证类型设了值形守卫，云桶/云区域是「子串命中即出口」。

于是任何**以数字开头**、而语句里恰好含 "bucket"/"region" **子串**的值都直接出口：

  ① cloud_region：101 值里 55 值（54%）是噪音。真区域名一律以 cn-/ap-/us-/eu-/na-
     开头，因此**全部**走字母链的 is_cloud_region_value；数字开头的值一个都不可能是
     区域名。噪音的真实出处（三库 source_snippet 原文）：
       duration_region: r(n, ["1~100","101~200", …])      时长档位/价格区间（18 值）
       regionId: "10035607" / regionUUID: "420100000000"  业务区域 ID（22 值）
       k: e.sr("sRegion", "500b1953-8,500b1953-7")        CSV（3 值）
       nv_REGIONAL_INDICATOR_START = nv_parseInt('0x1f1e6')  "REGIONAL" 里的 region
       this.getRegion() / getregionList( … )               代码标识符里的 region
       wx-pick-regions … "0;overflow-y:auto;padding-bottom:"  CSS 片段
     即触发词是**裸子串**：REGIONAL / getRegion / sRegion / duration_region 全都算。
  ② cloud_bucket_name：normsib 110 值里 25 值（23%）是 `concat(v.ossBucket,"<hex>.png")`
     里的**文件名**，另 1 值 `8:00-12:00` 来自 `timeBucket: ["8:00-12:00"]`。is_bucket_name
     对它们返回 **False**（值形 `^[a-z0-9][a-z0-9-]*[a-z0-9]$` 不含 `.`；`:` 也不在字符集里），
     所以这些值根本没走桶判据 —— icp / pkgref 两库桶名 0 噪音，正是因为它们没有
     「数字开头 + 语句含 bucket 子串」的值。

修法（与 4 个凭证类型同一位置、同一形状）：
  · CLOUD_REGION      → 值必须过 is_cloud_region_value（既有白名单判据，不新造规则）
  · CLOUD_BUCKET_NAME → 值必须过 is_bucket_name（主链同一条判据）
  · is_bucket_name    → 另加一条「无分隔符且数字夹在字母中间」的否决（见 ③ 的 docstring）
数字开头的**真桶名**（`1234567890-images` / `1254728086-buck` / 32 位 hex 桶名）
is_bucket_name 本来就收，守卫不误伤它们。

本文件固化的边界：
  1) ①的 55 个噪音形态不再判 cloud_region，②的 26 个不再判 cloud_bucket_name；
  2) 真值一个不许掉：21 个去重真区域值仍判 cloud_region，真桶名（含数字开头）仍判桶名；
  3) 守卫**只拒不放**：被拒值的去向 = 本链既有兜底（实测 pii_noise），不新增任何类型产出；
  4) 判据选型固化为**白名单**而非排除法：`0x1f1e6` / `20240425-address_add` 既不含 `~`
     也不是纯数字/CSV，排除法接不住；
  5) 已知副作用记录在 test_jscode2session_not_bucket 的 docstring 里（不隐藏）。

标注「实测」的期望值由 test-result/fix19_verify_corpus.py 对着三库真实 (值,上下文) 跑出来。

用法: .venv/bin/python unit-tests/test_cloud_region_bucket_noise.py
"""

import os
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

REGION = IDT.CLOUD_REGION
BUCKET = IDT.CLOUD_BUCKET_NAME

# ---- 「改动前」模块：从**当前源码**擦掉 fix19 的改动后内存 exec ----
# 不用 git show HEAD 取旧版：fix19 一旦提交，HEAD 就是新代码，「改动前」的断言会自己失效。
# 擦除标记与 test-result/validate_uid_pwd_region.py 的 rv_region 保持一致。
_GUARD_BLOCKS = (
    ("            # 云区域（fix19 ①）",
     "                if not is_cloud_region_value(s):\n                    continue\n"),
    ("            # 云桶名（fix19 ②）",
     "                if not is_bucket_name(s, stmt):\n                    continue\n"),
    ("    # fix19 ③：无分隔符且数字**夹在字母中间**的形态是代码标识符被拍平的结果，不是桶名。",
     "    if NO_SEPARATOR_IDENTIFIER_RE.match(s):\n        return False\n"),
)


def _strip_fix19(src):
    for start, end in _GUARD_BLOCKS:
        assert src.count(start) == 1, "擦除标记不唯一: %r" % start
        i = src.index(start)
        j = src.index(end, i) + len(end)
        src = src[:i] + src[j:]
    return src


def _build_before():
    mod = types.ModuleType("cc_before_fix19")
    mod.__file__ = C.__file__ + " (before-fix19)"
    exec(compile(_strip_fix19(open(C.__file__, encoding="utf-8").read()),
                 mod.__file__, "exec"), mod.__dict__)
    return mod


BEFORE = _build_before()


def _slugs(value, stmt, guards_on=True):
    """跑一遍分类；guards_on=False 时用擦掉 fix19 改动的模块，取「改动前」判定。"""
    mod = C if guards_on else BEFORE
    return [r[0] for r in mod.perform_constant_classifying([stmt], [(value, 0, "test.js")])]


# =========================================================
# 三库真实上下文（source_snippet 原文摘录）
# =========================================================
SN_DURATION = 'duration_region: r(n, [ "1~100", "101~200", "201~300", "301~400", "401~500", "501~" ])'
SN_DURATION2 = 'duration_region: n(r, [ "1~200", "201~500", "501~1000", "1001~2000", "2001~" ])'
SN_DURATION3 = 'duration_region: n(r, [ "1~500", "501~1000", "1001~2000", "2001~5000", "5001~10000", "10001~" ])'
SN_REGION_ID = 'regionId: "10035607"'
SN_REGION_UUID = 'regionUUID: "420100000000"'
SN_CSV = 'k: e.sr("sRegion", "500b1953-8,500b1953-7")'
SN_CSV2 = 'regionIdStr: encodeURIComponent("1,72,2839,0")'
SN_REGIONAL = "nv_REGIONAL_INDICATOR_START = nv_parseInt('0x1f1e6')"
SN_URLQUERY = '"/index.php?act=member_address&op=getAreaInfo&region=area_new&default_none=1", {});'
SN_PRICE = 'this.$sendEvent("PO", "56001.01", "装修报价页面"), this.fillHouseTypeList(), this.getRegion();'
SN_CSS = ('wx-pick-regions .",[1],"picker_input.",[1],"data-v-3f13a5b3{color:#858585}\\n.",[1],'
          '"form_item .",[1],"form_inp')
SN_CONSOLE = ('this.$refs.schoolDropDown.selectShow = !1, console.log("2handleSelectFloor", '
              'this.$refs.floorDropDown.selectedId), this.getregionList(this, this.startTime);')
SN_LOCATION = 'console.log(d, "2中心点坐标currentRegion"), this.setData({'
SN_COS = 'o = [ "cn-south", "cn-south-2" ].indexOf(a) > -1 ? "{Region}.myqcloud.com" : "cos." + t'
SN_PNG = 'badgeIconUrl:"".concat(v.ucOssBucket,"9f015ec44db54c19a6bb9e47e9527ad7.png")'
SN_PNG2 = 'staffUrl:"".concat(v.ossBucket,"11ba13961a2142619b556e58249cf4dd.png")'
SN_PNG3 = 'shareGroupBuyUrl:"".concat(v.ossBucket,"005c1f64a45c44ddb05959d6f2350d57.png")'
SN_TIME = 'timeBucket: [ "8:00-12:00" ]'
SN_JSC = ('"jscode2session",l+"/v1/wx/account/jscode2session"),"bind_phone_from",'
          'm+"/applet/user/bind_phone_from/mp"),"ossBucket","qsc-images")')

TRUE_REGIONS = ["ap-beijing", "ap-beijing-2", "ap-chengdu", "ap-guangzhou", "ap-nanjing",
                "ap-shanghai", "ap-shanghai-1", "ap-singapore", "cn-beijing", "cn-east",
                "cn-east-2", "cn-hangzhou", "cn-north", "cn-north-1", "cn-northwest-1",
                "cn-shanghai", "cn-south", "cn-south-2", "cn-southwest", "eu-moscow",
                "na-toronto"]


# =========================================================
# ① cloud_region
# =========================================================
def test_region_duration_tier_not_region():
    """时长档位/价格区间（含 ~，来自 duration_region）不再判云区域。"""
    for v, sn in (("101~200", SN_DURATION), ("201~300", SN_DURATION),
                  ("201~500", SN_DURATION2), ("5001~10000", SN_DURATION3),
                  ("501~1000", SN_DURATION3)):
        got = _slugs(v, sn)
        assert REGION not in got, (v, got)
        # 改动前：这些值确实出口成 cloud_region（守卫即成因）
        assert REGION in _slugs(v, sn, guards_on=False), v


def test_region_numeric_id_not_region():
    """业务区域 ID / 城市码（纯数字）不再判云区域。"""
    for v, sn in (("10035607", SN_REGION_ID), ("10009382", SN_REGION_ID),
                  ("420100000000", SN_REGION_UUID), ("3401000000", SN_REGION_UUID),
                  ("142933168465514496", SN_REGION_UUID)):
        got = _slugs(v, sn)
        assert REGION not in got, (v, got)
        assert REGION in _slugs(v, sn, guards_on=False), v


def test_region_csv_not_region():
    """CSV 形态（sRegion 选择列表）不再判云区域。"""
    for v, sn in (("1,72,2839,0", SN_CSV2), ("500b1953-8,500b1953-7", SN_CSV)):
        got = _slugs(v, sn)
        assert REGION not in got, (v, got)
        assert REGION in _slugs(v, sn, guards_on=False), v


def test_region_css_fragment_not_region():
    """CSS 片段（首字符数字，语句里含 wx-pick-regions）不再判云区域。"""
    v = "0;overflow-y:auto;padding-bottom:"
    got = _slugs(v, SN_CSS)
    assert REGION not in got, got
    assert REGION in _slugs(v, SN_CSS, guards_on=False)


def test_region_identifier_name_not_region():
    """代码标识符 / 控制台字符串 / REGIONAL 常量名里的 region 不再触发。"""
    for v, sn in (("2handleSelectFloor", SN_CONSOLE),
                  ("2中心点坐标currentRegion", SN_LOCATION),
                  ("0x1f1e6", SN_REGIONAL),
                  ("56001.01", SN_PRICE)):
        got = _slugs(v, sn)
        assert REGION not in got, (v, got)
        assert REGION in _slugs(v, sn, guards_on=False), v


def test_region_keyword_is_bare_substring():
    """根因固化：触发词是**裸子串** region，不要求独立词。

    `getRegion` / `getregionList` / `sRegion` / `duration_region` / `REGIONAL` /
    `&region=area_new` 全部命中 —— 这正是 55 个噪音值的来源，也是这批噪音的形态学解释。
    """
    for sn in (SN_CONSOLE, SN_CSV, SN_DURATION, SN_REGIONAL, SN_URLQUERY, SN_PRICE,
               SN_LOCATION, SN_CSS):
        assert "region" in sn.lower(), sn
    # URL 查询串里的 region= 参数（接口参数，不是云区域）
    got = _slugs("20240425-address_add", SN_URLQUERY)
    assert REGION not in got, got


def test_region_criterion_is_whitelist():
    """判据选型：白名单（值必须过 is_cloud_region_value），不是排除法。

    两个反例值不含 `~`、不是纯数字、也不含 `,`，排除法（挡纯数字/含~/含,/token）接不住；
    白名单一律拒绝。`0x1f1e6` 是十六进制常量，`20240425-address_add` 是带下划线的名字。
    """
    for v, sn in (("0x1f1e6", SN_REGIONAL), ("20240425-address_add", SN_URLQUERY)):
        assert "~" not in v and "," not in v and not v.isdigit(), v
        assert C.is_cloud_region_value(v) is False, v
        assert REGION not in _slugs(v, sn), v


def test_true_regions_still_region():
    """三库 21 个去重真区域值（46 值次）全部保留 cloud_region —— 0 误伤。"""
    for v in TRUE_REGIONS:
        assert C.is_cloud_region_value(v) is True, v
        got = _slugs(v, SN_COS)
        assert REGION in got, (v, got)
    assert REGION in _slugs("cn-south", 'cn-south')


def test_region_not_swallowed_by_bucket():
    """区域形态的值仍让位给 region（既有 fix3 行为不许回退）。"""
    got = _slugs("ap-shanghai-1", 'region:"ap-shanghai-1", ucOssBucket:"tc-buck-1254728086"')
    assert REGION in got and BUCKET not in got, got


# =========================================================
# ② cloud_bucket_name
# =========================================================
def test_bucket_png_filename_not_bucket():
    """`concat(ossBucket,"<hex>.png")` 里的文件名不再判桶名。"""
    for v, sn in (("9f015ec44db54c19a6bb9e47e9527ad7.png", SN_PNG),
                  ("11ba13961a2142619b556e58249cf4dd.png", SN_PNG2),
                  ("005c1f64a45c44ddb05959d6f2350d57.png", SN_PNG3)):
        got = _slugs(v, sn)
        assert BUCKET not in got, (v, got)
        assert BUCKET in _slugs(v, sn, guards_on=False), v
        # is_bucket_name 本来就拒绝它 —— 说明它走的不是桶判据那条路
        assert C.is_bucket_name(v, sn) is False, v


def test_bucket_time_range_not_bucket():
    """`timeBucket: ["8:00-12:00"]` 里的时间段不再判桶名。"""
    got = _slugs("8:00-12:00", SN_TIME)
    assert BUCKET not in got, got
    assert BUCKET in _slugs("8:00-12:00", SN_TIME, guards_on=False)


def test_jscode2session_not_bucket():
    """③ 微信 API 名不再判桶名。

    已知副作用（报告里量化过，不隐藏）：该值在 normsib 语料里落 id_user_identifier(2503,
    risk 3)；而它在 icp / pkgref 两库**本来就是** id_user_identifier（2f7fd0d 扫描结果）
    —— 本改动让三库对这个值的判定一致，不是新造一类误判。该 FP 的真根因在
    is_identifier 的 user-id 分支（只排除了「全小写字母」与「驼峰」两种命名模式），
    属 id_* 类组的复查范围，本轮未动。
    """
    got = _slugs("jscode2session", SN_JSC)
    assert BUCKET not in got, got
    assert BUCKET in _slugs("jscode2session", SN_JSC, guards_on=False)
    # 同族形态（拍平的标识符名）同样不判桶名
    assert BUCKET not in _slugs("json2url", "ossBucket:{ json2url: v }")
    assert BUCKET not in _slugs("image2excel", "ossBucket:{ image2excel: v }")
    # ③ 的判据本身
    assert C.NO_SEPARATOR_IDENTIFIER_RE.match("jscode2session") and \
        not C.NO_SEPARATOR_IDENTIFIER_RE.match("mt100180")


def test_true_buckets_still_bucket():
    """三库真桶名全部保留（含数字开头 / 纯 hex 无后缀）—— 0 误伤。"""
    cases = [
        ("tc-buck-1254728086", 'bucket: "tc-buck-1254728086"'),
        ("scedu-1259336801", 'Bucket: "scedu-1259336801"'),
        ("eqxiu-video", 'videoBucket: i > 0 ? "eqxiu-video" : "eqxiu-test"'),
        ("mt100180", 'e.BUCKET_NAME = r.IS_STANDALONE_DEPLOY ? n : "mt100180"'),
        ("qsc-images", 'ossBucket:"qsc-images"'),
        ("a-seatbucket", 'value: "a-seatbucket", ossBucket: v'),
        ("005c1f64a45c44ddb05959d6f2350d57", 'ucOssBucket:"005c1f64a45c44ddb05959d6f2350d57"'),
        # 数字开头的真桶名（is_bucket_name 本来就收，守卫不许把它们一起拒掉）
        ("1234567890-images", 'bucket: "1234567890-images"'),
        ("1254728086-buck", 'ucOssBucket:"1254728086-buck"'),
    ]
    for v, sn in cases:
        assert C.is_bucket_name(v, sn) is True, v
        got = _slugs(v, sn)
        assert BUCKET in got, (v, got)


def test_bucket_guard_is_shape_not_prefix():
    """守卫按**值形**判定，不按首字符：数字开头不构成拒绝理由。"""
    assert C.is_bucket_name("1234567890-images", 'bucket: "x"') is True
    assert C.is_bucket_name("9f015ec44db54c19a6bb9e47e9527ad7.png", SN_PNG) is False
    assert C.is_bucket_name("8:00-12:00", SN_TIME) is False


# =========================================================
# 归置：守卫只拒不放，出口去向是链路既定兜底
# =========================================================
def test_disposal_is_existing_fallback_only():
    """被拒的值落回本链既有兜底 pii_noise(2304)，不新增任何类型产出。"""
    for v, sn in (("101~200", SN_DURATION), ("10035607", SN_REGION_ID),
                  ("9f015ec44db54c19a6bb9e47e9527ad7.png", SN_PNG),
                  ("8:00-12:00", SN_TIME)):
        got = _slugs(v, sn)
        assert got == [IDT.PII_NOISE], (v, got)


def test_underscore_value_not_caught_by_wildcard_thinking():
    """带下划线的值不会被云桶/云区域接住（SQL 侧 `_` 通配符踩坑的代码侧对照）。"""
    got = _slugs("20240425-address_add", SN_URLQUERY)
    assert BUCKET not in got and REGION not in got, got


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
    print("cloud_region/cloud_bucket_name 语境词出口守卫（fix19）：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
