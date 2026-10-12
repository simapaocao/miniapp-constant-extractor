#!/usr/bin/env python3
"""backend_ip 类组两处噪音（fix18）：四段数字≠IP + 回环/未指定地址。

背景（三库 _v2 实测，口径：出现次数 = SUM(data_item.ref_count+1)，只从 data_item 求和）
-------------------------------------------------------------------------------
① `backend_ip_public` 里 40 个非 IP 值（icp 21 值/704 次、pkgref 35/584、normsib 38/1217，
   占 normsib 该类型出现次数的 37%），成因两类：
   ①a X.509 证书扩展 OID —— `this.oid="2.5.29.15"` / `keyUsage:"2.5.29.15"` /
       `certificatePolicies:"2.5.29.32"`，出处是 jsrsasign / wx_rsa 这类证书解析库；
       三库 75 值/2407 次，全部落在 id-ce 弧 2.5.29.*、全部是裸四段形态。
   ①b 四段版本号 —— `ext/userVersion:"3.176.6.101"` / `appVersion:"1.3.3.100"` /
       `version2Uint32("8.0.56.56","android")` / `version:"11.9.0.255"`。
   `2.x`/`3.x` 恰是 RIPE 与 AWS 的真实分配段，所以只靠形态会误伤，必须靠语境分辨。
② `127.0.0.1` 是 `backend_ip_private` 的头部值（normsib 240 次、三库 136 值/935 次）：
   开发/联调/mock 配置与「本机 hostname 判断」写死的回环地址，作为内网 IP 发现无价值。

本文件固化的边界（重点在**不许命中**的那些）
-------------------------------------------------------------------------------
1) 归置：① 走既有 `_is_oid_format` 兜底 → pii_noise(0)。依据是 5 段 OID（`2.5.29.37.0`）
   与「段值 >255 的四段数字」（`3.2.19.333` / `0.0.2.20250408`）今天已经都在 pii_noise，
   这里只是让 ≤255 的那部分回到同一归宿，不新造标签、不改桶语义。
2) 归置：② 回环 127.0.0.0/8 与 0.0.0.0（语义不同，报告分开统计）→ backend_ip_noise(0)，
   桶从空变为「是 IP 但没有信息量」，名实相符；值与 rvm 路径仍可回溯。
3) 真公网端点一个都不能被带走：`wss://162.14.13.203`、`http://3.176.6.101:8080/api`、
   `SERVER_IP: "182.140.186.147"`（端点键）必须仍是 backend_ip_public。
4) 语境臂只对**裸值**生效、且要求键紧贴值左边：`server: "8.0.17.34"` 里的 `ver`、
   `p = "8.0.17.34"`（无 version 键）都不得命中 —— 已知残留，见报告。
5) 回环判据不许波及邻近网段：`128.0.0.1` / `172.32.0.1` / `128.0.0.6` 仍是 PUBLIC。
6) 其它红线值不受本判据影响：base64 填充 cookie 值、`password1`、随机串密码、
   `04`+128hex 真公钥、`;` / `__` / `@@` 框架产物。

期望值均由 test-result/fix18/j_replay.py 对着真分类器（三库 9,346 pair 回放）跑出后写死。
用法: .venv/bin/python -X utf8 unit-tests/test_backend_ip_oid_loopback.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

PUB, PRIV, NOISE, PII = (IDT.BACKEND_IP_PUBLIC, IDT.BACKEND_IP_PRIVATE,
                         IDT.BACKEND_IP_NOISE, IDT.PII_NOISE)
GATES = ("is_dotted_number_not_ip", "is_loopback_or_unspecified")


def _classify(v, stmt, gate_on=True):
    """跑一遍分类；gate_on=False 时关掉本轮两个判据，取「改动前」判定。"""
    real = [(n, getattr(C, n)) for n in GATES]
    if not gate_on:
        for n, _f in real:
            setattr(C, n, lambda *a, **k: False)
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, "probe")])]
    finally:
        for n, f in real:
            setattr(C, n, f)


# =========================================================
# 1) ①a 证书 OID：形态臂（id-ce 弧）
# =========================================================
def test_x509_oid_arc_leaves_public_ip():
    """裸 `2.5.29.*` 三库实测 75 值/2407 次 → pii_noise(0)，改动前是 public(3)。"""
    for v in ("2.5.29.15", "2.5.29.17", "2.5.29.18", "2.5.29.19", "2.5.29.37",
              "2.5.29.35", "2.5.29.14", "2.5.29.32", "2.5.29.30", "2.5.29.36",
              "2.5.29.31", "2.5.29.20", "2.5.29.21", "2.5.29.54", "2.5.29.33",
              "2.5.29.10", "2.5.29.46"):
        assert _classify(v, 'this.oid="%s"' % v) == [PII], v
        assert _classify(v, 'keyUsage:"%s"' % v, gate_on=False) == [PUB], v


def test_x509_oid_arc_is_shape_based_not_context_based():
    """形态臂与语境无关：即便坐在端点键上（`server:`）也按 OID 处理 —— 已知取舍，写死为回归。"""
    assert _classify("2.5.29.15", 'server: "2.5.29.15"') == [PII]
    assert _classify("2.5.29.15", 'server: "2.5.29.15"', gate_on=False) == [PUB]


# =========================================================
# 2) ①a 证书 OID：语境臂（弧之外的 OID）
# =========================================================
def test_oid_key_context_leaves_public_ip():
    """弧位不在 2.5.29 的 OID，只要键紧贴值左边（oid/keyUsage/…）也照样判非 IP。"""
    for v, stmt in (("1.3.14.7", 'oid: "1.3.14.7"'),
                    ("1.3.36.3", 'this.oid="1.3.36.3"'),
                    ("2.23.140.1", 'oid = "2.23.140.1"'),
                    ("1.3.6.1", 'extKeyUsage: "1.3.6.1"')):
        assert _classify(v, stmt) == [PII], (v, stmt)
        assert _classify(v, stmt, gate_on=False) == [PUB], (v, stmt)


# =========================================================
# 3) ①b 四段版本号：version 键语境臂
# =========================================================
def test_four_segment_version_leaves_public_ip():
    """三库实测的真实语境（含 2.x/3.x RIPE/AWS 段、前导零、version2Uint32 调用形态）。"""
    for v, stmt in (("3.176.6.101", 'ext/userVersion: "3.176.6.101"'),
                    ("2.171.8.101", '"userVersion":"2.171.8.101"'),
                    ("1.3.3.100", 'appVersion: "1.3.3.100"'),
                    ("2.1.5.001", 'appVersion: "2.1.5.001"'),
                    ("11.9.0.255", 'version: "11.9.0.255"'),
                    ("3.12.38.2", 'version: "3.12.38.2"'),
                    ("3.3.3.100", '"patchVersion": "3.3.3.100"'),
                    ("0.0.20.123", 'bizVersion: "0.0.20.123"'),
                    ("25.12.31.15", '"versions":"25.12.31.15"'),
                    ("8.0.56.56", 't=(0,p.version2Uint32)("8.0.56.56","android")'),
                    ("8.0.54.34", 'i = (0, e.version2Uint32)("8.0.54.34", "ios")'),
                    ("8.0.56.34", '(0,n.versionToNumberV2)("8.0.56.34")')):
        assert _classify(v, stmt) == [PII], (v, stmt)
        assert _classify(v, stmt, gate_on=False) == [PUB], (v, stmt)


def test_version_key_boundary_is_not_a_substring_match():
    """`server:` / `conversion:` 里的 `ver` 不许命中 —— 键必须整体匹配且紧贴值左边。"""
    assert _classify("8.0.17.34", 'p = "8.0.17.34"') == [PUB]
    assert _classify("8.0.17.34", 'server: "8.0.17.34"') == [PUB]
    assert _classify("1.2.3.4", 'conversion: "1.2.3.4"') == [PUB]
    assert _classify("1.3.14.7", 'avoid: "1.3.14.7"') == [PUB]
    assert not C.is_dotted_number_not_ip("8.0.17.34", 'server: "8.0.17.34"')
    assert not C.is_dotted_number_not_ip("1.2.3.4", 'conversion: "1.2.3.4"')
    assert not C.is_dotted_number_not_ip("1.3.14.7", 'avoid: "1.3.14.7"')


# =========================================================
# 4) 真端点必须原封不动（红线）
# =========================================================
def test_real_public_endpoints_are_untouched():
    """三库真实端点：URL / 端口 / 端点键形态一律仍是 public(3)。"""
    for v, stmt in (("wss://162.14.13.203", 'url: "wss://162.14.13.203"'),
                    ("http://30.224.161.18:9110/res/upload",
                     'u = "http://30.224.161.18:9110/res/upload"'),
                    ("http://3.176.6.101:8080/api", 'url:"http://3.176.6.101:8080/api"'),
                    ("182.140.186.147", 'SERVER_IP: "182.140.186.147"'),
                    ("106.14.238.35", '"106.14.238.35" === n.location.hostname'),
                    ("58.23.3.82", 'payIp:"58.23.3.82"'),
                    ("59.111.239.249:31101", 'host: "59.111.239.249:31101"'),
                    ("http://2.5.29.15/x", 'url: "http://2.5.29.15/x"')):
        assert _classify(v, stmt) == [PUB], (v, stmt)


def test_private_and_neighbour_ranges_are_untouched():
    """内网判据与回环判据都不许外溢：128/172.32 不是回环也不是内网。"""
    for v, stmt, want in (("192.168.1.23", 'ip: "192.168.1.23"', PRIV),
                          ("10.0.3.226", 'ip: "10.0.3.226"', PRIV),
                          ("172.16.120.38", 'ip: "172.16.120.38"', PRIV),
                          ("128.0.0.1", 'ip: "128.0.0.1"', PUB),
                          ("128.0.0.6", 'ip: "128.0.0.6"', PUB),
                          ("172.32.0.1", 'ip: "172.32.0.1"', PUB),
                          ("126.255.255.255", 'ip: "126.255.255.255"', PUB)):
        assert _classify(v, stmt) == [want], (v, stmt)
        assert _classify(v, stmt, gate_on=False) == [want], (v, stmt)


# =========================================================
# 5) ② 回环 / 未指定地址 → backend_ip_noise(0)
# =========================================================
def test_loopback_goes_to_ip_noise():
    """裸值、带端口、URL 形态、127/8 其它地址：全部 NOISE（改动前是 private(2)）。"""
    for v, stmt in (("127.0.0.1", 'Spbill_create_ip: "127.0.0.1"'),
                    ("127.0.0.1", 'if (t.indexOf("127.0.0.1") >= 0)'),
                    ("127.0.0.1:9010", 'u = "127.0.0.1:9010"'),
                    ("http://127.0.0.1:3000/mock/55", 'exports.mockUrl = "http://127.0.0.1:3000/mock/55"'),
                    ("http://127.0.0.1:19952/Home/HidReadCard",
                     'url:"http://127.0.0.1:19952/Home/HidReadCard"'),
                    ("http://127.0.0.1:8008/pms", 'baseUrl:"http://127.0.0.1:8008/pms"'),
                    ("http://127.0.0.6/app/index.php",
                     'n = "http://127.0.0.6/app/index.php" == c.siteInfo.siteroot'),
                    ("127.0.0.0", 'ip: "127.0.0.0"'),
                    ("127.255.255.255", 'ip: "127.255.255.255"')):
        assert _classify(v, stmt) == [NOISE], (v, stmt)
        assert _classify(v, stmt, gate_on=False) == [PRIV], (v, stmt)


def test_unspecified_address_goes_to_ip_noise_by_itself():
    """0.0.0.0 与回环语义不同（监听全部接口 vs 本机）：单独一条，两桶都不得再判。"""
    for v, stmt in (("0.0.0.0", 'ip: "0.0.0.0"'),
                    ("0.0.0.0:8000", 'host: "0.0.0.0:8000"'),
                    ("http://0.0.0.0:8097/cms/get_index_banner_detail?id=",
                     'url: "http://0.0.0.0:8097/cms/get_index_banner_detail?id="'),
                    ("http://0.0.0.0:8001/authLogin/client/api",
                     'clientUrl: "http://0.0.0.0:8001/authLogin/client/api"'),
                    ("ws://0.0.0.0:9010/ajaxchattest", 'var url = "ws://0.0.0.0:9010/ajaxchattest"')):
        assert _classify(v, stmt) == [NOISE], (v, stmt)
        # 改动前：0.0.0.0 被判成 PUBLIC(3)（不可路由却被当公网）—— 本身即类型判错
        assert _classify(v, stmt, gate_on=False) == [PUB], (v, stmt)


# =========================================================
# 6) 判据直测（谓词真值表 + 优先级）
# =========================================================
def test_is_loopback_or_unspecified_table():
    for ip, want in ((("127", "0", "0", "1"), True),
                     (("127", "0", "0", "0"), True),
                     (("127", "255", "255", "255"), True),
                     (("0", "0", "0", "0"), True),
                     (("128", "0", "0", "1"), False),
                     (("10", "0", "0", "1"), False),
                     (("1", "0", "0", "1"), False),
                     (("0", "0", "0", "1"), False),
                     (("192", "168", "1", "1"), False)):
        assert C.is_loopback_or_unspecified(ip) is want, ip
    assert C.is_loopback_or_unspecified(None) is False
    assert C.is_loopback_or_unspecified(("1", "2", "3")) is False


def test_dotted_number_not_ip_requires_gate_evidence():
    """没有任何证据（无弧、无紧邻键）的四段数字仍是 IP —— 判据不是形态白名单。"""
    for v, stmt in (("182.140.186.147", 'SERVER_IP: "182.140.186.147"'),
                    ("3.176.6.101", '"userVerx": "3.176.6.101"'),
                    ("39.98.173.253", 'ip: "39.98.173.253"')):
        assert not C.is_dotted_number_not_ip(v, stmt), (v, stmt)
    assert C.is_dotted_number_not_ip("2.5.29.15", 'x = "2.5.29.15"'), "弧位即证据"
    assert not C.is_dotted_number_not_ip("2.5.30.15", 'x = "2.5.30.15"'), "弧位必须精确"
    assert not C.is_dotted_number_not_ip("182.140.186.147", ""), "空语句不产证据"


def test_gate_return_value_contract():
    """① 走 return False（交回通用链），② 走 return True（消费掉并产出 NOISE）。"""
    assert C.process_standalone_ip("2.5.29.15", 'this.oid="2.5.29.15"', "", 0, []) is False
    assert C.process_standalone_ip("3.176.6.101", 'ext/userVersion: "3.176.6.101"', "", 0, []) is False
    assert C.process_standalone_ip("127.0.0.1", 'ip: "127.0.0.1"', "", 0, []) is True
    res = []
    assert C.process_standalone_ip("127.0.0.1", 'ip: "127.0.0.1"', "f.js", 3, res) is True
    assert res == [(NOISE, "127.0.0.1", "f.js", 3)], res
    assert C.process_standalone_ip("not-an-ip", "x", "", 0, []) is False


# =========================================================
# 7) 其它红线值不受本判据影响
# =========================================================
def test_other_redline_values_unaffected():
    """基线与本项目其它四条红线（cookie base64 / 密码串 / 真公钥 / 框架产物）逐位一致。"""
    cases = (("LmF3LWNvb2tpZS1iYW5uZXI=", 'Cookie: "a"="LmF3LWNvb2tpZS1iYW5uZXI="'),
             ("password1", 'password: "password1"'),
             ("mnP7XKDCaWFjINWi", 'pwd: "mnP7XKDCaWFjINWi"'),
             ("o0IN8wTN50QMxX-V4siq_GSRFuts", 'password: "o0IN8wTN50QMxX-V4siq_GSRFuts"'),
             ("signBoardPassword_S8hY", 'signBoardPassword: "signBoardPassword_S8hY"'),
             ("046598273bfed3454720e21028815c22ce3b8a013bb4892f588d5e9a12e9206b58f386"
              "26e4e35ab49258cdec7b7cf559ba2b44b87135adab91ba931c4c31379b27",
              'certPublicKey: "%s"'),
             (";height:", 'setCssToHead(["a{height:1px;line-height:2"]);'),
             ("__scopeId", '["__scopeId","data-v-exO"]'),
             ("@@iterator", 'var k = "@@iterator";'))
    for v, stmt in cases:
        if "%s" in stmt:
            stmt = stmt % v
        assert _classify(v, stmt) == _classify(v, stmt, gate_on=False), v
        assert not C.is_dotted_number_not_ip(v, stmt), v
        assert not C.is_loopback_or_unspecified(C.ip_check_address(v.split(":")[0]))
    # 框架产物族仍是「命中即丢弃」
    assert _classify(";height:", 'setCssToHead(["a{height:1px;line-height:2"]);') == []


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
    print("backend_ip 类组两处噪音（OID/版本号 + 回环/0.0.0.0）验证：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
