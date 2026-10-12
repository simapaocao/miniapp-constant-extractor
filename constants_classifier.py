#!/usr/bin/env python3
"""
Constants Classifier - 常量分类器
完全按照 constant_types.json 的分类结构
"""

from __future__ import annotations
import sys
import json
import base64
from typing import List, Tuple, Set, Union
import re
import constant_ids as IDT


# =========================================================
# 通用工具函数
# =========================================================
def has_keyword_in_context(stmt: str, keywords: Union[Set[str], Tuple[str, ...]]) -> bool:
    """
    判断上下文是否包含指定关键词，使用单词边界匹配避免误报。
    处理逻辑:
    1. 先做快速子串匹配（忽略大小写），直接包含关键词就返回 True
    2. 将下划线/横杠/点替换为空格 (蛇形/脊柱形命名)
    3. 在小写和大写字母之间插入空格 (驼峰命名)
    4. 去除冒号和引号
    5. 拆分为单词列表，检查是否包含关键词
    """
    if not stmt:
        return False
    keyword_set = keywords if isinstance(keywords, set) else set(keywords)
    # 快速路径：直接子串匹配（忽略大小写）
    stmt_lower = stmt.lower()
    if any(kw in stmt_lower for kw in keyword_set):
        return True
    # 慢速路径：拆分驼峰/蛇形命名后匹配
    normalized = re.sub(r'[_\-\.]', ' ', stmt)
    normalized = re.sub(r'([a-z])([A-Z])', r'\1 \2', normalized)
    normalized = re.sub(r'[:\"\']', ' ', normalized)
    words = set(normalized.lower().split())
    return not words.isdisjoint(keyword_set)


def has_keyword_substring(stmt: str, keywords: Union[Set[str], Tuple[str, ...]]) -> bool:
    """检查 stmt 是否包含任一关键词子串（小写匹配）"""
    if not stmt:
        return False
    stmt_lower = stmt.lower()
    return any(kw in stmt_lower for kw in keywords)


# 短关键词（uid / pwd）必须落在「独立词或驼峰段」边界上。
# has_keyword_in_context 的快速路径是纯子串匹配（`kw in stmt_lower`），对长关键词没问题，
# 对两个字母级别的短词则过宽：
#   uid  → uuid / uuids / __uuid__ / guid / guide / skuId / menuId / t2zxNHFUIdE
#   pwd  → has_paypwd / dmPwD / 随机 base64 载荷里的 "pwd" 子串
# 因此这两个词不走原函数，改走下面的段匹配（其余关键词行为完全不变）。
RE_SHORT_KEYWORD_TOKEN = re.compile(r"[A-Za-z0-9$]+")
UID_LOOKALIKE_SUBSTRINGS = ("uuid", "guid", "guide")


def has_keyword_in_context_strict(stmt: str, keyword: str,
                                  lookalikes: Tuple[str, ...] = ()) -> bool:
    """判断 keyword 是否以「独立词或驼峰段」形式出现在 stmt 中（大小写不敏感）。

    例: uid 认 o.uid / visitorUid / uidRule / ProductUidL / uid:，
    不认 uuid / uuids / __uuid__ / guid / mobxGuid / guide / skuId / t2zxNHFUIdE。
    lookalikes 给出该短词的同形家族子串（如 uuid/guid/guide），命中即整段跳过。

    断词规则与 has_keyword_in_context 的慢速路径一致（小写/数字接大写处断开），
    另外把 `_ - . : " '` 与其它非标识符字符当作分隔符。
    已知漏报形态：全大写段紧接另一个大写开头单词的写法不算段，例如
    getUIDByUser（无小写→大写断点）不命中；getUidByUser / uidRule / UID 命中。
    """
    if not stmt:
        return False
    kw = keyword.lower()
    for token in RE_SHORT_KEYWORD_TOKEN.findall(stmt):
        token_lower = token.lower()
        if any(lk in token_lower for lk in lookalikes):
            continue
        if kw in re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", token).lower().split():
            return True
    return False


# =========================================================
# 剥值：外部证据（把「值自己」从上下文里去掉）
# =========================================================
# 病根：语境判据形如 has_keyword_*(stmt, ...)，而 stmt 是值周围 512 字符窗口，
# **里面包含值本身**。于是
#     值 = auth.updatePassword
#       -> stmt 必然含 "updatePassword" -> 命中关键词 "password" -> 语境通过
# 值自己给自己开闸。全仓原先只有 has_iv_context 做了处理（str.replace 全删）。
#
# 但「全删」会连**键名位置**的出现一起删掉，让自赋值常量的证据消失：
#     H5PayTradeNo: "H5PayTradeNo"   replace 全删 -> ': ""'，键名证据没了
#     password:     "password"       真弱口令会因此消失
# 所以这里逐出现判断：**后面（跳过引号与空白）紧跟 `:` 的出现视为键名/属性名位置，
# 保留**；其余出现（值位置）删掉。
#
#   | 语句                                   | 剥值后                |
#   |----------------------------------------|-----------------------|
#   | H5PayTradeNo: "H5PayTradeNo"           | H5PayTradeNo: ""      |（键名保留，行为不变）
#   | password: "password"                   | password: ""          |（仍然检出）
#   | "auth.updatePassword"（数组元素）        | ""                    |（假证据除掉）
#   | signHeaderKeys:["x-expire-timestamp"]  | signHeaderKeys:[""]   |（假证据除掉）
#
# 已接入的判据（逐批推广，value 一律**无默认值**：漏改调用点直接 TypeError）：
#   第 0 批：has_user_id_context / has_cloud_password_context（value 必填）
#   第 1 批：has_secret_context / has_appkey_context / has_session_key_context /
#            has_aes_key_context（value 必填）
#   自始有：has_iv_context（value 有默认值 ""，见下面第 4 条）
#
# 口径边界（**未**统一，留痕）：
#   1. is_rsa_hex_public_key / process_Regex_crypto_key 读的是**整条语句**而不是这个
#      512 字符窗口，剥值口径与它们不一致；只动逐判据的接线，那两处不改。
#   2. process_generic_digit_prefixed_constant 里的裸串守卫（如 `if "point" in stmt_lower`）
#      读的也是原 stmt，不动。
#   3. extract_context 在语句很长时返回的是「3 个空白分隔 token 的 join」，不保证是
#      原语句的连续切片；值不在窗口里时剥值退化为空操作（保守，不改变原判定）。
#      三库实测：第 1 批四条判据各有 ~59.9–64.1 万次（约 23%）调用属于这种空操作。
#   4. has_iv_context 仍在用 `stmt.replace(value, "")`（全删、**不**保留键名位置）。
#      「要不要统一到 external_context」已实测评估过（test-result/b1-strip/
#      analyze_iv_unify.out），结论是**不统一**：判据级差集 11 对（全部 F→T），
#      类型级 1 对变 PII_NOISE(200) -> crypto_static_iv(202)。F→T 的来源正是「值自己
#      占了键名位」：`"45wAAWzMlKbIV6Zbiqpgch": [...]`（值里含 IV，值充当键名）、
#      `"safe-password-nonce": ""` / `"--vector": i.value`（键名 == 值）、以及三元表达式
#      `? "68uO6IvE..." : "..."`（`" :` 被 RE_KEYNAME_TAIL 当成键名）。统一会把值自证
#      重新放回来，净增 1 个误报、0 个真阳性，所以 replace 的更狠口径在这里反而更准。
#   5. 出现按**子串**匹配（与 str.replace 一致，不是整 token）。因此「值嵌在更长标识符
#      中间」的那次出现也会被删：`passwordField: "password"` -> `Field: ""`（键名里的
#      password 段被削掉，该键名不再提供语境）。反过来，值正好是键名**后缀**且后面紧跟
#      冒号时会被保留（`myField_pwd: "x"` 里的 pwd 不动）。第 1 批 1341 个翻转对里，
#      「整 token 口径」能多保住语境的有 8 对，但这 8 对**没有一个**改变类型判定
#      （test-result/b1-strip/analyze_b1.out）；唯一那处类型变更两种口径都删，
#      所以本轮不引入整 token 口径。
#
# 注意 RE_KEYNAME_TAIL **故意不带 `^`**：下面用 `RE.match(stmt, end)` 在指定位置
# 起判，而 `^` 在带 pos 的 match 里只认字符串开头（除非 re.M），会把键名位置一律
# 判成「非键名」——第一版就踩了这个坑（`H5PayTradeNo: "H5PayTradeNo"` 被剥成 `: ""`）。
RE_KEYNAME_TAIL = re.compile(r"[\"'\t ]*:")


def external_context(stmt: str, value: str) -> str:
    """返回「去掉值自身贡献」的上下文：删除值在语句里的出现，但保留键名位置的出现。

    键名位置 = 该出现之后（跳过引号与空白）紧跟 `:` —— 即 `key: "value"` /
    `"key": "value"` 里的 key。

    与 has_iv_context 原先的 `stmt.replace(value, "")` 相比，这里多保留了**键名位置**的
    出现（`key: "value"` 里的 key 不动）；但按子串口径，值嵌在更长标识符中间的那次出现
    仍会被删（`passwordField: "password"` -> `Field: ""`），这是本规则的已知代价。

    空值 / 值不在语句里 / 空语句都是空操作，返回原语句（调用方拿到的一定是 str）。
    """
    if not stmt or not value or value not in stmt:
        return stmt
    parts = []
    pos = 0
    v_len = len(value)
    while True:
        idx = stmt.find(value, pos)
        if idx < 0:
            parts.append(stmt[pos:])
            return "".join(parts)
        end = idx + v_len
        if RE_KEYNAME_TAIL.match(stmt, end):
            parts.append(stmt[pos:end])      # 键名位置：保留
        else:
            parts.append(stmt[pos:idx])      # 值位置：删掉
        pos = end


# =========================================================
# 通用验证函数 (提高复用率)
# =========================================================
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
ALNUM_EXTENDED_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def is_hex_string(s: str) -> bool:
    """判断是否为纯十六进制字符串"""
    return all(c in HEX_CHARS for c in s)


def is_base64_chars(s: str) -> bool:
    """判断是否为合法的 Base64 字符集 (包括 URL-safe 变体)"""
    return all(c in BASE64_CHARS for c in s)


def is_alnum_extended(s: str) -> bool:
    """判断是否为字母数字加下划线和连字符"""
    return all(c in ALNUM_EXTENDED_CHARS for c in s)


def check_length_range(s: str, min_len: int, max_len: int) -> bool:
    """检查字符串长度是否在指定范围内"""
    return min_len <= len(s) <= max_len


def has_min_unique_chars(s: str, min_count: int) -> bool:
    """检查字符串是否有足够的不同字符（排除占位符）"""
    return len(set(s)) >= min_count


def is_placeholder_value(s: str) -> bool:
    """检测是否为占位符/测试数据 (去重后字符数 < 3)"""
    return len(set(s)) < 3


def calculate_byte_entropy(data: bytes) -> float:
    """计算字节序列的信息熵"""
    if not data:
        return 0.0
    from collections import Counter
    import math
    byte_counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


def extract_context(stmt: str, s: str, l: int = 256) -> str:
    """从长语句中提取目标字符串周围的上下文"""
    if len(stmt) <= l:
        return stmt
    fs = stmt.split()
    for idx, f in enumerate(fs):
        if s in f:
            start = max(0, idx - 1)
            end = min(len(fs), idx + 2)
            return " ".join(fs[start:end])
    return stmt[:l]


def append_result(res: list, slug_id: int, s: str, src: str, sid: int):
    """统一的结果添加函数"""
    res.append((slug_id, s, src, sid))


# =========================================================
# IP 地址工具函数
# =========================================================
def ip_check_address(s: str) -> tuple:
    """检查是否为有效 IP 地址，返回 tuple 或 None"""
    parts = s.split(".")
    if len(parts) != 4:
        return None
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return None
    return tuple(parts)


def ip_get_ip_type(ip: tuple) -> str:
    """获取 IP 类型: PRIVATE, PUBLIC 或 INVALID"""
    if not isinstance(ip, tuple) or len(ip) != 4:
        return "INVALID"
    try:
        ip_int = tuple(int(p) for p in ip)
    except ValueError:
        return "INVALID"
    # 私有地址范围
    if ip_int[0] == 10:
        return "PRIVATE"
    if ip_int[0] == 172 and 16 <= ip_int[1] <= 31:
        return "PRIVATE"
    if ip_int[0] == 192 and ip_int[1] == 168:
        return "PRIVATE"
    if ip_int[0] == 127:
        return "PRIVATE"
    return "PUBLIC"


# =========================================================
# fix18 ①：四段点分数字 ≠ IP（证书 OID / 四段版本号）
# =========================================================
# ip_check_address 只做**形态**检查（四段、每段 ≤255），所以下面这些每段都 ≤255 的
# 四段数字全被判成公网 IP。backend_ip_public 里的非 IP 值（用户报的规模：icp 21 值/704 次、
# pkgref 35 值/584 次、normsib 38 值/1217 次，在 normsib 该类型里占出现次数的 37%）
# 分两类成因（本轮实测的离开值见 test-result/fix18/j_replay.out）：
#   ①a X.509 证书扩展 OID：`this.oid="2.5.29.15"` / `keyUsage:"2.5.29.15"` /
#      `certificatePolicies:"2.5.29.32"`，出处是 jsrsasign / wx_rsa 这类证书解析库。
#      三库 75 个值 / 2407 次，全部落在 id-ce 弧 2.5.29.*，且全部是**裸四段**形态。
#   ①b 四段版本号：`ext/userVersion:"3.176.6.101"` / `appVersion:"1.3.3.100"` /
#      `version2Uint32("8.0.54.61","android")` / `version:"11.9.0.255"`。
#      `2.x`/`3.x` 恰好是 RIPE(2.0.0.0/8) 与 AWS(3.0.0.0/8) 的真实分配段，所以
#      形态判据单独用会误伤，必须靠语境分辨。
#
# 判据取 (c) 组合，两条臂各自要「证据」：
#   形态臂：值本体落在 id-ce 弧（2.5.29.）—— 该弧下一切 4 段值在三库里 100% 是证书
#           扩展 OID（对照：同弧的 5 段 `2.5.29.37.0` / `2.5.29.32.0` 今天就在 pii_noise）。
#   语境臂：**只对裸值生效**，且要求证书键 / version 键紧接在值左边（[:=(] 直接接值），
#           避免整行压缩代码里远处出现的 certificate/version 字样把真端点带走。
# 归置：不走 IP 分支（交给既有 `_is_oid_format` 兜底 → pii_noise(0)），不是丢弃也不是
# backend_ip_noise —— 依据是 5 段 OID 与「段值 >255 的四段数字」（3.2.19.333 /
# 8.0.x 长段版本号）今天已经都在 pii_noise：这里只是让 ≤255 的子集回到同一归宿，
# 不新造标签、不改桶语义。误伤实测见 test-result/fix18/ 报告。
RE_X509_ID_CE = re.compile(r"^2\.5\.29\.")
# 键名左侧要求「词边界」：否则 `avoid:` 里的 oid、`server:` 里的 ver 会误命中。
# 键名右侧允许被引号/括号包住（`"userVersion":"1.2.3.4"`、`version2Uint32("8.0.56.56"`），
# 值左侧的引号可有可无：stmt 窗口到值本体为止。
RE_OID_KEY_BEFORE = re.compile(
    r"(?:^|[^\w$])(?:oid|keyusage|extkeyusage|extendedkeyusage|basicconstraints|"
    r"subjectaltname|subjectkeyidentifier|authoritykeyidentifier|certificatepolicies|"
    r"inhibitanypolicy|nameconstraints|policyconstraints|crldistributionpoints|"
    r"freshestcrl|x509|asn1)\s*[\"']?\s*[\)\]]?\s*[:=(]\s*(?:[\"']\s*)?$", re.I)
RE_VER_KEY_BEFORE = re.compile(
    r"(?:^|[^\w$])(?:version\w*|ver|(?-i:[a-z][a-z0-9]*Version\w*))\s*[\"']?\s*[\)\]]?\s*"
    r"[:=(]\s*(?:[\"']\s*)?$", re.I)


def _has_non_ip_key_context(s: str, stmt: str, width: int = 48) -> bool:
    """s 在 stmt 中**任一次**出现的紧邻左语境是否为证书键 / version 键。

    只取紧邻的 48 字符：压缩代码整行里远处出现的 certificate/version 字样不该把
    真端点带走（实测三库 0 例）。
    """
    if not stmt:
        return False
    start = 0
    while True:
        i = stmt.find(s, start)
        if i < 0:
            return False
        ctx = stmt[max(0, i - width):i]
        if RE_OID_KEY_BEFORE.search(ctx) or RE_VER_KEY_BEFORE.search(ctx):
            return True
        start = i + 1


def is_dotted_number_not_ip(ip_part: str, stmt: str) -> bool:
    """四段数字但**不是 IP**：X.509 证书扩展 OID 或四段版本号（fix18 ①）。

    只用于裸值路径（process_standalone_ip）。URL 形态的 host 不在此列：
    带 scheme/路径的 host 是「端点声明」，且三库实测 0 例 OID 弧 host。
    """
    return bool(RE_X509_ID_CE.match(ip_part) or _has_non_ip_key_context(ip_part, stmt))


# =========================================================
# fix18 ②：回环与未指定地址（无基础设施信息量）→ IP 噪声(0)
# =========================================================
# 127.0.0.1 是 backend_ip_private 的头部值（normsib 240 次、三库 136 值/935 次）：
# 开发/联调/mock 配置与「本机 hostname 判断」写死的回环地址，每个应用都有，作为
# 「内网 IP 发现」没有分析价值。0.0.0.0 语义不同（未指定 / 监听全部接口，不是回环），
# 但作为 URL host 同样不指向任何可分析目标，且今天被 ip_get_ip_type 判成 PUBLIC
# （不可路由，属于类型判错）。
# 归置选 backend_ip_noise(0)：这两者是**货真价实的 IP 字面量**（属于本类组成员），
# 只是没有信息量 —— 用本类组的 risk0 桶承接，语义贴合、不产生告警，值仍可回溯
# （如 `http://127.0.0.1:19952/Home/HidReadCard` 这类本机 agent 端点）。
# 与 ① 归置不同的理由：OID/版本号**根本不是 IP**，放 IP 噪声桶会把「IP噪声」这个名字
# 扭曲成「OID 桶」；回环/未指定则是 IP，放本类组的噪声桶名实相符。
# ::1 与 localhost 不在此列：ip_check_address 只认四段数字，它们在结构上到不了
# backend_ip_*（三库实测 0 值），不为不存在的形态写分支。
def is_loopback_or_unspecified(ip: tuple) -> bool:
    """回环 127.0.0.0/8 或未指定地址 0.0.0.0"""
    if not isinstance(ip, tuple) or len(ip) != 4:
        return False
    try:
        octets = [int(p) for p in ip]
    except ValueError:
        return False
    if octets[0] == 127:
        return True
    return octets == [0, 0, 0, 0]


# =========================================================
# 前缀匹配字典
# =========================================================
# fmt: off
TOKEN_PREFIX_WORDS = {
    "eyJ": IDT.TOKEN_JWT,
    "Bearer ": IDT.TOKEN_BEARER,
    "bearer ": IDT.TOKEN_BEARER,
    "Basic ": IDT.TOKEN_BASIC,
    "basic ": IDT.TOKEN_BASIC,
}

CRYPTO_PREFIX_WORDS = {
    "-----BEGIN PRIVATE": IDT.CRYPTO_PRIVATE_KEY,
    "-----BEGIN RSA PRIVATE": IDT.CRYPTO_PRIVATE_KEY,
    "-----BEGIN PUBLIC": IDT.CRYPTO_PUBLIC_KEY
}

# 纯 PEM `BEGIN` 行：值只有 `-----BEGIN … KEY-----`（可带尾随换行/CRLF/转义），没有密钥体。
#
# 这类值**不是被截断的密钥**，是**拼接 PEM 用的分隔符字面量** —— 三库真实上下文：
#   decrypt.setPrivateKey("-----BEGIN RSA PRIVATE KEY-----" + privateKey + "-----END RSA PRIVATE KEY-----")
#   value: function(){ return "-----BEGIN RSA PRIVATE KEY-----\n" + t.wordwrap(this.getPrivateBaseKeyB64()) + … }
#   s = "-----BEGIN PRIVATE KEY-----\n" + a.config.javaprik + "\n-----END PRIVATE KEY-----"
# 材料从来不在这个字面量里：要么是运行时变量，要么（`"-----BEGIN RSA PRIVATE KEY-----".concat("MIIC…")`
# 那种）在**另一条记录**里。所以它按构造就不可能承载密钥，判掉不丢任何东西。
#
# 量化（test-result/risk5_struct/crypto_pem_survey.py + crypto_pem_pairing.py）：
#   crypto_private_key(2102) 该形态 12 值 / 1,893 次 = 该桶出现次数的 **70.7%**
#     （`-----BEGIN RSA PRIVATE KEY-----` 1,207 次、`…-----\n` 667 次、`-----BEGIN PRIVATE KEY-----` 6 次…）
#   同形态在 crypto_public_key 里还有 2 值 / 1,752 次（`-----BEGIN PUBLIC KEY-----` + `…-----\n`），
#   一并收掉 —— 判据在同一个 CRYPTO_PREFIX_WORDS 循环里，不分公私钥。
# 同族先例：`;` 开头（WXSS 样式分隔符）、`&参数=`（URL 分隔符）都是「命中即丢弃」。
# 阈值形态：字符类 `[\s\\nrt]` 排除了 base64 全部字符（A-Za-z0-9+/=），
# 因此匹配成功即证明后面没有任何密钥体，无需再加长度判断。
RE_PEM_BEGIN_ONLY = re.compile(r"^-----BEGIN [A-Z0-9 ]*KEY-----[\s\\nrt]*$")


def is_pem_header_fragment(s: str) -> bool:
    """值是否只有一个 PEM `BEGIN` 行（拼接 PEM 的分隔符，不含密钥材料）。"""
    return bool(RE_PEM_BEGIN_ONLY.match(s))

# Base64 编码的公钥前缀 (DER 格式)
# MIGf, MIIBIj 等是 RSA 公钥的 Base64 编码开头
# MHQ, MHY 等是 EC 公钥的 Base64 编码开头
BASE64_PUBLIC_KEY_PREFIXES = ("MIGf", "MIIBIj", "MIIBoj", "MHQ", "MHY")

# Base64 编码的私钥前缀 (DER 格式)
# MIICd, MIICe, MIICX 等是 RSA-1024 私钥
# MIIE 是 RSA-2048 私钥 (PKCS#8 或 PKCS#1)
# MIIEv, MIIEo, MIIEp 是 RSA-2048 私钥 (PKCS#1)
# MIGH, MIGE 等是 EC 私钥
BASE64_PRIVATE_KEY_PREFIXES = ("MIICd", "MIICe", "MIICX", "MIIE", "MIGH", "MIGE")

URL_PREFIX_WORDS = ["https://", "http://", "wss://", "ws://"]
URL_ENCODED_PREFIX_WORDS = ["https%3a%2f%2f", "http%3a%2f%2f"]
CLOUD_URL_PREFIX_WORDS = {"cloud://", "cos://", "oss://", "s3://"}
MINIAPP_PAGES_PREFIX_WORDS = ["pages/", "/pages/"]
MINIAPP_PLUGIN_PREFIX_WORDS = ["plugin://", "plugin-private://"]
DATA_URI_PREFIX = "data:"

MINIAPP_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm",
    ".ttf", ".woff", ".woff2", ".eot",
)
MINIAPP_MODULE_EXTENSIONS = (".js", ".ts", ".json", ".wxs", ".wxss", ".wxml")

CLOUD_REGION_PREFIX_WORDS = [
    "cn-", "ap-", "us-", "eu-", "sa-", "me-", "af-", "na-",
]

# 区域名 = <前缀>-<方向词或地域节点>[-<数字>]。前缀只有两个字母，光看前缀会把
# CSS/BEM 类名整批吞掉（me-service / sa-image__img / na-big-pic / us-close / ap-page），
# 所以第二段必须是真地域名。见 is_cloud_region_value。
CLOUD_REGION_DIRECTION_WORDS = (
    "north", "south", "east", "west", "central",
    "northeast", "northwest", "southeast", "southwest",
)
CLOUD_REGION_PLACE_WORDS = (
    # 腾讯 COS / 阿里 OSS / AWS S3 / 华为 OBS 的地域节点名
    "beijing", "shanghai", "guangzhou", "shenzhen", "chengdu", "hangzhou",
    "nanjing", "chongqing", "wuhan", "changsha", "xian", "jinan", "fuzhou",
    "hongkong", "taipei", "macau",
    "singapore", "tokyo", "osaka", "seoul", "mumbai", "bangkok", "jakarta",
    "kualalumpur", "manila", "hanoi", "hochiminh", "sydney", "melbourne",
    "siliconvalley", "ashburn", "virginia", "toronto", "dallas", "seattle",
    "saopaulo", "santiago", "frankfurt", "london", "dublin", "paris",
    "amsterdam", "milan", "madrid", "stockholm", "zurich", "moscow",
    "dubai", "riyadh", "johannesburg", "cairo",
)

BUCKET_CONTEXT_WORDS = (
    "bucket", "bucketname", "bucket_name",
    "ossbucket", "oss_bucket", "cosbucket", "cos_bucket",
    "s3bucket", "s3_bucket", "storagebucket", "storage_bucket",
)

EMAIL_DOMAIN_SUFFIXES = (
    ".com", ".cn", ".net", ".org", ".edu", ".gov",
    ".io", ".co", ".cc", ".me", ".info", ".biz",
)

MAP_KEY_PREFIX_GOOGLE = "AIzaSy"
MAP_KEY_CONTEXT_WORDS = {
    "mapkey", "map_key", "amap", "qqmap", "bmap", "googlemap",
    "tencentmap", "gaodemap", "baidumap",
}

ANALYTICS_KEY_CONTEXT_WORDS = {
    "mobkey", "umeng", "umengkey", "bugly", "buglyid", "buglykey",
    "sentry", "sentrydsn", "mixpanel", "sensors", "sensorsdata",
    "growingio", "zhugeio", "analyticskey", "analyticsid", "trackingid",
    "siteid", "site_id",  # 京东联盟等站点 ID
}

UPLOAD_POLICY_REQUIRED_FIELDS = ("expiration", "conditions")
UPLOAD_POLICY_PROVIDER_KEYWORDS = (
    "bucket", "content-length-range", "starts-with",
    "x-amz-credential", "x-oss-",
)

CLOUD_TOKEN_PREFIXES = {
    "ghp_": "github", "gho_": "github", "ghu_": "github",
    "ghs_": "github", "ghr_": "github",
    "glpat-": "gitlab",
    "xoxb-": "slack", "xoxp-": "slack", "xoxa-": "slack", "xoxr-": "slack",
    "sk_live_": "stripe", "sk_test_": "stripe",
    "pk_live_": "stripe", "pk_test_": "stripe",
    "rk_live_": "stripe", "rk_test_": "stripe",
    "npm_": "npm", "pypi-": "pypi", "hrku-": "heroku",
    "SG.": "sendgrid",
    "shpat_": "shopify", "shpca_": "shopify", "shppa_": "shopify",
    "oauth:": "twitch",
    "dop_v1_": "digitalocean", "doo_v1_": "digitalocean",
    "sl.": "dropbox",
}

# 需要**体形校验**的前缀（前缀 -> 体形正则，体 = 去掉前缀的部分）。
#
# 病根：is_cloud_token 只做 `s.startswith(prefix) + 长度 20..200`，既不看 stmt、
# 也不看体形。`ghp_`/`glpat-`/`xoxb-` 这类前缀不像自然语言，裸 startsWith 没问题；
# 但 `npm_` 是「普通词 + 下划线」，于是路径与命令行全部命中：
#     npm_components/@alife/saas-mini/es/alert/index          （路径）
#     npm_config_report=true npm run task build plugin ...    （命令行）
# 三库实测 cloud_cred_token(1205) 桶 = 582 值 / 2,237 次，**100% 是 npm_ 前缀**，
# 且 582/582 的体形都不是 token（含 / @ . - 或空格）——真 token 数为 0。
# 真 npm token = `npm_` + 36 位 Base62（末 6 位是 CRC32 校验），见
# https://github.blog/security/announcing-npms-new-access-token-format/
# 全库（不限类型）582 个 `npm_` 开头的值里，体形纯字母数字的有 **0** 个，
# 所以这条守卫的真阳性损失为 0。
CLOUD_TOKEN_BODY_PATTERNS = {
    "npm_": re.compile(r"^[A-Za-z0-9]{36}$"),
}

CLOUD_COOKIE_NAMES = (
    "aliyun_", "alicloud_", "acs_", "login_aliyunid",
    "qcloud_", "tencent_", "uin=", "skey=",
    "aws-", "awsalb", "awsalbcors", "x-amz-",
    "huaweicloud_", "hws_", "bce_", "baidu_",
    "qiniu_", "upyun_",
)

CLOUD_PASSWORD_CONTEXT_WORDS = {
    "password", "passwd", "pwd",
    "dbpassword", "db_password", "dbpwd", "db_pwd",
    "mysqlpassword", "mysql_password", "mysqlpwd",
    "redispassword", "redis_password", "redispwd",
    "mongopassword", "mongo_password",
    "pgpassword", "pg_password", "postgrespassword",
    "osspassword", "oss_password", "cospassword", "cos_password",
    "s3password", "s3_password",
    "ftppassword", "ftp_password", "ftppwd",
    "sftppassword", "sftp_password",
    "smtppassword", "smtp_password", "mailpassword", "mail_password",
    "mqpassword", "mq_password", "rabbitmqpassword", "kafkapassword",
}

# ---------------------------------------------------------
# 路径/路由里的 password 不是密码语境（fix16 ①）
# ---------------------------------------------------------
# 病根：has_cloud_password_context 的**长词**（password / passwd / db_pwd …）走裸子串匹配，
# 于是页面路径里的 password 段也算语境：
#     o.disabled=!1,e.index.__f__("log","at pages/login/passwordLogin.vue:484","err3241",t)
#     -> 值 err3241（日志 tag）被判 cloud_cred_password(1203, risk5)
# 三库实测该桶 2,847 个「值×上下文」对里 304 对含路径式 password（`pages?/[^ ]*password`）。
#
# 判据只动**语境侧**，且只挖掉「明显在路径上」的那些出现，两种情况之一：
#   a) 关键词被 `/` 夹住（`pages/login/password` / `password/index.js`）——
#      路径段的分隔符就在紧邻两侧；`login/passwordLogin.vue` 也落在这一条。
#   b) 关键词落在**含 `/` 的引号串**里（`"/pages/setPassword/setPassword?x=1"`）——
#      覆盖 `setPassword` / `updatePwd` 这类驼峰式路径段（它们的左邻是字母，a) 够不到）。
# 例外的例外（**必须保留**）：关键词处于键名/赋值位置（后面跳过引号空白紧跟 `:` 或 `=`）
# 时一律不动 —— 这是「赋值的仍算」的落地，也保住 DSN 形态 `…?password=`。
#
# 实测（三库真实 (值,上下文) 回放，见 test-result/fix16/）：
#   语境闸门 T->F 343 对；落桶 1203 消失 159 对；按 data_item 复算：57 项 / 49 值 /
#   158 次出现离开 1203，去向 丢弃 26、other 19、pii_noise 11、platform_access_token 1，
#   逐条人工判读**全部**是路径/URL 片段/chunk 名/图片名/日志 tag；
#   fix12 人工核定的 29 个在库真阳性误伤 0（误伤标尺见 c_ccp_before_after.out）。
#
# 被否决的更宽方案：「关键词所在的空白 token 含 `/` 就挖」会把真键名一起带走 ——
#   `…url:"/pages/x"… ,pwdType:"recordPsw"…` 里的 pwdType 与 URL 同处一个 minified token，
# 该方案比本判据多踢 71 个值，其中 `qrcode_19_noPowerError` 一类正是靠 pwdType 开闸的，
# 故只取 a) ∪ b)（见 test-result/fix16/b_ccp_flip_R6.out 与 R8 的差集）。
RE_CLOUD_PWD_WORD_ROOT = re.compile(r"password|passwd|pwd", re.I)
# 键名/赋值尾巴：`password:` / `password =` / `password="`。`=` 还要排掉 `==` `===` `=>`。
RE_CTX_KEY_OR_ASSIGN_TAIL = re.compile(r"[\"'\t ]*[:=]")


def _is_key_or_assign_tail(stmt: str, end: int) -> bool:
    """关键词之后（跳过引号/空白）紧跟 `:` 或 `=` —— 键名/赋值位置，不参与挖掘。"""
    m = RE_CTX_KEY_OR_ASSIGN_TAIL.match(stmt, end)
    if not m:
        return False
    if stmt[m.end() - 1] == ":":
        return True
    return stmt[m.end():m.end() + 1] not in ("=", ">")     # == / === / => 是比较与箭头


def _inside_quoted_path(stmt: str, pos: int) -> bool:
    """pos 是否落在「含 `/` 的引号串」内。

    朴素配对：左侧同种引号数为奇即认为在串内（窗口可能从串中间开始，此时偏保守：
    数不出来就不挖，不会误挖）。串内没有 `/` 则不算路径。
    """
    for q in ('"', "'"):
        if stmt.count(q, 0, pos) % 2:
            close = stmt.find(q, pos)
            return close > 0 and "/" in stmt[stmt.rfind(q, 0, pos) + 1:close]
    return False


# ⚠️ 本函数**故意定义在 has_user_id_context / has_cloud_password_context 之前**：
# test-result/validate_uid_pwd_region.py 用「源码擦除」构造修复前模块，擦除范围正好覆盖
# 那两个 wrapper；把它放进那个范围会连这条判据一起擦掉，而该脚本的口径是「没被 REVERTS
# 关掉的改动对 before/after 两侧一视同仁」。
def strip_path_password_context(stmt: str) -> str:
    """把路径/路由里的 password 词挖成等长空白（保持偏移），其余位置逐位不动。

    只挖 CLOUD_PASSWORD_CONTEXT_WORDS 的词根出现（这些词**全部**含 password/passwd/pwd
    之一），且仅在「被 `/` 夹住」或「落在含 `/` 的引号串里」时挖；键名/赋值位置不挖。
    空语句 / 无命中都是原样返回（调用方拿到的一定是 str）。
    """
    if not stmt:
        return stmt
    out = None
    for m in RE_CLOUD_PWD_WORD_ROOT.finditer(stmt):
        start, end = m.start(), m.end()
        if _is_key_or_assign_tail(stmt, end):
            continue
        prev_slash = start > 0 and stmt[start - 1] == "/"
        next_slash = end < len(stmt) and stmt[end] == "/"
        if not (prev_slash or next_slash or _inside_quoted_path(stmt, start)):
            continue
        if out is None:
            out = list(stmt)
        for i in range(start, end):
            out[i] = " "
    return stmt if out is None else "".join(out)


CLOUD_PASSWORD_PLACEHOLDERS = (
    "xxx", "***", "password", "123456", "admin", "root", "test",
    "null", "none", "empty", "undefined", "default",
)

SERVER_COOKIE_CONTEXT_WORDS = (
    "cookie", "cookies", "set-cookie", "setcookie", "set_cookie",
    "sessionid", "session_id", "jsessionid", "phpsessid", "asp.net_sessionid",
)

# 常见的 cookie **名**（不是 cookie 值）。原先写在 is_server_cookie 体内，fix15 ③ 的
# 「名 + 空值」判据（_is_cookie_name_without_value）与单测也要用同一份清单，故提到模块级。
SERVER_COOKIE_NAME_KEYWORDS = (
    "sessionid", "jsessionid", "phpsessid", "cookie2", "usercookie",
    "localstorage", "sessionstorage", "visitkey", "globalmemory",
    "shshshfp", "referer", "msgreaded", "logedout", "removelogincache",
)

AK_PREFIX_PATTERNS = {
    "LTAI": "aliyun", "AKID": "tencent",
    "AKIA": "aws", "ABIA": "aws", "ACCA": "aws", "ASIA": "aws",
}

AK_CONTEXT_WORDS = (
    "accesskeyid", "access_key_id", "ossaccesskeyid",
    "secretid", "secret_id", "akid", "accesskey", "access_key",
)

SK_CONTEXT_WORDS = (
    "accesskeysecret", "access_key_secret",
    "secretaccesskey", "secret_access_key",
    "ossaccesskeysecret", "secretkey",
)

ELLIPTIC_CURVE_KEYWORDS = (
    "p521", "p384", "p256", "p224", "p192",
    "curve", "ed25519", "secp256k1",
    "gred", "prime:", "type:", "basis:", "lambda:", "beta:",
)

# =========================================================
# process_Regex_crypto_key 的**语境证据**（fix17）
# =========================================================
# 病根：这条路径原先只有两个**排除**分支（椭圆曲线预计算点表、曲线关键词）+ 一个私钥
# 关键词分支，**没有「要语境」的闸门**：
#     if 私钥语境: -> crypto_private_key(2102, risk5)
#     else:        -> crypto_public_key(2103, risk2)      ← 无任何证据也判
# 三库回放（test-result/fix17/，口径：值×source_snippet，出现次数=SUM(ref_count+1)）：
# 该路径接住 1,379 值 / 40,738 次，其中 48/64 位 hex 有 44,923 条 pair 的语句里
# **一个 public/private 类词都没有**（v2 库：476 值里 393 个、2,084 次里 1,763 次），
# 典型值是曲线常量（SM2 n/Gx/Gy/b、secp256k1 Gx/Gy、ed25519 基点 y、P-192/P-256 的
# p/n/b）与 `s = new r("FFFFFFFE…", 16)` / `g: [...]` 这类**语句就是值本身**的赋值。
#
# 形态分档的依据：`04`+128 位是**未压缩点编码**（ECDSA/SM2 公钥的合法前缀形态），
# 三库 152 个该形态的值里 46 个的语句没有任何关键词，但逐个看过都是真公钥
# （`export.PUBLICKEY=…` / `certPublicKey:…` / `M?"04659827…":"04727940…"` 开发/生产
# 双密钥选择）；48/64 位 hex 则只是 24/32 字节，曲线常量、摘要、AES salt、随机数都同形，
# 三库 48 位那 14 个值里真公钥 0 个。所以：**强形态照旧，弱形态要证据**。
RE_UNCOMPRESSED_PUBKEY = re.compile(r"^04[0-9a-f]{128}$", re.I)

# 证据词分两档：3 字母的 pub/priv 走「独立词或驼峰段」匹配（裸子串会命中
# publish*/publication/isPublished/ecpubhex/privilege*/deprive，把曲线常量重新放回来——
# 三库实测 SM2 n 靠字符串表里的 "ecpubhex"、P-256 n 靠 ASN.1 名字表里的
# "subjectPublicKeyRSA_hN" 各开一次闸，合计 544 次出现）；复合词与长词无歧义，保持子串语义
# （pubkey/privkey 尤其不能丢：`pubKey:` 已是段匹配，但全小写 `pubkey=` 只有这条能认）。
CRYPTO_PUBLIC_KEY_EVIDENCE_WORDS = ("public", "pubkey", "publickey")
CRYPTO_PRIVATE_KEY_EVIDENCE_WORDS = (
    "private", "privatekey", "privkey", "secret", "secretkey",
)

RSA_PUBLIC_KEY_CONTEXT_WORDS = (
    "setpublic", "setpublickey", "set_public", "set_public_key",
    "publickey", "public_key", "rsapublic", "rsa_public",
    "modulus", "exponent", "rsa",
)

HEX_TOKEN_CONTEXT_WORDS = (
    "token", "auth", "authorization", "bearer",
    "apikey", "api_key", "appkey", "app_key",
    "accesstoken", "access_token", "secretkey", "secret_key",
)

HEX_SESSION_CONTEXT_WORDS = (
    "session", "sessionid", "session_id", "sid", "credential",
)
# "sid" 是上面元组里唯一的 3 字母短词，且元组一律走 has_keyword_substring（纯子串），
# 于是 canvasId / goodsId / transid / bxksid / cateRecommendWindowsId / serviceId 里的
# "sid" 会把一批**数据库文档 ID** 拽进 server_cred_session_key(1603)。三库实测：
# 仅靠裸 "sid" 子串（去掉 sid 后其余词全不命中）进来的有 37 值 / 147 次，
# 逐条看过——全是 xxxId 形态，只有 `sid: "…"` 两个键名是真 sid。
# 因此只把 sid 摘出来走 has_keyword_in_context_strict（独立词/驼峰段边界），
# 其余长词保持子串语义不变。
HEX_SESSION_CONTEXT_WORDS_SUBSTR = tuple(
    k for k in HEX_SESSION_CONTEXT_WORDS if k != "sid")

VALID_HEX_TOKEN_LENGTHS = (24, 32, 40, 64)

PAYMENT_PARAM_NAMES = {
    "timestamp": IDT.PAYMENT_REQUEST_PARAMS,
    "timeStamp": IDT.PAYMENT_REQUEST_PARAMS,
    "time_stamp": IDT.PAYMENT_REQUEST_PARAMS,
    "noncestr": IDT.PAYMENT_NONCE,
    "nonceStr": IDT.PAYMENT_NONCE,
    "nonce_str": IDT.PAYMENT_NONCE,
    "paysign": IDT.PAYMENT_PAY_SIGN,
    "paySign": IDT.PAYMENT_PAY_SIGN,
    "pay_sign": IDT.PAYMENT_PAY_SIGN,
    "signtype": IDT.PAYMENT_SIGN_TYPE,
    "signType": IDT.PAYMENT_SIGN_TYPE,
    "sign_type": IDT.PAYMENT_SIGN_TYPE,
}

# 值侧查表：上面的 12 个写法按小写合并成 8 个 key（timeStamp/timestamp -> 同一个 slug，
# 因此小写化不会产生冲突）。is_payment_param 用它做「值 == 参数名」判定，
# 并让每次调用从「12 次子串扫描」变成「1 次 dict 查表」。
PAYMENT_PARAM_NAME_TO_SLUG = {name.lower(): slug for name, slug in PAYMENT_PARAM_NAMES.items()}

PAYMENT_SECRET_KEYWORDS = (
    "mchkey", "mch_key", "merchantkey", "merchant_key",
    "mchsecret", "mch_secret", "merchantsecret", "merchant_secret",
    "paykey", "pay_key", "paysecret", "pay_secret",
    "wxpaykey", "wxpay_key", "alipaykey", "alipay_key",
    "signkey", "sign_key", "apisecret", "api_secret",
    "partnerkey", "partner_key",
)

PAYMENT_PACKAGE_PREFIX = "prepay_id="

DEVICE_ID_KEYWORDS = {
    "idfa", "idfv", "imei", "imsi", "meid",
    "androidid", "android_id", "deviceid", "device_id",
    "macaddress", "mac_address", "oaid", "udid",
}

AD_ID_KEYWORDS = {
    "adid", "ad_id", "advertisingid", "advertising_id",
    "trackingid", "tracking_id", "gaid",
}

USER_ID_KEYWORDS = {
    "uid", "userid", "user_id", "memberid", "member_id",
    "openid", "unionid", "accountid", "account_id",
    "tenantid", "tenant_id",
    "orgid", "org_id",
    "companyid", "company_id",
}


def has_user_id_context(stmt: str, value: str) -> bool:
    """USER_ID_KEYWORDS 的上下文判定：uid 收紧为「独立词/驼峰段」，其余关键词不变。

    uid 走 has_keyword_in_context_strict —— 裸子串会让 uuid / guid / skuId / menuId
    等一并命中 id_user_identifier；userid / openid / account_id 等长关键词仍走原函数。

    value 参与剥值（见 external_context）：值自身的出现不再能单独把语境闸门打开。
    `value` **无默认值**是刻意的 —— 漏改一个调用点就 TypeError，而不是静默退回旧行为。
    """
    context = external_context(stmt, value)
    return (has_keyword_in_context_strict(context, "uid", UID_LOOKALIKE_SUBSTRINGS)
            or has_keyword_in_context(context, USER_ID_KEYWORDS - {"uid"}))


def has_cloud_password_context(stmt: str, value: str) -> bool:
    """CLOUD_PASSWORD_CONTEXT_WORDS 的上下文判定：pwd 收紧为「独立词/驼峰段」，其余不变。

    pwd 走 has_keyword_in_context_strict —— 裸子串会让 has_paypwd / dmPwD /
    base64 随机载荷中的 "pwd" 命中；password / passwd / db_pwd 等仍走原函数。

    value 参与剥值（见 external_context）：值自身含 password/pwd 时不再能单独定罪，
    值形一侧由 is_segmented_identifier_name 承担（fix12）。`value` 无默认值，理由同上。

    另经 strip_path_password_context 挖掉路径/路由里的 password（fix16 ①）：页面路径、
    URL 片段里的 password 段不是密码语境，赋值与键名位置不受影响。
    """
    context = strip_path_password_context(external_context(stmt, value))
    return (has_keyword_in_context_strict(context, "pwd")
            or has_keyword_in_context(context, CLOUD_PASSWORD_CONTEXT_WORDS - {"pwd"}))

ORDER_ID_KEYWORDS = {
    "orderid", "order_id", "orderno", "order_no",
    "transactionid", "transaction_id", "tradeno", "trade_no",
}

VALID_DEVICE_ID_LENGTHS = {12, 15, 16, 32, 36}

IV_CONTEXT_KEYWORDS = {"iv", "nonce", "vector", "sm4iv", "sm4_iv"}
# 除 `iv` 以外的关键词仍是朴素小写子串匹配（nonce / vector / sm4_iv / sm4iv 都是
# 长词，且 sm4iv / sm4_iv 还要兜住 SM4IV 这种全大写写法）。`iv` 单独走 RE_IV_CONTEXT。
IV_CONTEXT_SUBSTR_KEYWORDS = tuple(sorted(IV_CONTEXT_KEYWORDS - {"iv"}))
AES_KEY_CONTEXT_KEYWORDS = {
    "aeskey", "aes_key", "encryptkey", "encrypt_key",
    "deskey", "des_key", "sm4key", "sm4_key",
}

IV_HEX_LENGTHS = (16, 24, 32)
IV_BASE64_LENGTHS = (12, 16, 22, 24)
IV_STR_LENGTHS = (8, 12, 16)

# ---------------------------------------------------------
# 硬编码 IV / AES KEY 的值形态守卫（标识符不是密钥）
# ---------------------------------------------------------
# IV 的 base64/字符串两条路径原先只看「长度 + 字符集」，长度 12/16 与字符集
# A-Za-z0-9+/=-_ 太宽，于是「标识符形态」的值（CSS 类名 / 变量名 / 常量名）
# 全部漏进 crypto_static_iv：
#   test-passive / custom-class / tab-active-class       → CSS 类名（kebab）
#   _customer_latitude_cache / class_detail / pay_share_id → snake_case
#   DISCOUNT / THEME_CLASS_NAME / BEFORE_THE_TITLE       → SCREAMING_SNAKE
#   noMobileFallback / setEnable1v1Chat                  → 驼峰标识符
#   des-ede3-cbc                                         → 算法名（外形也是 kebab 词串）
# 唯一能通过原检查的身份护栏是 `s.islower() and s.isalpha()`，它挡不住混合大小写、
# 驼峰、以及含 -/_ 的标识符。is_static_aes_key 同样只按「长度 + isalnum」放行，
# 于是 aesKey 上下文里的变量名（noMobileFallback / setEnable1v1Chat /
# MobileVerifyType）也被判成 crypto_static_iv，所以它也复用这里的词形判据。
#
# 逐条排除的「词」特征，代价在 test-result/iv-fix/ 用 3 个真库语料 + 模拟真实 IV 量化：
#   1) 纯数字 / 全大写 / SCREAMING_SNAKE —— 随机字节串的概率 < 1e-3
#   2) 含 -/_ 且切段后「像词的字符过半」—— kebab / snake / BEM（见 is_iv_word_token）
#   3) 驼峰 / 帕斯卡单词串 —— 每段是「大写 + ≥2 个小写」的真单词（见下方说明）
RE_IV_WORD_TOKEN = re.compile(r"^[-_A-Za-z0-9]+$")
RE_IV_SCREAMING = re.compile(r"^[A-Z0-9]+(?:_[A-Z0-9]+)*$")
RE_IV_CAMEL_WORDS = re.compile(r"^[a-z0-9]+(?:[A-Z][a-z]{2,}[a-z0-9]*)+$")
RE_IV_PASCAL_WORDS = re.compile(r"^[A-Z][a-z]{2,}[a-z0-9]*(?:[A-Z][a-z]{2,}[a-z0-9]*)+$")

# 判据 2 的词段特征：把 -/_ 当词边界切段，再问「多少字符落在像词的段里」。
#   [a-z]{2,}[0-9]*    小写单词（可带尾随数字）: passive / customer / latitude / sf2 / kuaidi100
#   [A-Z][a-z]{2,}[0-9]*  首字母大写的单词:      Letter / Uppercase / FluidR3
#   [A-Z]{2,}[0-9]*    全大写缩写:               GM / API / ID
#   is_word_shaped_identifier 驼峰/帕斯卡词串:   ClassDetail / footerBtn / baseUrlLocal
RE_IV_WORD_SEG_LOWER = re.compile(r"[a-z]{2,}[0-9]*")
RE_IV_WORD_SEG_CAP = re.compile(r"[A-Z][a-z]{2,}[0-9]*")
RE_IV_WORD_SEG_ABBR = re.compile(r"[A-Z]{2,}[0-9]*")

IV_VALUE_BLACKLIST = (
    "enterkeyhint", "controlslist", "autocomplete", "hreflang", "datetime",
    "contenteditable", "spellcheck", "draggable", "inputmode", "tabindex",
    "collected", "activity", "status", "signup", "avatar", "native",
    "relative", "sensitive", "positive", "negative", "primitive",
    "interactive", "alternative", "representative", "administrative",
)

CRYPTO_ALGORITHM_NAMES = (
    "md5", "sha1", "sha256", "sha384", "sha512",
    "sha-1", "sha-256", "sha-384", "sha-512",
    "aes", "aes128", "aes256", "aes-128", "aes-256",
    "aes-cbc", "aes-gcm", "aes-ecb",
    "des", "3des", "des3", "triple-des",
    "rsa", "rsa1024", "rsa2048", "rsa4096",
    "rsa-1024", "rsa-2048", "rsa-4096",
    "ecdsa", "ed25519", "ecdh", "sm2", "sm3", "sm4",
    "hmac", "hmac-sha256", "hmac-sha1", "hmac-md5",
)

WEAK_CRYPTO_ALGORITHMS = ("md5", "sha1", "sha-1", "des", "rc4", "md4", "md2")

SENSITIVE_CRYPTO_CONTEXT = (
    "password", "passwd", "pwd", "secret", "token", "key",
    "sign", "signature", "verify", "encrypt", "decrypt",
    "hash", "digest", "auth", "credential",
)

CIPHERTEXT_PREFIX = "U2FsdGVk"

APP_KEY_CONTEXT_WORDS = {
    "appkey", "app_key", "appKey",
    "apikey", "api_key", "apiKey",
    "accesskey", "access_key", "accessKey",
}

# is_app_key 的语境词把两种语义混在一起，过去一律判成 platform_app_secret(1101)：
#   ① 公开 AppKey/ApiKey —— SDK 的客户端标识：友盟(umaAppKey/umengAppKey/UM_APP_KEY/
#      ymAppKey)、TalkingData(talkingDataAppKey)、腾讯广告(VUE_APP_TENCENT_AD_APP_KEY)、
#      七鱼(_$configAppKey)、IM/地图/推送 SDK 的 appKey。和 appid 一样随包发布、
#      必须内置在客户端，本身不是机密 —— 改判 saas_analytics_key(1402)。
#   ② 凭证 —— 云厂商/开放平台的 AccessKey(Id/Secret) 与 AppSecret/ApiSecret/api_secret，
#      是凭证对的一半，必须留在 1101。
# 三库真实语料（unlist_icp_filing_v3 / unlist_package_reference_v2 /
# unlist_normal_sibling_v2 的 platform_app_secret 桶，is_app_key 命中 898 个值）里 ②
# 的语境词全部落在下面三个上，其余槽位（appkey/app_key/ymappkey/umaappkey/apikey/…）
# 都是 ①。
PUBLIC_APP_KEY_CONTEXT_WORDS = ("appkey", "app_key", "apikey", "api_key")
CREDENTIAL_APP_KEY_CONTEXT_WORDS = ("accesskey", "access_key", "secret")

APP_SECRET_CONTEXT_WORDS = {
    "secret", "appsecret", "app_secret", "appSecret",
    "clientsecret", "client_secret", "clientSecret",
    "secretkey", "secret_key", "secretKey",
    "memberappid", "memberappsecret", "member_app_id", "member_app_secret",
    "invoiceappid", "invoiceappsecret", "invoice_app_id", "invoice_app_secret",
    "ticketappid", "ticketappsecret", "ticket_app_id", "ticket_app_secret",
    "v2appid", "v2appsecret", "v2_app_id", "v2_app_secret",
    "signappid", "sign_app_id",
    "wxcontactkey", "wx_contact_key", "alipayappid", "alipay_app_id",
}

# 会话密钥的语境词。24 字符 base64(16B) 这个形态本身没有区分度（三库 2632 行
# platform_session_key 里 89.8% 的上下文是 LogPid / alipayPid 这类日志流水号），
# 必须靠语境收敛。这里只放有实测支撑的两个词：
#   session_key:"DqoBcsyp60OUVOSydoE37Q==" / sessionKey: "n2a6ZXGM8toABFypcQjEow=="
#     / e.session_key = "SNzPSsB9wKBGzrftrjK13g=="
# 三个库全部 8 行「上下文含 session」的记录都被这两个词覆盖（sessionKey 经 stmt.lower()
# 后含 sessionkey）。
# 刻意不加 code2session / checkSession / encryptedData：旧判据没有语境要求，
# 所有 24 字符 base64 形态的值都已经被判成 session_key（三库 2632 行即是全部），
# 所以不存在「该判而没判」的漏报，加宽语境只会把更多噪音留在 risk 5 类型里；
# 而 encryptedData 语句里那个 24 字符 base64 是密文/16 字节 IV，不是密钥本身。
SESSION_KEY_CONTEXT_WORDS = (
    "session_key", "sessionkey",
)

BUCKET_VALUE_BLACKLIST = (
    "bucket", "token", "secret", "key", "name", "list",
    "conf", "config", "param", "setting", "option",
    "md5", "sha", "hash", "sign", "encrypt",
    "time", "date", "hour", "minute", "second",
    "url", "http", "path", "dir", "folder", "route",
    "container", "prog", "app", "service", "handler",
    "video", "image", "photo", "file", "media", "audio",
    "watermark", "thumb", "resize", "crop",
    "miniprogram", "wechat", "weixin", "alipay",
)

CODE_NAMING_PREFIXES = ("on", "get", "set", "is", "has", "can", "do", "will", "did")

URL_SENSITIVE_KEYWORDS = {
    "webhook/send": IDT.WEBHOOK_URL,
    "cgi-bin/webhook": IDT.WEBHOOK_URL,
    "robot/send": IDT.WEBHOOK_URL,
    "bot/v2/hook": IDT.WEBHOOK_URL,
    "bot/hook": IDT.WEBHOOK_URL,
    "login": IDT.SERVER_URL_AUTH,
    "signin": IDT.SERVER_URL_AUTH,
    "auth": IDT.SERVER_URL_AUTH,
    "oauth": IDT.SERVER_URL_AUTH,
    "pay": IDT.SERVER_URL_PAYMENT,
    "payment": IDT.SERVER_URL_PAYMENT,
    "admin": IDT.SERVER_URL_INTERNAL,
    "internal": IDT.SERVER_URL_INTERNAL,
    "debug": IDT.SERVER_URL_INTERNAL,
}

SENSITIVE_PAGE_KEYWORDS = ("admin", "test", "debug", "config", "internal", "manage")

CONTEXT_KEYWORDS = {
    "appsecret": IDT.PLATFORM_APP_SECRET,
    "app_secret": IDT.PLATFORM_APP_SECRET,
    "session_key": IDT.PLATFORM_SESSION_KEY,
    "sessionkey": IDT.PLATFORM_SESSION_KEY,
    "access_token": IDT.PLATFORM_ACCESS_TOKEN,
    "accesstoken": IDT.PLATFORM_ACCESS_TOKEN,
    "secret_key": IDT.CLOUD_CRED_AK_SK_PAIR,
    "secretkey": IDT.CLOUD_CRED_AK_SK_PAIR,
    "password": IDT.SERVER_CRED_PASSWORD,
    "passwd": IDT.SERVER_CRED_PASSWORD,
    "cookie": IDT.SERVER_CRED_COOKIE,
    "paysign": IDT.PAYMENT_PAY_SIGN,
    "noncestr": IDT.PAYMENT_NONCE,
    "timestamp": IDT.PAYMENT_REQUEST_PARAMS,
    "secretid": IDT.CLOUD_CRED_AK_SK_PAIR,
    "bucket": IDT.CLOUD_BUCKET_NAME,
    "region": IDT.CLOUD_REGION,
}
CONTEXT_KEYWORDS_2 = {
    "appsecret": IDT.PLATFORM_APP_SECRET,
    "app_secret": IDT.PLATFORM_APP_SECRET,
    "access_token": IDT.PLATFORM_ACCESS_TOKEN,
    "accesstoken": IDT.PLATFORM_ACCESS_TOKEN,
    "cookie": IDT.SERVER_CRED_COOKIE,
}
STATIC_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js", ".mp3", ".mp4", ".pdf")

MINIAPP_API_PATH_PATTERNS = ("/api/", "/v1/", "/v2/", "/v3/", "api/")

# 组件引用路径：值形如 /components/loading、/component/Common/store-list/index、
# /wxcomponents/vant/button/index，出现在页面/组件的 usingComponents 声明里
# （"van-button":"/wxcomponents/vant/button/index"），少数出现在 require(...) 里，
# 两者都是前端组件引用，不是后端端点。原先第 6 步只挡 /components/，其余拼写一路
# 掉进「后端 API 路径」兜底。
#
# 选「首段是已知组件目录名」的有限枚举，而不是模式匹配，理由（实测三库首段）：
#   - components 类首段是超长尾：components_new / components-async / components-common /
#     commoncomponents / comps / compoment / comonents4vant / ui-components … 上百种，
#     枚举要漏一大片，但任何模式都比枚举更松。
#   - 模式（如 ^/[a-z_-]*components? 或含 comp 的首段）会顺带吞掉同前缀的非组件目录：
#     /company(426)、/complaint(61)、/competition(44)、/compilation(40)、/composition(39)
#     都是 comp 开头但不是组件库（三库 usingComponents 证据率均为 0%），
#     它们更像接口前缀，判错方向正好是要避免的误伤。
#   - 枚举的每个成员都用上下文核实过（该前缀的全部值，三库合并 / usingComponents 证据率）：
#       /components/        42,379 值  96.0%~97.3%
#       /component/          3,043 值  95.1%~96.1%
#       /wxcomponents/         958 值  93.9%~97.5%
#       /vant/                 197 值  98.5%~100%
#       /components-common/    100 值  86.8%~93.6%
#       /commpents/             62 值  92.9%~100%（语料里真实存在的拼写错误）
#     枚举之外还剩一批同样高证据的小前缀没有收（三库合计：comps 62 值 94%~100%、
#     compts 36 值 100%、compoment 38 值 100%、components-light 33 值 100%……），
#     它们和 /company(0%)、/complaint(0%)、/competition(0%) 混在同一个 comp 前缀下，
#     本轮不扩大枚举范围，留作后续按同一取证口径逐个补。
#   - 本轮把第 6 步的 /components/ 与第 6b 步的组件库前缀合并成同一个判定，并新增
#     /component/：两族的上下文分布几乎重合（require/import 占比都在 0.1%~1.8%），
#     分裂成两个类型没有依据，详见 process_generic_slash_prefixed_constant 的注释。
MINIAPP_COMPONENT_PREFIXES = (
    "/components/", "/component/", "/wxcomponents/", "/vant/",
    "/components-common/", "/commpents/",
)

# 项目自建页面根目录 /page/（不是微信约定的 /pages/），只在「带查询参数」的入口认它。
# /page/xxx?yyy= 是带参页面路由：实测三库 896 个带参值里 67.2% 上下文是 navigateTo/url
# 字段；按「请求构造 + REST 动词第二段 + 大写首段」三种可疑形态过一遍只剩 5 个（0.6%），
# 逐条看仍是 /page/others/auth/auth?from=rescue 这类页面，首段写成大写 /Page/ 的为 0。
# 而 /page/xxx 不带参数时混着 20.1% 的组件引用（/page/ai_chat/components/AiAttachSheet）、
# 3.7% 的 require() 模块引用和 1.9% 的接口（/Page/getAdlistByType 一族），
# 整族归页面会误伤，所以不放宽到无参路径。
# 故意不加 re.I：语料里 /Page/…（首字母大写）这一族是 PHP 风格控制器
# （/Page/getAdlistByType、/Page/getIndexRecommedList），值是接口不是页面。
RE_MINIAPP_PAGE_DIR_ROUTE = re.compile(r"^/page/")

# 小程序内部「静态资源路径」判定用的后缀 = 原 MINIAPP_ASSET_EXTENSIONS ∪ STATIC_EXTENSIONS，
# 去掉 .js/.json 这类模块后缀（第 2 步已按 MINIAPP_PATH_MODULE 判过，不能在这里抢；
# 复用 STATIC_EXTENSIONS 是为了补上原先只对绝对 URL 生效的 .pdf，还顺带补了 .css）。
MINIAPP_PATH_ASSET_EXTENSIONS = MINIAPP_ASSET_EXTENSIONS + tuple(
    ext for ext in STATIC_EXTENSIONS
    if ext not in MINIAPP_ASSET_EXTENSIONS and ext not in MINIAPP_MODULE_EXTENSIONS
)

# 小程序 AppID 正则模式
MINIAPP_APPID_PATTERN = re.compile(r'^wx[a-f0-9]{15,18}$')  # 微信小程序
MINIAPP_WW_APPID_PATTERN = re.compile(r'^ww[a-f0-9]{15,18}$')  # 企业微信
MINIAPP_GH_ID_PATTERN = re.compile(r'^gh_[a-f0-9]{11,16}$')  # 公众号
# fmt: on



# =========================================================
# Token 处理函数
# =========================================================
def process_prefixed_token(token_type: str, s: str, stmt: str, src: str, sid: int, res: list):
    """分类 Token (JWT/Bearer/Basic)"""
    if token_type == IDT.TOKEN_JWT and s.count(".") == 2:
        append_result(res, IDT.PLATFORM_ACCESS_TOKEN, s, src, sid)
    elif token_type == IDT.TOKEN_BEARER:
        append_result(res, IDT.SERVER_CRED_TOKEN, s, src, sid)
    elif token_type == IDT.TOKEN_BASIC:
        append_result(res, IDT.CLOUD_CRED_BASIC_AUTH, s, src, sid)
    else:
        append_result(res, IDT.SERVER_CRED_TOKEN, s, src, sid)


# =========================================================
# 加密密钥处理函数
# =========================================================
def process_prefixed_crypto_key(slug: str, s: str, stmt: str, src: str, sid: int, res: list):
    """分类 PEM 格式密钥"""
    append_result(res, slug, s, src, sid)


def is_rsa_hex_public_key(s: str, stmt: str, raw_stmt: str = None) -> bool:
    """检测是否为 RSA 十六进制格式公钥"""
    if len(s) < 256 or not is_hex_string(s):
        return False
    check_stmt = raw_stmt if raw_stmt else stmt
    return has_keyword_substring(check_stmt, RSA_PUBLIC_KEY_CONTEXT_WORDS)


def is_base64_public_key(s: str) -> bool:
    """
    检测是否为 Base64 编码的公钥 (DER 格式)

    特征:
    - 以 MIGf/MIIBIj/MHQ/MHY 等开头
    - 长度 >= 100 (RSA-1024 公钥约 216 字符)
    - 是有效的 Base64 字符

    示例:
    - MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ... (RSA-1024)
    - MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCg... (RSA-2048)
    """
    if len(s) < 100:
        return False
    # 检查前缀
    if not any(s.startswith(prefix) for prefix in BASE64_PUBLIC_KEY_PREFIXES):
        return False
    # 检查是否为有效 Base64 字符
    return is_base64_chars(s)


def is_base64_private_key(s: str) -> bool:
    """
    检测是否为 Base64 编码的私钥 (DER 格式)

    特征:
    - 以 MIICd/MIICe/MIIE 等开头
    - 长度 >= 200 (私钥通常很长，但可能被截断)
    - 是有效的 Base64 字符

    示例:
    - MIICdgIBADANBgkqhkiG9w0BAQEFAAOCAQ... (RSA-1024 PKCS#8)
    - MIIEvgIBADANBgkqhkiG9w0BAQEFAAOCAQ... (RSA-2048 PKCS#8)
    """
    if len(s) < 200:
        return False
    # 检查前缀
    if not any(s.startswith(prefix) for prefix in BASE64_PRIVATE_KEY_PREFIXES):
        return False
    # 检查是否为有效 Base64 字符
    return is_base64_chars(s)


def process_base64_public_key(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 Base64 编码的公钥"""
    append_result(res, IDT.CRYPTO_PUBLIC_KEY, s, src, sid)


def process_base64_private_key(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 Base64 编码的私钥"""
    append_result(res, IDT.CRYPTO_PRIVATE_KEY, s, src, sid)


def process_rsa_hex_public_key(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 RSA 十六进制公钥"""
    append_result(res, IDT.CRYPTO_PUBLIC_KEY, s, src, sid)


def crypto_key_evidence(stmt: str) -> Tuple[bool, bool]:
    """返回本路径的语境证据 (is_private, is_public)。

    pub / priv 这两个 3 字母词只走「独立词或驼峰段」匹配（has_keyword_in_context_strict）；
    复合词与长词保持子串语义，与改动前逐位一致。理由与三库实测见上面
    CRYPTO_PUBLIC_KEY_EVIDENCE_WORDS 那段注释。
    """
    stmt_lower = stmt.lower()
    is_private = (has_keyword_substring(stmt_lower, CRYPTO_PRIVATE_KEY_EVIDENCE_WORDS)
                  or has_keyword_in_context_strict(stmt, "priv"))
    is_public = (has_keyword_substring(stmt_lower, CRYPTO_PUBLIC_KEY_EVIDENCE_WORDS)
                 or has_keyword_in_context_strict(stmt, "pub"))
    return is_private, is_public


def process_Regex_crypto_key(s: str, stmt: str, src: str, sid: int, res: list, raw_stmt: str = None):
    """处理通过正则匹配到的加密密钥（SM2公钥等）。

    出三条出口：
        私钥语境（且无公钥语境） -> crypto_private_key(2102)
        公钥语境                -> crypto_public_key(2103)
        `04`+128 位未压缩点形态 -> crypto_public_key(2103)（形态本身即强证据）
    其余（48/64 位 hex 且无语境）**不出口**，回落到通用分流 —— 与 process_hex_token
    去掉兜底后的口径一致（见 fix15 ①）。48/64 位 hex 只是 24/32 字节，曲线常量、摘要、
    salt、随机数全是这个形态，三库实测这批里真公钥 0 个（依据见 RE_UNCOMPRESSED_PUBKEY
    上方的注释）。
    """
    check_stmt = raw_stmt if raw_stmt else stmt
    ctx_lower = check_stmt.lower()

    # 排除椭圆曲线预计算点表
    if "point" in ctx_lower or "points" in ctx_lower or ("doubles" in ctx_lower and "naf" in ctx_lower):
        return
    if has_keyword_substring(ctx_lower, ELLIPTIC_CURVE_KEYWORDS):
        return
    if not has_min_unique_chars(s.upper(), 6):
        return

    # 上下文关键字判断是公钥还是私钥
    is_private, is_public = crypto_key_evidence(check_stmt)
    if not (is_private or is_public) and not RE_UNCOMPRESSED_PUBKEY.match(s):
        return

    slug = IDT.CRYPTO_PRIVATE_KEY if is_private and not is_public else IDT.CRYPTO_PUBLIC_KEY
    append_result(res, slug, s, src, sid)


# =========================================================
# URL 处理函数
# =========================================================
# W3C / XML 命名空间标识符（xmlns / setAttributeNS 里的值）是 XML 规范定义的协议常量，
# 不是接口端点。三库实测 16 个去重值 / 11174 行，引用次数畸高
# （"http://www.w3.org/2000/svg" 单个值 3696 行），会把 server_url_api_plain 里
# 按「出现次数」做的统计带偏。
# 归到 other：协议常量不是业务端点，但也不该被当成噪音丢掉 —— 它形态完好、
# 会被 biz 误当接口读，留在库里便于回溯。本次只改注释不动行为：is_framework_artifact
# 已改为「命中即丢弃」，两者口径从此不同（那边是编译产物、且量级上万；这边 16 个值）。
# 不放进 server_url_noise —— 后者在 process_prefixed_url 里的含义是「没有 host 的
# 退化 URL」，命名空间 URL 形态完好，混进去会模糊那个信号。
RE_W3C_NAMESPACE_URL = re.compile(r"^https?://www\.w3\.org(?:/|$)", re.I)


def is_w3c_namespace_url(url_full: str) -> bool:
    """是否为 W3C / XML 命名空间标识符（xmlns 的值）"""
    return bool(RE_W3C_NAMESPACE_URL.match(url_full.strip()))


def process_prefixed_url(url_full: str, stmt: str, src: str, sid: int, res: list):
    """分类 URL"""
    # W3C/XML 命名空间不是接口端点（见 is_w3c_namespace_url）
    if is_w3c_namespace_url(url_full):
        append_result(res, IDT.OTHER, url_full, src, sid)
        return

    url_body = url_full
    for prefix in URL_PREFIX_WORDS:
        if url_full.lower().startswith(prefix):
            url_body = url_full[len(prefix):]
            break

    if len(url_body) == 0 or not url_body[0].isalnum():
        return

    # 带凭证的 URL: user:pass@host 格式
    if "@" in url_body:
        at_idx = url_body.index("@")
        cred_part = url_body[:at_idx]
        rest_part = url_body[at_idx + 1:]

        # 排除 npm scope URL: /@babel/xxx, /@vant/xxx (cred_part 含 /)
        # 排除 Retina 图片: icon@2x.png, logo@3x.png
        # 排除路径中的邮箱片段: xxx.com/user@example.com/...
        is_npm_scope = "/" in cred_part
        is_retina = len(rest_part) >= 2 and rest_part[0].isdigit() and rest_part[1] == "x"

        if not is_npm_scope and not is_retina:
            url_body = rest_part
            append_result(res, IDT.SERVER_URL_WITH_CREDENTIALS, url_full, src, sid)
            if ":" in cred_part:
                append_result(res, IDT.SERVER_CRED_PASSWORD, url_full, src, sid)

    fs = url_body.split("/")
    if len(fs) < 1 or len(fs[0]) == 0:
        append_result(res, IDT.SERVER_URL_NOISE, url_full, src, sid)
        return

    server_name = fs[0].split(":")[0]
    ip_addr_tuple = ip_check_address(server_name)
    if ip_addr_tuple:
        # fix18 ②：回环/未指定地址（http://127.0.0.1:19952/Home/…）无基础设施信息量
        if is_loopback_or_unspecified(ip_addr_tuple):
            append_result(res, IDT.BACKEND_IP_NOISE, url_full, src, sid)
            return
        ip_type = ip_get_ip_type(ip_addr_tuple)
        slug = {
            "PRIVATE": IDT.BACKEND_IP_PRIVATE,
            "PUBLIC": IDT.BACKEND_IP_PUBLIC
        }.get(ip_type, IDT.BACKEND_IP_NOISE)
        append_result(res, slug, url_full, src, sid)
        return

    # 检查查询字符串
    if url_body.count("?") == 1:
        idx = url_body.find("?")
        query_str = url_body[idx + 1:]
        if url_is_query(query_str):
            process_url_query_string(query_str, stmt, src, sid, res)

    url_lower = url_body.lower()

    # 静态资源
    for ext in STATIC_EXTENSIONS:
        if url_lower.endswith(ext):
            append_result(res, IDT.SERVER_URL_STATIC, url_full, src, sid)
            return

    # 敏感路径关键字
    for keyword, slug_id in URL_SENSITIVE_KEYWORDS.items():
        if keyword in url_lower:
            append_result(res, slug_id, url_full, src, sid)
            return

    # 云存储域名
    cloud_domains = ("oss-", "cos.", "s3.", "cdn.", "aliyuncs.com", "myqcloud.com")
    if has_keyword_substring(url_lower, cloud_domains):
        append_result(res, IDT.CLOUD_STORAGE_PATH, url_full, src, sid)
        return

    append_result(res, IDT.SERVER_URL_API_PLAIN, url_full, src, sid)


def process_prefixed_cloud_url(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云存储 URL"""
    append_result(res, IDT.CLOUD_STORAGE_PATH, s, src, sid)


def process_standalone_ip(s: str, stmt: str, src: str, sid: int, res: list) -> bool:
    """分类独立 IP 地址，返回是否匹配"""
    ip_part = s.split(":")[0]
    ip_tuple = ip_check_address(ip_part)
    if not ip_tuple:
        return False
    # fix18 ①：形态是四段数字，但语境/弧位说明它不是 IP（证书 OID / 四段版本号）。
    # 返回 False = 未匹配，交回通用链由既有 _is_oid_format 兜底 → pii_noise(0)。
    if is_dotted_number_not_ip(ip_part, stmt):
        return False
    # fix18 ②：回环 127.0.0.0/8 与未指定地址 0.0.0.0 —— 是 IP 但没有信息量 → IP 噪声(0)。
    if is_loopback_or_unspecified(ip_tuple):
        append_result(res, IDT.BACKEND_IP_NOISE, s, src, sid)
        return True
    ip_type = ip_get_ip_type(ip_tuple)
    if ip_type == "PRIVATE":
        append_result(res, IDT.BACKEND_IP_PRIVATE, s, src, sid)
    elif ip_type == "PUBLIC":
        append_result(res, IDT.BACKEND_IP_PUBLIC, s, src, sid)
    return True


def process_data_uri(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 data URI"""
    append_result(res, IDT.ENCODING_BASE64, s, src, sid)


def process_url_encoded(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 URL 编码的 URL"""
    append_result(res, IDT.ENCODING_URL, s, src, sid)


def process_cloud_region(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云区域标识"""
    append_result(res, IDT.CLOUD_REGION, s, src, sid)


def url_is_query(s: str) -> bool:
    """检查是否为查询字符串"""
    return len(s) >= 3 and "=" in s


# =========================================================
# Bucket 名称检测
# =========================================================
def is_cloud_region_value(s: str) -> bool:
    """判断值是否形如云区域名 (cn-southwest / ap-shanghai / us-east-1 / cn-north)。

    条件与原 process_generic_alpha_prefixed_constant 里的区域判定完全一致，抽出来共用：
    COS 模板语句里 {{Region}} 与 {{Bucket}} 并存，而 is_bucket_name 在主链上先于区域
    判定运行，会把区域名吞成桶名（cn-southwest → cloud_bucket_name），所以桶判定必须
    显式给区域形态的值让路。

    原判据只有「前缀命中 + 长度 <30 + 不含 / 和 .」，而 cn-/ap-/us-/eu-/sa-/me-/af-/na-
    这 8 个前缀都是两个字母，正好和 CSS/BEM 类名前缀重合，于是 me-service / me-avatar /
    sa-image__img / na-big-pic / us-close / ap-page / cn-money / cn-big5 / us-ascii /
    na-xie-di-fang-zhi-de-qu 这一大批类名与字符编码名都被判成了云区域（三库 4369 行里
    约 3000 行）。现在要求第二段真的是地域名：
      - 方向词 north / south / east / west / central / …  → cn-southwest / us-east-1 /
        cn-south-2 / cn-northwest-1 / me-central-1
      - 已知地域节点名（各家对象存储的地域）           → ap-shanghai / cn-hangzhou /
        ap-chengdu / ap-guangzhou / ap-beijing / na-toronto / eu-moscow
      - 其后只允许「一段纯数字」后缀                   → cn-south-2 / ap-shanghai-1
    没有方向词/节点名兜底的（ap-page / cn-money / me-service / sa-hover-menu …）一律不当
    区域，交回主链按上下文判定。已用三库 cloud_region 语料逐值核过，见报告。
    """
    if not s or len(s) >= 30 or "/" in s or "." in s:
        return False
    s_lower = s.lower()
    for prefix in CLOUD_REGION_PREFIX_WORDS:
        if not s_lower.startswith(prefix):
            continue
        parts = s_lower[len(prefix):].split("-")
        if (parts[0] not in CLOUD_REGION_DIRECTION_WORDS
                and parts[0] not in CLOUD_REGION_PLACE_WORDS):
            return False
        return all(p.isdigit() for p in parts[1:])
    return False


def has_bucket_blacklist_word_in_head(s: str) -> bool:
    """BUCKET_VALUE_BLACKLIST 是否命中值的**首段**（第一个 `-` 之前）。

    原实现是 has_keyword_substring(s_lower, BUCKET_VALUE_BLACKLIST)，即「短词裸子串」：
    只要值里任意位置出现 video / key / name / time / url … 就整值否决，与 uid→Guide
    是同一类错（裸子串没有词边界）。但直接改成「词段匹配」在这里修不好目标值：
    `eqxiu-video` 按 `-` 切出来的第二段就是独立的 `video`，词段匹配照样命中。

    实测（三库中 source_snippet 含 bucket 语境词的全部记录 = 能走到这一步的完整集合，
    121 个去重值）：裸子串匹配总共只命中 1 个值 —— 而它是唯一的错杀：
      "videoBucket", o>0?"eqxiu-video":"eqxiu-test"
        → eqxiu-test 判 cloud_bucket_name，eqxiu-video 却被 "video" 否决，
          最后掉到 payment_pay_sign。
    改成「首段命中」后：
      - eqxiu-video（通用词在尾部 = 「品牌-用途」型桶名，正是 COS 桶名的常见形态）
        → 放行，与 eqxiu-test 一致
      - bucket-name / image-list / key-value / videoBucket 这类**以通用词开头**、
        看着像变量名的值 → 仍然否决
      - 值里没有 `-` 时首段就是整个值，行为与原实现完全一致（bucketname 仍否决）

    is_bucket_name 在此处已保证 s 是全小写且只含 [a-z0-9-]，所以首段就是 split("-")[0]。
    """
    return has_keyword_substring(s.split("-", 1)[0], BUCKET_VALUE_BLACKLIST)


def is_bucket_name(s: str, stmt: str) -> bool:
    """检测是否为云存储桶名称"""
    if not has_keyword_substring(stmt, BUCKET_CONTEXT_WORDS):
        return False

    s = s.strip()
    s_lower = s.lower()
    length = len(s)

    if not check_length_range(s, 6, 63) or s != s_lower:
        return False
    if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', s) or s.isdigit():
        return False

    # 语义黑名单（只看首段，见 has_bucket_blacklist_word_in_head）
    if has_bucket_blacklist_word_in_head(s):
        return False

    # 区域形态的值是区域名，不是桶名（让位给更具体的区域判定）
    if is_cloud_region_value(s):
        return False

    # 结构复杂度: 必须包含 '-' 或数字
    return '-' in s or any(c.isdigit() for c in s)


def process_bucket_name(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云存储桶名称"""
    append_result(res, IDT.CLOUD_BUCKET_NAME, s, src, sid)


# =========================================================
# 邮箱检测
# =========================================================
def is_email(s: str) -> bool:
    """判断是否为邮箱格式"""
    if s.count("@") != 1:
        return False
    at_idx = s.index("@")
    local_part, domain_part = s[:at_idx], s[at_idx + 1:]
    if len(local_part) < 1 or len(domain_part) < 3 or "." not in domain_part:
        return False
    return any(s.lower().endswith(suffix) for suffix in EMAIL_DOMAIN_SUFFIXES)


def process_email(s: str, stmt: str, src: str, sid: int, res: list):
    """分类邮箱地址"""
    append_result(res, IDT.PII_EMAIL_NAME, s, src, sid)


# =========================================================
# API Key 格式验证
# =========================================================
def is_valid_api_key_format(s: str) -> bool:
    """检查字符串是否符合 API Key 的基本格式特征"""
    if len(s) < 16 or "/" in s or ".." in s:
        return False
    if s.isdigit() or (s.islower() and s.isalpha()):
        return False
    # 排除国际化key/变量名模式: 数字+字母开头 + 下划线分隔的单词
    # 如 0pverification_basis, 12forbidden_but_on
    if s[0].isdigit() and "_" in s:
        return False
    # 排除纯下划线分隔的小写单词 (如 selected_attribute_names)
    if "_" in s and s.replace("_", "").islower():
        return False
    return is_alnum_extended(s)


# =========================================================
# 地图 SDK Key 检测
# =========================================================
def is_tencent_map_key_format(s: str) -> bool:
    """检测是否为腾讯地图 Key 格式 (XXXBZ-XXXXX-...)"""
    # 格式: 5位字母数字 + BZ 结尾 + 横杠分隔
    # 如 F3MBZ-2RZW4-CBVU4-FQC4D-WOZLQ-6CFYW
    return (len(s) >= 6 and s[5] == "-" and
            s[:5].isalnum() and s[3:5] == "BZ")


def is_any_map_key_format(s: str, stmt: str = "") -> bool:
    """
    检测是否为任意地图 Key 格式
    支持：腾讯地图、Google Maps、高德、百度等
    """
    # 腾讯地图 Key: XXXBZ-XXXXX-...
    if is_tencent_map_key_format(s):
        return True
    # Google Maps Key: AIzaSy 开头
    if s.startswith(MAP_KEY_PREFIX_GOOGLE):
        return True
    # 有地图上下文 + 有效 API Key 格式
    if stmt:
        has_context = (has_keyword_in_context(stmt, MAP_KEY_CONTEXT_WORDS) or
                       has_keyword_substring(stmt.lower(), MAP_KEY_CONTEXT_WORDS))
        if has_context and is_valid_api_key_format(s):
            return True
    return False


def is_map_key(s: str, stmt: str) -> bool:
    """判断是否为地图 SDK Key"""
    return is_any_map_key_format(s, stmt)


def is_map_secret_key(s: str, stmt: str) -> bool:
    """
    判断是否为地图 SDK 的 Secret Key（用于签名）
    条件：上下文同时包含 mapKey 和 secretKey
    """
    stmt_lower = stmt.lower()
    # 上下文必须同时包含 mapkey 和 secretkey
    has_map_context = "mapkey" in stmt_lower or "map_key" in stmt_lower
    has_secret_context = "secretkey" in stmt_lower or "secret_key" in stmt_lower
    if not (has_map_context and has_secret_context):
        return False
    # 格式检查：24-64位字母数字混合
    if not check_length_range(s, 24, 64):
        return False
    if not s.isalnum():
        return False
    return any(c.isalpha() for c in s) and any(c.isdigit() for c in s)


def find_map_key_in_neighbors(idx: int, constants: list, statements: list) -> bool:
    """在邻近索引寻找地图 Key（支持所有地图类型）"""
    for ni in [idx + 1, idx - 1]:
        if 0 <= ni < len(constants):
            neighbor_val = constants[ni][0]
            neighbor_sid = constants[ni][1]
            neighbor_stmt = statements[neighbor_sid] if neighbor_sid < len(statements) else ""
            if is_any_map_key_format(neighbor_val, neighbor_stmt):
                return True
    return False


def is_map_secret_key_by_neighbor(s: str, stmt: str, idx: int, constants: list, statements: list) -> bool:
    """
    通过相邻常量判断是否为地图 Secret Key
    条件：上下文包含 secretKey + 相邻常量是地图 Key 格式
    """
    stmt_lower = stmt.lower()
    if "secretkey" not in stmt_lower and "secret_key" not in stmt_lower:
        return False
    # 格式检查：24-64位字母数字混合
    if not check_length_range(s, 24, 64) or not s.isalnum():
        return False
    if not (any(c.isalpha() for c in s) and any(c.isdigit() for c in s)):
        return False
    # 检查相邻常量是否是地图 Key
    return find_map_key_in_neighbors(idx, constants, statements)


def process_map_key(s: str, stmt: str, src: str, sid: int, res: list):
    """分类地图 SDK Key"""
    append_result(res, IDT.SAAS_MAP_KEY, s, src, sid)


# =========================================================
# 统计分析 SDK Key 检测
# =========================================================
def is_analytics_key(s: str, stmt: str) -> bool:
    """判断是否为统计分析 SDK Key"""
    if not has_keyword_in_context(stmt, ANALYTICS_KEY_CONTEXT_WORDS):
        return False
    if len(s) < 8 or not is_alnum_extended(s):
        return False

    s_lower = s.lower()

    # 排除编程命名前缀
    for prefix in CODE_NAMING_PREFIXES:
        if s_lower.startswith(prefix) and len(s) > len(prefix) and s[len(prefix)].islower():
            return False

    # 纯小写字母且长度不是 32/64
    if s_lower == s and s.isalpha() and len(s) not in (32, 64):
        return False

    # 要求包含数字（除非是 32/64 位）
    if not any(c.isdigit() for c in s) and len(s) not in (32, 64):
        return False

    return True


def process_analytics_key(s: str, stmt: str, src: str, sid: int, res: list):
    """分类统计分析 SDK Key"""
    append_result(res, IDT.SAAS_ANALYTICS_KEY, s, src, sid)



# =========================================================
# AK/SK 密钥对检测
# =========================================================
def is_secret_key_sk(s: str, stmt: str) -> bool:
    """检测是否为 SecretKey (SK)"""
    if not check_length_range(s, 16, 64):
        return False
    if not has_keyword_substring(stmt, SK_CONTEXT_WORDS):
        return False
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(c in valid_chars for c in s)


def is_sk_format(s: str) -> bool:
    """检测值是否符合 SK 格式（不检查上下文关键词）"""
    if not check_length_range(s, 16, 64):
        return False
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return all(c in valid_chars for c in s)


def is_access_key(s: str, stmt: str) -> tuple:
    """检测是否为 AccessKey，返回 (是否匹配, 云厂商)"""
    if is_secret_key_sk(s, stmt):
        return (False, None)

    # 前缀匹配
    for prefix, provider in AK_PREFIX_PATTERNS.items():
        if s.startswith(prefix) and check_length_range(s, 16, 40) and s.isalnum():
            return (True, provider)

    # 上下文关键词 + 格式验证
    if has_keyword_substring(stmt, AK_CONTEXT_WORDS):
        if check_length_range(s, 16, 40) and s.isalnum():
            return (True, "unknown")

    return (False, None)


def find_ak_in_neighbors(sk_idx: int, constants: list, statements: list) -> tuple:
    """在 SK 的邻近索引寻找 AK"""
    for ni in [sk_idx + 1, sk_idx - 1]:
        if 0 <= ni < len(constants):
            ak_val, ak_sid, _ = constants[ni]
            if ak_sid < len(statements):
                is_ak, provider = is_access_key(ak_val, statements[ak_sid])
                if is_ak:
                    return (ak_val, statements[ak_sid], provider, ni)
    return (None, None, None, None)


def find_sk_in_neighbors(ak_idx: int, constants: list, statements: list) -> tuple:
    """在 AK 的邻近索引寻找 SK"""
    for ni in [ak_idx + 1, ak_idx - 1]:
        if 0 <= ni < len(constants):
            sk_val, sk_sid, _ = constants[ni]
            if sk_sid < len(statements):
                sk_stmt = statements[sk_sid]
                if is_secret_key_sk(sk_val, sk_stmt) or is_sk_format(sk_val):
                    return (sk_val, sk_stmt, ni)
    return (None, None, None)


def process_ak_sk_pair(ak_val: str, ak_stmt: str, sk_val: str, sk_stmt: str, 
                       provider: str, src: str, sid: int, res: list):
    """处理 AK/SK 密钥对"""
    combined_val = f"AK={ak_val}, SK={sk_val}"
    append_result(res, IDT.CLOUD_CRED_AK_SK_PAIR, combined_val, src, sid)


# =========================================================
# Session Key 检测
# =========================================================
def has_session_key_context(stmt: str, value: str) -> bool:
    """上下文是否处在会话密钥的语境里（见 SESSION_KEY_CONTEXT_WORDS）。

    value 参与剥值（见 external_context）：值自己含 sessionKey / session_key 时不能再
    单独把语境闸门打开（`wx.setStorageSync("sessionKey", ...)` 这类自指认）。
    `value` **无默认值**，与 has_user_id_context 同一约定 —— 漏改调用点直接 TypeError。
    """
    context = external_context(stmt, value)
    return has_keyword_in_context(context, SESSION_KEY_CONTEXT_WORDS)


def is_session_key(s: str, stmt: str) -> bool:
    """判断是否为微信/支付宝 Session Key（24 字符 base64 = 16 字节密钥）。

    原判据「只判 24 字符 base64 + 16 字节 + 熵 >= 3.0 + 可打印 < 12」不看上下文，
    于是任何符合该形态的值都会命中。三库实测 2632 行 / 286 个去重值里：
      - 89.8% 的上下文含 pid/log（LogPid: "opbiznojnzl7iml6kgpmjw==" —— 日志流水号）
      - 只有 0.3%（8 行 / 6 个值）的上下文真的提到 session
    故新增两条收敛，均以「当前代码下仍然命中」的语料为基准：

    1) 语境要求：stmt 必须落在 session_key / sessionkey 语境（见
       SESSION_KEY_CONTEXT_WORDS）。stmt 是**必填**参数，没有默认值 —— 形态本身
       毫无区分度，任何「没传上下文就不要求语境」的默认值都会把 89.8% 的噪音
       原样放回来，等于给未来调用者留了个无声的坑。生产链路
       perform_constant_classifying 里唯一的调用点与测试都显式传 stmt。
    2) 形态收紧：拒绝「22 个有效字符里一个大写字母都没有」的值。
       16 字节真随机值的 base64 每个 6-bit 组落在非大写字符集 {a-z,0-9,+,/}
       （38/64 个字符）内的概率是 38/64，22 组同时如此的概率 ≈ (38/64)^22 ≈ 1e-5。
       而三库 286 个去重值里有 126 个（44%）无大写 —— 真随机密钥出现这种情况的概率
       ≈ 1e-109，是不可能事件，说明这些值的字符集是被构造出来的，不是随机密钥
       （实测这 126 个值解码后 6-bit 组均匀落在 [26,63]，正是「字符集被限制在大写以外」
       的特征）。代价：真随机密钥被这条误杀的概率 ≈ 1e-5/个。
    """
    if not has_session_key_context(stmt, s):
        return False
    if len(s) != 24 or not s.endswith("=="):
        return False
    if not any(c.isupper() for c in s[:22]):
        return False
    try:
        decoded_bytes = base64.b64decode(s, validate=True)
        if len(decoded_bytes) != 16 or decoded_bytes == b"\x00" * 16:
            return False
        if calculate_byte_entropy(decoded_bytes) < 3.0:
            return False
        printable_count = sum(1 for b in decoded_bytes if 0x20 <= b <= 0x7E)
        return printable_count < 12
    except Exception:
        return False


def process_session_key(s: str, stmt: str, src: str, sid: int, res: list):
    """分类微信/支付宝 Session Key"""
    append_result(res, IDT.PLATFORM_SESSION_KEY, s, src, sid)


# =========================================================
# Hex Token 检测
# =========================================================
# MongoDB ObjectID：24 位 hex = 4 字节秒级时间戳 + 5 字节随机 + 3 字节自增计数器，
# 前 8 个 hex 字符就是 Unix 秒时间戳。
#
# 证据（新库 unlist_icp_filing_v2 真实语料）：
#   ① server_cred_session_key(1603, risk5) 桶里 328 个 24 位纯 hex 值，325 个落在
#      下面的窗口内；其余 3 个全是区间外的随机 hex。
#   ② 更硬的是「连号」—— 同一秒内连续生成的文档 ID 会连号，密钥不会：
#        6210b04d58f1bb067ef9c742 / ...c743 / ...c744
#        60eda378877842c4 02636092 / ...02636093 / ...02636094（同前缀 91 个连号）
#   ③ 跨 5 个库的 1603 桶里共 2334 个不同的 24hex 值，没有一个是带真凭证语境的
#      会话密钥：6 个带 "appKey" 的也是 appKey: 的值域查表（值本身同样是 ObjectID
#      形态），61 个靠 "sid" 子串命中（checkinsId 里的 sid，属关键词假阳性）。
#   它们是数据库文档 ID，不是凭证。
#
# 窗口 2015-03-11 ~ 2026-02-26 覆盖小程序生态常见的 ObjectID 生成时间跨度。
# 区间外占首 4 字节全空间约 91.95%，一律不动 —— 代价是「随机生成的 24 位 hex 密钥
# 恰好落在区间内」会被当成 ObjectID，理论命中率 = 区间占全空间 8.0469%。
# 注：上界是固定值，ObjectID 计数器走到 0x6A000000 之后需要上调。
OBJECTID_TS_MIN = 0x55000000   # 1426063360 -> 2015-03-11
OBJECTID_TS_MAX = 0x69999999   # 1772093849 -> 2026-02-26
RE_HEX24_LOWER = re.compile(r"^[0-9a-f]{24}$")


def looks_like_mongodb_objectid(s: str) -> bool:
    """24 位小写 hex、且前 4 字节落在合理时间戳区间 —— MongoDB ObjectID 形态。"""
    if not RE_HEX24_LOWER.match(s):
        return False
    return OBJECTID_TS_MIN <= int(s[:8], 16) <= OBJECTID_TS_MAX


def has_hex_session_context(stmt: str) -> bool:
    """HEX_SESSION_CONTEXT_WORDS 的语境判定：长词走子串，`sid` 走词/驼峰段边界。

    见 HEX_SESSION_CONTEXT_WORDS_SUBSTR 处的说明。

    ⚠ 必须传**保留大小写**的 stmt，不能传 stmt_lower：has_keyword_in_context_strict
    靠「小写/数字接大写」处断词，喂进全小写会丢掉驼峰段 —— `storeSid` 会被当成单段
    token `storesid`，`sid` 段就找不到了（真会话键名被挡掉）。子串那条自己会 lower。
    """
    if has_keyword_substring(stmt, HEX_SESSION_CONTEXT_WORDS_SUBSTR):
        return True
    return has_keyword_in_context_strict(stmt, "sid")


def is_hex_token(s: str, stmt: str = None) -> bool:
    """判断是否为 Hex Token

    ObjectID 形态的 24 位 hex 不算 hex token：process_hex_token 只有「token/auth/
    apikey 语境 -> server_cred_token」「session 语境 -> server_cred_session_key」
    「无语境兜底 -> server_cred_session_key」三条出口，后两条会把文档 ID 判成
    risk5 的会话密钥（实测 1603 桶里 99.8% 的行走的就是无语境兜底）。在入口一次性
    拦掉，比在三条出口各补一次更收敛。拦掉后该值回落到通用分流（risk0），不是丢弃。

    注：入口守卫只放**值形**判据（ObjectID 形态与上下文无关）。「无语境」是**语境**
    判据，放在入口会把 process_hex_token 的两条语境出口变成死代码，所以它归
    process_hex_token 自己处理（见该函数）。
    """
    if len(s) not in VALID_HEX_TOKEN_LENGTHS:
        return False
    if not is_hex_string(s):
        return False
    if looks_like_mongodb_objectid(s):
        return False
    return has_min_unique_chars(s, 4)


def process_hex_token(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 Hex Token —— 只有**有语境**的才出口，无语境一律回落到通用分流。

    原先第三条出口是无条件兜底 `else -> server_cred_session_key`，把「语句就是值
    本身」的十六进制串（算法常量：MD5("hello")、国密曲线域多项式 ……）成批推进
    risk5 会话密钥桶。三库实测（口径：该值的所有 source_snippet 都不含 token/
    session 类词）：
        1603 桶 125,923 次出现里 124,868 次（99.16%）走的就是这条兜底；
        桶里最重的值 5d41402abc4b2a76b9719d911017c592 = MD5("hello")，单库 578 次。
    去掉兜底后它们回落到通用分流（risk0），不是丢弃 —— 与 is_hex_token 的 docstring
    一致。

    为什么不是「在 is_hex_token 入口加守卫」：入口守卫只适合放**值形**判据
    （如 looks_like_mongodb_objectid，与语境无关）。「无语境」是语境判据，放到入口
    会让下面两条语境出口永远为假 —— 判定被劈成两半，反而更难维护。
    """
    stmt_lower = stmt.lower() if stmt else ""

    if has_keyword_substring(stmt_lower, HEX_TOKEN_CONTEXT_WORDS):
        append_result(res, IDT.SERVER_CRED_TOKEN, s, src, sid)
    elif has_hex_session_context(stmt):
        append_result(res, IDT.SERVER_CRED_SESSION_KEY, s, src, sid)
    # else: 无语境 —— 不出口，回落到通用分流（risk0）。


# =========================================================
# 支付参数检测
# =========================================================
def is_payment_secret(s: str, stmt: str) -> bool:
    """检测是否为支付密钥"""
    if len(s) != 32 or not is_hex_string(s):
        return False
    return has_keyword_substring(stmt, PAYMENT_SECRET_KEYWORDS)


def _is_valid_payment_value(s: str) -> bool:
    """验证值是否符合支付参数的基本格式特征"""
    bad_chars = ('.', '/', '&', '^', ':', ';', '{', '}', '[', ']', '=', '"', "'", ' ')
    if any(char in s for char in bad_chars):
        return False
    if not s.isascii():
        return False
    if s.islower() and s.isalpha():
        return False
    if '_' in s and s[0].isalpha():
        return False
    if s.isdigit():
        return False
    return len(s) >= 5


def is_payment_param(s: str, stmt: str) -> tuple:
    """检测是否为支付参数，返回 (是否匹配, 分类ID)

    值侧判据（fix11 收严）：
        原实现最后一段是 `if param_name.lower() in stmt_lower` —— 只看**语句**里有没有
        timeStamp/nonceStr/paySign/signType 这些词，与值本身是什么无关；而 stmt 是值周围
        512 字符的上下文、必然包含值自己，于是任何含该子串的自指值（$taroTimestamp /
        timeStamp-wrap / data-signtype）都会把自己判进支付桶。
        三库实测（test-result/fix11_payparam_flow.out，2401 共 847 个值）：
          · 该循环贡献的命中里，值正好是支付参数名的只有 1 个（TIMESTAMP）；
          · 其余是 HTTP 头名（fix10 已拦）/ Taro 框架名 / CSS 类名 / 组件属性名；
          · 收严后 409 个值不再产出任何类型（噪音直接出局）。

    为什么选「值 == 参数名（大小写不敏感）」而不是「值里以词边界包含参数名」：
        · 词边界口径多留 50 个值（构成 refs 65 -> 434），多留的全是 `timeStamp-wrap`、
          `-timeStamp`、`x-expire-timestamp` 这类拼接名，却只少丢 1 个真阳性；
        · 参数名表里本就同时有 `time_stamp`/`sign_type`/`nonce_str` 写法，词边界对 `_`
          的处理是无据可依的额外规则；相等判定不需要额外边界语义；
        · 类型定义（constant_types_doc.md 的 2401「requestPayment 参数
          (timeStamp/nonceStr/package/paySign/signType)」）指的就是参数**名**。

    已知代价（实测，报告第 4b 节留痕）：2402/2405 的语义其实是「nonceStr/paySign 的
    **取值**」，相等判定会把真正落在 `paySign:"..."` 值位置上的值改判到
    server_cred_session_key。按用户要求本次只做值侧相等，未动这条语义，也**未**动
    CONTEXT_KEYWORDS 里同族的 paysign/noncestr/timestamp 三条（那会删掉
    `timeStamp:<13位毫秒>` 这类真阳性）。
    """
    s_lower = s.lower()
    stmt_lower = stmt.lower()

    if is_payment_secret(s, stmt):
        return (True, IDT.PAYMENT_SECRET)

    if s_lower.startswith(PAYMENT_PACKAGE_PREFIX):
        return (True, IDT.PAYMENT_PACKAGE)

    if "/" in s:
        return (False, None)

    if s.upper() in ("MD5", "SHA256", "HMAC-SHA256", "RSA") and "sign" in stmt_lower:
        return (True, IDT.PAYMENT_SIGN_TYPE)

    if not _is_valid_payment_value(s):
        return (False, None)

    # 值侧判据：值本身必须正好是某个支付参数名（12 个写法，按小写合并成 8 个 key）
    slug_id = PAYMENT_PARAM_NAME_TO_SLUG.get(s_lower)
    if slug_id is not None:
        return (True, slug_id)

    return (False, None)


def process_payment_param(s: str, stmt: str, src: str, sid: int, slug_id: int, res: list):
    """分类支付参数"""
    append_result(res, slug_id, s, src, sid)


# =========================================================
# 标识符检测
# =========================================================
def _luhn_checksum(s: str) -> bool:
    """Luhn 算法校验"""
    if not s.isdigit():
        return False
    digits = [int(d) for d in s]
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10 == 0


def _is_asn1_oid_hex(s: str) -> bool:
    """检测是否为 ASN.1 OID 编码的十六进制"""
    return s.lower().startswith("2a8648")


def _is_oid_format(s: str) -> bool:
    """
    检测是否为 OID (Object Identifier) 格式
    OID 格式: 数字.数字.数字... (如 1.3.6.1.5.5.7.3.8, 1.2.840.113549.1.9.16.2.48)
    """
    if "." not in s:
        return False
    parts = s.split(".")
    if len(parts) < 3:
        return False
    return all(p.isdigit() for p in parts)


def is_valid_imei(s: str) -> bool:
    """验证是否为有效的 IMEI"""
    return (len(s) == 15 and s.isdigit() and 
            not is_placeholder_value(s) and _luhn_checksum(s))


def is_android_id_format(s: str) -> bool:
    """Android ID: 16位十六进制"""
    return len(s) == 16 and is_hex_string(s) and not is_placeholder_value(s)


def is_oaid_format(s: str) -> bool:
    """OAID: 32位十六进制"""
    return (len(s) == 32 and is_hex_string(s) and 
            not is_placeholder_value(s) and not _is_asn1_oid_hex(s))


def is_uuid_format(s: str) -> bool:
    """UUID: 36位 8-4-4-4-12 格式"""
    if len(s) != 36 or s.count("-") != 4:
        return False
    parts = s.split("-")
    if len(parts) != 5 or [len(p) for p in parts] != [8, 4, 4, 4, 12]:
        return False
    return all(is_hex_string(p) for p in parts)


def is_mac_address_format(s: str) -> bool:
    """MAC地址: 17位 XX:XX:XX:XX:XX:XX 或 XX-XX-XX-XX-XX-XX"""
    if len(s) != 17 or (s.count(":") != 5 and s.count("-") != 5):
        return False
    sep = ":" if ":" in s else "-"
    parts = s.split(sep)
    return len(parts) == 6 and all(len(p) == 2 and is_hex_string(p) for p in parts)


def is_mac_address_no_sep(s: str) -> bool:
    """MAC地址: 12位十六进制 (无分隔符)"""
    return len(s) == 12 and is_hex_string(s) and not is_placeholder_value(s)


def is_openid_format(s: str) -> bool:
    """微信 openid: 28位，以 'o' 开头"""
    return len(s) == 28 and s[0] == "o" and s.isalnum()


def is_miniapp_appid(s: str) -> bool:
    """检测是否为小程序/公众号 AppID"""
    if MINIAPP_APPID_PATTERN.match(s):  # wx开头
        return True
    if MINIAPP_WW_APPID_PATTERN.match(s):  # ww开头（企业微信）
        return True
    if MINIAPP_GH_ID_PATTERN.match(s):  # gh_开头（公众号）
        return True
    return False


def process_miniapp_appid(s: str, stmt: str, src: str, sid: int, res: list):
    """分类小程序/公众号 AppID"""
    append_result(res, IDT.MINIAPP_NOISE, s, src, sid)


def is_identifier(s: str, stmt: str) -> tuple:
    """检测是否为标识符，返回 (是否匹配, 分类ID)"""
    s_len = len(s)

    if is_placeholder_value(s) or _is_asn1_oid_hex(s):
        return (False, None)

    # 纯格式匹配
    if is_valid_imei(s) or is_android_id_format(s) or is_mac_address_format(s):
        return (True, IDT.ID_DEVICE_IDENTIFIER)

    if is_oaid_format(s) and has_keyword_in_context(stmt, DEVICE_ID_KEYWORDS):
        return (True, IDT.ID_DEVICE_IDENTIFIER)

    if is_uuid_format(s):
        if has_keyword_in_context(stmt, DEVICE_ID_KEYWORDS):
            return (True, IDT.ID_DEVICE_IDENTIFIER)
        if has_keyword_in_context(stmt, AD_ID_KEYWORDS):
            return (True, IDT.ID_AD_IDENTIFIER)
        if has_user_id_context(stmt, s):
            return (True, IDT.ID_USER_IDENTIFIER)
        if has_keyword_in_context(stmt, ORDER_ID_KEYWORDS):
            return (True, IDT.ID_ORDER_IDENTIFIER)

    # 上下文 + 精准长度匹配
    if has_keyword_in_context(stmt, DEVICE_ID_KEYWORDS):
        if s_len in VALID_DEVICE_ID_LENGTHS and s.isalnum():
            return (True, IDT.ID_DEVICE_IDENTIFIER)

    if has_keyword_in_context(stmt, AD_ID_KEYWORDS):
        if s_len in VALID_DEVICE_ID_LENGTHS and s.isalnum():
            return (True, IDT.ID_AD_IDENTIFIER)

    if has_user_id_context(stmt, s):
        if check_length_range(s, 8, 64) and (s.isdigit() or s.isalnum()):
            # 排除纯小写字母的常见命名模式（页面名、事件名等）
            if s.islower() and s.isalpha():
                return (False, None)
            # 排除驼峰命名模式（如 pageMyPhoneAuth, liveBindPhone）
            if s[0].islower() and any(c.isupper() for c in s):
                return (False, None)
            return (True, IDT.ID_USER_IDENTIFIER)

    if has_keyword_in_context(stmt, ORDER_ID_KEYWORDS):
        if check_length_range(s, 12, 64) and (s.isdigit() or s.isalnum()):
            return (True, IDT.ID_ORDER_IDENTIFIER)

    return (False, None)


def process_identifier(s: str, stmt: str, src: str, sid: int, slug_id: int, res: list):
    """分类标识符"""
    append_result(res, slug_id, s, src, sid)



# =========================================================
# 预签名上传策略检测
# =========================================================
def is_upload_policy_signed(s: str) -> bool:
    """检测是否为预签名上传策略 (OSS/S3 Policy)"""
    if not s.startswith("eyJ") or len(s) < 20 or s.count(".") == 2:
        return False
    try:
        decoded = base64.b64decode(s).decode("utf-8")
        policy = json.loads(decoded)
    except Exception:
        return False

    if not isinstance(policy, dict):
        return False
    if not all(field in policy for field in UPLOAD_POLICY_REQUIRED_FIELDS):
        return False

    return has_keyword_substring(decoded.lower(), UPLOAD_POLICY_PROVIDER_KEYWORDS)


def process_upload_policy_signed(s: str, stmt: str, src: str, sid: int, res: list):
    """分类预签名上传策略"""
    append_result(res, IDT.CLOUD_CRED_UPLOAD_POLICY_SIGNED, s, src, sid)


# =========================================================
# 云服务 Token 检测
# =========================================================
def is_cloud_token(s: str) -> tuple:
    """检测是否为云服务 Token，返回 (是否匹配, 服务商)

    少数前缀（如 npm_）额外要求体形匹配，见 CLOUD_TOKEN_BODY_PATTERNS。
    """
    for prefix, provider in CLOUD_TOKEN_PREFIXES.items():
        if not s.startswith(prefix):
            continue
        body_pattern = CLOUD_TOKEN_BODY_PATTERNS.get(prefix)
        if body_pattern is not None and not body_pattern.match(s[len(prefix):]):
            continue
        if check_length_range(s, 20, 200):
            return (True, provider)
    return (False, None)


def process_cloud_token(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云服务 Token"""
    append_result(res, IDT.CLOUD_CRED_TOKEN, s, src, sid)


# =========================================================
# 云平台 Cookie 检测
# =========================================================
def is_cloud_cookie(s: str) -> bool:
    """检测是否为云平台会话 Cookie"""
    if len(s) < 10 or "=" not in s:
        return False
    return has_keyword_substring(s.lower(), CLOUD_COOKIE_NAMES)


def process_cloud_cookie(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云平台 Cookie"""
    append_result(res, IDT.CLOUD_CRED_COOKIE, s, src, sid)


# =========================================================
# 服务器 Cookie 检测
# =========================================================
def is_server_cookie(s: str, stmt: str) -> bool:
    """检测是否为服务器 Cookie"""
    if not has_keyword_substring(stmt, SERVER_COOKIE_CONTEXT_WORDS):
        return False
    if not check_length_range(s, 10, 500) or "=" not in s:
        return False
    if s.startswith("{") or s.startswith("["):
        return False

    # 排除常见的cookie名称（不是cookie值）
    cookie_name_keywords = SERVER_COOKIE_NAME_KEYWORDS
    s_lower = s.lower()
    if s_lower in cookie_name_keywords:
        return False
    # cookie **名** + 空值（`JSESSIONID=` / `PHPSESSID=` / `SessionId=`）：
    # `=` 右侧是空的，说明这只是拼接用的名字。上面的全值相等检查被那个 `=` 挡掉了。
    if _is_cookie_name_without_value(s, cookie_name_keywords):
        return False
    # 单段值形守卫（与 cloud_cred_password 同族），见 is_single_segment_identifier_name。
    if is_single_segment_identifier_name(s):
        return False

    # 排除隐私政策文本（包含中文）
    if any("\u4e00" <= c <= "\u9fff" for c in s):
        return False

    # 排除URL参数片段
    if s.startswith("&") or s.startswith("?"):
        return False

    # 排除cookie设置语法片段
    cookie_syntax_keywords = (
        "path=/", "httponly", "expires=", "secure", "samesite",
        "domain=", "max-age=",
    )
    if has_keyword_substring(s_lower, cookie_syntax_keywords) and ";" in s:
        # 如果只是cookie属性设置，不是真正的cookie值
        if not re.match(r'^[a-zA-Z0-9_-]+=.+', s):
            return False

    # 排除SDK版本号等常量
    if s_lower.endswith("v2") or s_lower.endswith("v1"):
        if "_" in s and s.replace("_", "").isalnum():
            return False

    # 排除纯数字值
    parts = s.split("=")
    if len(parts) == 2 and parts[1].isdigit():
        return False

    return True


def process_server_cookie(s: str, stmt: str, src: str, sid: int, res: list):
    """分类服务器 Cookie"""
    append_result(res, IDT.SERVER_CRED_COOKIE, s, src, sid)


# =========================================================
# 云服务密码检测
# =========================================================
# 值形守卫：「多段词形标识符/属性名」永远不是密码明文。
#
# 问题（fix12 A）：`cloud_cred_password(1203, risk 5)` 的头部全是**名字**而不是密码 ——
#   API 动作名 `auth.signUpWithEmailAndPassword`(1154 次)、i18n key
#   `bathCode.prompt2`、事件/常量名 `RESET_PASSWORD`、CSS 类名与图标名
#   `eye-fill` / `password-view`、属性名 `safe-password-*` …
# 它们能进这个桶是因为**值自己含 password/pwd** —— 而 has_cloud_password_context(stmt)
# 判的是整段语句（含值本身），于是值自指就能把上下文闸门打开（与 fix11 在
# is_payment_param 上发现的自指问题同源）。逐个补关键词排除不收敛，改用值形判据。
#
# 剥值轮（external_context）：上下文闸门**自己**也补上了 —— has_cloud_password_context
# 现在先 external_context(stmt, s) 把值的出现剥掉（键名位置保留），自指证据不再单独定罪。
# 本值形守卫保留为第二道防线：它拦的是「值形就是名字」这一类，与语境证据独立。
# 代价（方案甲已接受）：值自身文本提供语境、且值形是材料的（`&admin=admin&pwd=admin`、
# 43 位随机串…）落不到这个桶。
#
# 判据：值由 `.` / `-` / `_` 分隔成 ≥2 段，每段是「纯字母（任意大小写）+ 可选结尾数字」。
#   · 允许结尾数字：`register-step3` / `v1_step_insu_pwd` / `common_icon_line_invisible1`
#     都是库内真实噪声成员。
#   · **不允许数字夹在字母中间**是这条判据的关键：随机材料靠它被放过 —— 三库
#     「值坐在 password/pwd 赋值位」的取值里，只有
#     `password: "o0IN8wTN50QMxX-V4siq_GSRFuts"`（icp）与
#     `signBoardPassword:"signBoardPassword_S8hY"`（normsib）两个像材料，而放宽成
#     `^[A-Za-z][A-Za-z0-9]*`（只要求段以字母开头）会把这两个真阳性一起丢掉。
#   · 数字打头的段也不命中（UUID `3708d2bc-bc52-45a3-8f49-08c62f55f5b3`、`MyPage_6`、
#     `April_2024`）：保守，宁可留噪音。
#
# 量化（DB = 2807205 扫描的库；用库内真实 (值, 上下文) 重跑，见
# test-result/fix12/measure_ccp_guard.py + a_tp_review.py + a_guard_dest_all3.out）：
#   normsib 1151 值/14172 次（65.8% 值 / 82.6% 次）、icp 777/9026（72.0%/90.7%）、
#   pkg 814/7618（68.1%/85.2%）不再判该类型。
#   移出的 (值,上下文) 对（3523+2988+2555=9066）里 99.80% 直接出局（不产出任何类型），
#   剩 18 对 / 5 值（access_token / credit_card / id_card / refresh_token / workai_ck，
#   都是「敏感键名列表」的成员）落到 server_cred_cookie(5)：它们修复前就在 risk 5，
#   风险等级不变，不是「把噪音升级」。清单见 test-result/validate_fix12.py 的
#   KNOWN_R5_DRIFT。
#   误伤：三库「值真的坐在 password/pwd 赋值位」的 244 个值（111/80/53），本判据命中
#   133 个（70/29/34），逐条人工核对**全是常量名/事件名/路由名/图标名/i18n key**
#   （含 `RESET_PASSWORD: "RESET_PASSWORD"` 这类自赋值常量）；唯一两个像材料的已被放过。
RE_IDENTIFIER_NAME_VALUE = re.compile(r"^[A-Za-z]+[0-9]*(?:[.\-_][A-Za-z]+[0-9]*)+$")


def is_segmented_identifier_name(s: str) -> bool:
    """值形是否为「多段词形标识符/属性名」（API 动作名 / i18n key / CSS 类名 /
    属性名 / 常量名 / 路由名）。判据与依据见上面 RE_IDENTIFIER_NAME_VALUE 的注释。

    典型命中：auth.updatePassword / bathCode.prompt2 / RESET_PASSWORD /
    eye-fill / safe-password-time-stamp / password-view / enter-whitelist-password-login
    典型放过：1Passw0rd!xyz / jia23xia4kaoshi5t2 / 123456a /
    o0IN8wTN50QMxX-V4siq_GSRFuts / 3708d2bc-bc52-45a3-8f49-08c62f55f5b3
    （单段值不在射程内：`pwd2` / `WXOFFICIAL` 这类是已知残留。）

    单段残留见 is_single_segment_identifier_name。
    """
    return bool(RE_IDENTIFIER_NAME_VALUE.match(s))


# =========================================================
# 单段值形守卫（fix15 ③）
# =========================================================
# is_segmented_identifier_name 要求值由 `.`/`-`/`_` 分成 **≥2 段**，够不到单段的名字。
# 而单段才是这两个桶的大头（三库实测，见 test-result/risk5_struct/ccp_seg_survey.py）：
#   cloud_cred_password(1203) 单段占 66~71% 值；
#   server_cred_cookie(1604)  单段占 41~45% 值。
# 头部值：`WXOFFICIAL`(163) / `adapter`(180) / `timeout`(176) / `requireIdCard` /
#   `mobileEmptyTips` / `#tips_popup` / `.page-recharge-wallet-list-balance` / `===success`
#
# 选型过程（每一步都拿 fix12 人工核定清单当标尺，见
# test-result/risk5_struct/ccp_seg_candidates.py）：
#   · 先把「字母+尾数字」整族（`err3241` / `passwordTips3` / `emoney5` / `A70702000008000803`）
#     **整个排除** —— 它与弱口令同形（`Admin123` / `video123` / `ytx123456` /
#     `jdf123456` / `Nihao123` 都是这个形状），正是 fix12 点名不许碰的那一类。
#   · 「驼峰多词 + 尾数字」（`passwordTips3` / `errorNode2`）看着能把上面这族救回来，
#     实测**会误杀 `mnP7XKDCaWFjINWi`**（fix12 人工核定的 16 位随机口令，判据
#     `^[a-z]+(?:[A-Z][a-z0-9]*)+[0-9]*$` 分不清「随机大小写」与「驼峰」）——
#     故**否决**，不用更宽的写法。
#   · 最终只留「结构上不可能承载材料」的四类，它们对 fix12 的 29 个核定真阳性
#     + 2 个材料值的误伤为 **0**：
#       纯小写英文单词      adapter / timeout / globalmemory / decompress
#       纯大写单词          WXOFFICIAL / EMPHASIS / AUTHORIZED / PHPSESSID
#       驼峰纯字母（无数字） requireIdCard / mobileEmptyTips / backFromPhone
#       单段 + 尾部下划线    recordPsw_
#     加一条**语法片段前缀**（不是词形，是 CSS/选择器/私有字段的写法）：
#       `#tips_popup` / `.page-recharge-…` / `===success` / `_is_enter_password`
#     fix12 明确点名的 `password1` / `password123` / `admin123` 与上述**全部不匹配**
#     （要么含数字，要么没有 `#`/`.`/`===`/`_` 前缀）—— 已固化成单测的反例矩阵。
RE_SINGLE_SEGMENT_WORD_NAME = re.compile(
    r"^(?:"
    r"[a-z]{3,}"                    # adapter / timeout / globalmemory
    r"|[A-Z]{3,}"                   # WXOFFICIAL / EMPHASIS / PHPSESSID
    r"|[a-z]+(?:[A-Z][a-z]+)+"      # requireIdCard / mobileEmptyTips
    r"|[A-Za-z][A-Za-z0-9]*_"       # recordPsw_
    r")$")
RE_SINGLE_SEGMENT_SYNTAX_PREFIX = re.compile(r"^(?:[#.]|===|_)")

# cookie **名** + 空值：`JSESSIONID=` / `PHPSESSID=` / `SessionWsid=` / `ASP.NET_SessionId=`。
# is_server_cookie 本就有 cookie_name_keywords 排除，但判据是 `s_lower in cookie_name_keywords`
# （**全值相等**），带 `=` 的形态因那个等号逃掉了。`=` 右侧为空说明这个值只是拼接用的
# **名字**，不是 cookie 值。三库实测可安全收掉 14 值 / 458 次，且桶内
# 「cookie名 + 非空值」只有 1 值 —— 非空值一律不动（见 test-result/risk5_struct/cookie_name_only.py）。
RE_COOKIE_NAME_NO_VALUE = re.compile(r"^[\"']?[A-Za-z][A-Za-z0-9_.\-]*[\"']?=\s*$")

# fix16 ②：cookie 名里的「cookie 类词」。名字在这一族里 + 右侧为空 = 强证据说明它是 cookie 名，
# 而不是靠「表里有没有」这一条孤证。三库头部残留：ASP.NET_SessionId= / temp_token_auth= /
# token_auth= / auth_token= / login_token= / bujiang_session_id= / access_token= /
# session_id= / fsidCount= …（判据只放宽**名字侧**，`=` 右侧非空的一律不动。）
COOKIE_NAME_WORDS = ("token", "session", "sid", "auth", "cookie", "login",
                     "ticket", "jwt", "credential")


def is_single_segment_identifier_name(s: str) -> bool:
    """值形是否为「单段词形标识符 / 语法片段前缀」——这一类永远不是凭证材料。

    判据、选型过程与误伤量化见上面 RE_SINGLE_SEGMENT_WORD_NAME 的注释块。
    典型命中：WXOFFICIAL / adapter / timeout / requireIdCard / mobileEmptyTips /
             recordPsw_ / #tips_popup / .page-recharge-wallet-list-balance /
             ===success / _is_enter_password
    典型放过（必须放过）：password1 / password123 / admin123 / Admin123 /
             video123 / err3241 / emoney5 / mnP7XKDCaWFjINWi /
             o0IN8wTN50QMxX-V4siq_GSRFuts / signBoardPassword_S8hY
    """
    if RE_SINGLE_SEGMENT_WORD_NAME.match(s):
        return True
    return bool(RE_SINGLE_SEGMENT_SYNTAX_PREFIX.match(s))


def _is_cookie_name_without_value(s: str, cookie_name_keywords: tuple) -> bool:
    """cookie **名** + 空值（`JSESSIONID=`）—— 见 RE_COOKIE_NAME_NO_VALUE 的注释。

    fix16 ② 放宽了「名字」那一半：除关键词表之外，**名字含 cookie 类词**
    （COOKIE_NAME_WORDS：token/session/sid/auth/cookie/login/…）也算。
    只认表里的名字会漏掉 `auth_token=` / `temp_token_auth=` / `ASP.NET_SessionId=` 等
    三库头部值（实测该形态 111 个 data_item / 777 次出现在表外）。

    但**名字还必须是词形标识符**（is_segmented_identifier_name /
    is_single_segment_identifier_name）：`=` 右侧为空并不等于名字 ——
    base64 的 `=` 填充也是同一个形状，`LmF3LWNvb2tpZS1iYW5uZXI=` 就是桶里的真值。
    「任何 `名=` 空值」这条更宽的写法（不带形态判据）实测会吃掉 4 个 base64 填充值
    （见 test-result/fix16/e_cookie_widen.out 的 W4 对照组），故不采用。

    实测（三库 1,750 个 data_item 真实 (值,上下文) 回放）：1604 净减 67 值 / 629 次出现，
    全部落到「丢弃」；右侧非空被碰 0 个；base64 填充真值丢失 0 个。
    """
    if not RE_COOKIE_NAME_NO_VALUE.match(s):
        return False
    name = s.split("=", 1)[0].strip().strip("\"'")
    name_lower = name.lower()
    if name_lower in cookie_name_keywords:
        return True
    if not any(w in name_lower for w in COOKIE_NAME_WORDS):
        return False
    return (is_segmented_identifier_name(name)
            or is_single_segment_identifier_name(name))


def is_cloud_password(s: str, stmt: str) -> bool:
    """检测是否为云服务密码明文"""
    if not has_cloud_password_context(stmt, s):
        return False
    if not check_length_range(s, 6, 64):
        return False

    # 值形守卫：多段词形标识符/属性名（见 is_segmented_identifier_name 的注释）。
    # 放在最前面：它是「值形」判据，与后面的排除规则互不依赖。
    if is_segmented_identifier_name(s):
        return False
    # 单段残留（WXOFFICIAL / requireIdCard / #tips_popup / ===success …），见
    # is_single_segment_identifier_name 的注释块。
    if is_single_segment_identifier_name(s):
        return False

    s_lower = s.lower()
    # 排除规则
    if s.isdigit() or " " in s:
        return False
    if any("\u4e00" <= c <= "\u9fff" for c in s):
        return False
    if s_lower in CLOUD_PASSWORD_PLACEHOLDERS:
        return False
    if "://" in s or "/" in s:
        return False
    if s.startswith("eyJ") or s.startswith("Bearer ") or s.startswith("Basic "):
        return False

    # 排除国际化key格式: 数字+字母开头 + 点号分隔的单词
    # 如 0vmodify.field.informed.in.advance, 09tab.title.all
    if s[0].isdigit() and "." in s:
        return False
    # 排除纯点号分隔的小写单词 (如 knowledge.fileScope.emptyCategory)
    if "." in s and s.replace(".", "").replace("_", "").isalpha():
        parts = s.split(".")
        if len(parts) >= 2 and all(p.islower() or p[0].isupper() for p in parts if p):
            return False

    # CSS 样式排除
    css_keywords = ("::after", "::before", ":before", ":after", "content:",
                    "text-align", "position:", "width:", "height:", "margin",
                    "padding", "border", "font-", ",.")
    if has_keyword_substring(s_lower, css_keywords):
        return False
    # 排除 CSS 声明形态的值 (display:none / overflow:hidden / model:value)：
    # 这类语句里常另有 pwdStyle / pwdInput 之类「合法的」pwd 段，word 边界匹配拦不住，
    # 只能按值形拦 —— 密码明文不会长成「全小写属性:全小写值」。
    if re.match(r'^[a-z-]+:[a-z-]+$', s_lower):
        return False
    if re.match(r'^[a-z]+-[a-z]+-[a-z]+-\d+', s_lower):
        return False
    if re.match(r'^[a-z]+-\d+,?\.', s_lower):
        return False

    # 排除国际化 key: 0 开头后跟字母 (如 0mfield, 0gultiple_type_text)
    if s[0] == "0" and len(s) > 1 and s[1].isalpha():
        return False

    # 排除 icon font 名称 (如 icon-gouwuche1., icon_xxx)
    if s_lower.startswith("icon-") or s_lower.startswith("icon_"):
        return False

    # 排除纯小写字母的属性名/变量名 (如 readonly, clearable, required)
    if s.isalpha() and s.islower():
        return False

    # 排除驼峰命名的函数/变量名 (如 sendOldPhoneSms, checkPhoneNumber, loopArray88)
    _PWD_CODE_PREFIXES = ("get", "set", "send", "check", "update", "input", "show",
                          "handle", "on", "is", "has", "can", "do", "will", "did",
                          "loop", "anonymous", "member", "thumb")
    if any(s_lower.startswith(p) for p in _PWD_CODE_PREFIXES) and any(c.isupper() for c in s):
        return False

    # 排除以 . 结尾的纯标识符 (如 newbtn2., icon-xxx1.)
    # 但保留含特殊字符的密码 (如 Hyn132465.)
    if s.endswith(".") and s[:-1].replace("-", "").replace("_", "").isalnum():
        return False

    return any(c.isalpha() for c in s)


def process_cloud_password(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云服务密码明文"""
    append_result(res, IDT.CLOUD_CRED_PASSWORD, s, src, sid)


# =========================================================
# 小程序 API 路径检测
# =========================================================
def is_miniapp_api_params(s: str) -> bool:
    """检测是否为小程序 API 路径（带参数）"""
    s_lower = s.lower()
    if "://" in s:
        return False
    if s_lower.startswith("pages/") or s_lower.startswith("/pages/"):
        return False
    if s.startswith("./") or s.startswith("../") or s.startswith("@/"):
        return False
    if "?" not in s or "=" not in s:
        return False
    return s.startswith("/") or has_keyword_substring(s_lower, MINIAPP_API_PATH_PATTERNS)


def slash_path_body(s_lower: str) -> str:
    """斜杠路径的「实体部分」：去掉 ?/# 之后的内容。

    缓存串是 /xxx.png?t=20230714 这类值进不了资源分支的唯一原因，
    所以后缀判定必须看 ? 之前的部分。
    """
    return s_lower.split("?")[0].split("#")[0]


def process_miniapp_api_params(s: str, stmt: str, src: str, sid: int, res: list):
    """分类小程序 API 路径

    本函数的唯一调用点是 perform_constant_classifying 里 is_miniapp_api_params 那道
    门，而那道门只收「同时含 ? 和 =」的斜杠路径 —— 也就是说所有带查询字符串的
    斜杠常量都在这里落地，根本走不到 process_generic_slash_prefixed_constant 的第 7 步
    （第 7 步对斜杠路径不可达，探针实测三库语料 1,623,044 个 (值, 上下文) 对命中 0 次）。
    所以「带参数的页面路由」和「带缓存串的静态资源」的改判只能放在这里，
    放在第 7 步前面对它们没有任何效果。
    """
    s_lower = s.lower()

    # 带参数的页面路由：/packageC/pages/payCode/payCode?id=、
    # /unionMallOnlinePackage/pages/payment/index?groupCode= 这类值上下文是
    # e.redirectToAction(...)、url: 字段，是前端路由不是后端端点。
    # 复用第 9 步同一个 helper + 同一个分发函数（含 page_path_sensitive 分流）。
    # with_page_dir=True 额外认项目自建的 /page/ 根目录（见 RE_MINIAPP_PAGE_DIR_ROUTE）。
    # 注意这里不调 process_url_query_string：本函数原先也不调，改判不减少任何
    # query 抽取结果（改前这些值的 query 本来就没被抽过）。
    if is_miniapp_page_route(s, with_page_dir=True):
        process_prefixed_miniapp_pages(s, 0, stmt, src, sid, res)
        return

    # 带缓存串的静态资源：/app/images/share/intro.mp4?time=1、/xxx.png?t=20230714。
    # 后缀表复用 MINIAPP_PATH_ASSET_EXTENSIONS（含原先只对绝对 URL 生效的 .pdf）。
    # 只判资源后缀、不判 .js/.json：带参数的 .json 多为接口
    # （/api/cms/articles/views.json?、/cos/applySignature.json?client=），
    # 判成模块反而制造误伤。
    if any(slash_path_body(s_lower).endswith(ext) for ext in MINIAPP_PATH_ASSET_EXTENSIONS):
        append_result(res, IDT.MINIAPP_PATH_ASSET, s, src, sid)
        return

    append_result(res, IDT.MINIAPP_API_PARAMS, s, src, sid)


# =========================================================
# 硬编码 IV/KEY 检测
# =========================================================
# `iv` 只有两个字母，原来的小写子串匹配会让 div / give / active / relative /
# driver / private / deliver / divider / lively / activity / native ... 里的 `iv`
# 建立「IV 上下文」——`<div class="test-passive">` 一条语句就够。语句里任何 IV 形态
# 的值都会因此被判成 crypto_static_iv(2104)，所以 `iv` 不能再用子串匹配。
#
# 收紧方向和上一轮的值形态修复相反：判紧了会真的漏掉 IV，所以判据必须覆盖真实写法。
# 现实里 `iv` 作为独立语义单元出现只有两种外形：
#   1. 独立词 / 分隔词：`iv` `IV` `Iv`、`iv:` `iv=` `iv,`、`aes_iv`、`options.iv`、
#      `iv_key`、`iv="..."`、`{iv}` —— `i` 前一个字符不是字母数字（标识符起点或分隔符）；
#   2. 驼峰段：`aesIv` `sm4Iv` `staticIv` `aesIV`、`IvValue` —— 大写 `I` 前面是小写
#      字母或数字（`4I` 也算，`,sm4Iv` 要命中）。
# 两条都要求 `v` 后面不是小写字母：`ivStr` / `ivKey2` / `IvValue` 命中，而英语词里的
# `iv`（后面几乎总是元音：active / relative / divider / activity / give）落空。
#
# 反例一侧的证据（6001 个真实文件采样，脚本与语料见 test-result/iv-context/）：
#   - 小写 `iv` 前面是小写字母的一律不算：div（_div / divRemTo / "div-xxx"）、give、
#     active、relative、driver、private、deliver、divider、lively 全部落空；
#   - 全大写词里的 `IV` 若前面还是大写字母也不算：ACTIVITY / RECEIVE / DELIVERY /
#     PRIVACY / NEGATIVE / POSITIVE / DIV 这类 SCREAMING_SNAKE 落空（这是 `iv` 误命中的
#     另一大来源，`A[Ii][Vv](?![a-z])` 这种写法会把它全放进来）。
#     代价：`AESIV` / `KEYIV` 这种「全大写下 `IV` 直接贴在字母后面」的写法会漏掉。
#     真实采样里 0 出现；且 AES_IV / aesIv / sm4Iv / SM4IV（后者由 sm4iv 关键词兜底）
#     仍然命中。若日后真出现 AESIV 写法，应作为关键词补进 IV_CONTEXT_KEYWORDS，
#     而不是放宽这条正则。
#   - 小写 `iv` 在词中、后面跟大写的写法（aesivKey / divClass 一类）同样不算：采样里
#     89 次出现全部是 base64 乱码或 divRemTo，没有任何真 IV，故不为此放宽。
#   - 唯一需要靠「对的大小写」挡掉的是 `iVB`：base64 PNG 前缀 iVBORw0KGgo... 就是
#     「词首 iV」，所以词首分支只接受 iv / Iv / IV 三种拼法，不接受 iV。
RE_IV_CONTEXT = re.compile(r"(?<![0-9A-Za-z])(?:iv|Iv|IV)(?![a-z])"
                           r"|(?<=[a-z0-9])I[Vv](?![a-z])")


def has_iv_context(stmt: str, value: str = "") -> bool:
    """判断上下文是否包含 IV 含义。

    先把值本身从语句里剔除（值自己可能含 `iv`，不能由它建立上下文），再判断：
      - `iv` 走 RE_IV_CONTEXT 的「词边界 / 驼峰段」匹配（在**原始大小写**上判断，
        因为小写化后就分不出 aesIv 和 div 了）；
      - 其余关键词仍是原来的小写子串匹配，行为不变。
    """
    context_only = stmt.replace(value, "") if value and value in stmt else stmt
    if not context_only:
        return False
    if RE_IV_CONTEXT.search(context_only):
        return True
    context_lower = context_only.lower()
    return any(kw in context_lower for kw in IV_CONTEXT_SUBSTR_KEYWORDS)


def has_aes_key_context(stmt: str, value: str) -> bool:
    """判断上下文是否包含 AES_KEY 含义。

    value 参与剥值（见 external_context）：`aesKey: "aesKey"` 这类自赋值常量不再能
    仅凭值自身建立语境。`value` **无默认值**，与 has_user_id_context 同一约定。
    """
    context = external_context(stmt, value)
    return has_keyword_in_context(context, AES_KEY_CONTEXT_KEYWORDS)


def is_iv_identifier_like(s: str) -> bool:
    """判断值是否为「标识符/词」形态（CSS 类名、变量名、常量名、算法名）。

    这是 is_static_iv 在 base64/字符串两条路径上的身份护栏：真实 IV 是随机字节，
    不是词。每条判据都要求「分词」特征，随机串几乎不可能满足：

      1. 纯数字：12 位随机 base64 全为数字的概率 (10/64)^12 ≈ 1e-10
      2. SCREAMING_SNAKE / 全大写：22 位随机 base64 全在 [A-Z0-9_] 内 ≈ 1e-6
      3. 含 -/_ 且「像词串」：即 kebab / snake / BEM（如 _customer_latitude_cache /
         at-tab-bar__item / test-passive）。原先这里只看 `[A-Za-z0-9-_]+` 就一律拒绝，
         代价是 URL-safe 无 padding 的 IV（22 位）约 47% 被误杀 —— 因为随机 base64url
         里 -/_ 占 2/64 ≈ 3%，22 位里出现的概率约 50%，而其中 100% 都满足那个字符集。
         现在改由 is_iv_word_token 判「是否真像词串」，同一批随机 IV 的误杀率降到 ~1%
         （见该函数的说明与实测）。
      4. 驼峰 / 帕斯卡「单词串」：每段是「大写 + ≥2 个小写」的真单词。随机串里
         小写连排的平均长度约 1.5，要求每段 ≥3 字符后 22 位随机 base64 的通过率
         约 1e-4。这正是 noMobileFallback / setEnable1v1Chat / MobileVerifyType
         被挡住的原因；而手写的示例 IV（AbCdEfGhIjKlMnOp 这类每段只有 1 个小写）
         不会被挡。
      5. 纯小写字母（原有护栏，保留）
    """
    if s.isdigit():
        return True
    if RE_IV_SCREAMING.match(s):
        return True
    if ("-" in s or "_" in s) and RE_IV_WORD_TOKEN.match(s) and is_iv_word_token(s):
        return True
    # 以 '/' 开头的接口路径（/payment/v1/generalPay、/login/authLogin …）
    if is_iv_path_like(s):
        return True
    if is_word_shaped_identifier(s):
        return True
    if s.isalpha() and s.islower():
        return True
    return False


def is_word_shaped_identifier(s: str) -> bool:
    """值是否是「驼峰 / 帕斯卡单词串」——每段是「大写 + ≥2 个小写」的真单词。

    这是最保守的一条标识符判据：要求每个大写字母后面至少跟 2 个小写字母，
    即必须能切成真单词（Mobile / Verify / Type、no / Mobile / Fallback），
    而不是靠大小写切换凑出来的随机串。

      - 随机 22 位 base64 的通过率约 1e-4（随机串里小写连排平均长度 ≈ 1.5）；
      - 手写示例 IV（AbCdEfGhIjKlMnOp 这类每段只有 1 个小写）不会被挡；
      - 变量名/组件名（noMobileFallback / setEnable1v1Chat / MobileVerifyType /
        BeforeGetUserPhoneNumber）会被挡。

    is_static_iv 用它之外还叠了别的规则；is_static_aes_key 只用了这一条
    （AES KEY 允许是纯数字/纯小写/SCREAMING 口令，不能一刀切）。
    """
    return bool(RE_IV_CAMEL_WORDS.match(s) or RE_IV_PASCAL_WORDS.match(s))


def is_iv_word_token(s: str) -> bool:
    """含 -/_ 的值是否「像词串」（CSS 类名 / snake_case / BEM）。

    把 -/_ 当词边界切段，要求「像词的段」覆盖了值的一半以上字符：

      - 段的形状由 RE_IV_WORD_SEG_* 三条规定（小写单词 / 首字母大写单词 / 全大写缩写，
        都允许尾随数字），或整段是驼峰/帕斯卡词串（is_word_shaped_identifier）。
      - 段不算词的部分（纯数字、单字母、随机大小写混排）只起拉低覆盖率的作用。

    为什么用「覆盖率」而不是「任意一段是词」：标识符的 -/_ 落在词边界上，两侧都是词，
    于是覆盖率天然很高（test-passive 100%、_customer_latitude_cache 88%、
    at-tab-bar__item 63%、0391_FluidR3_GM_sf2_file 38%）；随机 base64url 的 -/_
    落在随机位置，覆盖率要么是 0（旁边不是词形的段），要么只有一小截。

    连续分隔符 `__` / `--` 是 BEM 的结构特征，随机串出现的概率约 1%，直接判词串。

    实测（20000 个真实 urlsafe_b64encode(os.urandom(16)) 去 padding 的 22 位值，
    与三库 crypto_static_iv 语料里去重后 5822 个「原规则挡下的值」对比）：
      - 随机 IV 被这条误杀 ~1.3%（原「一律拒绝」是 ~47%）
      - 5822 个标识符里仍挡下 ~93%
      - 标准 base64（含 +/=）没有 -/_，走不到这个分支，行为完全不变
    """
    if "__" in s or "--" in s:
        return True
    covered = 0
    for seg in re.split(r"[-_]", s):
        if not seg:
            continue
        if (RE_IV_WORD_SEG_LOWER.fullmatch(seg)
                or RE_IV_WORD_SEG_CAP.fullmatch(seg)
                or RE_IV_WORD_SEG_ABBR.fullmatch(seg)
                or is_word_shaped_identifier(seg)):
            covered += len(seg)
    return covered * 2 >= len(s)


def is_iv_path_like(s: str) -> bool:
    """值是否像 URL 接口路径（/seg[/seg]…），而不是随机 IV。

    这是「真接口被判成 IV」那一类误报的身份护栏。三库实测（真实 source_snippet
    重跑）：84 行 / 21 个值既是「以 / 开头的接口路径」又命中 crypto_static_iv，
    例如 /payment/v1/generalPay（13 行）、/login/authLogin（24 行）。

    根因：is_iv_identifier_like 原有的 kebab/snake 分支只把 - 和 _ 当词边界，
    RE_IV_WORD_TOKEN(`^[-_A-Za-z0-9]+$`) 不匹配含 '/' 的值，于是接口路径整批漏过，
    进到 is_random_iv_value 后逐条通过：
      - /payment/v1/generalPay 长度 22 ∈ IV_BASE64_LENGTHS；
      - 字符全在 BASE64_CHARS 内（'/' 也在表里）；
      - 大小写混排（'P'）。
    is_static_iv 原有的「含 / 即拒」护栏只拦「结构上不是合法 base64」的值
    （pages/index/index、/api/v1/user），拦不住长度和字符表都正好合法的接口路径。

    判据复用 is_iv_word_token（把 '/' 也当词边界），所以问的是「段是不是词」而不是
    「有没有 '/'」，代价用 Monte Carlo 量过（30 万次，见报告）：
      - 随机 16 字节标准 base64（24 字符）首字符恰好是 '/' 的概率 1/64 = 1.59%，
        要求「像路径」后误杀降到 0.032%（相差 50 倍）；
      - base64url（22 字符，- _）与 hex 路径根本不含 '/'，代价恒为 0。
    实测覆盖 21 个误报值里的 17 个（84 行里的 80 行）；剩余 4 个值见报告。
    """
    if not s.startswith("/"):
        return False
    return is_iv_word_token(s.replace("/", "-"))


def is_random_iv_value(s: str) -> bool:
    """base64 / 字符串两条路径共用的值形态校验。

    要求值「不是词、大小写混排、结构上是合法 base64」：

      - 词形态由 is_iv_identifier_like 排除（本次修复的主体）。
      - 大小写混排：真实 IV 是随机字节，base64 编码后必然大小写混排；
        22 位随机 base64 里完全没有大写（或完全没有小写）的概率约 4e-5。
      - 结构校验：随机字节的 base64 一定可解码。'=' 出现在中间的值不是合法
        base64（例如 targetItem====== / =====getUserProfile=====），也不是 IV。

    未采用「解码后必须是非可打印字节」这条更强的随机性判据：它会把
    「base64 包了一层明文 IV」的值一并砍掉（真实语料里就有
    MTIzNDU2NzgxMjM0NTY3OA== → '1234567812345678'、I3Jla2xhbWk= → 'reklami'），
    按「宁可漏报少一点」的方向放弃，详见报告。
    """
    if is_iv_identifier_like(s):
        return False
    if not (any(c.isupper() for c in s) and any(c.islower() for c in s)):
        return False
    return _decode_base64_or_none(s) is not None


def _decode_base64_or_none(s: str):
    """按 base64 / base64url 解码，非法结构返回 None（不抛异常）。"""
    normalized = s.replace("-", "+").replace("_", "/")
    pad = (-len(normalized)) % 4
    if pad == 3:  # 4n+1 长度不是任何字节串的 base64
        return None
    try:
        return base64.b64decode(normalized + "=" * pad, validate=True)
    except (ValueError, TypeError):
        return None


def is_static_iv(s: str, stmt: str) -> bool:
    """检测是否为硬编码 IV"""
    # 排除路径格式。原先写的是「含 / 即拒」，但标准 base64 的字母表本身就含 /（BASE64_CHARS
    # 里的 + / 与 - _ 是同一张 64 字符表的两种变体），16 字节 IV 的标准 base64 去 padding
    # 写法里约 28% 含 /，一律拒绝等于误杀它们。改成只问「结构上是不是合法 base64」：
    #   pages/index/index  → 长度 17，(-17)%4==3，不是任何字节串的 base64 → 仍拒
    #   /api/v1/user       → 结构合法，但无大写字母，被 is_random_iv_value 的混排检查拦下
    #   https://x.com/a    → 长度 15 不进 IV_BASE64_LENGTHS → 仍拒
    # URL-safe 变体（- _）与 hex 路径不受影响（hex 分支在下面，未改动）。
    if "/" in s and _decode_base64_or_none(s) is None:
        return False

    s_lower = s.lower()
    if has_keyword_substring(s_lower, IV_VALUE_BLACKLIST):
        return False
    if not has_iv_context(stmt, s):
        return False

    length = len(s)

    # hex 路径保持原样：16/24/32 位 hex 正是 IV 的标准形态（32 位 = AES 16 字节 IV），
    # 随机 hex 判得准，不做任何收紧。
    if length in IV_HEX_LENGTHS and is_hex_string(s):
        return True
    if length in IV_BASE64_LENGTHS and is_base64_chars(s):
        return is_random_iv_value(s)
    if length in IV_STR_LENGTHS and s.isalnum():
        return is_random_iv_value(s)

    return False


def is_static_aes_key(s: str, stmt: str) -> bool:
    """检测是否为硬编码 AES KEY"""
    if not has_aes_key_context(stmt, s):
        return False

    length = len(s)
    # hex 形态先判：32/48/64 位 hex 未受影响
    if length in (32, 48, 64) and is_hex_string(s):
        return True
    if length in (16, 24, 32) and s.isalnum():
        # 只挡「驼峰/帕斯卡单词串」这一种标识符形态（aesKey: "noMobileFallback" /
        # "setEnable1v1Chat" / "MobileVerifyType" 这类变量名被当成 AES KEY）。
        # 密钥本身常见的形态全部保留：纯数字口令(1234567890123456)、
        # 纯小写口令(abcdefghijklmnop)、SCREAMING(MYAESKEY12345678)、
        # 随机混合串(EpdnnX4MBpPjdlsZ)，都仍然命中。
        return not is_word_shaped_identifier(s)

    return False


def process_static_iv(s: str, stmt: str, src: str, sid: int, res: list):
    """分类硬编码 IV 或 AES KEY"""
    append_result(res, IDT.CRYPTO_STATIC_IV, s, src, sid)


# =========================================================
# 加密算法名称检测
# =========================================================
def is_crypto_algorithm(s: str) -> tuple:
    """检测是否为加密算法名称，返回 (是否匹配, 是否为弱算法)"""
    s_lower = s.lower()
    s_normalized = s_lower.replace("-", "")

    for algo in CRYPTO_ALGORITHM_NAMES:
        algo_normalized = algo.replace("-", "")
        if s_lower == algo or s_normalized == algo_normalized:
            is_weak = any(s_lower == weak or s_lower.startswith(weak)
                         for weak in WEAK_CRYPTO_ALGORITHMS)
            return (True, is_weak)

    return (False, False)


def is_weak_algorithm_in_sensitive_context(s: str, stmt: str) -> bool:
    """检测是否在敏感上下文中使用弱加密算法"""
    s_lower = s.lower()
    is_weak = any(s_lower == weak or s_lower.startswith(weak)
                  for weak in WEAK_CRYPTO_ALGORITHMS)
    if not is_weak:
        return False
    return has_keyword_substring(stmt.lower(), SENSITIVE_CRYPTO_CONTEXT)


def process_crypto_algorithm(s: str, stmt: str, src: str, sid: int, res: list):
    """分类加密算法名称"""
    append_result(res, IDT.CRYPTO_ALGORITHM_NAME, s, src, sid)


def process_weak_algorithm(s: str, stmt: str, src: str, sid: int, res: list):
    """分类弱加密算法"""
    append_result(res, IDT.CRYPTO_WEAK_ALGORITHM, s, src, sid)


# =========================================================
# Secret/API Key 检测
# =========================================================
def has_appkey_context(stmt: str, value: str) -> bool:
    """检查上下文是否包含 appKey 相关关键词。

    value 参与剥值（见 external_context）：`appKey: "appKey"` 这类自赋值常量不再能
    仅凭值自身建立语境。`value` **无默认值**，与 has_user_id_context 同一约定。

    顺手留痕（未改语义）：APP_KEY_CONTEXT_WORDS 里的 appKey / apiKey / accessKey
    三个驼峰写法在 `.lower()` 之后的串上永远匹配不到，是死键 —— 真正生效的只有
    appkey / app_key / apikey / api_key / accesskey / access_key 六个小写写法。
    """
    context = external_context(stmt, value)
    return has_keyword_substring(context.lower(), APP_KEY_CONTEXT_WORDS)


def has_secret_context(stmt: str, value: str) -> bool:
    """检查上下文是否包含 secret 相关关键词。

    value 参与剥值（见 external_context）：值自己含 secret 时不再能单独建立语境
    （`["getSecretTest"]` 这类把函数名当密钥的自我指认）。注意**键名位置**的出现仍保留
    （`secret: "secret"` 里的 secret），所以真·自赋值密钥不会被误剥 —— 与
    has_cloud_password_context 同一口径。`value` **无默认值**，理由同上。
    """
    context = external_context(stmt, value)
    return has_keyword_in_context(context, APP_SECRET_CONTEXT_WORDS)


def is_access_token_format(s: str) -> bool:
    """AccessToken 值的格式校验（字母开头 / 数字开头两条路径共用同一套）

    只接受“像 token”的值：
      - 长度 >= 20（真实 OAuth/JWT token 远长于此）
      - 字母与数字混合
      - 不含路径/表达式/日期/URL 查询类分隔符（, ; : . / @ ? & = 等）
      - 排除驼峰标识符（如 getUserInfo2）
    真实 token 常见形态为 alnum 或 base64url（A-Za-z0-9-_）。

    关于排除 '.'：JWT 以 eyJ 开头，在更早的 TOKEN_PREFIX_WORDS 分支
    （process_generic_alpha_prefixed_constant，先于本函数的调用点）就被接住，
    且 JWT 不可能数字开头，因此这里排除 '.' 不会漏掉 JWT。
    """
    if len(s) < 20:
        return False
    if s.isdigit():
        return False
    if not any(c.isalpha() for c in s) or not any(c.isdigit() for c in s):
        return False
    if not has_min_unique_chars(s, 4):
        return False
    if any(c in s for c in ",;:./@?&=#!*()[]{}'\"\\|<> \t\n\r"):
        return False
    if s[0].islower() and any(c.isupper() for c in s):
        return False
    return True


def is_app_key(s: str, stmt: str) -> tuple:
    """检测是否为 AppKey/ApiKey，返回 (是否匹配, 分类ID)"""
    if not has_appkey_context(stmt, s):
        return (False, None)
    # 长度下限从 10 提到 16，排除 d5f5e1f6b0 之类的短噪声
    if not check_length_range(s, 16, 40) or s.isdigit():
        return (False, None)
    if not is_alnum_extended(s) or not any(c.isalpha() for c in s):
        return (False, None)
    # 排除含连字符/下划线的值（如 data-v-79e6a490、错误码常量）
    if "-" in s or "_" in s:
        return (False, None)
    # 排除全大写的错误码常量（如 ERROR5_ON_LOGIN_PEER_SECRET_PAGE），
    # 但纯 hex 值（如大写 AppSecret）不受影响，避免漏报
    if s.isupper() and not is_hex_string(s):
        return (False, None)
    # 排除纯小写字母（变量名/页面名，如 editaccount, presuccess）
    if s.islower() and s.isalpha():
        return (False, None)
    # 排除驼峰命名模式（如 editAccount, getUserInfo）
    if s[0].islower() and any(c.isupper() for c in s):
        return (False, None)
    # 要求包含数字（真正的 API Key 几乎都有数字）
    if not any(c.isdigit() for c in s):
        return (False, None)
    # 要求足够的字符多样性，排除低熵噪声（如 f8a69f1719916z，16位仅8个不同字符）
    if not has_min_unique_chars(s, 10):
        return (False, None)
    # 公开 AppKey 与凭证分流（见 PUBLIC_APP_KEY_CONTEXT_WORDS 的注释）：
    # 段内出现 appkey/app_key/apikey/api_key、且不出现 accesskey/access_key/secret
    # 的，是客户端公开标识，复用统计分析 SDK Key 的类型（1402）；
    # 含 accesskey/secret 的留在 platform_app_secret(1101)。
    stmt_lower = stmt.lower()
    if (any(w in stmt_lower for w in PUBLIC_APP_KEY_CONTEXT_WORDS)
            and not any(w in stmt_lower for w in CREDENTIAL_APP_KEY_CONTEXT_WORDS)):
        return (True, IDT.SAAS_ANALYTICS_KEY)
    return (True, IDT.PLATFORM_APP_SECRET)


def process_app_key(s: str, stmt: str, src: str, sid: int, slug_id: int, res: list):
    """分类 AppKey/ApiKey"""
    append_result(res, slug_id, s, src, sid)


def is_secret_key(s: str, stmt: str) -> tuple:
    """检测是否为 Secret/API Key，返回 (是否匹配, 分类ID)"""
    if not has_secret_context(stmt, s):
        return (False, None)

    length = len(s)
    stmt_lower = stmt.lower()

    if s.startswith(CIPHERTEXT_PREFIX) or length > 128:
        return (False, None)

    if s.endswith("=="):
        if "clientsecret" in stmt_lower or "client_secret" in stmt_lower:
            # base64 padding 结尾：要求 base64 字符集、字母+数字混合、字符多样性足够。
            # 不再排除全大写：'==' 结尾使 is_hex_string 恒为 False，那条会退化成
            # “排除全大写”而漏掉全大写 base64 密钥；低熵噪声由多样性阈值拦住。
            if (check_length_range(s, 16, 64) and is_base64_chars(s)
                    and any(c.isalpha() for c in s) and any(c.isdigit() for c in s)
                    and has_min_unique_chars(s, 10)):
                return (True, IDT.PLATFORM_APP_SECRET)
        return (False, None)

    is_hex = is_hex_string(s)
    has_letter = any(c.isalpha() for c in s)
    has_digit = any(c.isdigit() for c in s)

    # 类型 A: 32位 Hex (微信 AppSecret/MD5)
    if length == 32 and is_hex:
        return (True, IDT.PLATFORM_APP_SECRET)
    # 类型 B: 40/64位 Hex (GitHub/AWS Secret, SHA1/SHA256)
    if length in (40, 64) and is_hex:
        return (True, IDT.PLATFORM_APP_SECRET)
    # 类型 C: 24-64位 混合字符 (API Key) - 放宽下限从32到24
    if 24 <= length <= 64 and has_letter and has_digit:
        # 排除含 URL/查询串分隔符、连字符、下划线的值
        # （如 UUID4DE47302-EDC7-41D4-888F-59A79DF4EA46、ERROR5_ON_LOGIN_PEER_SECRET_PAGE）
        if not any(c in s for c in "/:@?&=-_"):
            # 排除日志/报错文案：真实密钥不含空白，而这类句子只因为 512 字符上下文里
            # 恰好出现 secret 一词就被判成密钥。实测三库语料里仍命中的（修复前 3 值/6 行）：
            #   "Crypto key must be 32 characters long"
            #   "the speechRecognizerV2 get url"
            #   "do not support s3 endpoint, please use tos endpoint."
            if any(c.isspace() for c in s):
                return (False, None)
            # 排除模块/资源文件名：构件名不是密钥
            # （如 ReactPropTypesSecret = require("68CE51906B707CCF0EA83997ABE78D80.js")）
            if s.lower().endswith(MINIAPP_MODULE_EXTENSIONS + MINIAPP_ASSET_EXTENSIONS):
                return (False, None)
            # 排除全大写错误码常量（纯 hex 大写密钥不受影响，避免漏报），
            # 并要求足够的字符多样性以排除低熵噪声
            if not (s.isupper() and not is_hex_string(s)) and has_min_unique_chars(s, 10):
                return (True, IDT.PLATFORM_APP_SECRET)

    return (False, None)


def process_secret_key(s: str, stmt: str, src: str, sid: int, slug_id: int, res: list):
    """分类 Secret/API Key"""
    append_result(res, slug_id, s, src, sid)



# =========================================================
# PII 检测
# =========================================================
def pii_get_digit_type(s: str) -> str:
    """检查数字字符串的类型 (身份证/手机号)"""
    s_len = len(s)

    # 身份证号 18位
    if s_len == 18:
        last_char = s[-1]
        if last_char.lower() == 'x':
            body = s[:-1]
        elif last_char.isdigit():
            body = s[:-1]
        else:
            return ""
        if not body.isdigit() or len(set(body)) < 4:
            return ""

        # 验证出生日期 (第7-14位: YYYYMMDD)
        birth_year = s[6:10]
        birth_month = s[10:12]
        birth_day = s[12:14]
        try:
            year = int(birth_year)
            month = int(birth_month)
            day = int(birth_day)
            # 年份范围: 1900-2026
            if not (1900 <= year <= 2026):
                return ""
            # 月份范围: 01-12
            if not (1 <= month <= 12):
                return ""
            # 日期范围: 01-31
            if not (1 <= day <= 31):
                return ""
        except ValueError:
            return ""

        return "pii_sfz"

    # 手机号 11位
    if s_len == 11 and s.isdigit() and s[0] == '1' and len(set(s)) >= 3:
        return "pii_phone"

    return ""


# =========================================================
# 小程序路径处理
# =========================================================
# 小程序页面/分包路由的形态：含 /pages/（覆盖 #/pages/ 写法），或以 /package、/packages/
# 开头。实测三库 server_url_payment 里这样的值有 622 个：
#   /GaoDeng/pages/gdPay/main                                  ← "pay" 命中 gdPay
#   /0WX1XCX/repayment/#/pages/index/index                     ← "pay" 命中 repayment
#   /TUICallKitAlipay/pages/visitDetail                        ← "pay" 命中 alipay
#   /packages/pay/unicashier/index
# 它们经 URL_SENSITIVE_KEYWORDS 的裸子串匹配被判成支付/登录/后台接口，但值本身是
# 前端页面路由，不是后端端点。
#
# 2026-10 补 subPackages/subPages：原正则只认 /pages/ 与 ^/package，分包目录写成
# /subPackages/、/subPages/（大小写混写）时判不出来，于是不含敏感词的页面路由一路掉到
# 「后端 API 路径」兜底，被记成 miniapp_api_params。实测三库 data_item 里首段是
# /subpages*、/subpackage* 的值共 13,482 个，其中含 API 标记（/api/、/v1/…）的只有 3 个
# （它们仍按「含 API 标记不算页面路由」的既有优先级判为接口），加这两个前缀不吞真接口。
# 用 ^/subpackage、^/subpages（不带结尾斜杠）而非 /subpackages/：分包目录名带后缀是常态
# （/subpackages0/、/subpagesa/、/subpackageb/、/subpagef/……）。
RE_MINIAPP_PAGE_ROUTE = re.compile(r"/pages/|^/package|^/subpackage|^/subpages", re.I)


def is_miniapp_page_route(s: str, with_page_dir: bool = False) -> bool:
    """值是否为小程序页面/分包路由形态（不是后端接口路径）。

    含 API 路径标记（/api/、/v1/、/v2/、/v3/、api/）的值不算页面路由：
    `/api/v1/pages/list` 里的 "pages" 是 REST 资源名，不是小程序页面目录。
    实测本次从 server_url_payment 改判的 609 个值（1220 个「值 + 上下文」对）里，
    含 API 标记的为 0，所以这条排除不损失任何目标值，只是把这类理论误伤挡在门外。

    with_page_dir=True 时额外认项目自建的 /page/ 根目录。默认 False：只有带查询参数的
    入口（process_miniapp_api_params）需要这条，无参的 /page/xxx 混着组件/模块引用，
    证据不足不能整族归页面（见 RE_MINIAPP_PAGE_DIR_ROUTE 的注释）。
    """
    if has_keyword_substring(s.lower(), MINIAPP_API_PATH_PATTERNS):
        return False
    # 页面目录前缀只能出现在路径部分。带查询串的值里，页面路径可能只是被当成一个
    # 查询参数（/index.php?q=/app/leadmall/pages/ 的上下文是
    # n.$.http("/index.php?q=/app/leadmall/pages/" + t)），那种值是接口不是页面路由。
    # 本轮从 2001 迁走的 24,259 个值里，这一条正好摘掉该类误伤，对无 ? 的值是恒等变换。
    path = s.split("?")[0]
    if with_page_dir and RE_MINIAPP_PAGE_DIR_ROUTE.search(path):
        return True
    return bool(RE_MINIAPP_PAGE_ROUTE.search(path))


def url_process_path(rel_path: str) -> str:
    """处理小程序路径类型"""
    s_lower = rel_path.lower()
    if rel_path.startswith("plugin"):
        return "PLUGIN"
    if has_keyword_substring(s_lower, SENSITIVE_PAGE_KEYWORDS):
        return "SENSITIVE"
    if "?" in rel_path:
        return "PARAM"
    if any(s_lower.endswith(ext) for ext in MINIAPP_ASSET_EXTENSIONS):
        return "ASSET"
    if any(s_lower.endswith(ext) for ext in MINIAPP_MODULE_EXTENSIONS):
        return "MODULE"
    if "pay.php" in s_lower:
        return "PAY"
    if "login.php" in s_lower:
        return "LOGIN"
    return "UNKNOWN"


def process_prefixed_miniapp_pages(s: str, offset: int, stmt: str, src: str, sid: int, res: list):
    """分类小程序路径"""
    rel_path = s[offset:]
    s_lower = rel_path.lower()
    data_ty = url_process_path(rel_path)

    slug_map = {
        "PLUGIN": IDT.MINIAPP_PLUGIN_URL,
        "SENSITIVE": IDT.MINIAPP_PAGE_PATH_SENSITIVE,
        "PARAM": IDT.MINIAPP_SCENE_PARAM,
        "ASSET": IDT.MINIAPP_PATH_ASSET,
        "MODULE": IDT.MINIAPP_PATH_MODULE,
    }

    if data_ty in slug_map:
        append_result(res, slug_map[data_ty], s, src, sid)
    elif "pay.php" in s_lower:
        append_result(res, IDT.SERVER_URL_PAYMENT, s, src, sid)
    elif "login.php" in s_lower:
        append_result(res, IDT.MINIAPP_PAGE_PATH_SENSITIVE, s, src, sid)
    else:
        append_result(res, IDT.MINIAPP_PAGE_PATH, s, src, sid)


def process_prefixed_miniapp_plugin(rel_path: str, stmt: str, src: str, sid: int, res: list):
    """分类小程序插件路径"""
    append_result(res, IDT.MINIAPP_PLUGIN_URL, rel_path, src, sid)


def process_url_query_string(kv_pairs: str, stmt: str, src: str, sid: int, res: list):
    """分类查询字符串 - 检测 PII 和标识符"""
    for part in kv_pairs.split("&"):
        if "=" not in part:
            continue
        fs = part.split("=")
        if len(fs) != 2 or not fs[0] or not fs[1]:
            continue
        key, val = fs
        key_lower = key.lower()

        # 检查 key 是否是敏感关键词，复用 has_secret_context 的逻辑
        if has_keyword_substring(key_lower, APP_SECRET_CONTEXT_WORDS):
            is_secret, slug = is_secret_key(val, key)  # 用 key 作为上下文
            if is_secret:
                append_result(res, slug, val, src, sid)
                continue

        if val[0].isdigit():
            data_ty = pii_get_digit_type(val)
            if data_ty == "pii_sfz":
                append_result(res, IDT.PII_SFZID_NAME, val, src, sid)
            elif data_ty == "pii_phone":
                append_result(res, IDT.PII_PHONE_NAME, val, src, sid)
            else:
                append_result(res, IDT.PII_NOISE, val, src, sid)


# =========================================================
# 通用分类处理函数
# =========================================================
def process_generic_spaced_constant(s: str, stmt: str, src: str, sid: int, results: list):
    """处理包含空格的常量"""
    pass


def process_generic_digit_prefixed_constant(s: str, stmt: str, src: str, sid: int, res: list):
    """处理数字开头的常量"""
    # 排除椭圆曲线预计算点表
    stmt_lower = stmt.lower()
    if "point" in stmt_lower or "points" in stmt_lower:
        return

    # IMEI
    if is_valid_imei(s):
        append_result(res, IDT.ID_DEVICE_IDENTIFIER, s, src, sid)
        return

    # 独立 IP 地址
    if process_standalone_ip(s, stmt, src, sid, res):
        return

    # PII
    data_ty = pii_get_digit_type(s)
    if data_ty == "pii_sfz":
        append_result(res, IDT.PII_SFZID_NAME, s, src, sid)
        return
    if data_ty == "pii_phone":
        append_result(res, IDT.PII_PHONE_NAME, s, src, sid)
        return

    # 排除 OID 格式 (如 1.3.6.1.5.5.7.3.8, 1.2.840.113549.1.9.16.2.48)
    if _is_oid_format(s):
        append_result(res, IDT.PII_NOISE, s, src, sid)
        return

    # 通过上下文关键词匹配 (数字开头的值需要更严格的验证)
    for keyword, slug_id in CONTEXT_KEYWORDS.items():
        if keyword in stmt_lower:
            # 排除路径格式
            if "/" in s:
                continue
            # 凭证类型：纯数字不分类
            if slug_id in (IDT.PLATFORM_APP_SECRET, IDT.PLATFORM_ACCESS_TOKEN,
                           IDT.PLATFORM_SESSION_KEY, IDT.SERVER_CRED_PASSWORD):
                if s.isdigit():
                    continue
                if slug_id == IDT.PLATFORM_ACCESS_TOKEN:
                    # ACCESS_TOKEN 是这 4 种里唯一只有本分支能判的类型
                    if not is_access_token_format(s):
                        continue
                else:
                    # APP_SECRET/SESSION_KEY/PASSWORD 不在此判定：它们已分别由更早的
                    # is_secret_key(L2135)/is_session_key(L2185)/is_cloud_password(L2202)
                    # 覆盖，而那些检查对同一 (s, stmt) 结果确定，此处再判恒为 False。
                    continue
            append_result(res, slug_id, s, src, sid)
            return

    append_result(res, IDT.PII_NOISE, s, src, sid)


def process_generic_alpha_prefixed_constant(s: str, stmt: str, src: str, sid: int, res: list):
    """处理字母开头的常量"""
    s_lower = s.lower()
    stmt_lower = stmt.lower()

    # 排除椭圆曲线预计算点表
    if "point" in stmt_lower or "points" in stmt_lower:
        return

    # 云存储 URL
    for pattern in CLOUD_URL_PREFIX_WORDS:
        if s_lower.startswith(pattern):
            process_prefixed_cloud_url(s, stmt, src, sid, res)
            return

    # 预签名上传策略
    if is_upload_policy_signed(s):
        process_upload_policy_signed(s, stmt, src, sid, res)
        return



    # Token (eyJ/Bearer/Basic)
    for pattern, token_type in TOKEN_PREFIX_WORDS.items():
        if s.startswith(pattern):
            process_prefixed_token(token_type, s, stmt, src, sid, res)
            return

    # openid
    if is_openid_format(s):
        append_result(res, IDT.ID_USER_IDENTIFIER, s, src, sid)
        return

    # 加密算法名称
    is_algo, is_weak = is_crypto_algorithm(s)
    if is_algo:
        if is_weak and is_weak_algorithm_in_sensitive_context(s, stmt):
            append_result(res, IDT.CRYPTO_WEAK_ALGORITHM, s, src, sid)
        else:
            append_result(res, IDT.CRYPTO_ALGORITHM_NAME, s, src, sid)
        return

    # 云区域标识
    if is_cloud_region_value(s):
        append_result(res, IDT.CLOUD_REGION, s, src, sid)
        return

    # 查询字符串
    if url_is_query(s):
        process_url_query_string(s, stmt, src, sid, res)
        return

    # 通过上下文关键词匹配 (需要额外验证值格式)
    stmt_lower = stmt.lower()
    for keyword, slug_id in CONTEXT_KEYWORDS_2.items():
        if keyword in stmt_lower:
            # 排除路径格式的值 (包含 / 的通常是 API 路径而非凭证)
            if "/" in s:
                continue
            # appsecret 复用收紧后的判定，避免 appSecret 上下文绕过
            # is_secret_key/is_app_key（stmt 含 appsecret/app_secret，
            # 二者都在 APP_SECRET_CONTEXT_WORDS 中，has_secret_context 为 True）
            if slug_id == IDT.PLATFORM_APP_SECRET:
                if not is_secret_key(s, stmt)[0]:
                    continue
            elif slug_id == IDT.PLATFORM_ACCESS_TOKEN:
                # 原有宽松规则（抽成 is_access_token_format，数字开头分支复用同一套）
                if not is_access_token_format(s):
                    continue
            elif slug_id == IDT.SERVER_CRED_COOKIE:
                # cookie 是本条唯一**没有专属判据把关**的出口：只有它靠裸关键词
                # `"cookie" in stmt` 就出口，于是 `adapter` / `timeout` / `storage` /
                # `weapp-cookie:` 这类**代码标识符**整族进 risk5。补一层值形守卫
                # （与 is_server_cookie / is_cloud_password 同一条），见
                # is_single_segment_identifier_name 的注释块。
                if is_single_segment_identifier_name(s):
                    continue
            append_result(res, slug_id, s, src, sid)
            return


def process_generic_dot_prefixed_constant(s: str, stmt: str, src: str, sid: int, results: list):
    """处理点号开头的常量"""
    pass


def process_generic_slash_prefixed_constant(s: str, stmt: str, src: str, sid: int, results: list):
    """处理斜杠开头的常量"""
    s_lower = s.lower()

    # 1. 排除相对路径模块引用 (./xxx, ../xxx, /./xxx)
    if s.startswith("./") or s.startswith("../") or s.startswith("/./"):
        return

    # 2. 模块文件引用
    if any(s_lower.endswith(ext) for ext in MINIAPP_MODULE_EXTENSIONS):
        append_result(results, IDT.MINIAPP_PATH_MODULE, s, src, sid)
        return

    # 3. 资源文件引用（后缀判定看 ? 之前的部分：/x/rank4.png?202011022153 的尾巴是
    #    缓存串，不是路径的一部分；带 ? 但不带 = 的资源值原先会一路掉到第 10 步）。
    #    第 2 步刻意不做同样的「去查询串」处理：带参数的 .json 多是接口
    #    （/api/cms/articles/views.json?、/api/company/uploadContractPhoto.json?），
    #    去串后判成模块会制造误伤。
    if any(slash_path_body(s_lower).endswith(ext) for ext in MINIAPP_PATH_ASSET_EXTENSIONS):
        append_result(results, IDT.MINIAPP_PATH_ASSET, s, src, sid)
        return

    # 4. 包含协议头的不在这里处理 (应该已被 URL 分支捕获)
    if "://" in s:
        return

    # 5. 排除小程序框架/npm 模块引用路径
    _MODULE_PATH_MARKERS = (
        "miniprogram_npm/", "node_modules/", "uni_modules/",
        "@babel/", "@vant/", "uview-ui/",
        "/dist/", "/assets/dist/",
    )
    if has_keyword_substring(s_lower, _MODULE_PATH_MARKERS):
        append_result(results, IDT.MINIAPP_PATH_MODULE, s, src, sid)
        return

    # 6. 排除组件引用路径 (/components/xxx、/component/xxx、/wxcomponents/xxx、
    #    /vant/xxx、/components-common/xxx、/commpents/xxx，且不含 api/v1 等 API 特征)。
    #    原先 /components/ 判 1906、下面几种组件库前缀判 1905，同一个函数里两处口径不一致。
    #    取证后统一到 1906（MINIAPP_PATH_MODULE）：
    #      - 两族的上下文分布几乎重合，本就该是同一类型（三库实测 usingComponents
    #        占比 /components/ 96.0%~97.3%、/wxcomponents/ 93.9%~97.5%、
    #        /component/ 95.1%~96.1%；require/import 都只有 0.1%~1.8%）。
    #      - 1906 桶里 ref_count 最高的值全是被 usingComponents 引用的组件目录
    #        （/components/loading 14751 次、/components/aiCreateTip/index 14532 次），
    #        1905 桶里最高的全是 .png/.svg（/utility/banner/plz_wait_2.png 2415 次），
    #        两个桶既有的语义已经定死：组件引用属于 1906。
    #      - 改动量也支持这个方向：挪小族（/wxcomponents 等 1,317 值）比挪大族
    #        （/components/ 42,379 值）小 30 倍以上。
    if s_lower.startswith(MINIAPP_COMPONENT_PREFIXES) and not has_keyword_substring(s_lower, MINIAPP_API_PATH_PATTERNS):
        append_result(results, IDT.MINIAPP_PATH_MODULE, s, src, sid)
        return

    # 7. 带查询参数的 API 路径
    if "?" in s and "=" in s:
        process_url_query_string(s, stmt, src, sid, results)
        append_result(results, IDT.MINIAPP_API_PARAMS, s, src, sid)
        return

    # 8. 敏感路径关键字检测 (login/auth/pay/admin 等)
    for keyword, slug_id in URL_SENSITIVE_KEYWORDS.items():
        if keyword in s_lower:
            # 小程序/H5 页面路由不是后端接口：页面名里的 pay/alipay/repayment/login/
            # admin 只是路由词，不该被裸子串匹配吞成支付/登录/后台接口（见
            # is_miniapp_page_route）。
            if is_miniapp_page_route(s):
                process_prefixed_miniapp_pages(s, 0, stmt, src, sid, results)
                return
            append_result(results, slug_id, s, src, sid)
            return

    # 9. 小程序页面/分包路由（必须先于第 10 步的后端路径兜底）
    #    第 8 步只在「路径含敏感关键字」时才调 is_miniapp_page_route，不含敏感词的页面
    #    路由会直接掉到第 10 步。实测：三库 miniapp_api_params 里 10.9%~13.0% 的值本就是
    #    页面/分包路由（/pages/…、/packageA/…、/subPackages/…），上下文是
    #    e.redirectToAction("/packageI/pages/mall/mall",e) 这类导航调用 —— 不是接口。
    #    本步三库分别改判 8,472 / 10,180 / 18,011 个值到页面路径。
    #    这里复用第 8 步同一个 helper + 同一个分发函数（含 page_path_sensitive 分流），
    #    只把「去向」从 api_params 改成页面路径，不丢弃任何值。
    #    注（2026-10 复核）：这里原先写「含 ?&= 的值在第 7 步就被 process_url_query_string
    #    吃掉了，到不了这里」——本轮证明该判断不成立。第 7 步对斜杠路径不可达（探针实测
    #    三库语料 1,623,044 个 (值, 上下文) 对命中 0 次），带 ?&= 的值其实是在
    #    perform_constant_classifying 的 is_miniapp_api_params 门就被截住的，根本进不了
    #    本函数。本轮已在那道门上补了同一条页面判断（见 process_miniapp_api_params），
    #    带参页面路由不再漏到兜底桶里。
    if is_miniapp_page_route(s):
        process_prefixed_miniapp_pages(s, 0, stmt, src, sid, results)
        return

    # 10. 后端 API 路径特征判断
    #    - 去掉开头的 / 后，至少有一段包含字母
    #    - 长度 >= 4
    #    - 不是纯数字路径
    segments = [seg for seg in s.strip("/").split("/") if seg]
    if not segments:
        return
    has_alpha_segment = any(any(c.isalpha() for c in seg) for seg in segments)
    if has_alpha_segment and len(s) >= 4:
        append_result(results, IDT.MINIAPP_API_PARAMS, s, src, sid)
        return


def process_generic_unknown_constant(s: str, stmt: str, src: str, sid: int, res: list):
    """处理未知类型的常量，统一归类为 OTHER"""
    append_result(res, IDT.OTHER, s, src, sid)



# =========================================================
# 前端框架/构建产物标记（结构性拦截）
# =========================================================
# Vue scoped CSS：Vue 编译 SFC 时给每个组件生成一个 hash，DOM 元素上挂
# data-v-<hash> 属性，配套 CSS 选择器 [data-v-<hash>]。uni-app / Taro 编译到
# 小程序后同样保留。它是编译产物，永远不是密钥。
#
# 不拦这些标记时，同一个 data-v-10bfb526 会被判成 cloud_cred_password(5)、
# platform_app_secret(5)、platform_access_token(5)、payment_pay_sign(4)、
# payment_request_params(3)、payment_sign_type(1)、saas_analytics_key(1) ——
# 7 个互不相干的类型，逐个给判定函数打补丁既漏又不收敛。因此在分类链最前面
# 统一拦截，一次覆盖全部受影响类型。
#
# 直接丢弃（不产出任何类型）：
#   1) 框架产物是编译器的确定性产物，不是「待定」的未知常量 —— 记进 other(9901)
#      只是把它从「7 个高敏感桶」挪到「unknown 桶」，噪音并没有真正消失。
#   2) 新库 unlist_icp_filing_v2 实测：other(9901) 197013 个值里 131516 个是这类
#      产物（占该桶 66.75%、占全库 data_item 20.11%），而加闸门之前扫出来的旧库
#      other 桶里只有 0 个 —— 这 13 万条本来就不该入库。
#   3) 框架产物不是个人信息，放 pii_noise(2304) 会污染 PII 分类的语义，所以
#      「丢弃」比「换个 risk0 的桶」更准确。
# 注：同一段代码里的 is_w3c_namespace_url（W3C/XML 命名空间）仍判 other(9901)，
# 本次不动 —— 那是 16 个值，且是「协议常量」而非「编译产物」，口径不同。
VUE_SCOPE_HEX = r"[0-9a-f]{6,10}"
# 裸 scope 标记: data-v-10bfb526
RE_FW_VUE_SCOPE_BARE = re.compile(rf"^data-v-{VUE_SCOPE_HEX}$")
# 逗号/分号接组件名: data-v-d23bceb8,wx-video. / data-v-b62b882e,wx-view.
RE_FW_VUE_SCOPE_LIST = re.compile(rf"^data-v-{VUE_SCOPE_HEX}[,;]")
# 类名 + scope 复合（值以 data-v-<hash> 结尾、且紧邻前置字符是空格或下划线）:
#   secretFree data-v-3db3bba7
#   secret-pr-textarea _div data-v-973c8bc8
RE_FW_VUE_SCOPE_COMPOSITE = re.compile(rf"^.+[ _]data-v-{VUE_SCOPE_HEX}$")
# Vue 模板指令: v-bind:title.once / v-bind:descript.sync / v-on:confirm / v-model / v-if
# else-if 放在 else 之前，避免 "v-else-if" 先匹配到 else 再卡在 '-' 上
RE_FW_VUE_DIRECTIVE = re.compile(
    r"^v-(?:bind|on|if|else-if|else|for|model|show|html|text|slot|cloak|once|pre)(?:[:.]|$)"
)
# WXML 属性命名空间前缀：wx:if / wx:for / wx:key / wx:scope-data / wx:for-item。
# 出处是平台运行时 page-frame.html（微信小程序页面框架，非业务代码）：
#   if(e.tag=="wx-wx-scope"){e.tag="virtual";e.wxCkey="11";
#      e["wxScopeData"]=e.attr["wx:scope-data"]; ...}
# 属性名在这儿以字符串形式进了运行时，被当成常量提取出来；模板属性名永远不是密钥。
# 只认「冒号」形态，且属性名必须全小写（WXML 规范）：
#   wx.request 是 API 调用（点号）、wx-video 是内置组件名（连字符），都不匹配。
RE_FW_WXML_ATTR = re.compile(r"^wx:[a-z][a-z0-9-]*$")


# =========================================================
# HTTP 头名（协议常量，不是凭证）
# =========================================================
# 问题：`x-expire-timestamp` / `cache-control` / `X-Auth-Token` 这类**头名**被 5 个
# 互不相干的类型各判一次。三库去重实测（本报告的量化口径）：
#   payment_request_params(3) 66 值/10159 次、server_cred_cookie(5) 25 值/3390 次、
#   payment_nonce(3) 4 值/67 次、cloud_bucket_name(2) 10 值/42 次、
#   saas_analytics_key(1) 2 值/16 次、cloud_cred_cookie(4) 1 值/1 次、
#   cloud_cred_password(5) 1 值/0 次。
# 逐个给那 5 个判定函数打补丁既不收敛也易漏，所以仿 is_framework_artifact 统一拦截。
#
# 为什么**不用裸 x- 前缀**：
#   抽样三库源文件（test-result/fix10_xprefix_scan.py，12 万文件）里以 x-/X- 开头的
#   不同字面量 374 个，裸前缀会把 374 个全收；其中 214 个不是头名 ——
#   CSS 字号 `x-large`(111 次)/`x-small`(109 次)、组件名 `x-popup`/`x-nav`/`x-icon`/
#   `x-modal`/`x-toast`、属性名 `x-attribsPrefix`/`x-attribsNamespace`、
#   选择器 `x-head-carousel-component .`、拼接前缀 `x-cos-meta-` 等。
#   因此收严成「枚举 + 结构模式」两部分。
#
# 判据 A：标准头名枚举（RFC 7230/7231/7234/7235 与常见 CORS/安全头）。
HTTP_HEADER_NAMES = frozenset({
    "accept", "accept-charset", "accept-encoding", "accept-language", "accept-ranges",
    "access-control-allow-credentials", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-allow-origin",
    "access-control-expose-headers", "access-control-max-age",
    "access-control-request-headers", "access-control-request-method",
    "age", "allow", "authorization", "cache-control", "connection",
    "content-disposition", "content-encoding", "content-language", "content-length",
    "content-location", "content-range", "content-security-policy", "content-type",
    "cookie", "date", "etag", "expect", "expires", "forwarded", "from", "host",
    "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since",
    "last-modified", "link", "location", "max-forwards", "origin", "pragma",
    "proxy-authenticate", "proxy-authorization", "range", "referer", "referrer",
    "retry-after", "server", "set-cookie", "strict-transport-security", "te",
    "trailer", "transfer-encoding", "upgrade", "user-agent", "vary", "via", "warning",
    "www-authenticate", "x-content-type-options", "x-frame-options", "x-xss-protection",
    # 事实标准 / 云厂商约定头（只有一张 `-`，结构模式覆盖不到，只能枚举）
    "x-requested-with", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
    "x-real-ip", "x-csrf-token", "x-xsrf-token", "x-api-key", "x-request-id",
    "x-correlation-id", "x-trace-id", "x-sdk-version", "x-seqid", "x-amz-signature",
    # 三库实测出现的两段式头名（x-timestamp / x-nonce / X-Signature / X-Token /
    # x-auth 都在真实头名声明语境里，见 report 里的 source_snippet 证据）
    "x-timestamp", "x-nonce", "x-signature", "x-token", "x-auth", "x-client-time",
})
# 判据 B：x- 厂商头名的结构模式 —— 值必须形如 `x-段-段`，即整值至少含**两个**连字符
# （x- 之后再接两段以上 `-` 分隔的字母数字），并允许一个结尾的 `=`（x-amz-signature=
# 这种签名 URL 参数名形态）。
# 为什么必须「两个连字符」而不是裸前缀：CSS 字号 x-large/x-small、组件名
# x-popup/x-nav/x-icon/x-modal/x-toast、属性名 x-attribsPrefix/x-systemId、
# 拼接前缀 x-cos- 都只有**一个**连字符（或带非字母数字字符），会被这条挡在外面；
# 而库内实测到的头名（x-expire-timestamp / x-account-key / x-cos-copy-source /
# X-TAI-ChannelId / X-TT-ENV …）全都有两个以上连字符。
RE_HTTP_X_HEADER = re.compile(r"^x-[a-z0-9]+(?:-[a-z0-9]+)+=?$")


def is_http_header_name(s: str) -> bool:
    """判断是否为 HTTP 头名/协议参数名（**名字**本身，永远不是密钥材料）。

    语境证据（三库 miniapp_to_dataitem.source_snippet）：
        v["X-TimeStamp"] = g
        signHeaderKeys:["x-data-api-type","x-expire-timestamp"]
        delete o["x-cos-copy-source"],delete o["x-cos-metadata-directive"],...
        u["X-PA-NONCESTR"]=1
        "X-Auth-Token": wx.getStorageSync("cookie")
    即：值出现在**头名位置**（对象键 / 头名数组元素），真正的密钥是它对应的另一个值。
    """
    low = s.lower()
    if low in HTTP_HEADER_NAMES:
        return True
    return bool(RE_HTTP_X_HEADER.match(low))


# =========================================================
# HTML data-* 属性名（模板属性名，不是凭证）
# =========================================================
# 问题：`data-sid` / `data-index` / `data-timestamp` / `data-password` 这类
# **HTML 自定义数据属性名**被 7 个互不相干的类型各判一次。三库实测（口径：库内
# `raw_value LIKE 'data-%'` 的全部值，见 test-result/fix12/measure_data_attr.py）：
#   cloud_cred_password(5) 67 值/422 次、payment_request_params(3) 15 值/98 次、
#   cloud_bucket_name(2) 5 值/10 次、payment_sign_type(1) 3 值/11 次、
#   saas_analytics_key(1) 2 值/79 次、saas_map_key(2) 1 值/2 次、
#   server_cred_cookie(5) 1 值/5 次；**非凭证类型（真接口/真 key）里 0 值**。
# 逐个给判定函数打补丁既不收敛也易漏（同 fix10 对头名的理由），因此统一拦截。
# 本次修复的直接动因：fix11 把 is_payment_param 的值侧判据收严成「值 == 参数名」
# 之后，原先靠自指子串混进 payment_request_params(3) 的这一族改由 is_cloud_password
# 接住（其语境词表含 password/timestamp/pwd），噪音从 risk3 升到 risk5 —— 不拦它
# 比不修更糟。
#
# 为什么这里**可以用裸 data- 前缀**（不像 fix10 的 x- 必须收严成枚举+结构模式）：
#   data- 是 HTML 规范为「自定义数据属性」保留的**专有前缀**，x- 不是 —— 任何
#   `data-*` 字符串都在声明「这是个属性名」，而 `x-*` 还同时是 CSS 字号(x-large)、
#   组件名(x-popup)、变量名(x-attribsPrefix)。量化依据：
#     · 三库 data_item 里 `LIKE 'data-%'` 的全部值 100% 落在上表 7 个凭证类桶、
#       且逐个查 source_snippet 全是属性名位置（`_mz(z,'input',[...'data-id'...])`
#       这类「元素+属性名表」编译产物、CSS 选择器、`["__scopeId","data-v-exO"]`）；
#       miniapp_api_params / other / PII 等桶里一个都没有 —— 不存在「真接口/真 key
#       以 data- 开头」的实例。
#     · 抽样三库源文件（test-result/fix12_data_prefix_scan.py；三库解包目录共
#       4,470,284 个 js|json|wxml|wxss|wxs|html，按包目录分层随机抽样 9 万）里
#       `data-` 字面量 26,395 个，命中本模式的 3,769 个全部是「名字」：2,770 个是
#       fix7 已拦的 data-v-<hash>，其余是属性名（data-event-opts/data-index/data-sid/…）、
#       以 data- 开头的 BEM 类名（data-card__right__top）、`__scopeId` 值；
#       其中含 16 位以上 hex 的 **0 个**、前缀大写 `DATA-` 的 **0 个**。
#       => 裸前缀不会误伤真凭证，无需收严。
# 与 is_framework_artifact 的关系：不重复也不冲突 —— 那边管的是 `data-v-<hash>`
# （Vue scoped 标记，含 `data-v-xxx,`/`data-v-xxx{`/`类名 data-v-xxx` 等复合形态，
# 这里匹配不到）与 v-/wx: 指令；本判据只覆盖「纯属性名形态」的 data-*。二者对
# 裸 `data-v-<hash>` 都能命中且**归置相同**（都是丢弃），所以行为不变。
#
# 直接丢弃（不产出任何类型），与 fix7/is_framework_artifact 的归置一致：
#   属性名不是密钥材料（真值在 `attr="value"` 的值侧），也不是个人信息；
#   现有类型里没有「HTML 属性名」这一档，constant_types.json 本次冻结，
#   记进 other(9901) 只会把噪音从 7 个桶挪到 unknown 桶（见 is_framework_artifact
#   注释里的 13 万条实测），所以按「不制造错误的标签」处理：丢弃。
RE_HTML_DATA_ATTR = re.compile(r"^data-[A-Za-z0-9_-]+$")


def is_html_data_attr_name(s: str) -> bool:
    """判断是否为 HTML 自定义数据属性名（`data-*` 形式的**名字**，不是密钥材料）。

    属性名允许大小写混写与下划线（编译产物实测 `data-hasPassword` /
    `data-ctLineId` / `data-pwdType` / `data-my_time` / `data-devtool_`），
    只要求 `data-` 前缀本身全小写（HTML 规范里属性名小写；抽样 9 万文件里的
    字面量实测无 `DATA-` 形态）。裸 `data-`（5 字符，源里是 `e.startsWith("data-")` 的前缀
    判断）**不拦** —— 它不是属性名，也从未被任何类型误收。

    语境证据（三库 miniapp_to_dataitem.source_snippet，属性名表位置）：
        oB=_mz(z,'input',['adjustPosition',238,'bindblur',3,'data-sid',6,...],...)
        oTWD=_mz(z,'image',['catchtap',69,'class',1,'data-img',2,'data-index',3,...])
        eHG=_mz(z,'view',['bindtap',29,'class',1,'data-designType',2,'data-name',3])
    """
    return bool(RE_HTML_DATA_ATTR.match(s))


def is_framework_artifact(s: str) -> bool:
    """判断是否为前端框架/构建产物标记（编译产物，不可能是凭证）。

    覆盖 Vue scoped CSS 的 data-v-<hash> 家族、Vue 模板指令、WXML 的 wx: 属性名。

    廉价预过滤后再上正则：
      - data-v-<hash> 三兄弟（裸/逗号/复合）都含子串 "data-v-"；
        复合形态的值以任意类名开头（如 secretFree），不能按首字符过滤，
        这里必须用子串判断，否则 secretFree data-v-3db3bba7 会被漏掉。
      - Vue 模板指令以 "v-" 开头。
      - WXML 属性名以 "wx:" 开头（wx:scope-data 原先被判成 cloud_cred_password(5)）。
    """
    if "data-v-" in s:
        return bool(
            RE_FW_VUE_SCOPE_BARE.match(s)
            or RE_FW_VUE_SCOPE_LIST.match(s)
            or RE_FW_VUE_SCOPE_COMPOSITE.match(s)
        )
    if s.startswith("v-"):
        return bool(RE_FW_VUE_DIRECTIVE.match(s))
    if s.startswith("wx:"):
        return bool(RE_FW_WXML_ATTR.match(s))
    return False


# =========================================================
# URL 查询片段 / CSS 选择器 / CSS 模块类名（语法片段，不是凭证）
# =========================================================
# 问题：把一条 URL 或一段模板编译产物按 `&` / `^` / `-module__` 切开之后，切出来的
# **语法片段本身**被当成常量收进了库，并被凭证类判定函数接住。三库实测（口径：库内真实
# (值,上下文) 重跑当前代码，见 test-result/fix13/a_census.py；按「裸前缀族」统计）：
#   A. `&` 开头    cloud_cred_password(5) 164 值/1965 次、cloud_cred_cookie(4) 14 值/74 次
#   B. `^` 开头    cloud_cred_password(5)   7 值/58 次
#   C. `-module__` cloud_cred_password(5)  12 值/14 次、saas_map_key(2) 1 值/4 次
# 典型的头几名：`&callBack=`(46 次) `&password=`(44) `^navigate`(22) `&target=`/`&username=`(各 14)
# `&newPassword=`(8) `^stillPassword`(4) `LoginPage-module__pwd-input___nXiLS`。
# 逐个给判定函数打补丁既不收敛也易漏（同 fix10/fix12 对头名、data-* 的理由），因此统一拦截。
#
# 为什么**不用 `.` 开头**当判据（本轮的硬约束）：
#   `other` / `miniapp_path_module` / `miniapp_api_params` 里以 `.` 开头的值极多
#   （normal_sibling 的 other 一个桶就 2.7 万），其中 `./components/foo`、`../utils/x`
#   是**合法的相对路径**，按前缀拦会成片误伤路径类常量。所以本轮只收拢下面三小类。
#
# 为什么判据必须**收窄**（实测误伤，本轮最关键的取舍）：
#   三小类的「裸族」里，A 族远不是同质的：最宽的写法「`&` 开头」、甚至「`&名=值`」，
#   都会把**查询串里内嵌的真 key** 一起丢掉。实测（test-result/fix13/f_embedded_secret.py）
#   这类条目共 163 条 / 136 个去重值，例如：
#       `&key=97b588d3e3e852c4acbe118886022078`       （高德 key，20 次）
#       `&key=UBNBZ-PTP3P-TE7DB-LHRTI-Y4YLE-VWBBD`    （腾讯地图 key，12 次）
#       `&key=8b650dd596444be8bb603d181591cba6`       （MD5 签名密钥）
#       `&token=b8e41f749d861dda`
#   因此 A 族收成「**整个值就是一个空值参数名**」的 `&名=` 形态 —— 右侧没有内容，
#   结构上不可能内嵌任何东西（实测内嵌敏感值 0 条）。宽写法同时会吃掉
#   `&serviceDir=/api/public/index.php?service=X`（真接口端点，miniapp_api_params 30 值）
#   与 `&emsp;&emsp;电子邮箱：id@189.cn`（PII_EMAIL_NAME），收窄后两者都留住。
#   `^标识符` 与 `-module__` 两条同理收成全值匹配：`^1\d{10}$` 这类**校验用正则**
#   含反斜杠、`^1.2.3` 这类 semver 数字开头，都匹配不到。
#
# 为什么是「丢弃」而不是改判：
#   URL 查询片段不是密钥材料（真值在 `=` 的右侧），CSS 选择器/类名更不是；
#   现有类型里没有对应档位，constant_types.json 本轮冻结。三库实测这三条判据命中的值
#   在库内**从未**落到任何真凭证类型（platform_app_secret / cloud_cred_ak_sk_pair /
#   saas_analytics_key / server_url_* 等 0 条），只落在凭证类误报桶 + other(0)。
#   把 other 桶里的这部分也一并去掉：它们同样只是切碎的语法片段
#   （抽 40 个去看，全部形如 `&goodsType=3` / `^toCardDetail` / `index-module__pwd___a1Xy`）。
#   唯一被顺带清掉的非 risk>=4 项是 saas_map_key(2) 的
#   `index-module__content-wrap___2AMAP` —— 该值是类名里撞上 `AMAP` 造成的既有误报。
#
# ⚠️ 口径坑（本轮实测踩到，供后续复用）：MySQL 的 `LIKE` 里 `_` 是「任意单字符」通配符，
#   `raw_value LIKE '%-module__%'` 的真实语义是 `%-module` + 任意 2 字符 + `%`，会把
#   `/login-module/auth/login`（**真接口路径**）也捞进来（三库多捞 2,880 条 (值,类型)）。
#   所以体检/复现一律用 `INSTR(raw_value,'-module__') > 0` 或转义后的 `LIKE`。
RE_URL_EMPTY_PARAM = re.compile(r"^&[A-Za-z][A-Za-z0-9_.\-]*=$")
RE_CSS_CARET_TOKEN = re.compile(r"^\^[A-Za-z_][A-Za-z0-9_\-]*$")
RE_CSS_MODULE_CLASS = re.compile(r"^[A-Za-z0-9_#][A-Za-z0-9_\-]*-module__[A-Za-z0-9_\-]+$")


def is_url_query_or_css_fragment(s: str) -> bool:
    """判断是否为被切碎的 URL 查询片段 / CSS 选择器 / CSS 模块类名（**语法片段**，不是凭证）。

    三条判据都是**全值匹配**，且都只覆盖「结构上不可能承载秘密」的形态：
      - `&参数名=`  —— 整个值就是一个空值参数名（`&password=` / `&callBack=`）；
        右侧没有内容，所以不会把 `&key=<真 key>` 一起吞掉。
      - `^标识符`   —— 模板编译产物里的属性/事件选择器名（`^navigate` / `^stillPassword`）；
        校验用正则（`^1\\d{10}$`）含反斜杠、semver（`^1.2.3`）数字开头，都匹配不到。
      - `名-module__名` —— CSS Modules 产物类名（`LoginPage-module__pwd-input___nXiLS`）。

    语境证据（三库 miniapp_to_dataitem.source_snippet）：
        url:e.default.host+"/oauth/token?grant_type=password&username="+a+"&password="+d
        Z([[4],[[5],[[4],[[5],[[5],[1,'^stillPassword']],[[4],[[5],[[4],[[5],[1,'stillPassword']]]]]]]]])
        "pwd-input": "LoginPage-module__pwd-input___nXiLS"
    """
    if s.startswith("&"):
        return bool(RE_URL_EMPTY_PARAM.match(s))
    if s.startswith("^"):
        return bool(RE_CSS_CARET_TOKEN.match(s))
    if "-module__" in s:
        return bool(RE_CSS_MODULE_CLASS.match(s))
    return False


# =========================================================
# 工具链产物：框架 / 编译器 / 运行时生成的符号与语法片段（结构性拦截）
# =========================================================
# 问题：三个消息库里有整整一族值**不是代码作者写的常量**，而是工具链吐出来的中间物。
# 三库实测（口径：库内真实 (值,上下文) 重跑当前代码，见 test-result/fix14/a_census.py）：
#   A. `;`  开头   29,905 值 / 1,389,145 次
#   B. `__` 开头    6,621 值 /   228,445 次
#   C. `@@` 开头      168 值 /    75,675 次
#   合计 36,694 值 / 1,693,265 次（≈全库出现次数的 9%）。
# 落桶：`other`(0) 几乎全部，另有 4 个凭证误报桶 —— server_cred_cookie(5) 205 次、
#   cloud_cred_password(5) 30 次、cloud_cred_cookie(4) 2 次、saas_analytics_key(1) 4 次。
#
# 这族与 is_framework_artifact（fix7 拦的 data-v-<hash> / v- / wx:）是同一类东西：
# 都不是代码作者写的常量，是工具链生成的。但**判据形态不同**，所以另立一个函数
# （理由见下）：fix7 那套是「标记名**全值**匹配」（32 项断言里 29 个反例专门证明
# `v-binder-secret-…` / `myData-v-12345678` / `data-vault-key-…` 这类近似形态不被误吞），
# 本条是「**保留前缀**」——精度来自前缀本身被生态圈保留，而不是来自全值形状。
#
# ---- 三族各自的来源与边界（逐条量化，本轮重点是误伤体检）----
# A. `;` 开头 = WXSS 被内联进 JS 后切碎的样式片段。
#    来源已确证（三库 source_snippet）：
#        __wxAppCode__['pages/goods/index.wxss'] = setCssToHead([[2,"./pages/goods/index.wxss"], …
#        setCssToHead(["@charset \x22UTF-8\x22;\nwx-view{font-size:",[0,28],";lin…
#    setCssToHead 按「动态值占位」把 wxss 切开，切出的每一片都以 `;` 开头
#    （头几名 `;height:` 65,449 次 / `;line-height:` 60,411 / `;padding:` 55,884）。
#    它们是代码里**真实的字符串字面量**，提取器没做错 —— 是这些值本来就不算「常量」。
#    **误伤体检（本轮最关键）**：29,905 个值逐个过 9 条硬线索（URL / 域名 / 中文 /
#    hex>=16 / key|token|secret 词 / appid / 路径 / @ / 高熵），命中的全部人工过目：
#      · SQL 片段 0 个（含 SQL 关键字 29 个全部是 CSS 的 `user-select`；
#        三库 `LIKE '%SELECT %FROM%'` 的 SQL 语句**无一以 `;` 开头**）；
#      · JSON 片段 0 个（JSON 以 `{`/`[` 开头，与前缀互斥）；
#      · 含 `=` 且右侧有内容的只有 44 个，逐个看过全是 cookie 属性 / charset /
#        查询参数（`;charset=utf-8`、`;path=/;domain=.ktvme.com`、`;page_size=20;page_index=1`），
#        **没有一条内嵌真密钥**（与 fix13 的 `&key=<真 key>` 情形不同：`;` 是头/样式分隔符，
#        其右值是运行时拼接上去的动态量，静态字面量里没有密钥材料）；
#      · 手写 CSS 常量**不受影响**：判据是前缀匹配，`"width:100px"` / `"display:none"`
#        这种不以 `;` 开头的值根本进不来。爆炸半径实测：库里「含 `;` 但不在首位」的值
#        有 1,818 + 6,228 + 18,890 个（如 `0;width:`、`!important;position:relative;width:`），
#        本轮**一个都不动**。
# B. `__` 开头 = 框架 / 编译器 / 运行时的内部符号（JS 双下划线约定）。
#    头部：`__scopeId` 32,421 次（Vue scoped 样式）、`__set_model` 24,050（WXML 数据绑定）、
#    `__wxspec__` 14,071（微信框架）、`__DC_STAT_UUID` 7,825（统计 SDK）、
#    `__webpack_require_UNI_MP_PLUGIN__` 3,561（webpack）、`__compileDebugInfo__` 3,050（编译信息）。
#    **误伤体检**：6,621 个值当前只落 other(0) 与 4 个误报桶，落到非 other 的**只有 6 个**，
#    逐个看过全是误报（`__password` / `__password--active` / `__password--dot` 是 BEM 元素类名；
#    `__wj_userid=` / `__cube__tm=` 是 cookie 名；`__sentry_xhr_v3__` 是 Sentry 标记名）。
#    JS 内建 dunder（`__proto__`）**不在库**；base64/hex 密钥的字母表分别是 A-Za-z0-9+/ 与
#    0-9a-f，**结构上不可能以 `__` 开头**，所以「以 `__` 开头的真密钥」不存在。
#    注：B 族里最大的一块是 `__plugin__/wx…/pages/…`（1,274 值 / 24,139 次），
#    即小程序插件的虚拟路径（`__plugin__/` 前缀由编译器注入）——当前同样落 other(0)，
#    丢弃不损失任何已分类产出。
# C. `@@` 开头 = JS 语言内部 well-known symbol + 各框架的 action 前缀。
#    头部：`@@iterator` 39,885 次、`@@toStringTag` 15,543、`@@asyncIterator` 13,217、
#    `@@__IMMUTABLE_*__@@`、`@@redux/*`、`@@DVA_*`、`@@transducer/*`、`@@taro-*`。
#    **误伤体检**：168 个值已**全量列出**逐个过目，无一例外都是框架内部标记。
#    邮箱/句柄不会被误伤 —— 邮箱的 local-part 不能以 `@` 开头，三库含 `@` 且含 `.` 的
#    13,527 个值里**没有一个以 `@@` 开头**。
#
# ---- 为什么是「丢弃」而不是改判 ----
# 与 fix7 / fix10 / fix12 / fix13 的归置一致：这些值不是密钥材料，现有类型里没有
# 「工具链中间物」这一档（constant_types.json 本轮冻结），记进 other(9901) 只是把噪音
# 从几个误报桶挪到 unknown 桶、噪音并没有消失（fix7 注释里的 13 万条实测）。所以按
# 「不制造新的错误标签」处理：丢弃，不产出任何类型。
#
# ⚠️ 口径坑（本轮实测踩到，供后续复用）：MySQL 的 `LEFT(x,1) = CHAR(59)` 在
#   utf8mb4_unicode_ci 下**同时匹配全角 `；`(U+FF1B)** —— 三库 A 族各有 8/1/9 条是全角
#   分号开头的中文 UI 文案（`；如您预约成功的时间为10:30…`），而 Python 的
#   `s.startswith(";")` 只认 ASCII 分号。所以普查一律用 `HEX(LEFT(...))` 精确比码点。
#   同理，`LIKE` 里 `_` 是「任意单字符」通配符，B 族的 `__` 绝不能用 `LIKE '__%'` 匹配。
TOOLCHAIN_ARTIFACT_PREFIXES = (";", "__", "@@")


def is_toolchain_generated_artifact(s: str) -> bool:
    """判断是否为框架 / 编译器 / 运行时生成的符号或语法片段（工具链产物，不是常量）。

    三条判据都是**保留前缀**，覆盖「作者不可能这么写」的三种开头：
      - `;`  —— 语句/声明分隔符开头。wxss 被 setCssToHead 内联进 JS 后切出的样式片段
               （`;height:`），以及拼接到已有串尾部的 cookie 属性片段（`;PHPSESSID=`）。
               正常常量（手写 CSS `width:100px`、SQL、JSON）都不以 `;` 开头。
      - `__` —— JS/生态圈的「内部符号」约定。Vue/微信/webpack/lodash/sentry 等
               框架内部字段与编译器注入的虚拟路径（`__scopeId` / `__plugin__/wx…`）。
      - `@@` —— ECMAScript well-known symbol 的书写形式（`@@iterator`）与各状态管理
               框架的 action 前缀（`@@redux/INIT` / `@@DVA_LOADING/HIDE`）。

    与 is_framework_artifact 的分工：那边管**标记名**（`data-v-<hash>` / `v-bind:x` /
    `wx:y`，全值正则匹配，怕误吞 `v-binder-secret-…` 这类近似值）；本条管**开头**，
    精度来自前缀被生态圈保留（实测三库 36,694 个值里真阳性 0 个，见上方注释）。

    语境证据（三库 miniapp_to_dataitem.source_snippet）：
        __wxAppCode__['pages/goods/index.wxss'] = setCssToHead([[2,"./pages/goods/index.wxss"]…
        setCssToHead(["@charset \x22UTF-8\x22;\nwx-view{font-size:",[0,28],";lin…
        t.header.Cookie = "oid=".concat(u("moid") || "", "; sessionid=").concat(…
        ["__scopeId","data-v-exO"]
        o.cookie="".concat(o.cookie?"".concat(o.cookie,";"):"","__wj_userid=").concat(s)
        @@iterator  /  @@__IMMUTABLE_KEYED__@@  /  @@redux/INIT
    """
    return s.startswith(TOOLCHAIN_ARTIFACT_PREFIXES)


# =========================================================
# 主分类函数
# =========================================================
def perform_constant_classifying(statements: List[str], constants: List):
    """对常量进行分类"""
    res = []
    processed_indices = set()
    truncated_contexts = {}

    for i, (s, sid, src) in enumerate(constants):
        if i in processed_indices:
            continue
        assert sid < len(statements) and len(s) >= 4

        raw_stmt = statements[sid]
        if sid not in truncated_contexts:
            truncated_contexts[sid] = extract_context(raw_stmt, s, 512)
        stmt = truncated_contexts[sid]

        consumed = False
        s_lower = s.lower()

        # =========================================================
        # 框架/构建产物标记（结构性拦截，必须早于所有类型判定）
        # =========================================================
        # data-v-<hash> 会被 is_cloud_password / is_secret_key / is_payment_param /
        # is_analytics_key 等多个互不相干的判定函数各自误伤，且误判结果随上下文
        # 漂移。在这里一次性拦掉，比逐个补 7 个判定函数更收敛。
        # 命中即丢弃：不产出任何类型，值不进 data_item。
        if is_framework_artifact(s):
            continue

        # =========================================================
        # HTML data-* 属性名（模板属性名，不是凭证）—— 结构性拦截
        # =========================================================
        # 与 is_framework_artifact 同属「标记名」拦截，但覆盖的是**纯属性名形态**
        # 的 data-*（data-sid / data-index / data-timestamp / data-password …），
        # fix7 的 data-v-<hash> 复合形态这里匹配不到、仍由上一段负责。
        # 归置同为丢弃，依据见 is_html_data_attr_name 的注释与报告：
        # 三库 `LIKE 'data-%'` 的值 100% 是属性名/类名/scope 标记，且只落在
        # 7 个凭证类桶（真接口/真 key 类型里 0 值），现有类型里没有「HTML 属性名」档。
        if is_html_data_attr_name(s):
            continue

        # =========================================================
        # HTTP 头名（协议常量，不是凭证）—— 结构性拦截
        # =========================================================
        # 与 is_framework_artifact 同样是「一次拦掉，而不是补 5 个判定函数」，
        # 但归置不同：见 is_http_header_name 的 docstring 与报告 ——
        # 实测语境 100% 是「头名声明」，值本身是名字不是材料；
        # 现有类型里没有「HTTP 头名」这一档（miniapp_api_params 的语义是后端 API 路径，
        # cloud_bucket_name/payment_* 都是别的语义），constant_types.json 本次冻结，
        # 所以按「不制造新的错误标签」处理：丢弃，不改判到任何既有类型。
        if is_http_header_name(s):
            continue

        # =========================================================
        # URL 查询片段 / CSS 选择器 / CSS 模块类名（语法片段）—— 结构性拦截
        # =========================================================
        # 与 is_http_header_name 同样是「一次拦掉，而不是补 N 个判定函数」，归置同为丢弃。
        # 三库实测本判据清掉的 risk>=4 误报：cloud_cred_password 143 值/1924 次、
        # cloud_cred_cookie 8 值/19 次；顺带清掉 saas_map_key(2) 的 1 值/4 次
        # （类名撞上 AMAP 的既有误报）。risk>=4 总出现次数 2111 -> 168，
        # **没有任何新噪音进 risk>=4 桶**；miniapp_api_params(1) 30 值/62 次、
        # pii_email_name(3) 1 值/1 次原样不动。
        # 误伤边界（内嵌 key、路径类常量、`.` 相对路径）见 is_url_query_or_css_fragment 注释。
        if is_url_query_or_css_fragment(s):
            continue

        # =========================================================
        # 工具链产物：框架/编译器/运行时生成的符号与语法片段 —— 结构性拦截
        # =========================================================
        # 与 is_framework_artifact 同一族（都不是作者写的常量），但判据形态不同：
        # 那条是全值匹配「标记名」，本条是保留前缀「`;` / `__` / `@@` 开头」。
        # 归置同为丢弃，依据见 is_toolchain_generated_artifact 的注释与报告：
        # 三库 36,694 值 / 1,693,265 次命中，逐族做完误伤体检（真阳性 0 个）：
        #   `;`  29,905 值 —— SQL/JSON 0 个、内嵌真密钥 0 个、手写 CSS 前缀不匹配；
        #   `__`  6,621 值 —— 落到非 other 的只有 6 个且全是既有误报；
        #   `@@`    168 值 —— 全量过目，全是框架内部标记（邮箱不可能以 `@` 开头）。
        # 清掉的 risk>=4 误报：server_cred_cookie 205 次、cloud_cred_password 30 次、
        # cloud_cred_cookie 2 次（另 saas_analytics_key(1) 4 次）—— **没有新噪音进 risk>=4 桶**
        # （纯丢弃不会新增产出，实测见 test-result/fix14/f_before_after.py）。
        if is_toolchain_generated_artifact(s):
            continue

        # =========================================================
        # 高频类型优先检测
        # =========================================================
        # URL
        for pattern in URL_PREFIX_WORDS:
            if s_lower.startswith(pattern):
                process_prefixed_url(s, stmt, src, sid, res)
                consumed = True
                break
        if consumed:
            continue

        # 小程序/公众号 AppID (wx/ww/gh_ 开头)
        if is_miniapp_appid(s):
            process_miniapp_appid(s, stmt, src, sid, res)
            continue

        # miniapp pages
        for pattern in MINIAPP_PAGES_PREFIX_WORDS:
            if s.startswith(pattern):
                process_prefixed_miniapp_pages(s, len(pattern), stmt, src, sid, res)
                consumed = True
                break
        if consumed:
            continue

        # miniapp plugin
        for pattern in MINIAPP_PLUGIN_PREFIX_WORDS:
            if s.startswith(pattern):
                process_prefixed_miniapp_plugin(s[len(pattern):], stmt, src, sid, res)
                consumed = True
                break
        if consumed:
            continue

        # URL 编码
        for pattern in URL_ENCODED_PREFIX_WORDS:
            if s_lower.startswith(pattern):
                process_url_encoded(s, stmt, src, sid, res)
                consumed = True
                break
        if consumed:
            continue

        # =========================================================
        # AK/SK 密钥对检测
        # =========================================================
        is_ak, provider = is_access_key(s, stmt)
        if is_ak:
            sk_val, sk_stmt, sk_idx = find_sk_in_neighbors(i, constants, statements)
            if sk_val:
                process_ak_sk_pair(s, stmt, sk_val, sk_stmt, provider, src, sid, res)
                processed_indices.add(sk_idx)
                continue

        if is_secret_key_sk(s, stmt):
            ak_val, ak_stmt, ak_provider, ak_idx = find_ak_in_neighbors(i, constants, statements)
            if ak_val:
                process_ak_sk_pair(ak_val, ak_stmt, s, stmt, ak_provider, src, sid, res)
                processed_indices.add(ak_idx)
                continue

        # 云平台 Cookie
        if is_cloud_cookie(s):
            process_cloud_cookie(s, stmt, src, sid, res)
            continue

        # CRYPTO (PEM 格式)
        for pattern, slug in CRYPTO_PREFIX_WORDS.items():
            if s.startswith(pattern):
                # 只有 BEGIN 行的 PEM 分隔符不是密钥，见 is_pem_header_fragment。
                if not is_pem_header_fragment(s):
                    process_prefixed_crypto_key(slug, s, stmt, src, sid, res)
                    consumed = True
                break
        if consumed:
            continue

        # CRYPTO (Base64 编码的私钥 - 优先检测，风险更高)
        if is_base64_private_key(s):
            process_base64_private_key(s, stmt, src, sid, res)
            continue

        # CRYPTO (Base64 编码的公钥)
        if is_base64_public_key(s):
            process_base64_public_key(s, stmt, src, sid, res)
            continue

        # 硬编码 IV
        if is_static_iv(s, stmt):
            process_static_iv(s, stmt, src, sid, res)
            continue

        # 硬编码 AES KEY
        if is_static_aes_key(s, stmt):
            process_static_iv(s, stmt, src, sid, res)
            continue

        # AppKey/ApiKey
        # is_app_key 现在按语境返回两种类型：公开 AppKey -> saas_analytics_key(1402)
        # （复用已有的统计分析 SDK Key 类型，不新造类型；process_analytics_key 与
        # process_app_key 都是 append_result 的一层包装，所以这里不需要再分支）；
        # 云厂商 AccessKey / AppSecret 等凭证 -> platform_app_secret(1101)
        is_appkey, appkey_slug = is_app_key(s, stmt)
        if is_appkey:
            process_app_key(s, stmt, src, sid, appkey_slug, res)
            continue

        # 地图 Secret Key (必须在通用 secret key 之前检测)
        if is_map_secret_key_by_neighbor(s, stmt, i, constants, statements):
            process_map_key(s, stmt, src, sid, res)
            continue

        # Secret/API key
        is_secret, secret_slug = is_secret_key(s, stmt)
        if is_secret:
            process_secret_key(s, stmt, src, sid, secret_slug, res)
            continue

        # RSA 十六进制公钥
        if is_rsa_hex_public_key(s, stmt, raw_stmt):
            process_rsa_hex_public_key(s, stmt, src, sid, res)
            continue

        # SM2 公钥等
        if (re.match(r"^[a-f0-9]{48}$", s_lower) or
            re.match(r"^[a-f0-9]{64}$", s_lower) or
            re.match(r"^04[a-f0-9]{128}$", s_lower)):
            res_len_before = len(res)
            process_Regex_crypto_key(s, stmt, src, sid, res, raw_stmt)
            if len(res) > res_len_before:
                continue

        # 小程序 API 路径
        if is_miniapp_api_params(s):
            process_miniapp_api_params(s, stmt, src, sid, res)
            continue

        # data URI
        if s_lower.startswith(DATA_URI_PREFIX):
            process_data_uri(s, stmt, src, sid, res)
            continue

        # cloud bucket name
        if is_bucket_name(s, stmt):
            process_bucket_name(s, stmt, src, sid, res)
            continue

        # email
        if is_email(s):
            process_email(s, stmt, src, sid, res)
            continue

        # map key (mapKey 格式或有地图上下文)
        if is_map_key(s, stmt) or is_map_secret_key(s, stmt):
            process_map_key(s, stmt, src, sid, res)
            continue

        # analytics key
        if is_analytics_key(s, stmt):
            process_analytics_key(s, stmt, src, sid, res)
            continue

        # session key（判据需要语境，必须把 stmt 传进去）
        if is_session_key(s, stmt):
            process_session_key(s, stmt, src, sid, res)
            continue

        # 支付参数
        is_pay_param, pay_slug = is_payment_param(s, stmt)
        if is_pay_param:
            process_payment_param(s, stmt, src, sid, pay_slug, res)
            continue

        # 标识符
        is_id, id_slug = is_identifier(s, stmt)
        if is_id:
            process_identifier(s, stmt, src, sid, id_slug, res)
            continue

        # 云服务密码
        if is_cloud_password(s, stmt):
            process_cloud_password(s, stmt, src, sid, res)
            continue

        # 服务器 Cookie
        if is_server_cookie(s, stmt):
            process_server_cookie(s, stmt, src, sid, res)
            continue

        # 云服务 Token
        is_cloud_tok, _ = is_cloud_token(s)
        if is_cloud_tok:
            process_cloud_token(s, stmt, src, sid, res)
            continue

        # Hex Token
        if is_hex_token(s, stmt):
            process_hex_token(s, stmt, src, sid, res)
            continue

        # 空格检测
        if any(c.isspace() for c in s):
            process_generic_spaced_constant(s, stmt, src, sid, res)
            continue

        # 字符类型分流
        if s[0].isdigit():
            process_generic_digit_prefixed_constant(s, stmt, src, sid, res)
        elif s[0].isalpha():
            process_generic_alpha_prefixed_constant(s, stmt, src, sid, res)
        elif s[0] == ".":
            process_generic_dot_prefixed_constant(s, stmt, src, sid, res)
        elif s[0] == "/":
            process_generic_slash_prefixed_constant(s, stmt, src, sid, res)
        else:
            process_generic_unknown_constant(s, stmt, src, sid, res)

    # 替换 sid 为截断上下文
    final_res = []
    for (slug_id, content, src, sid) in res:
        if sid in truncated_contexts:
            truncated_ctx = truncated_contexts[sid]
        else:
            stmt = statements[sid] if sid < len(statements) else ""
            truncated_ctx = extract_context(stmt, content, 512)
        final_res.append((slug_id, content, src, truncated_ctx))

    return final_res


# =========================================================
# I/O helpers / CLI
# =========================================================
def load_extractor_json(path: str) -> Tuple[List[str], List[Tuple]]:
    """Load JSON: {"statements": [...], "constants": [[s, sid, src], ...]}"""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    statements = data.get("statements", [])
    constants = data.get("constants", [])
    parsed = [(s, sid, src) for s, sid, src in constants]
    return statements, parsed


def main_218584b4(argv: List[str]) -> int:
    """For testing"""
    if len(argv) != 2 or not argv[1].endswith((".json", ".txt")):
        print(f"Usage: python {argv[0]} <input.json>")
        return 2

    input_path = argv[1]
    output_path = input_path.replace(".json", "_classified.json")

    try:
        statements, constants = load_extractor_json(input_path)
    except FileNotFoundError:
        print(f"Error: File '{input_path}' not found.")
        return 1
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON: {e}")
        return 1

    results = perform_constant_classifying(statements, constants)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"Output saved to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_218584b4(sys.argv))
