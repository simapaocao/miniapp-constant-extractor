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

# ---------------------------------------------------------
# fix41：**出口**侧的体形判据（前缀 → 体形正则），与上面那张刻意分开
# ---------------------------------------------------------
# `CLOUD_TOKEN_BODY_PATTERNS` 是**入口粗筛**的一部分（命中即进入 token 出口），
# 这一张只在出口的形态判定里用 —— 粗筛保持宽松，形态不合格的值才能被**显式**改判
# cloud_cred_noise(1207, risk0)，而不是被入口挡回去以后往链下漂（本值的体含空格，
# 链尾 `process_generic_spaced_constant` 是 `pass` ⇒ 会静默消失，fix32 明确禁止）。
# 病根：前缀表里 `pk_test_` / `sk_test_` 这类「普通词 + 下划线」会撞上 CSS 类名列表 ——
# 三库唯一一个 cloud_cred_token(1205) 值是 `pk_test_paper_title flex-c`。
# Stripe 密钥 = 前缀 + ≥24 位字母数字（真密钥就是这个形状）。
# 值侧字符集 = token 可见字符的超集（`_ - . / + = : ~ @`；`@` 是 npm 作用域/用户信息形态里
# 会出现的字符，见 unit-tests/test_risk5_struct_fp.py 的对照组），**空白不在其中** ——
# `pk_test_paper_title flex-c` 正是被这一条挡下的。
CLOUD_TOKEN_CHARSET_RE = re.compile(r"^[A-Za-z0-9_\-./+=:~@]+$")
CLOUD_TOKEN_VALUE_BODY_PATTERNS = {
    "pk_live_": re.compile(r"^[A-Za-z0-9]{24,}$"),
    "pk_test_": re.compile(r"^[A-Za-z0-9]{24,}$"),
    "sk_live_": re.compile(r"^[A-Za-z0-9]{24,}$"),
    "sk_test_": re.compile(r"^[A-Za-z0-9]{24,}$"),
    "rk_live_": re.compile(r"^[A-Za-z0-9]{24,}$"),
    "rk_test_": re.compile(r"^[A-Za-z0-9]{24,}$"),
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

# fix45：`prepay_id=` 之后必须**像一个预支付 ID** 才判 payment_package(2403)，判据见
# is_prepay_id_shaped。真形态是 `wx` + 日期段 + 随机段（微信统一下单返回值）；两库普查里
# 19 个 wx 形态值的 wx 后体长 15~34、全 ASCII 字母数字、含 8~14 位数字。
_PREPAY_ID_WX_BODY_RE = re.compile(r"[0-9a-z]+$")
PREPAY_ID_WX_BODY_MIN = 12

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


# AD_ID_KEYWORDS 里 adid / ad_id / gaid 三个短词必须落在「独立词或相邻驼峰段」上。
# has_keyword_in_context 的快速路径是裸子串（`kw in stmt_lower`），于是
#   adid → threadId / readID / uploadIdCard / mobileListAdOpen / subCategoryThreadId
#          （pkgref 一库 30/35 个 id_ad 值就是这么进来的）
#   gaid → orgaID = "C0B37E18…"（org/orga 账号 id，不是 GAID）
# 都被判成 id_ad_identifier。长关键词（advertisingid / advertising_id / trackingid /
# tracking_id）不受影响，仍走原函数。
#   adId: / AD_ID_INTERRELATION_DETAIL / ad_id 这份写法必须保住 —— 段对 ("ad","id")
#   正是为 `adId` 这种「两个驼峰段拼成关键词」的写法准备的。
AD_ID_SEGMENT_KEYWORDS = {
    "adid": ("ad", "id"),
    "ad_id": ("ad", "id"),
    "gaid": ("ga", "id"),
}


def _has_segment_or_pair(stmt: str, keyword: str) -> bool:
    """keyword 以独立词出现，或以相邻两个驼峰段出现（adId -> ad id）。"""
    normalized = re.sub(r"[_\-\.]", " ", stmt)
    normalized = re.sub(r"([a-z])([A-Z])", r"\1 \2", normalized)
    normalized = re.sub(r"[:\"']", " ", normalized)
    tokens = re.split(r"\s+", normalized.lower())
    if keyword in tokens:
        return True
    pair = AD_ID_SEGMENT_KEYWORDS[keyword]
    return any(tokens[i] == pair[0] and tokens[i + 1] == pair[1]
               for i in range(len(tokens) - 1))


def has_ad_id_context(stmt: str, value: str) -> bool:
    """AD_ID_KEYWORDS 的上下文判定（fix21 ②）：adid / ad_id / gaid 收紧为段匹配。

    value 参与剥值（见 external_context）：值自身含 adId 的写法不再单独定罪，
    与 has_user_id_context / has_cloud_password_context 同一口径。`value` 无默认值，
    漏改调用点直接 TypeError。
    """
    context = external_context(stmt, value)
    long_keywords = AD_ID_KEYWORDS - set(AD_ID_SEGMENT_KEYWORDS)
    if has_keyword_in_context(context, long_keywords):
        return True
    return any(_has_segment_or_pair(context, kw) for kw in AD_ID_SEGMENT_KEYWORDS)


# =========================================================
# fix44：广告语境里的「名字形值」守卫
# =========================================================
# 病根：ad 臂（is_identifier 里判 ID_AD_IDENTIFIER 的两处）只要求
#   has_ad_id_context + 长度 ∈ VALID_DEVICE_ID_LENGTHS{12,15,16,32,36} + isalnum()
# （uuid 形态那一处连长度都不要求）。has_ad_id_context 判的是**整段语句的 512 字符窗口**，
# 于是只要窗口里出现过 adId / ad_id / advertisingId / gaid（或 fix21 ② 收紧后的段对），
# 窗口里**任何**该长度的字母数字串都判 id_ad_identifier —— 与 fix31 的
# `has_cloud_password_context` 同型：语境是窗口级的，值却只要「在窗口里」。
#
# 量化（两库 normal_quarkpan_v2 + unlist_package_reference_v2 的 id_ad 桶，
# 口径 = SUM(data_item.ref_count+1)，见 test-result/fix44/）：
#   桶 41 值 / 957 次里 **19 值 / 913 次（95.4%）是误分类**；v2 一库去重值 39 个，
#   是全部 44 个保留小类里归一倍数最高的一类（按应用 60.7）。
#
# 判读方法：41 个值逐个打开源文件、取值出现处前后 ±300 字符，看它绑在哪个键、在什么调用里。
# 误分类的 19 个值全部落在下面这些形态（掩码清单见 test-result/fix44/judge.tsv）：
#   · 字符串表成员      `######XXXXXX`（6 位数字 + 6 位字母）。三个源文件的**同一个** webpack
#                       字符串数组里各有 6~8 个同形成员（index2.js 6/122、task.js 8/94、
#                       invite.js 6/63）—— 编译器生成的模块名映射表，不是广告 ID。
#   · 字段名/属性名     creativetype（`t.cache("creativetype")`）/ mobileListAdOpen
#                       （`adInfo.mobileListAdOpen`）/ adrightlabel（WXML 属性名
#                       `['adid',…,'adleftlabel',…,'adrightlabel',…]`）/ videoplayurl
#                       （观察者属性名 + `twslvideoplayurl` setter）/ c3ReportData
#                       （组件 props 名列表成员）
#   · 事件名            adpageshareclick（sensors.track 事件名）/ huodongzhongxin（report 事件名）
#   · 广告位 / 页面名   paySuccess01 / productDetail01（`adId === "paySuccess01"`；同名前缀还有
#                       paySuccess01ItemClick / paySuccess01MainClick 两个事件名）
#   · 广告类型名        interstitial（`adType === "interstitial"`、adv_type 取值、
#                       路由名 interstitialAdv、`isInterstitial: "interstitial" === f`）
#   · 配置字典键名      makevideorunning（`appsetting.app.ad_set.adid["makevideorunning"].id` ——
#                       真 id 在 `.id`，本值只是 adid 字典的键）
#   · 中文上报值        12底部平铺banner（`resource_type:`）
#
# 归置：**显式改判 id_noise(2505, risk 0)**，即 fix21 ① 的 `(True, IDT.ID_NOISE)` 写法，
# 而不是 fix22 的 `NAME_CLASS_REJECT = (False, IDT.ID_NOISE)`。理由：本轮的硬约束是
# 「被排除的值不得继续往下落到 id_user / id_order（risk 2~3）或任何 risk≥4 桶」，
# 而 (False, id_noise) 是**三态回报**、只在调用点、且只在凭证判据真要接手时才 consuming，
# 否则值会继续往下走（实测同批值在别的上下文里会落到 server_cred_token 一类出口）。
# (True, id_noise) 一步到位：值只产出 id_noise 一个标签，不回落到任何桶。
#
# 反例（必须 100% 留住，两库实测 22 值 / 44 次全部保留）：「值绑在广告键上」的真实广告 ID，
# 形态全是 32 位 hex —— adId: / adId_2: / ad_id:（wx.reportAnalytics）/
# adUnitId:（createInterstitialAd）/ VUE_APP_INTERSTITIAL_AD_ID / INTERSTITIAL_AD_ID /
# REWARDEDVIDEO_AD_ID / GameRewardedVideoAdIdByQQ / boxAdId / intersitialAdId /
# jlVideoAdId / bannerAdId / vivoSpecificAdId / vivoProhibitedAdId / vivoEndAdId。
# 微信的 `adunit-…` 形状带 `-`（isalnum 为假），本来就不走这两处分支。
#
# 「字母 + 尾数字」/「首小写驼峰」两条正则的**长度闸门 24 是刻意的**：真广告标识在两库里
# 最短也是 32 位 hex，而 32 位 hex 里字母与数字是交错的 —— 唯一能命中 `[A-Za-z]+[0-9]+`
# 的 32 位 hex 是 `abcdef0123456789abcdef0123456789` 这种「字母全在前、数字全在后」的写法，
# 被长度闸门挡在外面，不会误收。（`is_name_like_identifier_value` 那一支不加长度闸门，
# 与 fix21 ③ 在其 user 臂上的用法一致：32 个字符**全是 [a-f]** 的概率是 (6/16)^32 ≈ 4e-13。）
RE_AD_IDENTIFIER_TAIL_DIGITS = re.compile(r"^[A-Za-z]+[0-9]+$")
RE_AD_IDENTIFIER_CAMEL_WORD = re.compile(r"^[a-z][a-z0-9]*(?:[A-Z][A-Za-z0-9]*)+$")
RE_AD_IDENTIFIER_OBFUSCATED_TOKEN = re.compile(r"^[0-9]{6}[A-Za-z]{6}$")
AD_IDENTIFIER_NAME_MAX_LEN = 24


def is_ad_identifier_name_like(s: str) -> bool:
    """值形是「词 / 名字」（字段名、事件名、页面名、广告位名、类型名、串表 token）而不是广告标识值。

    只判**值形**，不判语境 —— 调用点必须已经确认 `has_ad_id_context`（广告语境之外的同类值
    一行不动）。判据、判读依据与反例见上方注释块。复用只读的
    `is_name_like_identifier_value`（fix21 ③：含非 ASCII / 全字母）与
    `is_segmented_identifier_name`（fix12：多段词形标识符名）。
    """
    if is_name_like_identifier_value(s):
        return True
    if len(s) > AD_IDENTIFIER_NAME_MAX_LEN:
        return False
    return bool(RE_AD_IDENTIFIER_TAIL_DIGITS.match(s)
                or RE_AD_IDENTIFIER_CAMEL_WORD.match(s)
                or RE_AD_IDENTIFIER_OBFUSCATED_TOKEN.match(s)
                or is_segmented_identifier_name(s))


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

# 命中方式：按插入序迭代 + `in` 裸子串 + **首个命中即 return**（URL 分支与
# process_generic_slash_prefixed_constant 第 8 步共用同一份判据）。
# 因此**任何键只要包含更靠前的键，就永远不可达**（更靠前的键先命中并 return）。
# fix20 ②：原顺序里 "oauth"（在 "auth" 之后）与 "payment"（在 "pay" 之后）就是这种
# 死键 —— 三库实测首命中只有 login/auth/signin（1702）与 pay（1703），
# oauth / payment 命中 0 次（test-result/fix20/issue2_quantify.out）。
# 修法是让更专用的词排在它的子串之前，并加单测守住「无键被更靠前的键包含」这条性质。
# 注意这次重排**不改变任何输出**：oauth/auth 同映射 SERVER_URL_AUTH、
# payment/pay 同映射 SERVER_URL_PAYMENT，三库回放 0 变化（同报告）；它修的是死键本身。
URL_SENSITIVE_KEYWORDS = {
    "webhook/send": IDT.WEBHOOK_URL,
    "cgi-bin/webhook": IDT.WEBHOOK_URL,
    "robot/send": IDT.WEBHOOK_URL,
    "bot/v2/hook": IDT.WEBHOOK_URL,
    "bot/hook": IDT.WEBHOOK_URL,
    "login": IDT.SERVER_URL_AUTH,
    "signin": IDT.SERVER_URL_AUTH,
    "oauth": IDT.SERVER_URL_AUTH,     # 必须先于 "auth"（"auth" in "oauth"）
    "auth": IDT.SERVER_URL_AUTH,
    "payment": IDT.SERVER_URL_PAYMENT,  # 必须先于 "pay"（"pay" in "payment"）
    "pay": IDT.SERVER_URL_PAYMENT,
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

# fix20 ③：组件引用路径的首段还有下面几族，原先全部漏网 —— 它们不含上面 6 个前缀，
# 于是掉进第 8 步的裸子串匹配，成为 server_url_auth(risk4) /
# miniapp_page_path_sensitive(risk3) 的**头部**（/@y/ppt/lib/user-authorize/index
# 单值 2075 次、/ext-tee-passport/…/widgets/rt/Main 1054 次、/mainComponents/authPopup/authPopup 765 次）。
# 收进来的依据是三库全量取证（值数 icp/pkgref/normsib，usingComponents 语境占比）：
#   /@y/               41/72/53 值   100%/100%/100%（页面路由 0、API 标记 0）
#   /mainComponents/   19/16/0 值   100%/100%/—
#   /wigets/           22/21/20 值  100%/100%/100%
#   /ext-tee-passport/  3/4/1 值    100%/100%/100%
# （test-result/fix20/issue3_prefixes.out）
# 注意：成员必须**全小写** —— 调用点是 `s_lower.startswith(...)`，写 "/mainComponents/"
# 这种带大写的成员永远不会命中（本轮踩过：加了前缀但 /mainComponents/ 一族纹丝不动）。
MINIAPP_COMPONENT_PREFIXES_EXT = (
    "/@y/", "/maincomponents/", "/wigets/", "/ext-tee-passport/",
)

# 项目自建源码根**不能整族收**：/src/、/common/、/usercenter/ 下混着真接口与页面路由
# （三库全量：usingComponents 语境占比只有 9.9%~34.9%；/common/getDictData、
# /common/sendSmsVerifyCode、/common/getCaptcha 是真接口，/common/pages/login/login、
# /src/pages/home/index 是页面路由，/usercenter/dashboard/index 是别的页面路径）。
# 整族收会把它们一起搬进 1906（实测 /src/ 一族有 90/375/540 个页面路由形态的值）。
# 改为**逐值要语境证据**：只有值附近确实出现 usingComponents 声明，才算组件引用。
# 取证：加了这道语境门之后，三库该族被移动的值 100% 都能在自己的 snippet 里找到自己的
# 路径（值 221/253/679，出现 3573/16171/22182），即证据确实指向该值而不是同语句的其它常量。
MINIAPP_COMPONENT_CONTEXT_PREFIXES = (
    "/src/", "/common/", "/usercenter/",
)

# 分包（/packages/…、/packageA/…、/subPackages/…）整体被 is_miniapp_page_route 认成
# 页面路由（RE_MINIAPP_PAGE_ROUTE 里的 `^/package` 是前缀匹配），于是**分包内部的组件引用**
# 也一起落进页面路径桶；其中带敏感词的那些正是 miniapp_page_path_sensitive(risk3) 的头部：
#   /packages/async-minor/components/shop-pop-manager/index   552 次 icp / 308 次 pkgref
#   /packages/async-feature-ext/rt/ext-tee-wsc-goods-biz-sku-manage-local/rt/Main  504/207
# 这两族的差别是「路径里有没有组件目录段」：带 `/components/` 的那族取证干净
# （三库 428/570/451 值、38,269/19,730/26,637 次，UC 语境 416/553/408 值，
#  且这批值 100% 能在自己的 snippet 里找到自己 —— test-result/fix20/issue3_segment.out），
# 所以按「组件目录段 + usingComponents 语境」单独放行；不带组件目录段的分包路径
# （head #2 那条 /rt/…/Main）本轮不动，见 fix20 报告。
MINIAPP_COMPONENT_DIR_SEGMENTS = (
    "/components/", "/component/", "/components-common/", "/commpents/", "/wxcomponents/",
)
MINIAPP_PACKAGE_ROOTS = ("/package", "/subpackage", "/subpages")

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


def has_url_userinfo_credential(cred_part: str) -> bool:
    """URL 的用户信息段（第一个 `@` 之前的部分）是否为**真凭证** `user:password`。

    fix20 ①：原判据只有 `"@" in url_body` + npm-scope/retina 两个排除，于是
    「URL 里有任意 userinfo」= risk 5 / action=block 的 server_url_with_credentials。
    三库并集实测 122 个去重值 / 734 次出现，逐条判读后 120 个值 / 728 次是误报：

      - 遥测/Sentry DSN 形态 `https://<32hex>@host/project`  112 值 / 650 次（91.8%）
        （`https://733e…@sentry.58.com/313`、`…@rum.17u.cn/317`、`…@report.url.cn/sentry/…`）
        —— Sentry 的 DSN 公钥按设计就是**公开的前端写入键**，不带口令，
        挂在 block 级告警上是高危误报；
      - git 仓库 URL 只有用户名（`http://suguowei@192.9.180.91/drcBank/credit-applet.git`）
        6 值 / 28 次；其余 2 值 / 50 次是拼接模板与垃圾（`https://a@b`、`https://uni-patient-@tag…`）。

    真值只有 2 个值 / 6 次：`http://zhangxiaoyang:zxy081818@119.191.58.19:10080/…`、
    `https://oath2:sps8yaQRN8nCAcLDNRBN@igit.ykbenefit.com/…`，两者都含 `user:password`。

    判据取「含 `:` 且两侧非空」，与 URL 用户信息的语法一致（`user:password@`）：
      - `@` 前无冒号 = 只有用户名（Sentry 公钥、git 用户名）→ 不是凭证；
      - `user:@host` / `:pass@host`（RFC 3986 允许的退化写法）→ 没有可泄漏的口令，也不算。
    RFC 3986 允许用户名/口令里出现百分号转义（`%3A`），故只看**未转义**的第一个 `:`；
    百分号转义形态在三库 122 个值里为 0，不额外处理。
    """
    if ":" not in cred_part:
        return False
    user, _, password = cred_part.partition(":")
    return bool(user) and bool(password)


# =========================================================
# 云存储 host 判据（fix34）
# =========================================================
# 改动前的云存储判据是「整条 URL（含路径与查询串）的裸子串匹配」：
#     cloud_domains = ("oss-", "cos.", "s3.", "cdn.", "aliyuncs.com", "myqcloud.com")
# 于是 v2 cloud_storage_path 14,595 值 / 54,111 次里，http(s) 值 11,075 个中
#   · 4,546 值 / 25,359 次（占全桶 47%）只因 `cdn.` 进来（字体 `at.alicdn.com/*.ttf`、
#     `img.dmallcdn.com`、`img01.yzcdn.cn`、`si.geilicdn.com`、`cdn.51yanpu.com` …）；
#   · `s3.` 把 `images3.c-ctrip.com`（379 值）整段当成 S3；
#   · 路径/查询串里的字样同样算证据（`…/fetch?target=oss-cn-hangzhou`）。
# 下面这张表就是那个旧口径，**只留给回放/测试的「改动前等效开关」**用
# （见 unit-tests/test_fix34_storage_host.py 的 guard_off）。
CLOUD_STORAGE_DOMAIN_SUBSTRINGS = ("oss-", "cos.", "s3.", "cdn.", "aliyuncs.com", "myqcloud.com")

# 真实对象存储端点表（每条都在 v2 语料里逐 host 核过，见 test-result/fix34/）。
# 关键不变量：**每一条都必然让整条 URL 里出现上面六个裸子串之一**——
#     aliyun-oss → "aliyuncs.com"、tencent-cos → "myqcloud.com"、aws/s3-兼容 → "s3."、
#     baidu-bos → "cdn."、x-oss-process 支 → "oss-"（见 is_cloud_storage_url）。
# 因此新判据在集合意义上是旧判据的**真子集**：只会把值移出 1303，不会把任何值拉进来
# （回放要求「反向进入目标桶 = 0」由此结构性保证，而不是抽样保证）。
# 语料里的非存储服务因此被收紧：SLS 日志 `*.log.aliyuncs.com`、ARMS/RUM 上报
# `arms-retcode.aliyuncs.com` / `*.rum.aliyuncs.com`、智能语音 `nls-gateway*.aliyuncs.com`、
# DashScope `dashscope.aliyuncs.com`、API 网关 `*.apigateway.myqcloud.com`、
# 点播 `*.liveplay/vod2.myqcloud.com`、品牌自建 host（`cos.blemon.net`、`oss.fmy90.cn` …）。
CLOUD_STORAGE_HOST_PATTERNS = (
    # 阿里云 OSS：<bucket>.oss-<region>.aliyuncs.com、<bucket>.oss.aliyuncs.com、
    # oss[-<region>].aliyuncs.com（路径式），oss-accelerate 也落这一支
    ("aliyun-oss", re.compile(r'^(?:[a-z0-9][a-z0-9.-]*\.)?oss(?:-[a-z0-9-]+)?\.aliyuncs\.com$')),
    # 腾讯云 COS：<bucket-APPID>.cos.<region>.myqcloud.com、cos.<region>.myqcloud.com（路径式）、
    # <bucket-APPID>.file.myqcloud.com（默认 CDN 加速域）、<bucket-APPID>.image.<region>｜.ci.<region>
    # （图片处理域）、历史省写域 <bucket-APPID>.cossh/.cosgz/.picsh.myqcloud.com、
    # service.cos.myqcloud.com / region.file.myqcloud.com（服务域）
    ("tencent-cos", re.compile(
        r'^(?:[a-z0-9][a-z0-9.-]*\.)?'
        r'(?:cos|ci|pic|image|file)[a-z]{0,4}(?:\.[a-z0-9-]+)?\.myqcloud\.com$')),
    # AWS S3：<bucket>.s3.amazonaws.com、<bucket>.s3.<region>.amazonaws.com[.cn]、
    # s3.<region>.amazonaws.com[.cn]（路径式；只认 `.s3` 点分式，历史 `s3-<region>` 短横式不在语料里）
    ("aws-s3", re.compile(
        r'^(?:[a-z0-9][a-z0-9.-]*\.)?s3\.(?:[a-z0-9-]+\.)?amazonaws\.com(?:\.cn)?$')),
    # 百度 BOS：语料里 BOS 的数据面全是 <bucket>.cdn.bcebos.com（含 `cdn.` ⇒ 仍蕴含旧证据）
    ("baidu-bos-cdn", re.compile(r'^(?:[a-z0-9][a-z0-9.-]*\.)?cdn\.bcebos\.com$')),
    # 京东云 OSS（S3 兼容）：<bucket>.s3.<region>.jdcloud-oss.com
    ("jdcloud-oss", re.compile(r'^(?:[a-z0-9][a-z0-9-]*\.)?s3\.[a-z0-9-]+\.jdcloud-oss\.com$')),
    # Bitiful（S3 兼容）：<bucket>.s3.bitiful.net
    ("bitiful-s3", re.compile(r'^(?:[a-z0-9][a-z0-9-]*\.)?s3\.bitiful\.net$')),
)


def is_object_storage_host(host: str) -> bool:
    """host 是否命中真实对象存储端点（入参须已去端口、小写；大小写不敏感）。"""
    if not host:
        return False
    host = host.lower()
    for _name, pattern in CLOUD_STORAGE_HOST_PATTERNS:
        if pattern.match(host):
            return True
    return False


def is_cloud_storage_url(url_lower: str, host: str) -> bool:
    """fix34：这条 URL 是否指向云对象存储。

    判据只看 **host**（`process_prefixed_url` 里已有的 `server_name`）是否命中
    `CLOUD_STORAGE_HOST_PATTERNS` 里的真实存储端点；**路径与查询串里的子串不再是证据**
    （`cos.` 出现在路径里、`oss-` 出现在 query 里都不算）。

    唯一的整条-URL 例外是**不确定支**：非存储 host 但带 `x-oss-process`（形如 OSS 图片
    处理参数）—— 按任务要求**保持现行为不变**（仍判 1303），不在本轮改判，只报数量
    （v2 1,324 值 / 3,444 次）。它不是新增证据：`x-oss-process` 本身就含 `oss-`，
    改动前同样命中。
    """
    if is_object_storage_host(host):
        return True
    return "x-oss-process" in url_lower


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

    # 带凭证的 URL: user:password@host 格式
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
            # 用户信息段一律不参与「主机 / 路径」分类（下面的 fs[0] 取主机），
            # 这一点与改动前一致 —— 改动的是「哪些算凭证」，见 is_url_userinfo_credential。
            url_body = rest_part
            # fix20 ①：只有真 `user:password` 才算带凭证 URL。
            # 判据与量化见 has_url_userinfo_credential 的 docstring：收严后三库
            # 1701 从 122 值/734 次降到 2 值/6 次，两个真值都保住，误伤 0。
            # 其余值（Sentry DSN 公钥、git 用户名 URL…）**去向不变**：它们本来就
            # 会把用户信息段剥掉后按主机/路径继续分类（实测三库 120 个值在本分支
            # 之下都还会产出同一条次要标签），本次只是不再产出 1701 这一条。
            if has_url_userinfo_credential(cred_part):
                append_result(res, IDT.SERVER_URL_WITH_CREDENTIALS, url_full, src, sid)
                # 顺带产出的 server_cred_password 与 1701 同条件：原本这条分支要求
                # `":" in cred_part`，收严后该条件恒真（cred_part 含 ':' 正是 1701 的
                # 判据），三库能触发它的本来也只有那 2 个真值（6 次），故保留配对产出。
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

    # 云存储域名（fix34：host 必须命中真实存储端点，见 is_cloud_storage_url；
    # 路径/查询串里的 "cdn." / "s3." / "cos." 等裸子串不再是证据）
    if is_cloud_storage_url(url_lower, server_name.lower()):
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


# 无分隔符、数字夹在字母中间（jscode2session / code2session / utf8decode）。
# 只在 is_bucket_name 里用于否决桶名，见该函数内的说明。
NO_SEPARATOR_IDENTIFIER_RE = re.compile(r'^[a-z]+\d+[a-z]+$')

# =========================================================
# 桶名上下文证据（fix35）
# =========================================================
# 改动前的判据是**窗口裸子串**：`has_keyword_substring(stmt, BUCKET_CONTEXT_WORDS)` ——
# 值周围 512 字符里出现过 `bucket` 就够，从不问这个 `bucket` 是谁的。三库实例：
#   · pkgref 96 个 cloud_bucket_name 值里 62 个是 `logo-*`：它们来自同一个图标数组
#     `"logo-bitbucket", "logo-bitcoin", …` —— `logo-bitbucket` **自身**含 "bucket"，
#     于是同语句所有元素的窗口都含 "bucket"，60 多个图标名整片被判成桶名；
#   · v2 约 12 值 / 58 次是编译模板标签或组件名（`_mz(z,'<tag>',[…,'bucketInfo',…])`、
#     `"<name>":"../components/…"`），例如 topic-layout / header-bar / *-bucket-detail /
#     order-module-bucket / skeleton-rect 这类组件名与类名；
#   · S3 POST policy 的算子词 `starts-with`（v2 11 次）、32 位 hex（3 个，其中一个坐在
#     `bucket_access_sec:` 键上）、日志串 2 个。
# 判据（三条，全部只看「本值」这一侧）：
#   ① 证据必须是**绑定在本值位置**的键：口径直接复用 fix24 的 `_bound_value_keys`
#      （值须自成字面量 + 键须紧邻值左侧，含 `键: 表达式 || "字面量"` 的默认值写法）；
#      键名（lower）含 `bucket` 即算桶键族 —— 语料 44 个真实键逐个核过（bucket / Bucket /
#      bucketName / bucket_name / mfBucketName / bucketNameforESF / cosBucket / ossBucket /
#      oss_bucket / BUCKET_NAME / VUE_APP_OSS_BUCKET / REACT_APP_OSS_BUCKET / MINIO_BUCKET /
#      content_bucket_name / obsPublicBucket / actualBucket / jjbucket0001 …），与 fix24
#      的「族内复合键名放行」同一套写法；
#   ② **值自身或同语句其它字面量里的 `bucket` 字样不算证据** —— 这正是 ① 里两个病根的来源；
#   ③ 硬否决（优先于任何键绑定）：S3 policy 算子词与 32 位 hex 不可能是桶名。
# 豁免：腾讯 COS 桶名形态 `<name>-<10 位数字 appid>` **本身就是证据** —— 这类值常出现在
#   三目/`||` 表达式里（`avatorBucket: a? "avatar-1302652390" : "avatar-1253822818"`），
#   紧邻键拿不到绑定，但形态本身就说明它是 COS 桶名。
BUCKET_POLICY_OPERATOR_WORDS = ("starts-with", "eq", "content-length-range")
RE_BUCKET_HEX32 = re.compile(r'^[0-9a-f]{32}$')
RE_COS_BUCKET_NAME_SHAPE = re.compile(r'^[a-z0-9][a-z0-9-]*-\d{10}$')


def has_bucket_name_evidence(s: str, stmt: str) -> bool:
    """fix35：本值是不是云桶名的上下文证据（绑定键 / COS 形态），见上面的判据说明。

    只读复用 `_bound_value_keys`（fix24/25/26 的共用扫描器）：绑定必须是**本值位置**上的
    紧邻键，窗口搜索一律不算。COS 形态（`<name>-<10 位数字 appid>`）豁免绑定要求。
    """
    s_low = s.strip().lower()
    if s_low in BUCKET_POLICY_OPERATOR_WORDS or RE_BUCKET_HEX32.match(s_low):
        return False
    if RE_COS_BUCKET_NAME_SHAPE.match(s_low):
        return True
    return any("bucket" in key.lower() for key in _bound_value_keys(s, stmt))


def looks_like_bucket_name(s: str, stmt: str) -> bool:
    """**改动前的完整判据**：窗口里有 bucket 子串 + 值形像桶名。

    fix35 之后它不再决定出口，只决定「候选范围」：`is_bucket_name` = 本函数 + 证据
    （`has_bucket_name_evidence`）。保留独立函数的唯一用途是**归置**：既过本判据又没有
    证据的值是「看着像桶名的名字类噪音」，由主链显式改判 id_noise(2505, risk0)，
    不许只摘掉 1301 就往下走（同 fix32 的归置口径；三库回放实测这 66/54 个值在改动后
    **不产出任何标签** = 静默丢弃，见 test-result/fix35/）。
    """
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

    # fix19 ③：无分隔符且数字**夹在字母中间**的形态是代码标识符被拍平的结果，不是桶名。
    # 桶名要全局唯一，因此绝大多数带数字的桶名是「品牌-用途-<appid>」或「品牌<尾号数字>」
    # （本仓三库实例：tc-buck-1254728086 / mt100180 / vias2019），把数字夹在字母中间且
    # 全程没有 '-' 的值读起来是 `jscode2session` / `code2session` / `utf8decode` 这类
    # **驼峰标识符**（三库实测：该形态在 149 个 cloud_bucket_name 去重值里只命中 1 个，
    # 就是噪音值 jscode2session，真桶名 0 误伤；见 fix19 报告）。
    if NO_SEPARATOR_IDENTIFIER_RE.match(s):
        return False

    # 结构复杂度: 必须包含 '-' 或数字
    return '-' in s or any(c.isdigit() for c in s)


def is_bucket_name(s: str, stmt: str) -> bool:
    """检测是否为云存储桶名称。

    fix35：**候选范围**（`looks_like_bucket_name`，= 改动前的整条判据）**加上**证据
    （`has_bucket_name_evidence`：绑定在本值位置的桶键，或值自身的 COS 形态）。
    窗口里出现裸子串不再算证据 —— `logo-bitbucket` 连坐 60 多个图标名、`bucketInfo`
    属性连坐组件名/类名、policy 窗口里的算子词与 32 位 hex 都是从这个口子进来的。
    """
    return looks_like_bucket_name(s, stmt) and has_bucket_name_evidence(s, stmt)


def process_bucket_name(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云存储桶名称"""
    append_result(res, IDT.CLOUD_BUCKET_NAME, s, src, sid)


# =========================================================
# 邮箱检测
# =========================================================
# ---------------------------------------------------------
# fix37：邮箱的「整串」校验
# ---------------------------------------------------------
# 病根：原 `is_email` 只数 `@` 的个数、要求 local 非空、domain 含点、整串以白名单后缀
# 结尾 —— 于是「整篇隐私政策/用户协议正文末尾带一个邮箱」「客户服务电子邮箱：xxx@…」
# 「联系方式：xxx@…」这类含中文/空格/冒号的整段文本、domain 里带 `/` 的路径片段
# （`xxx@webank/wxa-webankui/component/…/upload.com`）全都出口 pii_email_name(2303)。
# 只读普查（v2 = normal_quarkpan_v2 1,269 值 / pkgref = unlist_package_reference_v2 259 值）：
# v2 应否定 309 值 / 555 链接（含中文 188、含空白 97、保留域 11、含冒号 9、local 带 `*`
# 的掩码占位 4），pkgref 应否定 21 值 / 67 链接（含中文 12、含空白 7、domain 带 `/` 2）。
#
# 口径：整串必须是邮箱 —— local 只含 `[A-Za-z0-9._%+-]`，domain 由 `[A-Za-z0-9-]` 组成的
# 标签以点分隔（≥1 个点），整串不含空白/中文/`/`/`:` 等；白名单后缀
# （EMAIL_DOMAIN_SUFFIXES）**保留**（本轮只让出口更窄，绝不放宽）；RFC 2606/6761 保留域
# 拒绝；**不**从长文本里抽取邮箱生成新值。`test.com` 是真实域名，不按保留域处理。
_EMAIL_LOCAL_RE = re.compile(r"[A-Za-z0-9._%+-]+")
_EMAIL_DOMAIN_RE = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_EMAIL_RESERVED_DOMAINS = ("example.com", "example.net", "example.org")
_EMAIL_RESERVED_TLDS = (".test", ".example", ".invalid", ".localhost")


def is_reserved_email_domain(domain_part: str) -> bool:
    """RFC 2606 / 6761 保留域（`example.com/net/org` 及其子域、保留 TLD）。

    `test.com` 是真实域名，不在此列。
    """
    d = domain_part.lower()
    if d in _EMAIL_RESERVED_DOMAINS:
        return True
    if any(d.endswith("." + r) for r in _EMAIL_RESERVED_DOMAINS):
        return True
    return any(d.endswith(t) for t in _EMAIL_RESERVED_TLDS)


def is_email_shape_loose(s: str) -> bool:
    """fix37 **之前**的 `is_email` 口径（逐字保留）。

    它现在只用来判**否定**：形态像邮箱但整串不是 → 显式落 pii_noise(2304, risk0)
    （见 `perform_constant_classifying` 的 email 出口）。许可判断一律走 `is_email`。
    """
    if s.count("@") != 1:
        return False
    at_idx = s.index("@")
    local_part, domain_part = s[:at_idx], s[at_idx + 1:]
    if len(local_part) < 1 or len(domain_part) < 3 or "." not in domain_part:
        return False
    return any(s.lower().endswith(suffix) for suffix in EMAIL_DOMAIN_SUFFIXES)


def is_email_strict(s: str) -> bool:
    """整串校验（fix37 的判据本体）：整串必须是邮箱，且不是保留域。

    与 `is_email_shape_loose` 是**与**关系：本判据只会让 email 出口更窄。
    """
    if s.count("@") != 1:
        return False
    local_part, domain_part = s.split("@", 1)
    if not _EMAIL_LOCAL_RE.fullmatch(local_part):
        return False
    if not _EMAIL_DOMAIN_RE.fullmatch(domain_part):
        return False
    return not is_reserved_email_domain(domain_part)


def is_email(s: str) -> bool:
    """判断是否为邮箱格式：**整串**必须是邮箱"""
    return is_email_shape_loose(s) and is_email_strict(s)


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


# ---------------------------------------------------------
# fix26：地图 Key「通用语境分支」的标识符名守卫
# ---------------------------------------------------------
# 病根：is_any_map_key_format 的第三支（有地图语境 + is_valid_api_key_format）把**值形**门槛
# 设成「长度 ≥16 / 非纯数字 / 非全小写单词 / 字符集 ⊆ [A-Za-z0-9_-]」，而语境走的是裸子串匹配
# MAP_KEY_CONTEXT_WORDS。于是只要值周围 512 字符窗口里出现过 `amap` / `mapKey`（真实来源：
# require("~/utils/amap-fn")、o.isAmap ?、e.mapKey、businessCfgMapKey），kebab 形态的路由名 /
# 页面名 / 模块名（`user-medicine-edit` / `mobx-miniprogram-bindings` / `MINIPROGRAM-ALIPAY`）
# 与全大写 snake 常量名整族就被判成 saas_map_key(1401)。
#
# 三库只读普查（test-result/fix26/probe_map_key_branch.py；normal_quarkpan 12,390 条链接）：
#   通用语境支 7,974 条里「多段词形标识符名 且 未绑定在地图 Key 值位置」= 6,337 条 / 691 值；
#   腾讯格式支 4,387 条、Google 格式支 2 条 —— 这两支一律不许动（母任务红线）。
#
# 判据只加在第三支上：值形是多段词形标识符名（复用 fix12 的 is_segmented_identifier_name，
# 已在 cloud_cred_password(1203) / server_cred_cookie(1604) 上验证）**且**没有坐在「地图 Key
# 值位置」→ 不是地图 Key。两支格式自证在进入这一支之前就已 return True，因此**无绑定的腾讯
# BZ Key**（含恰好每段都是「字母+尾数字」、会被 is_segmented_identifier_name 命中的那一小批）
# 与 Google Key 完全不受影响；非标识符形的值（32 位 hex 高德 Key / 24 位百度 AK / 坐在
# `return "…"` 里的真 Key）也不受影响 —— 判据**不要求「必须绑定」**，只对标识符形那一族生效。
#
# 值位置绑定 = 紧邻本值左侧的键名（口径复用 fix24 的 _PAYMENT_VALUE_BINDING_RE）在下面这张
# 键表里。键表只收「键名本身就叫地图 Key」的写法；键名含 map 但语义不是「地图 Key 值位置」的
# 复合键（`MAPKEY_ENCRYPT_PUBLIC_KEY` / `over_pay_no_amapOrderId` / `businessCfgMapKey = i.configs…` /
# 通用 `key:`）刻意不收 —— 那些键位坐的是名字本身，正是本轮要清的噪音。
MAP_KEY_VALUE_BINDING_KEYS = frozenset((
    "mapkey", "map_key",
    "amapkey", "amap_key", "amapwxkey", "amapwebkey", "amapwebservicekey", "amapmpkey",
    "gdmapkey", "gaodemapkey",
    "qqmapkey", "tencentmapkey",
    "bmapkey", "bmapak", "bmapwxak", "baidumapkey", "baidumapak",
    "googlemapkey", "vite_app_map_key",
))


def is_map_key_value_bound(s: str, stmt: str) -> bool:
    """本值是否坐在「地图 Key 值位置」：独立出现位置左侧紧邻的键名在 MAP_KEY_VALUE_BINDING_KEYS 里。

    只看紧邻本值的键（`mapKey:` / `mapKey=` / `"mapKey":`），不做窗口搜索；本值必须自成字面量
    （前/后紧邻标识符字符的出现不算），否则「本值只是更长字面量的前缀/后缀」时会把外层的键算到
    本值头上 —— 两条细则与 fix24 / fix25 的绑定口径完全一致（共用 `_bound_value_keys`）。
    """
    if not stmt or not s:
        return False
    return any(key.lower() in MAP_KEY_VALUE_BINDING_KEYS
               for key in _bound_value_keys(s, stmt))


def is_unbound_identifier_name_map_candidate(s: str, stmt: str) -> bool:
    """fix26 守卫：通用语境支里，多段词形标识符名且未绑定在地图 Key 值位置 → 判为噪音。

    已知残留（本轮刻意不扩大判据）：单段名（`noMobileFallback`）与前导分隔符的名字
    （`_ADDRESS_MAP_KEY_`）不在多段判据的射程内。
    """
    return is_segmented_identifier_name(s) and not is_map_key_value_bound(s, stmt)


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
            # fix26：通用语境支的标识符名守卫（只在这一支生效，理由与代价见上面的键表注释）
            if is_unbound_identifier_name_map_candidate(s, stmt):
                return False
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
# fix32：统计分析出口（1402）的「命名报送 callee 实参」守卫
# ---------------------------------------------------------
# 病根：`is_analytics_key` 的语境闸门是**裸子串** —— `ANALYTICS_KEY_CONTEXT_WORDS` 里的
# `sensors` / `sensorsdata` / `mixpanel` / `sentry` … 在值周围 512 字符窗口里出现即成立。
# 而报送类 callee 的**名字本身**就把这个闸门打开了：`getApp().sensors.track("h5_click", …)`
# 里的 `sensors.track` 让**事件名** `h5_click` 以 `saas_analytics_key(1402)` 出口。
# 也就是说「谁被喂给报送函数，谁就变成统计分析 Key」，哪怕它坐在 callee 的实参位上、
# 左侧没有任何键名。
#
# 只读普查（normal_quarkpan，1402 桶全部 7,383 条链接 / 2,537 个值；脚本
# test-result/fix32/probe_analytics_callee.py，TSV 同目录）：
#   · 值的**每次**独立出现都「未绑定 + 是命名报送 callee 的实参」= 496 条链接 / 184 个值
#     （父任务探针口径 501 / 181；差的是白名单边界的 `etc.` 条目，见下「白名单」），
#     其中 174 个值的全部链接都在这一族里（整值离开 1402）；
#   · 这 496 条里**没有一条**走公开 AppKey 路由（普查 appkey_route=0）—— `is_app_key`
#     在分类器里比 analytics 出口**更早**判定，本判据碰不到公开 AppKey；
#   · 值形是事件名（`h5_click` / `AyhH5Click` / `NXPT_O00000175` / `chart2View` …），
#     被喂给**工具类** callee 的值（`wx.getStorageSync` / `.concat` / `console.log`）
#     不在这一族里。
#
# 判据（只作用于 analytics 出口这一处）：
#   ① 值含**至少一个字母**（硬化：纯数字值一律不动，见下）；
#   ② 窗口里至少有一次独立出现；
#   ③ **每一次**独立出现都满足「左侧紧邻没有键绑定」（口径 = `_bound_value_keys` 那台
#      `_PAYMENT_VALUE_BINDING_RE`）且「最内层包住它的调用是显式白名单里的报送 callee」。
#
# 白名单（父任务探针给的显式清单；**按尾部段**匹配 —— 语料里的接收者被压缩器加过前缀：
# `.globaldata.sensors.track` / `c.sensors.track` / `e.sensorsClick.send`，尾部段匹配是
# 同一张清单在压缩器下的唯一可行写法，不是「名字像就放行」）：
#   TAIL2 = 末两段：sensors.track / sensorsclick.send / track.clickEvent / track.pageShowEvent /
#           ehiSensors.track / _mixpanel.send / Exposure.removeObserverByClassName
#   TAIL1 = 末一段：sensorsTrack / saTrack / sensorsTrackClick / saEvent / sentryCaptureEvent /
#           emotionalRuleReport / xjSensorsTrack
# 刻意**不含**工具类 callee（`wx.getStorageSync` / `getStorageSync` / `concat` /
# `console.log` / 裸 `send`）；`u.Sensors.removeObserverByClassName([...])`（数组实参、
# 14 条链接）也不在射程内 —— 白名单是显式的，不靠「名字像」扩。
#
# 归置（本轮红线）：命中即**显式**写既有的 risk0 噪音标签 `id_noise(2505)`，
# **不是**「无标签」。原因：只把 1402 摘掉、放任往下走，normal_quarkpan 全桶实测有 1,179 条
# 链接（父任务探针口径 571）会平移进 `cloud_cred_password(1203, risk5)` —— 那是把噪音
# 从左口袋挪到右口袋。`append_result` 写在 analytics 出口上，落不到下面的凭证判据上。
#
# 保留组（逐条钉在 unit-tests/test_fix32_analytics_callee_guard.py）：
#   · 公开 AppKey 路由（`appkey:`/`appKey:` 命中的 2,618 条链接）与绑在键上的值
#     （`event_name:` / `$element_name:` 那一族，1309 值 / 3005 链接量级）；
#   · `sensorsdata` 存储键这类**非报送 callee 实参**的 SDK 标识（`getStorageSync` 的实参）；
#   · 被工具类 callee 喂的值；纯数字的 10 位页 ID。
#
# 刻意不做（本轮授权之外）：不碰 `is_app_key` / AppKey 路由；不做纯 hex 抑制；
# 不做事件名模板（白名单是 callee 名，不是事件名模式）；不做「值里含厂商词就收掉」的
# 值侧收严。已知残留：`u.Sensors.removeObserverByClassName` 数组实参族照旧 1402。
ANALYTICS_REPORTING_CALLEE_TAIL2 = frozenset((
    "sensors.track",
    "sensorsclick.send",
    "track.clickevent",                  # $track.clickEvent
    "track.pageshowevent",               # $track.pageShowEvent
    "ehisensors.track",
    "_mixpanel.send",
    "exposure.removeobserverbyclassname",
))
ANALYTICS_REPORTING_CALLEE_TAIL1 = frozenset((
    "sensorstrack",
    "satrack",
    "sensorstrackclick",
    "saevent",
    "sentrycaptureevent",
    "emotionalrulereport",
    "xjsensorstrack",
))
# 命中后的归置：既有的 risk0 噪音标签（与 fix21 ① / fix22 「已知噪音」同一目的地）
ANALYTICS_CALLEE_NOISE_SLUG = IDT.ID_NOISE


def is_analytics_reporting_callee(name: str) -> bool:
    """callee 链（原拼写）是否落在显式报送白名单里。

    归一化 = 去 `$` + 小写 + 去前导点；再按**尾部段**查表（`TAIL2` 末两段 / `TAIL1` 末一段）。
    压缩器给接收者加前缀（`e.sensorsClick.send`）时尾部段不变，所以两张表合起来就是
    父任务那份显式清单本身。
    """
    head = (name or "").replace("$", "").lower().strip(".")
    segs = [seg for seg in head.split(".") if seg]
    if not segs:
        return False
    if len(segs) >= 2 and ".".join(segs[-2:]) in ANALYTICS_REPORTING_CALLEE_TAIL2:
        return True
    return segs[-1] in ANALYTICS_REPORTING_CALLEE_TAIL1


def _analytics_occurrence_positions(value: str, stmt: str):
    """本值在窗口里的**独立出现**位置（细则与 `_bound_value_keys` 逐字相同）。

    「独立出现」：值必须自成字面量 —— 前/后紧邻标识符字符（字母数字 `_` `$`）的出现不算，
    否则「本值只是更长字面量的前缀/后缀」时会把外层的键/callee 算到本值头上。
    """
    out = []
    pos = stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            out.append(pos)
        pos = stmt.find(value, pos + 1)
    return out


def _analytics_bound_key_at(stmt: str, pos: int):
    """出现位置左侧紧邻的绑定键（口径 = `_bound_value_keys` 用的同一台正则）。

    只认「紧邻本值」的 `键:` / `键=` / `"键":`（含 `键: 表达式 || "字面量"` 的默认值写法），
    不做窗口搜索 —— `stmt` 是值周围 512 字符的上下文，窗口里出现某个词不能说明值绑给谁。
    """
    m = _PAYMENT_VALUE_BINDING_RE.search(stmt, 0, pos)
    return m.group(1) if m is not None else None


def _analytics_enclosing_callee_chains(stmt: str, pos: int):
    """覆盖 stmt[pos] 的调用标识符链，**由内到外**。

    正向扫到 pos 为止，维护括号栈（跳字符串与 `//` 注释）；值落在对象/数组字面量实参里时，
    继续往外走到包住它的那个 `(`。只从括号栈里取 `(` 层 —— `{` / `[` 不是调用。
    """
    stack = []
    i = 0
    while i < pos:
        ch = stmt[i]
        if ch in "'\"`":
            quote = ch
            i += 1
            while i < pos:
                if stmt[i] == "\\":
                    i += 2
                    continue
                if stmt[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "/" and i + 1 < pos and stmt[i + 1] == "/":
            nl = stmt.find("\n", i)
            i = pos if nl == -1 or nl > pos else nl
            continue
        if ch in "([{":
            stack.append((ch, i))
        elif ch in ")]}":
            if stack:
                stack.pop()
        i += 1

    chains = []
    for ch, idx in reversed(stack):
        if ch != "(":
            continue
        j = idx - 1
        while j >= 0 and stmt[j] in " \t":
            j -= 1
        end = j + 1
        while j >= 0 and (stmt[j].isalnum() or stmt[j] in "_$."):
            j -= 1
        name = stmt[j + 1:end]
        if name:
            chains.append(name)
    return chains


def is_analytics_callee_argument(value: str, stmt: str) -> bool:
    """fix32 守卫：本值是不是「命名报送 callee 的实参」（判据与代价见上面的注释块）。

    成立条件（缺一不可）：
      · 值含至少一个字母 —— 硬化项：纯数字值（10 位页 ID 那一族，
        `t.$track.pageShowEvent("1732848545", …)`）一律不动；
      · 至少有一次独立出现；
      · **每一次**独立出现都「左侧紧邻没有键绑定」且「最内层包住它的调用在报送白名单里」。
        任一出现绑在键上（`event_name:` / `$element_name:`）或坐在白名单外的 callee
        （`wx.getStorageSync` / `.concat` / `console.log` / `foo(`）实参位上 → 整值不成立。
    """
    if not value or not stmt or not any(c.isalpha() for c in value):
        return False
    positions = _analytics_occurrence_positions(value, stmt)
    if not positions:
        return False
    for pos in positions:
        if _analytics_bound_key_at(stmt, pos) is not None:
            return False
        chains = _analytics_enclosing_callee_chains(stmt, pos)
        if not chains or not is_analytics_reporting_callee(chains[0]):
            return False
    return True


def is_analytics_key(s: str, stmt: str) -> bool:
    """判断是否为统计分析 SDK Key

    fix32：本判据只管「值位置」；坐在**命名报送 callee 实参**位上、且左侧无键绑定的值
    （`sensors.track("h5_click", …)` 这类事件名）由出口处的 `is_analytics_callee_argument`
    接手改判 risk0 噪音，见上面的注释块与 unit-tests/test_fix32_analytics_callee_guard.py。
    """
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


def find_ak_in_neighbors(sk_idx: int, constants: list, statements: list,
                         vetoed_indices: Set[int] = None) -> tuple:
    """在 SK 的邻近索引寻找 AK（fix40：这一对也要过不可能形态闸门）

    方向反过来同样会**新造**假配对：被拒掉的邻居值可能被 `is_access_key` 的**语境**分支
    （AK_CONTEXT_WORDS 里的 `accesskeyid`）当成 AK —— 实测 `{accessKeyId:"LTAI…",
    key:"<支付宝 appid>"}` 在 AK-first 配对被拒后会产出
    `AK=<支付宝 appid>, SK=LTAI…` 这个**改动前不存在**的组合值。所以两个方向都要问。

    `vetoed_indices`（fix40b）：**被否决成员的下标集合**，由闸门否决时写入（`update`）。
    调用方（主链 AK/SK 段）据此让这些成员**不再参与后续配对** —— 见 `find_sk_in_neighbors`。
    刻意**不**在这里读它（不跳过「成员作为邻居」的候选）：邻居搜索本来就不看
    `processed_indices`，改动前「成员以邻居身份参与配对」的配对（pkgref 实测 1 个强前缀
    真配对 `AK=LTAI…(24), SK=…(30)`）在改动前也存在；一旦跳过候选，那些**改动前有**的配对
    会消失（真阳性回退，实测 pkgref 24 -> 23），而且会把另一端的值释放出来（v2 实测 1 个
    值因此新落 platform_app_secret）。反向进入 1201 的机制是**成员在自己下标上发起配对**，
    由主链那一处 `i not in vetoed_indices` 拦住，不需要跳过邻居。
    """
    if vetoed_indices is None:
        vetoed_indices = set()
    if not (0 <= sk_idx < len(constants)):
        return (None, None, None, None)
    sk_val = constants[sk_idx][0]
    for ni in [sk_idx + 1, sk_idx - 1]:
        if 0 <= ni < len(constants):
            ak_val, ak_sid, _ = constants[ni]
            if ak_sid < len(statements):
                is_ak, provider = is_access_key(ak_val, statements[ak_sid])
                if is_ak:
                    if is_impossible_ak_sk_pair(ak_val, sk_val):
                        vetoed_indices.update((sk_idx, ni))   # fix40b：两个成员都不再配对
                        return (None, None, None, None)      # veto：不试另一个邻居，见下
                    return (ak_val, statements[ak_sid], provider, ni)
    return (None, None, None, None)


# =========================================================
# fix40：SK 侧的**不可能形态**闸门（值自己说了算）
# =========================================================
# fix40c（本轮）：闸门加「**强有效半边**」放行 —— 只要一对里有一半强有效（现为 AK 侧强前缀），
# 这一对就照常配对，另一半即使命中下面五类形态也不否决（用户口径：SK 和 AK 有一个正确就行）；
# 例外 ⑤（同一串/互为前缀）不受放行影响。判据与数据依据见 is_strong_valid_ak_half /
# is_strong_valid_sk_half / is_impossible_ak_sk_pair。
# 病根：配对完全靠**常量列表里的邻居下标**，SK 侧只要过
# `is_secret_key_sk(...) or is_sk_format(...)`（16-64 位 b64 字母表）就成立 —— 而 `/`
# 和小写字母都在 b64 字母表里，于是微信 appid、支付宝 appid、路径片段、占位字母表、
# 以及「邻居就是 AK 自己的副本」全都成了「SK」。
# 只读普查（test-result/fix40/probe_sk_shapes.py，normal_quarkpan_v2 的 341 个组合值）：
#   alipay_appid 19、sk==ak/前缀关系 26、路径片段 21、占位字母表 7、wx_appid 5。
# 刻意**不**收的口径（都有实测理由，见 unit-tests/test_fix40_aksk_bad_sk.py 文件头）：
#   · 16~19 位混合字母数字的短 SK（库内 49 个，坐在 `secretKey:"` 键上，是可能的 appSecret
#     材料）；「长度不足」这条在现行代码里也不可达（两个 SK 判据都硬卡 16-64）；
#   · 纯小写 hex（32 位 md5/sha 形，有歧义）；camelCase 词形名（另一族问题）。
# 也刻意**不加**「必须有语境证据才配对」的收紧 —— fix33 已证实那会丢掉约 40% 的真配对。
RE_WX_APPID_SK = re.compile(r"^wx[0-9a-f]{16}$")
RE_ALIPAY_APPID_SK = re.compile(r"^2021\d{12}$")
RE_PLACEHOLDER_ALPHABET_SK = re.compile(
    r"(?:ABCDEFGH|abcdefgh|ABCDEFGHJKMNPQRSTW|abcdefghjkmnpqrstw)")


def is_impossible_sk_candidate(v: str, other: str) -> bool:
    """fix40：`v` 作为**配对成员的半边**是不是不可能（五类值侧形态，任一命中即不可能）。

      ① 微信 appid：`wx` + 16 位小写 hex（`wx1234567890abcdef`）；
      ② 支付宝 appid：`2021` + 12 位数字（正好 16 位，`2021000123456789`）；
      ③ 路径片段：含 `/` 且**没有** `+` / `=` —— `+`/`=` 是 base64 材料的签名，
         真 SK（40 位 b64）常带 `+`/`/`/`=`，路径判据必须留这两个例外；
      ④ 占位字母表：值里出现 8 连的字母序片段（`ABCDEFGH…` / `abcdefgh…` / 30 位那个族）；
      ⑤ 与另一个成员 `other` 是同一个串、或互为前缀（真配对的 AK/SK 是两段独立材料；
         邻居取到同一个常量的副本时就是这个形态）。

    **只看值形态**，不看语境、不问「有没有 SK/secretKey 关键词」—— 配对成立与否由调用方
    （`find_sk_in_neighbors` / `find_ak_in_neighbors`）决定；本函数只回答「这个候选人可能
    不可能」。两个方向都要问：`is_access_key` 的**语境**分支（AK_CONTEXT_WORDS）会把
    appid/占位串也当成 AK，只查 SK 那一侧就会**新造** `AK=<appid>, SK=<真 AK>` 这种
    改动前不存在的组合值（fix40 实测，见 unit-tests 第 ① 组）。
    """
    if RE_WX_APPID_SK.match(v) or RE_ALIPAY_APPID_SK.match(v):
        return True
    if "/" in v and "+" not in v and "=" not in v:
        return True
    if RE_PLACEHOLDER_ALPHABET_SK.search(v):
        return True
    return v == other or v.startswith(other) or other.startswith(v)


def is_strong_valid_ak_half(v: str) -> bool:
    """fix40c：`v` 作为配对半边是不是**强有效**的 AK。

    用户口径：SK 和 AK 有一半「正确」就行 —— 这一半正确时整对照常产出，另一半即使是
    fix40 认定的不可能形态也不否决（用户已确认**保留 `AK=…, SK=…` 组合值本身**，
    不是只留下真的那一半）。

    判据 = `is_access_key` 的**前缀分支**同一形态：以 `AK_PREFIX_PATTERNS`
    （LTAI / AKID / AKIA / ABIA / ACCA / ASIA）之一开头、16-40 位、`isalnum()`。
    刻意**不认**「仅凭语境词（`AK_CONTEXT_WORDS`）识别出的 AK」：语境分支正是 fix40 里把
    appid / 占位串当成 AK 的那一半来源，认它会**新造** `AK=<appid>, SK=<真 SK>` 这种
    改动前不存在的组合值（fix40 实测 2 个）。判据只做前缀与形态，
    **不查语境、不查 `is_secret_key_sk`** —— 与配对入口的关系是「强有效 ⇒ 一定也是 AK」，
    由 unit-tests/test_fix40_aksk_bad_sk.py 的 `test_strong_half_predicates` 钉住。
    """
    return (any(v.startswith(p) for p in AK_PREFIX_PATTERNS)
            and check_length_range(v, 16, 40) and v.isalnum())


def is_strong_valid_sk_half(v: str, other: str = None) -> bool:
    """fix40c：`v` 作为配对半边是不是**强有效**的 SK —— 本轮**恒为 False**（刻意留空）。

    数据依据（都在 test-result/fix40/，合成值之外不落任何真值）：
      · `fix40c_probe_veto_detail.out` / `fix40c_probe_veto_shapes.out`：两库被 fix40 否决的
        76 / 11 个配对值里，**SK 侧每一半自己就是不可能形态**（v2：same 26 / path 19 /
        alipay 19 / alphabet 7 / wx 5；pkgref：wx 5 / same 3 / path 2 / alipay 1）——
        没有一例是「30-64 位、大小写+数字、非 hex 摘要」的材料形；
      · `fix40c_probe_gate_hits.out`（859 个 1201 源文件全量真扫、闸门命中的 118 次配对尝试
        逐个归因）：**SK 侧恒为不可能形态**（alipay 30 / path 24 / wx 13 / alphabet 11），
        「AK 侧不可能而 SK 侧干净」出现 **0 次**；连「材料形 SK」也是 0 次（同一个脚本里用
        候选判据 `30-64 位 + 大小写 + 数字 + 非 hex + 非不可能形态` 数出来的）。
    ⇒ 语料里**不存在**「强有效 SK + 不可能 AK」这半边：硬定一条判据（例如「30-64 位、
    同时含大小写与数字、不是 hex、本身不触发五类不可能形态」）在真扫里**一个值都不会放行**，
    而它唯一的实际作用是在未来扫描里放行 `AK=<appid>, SK=<真材料>` 这种**更差**的配对
    （AK 那一半假、SK 那一半真）。所以本轮定义为恒 False，只放行强前缀 AK。

    留成**显式钩子**（而不是写死 `False`）：日后若有证据（例如出现真 SK 坐在假 AK 旁边的
    现场），只需改这一个函数；接线由 `test_sk_half_hook_can_be_flipped_without_touching_the_gate`
    钉住（运行时替换该函数即能让这类配对产出）。
    """
    return False


def is_impossible_ak_sk_pair(ak: str, sk: str) -> bool:
    """fix40c：这一对要不要**否决**（值侧形态闸门的总闸）。

    顺序（fix40c 起）：
      ① **形态 ⑤ 先判**：两侧同一个串、或互为前缀 ⇒ 一律否决，**不受下面第 ② 条影响**。
         理由（用户确认的例外）：`AK=X, SK=X` 里只有一份材料，第二半是同一个常量的副本，
         等同于不存在的配对；
      ② **有强有效半边 ⇒ 不否决**（照常配对）：AK 侧见 `is_strong_valid_ak_half`、
         SK 侧见 `is_strong_valid_sk_half`（本轮恒 False）。用户口径：有一半正确就行；
      ③ 两个方向都没有强有效半边时，才按 fix40 的五类不可能形态否决。
    """
    if ak == sk or ak.startswith(sk) or sk.startswith(ak):
        return True
    if is_strong_valid_ak_half(ak) or is_strong_valid_sk_half(sk, ak):
        return False
    return is_impossible_sk_candidate(ak, sk) or is_impossible_sk_candidate(sk, ak)


# =========================================================
# fix40b：被否决配对的**成员**显式落点（risk>=4 的出口要改判）
# =========================================================
def is_risk4plus_slug(slug_id) -> bool:
    """fix40b：该类型在 `constant_ids` 的风险表里是不是 **risk>=4**（RISK_HIGH = 4）。

    只在「被 fix40 闸门否决的配对成员」这一条路径上使用（见主链 AK/SK 段与函数末尾的链尾
    改判）：成员不得**新获得** risk>=4 标签 —— 改动前它们被 consume 进 `AK=…, SK=…`
    组合值、自己没有行，改动后按各自分类走，于是 AK id（坐在 `accessKeyId` 语境里的
    16~36 位 alnum）被 `is_app_key` 的 CREDENTIAL 分支判成 platform_app_secret(1101, risk5)。
    """
    entry = IDT.SLUG_TO_DB.get(slug_id)
    return entry is not None and entry[1] >= IDT.RISK_HIGH


def find_sk_in_neighbors(ak_idx: int, constants: list, statements: list,
                         vetoed_indices: Set[int] = None) -> tuple:
    """在 AK 的邻近索引寻找 SK（fix40：候选要先过不可能形态闸门）

    闸门命中的候选**否决这次配对**（`return None`，**不**再试另一个邻居）⇒ 主链不为这一对
    consume AK、也不把 SK 记进 processed_indices，两个成员各自走自己的分类。

    为什么是「否决」而不是「跳过这个候选、再看另一个邻居」：跳过会让配对**换人**，从而
    **新造**出改动前不存在的组合值 —— v2 实测 8 个（9 条链接，newpair 的 AK/SK 两半都在
    16~36 个字符、SK 是 32 位 b64 形，看着像真配对）。本轮授权只是「加不可能判据」，不是
    「重排配对优先级」，而且把值**新扫进** risk5 的 1201 是明确红线；所以改动后
    **产出集是改动前的子集**（旧配对过了闸门就照旧，没过就整对不成立），新配对 0 个。
    代价（如实报告）：上面那 8 个「邻居回退才能找到的配对」本轮**不产出**，
    AK 与 SK 各自走自己的分类（见 test-result/fix40/rescan_aksk_summary_final.txt）。

    `vetoed_indices`（fix40b）：**被否决成员的下标集合**，由闸门否决时写入（`update`）——
    调用方（主链 AK/SK 段）据此让这些成员不再参与后续配对。与 `find_ak_in_neighbors` 同一
    约定：这里**只写不读**（不跳过「成员作为邻居」的候选，理由见那个函数的说明）。
    起因（fix40 的回归，v2 源码重扫实测反向进入 1201）：`[X, X(副本), Y]` 里下标 0 的 X 与
    下标 1 的 X 是 `sk==ak`（被否决），改动前下标 1 被 consume、不会再配对；现在它被释放，
    若它还能**在自己下标上**发起配对，就会和下标 2 的 Y 配成 `AK=X, SK=Y`（改动前不存在）。
    """
    if vetoed_indices is None:
        vetoed_indices = set()
    if not (0 <= ak_idx < len(constants)):
        return (None, None, None)
    ak_val = constants[ak_idx][0]
    for ni in [ak_idx + 1, ak_idx - 1]:
        if 0 <= ni < len(constants):
            sk_val, sk_sid, _ = constants[ni]
            if sk_sid < len(statements):
                sk_stmt = statements[sk_sid]
                if is_secret_key_sk(sk_val, sk_stmt) or is_sk_format(sk_val):
                    if is_impossible_ak_sk_pair(ak_val, sk_val):
                        vetoed_indices.update((ak_idx, ni))     # fix40b：两个成员都不再配对
                        return (None, None, None)
                    return (sk_val, sk_stmt, ni)
    return (None, None, None)


def process_ak_sk_pair(ak_val: str, ak_stmt: str, sk_val: str, sk_stmt: str, 
                       provider: str, src: str, sid: int, res: list):
    """处理 AK/SK 密钥对

    fix33：这里加的是**值侧配对不变量** —— 本函数的产出就是一对 `AK=…, SK=…`，两半必须
    各自过值侧格式（AK 16-40 alnum / SK 16-64 b64 字母表，见 `is_ak_sk_pair_value`）。
    真配对天然满足：`is_access_key` 已经在入口卡住 AK 的长度与字符集，
    `is_secret_key_sk` / `is_sk_format` 也卡住了 SK 的，所以这条对语料是**零影响**
    （5 个库的 761 个组合值逐个回验，见 test-result/fix33/replay_ak_sk_pairing.py）；
    它挡住的是「上游判据放宽后合成出半个对」这类日后回归，并与裸关键词出口
    （`process_generic_digit_prefixed_constant` 里 `CONTEXT_KEYWORDS` 那一段）**合用同一条
    值侧口径** —— 那一处是真正会产出裸值的地方。
    """
    combined_val = f"AK={ak_val}, SK={sk_val}"
    if not is_ak_sk_pair_value(combined_val):
        return
    append_result(res, IDT.CLOUD_CRED_AK_SK_PAIR, combined_val, src, sid)


# =========================================================
# fix33：AK/SK 的「值侧配对」判据（1201 两个出口合用一套口径）
# =========================================================
# 背景（只读普查，脚本与数字见 unit-tests/test_fix33_aksk_value_pairing.py 与
# test-result/fix33/）：normal_quarkpan 的 1201 桶 959 条链接 / 362 个值里，340 个值是
# `process_ak_sk_pair` 产出的 `AK=…, SK=…`（LTAI 136 / AKID 59 / 其余是语境配对），
# 另外 22 个**裸值**（34 条链接）**全部**从 `CONTEXT_KEYWORDS` 的裸关键词出口进来
# （`secret_key` / `secretkey` / `secretid` → 1201，只对数字开头的通用链生效）：
# 那条出口只问「语句里有没有这个子串」，从不问「这个值自己是不是一对」。
#
# 三分（22 个裸值，口径与 unit-tests 里的分组逐条对应）：
#   · 11 个值 / 11 条链接 —— 关键词只是更长标识符的一部分（`merchantContactSecretKey` /
#     `secretkeyDefault` / `signSecretKey` / `secretKeyp`），语句里没有独立成词的关键词、
#     也没有 AK 令牌，值的长 7~15 且够不上材料形态 → 本轮**删**（改判 pii_noise(2304)）；
#   · 6 个值 / 15 条链接 —— 值够得上密钥材料形态（16-19 字符 b64）→ 有歧义，**不删**；
#   · 2 个值 / 4 条链接 —— 语句里看得见真配对（独立成词的 `secret_key`；BAIDU/TX 凭据表里的
#     `AKIDhURU…` 令牌）→ **不删**。
# fix33b（review 缺陷 2）把原先算在「删」里的另 3 个值移出（14/15 → 11/11）：它们都是
# **分隔符形态的密钥材料**（UUID，坐在 `secretKey:` / `javaApiSecretKey:` / `SecretKey:` 键上）
# —— 原「材料形态」判据只认连续 alnum / b64 字母表，加上 `_has_standalone_word` 把窗口起点
# 当作「没字符可判」，两个缺陷叠在一起把它们删成了 pii_noise。两处判据已按 review 修正
# （见 is_credential_material_shape 第三支与 _has_standalone_word 的注释）。
# 刻意**不做**语境式删除：任何「有已知前缀 **或** 语境同时出现 secretid+secret_key 才留下」
# 的规则都不在本轮 —— 组合值里前缀族只占一部分（LTAI+AKID = 195/340），那种规则会把
# DB 可见的已验真配对关系一起丢掉。
AK_SK_PAIR_PREFIX = "AK="
AK_SK_PAIR_SEP = ", SK="

# 「看得见真配对」的关键词：独立成词才算（判定见 _has_standalone_word）。
AK_SK_EVIDENCE_WORDS = ("secret_key", "secretkey", "secret_id", "secretid", "akid")

# 「看得见真配对」的 AK 令牌：前缀后面必须跟着 AK 形态的字符（总长 16-40，与 is_access_key
# 同一口径），否则 `ASIA`（`asia-southeast`）、`acc` 这类普通词会把判据放开。
_VISIBLE_AK_TOKEN_RE = re.compile(
    "(%s)[A-Za-z0-9]{12,36}" % "|".join(sorted(AK_PREFIX_PATTERNS, key=len, reverse=True)))


def split_ak_sk_pair_value(v: str):
    """`AK=<ak>, SK=<sk>` → (ak, sk)；形态不符 → None。

    长度与字符集口径**逐字复用** `is_access_key` / `is_sk_format` 的值侧那一半
    （AK 16-40 alnum、SK 16-64 [A-Za-z0-9+/=]），刻意不另立一套更严的规则 ——
    判据比产出更严就会把真行判成丢对。所以库里 `AK=刷新阿里云sls的临时token,
    SK=/recommend/mygift` 这样的值照样算一对（Python 的 `str.isalnum()` 含 CJK 字母）。
    """
    if not v.startswith(AK_SK_PAIR_PREFIX):
        return None
    rest = v[len(AK_SK_PAIR_PREFIX):]
    if AK_SK_PAIR_SEP not in rest:
        return None
    ak, sk = rest.split(AK_SK_PAIR_SEP, 1)
    if not (check_length_range(ak, 16, 40) and ak.isalnum()):
        return None
    if not is_sk_format(sk):
        return None
    return (ak, sk)


def is_ak_sk_pair_value(v: str) -> bool:
    """值本身是不是一对 `AK=…, SK=…`（1201 的**值侧配对要求**）。"""
    return split_ak_sk_pair_value(v) is not None


def is_credential_material_shape(s: str) -> bool:
    """值自己够不够「密钥材料形态」：AK 形（16-40 alnum）或 SK 形（16-64 b64 字母表），
    或**分隔符形态**（fix33b：UUID / base64url，见下）。

    只有长度与字符集，**不看语境** —— 它回答的是「这个裸值有没有可能是被截断/没配成对的
    真材料」，用来决定裸值能不能删（是则保留 1201 当歧义残渣）。口径与 is_access_key /
    is_sk_format 同源，见 `split_ak_sk_pair_value` 的说明。

    fix33b（review 缺陷 2）：原口径只认连续 alnum 与 b64 字母表，**带分隔符**的材料一律命不
    中 —— `secretKey:` / `javaApiSecretKey:` / `SecretKey:` 键上的 UUID 真密钥
    （`861E3648-B028-4B01-9A61-246B6082464B`）被判成 pii_noise。补第三支：含 `-` / `_` / `.`
    分隔符、总长 16~64、每段都是 alnum、**同时含字母与数字**。长度与「含字母又含数字」两条
    是刻意留的窄口 —— 它把 `2026-04-10-1407`（日期串，无字母）、`merchant-contact-key`
    （词形名，无数字）、`ab-cd-ef-1234`（<16 字符）挡在外面，那一族仍按噪音删。
    """
    if check_length_range(s, 16, 40) and s.isalnum():
        return True
    if is_sk_format(s):
        return True
    if not check_length_range(s, 16, 64):
        return False
    body = re.sub(r"[-_.]", "", s)
    if body == s or not body.isalnum():        # 没有分隔符 / 段里混进了别的字符
        return False
    return any(c.isalpha() for c in body) and any(c.isdigit() for c in body)


def _has_standalone_word(stmt_lower: str, word: str) -> bool:
    """`word` 在语句里**独立成词**：左右各看得见一个非词字符（字母数字 `_` `$` 之外）。

    窗口**起点当作左边界**（fix33b，review 缺陷 2）：`stmt` 是值周围 512 字符的切片，关键词
    正好落在切片起点时，左边**没有字符**只是因为被切掉了，不代表那里接着标识符字符。原写法
    要求 `i > 0`，于是同一个 (值, 键) 只因窗口外多一个字符就换标签：
      `secretKey: "<uuid>"`（关键词落在起点）→ 判不出独立成词 → 被删成 pii_noise；
      `;secretKey: "<uuid>"`              → 独立成词 → 保留 1201。
    现在起点即满足左侧条件，两条一律判独立成词（= 有证据 → 保留），判定与「第 1 个字符是
    什么无关字符」无关。右侧仍要求**看得见**非词字符：`secretKeyp` / `secretkeyDefault`
    这类「关键词后面还接着更长标识符」的写法照旧不算证据。
    真实受影响的两处窗口整段就是 `secretKey: "5cb55d91-07e5-46cc-84f8-92189ecded5e"` /
    `SecretKey: "8dd7913b-…"`（值本身也是 UUID 形态的材料，见 is_credential_material_shape
    的第三支）—— 修复后这两项留在 1201，搬走的是 11 项 / 11 条链接（fix33b 重测）。
    逐条正反例见 unit-tests/test_fix33_aksk_value_pairing.py 第 ⑤ / ⑦ 组。
    """
    start = 0
    while True:
        i = stmt_lower.find(word, start)
        if i < 0:
            return False
        j = i + len(word)
        if j < len(stmt_lower):
            left_ok = i == 0 or not (stmt_lower[i - 1].isalnum() or stmt_lower[i - 1] in "_$")
            right = stmt_lower[j]
            if left_ok and not (right.isalnum() or right in "_$"):
                return True
        start = i + 1


def has_visible_ak_sk_pair_evidence(stmt: str) -> bool:
    """语句里**看得见真配对**的证据（本轮保留裸值的第二条豁免）。

    两类：独立成词的关键词（`secret_key` / `secretkey` / `secret_id` / `secretid` / `akid`），
    或语句里出现 AK 前缀令牌（`AKID…` / `LTAI…` / `AKIA…`）。两类都是「这段文本自己说明
    旁边有配对」—— 值可能只是其中一半（实测：`u.secret_key=(…)concat("40D*da3far…")`；
    BAIDU/TX 凭据表里的 `AKIDhURU…`），所以不删。
    """
    if not stmt:
        return False
    low = stmt.lower()
    if any(_has_standalone_word(low, w) for w in AK_SK_EVIDENCE_WORDS):
        return True
    return _VISIBLE_AK_TOKEN_RE.search(stmt) is not None


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


# ---------------------------------------------------------
# fix30：server_cred_token(1602) 十六进制出口的「标识符族键绑定」守卫
# ---------------------------------------------------------
# 病根：本函数的 token 出口是**裸子串**判据 —— HEX_TOKEN_CONTEXT_WORDS（token / auth /
# authorization / bearer / apikey …）在值周围 512 字符窗口里出现即出口，从不问这个值坐在谁的
# 键位上。于是**绑在标识符键上的十六进制 ID**（文档 / 关系 / 文件 / 包摘要）整族被拽进 risk5。
#
# 只读普查（normal_quarkpan，1602 桶全部 2,073 条链接 / 655 个值；
# 普查脚本 test-result/fix30/analyze_rule_variants.py）：
#   · 值的**每个**独立出现都绑在标识符族键上 = 183 条链接 / 42 个值，其中 168 条链接的值确实
#     是 hex token（`_shasum` 35 / `id` 63 / `target_id` 58 / `source_id` 12）——另外 15 条是
#     `card_id` 上的 JWT（非 hex，走前缀 token 出口，本判据碰不到）；
#   · 这 42 个值**没有一个**同时绑定 token/session 键（MIXED = 0）：十六进制值上「标识符族键」
#     与「凭证键」从不同时出现，「全部键都在标识符族」与「没有任何一次绑在凭证键上」同义；
#   · 归因全靠窗口子串凑巧：`{"id":"dacfba…","path":"utils/auth.js"}`（auth 来自路径）、
#     `"_shasum":"2904ab…","author":{"name":"Evan Vosberg"}`（auth 来自 `author`）、
#     `"target_id":"dacfba…"` 与 `"source_id":"11d510…"`（token 来自同语句的 eventCenter 触发对象）。
#
# 判据：本值每个独立出现左侧紧邻的键（口径 = fix24 的 `_bound_value_keys`，三条绑定判据共用同一台）
# **全部**落在这张表内，且至少有一次绑定 → 值坐在 ID 位置，不是凭证 token。
#   · 键表**只收「键名本身就叫标识符」的写法**，不含任何 token/session 键 —— 所以「全部键都在
#     表内」本身就蕴含「没有任何一次出现绑在凭证键上」；任何一次出现绑在 `token:` /
#     `authToken:` / `Authorization:` 上都会让判据为假（unit-tests/test_fix30_hex_token_id_binding.py
#     的保留组与混合绑定对照组逐条钉住这条线）；
#   · `docid` / `objectid` 是 `docId` / `objectId` 的小写形态（查表前 lower()，与既有键表同口径）。
#   · 已知残留（刻意不扩大）：驼峰拼写 `targetId` / `sourceId` 不在表内（证据里出现的都是
#     snake_case 键名）；同一值另有**无绑定**的独立出现时仍会命中 —— 七库实测更严口径
#     （要求「无绑定的独立出现一票否决」）射程一字不变（183=183、10=10、4=4、13=13、4=4、
#     0=0、0=0），故不为它多养一台扫描器。
HEX_TOKEN_ID_BINDING_KEYS = frozenset((
    "id", "target_id", "source_id", "_shasum",
    "docid", "objectid", "uid", "card_id",
    # fix30c：Mongo/导出式拼写的文档主键。`_id` 多为 ObjectID（24 hex，入口 `is_hex_token`
    # 就拦掉了），这里覆盖的是「主键写成 32/40/64 位 hex 字符串」的导出；`doc_id` 同理。
    # 只读普查（9 库 server_cred_token 桶全部 1,274 个有键行）里，这两个键**一条都不参与**
    # 出线（decisive 行 = 0），加进来是零实测影响的口径补齐；「全部出现都在表内」的规则不变，
    # 所以任何一次出现在 token/session 键上仍然整值不放行。
    "_id", "doc_id",
))


# ---------------------------------------------------------
# fix30b：把「值位置」的归因做对 —— 三元 `? :` 与 switch `case` 的分隔符冒号不是绑定位置
# ---------------------------------------------------------
# 病根（真阳性损失）：`_PAYMENT_VALUE_BINDING_RE` 只要求「键 + 引号/空白 + `:`/`=` + 引号/空白」
# 的**邻接**，分不出这个 `:` 是成员分隔符还是三元/switch 的分隔符。于是三元分支里的 `id`、
# `case id:` 的标签被当成「本值的绑定键」，而它们恰好都在上面这张表里 → 真 token 被静默丢弃
# （守卫一命中就 `return`，连标签都不出口）：
#     const token=data.id?data.id:"<hex>"    ← 真正的绑定是 `token =`，不是三元真分支的 data.id
#     x={token:cfg.id?cfg.id:"<hex>"}         ← 同上（三元冒号）
#     switch(x){case id:"<hex>"}              ← `case id:` 是标签，不是成员绑定
# 三条的对照：把守卫关掉都是 1602（`test_guard_is_the_change` 同一条口径），所以差别全在这条判据。
#
# 判据（只动本守卫的键归属，不动共用正则、不动 `_bound_value_keys`）：
#   · 真绑定位置 = `=` 分隔符，或左侧同一成员段里没有 `?` 的成员 `:` → 候选键就是绑定键；
#   · 三元冒号 / `case` 标签冒号 → 候选键不是绑定键，改归因到**宿主键**（`{token:x?y:"v"}` 的
#     `token`、`const token=x?y:"v"` 的 `token`）—— 让「值其实属于凭证键」这类混合绑定照旧
#     挡住消费（`is_hex_token_id_bound` 要求**每次出现**都在标识符族键上）；
#   · 但宿主键**只用来洗清、不用来定罪**：宿主键落在标识符族键表里时不产出
#     （`{id:cond?a:"v"}` 的 `a` 是三元真分支、`case id:"v"` 的 `id` 是标签，都不是「这个值
#     坐在 ID 键位」的证据）。这条把「归因修正」的射程限死在**减少误消费**上，不新增消费。
_HEX_TOKEN_CASE_LABEL_RE = re.compile(r"(?:^|[^\w$.])case(\s*)$")
_HEX_TOKEN_ENCLOSING_KEY_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*[\"']?\s*[:=]")
_HEX_TOKEN_MEMBER_BOUNDARY = ",;{}"
_HEX_TOKEN_SEGMENT_STOP = "=(["


def _hex_token_binding_candidates(value: str, stmt: str):
    """本值每个**独立出现**左侧紧邻的绑定候选（`re.Match`，键 = group(1)）。

    「独立出现」与「紧邻左侧的键」两条细则逐字沿用 `_bound_value_keys`（同一台
    `_PAYMENT_VALUE_BINDING_RE`、同样 `search(stmt, 0, pos)` 取最近一次匹配），只是把匹配对象
    本身交出来 —— fix30b 的判断要看分隔符的下标，光有键名不够。
    """
    pos = stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            m = _PAYMENT_VALUE_BINDING_RE.search(stmt, 0, pos)
            if m is not None:
                yield m
        pos = stmt.find(value, pos + 1)


def _hex_token_ternary_question(stmt: str, key_start: int):
    """候选键左侧同一成员段里的三元 `?` 下标；没有则 None。

    从键起点往前扫，遇到成员段边界（`, ; { }`）、顶层开括号（`( [`）或赋值 `=` 就停：
    `x={id:cond?a:"v"}` 的 `?` 在 `{` 之后、`a` 之前，属于本次出现；而
    `{a:b?c:d, id:"v"}` 里那个 `?` 隔着 `,`，不会波及 `id` 这次出现的判断。
    """
    for i in range(key_start - 1, -1, -1):
        ch = stmt[i]
        if ch in _HEX_TOKEN_MEMBER_BOUNDARY or ch in _HEX_TOKEN_SEGMENT_STOP:
            return None
        if ch == "?":
            return i
    return None


def _hex_token_enclosing_key(stmt: str, stop: int):
    """`stop` 左侧同一成员段里最近的 `键[:=]`（口径 = fix28 的 `_iv_nearest_left_key`）。

    用在「候选的分隔符不是绑定位置」时，把一个三元表达式归因给它真正的宿主键：
    `{token:cond?a:"v"}` → `token`、`const token=x?y:"v"` → `token`；找不到返回 None
    （`case id:"v"` 这种标签没有宿主键）。
    """
    best = None
    for m in _HEX_TOKEN_ENCLOSING_KEY_RE.finditer(stmt, 0, stop):
        if any(ch in _HEX_TOKEN_MEMBER_BOUNDARY for ch in stmt[m.end():stop]):
            continue
        best = m.group(1)
    return best


def _hex_token_value_position_keys(value: str, stmt: str):
    """本值每个独立出现**归因到的绑定键**（原拼写；无法归因的出现不产出）。

    归因规则（fix30b）见上面的注释块：真绑定位置产出候选键；三元/`case` 的分隔符不是绑定，
    改归因到宿主键且宿主键只在**非**标识符族键时才产出（只洗清、不定罪）。
    """
    for m in _hex_token_binding_candidates(value, stmt):
        key, key_start = m.group(1), m.start(1)
        sep = None
        for i in range(m.end(1), len(stmt)):
            ch = stmt[i]
            if ch in ":=":
                sep = i
                break
            if ch not in " \t\r\n'\"":
                break
        if sep is None or stmt[sep] == "=":
            yield key
            continue
        question = _hex_token_ternary_question(stmt, key_start)
        case = (_HEX_TOKEN_CASE_LABEL_RE.search(stmt[:key_start])
                if question is None else None)
        if question is None and case is None:
            yield key
            continue
        host = _hex_token_enclosing_key(
            stmt, question if question is not None else case.start(1))
        if host is not None and host.lower() not in HEX_TOKEN_ID_BINDING_KEYS:
            yield host


def is_hex_token_id_bound(s: str, stmt: str) -> bool:
    """本值每个独立出现都绑在标识符族键上（键表见上）→ 它是 ID，不是凭证 token。

    只看**紧邻本值左侧**的 `键:` / `键=` / `"键":`（`键: 表达式 || "字面量"` 的默认值写法算在
    同一个键上），不做窗口搜索：`stmt` 是值周围 512 字符的上下文，窗口里出现 token 词不能说明
    这个值是谁的值 —— 那正是本判据要修的。本值必须**自成字面量**，两条细则与 fix24/fix25/fix26
    完全一致（共用 `_bound_value_keys` 的同一台正则与同一套「独立出现」细则）。

    键归属再过一道 fix30b 的「真绑定位置」过滤（见上面的注释块）：三元 `? :` 的真/假分支与
    switch `case` 标签都不是绑定位置，不能拿它们里面的 `id` 当「值坐在 ID 键位」的证据。
    扫描器 `_hex_token_value_position_keys` 与 `_bound_value_keys` 同口径，只是多带位置信息。
    """
    keys = [key.lower() for key in _hex_token_value_position_keys(s, stmt)]
    return bool(keys) and all(key in HEX_TOKEN_ID_BINDING_KEYS for key in keys)


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
        # fix30：值位置**全部**绑在标识符族键上 -> 坐在 ID 位置，不是凭证 token（判据见上）。
        # 这里 `return` 而不是「不放行这一条、继续往下落到 session 出口」：命中的值已判定
        # 「不是凭证」，落到下面会**平移进 risk5 的 server_cred_session_key** —— 与「归置到
        # risk0」冲突（普查里双语境同时成立的链接为 0，但这是判据不变量，不靠语料巧合）。
        # session 出口自身的判据与可达输入集一行未改：token 语境缺席时本守卫根本不求值。
        if is_hex_token_id_bound(s, stmt):
            return
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


def is_prepay_id_shaped(s: str) -> bool:
    """`prepay_id=` 之后是否**像一个预支付 ID**（纯值形判据，不看语境）。

    病根（fix45）：package 分支原先只看前缀 `s_lower.startswith("prepay_id=")`，等号后面是什么
    完全不看 —— 两库普查（test-result/fix45/step1_grouping.md，v2 34 值 + pkgref 1 值，逐个打开
    真实源文件读 ±200 字符）里过半数是「不是 package 取值」的东西：

      · 左半拼接片段：裸前缀 `prepay_id=`（v2 1 值 3009 次 745 应用 / pkgref 1 值 229 次 113 应用），
        写法 `package:"prepay_id=".concat(r)`、`package:"prepay_id=" + res.prepay_id`。全量核验
        3009+229 次出现的右侧 6 字符直方图 **100%** 以引号开头（等号后紧跟字符串结束引号）；
      · 判等哨兵：`"prepay_id=null" == t.data.prepay.package`（未绑定商户分支）、`"prepay_id=undefined"`；
      · 测试夹具/占位词：`prepay_id=1` / `=jqx` / `=legacy` / `=upgrade` / `=member-cancel` /
        `=recharge-cancel` / `=calcSingle-0000000000` / `=1234567890abcdef`（同一文件里它还被当假 appId）。

    判据三条（为什么这么定，依据同一次普查）：
      ① 等号后非空；
      ② 以 `wx` 开头 —— 微信预支付 ID 的唯一前缀。语料 19 个真形态值 100% 命中；4 个非 wx 体里
         有一个（`1234567890abcdef`）正在同一文件里当**假 appId** 用，非 wx 体不构成预支付 ID；
      ③ `wx` 之后是 ASCII 字母数字、长度 ≥ 12、至少含 1 位数字。下界取 12 是因为语料里
         占位族尾部 ≤ 11（`jqx` 3 / `1` 1 / `131430354` 9）而 wx 形态 ≥ 15，12 落在**空隙**里，
         且远低于真实形态（文档示例形态 34）⇒ 只砍明确不是预支付 ID 的形态。要「≥1 位数字」
         是因为真值的 wx 后第一段就是日期段（语料 19 个 wx 值全部含 8~14 位数字，纯字母 wx 体 0 例）。
      **不设上界**：语料最大 36，没有需要上界的证据，不添加无据规则。

    不过闸门的值由 is_payment_param 显式改判 payment_noise(2407, risk0) —— 见那里的注释。
    """
    body = s.lower()
    if not body.startswith(PAYMENT_PACKAGE_PREFIX):
        return False
    body = body[len(PAYMENT_PACKAGE_PREFIX):]
    if not body.startswith("wx"):
        return False
    tail = body[2:]
    if len(tail) < PREPAY_ID_WX_BODY_MIN or not _PREPAY_ID_WX_BODY_RE.match(tail):
        return False
    return any(char.isdigit() for char in tail)


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
        # fix45：等号后面必须**像一个预支付 ID** 才判 2403（判据与数据依据见 is_prepay_id_shaped）。
        # 不过闸门的值**显式**改判 payment_noise(2407, risk0) 并在这里 return，而不是让判据返 False
        # 往下坠：实测（关掉本分支的开关对照，v2 全 34 个值里被改判的 16 个）——13 个在改动后
        # **不产出任何标签**（静默消失），另 3 个（`prepay_id=1` / `=2` / `=1234567890abcdef`）
        # 会平移进 pii_noise(2304)。归置口径同 fix32/fix39/fix40b：不许只摘标签，也不许挪进别的桶。
        if is_prepay_id_shaped(s_lower):
            return (True, IDT.PAYMENT_PACKAGE)
        return (True, IDT.PAYMENT_NOISE)

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


# =========================================================
# fix21 ①：值形成立但不是标识值的「标识符噪音」
# =========================================================
# 病根：is_identifier 的两条**纯值形臂**（16 位十六进制 android16、17 位 MAC）不看语境
# 就判 id_device_identifier，于是值形撞上就进桶。三库实测 id_device 桶 3,807 值 /
# 47,735 次里，下面五族占 1,761 值 / 39,285 次（82.3%），语境里没有任何设备语义：
#   支付宝 ISV appid  ^2021\d{12}$           474 值 / 25,473 次（appid_ali / isvAppId）
#   十六进制字母表本体                        19 值 / 10,895 次（"0123456789abcdef"）
#   组播位 MAC（含 macList 的 FF:03:00 清单）1,528 值 /  3,063 次
#   DER 编码的 X.509 扩展 OID（1.3.6.1 弧）    10 值 /    249 次
#   连号 / 整块重复的 16 位十六进制占位         27 值 /    984 次
# 归置：改判 id_noise(2505, risk 0, "Identifier noise") —— 不新增类型、不丢弃（值仍可回溯），
# 与 fix20 ④ 把编译产物改判 miniapp_noise 的做法同型。
# 误伤体检（逐族单独跑，见 test-result/fix21/c_rules.py）：五族迁出的值里，语境含设备
# 关键词的只有 1 个 —— 十六进制字母表自身恰好出现在某个 getDeviceId 函数体内，仍是噪音。
# 刻意**不**做的：16 位十六进制一刀切（那是 Android ID 的合法值形）、非 FF:03:00 单 OUI 的
# MAC 清单（PII 上无法与真设备 MAC 区分，见报告）。
RE_ALIPAY_ISV_APPID = re.compile(r"^2021\d{12}$")
HEX_ALPHABET_CHARS = frozenset("0123456789abcdef")
# DER 内容字节以 1.3.6.1 开头的 OID（X.509 证书扩展弧）：2b=1.3、06=6、01=1。
# 1.2.840.* 那一支由更早的 _is_asn1_oid_hex（2a8648 前缀）负责。
DER_OID_HEX_PREFIXES = ("2b0601",)


def _is_hex_alphabet_table(s: str) -> bool:
    """16 位且字符集恰好是 {0-9a-f} 全部十六个 —— 十六进制字母表本身，不是标识值。

    真 Android ID 要在 16 位上把十六个十六进制字符各用一遍，概率 16!/16^16 ≈ 1.1e-5；
    三库命中的 19 个值全部是编解码表/示例常量（"0123456789abcdef"、"1234567890abcdef"）。
    """
    return len(s) == 16 and set(s.lower()) == HEX_ALPHABET_CHARS


def _is_multicast_mac(s: str) -> bool:
    """MAC-48 首字节最低位为 1 = 组播地址，不可能是设备（单播）硬件地址。"""
    if not is_mac_address_format(s):
        return False
    return int(s[:2], 16) & 0x01 == 1


def _is_der_oid_hex(s: str) -> bool:
    """16 位十六进制且是 DER 编码的 X.509 扩展 OID（1.3.6.1.* 弧）。

    三库命中的是 jsrsasign / wx_rsa 这类证书解析库里的 `2b06010505073001`
    （= 1.3.6.1.5.5.7.3.1 serverAuth），语境是 getExtAuthorityInfoAccess / getHexOfV_AtObj。
    判据只看值形：真 Android ID 落在 2b0601 前缀上的概率是 16^-6 ≈ 6e-8。
    """
    return len(s) == 16 and is_hex_string(s) and s.lower().startswith(DER_OID_HEX_PREFIXES)


def _is_repeated_block(s: str) -> bool:
    """值由整块重复拼成（12345678|12345678、1234|1234|1234|1234）。"""
    for n in (2, 3, 4, 8):
        if len(s) % n == 0 and s == s[:len(s) // n] * n:
            return True
    return False


def _is_sequential_hex_placeholder(s: str) -> bool:
    """16 位十六进制，且数字部分是步进链（相邻 ±1，9→0 视作 +1）或整块重复。

    命中的是 `1234567890123456` / `8765432112345678` / `1234567812345678` 这类密钥/IV/
    示例占位（aesPassword、enc.Utf8.parse），不是 Android ID。真 Android ID 是 64 位随机值，
    连成一条步进链的概率可忽略（实测三库 27 个值全部是占位形态）。
    """
    if len(s) != 16 or not is_hex_string(s):
        return False
    if _is_repeated_block(s):
        return True
    if not s.isdigit():
        return False
    for i in range(len(s) - 1):
        a, b = int(s[i]), int(s[i + 1])
        if not (abs(a - b) in (0, 1) or (b - a) % 10 == 1 or (a - b) % 10 == 1):
            return False
    return True


def is_identifier_shaped_noise(s: str) -> bool:
    """「值形成立但不是标识值」的五族噪音（见上方注释与量化的族规模）。"""
    return (RE_ALIPAY_ISV_APPID.match(s) is not None
            or _is_hex_alphabet_table(s)
            or _is_multicast_mac(s)
            or _is_der_oid_hex(s)
            or _is_sequential_hex_placeholder(s))


def is_name_like_identifier_value(s: str) -> bool:
    """值形像「名字/文案」而不是「标识值」（fix21 ③④）。

    两族：
      含非 ASCII —— 中文文案、单据提示（`沪ICP备2023016466号`、`未传入订单orderid`、
        `服务提交orderid与requestid校验失败`）；
      全字母 —— 常量名/状态名/存储键/回调名（`PASSPORT`、`PROCESSING`、
        `GetUserPhoneNumBerState`、`delivererPhone`、`qianzhudenlgu`）。
    编号类标识值（uid/openid/unionid、订单号）都带数字，故不受影响；已带数字的常量名
    （`SESSIONTOKENA1` 这类）由调用点既有的驼峰排除处理。
    """
    return (not s.isascii()) or s.isalpha()


# fix22：identifier 臂「按命名形态拒掉」的回报值（口径见 is_identifier 的 docstring）。
#
# 病根：fix21 ③④ 把一批「名字/文案形态」的值从 identifier 臂排除出去，但这些值**被排除后
# 继续往下走**，落到下游的凭证判据上 —— 三库用真实 (值, 上下文) 重跑实测 14 行 / 17 次
# （cloud_cred_password 13 行、server_cred_cookie 1 行）由 risk 2~3 升到 risk 5，与 fix11
# 「收严支付参数后 220 值改判 cloud_cred_password」同型：**收严一处会让下游的既存误报显形**。
# 这批值是**已知的名字类噪音**（13 行进 cloud_cred_password：`ByPhoneRegisteredUsers`、
# `IdCardOcrAsync`、`VerifyPhoneRegister`、`MobileNumberToLoginOrRegistered`(两库)、
# `PhoneNumber`、`csairlugtransH5`/`emallH5Sichuan`/`holidayBocheH5`/`holidayPostScheduleH5`/
# `holidayViewTicketH5`/`rentalcarsH5`/`taskCenterModel5` 七个页面别名；
# 1 行进 server_cred_cookie：`在线建档h5需要unionId`），不该出现在任何风险桶里。
#
# 归置：改判既有的 id_noise(2505, risk 0) —— 不新增类型、不丢弃（与 fix21 ① 同型）。
# ⚠️ 归置**只在调用点、且只在凭证判据真要接手时**发生（见 perform_constant_classifying
# 里的 fix22 注释）。反过来，若在这里直接 `return (True, IDT.ID_NOISE)`，改动面会从 14 行
# 涨到 422 行：多出的 408 行里 406 行现在**根本不产出任何类型**（丢弃 → id_noise），
# 另有 2 行 id_device 值的标签集合被改（其中 `获取用户OPENID失败` 的首标签会从
# id_device 变成 id_noise）—— 都属于「改动面超出本轮授权」的范围，故不做。
#
# 刻意**不**接进闸门的两条命名排除（user 臂的 `islower()+isalpha()` 与首小写驼峰）：
# 它们是改动前就有的判据，把它们一起接上会额外翻转 82 行**既存**的同类误报
# （`userInfoV1` / `passWord2` / `apiPlatformUrl10093` …，全部已是 risk 5 的误报，
# 不是本轮 fix21 造成的升级）—— 同样属于本轮授权之外，留待专项处理。
NAME_CLASS_REJECT = (False, IDT.ID_NOISE)


def is_identifier(s: str, stmt: str) -> tuple:
    """检测是否为标识符，返回 (是否匹配, 分类ID)。

    fix22 的三态约定：**只因「命名形态排除」落选**时返回 `NAME_CLASS_REJECT`
    = (False, IDT.ID_NOISE)，即「不是标识值，而且是已知的名字类噪音」；其余落选仍是
    (False, None)。调用点据此在下游凭证判据要接手时把它 consuming 成 id_noise。
    """
    s_len = len(s)

    if is_placeholder_value(s) or _is_asn1_oid_hex(s):
        return (False, None)

    # fix21 ①：值形成立但不是标识值的「标识符噪音」—— 改判 id_noise(2505, risk 0)，
    # 拦在两条纯值形臂（android16 / mac17）之前，否则值形撞上就进 id_device。
    if is_identifier_shaped_noise(s):
        return (True, IDT.ID_NOISE)

    # 纯格式匹配
    if is_valid_imei(s) or is_android_id_format(s) or is_mac_address_format(s):
        return (True, IDT.ID_DEVICE_IDENTIFIER)

    if is_oaid_format(s) and has_keyword_in_context(stmt, DEVICE_ID_KEYWORDS):
        return (True, IDT.ID_DEVICE_IDENTIFIER)

    if is_uuid_format(s):
        if has_keyword_in_context(stmt, DEVICE_ID_KEYWORDS):
            return (True, IDT.ID_DEVICE_IDENTIFIER)
        if has_ad_id_context(stmt, s):
            # fix44：广告语境里的名字形值改判 id_noise(risk0)，不许继续往下落
            # （见 is_ad_identifier_name_like 的注释块）
            if is_ad_identifier_name_like(s):
                return (True, IDT.ID_NOISE)
            return (True, IDT.ID_AD_IDENTIFIER)
        if has_user_id_context(stmt, s):
            return (True, IDT.ID_USER_IDENTIFIER)
        if has_keyword_in_context(stmt, ORDER_ID_KEYWORDS):
            return (True, IDT.ID_ORDER_IDENTIFIER)

    # 上下文 + 精准长度匹配
    if has_keyword_in_context(stmt, DEVICE_ID_KEYWORDS):
        if s_len in VALID_DEVICE_ID_LENGTHS and s.isalnum():
            return (True, IDT.ID_DEVICE_IDENTIFIER)

    if has_ad_id_context(stmt, s):
        if s_len in VALID_DEVICE_ID_LENGTHS and s.isalnum():
            # fix44：广告语境里的名字形值改判 id_noise(risk0)（见 is_ad_identifier_name_like）
            if is_ad_identifier_name_like(s):
                return (True, IDT.ID_NOISE)
            return (True, IDT.ID_AD_IDENTIFIER)

    if has_user_id_context(stmt, s):
        if check_length_range(s, 8, 64) and (s.isdigit() or s.isalnum()):
            # 排除纯小写字母的常见命名模式（页面名、事件名等）
            if s.islower() and s.isalpha():
                return (False, None)
            # 排除驼峰命名模式（如 pageMyPhoneAuth, liveBindPhone）
            if s[0].islower() and any(c.isupper() for c in s):
                return (False, None)
            # fix21 ③：排除「名字/文案」形态（中文串、全字母的常量名与状态名）
            # fix22：这条是 fix21 **新加**的排除，落选时回报 NAME_CLASS_REJECT
            # （上面两条更早的命名排除是改动前就有的，本轮不动其行为，理由见常量注释）。
            if is_name_like_identifier_value(s):
                return NAME_CLASS_REJECT
            return (True, IDT.ID_USER_IDENTIFIER)

    if has_keyword_in_context(stmt, ORDER_ID_KEYWORDS):
        if check_length_range(s, 12, 64) and (s.isdigit() or s.isalnum()):
            # fix21 ④：order 分支原先一条命名模式排除都没有，与 id_user 分支同口径补齐
            # fix22：这三条都是 fix21 新加的，落选即「名字类噪音」
            if s.islower() and s.isalpha():
                return NAME_CLASS_REJECT
            if s[0].islower() and any(c.isupper() for c in s):
                return NAME_CLASS_REJECT
            if is_name_like_identifier_value(s):
                return NAME_CLASS_REJECT
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
def _cloud_token_match(s: str) -> tuple:
    """入口粗筛：前缀 + 长度 20..200 + 前缀专属体形（CLOUD_TOKEN_BODY_PATTERNS）。

    返回 (是否命中, provider, prefix)。fix41 把原 `is_cloud_token` 的函数体原样搬进来，
    只多回一个 prefix（出口的形态判定要用它切体）。
    """
    for prefix, provider in CLOUD_TOKEN_PREFIXES.items():
        if not s.startswith(prefix):
            continue
        body_pattern = CLOUD_TOKEN_BODY_PATTERNS.get(prefix)
        if body_pattern is not None and not body_pattern.match(s[len(prefix):]):
            continue
        if check_length_range(s, 20, 200):
            return (True, provider, prefix)
    return (False, None, None)


def is_cloud_token(s: str) -> tuple:
    """检测是否为云服务 Token，返回 (是否匹配, 服务商)

    少数前缀（如 npm_）额外要求体形匹配，见 CLOUD_TOKEN_BODY_PATTERNS。

    ⚠️ 这是**入口粗筛**（fix41 澄清）：只做「前缀 + 长度（+ 个别前缀的体形）」，
    **不判值自己像不像 token**。返回 True 只代表「进入 token 出口」，形态细分在
    `process_cloud_token`。语义与返回值契约一字未改（既有测试照旧）。
    """
    ok, provider, _prefix = _cloud_token_match(s)
    return (ok, provider)


def is_cloud_token_value(s: str) -> bool:
    """fix41：这个值自己**是不是**一个云服务 Token（前缀 + 体字符集 + 该前缀最短体长）。

    两道判据都只看值自己：
      · 字符集：前缀之后的体必须匹配 `CLOUD_TOKEN_CHARSET_RE`（**含空白即否**；
        `pk_test_paper_title flex-c` 就是被这一条挡下的）；
      · 最短体长：Stripe 族（`pk_/sk_/rk_ × live_/test_`）的体至少 24 位字母数字，
        见 `CLOUD_TOKEN_VALUE_BODY_PATTERNS`（与既有 `npm_` 体形正则同一机制）。
    """
    ok, _provider, prefix = _cloud_token_match(s)
    if not ok:
        return False
    body = s[len(prefix):]
    if not CLOUD_TOKEN_CHARSET_RE.match(body):
        return False
    pattern = CLOUD_TOKEN_VALUE_BODY_PATTERNS.get(prefix)
    return pattern is None or bool(pattern.match(body))


def process_cloud_token(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云服务 Token（fix41：形态细分放在**出口**）

    形态合格 → cloud_cred_token(1205, risk5)；不合格 → **显式**改判
    cloud_cred_noise(1207, risk0)。为什么不直接让 `is_cloud_token` 返回 False：
    那条路会把值放回主链继续往下走，而本值的体含空格 ⇒ 落到
    `process_generic_spaced_constant`，它是 `pass`（不产出任何标签 = **静默丢弃**）——
    fix32 已把「只摘标签 / 静默消失」列为禁止项。
    """
    if is_cloud_token_value(s):
        append_result(res, IDT.CLOUD_CRED_TOKEN, s, src, sid)
    else:
        append_result(res, IDT.CLOUD_CRED_NOISE, s, src, sid)


# =========================================================
# 云平台 Cookie 检测
# =========================================================
def is_cloud_cookie(s: str) -> bool:
    """云平台 Cookie 的**入口粗筛**：长度 ≥10、含 `=`、小写后含 CLOUD_COOKIE_NAMES 之一。

    ⚠️ fix39：这一层**故意保持宽松**（一字未改）。里面的 `uin=` / `skey=` 是常见 URL
    查询参数名，所以命中它的绝大多数是 URL 片段 —— 但**不能在这里返回 False**：
    那会把值放回主链继续往下走，实测有值会漂进 `server_cred_cookie`(1604, **risk5**)
    以及 `miniapp_api_params` / `pii_noise` / `other`（见
    unit-tests/test_fix39_cloud_cookie_url.py 第 ③ 组钉住的漂移）。形态细分与改判
    都在出口 `process_cloud_cookie`。
    """
    if len(s) < 10 or "=" not in s:
        return False
    return has_keyword_substring(s.lower(), CLOUD_COOKIE_NAMES)


# fix39：cookie **文**的两种形态（只看值自己，不看语境）
#   · Set-Cookie 头：`name=value;` 后跟 Path= / Domain= / Expires= 等属性；
#   · 单个 `name=value` cookie 令牌：无空白、name 与 value 都在 cookie 名字/值字符集里、
#     value 非空（`accessKey=` / `==busKey====` 这类**空值键名片段**不是令牌）。
# 其余一律不是 cookie 文：值含 `?` / `&` / `/`（`://` 必然含 `/`）或含空白（日志句子）。
_COOKIE_HEADER_RE = re.compile(r"^[^=;\s]+=[^;]*;")
_COOKIE_HEADER_ATTR_RE = re.compile(
    r";\s*(?:path|domain|expires|max-age|secure|httponly|samesite|version|comment)\b", re.I)
_COOKIE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]+=[A-Za-z0-9._~%+\-]+={0,2}$")


def is_cloud_cookie_literal(s: str) -> bool:
    """fix39：这个值自己是不是一段 cookie 文（Set-Cookie 头 / 单个 `name=value` 令牌）。"""
    if _COOKIE_HEADER_RE.match(s) and _COOKIE_HEADER_ATTR_RE.search(s):
        return True                       # Set-Cookie 头：属性里带 `/` 与空白，必须先判
    if any(ch in s for ch in "?&/"):      # URL 查询片段 / 协议串（`://` 里含 `/`）
        return False
    if any(c.isspace() for c in s):       # 成段文字：日志句子
        return False
    return _COOKIE_TOKEN_RE.match(s) is not None


def process_cloud_cookie(s: str, stmt: str, src: str, sid: int, res: list):
    """分类云平台 Cookie（fix39：形态细分放在**出口**）

    cookie 文 → cloud_cred_cookie(1206, risk4)；不是 cookie 文（URL 查询片段 / 日志串 /
    空值键名片段）→ **显式**改判 cloud_cred_noise(1207, risk0)。显式改判是刻意的：
    见 `is_cloud_cookie` 的说明（让粗筛返回 False 会漂进 risk5 的 server_cred_cookie）。
    """
    if is_cloud_cookie_literal(s):
        append_result(res, IDT.CLOUD_CRED_COOKIE, s, src, sid)
    else:
        append_result(res, IDT.CLOUD_CRED_NOISE, s, src, sid)


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
# 判据：值由 `.` / `-` / `_`（**单个**，或**同字符双写** `__` / `--`）分隔成 ≥2 段，
#   每段是「纯字母（任意大小写）+ 可选结尾数字」。
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
# 窄口补齐：BEM 类名用**同字符双写分隔符**（`__` 元素 / `--` 修饰符），而 `[.\-_]` 只认单个，
# 于是 `mt-input__icon` / `field__error-message` / `password-component--bank-navbar`
# 从判据漏出，在 pwd/password 语境下被判 cloud_cred_password(1203)。
# 分隔符只加「同字符双写 `__` / `--`」这一支，**单分隔符分支原样保留**；**混写**的连续
# 分隔符（`..` / `.-` / `._` / `-_` …）与连写 3 个以上都**不收** —— 证据只支持 BEM 的
# `__` / `--`，混写里唯一出现的是属性路径 `that._onHide1`（不是 BEM），不做无证据的放宽。
# 段的形状 `[A-Za-z]+[0-9]*`（每段必须以字母开头）原样保留 —— 纯数字段仍不在射程内，
# 材料形 `MyPwd__2024` 不命中。新判据是旧判据的**严格超集**（只多出同字符双写分支），
# 「每段以字母开头」这一形状不变量才是真阳性保护的实际机制。
RE_IDENTIFIER_NAME_VALUE = re.compile(r"^[A-Za-z]+[0-9]*(?:(?:--|__|[.\-_])[A-Za-z]+[0-9]*)+$")


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


# =========================================================
# 云服务密码的「三族结构噪音」窄口守卫（fix31）
# =========================================================
# 问题：cloud_cred_password(1203) 里混着两类完全不同的东西 —— **真密码/真材料**（fix12
# 人工核定的红线值），以及**语句里出现 password/pwd 词、值却是别的东西**的噪音：日志
# 调试 tag、URL 查询片段、字段名。它们能进来仍是同一个成因：has_cloud_password_context
# 判的是整段语句，值旁边的 `passWord` / `pwd` 段就能把闸门顶开。
#
# fix31b（review 缺陷 1）修正这轮留下的过收：② 与 ③ 合起来等价于只要求 ③（② 的拼接条件被
# ③ 完全包含 —— ④ 行判据里 `concat and url_fragment` 之后紧跟 `return url_fragment`），
# 于是**未绑定**的真材料只要带一个 URL 语法字符就整值掉出 1203：base64 的 `=` 填充
# （`Zq0s69…99993` 是 ② 组点名保护的盐，末尾补一个 `=` 即失守；`vPYkA3…Ps=` 是 fix12 红线
# 值）、盐里的 `&` / `:`。现在在 ① 之后、②/③ 之前加**材料形豁免**
# `is_cloud_password_material_shape`：值像凭证材料（base64 带 `=` 填充 / 材料字符 + 数字或
# 大写 / 大小写混排 + 数字）就不再按形态删；真 URL 片段（路径 `/a/b`、查询 `?x=1` /
# `&toRoot=1` / `===`、`key=value` 赋值 `roomId=`）与日志 tag 仍一律删（① 排在豁免之前）。
# 逐条正反例与「两族真删掉的值一个都不是材料形」的不变量见 unit-tests/test_fix31_ccp_
# family_guards.py 第 ⑦ 组；四库只读回放的修复前后对照见 test-result/fix31/replay_fix31.py。
#
# 本轮**只收结构上确定的三族**，且**不改绑定口径**（不引入「必须绑在密码键上才算真」的
# 值绑定闸门 —— 只读探针证明那会丢掉 70% 已核定的真阳性锚点与全部键名位）。三族判据
# 都只看**本值**与它在语句里的位置：
#
#   ① 日志/调试 callee 的实参（is_cloud_password_log_call_tag）
#      本值自成字面量地坐在严格 callee 表的调用实参位上：
#      `console.<任意> | __f__ | log | track | report | error`（RE_CCP_LOG_CALLEE，
#      callee 必须**整词命中**）。库内头部：`console.log("=passWord==", t)` /
#      `console.log("------onShow")` / `console.log("that._onHide1", …)`。
#      量化（normal_quarkpan 整桶链接口径，含现行口径已不复现的行）：563 链接 / 109 值，
#      其中 83 链接现行口径已不判 1203。
#
#   ② `+` 连接的 URL/查询片段（is_cloud_password_concat_operand + 值形）
#      本值所在字符串字面量是**拼接运算的一个分量**（字面量一侧紧邻 `+`，跳过空白），
#      **且**本值自身是 URL/查询片段形态（is_cloud_password_url_fragment）。
#      第二个条件是本轮**刻意加严**：「是 `+` 分量」这一条单独用会连**口令盐**一起收掉 ——
#      `hexMD5(n + s.password + "2019userperm")`、`password: hash(o + "cndcarezIUAGNu5")`、
#      `"cbs@bihu20250224"+r+"WC"` 都是拼接分量且是材料（探针实测该类 5 个值，远超计划里
#      点名的那 1 个），必须留在 1203。加严后本族只剩 URL/查询片段。
#
#   ③ 值形就是 URL 语法片段（is_cloud_password_url_fragment）
#      本值自身含 `/ \ : ? & =` 之一，或以 `?` / `&` 开头。库内头部：`passwd=` / `strshu=` /
#      `&position=about` / `index.php?act=login&op=save_password` / `register1:10013` /
#      `password|message:` / `display:black;`。（`/` 这一类其实到不了这里 ——
#      is_cloud_password 更早的 `"/" in s` 已拦；保留在值形判据里只为口径完整。）
#
# 三条**保护**（任一命中 → 不是噪音，本判据不碰它）：
#   · **绑在键上**：本值某个自成出现位置的左侧紧邻键（共用 fix24/25/26 的
#     `_bound_value_keys`）—— 守住直键 password/pwd/passwd 与密码族后缀键
#     （库内 259 / 95 链接），也守住 URL 拼接里绑在 `"&password="` 上的片段；
#   · **键名位**：本值右侧跳过引号/空白后紧跟 `:`（值被当作**键名**用，例如
#     `this.hasSetPassword ? "yhbp0400o02j" : "ybhp0400m010"` 的三元分支）—— 库内
#     149 链接 / 74 值，与计划点名数一致；
#   · **密码名 callee 的实参**：callee token 含 password/pwd/passwd
#     （`loginWithPassword("demo","V")` 的非首参、`e.pwdSetSk("…")`）—— 库内 2 链接 / 2 值。
#
# 已知代价（不隐藏）：严格表之外的日志 callee（logger./sentry./trackEvent…）与不以 `+`
# 连接、也不含 URL 字符的纯词形 tag（`wechat1` / `AAAF0199` / `keyboard,`）仍判 1203；
# snippet 不含值的 1139 值与 plain_unbound 一行不动。
#
# 只读回放（test-result/fix31/replay_fix31.py，**同一进程内**开关前后对照，四个库
# normal_quarkpan / unlist_normal_sibling_v2 / normal_17w / unlist_package_reference_v2）：
#   · 搬走 normal_quarkpan 733 链接 / 303 值（a 164 / b 412 / c 157），
#     另三库 82 / 107 / 61 行，家族构成相同；被搬走的行 100% 落在三族内（无「无族」行）；
#   · 受保护位置被搬走 **0**（绑键 / 密码族键 / 键名位 / 密码名 callee 实参）、
#     值形判据命中的值被碰 0、snippet 不含值的行被碰 0、反方向（别的桶→1203）0；
#   · 真升级进 risk>=4 **0**；横向迁移（修复前已在 risk 5）2 行：日志 tag
#     `smsLogin----ticketToken`（normal_quarkpan 5808500）与 URL 片段
#     `share-details&fromSource=1&status=4`（normal_17w 7094065）被既存的
#     server_cred_cookie(1604) 接手 —— 风险等级 5 不变（同 fix12 的 KNOWN_R5_DRIFT 口径）；
#   · 目的地分布（normal_quarkpan）：丢弃 439 行、other(0) 291 行、pii_noise(0) 2 行、
#     server_cred_cookie(5) 1 行。
# 量化与回放：unit-tests/test_fix31_ccp_family_guards.py +
# test-result/fix31/{prototype_guards,replay_fix31}.py（只读，无写库）。
CCP_URL_FRAGMENT_CHARS = "/\\:?&="
RE_CCP_LOG_CALLEE = re.compile(r"^(?:console\.\w+|__f__|log|track|report|error)$", re.I)
RE_CCP_PWD_CALLEE = re.compile(r"password|passwd|pwd", re.I)
RE_CCP_KEYNAME_TAIL = re.compile(r"^[\"']?\s*:")
# fix31b 材料形豁免的两张表（判据见 is_cloud_password_material_shape）：
#   · 材料字符：口令/盐/密钥里常见、却**不是** URL 语法字符的那一批；
#   · base64 带填充的整值形态：正文 ≥12 位 b64 字母表 + 1~2 个尾 `=`（下限与 ② 组点名的盐
#     对齐：`2019userperm=` 正文 12 位、`cndcarezIUAGNu5=` 15 位）；
#   · URL 语法里的「路径 / 查询」字符：b、c 两支不许含它们（`=` 另判）。
CCP_MATERIAL_CHARS = "@!#*^$%~+"
RE_CCP_B64_PADDED = re.compile(r"^[A-Za-z0-9+/]{12,}={1,2}$")
RE_CCP_URL_STRUCT_CHARS = re.compile(r"[/\\?]")


def _ccp_occurrence_positions(value: str, stmt: str):
    """本值在 stmt 中**自成字面量**的出现位置（前/后紧邻字母数字/`_`/`$` 的不算）。

    口径与 `_bound_value_keys` 的「独立出现」完全一致：本值只是更长字面量的前缀/后缀时，
    位置、callee、键名位都不该按本值算。
    """
    out, pos = [], stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            out.append(pos)
        pos = stmt.find(value, pos + 1)
    return out


def _ccp_callee_before(stmt: str, pos: int):
    """pos 左侧最近的**未配对** `(` 的 callee token（跳过嵌套括号），没有则 None。

    例：`console.log("x=", t)` 里值 `"x="` 的 callee 是 `console.log`；
    `e.pwdSetSk("…")` 里是 `e.pwdSetSk`。
    """
    depth, i = 0, pos - 1
    while i >= 0:
        ch = stmt[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                j = i - 1
                while j >= 0 and (stmt[j].isalnum() or stmt[j] in "_$."):
                    j -= 1
                return stmt[j + 1:i]
            depth -= 1
        i -= 1
    return None


def _ccp_literal_bounds(stmt: str, pos: int, end: int):
    """值所在字符串字面量的引号边界 (开引号下标, 闭引号下标)；不在字面量里返回 None。"""
    quote, i = None, pos - 1
    while i >= 0:
        if stmt[i] in "\"'":
            quote = stmt[i]
            break
        i -= 1
    if quote is None:
        return None
    j = end
    while j < len(stmt):
        if stmt[j] == quote:
            return (i, j)
        j += 1
    return None


def is_cloud_password_url_fragment(value: str) -> bool:
    """③ 值形：本值自身是 URL 语法片段（含 `/ \\ : ? & =` 之一，或以 `?` / `&` 开头）。"""
    if value[:1] in ("?", "&"):
        return True
    return any(ch in CCP_URL_FRAGMENT_CHARS for ch in value)


# fix31c ③：正文＝「驼峰标识符 + 末位序号」（`encodePhoneNumber3` / `registerParam1`）——
# 长拼写的查询键，被 RE_CCP_B64_PADDED 的尾 `=` 误当成 base64 填充时用这两条挡掉。
# 第二个条件（没有连续大写）是保护侧：`cndcarezIUAGNu5=` 靠 5 连大写留在材料里。
RE_CCP_B64_IDENT_BODY = re.compile(r"^[A-Za-z]+[0-9]$")
RE_CCP_UPPER_RUN = re.compile(r"[A-Z]{2}")


def is_cloud_password_material_shape(value: str) -> bool:
    """②/③ 的**材料形豁免**（fix31b 引入，fix31c 收窄）：值自己长得像凭证材料时，URL 片段形态
    不能单独删它。

    病根（review 复现）：② 是「拼接分量 **且** URL 片段形态」、③ 只要求「URL 片段形态」，两条
    合起来等价于**只**要求 ③ —— ② 的拼接条件其实什么都没守住，于是**未绑定**在密码键上的真
    材料只要带一个 URL 语法字符就整值掉出 1203：
      `Zq0s69O6YrvG090LgOg19z1l8RW99993`（② 组点名的盐，末尾补一个 `=` 即失守）/
      `vPYkA3HAAviBMiXnWQUxWdoPKPs=`（fix12 红线值，坐在 `return` 位置）/ `2019userperm=` /
      `cndcarezIUAGNu5=`（base64 的 `=` 填充）/ `s3cr3tSalt&pepper` / `Admin@123:456` /
      `QwErTy&2024`（盐里的 `&` `:`）。绑定矩阵那三条保护够不到它们（值未绑在任何键上）。

    fix31c（re-review 缺陷 2）：最初那三支 a/b/c 都只问「值自己像不像材料」，**没有一支要求证据
    超出 URL 语法字符本身**，于是值形是 URL 片段/标识符片段的一大批噪音也被豁免，②/③ 再也删不掉
    它们。re-review 的量法（本进程可复现）：把值放进无绑定、有密码语境的语句
    `function chk(){if(pwdOk(){return someFn("<值>")}}` 跑完整分类，结果含 1203 即「回到 1203」；
    语料侧样本取 test-result/fix31/replay_before_after.pre-fix31b.tsv 的 b/c 两族（13237 个去重
    值，其中 225 个原判据判为材料形）—— 那 225 个里 **76 个**在这条口径下仍判 1203（含
    `:wxParse1` … `:wxParse11` / `:tmpl_…_plateKeyboard` / `:work-category-list-V2` /
    `phone{color:#4293f4}` / `--td-brand-color:#a36a26;` / `encodePhoneNumber3=` …）。

    收窄后的四条窄口（任一支成立即豁免）：
      a. base64 带 `=` 填充：正文 ≥12 位 b64 字母表 + 1~2 个尾 `=`，**且正文含数字或 `+` / `/`**。
         真 base64 口令/盐的正文（`vPYkA3…PKPs` / `Zq0s69…99993` / `cndcarezIUAGNu5` /
         `2019userperm`）都含数字；查询片段 `passwd=` / `strshu=` / `&password=` / `roomId=`
         正文只有 6~11 位、`&password=` 还含 `&`，一律命不中；
         · 窄口 ③：正文若是「**纯字母 + 末位单数字、且没有连续大写**」（驼峰标识符 + 版本号：
         `encodePhoneNumber3` / `registerParam1` / `encodeUsercode3`）→ 长拼写的查询键，
         不是 base64 材料。四条受保护值都命不中：`cndcarezIUAGNu5`（5 连大写）/
         `2019userperm`、`vPYkA3…PKPs`（数字不在末位）/ `AbCd/EfGh/IjKlMnO1`（正文含 `/`）。
         注：re-review 建议「正文必须含 `+` / `/`」会把上面五条受保护 base64 一起删掉（实测
         protected 只剩 5/11），故改用这条更精确的窄口；
      b. 含材料字符（`@ ! # * ^ $ % ~ +`）**且含数字且含字母** —— `Admin@123:456`、
         `67884E9%^&*67899A26C18DC28`（盐）。只按「材料字符 + 数字或大写」会放过模板片段
         `^wifiState:`（回放实测），所以数字与字母都是必需的；
      c. 大小写混排 + 含数字 —— `s3cr3tSalt&pepper` / `QwErTy&2024`。
         · 窄口 ④：本支剩下的 URL 语法证据只有 `&` / `:` 这类**分隔**（`=` / `/` / `\` / `?` 在
         上面已挡掉）时，要求 **≥2 处数字** —— 单个数字是 `key1:value1` / `tab1&Home` 这类标识符
         片段的签名（库内同形噪音实测 `Stage1:Finished` / `subTemPassword2:` / `KG5_GetTmpPasswd:`），
         而 `QwErTy&2024`（4 处数字）/ `s3cr3tSalt&pepper`（2 处）照旧是材料。
         注：re-review 建议「本支要求材料字符或 `=` 填充」会把 `QwErTy&2024` /
         `s3cr3tSalt&pepper` 一起删掉（两者只有中间的 `&`，既无材料字符也无 `=`），故改用 ④。
    b / c 两支要求值里没有 `/ \ ?`、也没有 `=`：路径（`/a/b`）、查询串（`?x=1` / `&toRoot=1` /
    `&&srdzflag=`）、`key=value` 赋值（`roomId=` / `share-details&fromSource=1&status=4`）因此
    一律仍按形态删。① （严格日志 callee 实参）在调用点上排在豁免**之前**：日志 tag 与豁免
    无关，照旧一律删（`that._onHide1` 这类值形也像材料）。

    另两条 fix31c 窄口（值形根本不可能是材料）：
      ① URL 语法字符**打头** —— `:` 开头的 WXML 模板名（`:wxParse1` / `:tmpl_0_plateKeyboard` /
         `:work-category-list-V2`，语料里 28 条）、`?` / `&` 开头的查询串（`&QwErTy2024`），
         值形本身就是片段；
      ② wxss/CSS 语法 —— `;` `{` `}` 是声明/规则分隔、`--` 前缀是自定义属性或装饰横线：
         `phone{color:#4293f4}` / `m-mobile{background:#0b1d2b!important}` /
         `--td-brand-color:#a36a26;` / `-----eventH5BackPassword--`。`#` 在 CSS 里是颜色前缀、
         在口令里才是材料字符，这类语法一旦出现就不是凭证材料。

    附：review 点名的「高熵 alnum」不需要单独一支 —— 纯 alnum 值里**没有** `/ \ : ? & =`，
    `is_cloud_password_url_fragment` 对它恒为假，②/③ 本来就不可能删它（fix12 红线值里
    `o0IN8wTN50QMxX-V4siq_GSRFuts` 这类带 `-`/`_` 的也不含 URL 语法字符）。

    **已知残留（本判据射程到此为止，44 个值）**：a/b/c 收窄后，上面那 76 个里仍有 **44 个**在
    同一口径下判 1203 —— 全是同一类「混淆标识符池」串（`z2v0D2LUzg93zgf0yq==` /
    `BgvYDc1ZDg9YywDLlwS=` / `l3bHz2vZl25VDgLJzvC=` …，正文是 wxapp 混淆编码后的标识符，
    14~41 位、大小写混排、含数字、1~2 个尾 `=`）。**没有任何「值形」判据能把它们与受保护的
    base64（`vPYkA3HAAviBMiXnWQUxWdoPKPs=` / `Zq0s69O6YrvG090LgOg19z1l8RW99993=` /
    `xXxxx9xXX9XxXXx9X9x=` …）分开**：对 40 个值形特征做过穷举（长度 / 正文长度 / 填充数 /
    数字·大写·小写·字母占比 / 去重字符数 / 重复 n-gram / 数字与大写连续长度 / 香农熵 /
    字符类转移数 / 驼峰词界 / 前后缀语法字符…）—— 单特征阈值 **0 解**、两特征合取 **0 解**、
    两条规则并集 **0 解**；最相近的一对（受保护 `xXxxx9xXX9XxXXx9X9x=` vs 残留
    `l3bHz2vZl25VDgLJzvC=`）只在重复字符数 / 数字连续长度 / 熵这类统计量上差 9 个特征，
    任何一条阈值都会同时打到对面（放宽 → 残留回来，收紧 → 受保护值掉出 1203）。
    要再往下收只能靠**值邻接的绑定证据**（该值所在的字面量数组是否是一整片同形兄弟值 / 是否
    坐在密码键或密码名 callee 的邻位），那是**另一片射程**（绑定矩阵与 snippet 邻域），不属于
    这条只看本值的判据。残留集合在 unit-tests/test_fix31_ccp_family_guards.py 第 ⑧ 组按集合钉死
    （多一个都会失败）。

    量化见 unit-tests/test_fix31_ccp_family_guards.py 第 ⑦ 组（正反例 + 「两族真删掉的值一个
    都不是材料形」的不变量）与第 ⑧ 组（fix31c：32 个可分离噪音逐条钉住 + 44 个残留钉死）。
    """
    if not value:
        return False
    # fix31c ①：URL 语法字符打头（`:` 模板名 / `?` `&` 查询串开头）→ 值形本身就是片段
    if value[0] in CCP_URL_FRAGMENT_CHARS:
        return False
    # fix31c ②：wxss/CSS 语法（`;` `{` `}` 声明分隔、`--` 自定义属性/装饰横线）
    if value.startswith("--") or any(ch in value for ch in ";{}"):
        return False
    if RE_CCP_B64_PADDED.match(value):
        body = value.rstrip("=")
        # fix31c ③：正文是「驼峰标识符 + 末位序号」（长拼写的查询键，不是 base64 材料）
        if RE_CCP_B64_IDENT_BODY.match(body) and not RE_CCP_UPPER_RUN.search(body):
            return False
        # 正文含数字或 `+` / `/` 才当 base64 填充（理由见 docstring a 支：长拼写的查询键挡在外面）
        if any(c.isdigit() for c in body) or "+" in body or "/" in body:
            return True
        return False
    if RE_CCP_URL_STRUCT_CHARS.search(value) or "=" in value:
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    if has_digit and has_alpha and any(c in CCP_MATERIAL_CHARS for c in value):
        return True
    # fix31c ④：c 支只剩 `&` / `:` 这类分隔证据时要求 ≥2 处数字（单个数字是标识符片段的签名）
    return has_digit and has_upper and has_lower and sum(c.isdigit() for c in value) >= 2


def is_cloud_password_log_call_tag(value: str, stmt: str) -> bool:
    """① 本值是否坐在严格日志 callee 表（console./__f__/log/track/report/error）的实参位上。"""
    for pos in _ccp_occurrence_positions(value, stmt):
        callee = _ccp_callee_before(stmt, pos)
        if callee and RE_CCP_LOG_CALLEE.match(callee):
            return True
    return False


def is_cloud_password_concat_operand(value: str, stmt: str) -> bool:
    """② 本值所在字符串字面量是否为 `+` 拼接的一个分量（两侧任一紧邻 `+`，跳过空白）。

    只判「是不是拼接分量」，**不含** URL 片段形态要求 —— 那个条件在
    `is_cloud_password_noise` 里与它合用（分开写是为了让「拼接分量里的口令盐」这件事
    在单测里可断言：`is_cloud_password_concat_operand` 为真而 `is_cloud_password_noise`
    为假）。
    """
    end = len(value)
    for pos in _ccp_occurrence_positions(value, stmt):
        bounds = _ccp_literal_bounds(stmt, pos, pos + end)
        if bounds is None:
            continue
        left = stmt[:bounds[0]].rstrip()[-1:]
        right = stmt[bounds[1] + 1:].lstrip()[:1]
        if left == "+" or right == "+":
            return True
    return False


def _ccp_keyname_position(value: str, stmt: str) -> bool:
    """保护：本值出现在**键名位**（右侧跳过引号/空白后紧跟 `:`）。"""
    end = len(value)
    for pos in _ccp_occurrence_positions(value, stmt):
        if RE_CCP_KEYNAME_TAIL.match(stmt[pos + end:]):
            return True
    return False


def _ccp_password_callee_arg(value: str, stmt: str) -> bool:
    """保护：本值是「名字含 password/pwd/passwd」的调用实参（含非首参）。"""
    for pos in _ccp_occurrence_positions(value, stmt):
        callee = _ccp_callee_before(stmt, pos)
        if callee and RE_CCP_PWD_CALLEE.search(callee):
            return True
    return False


def _ccp_bound_to_any_key(value: str, stmt: str) -> bool:
    """保护：本值某个自成出现位置的左侧紧邻绑定键（口径 = fix24/25/26 的共用扫描器）。"""
    for _key in _bound_value_keys(value, stmt):
        return True
    return False


# =========================================================
# 云服务密码的「值锚判定窗口 + 语法位置守卫」（fix43）
# =========================================================
# 问题（已证实）：1203 判据拿到的 stmt 是 perform_constant_classifying 以**语句第一个常量**为
# 锚算出的 `extract_context(raw_stmt, s, 512)`。extract_context 把语句按空白切成 token 后只取
# 相邻 **3 个** token，于是：
#   · 语句里第 2 个以后的常量，判定窗口里常常根本没有这个值 —— fix31（三族）与 fix42（五族）
#     的位置判据一律先要求「值在窗口里」（`if value not in stmt: return False`），窗口不含该值
#     时它们全部失效。normal_quarkpan_v2 实测：1203 的 1,959 个去重值里 **1,037 个**的任何一行
#     source_snippet 都不含该值；
#   · 语句内常量的处理顺序还受 PYTHONHASHSEED 影响，同一个值的判定会随种子漂移。
#
# 本轮两半（**必须同批落地**；先行探针实测：只改窗口会在样本 A 新增 187 对 risk>=4、其中
# 162 对是**反向进入 1203**）：
#   ① 值锚窗口 `_ccp_value_anchor_context(raw_stmt, value, fallback)` —— **只接在 1203 判定
#      处**（主循环其余逻辑、truncated_contexts、其他判据、入库 source_snippet 一律不动）。
#      以当前值在 raw_stmt 里的**独立出现**（口径 = `_ccp_occurrence_positions`，与
#      `_bound_value_keys` 的「独立出现」细则逐字相同）为中心取 ±256 字符（总长 512，与既有
#      `extract_context(..., 512)` 同量级）；值在 raw_stmt 里找不到独立出现、或语句本身
#      <=512 字符（此时旧窗口本来就等于整条语句）→ **退回旧窗口**，判定逐位不变。
#      口径是「**修复前判 1203 ∧ 值锚窗口判 1203**」（见主循环调用点的长注释）：值锚窗口只用于
#      **收窄**。为什么不做成「直接用值锚窗口代替旧窗口」：那会 162 对反向进入 1203（上面实测），
#      而规格里「反向进入 1203 = 0」是红线；值锚窗口的价值在这里是**把位置判据从失效状态救活**
#      （fix31/fix42 的位置判据要求「值在窗口里」），顺带把「值旁边没有密码语境」的那批清掉。
#   ② 语法位置守卫 `is_cloud_password_position_noise(value, stmt)` —— 在 fix31 三条保护**之后**
#      判三类「位置已证实不是口令」的形态（字符串表元素 / 成员访问 / 扁平数组元素）。另三类由
#      既有判据覆盖、本守卫刻意不重复实现：i18n 键名位是 fix42 P1 的射程（fix42 单测把「右侧不含
#      CJK」那一支钉成**不是噪音**，所以本守卫不带无 CJK 的兄弟规则）；对象键位（值右侧紧跟 `:`，
#      含三元分支）是 fix31 键名位保护的射程；日志 callee 实参是 fix31 ① + fix42 P4 的射程。
#
# 被排除的值**显式改判** `cloud_cred_noise(1207, risk0)`（不静默消失），且只在「修复前判 1203」
# 时出手 —— 即本轮真正从 1203 移出的那一批，不许掉进别的 risk>=4 桶。
#
# 只读回放：test-result/fix43/replay_fix43.py（按 source_file 真扫，**同一进程内**开关前后对照，
# 固定 PYTHONHASHSEED=0 与 7 两个种子；数字见同目录报告）。
CCP_VALUE_ANCHOR_LEN = 512
CCP_VALUE_ANCHOR_HALF = 256

# 位置判据 C（成员访问）：值紧跟在 `.` 之后（`t.data.emoney7` / `x["k"].prop`）。
# `.` 左侧**必须是标识符字符或 `]`/`)`** —— 引号不在字符表里是刻意的：CSS 选择器写法
# （`pwdStyle = '.mt-input__icon{color:#fff}'` 里那一份 `mt-input__icon`）的 `'.` 会被
# `\"'` 误当成成员访问，unit-tests/test_cloud_password_bem.py 钉死了那一族必须保持 1203。
RE_CCP_POS_MEMBER_BEFORE = re.compile(r"[A-Za-z0-9_$\]\\)]\s*\??\.\s*$")
# 位置判据 B（字符串表）与 E（扁平数组）：同串字面量个数下限。
#   B：>=3（`"a","b","c"` 这种表面形态），且最近的未配对开括号**不是** `(`（调用实参位不算表）；
#   E：>=6 且最近开括号是 `[`（B 的窄化形态，二者合起来就是先行探针的 str_list / array_elem
#      两类的并集，多写一条是为了让「数组元素」在单测与回放里可单独断言）。
CCP_POS_TABLE_MIN = 3
CCP_POS_ARRAY_MIN = 6

# fix43：位置守卫的**临时关断**开关（只给主循环的改判记账用 —— 判「这个值修复前是不是 1203」）。
# 用模块级开关而不是第二份实现，保证「关掉守卫」与「守卫不存在」逐位等价。
CCP_POSITION_GUARD_OFF = False

# fix12 人工核定的红线值 + fix31c 的受保护材料：**值白名单**，位置判据永不碰它们。
# 名单本身早已公开在单测与回放脚本里（unit-tests/test_fix31_ccp_family_guards.py 的
# REDLINE_VALUES / FIX31C_PROTECTED_MATERIAL、test-result/fix42/replay_fix42.py 的同名表），
# 这里只是把「规格」搬到实现侧：位置判据是形态判据，原则上不该覆盖人工核定的真阳性。
CCP_POSITION_REDLINE_VALUES = frozenset((
    # fix12 红线（弱口令 / 随机口令 / 材料）
    "password1", "password123", "admin123", "Admin123", "emoney5", "video123",
    "Nihao123", "1Passw0rd!xyz", "jia23xia4kaoshi5t2", "123456a",
    "o0IN8wTN50QMxX-V4siq_GSRFuts", "mnP7XKDCaWFjINWi", "signBoardPassword_S8hY",
    # fix31c 受保护的 10 条真材料
    "vPYkA3HAAviBMiXnWQUxWdoPKPs=", "Zq0s69O6YrvG090LgOg19z1l8RW99993=",
    "2019userperm=", "cndcarezIUAGNu5=", "xXxxx9xXX9XxXXx9X9x=",
    "Admin@123:456", "QwErTy&2024", "s3cr3tSalt&pepper", "MyPwd__2024",
    "67884E9%^&*67899A26C18DC28",
))


def _ccp_value_anchor_context(raw_stmt: str, value: str, fallback: str) -> str:
    """fix43 ①：以**当前值**为锚的 1203 判定窗口（问题、射程与量化见上方注释块）。

    与旧窗口（`extract_context(raw_stmt, 首常量, 512)`）的关系：
      · 语句 <=512 字符 → 旧窗口本来就等于整条语句，直接返回 raw_stmt（判定逐位不变）；
      · 值在 raw_stmt 里**没有独立出现**（= 库里 snippet-absent 的那一批，或值只是更长字面量
        的前缀/后缀）→ 返回 fallback，判定逐位不变；
      · 其余情形以值的第一个独立出现为中心取 ±256 字符。
    本函数**不改**任何既有判据、不改 truncated_contexts、不改入库 snippet。
    """
    if not raw_stmt:
        return fallback
    if len(raw_stmt) <= CCP_VALUE_ANCHOR_LEN:
        return raw_stmt
    positions = _ccp_occurrence_positions(value, raw_stmt)
    if not positions:
        return fallback
    start = positions[0] - CCP_VALUE_ANCHOR_HALF
    if start < 0:
        start = 0
    end = positions[0] + len(value) + CCP_VALUE_ANCHOR_HALF
    if end > len(raw_stmt):
        end = len(raw_stmt)
    return raw_stmt[start:end]


def _ccp_pos_literal_bounds(value: str, stmt: str, pos: int):
    """值是否**整字面量**地坐在 pos 上；是则返回 (开引号, 闭引号)，否则 None。"""
    bounds = _ccp_literal_bounds(stmt, pos, pos + len(value))
    if bounds is None or stmt[bounds[0] + 1:bounds[1]] != value:
        return None
    return bounds


def _ccp_nearest_open_bracket(stmt: str, pos: int) -> str:
    """pos 左侧最近的**未配对**开括号字符（`(` / `[` / `{`）；窗口里没有则返回空串。"""
    depth, i = 0, pos - 1
    while i >= 0:
        ch = stmt[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                return ch
            depth -= 1
        i -= 1
    return ""


def is_cloud_password_string_table_position(value: str, stmt: str) -> bool:
    """位置判据 B：值是**字符串/符号表**的一个元素（`e = [ "alpha", "beta", "gamma" ]`）。

    细则：值必须整字面量；同串 >=CCP_POS_TABLE_MIN 个字面量（口径 = fix42 P3 的
    `_ccp_literal_run`，它只认**完整字面量**的逗号串）；最近的未配对开括号**不是** `(`
    —— 调用实参位是 A / C / F 的射程（`f("a","b")` 这种形态由 A 管），不按串表算。
    """
    for pos in _ccp_occurrence_positions(value, stmt):
        if _ccp_pos_literal_bounds(value, stmt, pos) is None:
            continue
        if _ccp_nearest_open_bracket(stmt, pos) == "(":
            continue
        if len(_ccp_literal_run(stmt, pos, pos + len(value))) >= CCP_POS_TABLE_MIN:
            return True
    return False


def is_cloud_password_flat_array_position(value: str, stmt: str) -> bool:
    """位置判据 E：值是**扁平数组**的元素（最近的未配对开括号是 `[` 且同串 >=6 个字面量）。

    B 的窄化形态（多一层「最近的未配对开括号必须是 `[`」与更高的元素数下限），对应先行探针
    的 array_elem 类；单独写出来是为了让这一族在单测/回放里可独立断言。
    """
    for pos in _ccp_occurrence_positions(value, stmt):
        if _ccp_pos_literal_bounds(value, stmt, pos) is None:
            continue
        if _ccp_nearest_open_bracket(stmt, pos) != "[":
            continue
        if len(_ccp_literal_run(stmt, pos, pos + len(value))) >= CCP_POS_ARRAY_MIN:
            return True
    return False


def is_cloud_password_member_access_position(value: str, stmt: str) -> bool:
    """位置判据 C：值是**成员访问的属性名**（值紧跟在 `.` 之后：`t.data.emoney7`）。

    口令材料是字面量，不会坐在属性名位上；这一族的库内形态是
    `wx.setStorageSync("emoney7", t.data.emoney7)` 里的属性名那一份。字符串字面量的紧邻
    `x."prop"` 不在此列（`.` 后紧跟引号不是成员访问，见 RE_CCP_POS_MEMBER_BEFORE）。
    """
    for pos in _ccp_occurrence_positions(value, stmt):
        before = stmt[:pos]
        if before[-1:] in ("\"", "'"):
            before = before[:-1]
        if RE_CCP_POS_MEMBER_BEFORE.search(before):
            return True
    return False


def is_cloud_password_position_noise(value: str, stmt: str) -> bool:
    """fix43 ② 唯一入口：本值在 stmt（= 值锚窗口）里的**语法位置**是否已证实不是口令。

    顺序（fix31 之后）：守卫被临时关断（`CCP_POSITION_GUARD_OFF`，只给主循环改判记账用）→
    False；值不在 stmt 里 → False（位置判据没有出现位置就没有依据，同 fix31/fix42 的
    snippet-absent 口径）；三条保护（绑在任何键上 / 键名位 / 密码名 callee 实参，任一命中即
    False）；fix12·fix31c 红线值白名单；材料形豁免（同 fix31b/c 的红线：值自己像凭证材料时，
    位置/形态判据不许单独删它 —— fix42 单测把「材料形值坐在串表里」钉成了必须保持 1203）；
    最后才是三类位置判据。

    三类位置判据（任一命中即噪音，判据本身见各自 docstring）：
      B 字符串表元素（`is_cloud_password_string_table_position`）
      C 成员访问（`is_cloud_password_member_access_position`）
      E 扁平数组元素（`is_cloud_password_flat_array_position`）

    另三类**不在这里实现**（各自有 owner，理由见本节开头注释块）：
      · i18n 键名位 —— fix42 P1（`is_cloud_password_i18n_key`）的射程。fix42 单测把「右侧不是
        含中日韩字符的字面量」这一支钉成了**不是噪音**（P1_NEGATIVE_CASES），所以本判据刻意
        不带「无 CJK」的兄弟规则：那会让「`(o,"KEY","Home Banner")`」这类被 fix42 判为保留的
        形态被本判据删掉。值锚窗口已经把 P1 从「窗口里没有值」的失效状态救活（i18n 表的
        `(0,a.default)(o,"KEY","中文")` 形态）—— fix43 的贡献在窗口，不在新写一条 P1。
      · 对象键位（值右侧跳过引号/空白紧跟 `:`，含 `cond ? "a" : "b"` 的三元分支）—— 已由
        fix31 的键名位保护覆盖，且它是**刻意保护**的位置（本地化表的键名、三元分支的模板名
        都是 fix31 点名不许动的）。
      · 日志 callee 的实参 —— fix31 ①（`console.*`/`__f__`/`log`/`track`/`report`/`error`）
        与 fix42 P4（`beforeLog`/`afterLog`/`writeLog`/`reportLog`/`logEvent`）已覆盖；更宽的
        callee 词根（`trackEvent` / `logger.` / `sentry.`）是 fix31 单测钉死的**已知残留**
        （`before == after` 必须成立），本判据不得把它们收进来。

    不变量：本判据只可能把值**移出** 1203，不可能把值推进 1203（它只在 is_cloud_password
    已经走到这一步时才被调用）。被它排除的值由主循环显式改判 cloud_cred_noise(1207, risk0)。
    """
    if CCP_POSITION_GUARD_OFF:
        return False
    if not value or value not in stmt:
        return False
    if (_ccp_bound_to_any_key(value, stmt)
            or _ccp_keyname_position(value, stmt)
            or _ccp_password_callee_arg(value, stmt)):
        return False
    if value in CCP_POSITION_REDLINE_VALUES:
        return False
    if is_cloud_password_material_shape(value):
        return False
    return (is_cloud_password_string_table_position(value, stmt)
            or is_cloud_password_member_access_position(value, stmt)
            or is_cloud_password_flat_array_position(value, stmt))


def is_cloud_password_before_fix43(s: str, stmt: str) -> bool:
    """同 `is_cloud_password`，但 fix43 的位置守卫不生效（= **修复前口径**，供主循环记账）。

    主循环用它判「这个值修复前是不是 1203」：
      · 不是 → 本轮一行不动（继续走原分类链，行为与修复前逐位相同）；
      · 是   → 由**值锚窗口**决定它留下还是改判 `cloud_cred_noise(1207, risk0)`。
    用模块级开关实现而不是复制一份判据，是为了保证「关掉守卫」与「守卫不存在」逐位等价
    （单测 unit-tests/test_fix43_ccp_value_anchor.py 用同一个开关做前后对照）。
    """
    global CCP_POSITION_GUARD_OFF
    prev = CCP_POSITION_GUARD_OFF
    CCP_POSITION_GUARD_OFF = True
    try:
        return is_cloud_password(s, stmt)
    finally:
        CCP_POSITION_GUARD_OFF = prev


# =========================================================
# 云服务密码的「五族结构噪音」窄口守卫（fix42）
# =========================================================
# 问题：fix31（含 fix31b/fix31c）收掉三族之后，cloud_cred_password(1203) 里仍混着五族
# 「语句里有 password/pwd 词、值本身却是别的东西」。它们与 fix31 三族的**关键差别**是判据
# 靠值在语句里的**位置**、不靠值的形态 —— 所以 fix31c 的「材料形豁免」不该挡它们：
# `pkcs5PBKDF2`（P2）、`1055120GWJCQi`（P3）这类值按 is_cloud_password_material_shape
# 都是 True（大小写混排 + ≥2 处数字命中 c 支）。调用点因此排在 ①（严格日志 callee）之后、
# 材料形豁免**之前**。
#
# 证据（**只读**判读 v2 两库 normal_quarkpan_v2 / unlist_package_reference_v2 的
# cloud_cred_password 桶；口径 = 对每个去重值取首次出现（MIN(m.id)）的 source_snippet
# 跑 perform_constant_classifying([snippet], [(value, 0, 0)])，"修复前 / 修复后" 只在
# **同一进程内** monkeypatch 本轮的 is_cloud_password_fix42_family_noise，fix31 三族
# 从头到尾保持生效；脚本 test-result/fix42/replay_fix42.py）：
#
#   P1 i18n 字典键            is_cloud_password_i18n_key          quarkpan 12 链接 / 12 值
#   P2 密码学 OID / 算法名     is_cloud_password_crypto_algorithm_name  quarkpan 171 / 20
#   P3 webpack / 混淆 chunk id is_cloud_password_obfuscated_chunk_id quarkpan  53 / 42
#   P4 事件码 / 日志 tag       is_cloud_password_event_tag         quarkpan  80 / 32
#   P5 密码学测试向量          is_cloud_password_kdf_test_vector   quarkpan  10 /  3
#   （pkgref：P2 20 链接 / 20 值、P3 19 / 13、P5 2 / 2；P1 与 P4 为 0 —— P4 的候选值在
#    pkgref 全被三条保护挡住或是 console 族已由 fix31 拿走。）
#
# 三条保护（fix31 已有，五族一律排在其后；任一命中 → 永不判噪音）：
#   · 值绑在任何键上（`_bound_value_keys`）；· 值处于键名位（右侧跳过引号/空白紧跟 `:`）；
#   · 值是 password/pwd/passwd 名 callee 的实参。
#
# 判定窗口（**本轮不改窗口**）：stmt 是 perform_constant_classifying 以语句**第一个常量**
# 为锚算的 extract_context(snippet, s, 512) 窗口，不一定包含当前值。五族一律要求「当前值在
# stmt 里的独立出现」（_ccp_occurrence_positions）；值不在窗口里时 is_cloud_password_noise
# 早已返回 False（同 fix31 的 snippet-absent 口径），本判据也不得凭空定罪。回放按家族分别
# 统计「窗口内可判定」与「窗口内不可判定」（不可判定的一律不动）。
CCP_CJK_CLASS = "\u3400-\u9fff\uf900-\ufaff\u3040-\u30ff"
RE_CCP_CJK = re.compile("[" + CCP_CJK_CLASS + "]")
RE_CCP_STR_LITERAL = re.compile(r"[\"']([^\"']*)[\"']")
# P1：键侧形态（纯 ASCII 键形；把「材料形 + 恰好后跟中文」的巧合挡在外面）与配对形态。
RE_CCP_I18N_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{3,48}$")
RE_CCP_I18N_CJK_PAIR = re.compile(r"^[\"']?\s*,\s*([\"'])(.*?)\1", re.S)
# P2：OID 形态与标准算法名表（ASN.1 签名算法 / HMAC / PBKDF2 / RSA / ECDSA 系列）。
RE_CCP_OID = re.compile(r"^\d+(?:\.\d+){2,}$")
RE_CCP_ASN1_ALGO_NAME = re.compile(
    r"^(?:hmacWith(?:SHA|MD)[0-9]*"
    r"|[a-z0-9]+With(?:RSA|DSA|ECDSA)Encryption"
    r"|rsaEncryption|RSAES-OAEP|mgf1|pSpecified|PBKDF2|scrypt"
    r"|ecdsa-with-[A-Za-z0-9-]+)$")
# P3：chunk id 形态 + 「混淆形」兄弟（javascript-obfuscator 串表成员：4~12 位纯 alnum、
# 含数字也含大写，如 `2oiKOVL` / `328XYgkqW` / `44OxMZUC`）。
RE_CCP_CHUNK_ID = re.compile(r"^\d{5,8}[A-Za-z]{5,7}$")
RE_CCP_OBFUSCATED_ID = re.compile(r"^(?=[A-Za-z0-9]{4,12}$)(?=.*[0-9])(?=.*[A-Z]).+$")
# P4：全大写事件码形态（≥2 连大写 + ≥1 位数字）；比较运算数一侧的**形态闸门**，见 docstring。
RE_CCP_EVENT_CODE = re.compile(r"^(?=[A-Z0-9_.\-]*[A-Z]{2})[A-Z0-9_.\-]*[0-9][A-Z0-9_.\-]*$")
# P4：fix31 ① 的严格 callee 表之外的日志 callee（`u.beforeLog(tag, tag, [])` 一族）。
RE_CCP_LOG_CALLEE_EXT = re.compile(
    r"^(?:[A-Za-z_$][\w$]*\.)*(?:beforeLog|afterLog|writeLog|reportLog|logEvent)$")
RE_CCP_CMP_OPS = ("===", "!==", "==", "!=")
# P5：hex 摘要 + KDF 调用 + 盐字面量（RFC 6070 / 3962 测试向量）。
RE_CCP_HEX_DIGEST = re.compile(r"^[0-9a-f]{16,128}$")
RE_CCP_KDF_CALL = re.compile(r"(?:^|[^\w$])(?:PBKDF2|pbkdf2|scrypt)\s*\(", re.I)
RE_CCP_SALT_LITERAL = re.compile(r"[\"'](?:password|passphrase|salt)[\"']", re.I)
# P3 的字面量串左右扩展（见 _ccp_literal_run）：CAP = 元素上限，LEFT_WINDOW = 左扩窗口。
RE_CCP_LIT_SEG_LEFT = re.compile(r"([\"'])([^\"']*)\1\s*,\s*$")
RE_CCP_LIT_SEG_RIGHT = re.compile(r"\s*,\s*([\"'])([^\"']*)\1")
CCP_LITERAL_RUN_CAP = 64
CCP_LITERAL_RUN_LEFT_WINDOW = 4096


def _ccp_paren_span(stmt: str, pos: int):
    """包住 pos 的最近一层 `(` … `)` 的 (左括号下标, 右括号下标)；不在任何括号里返回 None。

    P2（与 OID 同属一个调用）与 P5（同一调用里既有 KDF 又有盐字面量）的「同一调用」口径：
    只看**最近一层**，嵌套更深的调用不算证据。窗口把括号截断时右端退化为窗口末尾。
    """
    depth, i, left = 0, pos - 1, None
    while i >= 0:
        ch = stmt[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                left = i
                break
            depth -= 1
        i -= 1
    if left is None:
        return None
    depth, j = 0, left
    while j < len(stmt):
        if stmt[j] == "(":
            depth += 1
        elif stmt[j] == ")":
            depth -= 1
            if depth == 0:
                return (left, j)
        j += 1
    return (left, len(stmt) - 1)


def _ccp_literal_run(stmt: str, pos: int, end: int):
    """含该值字面量的「逗号分隔字符串字面量串」的全部字面量 [(左引号, 右引号, 内容), …]。

    P3 的「字符串表数组元素位」口径：值必须**整字面量**地坐在 `"a","b","c"` 这样一条串里，
    左右扩展时每一步都必须是完整字面量（`RE_CCP_LIT_SEG_LEFT/RIGHT`）。不依赖 `[]` 配对，
    所以窗口把数组开头/结尾截断时照样能数出兄弟元素。不在字面量里、或值只是更长字面量的
    前缀时返回 []（同 _ccp_occurrence_positions 的独立出现口径）。

    扩展带**上限**（CAP 个元素、LEFT_WINDOW 个字符）：判据只需要「≥6 个元素且 ≥2 个同形」，
    而窗口可能是上百 KB 的无空白压缩语句（extract_context 对无空白语句返回整段），
    无上限的二次扫描会退化成 O(n²)。
    """
    bounds = _ccp_literal_bounds(stmt, pos, end)
    if bounds is None or stmt[bounds[0] + 1:bounds[1]] != stmt[pos:end]:
        return []
    run = [(bounds[0], bounds[1], stmt[bounds[0] + 1:bounds[1]])]
    lo, hi = bounds[0], bounds[1]
    while len(run) < CCP_LITERAL_RUN_CAP:
        start = max(0, lo - CCP_LITERAL_RUN_LEFT_WINDOW)
        m = RE_CCP_LIT_SEG_LEFT.search(stmt, start, lo)
        if not m:
            break
        run.insert(0, (m.start(1), m.end(2), m.group(2)))
        lo = m.start(1)
    while len(run) < CCP_LITERAL_RUN_CAP:
        m = RE_CCP_LIT_SEG_RIGHT.match(stmt, hi + 1)
        if not m:
            break
        run.append((m.start(1), m.end(2), m.group(2)))
        hi = m.end(2)
    return run


def is_cloud_password_i18n_key(value: str, stmt: str) -> bool:
    """P1：值是否是 i18n 字典的**键侧**（`(0,a.default)(o,"ASCII 键","中文译文")`）。

    判据：值自成字符串字面量，其后紧跟 `,` 与**另一个含中日韩字符**的字符串字面量 ——
    即「ASCII 键, CJK 值」对里的键侧。值还必须自身是键形（`RE_CCP_I18N_KEY`，纯 ASCII、
    无空格与 `@!#*^$%~+` 这类材料字符）：`SellCenterText588` / `BindYourMobileNumber` 命中，
    `P@ssw0rd!2024`（材料形）与 CJK 侧本身命中不了。

    库内形态（app wx96e224d197ca3b8f / appservice.app.js 的 i18n 串表，同文件 872 个值）：
      `…"银行卡号长度为16位~19位"),(0,a.default)(o,"IncorrecormatofIDcard","身份证格式不正确"),…`
    注意该文件里绝大部分值的**出现位是 `KEY:"中文"` 的键名位**（被 fix31 的键名位保护挡住，
    一行不动）；本族只收 `,` 分隔的**调用实参**那一种形态。
    """
    if not value.isascii() or not RE_CCP_I18N_KEY.match(value):
        return False
    for pos in _ccp_occurrence_positions(value, stmt):
        bounds = _ccp_literal_bounds(stmt, pos, pos + len(value))
        if bounds is None or stmt[bounds[0] + 1:bounds[1]] != value:
            continue
        m = RE_CCP_I18N_CJK_PAIR.match(stmt[bounds[1] + 1:])
        if m and RE_CCP_CJK.search(m.group(2)):
            return True
    return False


def is_cloud_password_crypto_algorithm_name(value: str, stmt: str) -> bool:
    """P2：值是否是密码学 OID 表里的**算法名**。

    两支（任一成立）：
      · 值的字面量与一个 OID 形态字面量（`"1.2.840.113549.1.1.5"`）**同属最近一层调用** ——
        库内形态 `a("1.2.840.113549.2.8","hmacWithSHA224"),a("…","hmacWithSHA256"),…`；
      · 值本身是标准算法名（RE_CCP_ASN1_ALGO_NAME：ASN.1 签名算法名 / hmacWith… /
        rsaEncryption / RSAES-OAEP / mgf1 / pSpecified / PBKDF2 / scrypt / ecdsa-with-…）。

    这是 ASN.1/PKCS 的**名字表**，不是口令；值自形是算法名或坐在 OID 的邻位上，没有承载
    凭证材料的可能。库内 20 个值（rsaEncryption / md5WithRSAEncryption / hmacWithSHA1…512 /
    pkcs5PBKDF2 / x509Certificate …）全部由第一支命中。
    """
    for pos in _ccp_occurrence_positions(value, stmt):
        span = _ccp_paren_span(stmt, pos)
        if span is None:
            continue
        inner = stmt[span[0] + 1:span[1]]
        if any(RE_CCP_OID.match(m.group(1)) for m in RE_CCP_STR_LITERAL.finditer(inner)):
            return True
    return bool(RE_CCP_ASN1_ALGO_NAME.match(value))


def is_cloud_password_obfuscated_chunk_id(value: str, stmt: str) -> bool:
    """P3：值是否是 webpack / javascript-obfuscator **字符串表数组**里的 chunk id。

    判据（两条同时成立，见 memo：只判形态不够）：
      · 形态 `^\\d{5,8}[A-Za-z]{5,7}$`（`3758445RfzdXY` / `1055120GWJCQi` / `10741600SNMWce`）；
      · 值整字面量地坐在一条 ≥6 个字面量的逗号串里，且串里 ≥2 个元素是同形或**混淆形**
        （RE_CCP_OBFUSCATED_ID：`2oiKOVL` / `328XYgkqW` / `44OxMZUC` 这类 obfuscator 串表成员）。

    库内形态：`t=["1055120GWJCQi","260097VhsWmj","2oiKOVL","tap","triggerEvent","300nenSyN",
    "5474394XMgAbC",…]` / `e=["/common/pages/…/no_card.png","camera","66cjQJNk",…]`。
    孤立出现（`setPwd("3758445RfzdXY")`）或同表没有第二个同形/混淆形兄弟时不判噪音。
    """
    if not RE_CCP_CHUNK_ID.match(value):
        return False
    for pos in _ccp_occurrence_positions(value, stmt):
        run = _ccp_literal_run(stmt, pos, pos + len(value))
        if len(run) < 6:
            continue
        shaped = [lit for _l, _r, lit in run
                  if RE_CCP_CHUNK_ID.match(lit) or RE_CCP_OBFUSCATED_ID.match(lit)]
        if len(shaped) >= 2:
            return True
    return False


def is_cloud_password_event_tag(value: str, stmt: str) -> bool:
    """P4：值是否是事件码 / 日志 tag。

    两支（任一成立）：
      · 值是 `beforeLog` / `afterLog` / `writeLog` / `reportLog` / `logEvent` 这类日志 callee
        的实参（fix31 ① 的严格表只认 `console.*` / `__f__` / `log` / `track` / `report` /
        `error`）：`u.beforeLog("XLRPTJKSQ2025060317","XLRPTXXSQ2025060317",[])`；
      · 值是 `===` / `!==` / `==` / `!=` 的**比较运算数**，且形态是全大写事件码
        （RE_CCP_EVENT_CODE：≥2 连大写 + ≥1 位数字）：`"CCCD003852"===e.retMsgCode`、
        `"BFF005122043"!=i.code`、`"LOAN_IN_360"===x`。

    比较运算数一侧**必须**带这个形态闸门 —— 只判「在比较位」会吃掉已核实的真阳性（v2 只读
    实测两条）：
      `"admin123", "admin123" === r ? (… adminPassword: "" …)`（管理端硬编码口令，fix12 红线值）
      `if("a123456"==e.detail.value.password)…`（系统初始化口令）
    两者都无 2 连大写，被闸门放过；而本族实际拿走的 32 个值（CCCD*/BLPS*/BFF*/UM_*/LY*/
    FE*/APA*/LOAN_IN_360/FIAL_NUM_GT_3/USERERR500/123456BMS/…）全部命中事件码形态。
    已知代价：`DD_GATEWAY_`（无数字）、`qrcode_19_noPowerError`（无 2 连大写）这类 tag 不命中，
    保持 1203（已知残留，回放里逐条列出）。
    """
    for pos in _ccp_occurrence_positions(value, stmt):
        callee = _ccp_callee_before(stmt, pos)
        if callee and RE_CCP_LOG_CALLEE_EXT.match(callee):
            return True
        bounds = _ccp_literal_bounds(stmt, pos, pos + len(value))
        if bounds is None or stmt[bounds[0] + 1:bounds[1]] != value:
            continue
        if not RE_CCP_EVENT_CODE.match(value):
            continue
        left = stmt[:bounds[0]].rstrip()
        right = stmt[bounds[1] + 1:].lstrip()
        if (any(right.startswith(op) for op in RE_CCP_CMP_OPS)
                or any(left.endswith(op) for op in RE_CCP_CMP_OPS)):
            return True
    return False


def is_cloud_password_kdf_test_vector(value: str, stmt: str) -> bool:
    """P5：值是否是**密码学测试向量**（RFC 6070 / RFC 3962 形态）。

    判据：值是 hex 摘要形态（`^[0-9a-f]{16,128}$`），且它所在的**同一个调用**里既有 KDF 调用
    （`PBKDF2(` / `pbkdf2(` / `scrypt(`）又有 `"password"` / `"passphrase"` / `"salt"` 盐字面量。

    库内形态：`X.strictEqual(a.PBKDF2("password","ATHENA.MIT.EDUraeburn",16),
    "cdedb5281bb2f801565a1122b2563515")` —— 值是断言的期望值（另一个实参就是 KDF 调用）。
    hex 摘要 + 同一调用里的 KDF 与盐，是「测试向量」而不是任何线上凭证；值不是 hex、
    或同一调用里没有 KDF/盐时一律不碰（`QwErTy&2024` 这类**盐本身**保持 1203）。
    """
    if not RE_CCP_HEX_DIGEST.match(value):
        return False
    for pos in _ccp_occurrence_positions(value, stmt):
        span = _ccp_paren_span(stmt, pos)
        if span is None:
            continue
        inner = stmt[span[0] + 1:span[1]]
        if RE_CCP_KDF_CALL.search(inner) and RE_CCP_SALT_LITERAL.search(inner):
            return True
    return False


def is_cloud_password_fix42_family_noise(value: str, stmt: str) -> bool:
    """fix42 唯一入口：本值是否属于**五族结构噪音**（i18n 键 / 密码学算法名 / chunk id /
    事件码 tag / KDF 测试向量；判据、证据与已知残留见上方注释块）。

    三条保护（绑键 / 键名位 / password 名 callee 实参）先判，命中即 False。
    值不在 stmt 窗口里 → False（五族都是**位置**判据，没有出现位置就没有依据）。
    本判据只可能把值**移出** 1203（返回 True 即噪音），不可能把值推进 1203。
    """
    if value not in stmt:
        return False
    if (_ccp_bound_to_any_key(value, stmt)
            or _ccp_keyname_position(value, stmt)
            or _ccp_password_callee_arg(value, stmt)):
        return False
    return (is_cloud_password_i18n_key(value, stmt)
            or is_cloud_password_crypto_algorithm_name(value, stmt)
            or is_cloud_password_obfuscated_chunk_id(value, stmt)
            or is_cloud_password_event_tag(value, stmt)
            or is_cloud_password_kdf_test_vector(value, stmt))


def is_cloud_password_noise(value: str, stmt: str) -> bool:
    """fix31 + fix42 唯一入口：本值是否是 1203 桶里**结构上确定**的噪音族（判据与量化见上方
    注释块）。

    只看本值与它在语句里的位置，不再要求任何密码键绑定；三条保护（绑键 / 键名位 /
    密码名 callee 实参）先判，命中即返回 False。

    本值**不在** stmt 里（分类器看到的窗口不含它，即 memo 的 snippet-absent 1139 值）→
    一律不判噪音：所有族都是**位置**判据，没有出现位置就没有依据（这条把「值不在窗口里」
    的那批行原样留给现行口径，实测 1337 链接 / 1139 值一行不动）。

    顺序（fix31b 修正 + fix42 追加 + fix43 追加后）：三条保护 → **fix43 位置守卫**（四类：
    i18n 键名位 / 字符串表元素 / 成员访问 / 扁平数组元素，见 is_cloud_password_position_noise
    —— 与 fix42 五族同属位置判据、同样不能被材料形豁免挡掉）→ ① 日志 callee 实参（**先于**
    材料豁免，日志 tag 照旧一律删）→ **fix42 五族**（同样是位置判据，且不能被材料形豁免挡掉：
    `pkcs5PBKDF2` / `1055120GWJCQi` 按 fix31c 的形态判据都是「材料形」）→ **材料形豁免**
    `is_cloud_password_material_shape`（值像材料 → ②/③ 的形态规则不许单独删它，见该判据的
    注释）→ ② 拼接分量且 URL 片段形态 → ③ 值形即 URL 片段。
    """
    if value not in stmt:
        return False
    if (_ccp_bound_to_any_key(value, stmt)
            or _ccp_keyname_position(value, stmt)
            or _ccp_password_callee_arg(value, stmt)):
        return False
    # fix43：**语法位置**守卫（三类）。排在三条保护之后、① 与 fix42 五族之前 —— 它和 fix42 五族
    # 同属「位置判据」（不被 fix31c 的材料形豁免挡掉），但射程是另一片：值的**位置形态**是
    # 字符串表元素 / 成员访问属性名 / 扁平数组元素。i18n 键名位刻意留给 fix42 P1（理由见
    # is_cloud_password_position_noise 的 docstring）。判据与量化见本节开头注释块。
    if is_cloud_password_position_noise(value, stmt):
        return True
    if is_cloud_password_log_call_tag(value, stmt):
        return True
    # fix42：五族结构噪音（位置判据）。排在①之后、材料形豁免之前 —— 见
    # is_cloud_password_fix42_family_noise 上方注释块的顺序理由。
    if is_cloud_password_fix42_family_noise(value, stmt):
        return True
    # fix31b：②/③ 是**值形**判据（② 的拼接条件被 ③ 完全包含，见 is_cloud_password_
    # material_shape 的注释），形态命中不再单独构成「噪音」—— 值本身像凭证材料就留下。
    # fix31c 把「像材料」收窄成「证据超出 URL 语法字符本身」（模板名/CSS 片段/驼峰标识符
    # 查询键不再算材料）；射程内的 44 个混淆串残留与不可再分的证据见该判据的 docstring。
    if is_cloud_password_material_shape(value):
        return False
    if (is_cloud_password_concat_operand(value, stmt)
            and is_cloud_password_url_fragment(value)):
        return True
    return is_cloud_password_url_fragment(value)


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
    # fix31 三族结构噪音（日志 tag / `+` 连接的 URL 片段 / 值形即 URL 片段），
    # 判据、三条保护与量化见 is_cloud_password_noise 上方的注释块。
    if is_cloud_password_noise(s, stmt):
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


# ---------------------------------------------------------
# fix28：crypto_static_iv 的「值位置」门（数组字面量元素噪音）
# ---------------------------------------------------------
# 病根：is_static_iv / is_static_aes_key 的语境判定是**窗口**搜索（值周围 512 字符里找
# iv / nonce / vector / sm4Iv / aesKey …），与值是不是真坐在加密入口无关。于是 webpack
# 分包名表 / 文案表 / 路由表这类**数组字面量**里的元素，只要同一条语句窗口里出现过 iv 词，
# 就整批被判 crypto_static_iv(2104)。normal_quarkpan 只读普查
# （test-result/fix28/probe_bindings.py，7 库同口径）：
#   全量 3602 链接 / 1630 值，其中
#     直接绑定在 crypto 族键上       674 链接 / 255 值   ← 必须全保留
#     数组/列表元素                  2344 链接 / 1159 值 ← 噪音主体
#     非数组未绑定                   348 链接 / 153 值   ← 混合族，行为不变
#   7 库普查里「数组自身绑定在 iv/aes 键上」= 0 例。
#
# 判据（**放在产出点 `process_static_iv`**，不放在两个值形判据里）：至少一个**独立出现**
# 满足
#   (1) 紧邻左侧的键（键与值之间不得出现 , ; { }）是 crypto 族；或
#   (2) 该出现不在数组字面量里；或
#   (3) 所在数组是「加密材料形态列表」：数组绑定在 crypto 族键上，或 ≤5 个顶层元素且
#       ≥n-1 个是加密材料形态（IV 形 16/24/32 hex、16/22/24 base64；AES KEY 材料形
#       48/64 hex 与 32 位 alnum —— fix28b 补齐，形态表见 `_iv_is_shaped_element`）。
# 都不满足 → 本值消费成 id_noise(2505, risk 0)。
# 边界（刻意保留，不隐藏）：窗口里没有独立出现（值只是更长字面量的一部分 / 上下文被截断）
# → 保留原判定，按「不误伤」处理；`foo[…]` 这类下标访问不是数组字面量，不进本门。
#
# ⚠️ 位置为什么是产出点（而不是判据里）：判据返回 False 会让值**继续往下走**，落到下游
# 的窗口误报判据上。normal_quarkpan 实测 3 个值 / 6 条链接（扁平配置数组）会因此从
# risk 2(IV) 升到 risk 5(platform_app_secret) —— 与 fix21 `625ea27` 的「收严一处让下游
# 既存误报显形」同一模式；处置也同一模式：消费成 risk0 噪音（id_noise），不新增类型。
# 放产出点还有个附带好处：`is_static_iv` / `is_static_aes_key` 的直接调用契约（既有测试）
# 一字不动。
#
# 与 `_bound_value_keys`（fix24/25/26 共用）同口径的两条细则：值必须**自成字面量**
# （前/后紧邻标识符字符的出现不算），键取**值左侧最近**的一个；本门只把「键与值之间」的
# 放行字符放宽到「没有 , ; { }」（兼容 `键: 表达式 || "字面量"` 之外的成员访问等写法）。
_IV_CRYPTO_FAMILY_WORDS = ("aes", "encrypt", "decrypt", "sm4", "des", "nonce", "vector")
_IV_BINDING_KEY_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*[\"']?\s*[:=]")
_IV_STRING_OPEN = "'\"`"
_IV_BRACKET_PAIRS = {")": "(", "]": "[", "}": "{"}
_IV_LIST_MAX_ELEMENTS = 5
_IV_SHAPED_HEX_LENGTHS = (16, 24, 32, 48, 64)
_IV_SHAPED_BASE64_LENGTHS = (16, 22, 24)
# fix28b：AES KEY 材料的 alnum 长度。16/24 已由 base64 分支覆盖（BASE64_CHARS 含全部 alnum），
# 这里真正补的是 32 —— `is_static_aes_key` 接受 32 位 alnum，本表原先不认。
_IV_SHAPED_AES_KEY_ALNUM_LENGTH = 32


def _iv_value_positions(value: str, stmt: str):
    """本值每个**独立出现**的起点（口径与 `_bound_value_keys` 一致）。"""
    pos = stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            yield pos
        pos = stmt.find(value, pos + 1)


def _iv_is_crypto_family_key(key: str) -> bool:
    """键名是否 IV/AES 族：`iv` 按词/驼峰段判（复用 RE_IV_CONTEXT），其余是子串。"""
    if not key:
        return False
    if any(word in key.lower() for word in _IV_CRYPTO_FAMILY_WORDS):
        return True
    return bool(RE_IV_CONTEXT.search(key))


def _iv_nearest_left_key(stmt: str, pos: int):
    """值左侧最近的 `键[:=]`；键与值之间出现 `, ; { }` 就不算绑定（那是别的成员）。"""
    best = None
    for m in _IV_BINDING_KEY_RE.finditer(stmt, 0, pos):
        if any(ch in ",;{}" for ch in stmt[m.end():pos]):
            continue
        best = m.group(1)
    return best


def _iv_skip_string(stmt: str, i: int) -> int:
    quote = stmt[i]
    i += 1
    while i < len(stmt):
        if stmt[i] == "\\":
            i += 2
            continue
        if stmt[i] == quote:
            return i + 1
        i += 1
    return i


def _iv_bracket_stack(stmt: str, end: int):
    """stmt[:end] 里未闭合的括号栈 [(开括号, 下标), ...]（忽略字符串与注释）。"""
    stack = []
    i = 0
    while i < end:
        ch = stmt[i]
        if ch in _IV_STRING_OPEN:
            i = _iv_skip_string(stmt, i)
            continue
        if ch == "/" and i + 1 < end and stmt[i + 1] == "/":
            newline = stmt.find("\n", i)
            i = end if newline == -1 else newline
            continue
        if ch == "/" and i + 1 < end and stmt[i + 1] == "*":
            close = stmt.find("*/", i + 2)
            i = end if close == -1 else close + 2
            continue
        if ch in "([{":
            stack.append((ch, i))
        elif ch in ")]}":
            if stack and stack[-1][0] == _IV_BRACKET_PAIRS[ch]:
                stack.pop()
        i += 1
    return stack


def _iv_enclosing_array(stmt: str, pos: int):
    """包含 pos 的最内层数组**字面量** (开括号下标, 闭括号下标)；不在其中返回 None。

    只认数组字面量：`[` 前一个非空字符不是标识符 / `)` / `]` / `}`（`foo[…]` 是下标访问）。
    窗口被截断找不到闭括号时，闭括号下标按窗口末尾算。
    """
    stack = _iv_bracket_stack(stmt, pos)
    if not stack or stack[-1][0] != "[":
        return None
    open_idx = stack[-1][1]
    j = open_idx - 1
    while j >= 0 and stmt[j] in " \t\r\n":
        j -= 1
    if j >= 0 and (stmt[j].isalnum() or stmt[j] in "_$)]}"):
        return None
    depth = 0
    i = open_idx
    while i < len(stmt):
        ch = stmt[i]
        if ch in _IV_STRING_OPEN:
            i = _iv_skip_string(stmt, i)
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                return (open_idx, i)
        i += 1
    return (open_idx, len(stmt))


def _iv_array_top_level_elements(inner: str):
    """把数组内容按**顶层**逗号切分（忽略括号与字符串内部），返回各元素原文。"""
    parts = []
    depth = 0
    current = []
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch in _IV_STRING_OPEN:
            end = _iv_skip_string(inner, i)
            current.append(inner[i:end])
            i = end
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail or parts:
        parts.append(tail)
    return [p for p in parts if p]


def _iv_is_shaped_element(token: str) -> bool:
    """元素是不是**加密材料形态**（去掉引号后判），即列表例外的形态表。

    表按两个值形判据的取值形态对齐（fix28b 补齐 AES KEY 那一半）：

      · IV 形：16/24/32 hex、16/22/24 base64（原有，一行未动）；
      · AES KEY 材料形：48/64 hex，以及 32 位 alnum 中非「驼峰单词串」的那部分
        （与 `is_static_aes_key` 的 16/24/32 alnum + 标识符护栏逐条同形；16/24 的 alnum
        本来就落进上面的 base64 分支）。

    为什么必须补：本表原先只有 IV 形，于是「数组元素全是 AES KEY 材料」的**合法**数组
    （`l.aesKey=k,t=["<32位alnum>","<32位alnum>"]`、64 位 hex 对这类）一个元素都不算形态 →
    `_iv_is_shaped_list` 的列表例外不成立 → 值与兄弟一起被消费成 id_noise(2505, risk0)，
    尽管 `is_static_aes_key` 对同一个值判真；而把数组变量名换成 `aesKeys`（crypto 族键名）
    又会走另一条出口保留 —— 变量的拼写不该决定真 AES KEY 的生死。
    只放宽这一格：列表大小上限、crypto 族键名出口与「值不在数组里即保留」三条一行未动，
    主数组噪音（webpack 分包名表 / 文案表这类 >5 元素的大表）不受影响。
    """
    text = token.strip().strip("'\"`")
    if len(text) in _IV_SHAPED_HEX_LENGTHS and is_hex_string(text):
        return True
    if (len(text) == _IV_SHAPED_AES_KEY_ALNUM_LENGTH and text.isalnum()
            and not is_word_shaped_identifier(text)):
        return True
    return len(text) in _IV_SHAPED_BASE64_LENGTHS and is_base64_chars(text)


def _iv_is_shaped_list(stmt: str, open_idx: int, close_idx: int) -> bool:
    """数组是否为「IV 形态列表」：绑定在 crypto 族键上，或 ≤5 个顶层元素且 ≥n-1 IV 形态。"""
    if _iv_is_crypto_family_key(_iv_nearest_left_key(stmt, open_idx)):
        return True
    elements = _iv_array_top_level_elements(stmt[open_idx + 1:close_idx])
    if not elements or len(elements) > _IV_LIST_MAX_ELEMENTS:
        return False
    shaped = sum(1 for e in elements if _iv_is_shaped_element(e))
    return shaped >= len(elements) - 1


def _iv_value_position_kept(value: str, stmt: str) -> bool:
    """fix28 门：本值是否至少有一个独立出现坐在「真值位置」（理由与边界见上面的注释块）。

    三个出口任一成立即保留：直接绑定 crypto 族键 / 该出现不在数组字面量里 / 所在数组是
    IV 形态列表。窗口里没有独立出现时返回 True（无法判定 → 保留原判，不误伤）。
    """
    positions = list(_iv_value_positions(value, stmt))
    if not positions:
        return True
    for pos in positions:
        if _iv_is_crypto_family_key(_iv_nearest_left_key(stmt, pos)):
            return True
        array = _iv_enclosing_array(stmt, pos)
        if array is None:
            return True
        if _iv_is_shaped_list(stmt, array[0], array[1]):
            return True
    return False


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
    # fix28 注：值位置门不在这里 —— 判据的返回值留给既有契约（直接调用者），
    # 门放在共享的产出点 process_static_iv（见该函数与上面的注释块）。
    if length in IV_HEX_LENGTHS and is_hex_string(s):
        return True
    if length in IV_BASE64_LENGTHS and is_base64_chars(s):
        return is_random_iv_value(s)
    if length in IV_STR_LENGTHS and s.isalnum():
        return is_random_iv_value(s)

    return False


def is_static_aes_key(s: str, stmt: str) -> bool:
    """检测是否为硬编码 AES KEY

    fix28 注：值位置门不在这里，放在共享的产出点 process_static_iv（见该函数）。
    """
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
    """分类硬编码 IV 或 AES KEY（fix28：值位置门在**产出点**，且门不过时消费成 id_noise）。

    `is_static_iv` / `is_static_aes_key` 两个值形判据保持原样（既有直接调用契约不变），
    门在这里统一生效：至少一个**独立出现**坐在真值位置（直接绑定 crypto 族键 / 不在数组
    字面量里 / 所在数组是 IV 形态列表；细则见上面的注释块）→ 产 crypto_static_iv；
    三条都不满足（数组噪音）→ **消费成 id_noise(2505, risk 0)**，不让值继续往下走。

    为什么必须放在产出点、且必须消费：判据返回 False 会让值继续落到下游的窗口误报判据上。
    normal_quarkpan 实测 3 个值 / 6 条链接（扁平配置数组）会因此从 risk 2(IV) 升到
    risk 5(platform_app_secret) —— 与 fix21 `625ea27` 的「收严一处让下游误报显形」
    同一模式，处置也同一模式（消费成 risk0 噪音，不新增类型）。
    """
    if _iv_value_position_kept(s, stmt):
        append_result(res, IDT.CRYPTO_STATIC_IV, s, src, sid)
    else:
        append_result(res, IDT.ID_NOISE, s, src, sid)


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
# pii_get_digit_type 的**第三态**：形态像手机号/身份证，但号段/校验位判据明确否定。
# 调用方必须把它**显式**落到 pii_noise(2304, risk0)：静默落选（返回 ""）会让值继续往下
# 走支付/凭证/标识符判据，也就是「平移」到别的桶 —— 历次修复反复踩的坑。
PII_DIGIT_REJECT = "pii_noise"

# ---------------------------------------------------------
# fix36：11 位手机号的**号段**校验（工信部《电信网码号资源使用证书》编号计划）
# ---------------------------------------------------------
# 原判据只有「11 位 + 全数字 + 首位 1 + 至少 3 个不同数字」，没有任何号段校验。编号计划里
#   · 10x / 11x / 12x = **服务号段**（100xx 运营商客服、110/119/120/114/123xx 特种服务…）；
#   · 140~144 = **13 位**物联网网号（^140\d{10}$ 联通 / ^141\d{10}$ 电信 /
#     ^142\d{10}$~^143\d{10}$ / ^144\d{10}$ 移动），不是 11 位手机号；
# 所以这三种一律否定。145/146/147/148/149（上网卡/物联网的 11 位号段）与 15x~19x 一律
# **不收紧**（号段表会变，不做真实号段白名单）。
# 只读普查：v2 2302 桶 5,308 值里 615 值 / 1,809 链接、pkgref 701 值里 182 值 / 350 链接
# 属于这些号段（106 短信端口号 253、113xxxx0000 198、144 SDK 占位 97…），
# 都不是手机号而是端口号/连号 ID/SDK 占位串。
_PHONE_BAD_PREFIX2 = ("10", "11", "12")
_PHONE_BAD_PREFIX3 = ("140", "141", "142", "143", "144")


def is_impossible_phone_segment(s: str) -> bool:
    """11 位手机号形态的值，号段是否**明确不可能**是手机号。

    只看号段：不满足「11 位 + 全数字 + 首位 1」的形态一律 False（那不是本判据的对象）。
    """
    if len(s) != 11 or not s.isdigit() or s[0] != "1":
        return False
    return s[:2] in _PHONE_BAD_PREFIX2 or s[:3] in _PHONE_BAD_PREFIX3


# ---------------------------------------------------------
# fix38：18 位身份证号的 GB 11643-1999 三维校验
# ---------------------------------------------------------
# 原判据只有「18 位 + 末位数字或 X + 前 17 位全数字 + 至少 4 个不同数字 + 第 7~14 位像
# 日期（年 1900-2026、月 1-12、日 1-31）」—— 没有校验位、没有省级行政区代码、也不看
# 日历是否真实存在（20260230 照样通过）。补三维：
#   ① 校验位：前 17 位加权因子 × 模 11 映射 "10X98765432"（末位 x 大小写都接受）；
#   ② 省级行政区代码（GB/T 2260）：11~15 / 21~23 / 31~37 / 41~46 / 50~54 / 61~65 / 71 / 81 / 82；
#   ③ 出生日期真实存在（含闰年：20230229 不存在、20240229 存在）。
# 只读普查：v2 2301 桶 129 值中 33 值 / 78 链接、pkgref 16 值中 7 值 / 9 链接过不了这三维
# （其中 1 条只有省份码这一维不过）。示例号（110101…1234 这类）不设名单，校验通过就保留。
_SFZ_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_SFZ_CHECK_MAP = "10X98765432"
_SFZ_MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
_SFZ_PROVINCE_CODES = frozenset((
    "11", "12", "13", "14", "15", "21", "22", "23", "31", "32", "33", "34", "35", "36",
    "37", "41", "42", "43", "44", "45", "46", "50", "51", "52", "53", "54", "61", "62",
    "63", "64", "65", "71", "81", "82"))


def _sfz_calendar_ok(year: int, month: int, day: int) -> bool:
    """出生日期是否真实存在（含闰年判断）。"""
    if not (1 <= month <= 12):
        return False
    max_day = _SFZ_MONTH_DAYS[month - 1]
    if month == 2 and (year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)):
        max_day = 29
    return 1 <= day <= max_day


def is_valid_sfz18(s: str) -> bool:
    """18 位身份证号是否过 GB 11643-1999 的校验位 / 省份码 / 日历三维校验。

    形态（18 位、末位数字或 X、前 17 位全数字）由调用方的前置检查负责；这里对形态不对的
    输入一律 False，不会把「不是身份证形态」的值判成否定。
    """
    if len(s) != 18 or not s[:17].isdigit():
        return False
    if not (s[17].isdigit() or s[17] in "Xx"):
        return False
    if s[:2] not in _SFZ_PROVINCE_CODES:
        return False
    try:
        year, month, day = int(s[6:10]), int(s[10:12]), int(s[12:14])
    except ValueError:
        return False
    if not _sfz_calendar_ok(year, month, day):
        return False
    total = sum(int(c) * w for c, w in zip(s[:17], _SFZ_WEIGHTS))
    return _SFZ_CHECK_MAP[total % 11] == s[17].upper()


def pii_get_digit_type(s: str) -> str:
    """检查数字字符串的类型 (身份证/手机号)

    返回 `"pii_sfz"` / `"pii_phone"` / `PII_DIGIT_REJECT`（形态像但判据明确否定）/
    `""`（不是 PII 数字形态）。第三态必须由调用方显式落到 pii_noise —— 见
    `PII_DIGIT_REJECT` 的说明。
    """
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

        # fix38：GB 11643-1999 的校验位 / 省级行政区代码 / 日历三维校验
        if not is_valid_sfz18(s):
            return PII_DIGIT_REJECT
        return "pii_sfz"

    # 手机号 11位
    if s_len == 11 and s.isdigit() and s[0] == '1' and len(set(s)) >= 3:
        # fix36：号段校验（只拒绝工信部编号计划里明确不可能作 11 位手机号的号段）
        if is_impossible_phone_segment(s):
            return PII_DIGIT_REJECT
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


# 编译器身份上下文：小程序编译产物里 `__wxAppCode__['pages/x/y.wxml'] = …` 这类注册表键、
# 以及 `__wxAppCurrentFile__ = 'pages/x/y.wxss'`、`__wxAppFile__` 这类当前文件标记。
RE_COMPILER_IDENTITY_CONTEXT = re.compile(
    r"__wxappcode__|__wxappcurrentfile__|__wxappfile__", re.I)

# fix23（收严 fix20 ④）：标记必须**直接引用该值**，而不是「窗口里恰好出现了标记」。
#
# fix20 ④ 原来的判据是 `RE_COMPILER_IDENTITY_CONTEXT.search(stmt) and 值以 .wxml/.wxss/.json 结尾`
# —— 它读的是**窗口**（perform_constant_classifying 里 `stmt` = `extract_context(raw_stmt, 该语句第一个常量, 512)`，
# 同一语句的其它常量复用这个窗口，窗口里可能根本没有该值）。于是「同一语句里恰好有个
# __wxAppCode__，而本值只是这条语句里另一个位置的 .json/.wxml 串」也会被整条搬走。
#
# 真扫 icp（unlist_icp_filing_v2，代码 625ea27）实测：1907 里带 .wxml/.wxss/.json 的值
# 122,357 个，其中「标记直接引用该值」的 121,071 个、只有「窗口里有标记」而标记**没有**
# 引用该值的 1,286 个 / 10,771 次（test-result/fix23/c_direct.out）。这 1,286 个就是本条
# 收掉的部分，它取的是 fix20 ③ 的取证逻辑：**被移动的值必须能在自己的 snippet 里被标记点名**。
#
# 形态（先读真扫 source_snippet 再定，不凭空写；样例见 test-result/fix23/c_direct.out）：
#   `__wxAppCode__['pages/index/index.json'] = {…}`          ← 注册表键，值在引号里
#   `__wxAppCode__[ "pages/x/y.wxml" ] = [$gwx_XC_10, …]`     ← 引号可为 ' 或 "，中括号内可有空白
#   `__wxAppCurrentFile__ = 'pages/x/y.wxss'` / `__wxAppFile__ = '…'`  ← 当前文件标记
# 反例（不算直接引用，留在原桶）：
#   `__wxAppCode__['cms/auth.wxss'] = setCssToHead([[2,"./@titan/style.wxss"],]…)`
#       —— 值是 **setCssToHead 的 @import 目标**，标记点的名是 `cms/auth.wxss`，不是 `./@titan/style.wxss`
#   `__wxAppCode__['plugin-private://wx…/plugin.wxml'] = [$gwx, './plugin.wxml']`
#       —— 值是注册数组的第 2 个元素，标记点的名是 plugin-private://… 那个
RE_COMPILER_IDENTITY_REF = re.compile(
    r"__wxappcode__\s*\[\s*(?P<q1>['\"])(?P<k1>[^'\"]*)(?P=q1)\s*\]"
    r"|__wxapp(?:currentfile|file)__\s*=\s*(?P<q2>['\"])(?P<k2>[^'\"]*)(?P=q2)",
    re.I)

# fix20 ④：这些后缀在编译产物里是**模板/样式/配置**文件身份，两边读法（字面 require 路径 /
# 宽义的「前端模块引用」）下都不是模块引用：
#   `pages/account/reserve.json` ← `__wxAppCode__['pages/account/reserve.json'] = {…}`
#   `pages/account/login/index.wxml` / `.wxss` ← 编译模板/样式（setCssToHead、__wxAppCurrentFile__）
# **故意不包含 .js**：`__wxAppCode__['pages/x/index.js'] = function(){…}` 里的值就是编译后
# 模块的模块 id（同族里还有 343/786/2510 个值的同语境里直接出现 require/import），
# 按字面与宽义都可能算「模块路径」，证据不足以移走 —— 这一条是本处刻意留下的残余（见报告）。
# 真扫 icp 复验（code 625ea27）：1907 里 .js 为 0 个值，这条边界守住了。
MINIAPP_COMPILER_NONMODULE_EXTENSIONS = (".wxml", ".wxss", ".json")


def _norm_compiler_ref_path(p: str) -> str:
    """编译器身份串里的路径归一：反斜杠→斜杠，剥掉前导 `./`。

    真扫里同一个文件两种写法同时出现（`pages/index/index.wxml` 与 `./pages/index/index.wxml`
    是同一份模板的第 1、2 个注册位），所以两侧都按这个归一后比较。
    """
    p = (p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def is_compiler_file_identity(s: str, stmt: str) -> bool:
    """值是否为「编译器身份串里的非模块文件」——模板/样式/配置文件身份。

    判据 = ① 语境里出现编译器身份标记；② 值以 .wxml/.wxss/.json 结尾；
           ③ **标记直接引用该值**（值本身在标记的引号里，见 RE_COMPILER_IDENTITY_REF）。
    归置见 perform_constant_classifying 的**链尾改判**：把本来会产出的标签换成
    miniapp_noise(1907)，**不制造新行**（口径见那里的注释）。
    """
    if not RE_COMPILER_IDENTITY_CONTEXT.search(stmt or ""):
        return False
    if not s.lower().endswith(MINIAPP_COMPILER_NONMODULE_EXTENSIONS):
        return False
    want = _norm_compiler_ref_path(s)
    for m in RE_COMPILER_IDENTITY_REF.finditer(stmt):
        key = m.group("k1") if m.group("k1") is not None else m.group("k2")
        if _norm_compiler_ref_path(key) == want:
            return True
    return False


def has_usingcomponents_context(stmt: str) -> bool:
    """语句里是否出现 usingComponents 组件声明（大小写不敏感）。

    用于 fix20 ③：项目自建源码根（/src/、/common/、/usercenter/）下的斜杠路径，
    只有落在组件声明附近才算组件引用（见 MINIAPP_COMPONENT_CONTEXT_PREFIXES 的取证）。

    只认这一个标记、不做更复杂的结构解析：三库实测该标记在该族上从未误指向别的值
    —— 被移动的 1153 个值全部能在自己的 snippet 里找到自己的路径
    （test-result/fix20/issue3_mixed.out）。stmt 是 512 字符窗口，可能包含同一语句
    其它常量的内容（见 perform_constant_classifying 的窗口说明），这是本判据已知的
    精度上界；若把范围放宽到「任意前缀 + 该标记」，被移动的值会从 1.1k 涨到 30k+
    （icp 单库 3836 值 / 139,488 次，绝大多数来自 miniapp_api_params），故不再放宽。
    """
    return "usingcomponents" in (stmt or "").lower()


def is_subpackage_component_path(s_lower: str) -> bool:
    """分包根下的**组件引用**路径（分包根 + 组件目录段，见 MINIAPP_COMPONENT_DIR_SEGMENTS）。

    只用于 fix20 ③ 的语境放行：调用方还必须证到 usingComponents 语境。
    """
    return (s_lower.startswith(MINIAPP_PACKAGE_ROOTS)
            and has_keyword_substring(s_lower, MINIAPP_COMPONENT_DIR_SEGMENTS))


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
    # 后缀（资源/模块）先在「敏感关键词」之前定性：SENSITIVE 是**裸子串**判据，
    # `pages/images/management.png`（management ⊃ manage）、`pages/test/test.js` 这类
    # 词干巧合本来会被抢进 1901（risk 桶），而它们其实是静态资源 1905 / 模块引用 1906。
    # 只对**不带查询串**的值提前：带 `?` 的值保持原顺序（否则 `/xxx.png?t=` 会从 1904 被抢成 1905）。
    if "?" not in rel_path:
        if any(s_lower.endswith(ext) for ext in MINIAPP_ASSET_EXTENSIONS):
            return "ASSET"
        if any(s_lower.endswith(ext) for ext in MINIAPP_MODULE_EXTENSIONS):
            return "MODULE"
    if has_keyword_substring(s_lower, SENSITIVE_PAGE_KEYWORDS):
        return "SENSITIVE"
    if "?" in rel_path:
        return "PARAM"
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
                # fix36/fix38：第三态 PII_DIGIT_REJECT（形态像手机号/身份证但号段/校验位
                # 判据明确否定）与「不是 PII 数字形态」在这里本来就同落 pii_noise(2304,
                # risk0)；显式写出来是为了让这条归置不被后来的改动顺手打散。
                append_result(res, IDT.PII_NOISE, val, src, sid)


# =========================================================
# 通用分类处理函数
# =========================================================
def process_generic_spaced_constant(s: str, stmt: str, src: str, sid: int, results: list):
    """处理包含空格的常量"""
    pass


# ---------------------------------------------------------
# fix24：支付参数的「值位置绑定」判据（只给数字开头链用）
# ---------------------------------------------------------
# 背景（只读回放见 test-result/fix24/replay_payment_timestamp.py）：CONTEXT_KEYWORDS 里
# `"timestamp" → 2401` 是**裸子串**出口，且 dict 顺序把 paysign(2405)/noncestr(2402) 排在
# timestamp 之前，于是数字开头的值只要窗口（值周围 512 字符）里出现过 timestamp 子串就直接
# 出口 2401 —— normal_quarkpan 561 值 / 774 链接（409 值紧邻绑定在**小写通用** `timestamp:` 上
# 且窗口里没有任何支付证据词，332 个去重值是聊天 ISO 时间），pkgref 26 值 / 37 链接（多数是
# webpack 分包名数组撞上 `_$uCountDownTimestamp`）。反过来，真实支付对象里 `timeStamp` 的值
# 因为 paysign/noncestr 排在前面而落到 2405/2402（错 slug）。
#
# 判据：只看**本值的位置** —— 紧邻的 `键:` / `键=` / `"键":`（键与值之间只允许引号/空格），
# 额外允许 `键: 表达式 || "字面量"` 这种默认值写法（表达式内不许出现引号/逗号/花括号）。
# 绑定的键按 PAYMENT_PARAM_NAMES 的**精确拼写**（大小写敏感）查表：
#   · `timeStamp`（驼峰规范写法）→ 2401，不要求别的证据（保留既有真阳性契约）；
#   · `timestamp` / `time_stamp` 等通用写法 → 同窗口必须有支付证据词才判 2401，否则不判支付
#     （聊天记录里的 timestamp 就是这一族；证据词只在这一支里用）；
#   · `nonceStr` / `paySign` / `signType` → 2402 / 2405 / 2404（值位置口径）。
# 没有紧邻绑定、或紧邻绑定不是支付键（ReportTimestamp / cTimeStamp / appKey / alipaySignAsac /
# `e=[` 这类）→ 数字开头链不再因为窗口里出现支付词而出口。
# 已知代价（不隐藏）：URL 查询串里的 `&timestamp=` 参数值失去支付标签；alipaySignAsac /
# X-PA-NONCESTR 这类复合键名已由下面的族内放行保留，见
# unit-tests/test_payment_param_placement.py 的保留组与已知代价组。
_PAYMENT_VALUE_BINDING_RE = re.compile(
    r'(?:^|[^\w$])([A-Za-z_$][\w$]*)\s*["\']?\s*[:=]\s*'   # 键与分隔符：timeStamp: / paySign= / "nonceStr":
    r'(?:[A-Za-z0-9_$.\[\]()?!]*\s*\|\|\s*)?'              # 允许 `键: 表达式 || "字面量"` 的默认值写法
    r'["\']?\s*$')                                          # 键与值之间只允许引号/空格


def _bound_value_keys(value: str, stmt: str):
    """按出现顺序产出本值每个**独立出现位置**左侧紧邻的绑定键（原拼写）。

    fix24 / fix25 / fix26 三条「值位置绑定」判据共用的扫描器：两条细则原本在三条判据里
    各写了一份、逐字相同，只有键表与命中后的动作不同 —— 抽到这里后差异只剩键表/查表逻辑。
      · **独立出现**：值必须自成字面量 —— 前/后紧邻标识符字符（字母数字 `_` `$`）的出现不算，
        否则「本值只是更长字面量的前缀/后缀」时会把那个字面量的键算到本值头上；
      · **紧邻左侧的键**：`_PAYMENT_VALUE_BINDING_RE` 在本次出现起点之前最后一次匹配到的
        `键:` / `键=` / `"键":`（`键: 表达式 || "字面量"` 的默认值写法算在同一个键上），
        不做窗口搜索（`stmt` 是值周围 512 字符的上下文，窗口里出现某个词不能说明值绑给谁）。
    生成器是惰性的：调用方「首个命中即返回」的短路行为与去重前逐字一致。
    """
    pos = stmt.find(value)
    while pos != -1:
        end = pos + len(value)
        if not ((pos > 0 and (stmt[pos - 1].isalnum() or stmt[pos - 1] in "_$"))
                or (end < len(stmt) and (stmt[end].isalnum() or stmt[end] in "_$"))):
            m = _PAYMENT_VALUE_BINDING_RE.search(stmt, 0, pos)
            if m is not None:
                yield m.group(1)
        pos = stmt.find(value, pos + 1)


# 复合键名的**族内放行**（fix24）：键名含下面四个词之一 → 对应 slug。
# 只认 nonce/paySign 两族，**timestamp 族绝不参与** —— `alipaySignAsac`（支付宝签名键）
# 与 `X-PA-NONCESTR`（支付宝支付头名）是真阳性，不能因为「键名不是规范拼写」丢掉；
# 而 `ReportTimestamp` / `cTimeStamp` / `BUILD_TIMESTAMP` / `dumpEventTimeStamp` /
# `couponTimeStamp*` / `webtimestamp` 是前缀式时间戳键名，正是本修复要清的噪音。
_PAYMENT_COMPOUND_KEY_WORDS = (
    ("paysign", IDT.PAYMENT_PAY_SIGN),
    ("pay_sign", IDT.PAYMENT_PAY_SIGN),
    ("noncestr", IDT.PAYMENT_NONCE),
    ("nonce_str", IDT.PAYMENT_NONCE),
)

# 这三个 slug 只允许从「值位置绑定」出口：CONTEXT_KEYWORDS 的裸关键词出口对本函数关闭。
_PAYMENT_VALUE_ONLY_SLUGS = (IDT.PAYMENT_REQUEST_PARAMS, IDT.PAYMENT_NONCE, IDT.PAYMENT_PAY_SIGN)


def _payment_param_slug_bound_to_value(value: str, stmt: str, stmt_lower: str):
    """返回**紧邻本值**的支付参数键对应的 slug；没有绑定 / 绑定键不是支付参数 → None。

    只看本值每个出现位置左侧紧邻的键（`键:` / `键=` / `"键":`，`键: 表达式 || "字面量"`
    的默认值写法算在同一个键上），不做窗口搜索：`stmt` 是值周围 512 字符的上下文，
    窗口里出现支付词根本不能说明这个值是谁的值 —— 那正是 fix24 要修的。
    三条细则：
      · 本值必须**自成字面量**：前/后紧邻标识符字符（字母数字 `_` `$`）的出现不算绑定，
        否则「本值只是更长字面量的前缀/后缀」时会把那个字面量的键算到本值头上；
      · 通用 `timestamp` 写法且窗口里没有支付证据词 → **只跳过这一次出现**，继续看本值的
        其余出现（同一值可能在别处绑在规范写法 `timeStamp` 或支付键上，不能整值否定）；
      · 精确拼写查不到时按 `_PAYMENT_COMPOUND_KEY_WORDS` 做族内复合键名放行。
    出现位置与紧邻键的扫描口径由 `_bound_value_keys` 提供（fix25 / fix26 共用同一台）。
    """
    evidence = ("requestpayment", "prepay_id", "noncestr", "nonce_str",
                "paysign", "pay_sign", "signtype", "sign_type", "package")
    for key in _bound_value_keys(value, stmt):
        slug_id = PAYMENT_PARAM_NAME_TO_SLUG.get(key.lower())
        if slug_id is None:
            key_lower = key.lower()
            for word, family_slug in _PAYMENT_COMPOUND_KEY_WORDS:
                if word in key_lower:
                    slug_id = family_slug
                    break
        if slug_id is not None:
            # 通用 timestamp（非驼峰规范写法）：窗口里没有支付证据词 → 这一次出现不成立
            if slug_id == IDT.PAYMENT_REQUEST_PARAMS and key != "timeStamp" \
                    and not any(word in stmt_lower for word in evidence):
                continue
            return slug_id
    return None


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
    # fix36/fix38：第三态 —— 形态像手机号/身份证，但号段（fix36）/GB 11643 三维校验
    # （fix38）判据明确否定。**显式**落 pii_noise(2304, risk0) 后返回：这里若不返回，
    # 值会继续往下走 OID/支付/凭证/语境关键词判据，也就是「平移」到别的 risk≥4 桶。
    if data_ty == PII_DIGIT_REJECT:
        append_result(res, IDT.PII_NOISE, s, src, sid)
        return

    # 排除 OID 格式 (如 1.3.6.1.5.5.7.3.8, 1.2.840.113549.1.9.16.2.48)
    if _is_oid_format(s):
        append_result(res, IDT.PII_NOISE, s, src, sid)
        return

    # 支付参数：只有**紧邻本值**的支付键才出口（fix24，判据与代价见上面的说明）
    pay_slug = _payment_param_slug_bound_to_value(s, stmt, stmt_lower)
    if pay_slug is not None and "/" not in s:
        append_result(res, pay_slug, s, src, sid)
        return

    # 通过上下文关键词匹配 (数字开头的值需要更严格的验证)
    for keyword, slug_id in CONTEXT_KEYWORDS.items():
        if keyword in stmt_lower:
            # 排除路径格式
            if "/" in s:
                continue
            # 支付关键词不再作为裸窗口出口（fix24）：本值走不走支付桶只看上面那条绑定判据
            if slug_id in _PAYMENT_VALUE_ONLY_SLUGS:
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
            # 云区域（fix19 ①）：语境词 region 只说明「这句话在配云区域」，值本身还得真是
            # 区域名。本链只处理**数字开头**的值，而区域名一律以 cn-/ap-/us-/eu-/na- 这类
            # 字母前缀开头，所以数字开头的值一律过不了与主链同一条 is_cloud_region_value。
            # 补这条守卫前，任何「stmt 里含 region 子串」的数字开头值都直接出口：
            #   region: [101,200] / 201~500        → 价格区间（三库 18 个值，均含 ~）
            #   regionId:10006378 / 420100000000  → 纯数字 ID（22 个值）
            #   1,72,2839,0 / 500b1953-8,xxx-7    → CSV（3 个值）
            #   0x1f1e6 / 20240425-address_add / 2handleSelectFloor /
            #   2中心点坐标currentRegion / 82D9….js / 0;overflow-y:auto;… → 逐个见报告
            # 三库合计 55/101 值（54%）是这一类噪音，46 个真区域 0 误伤。
            elif slug_id == IDT.CLOUD_REGION:
                if not is_cloud_region_value(s):
                    continue
            # 云桶名（fix19 ②）：同理，值必须过主链同一条 is_bucket_name。桶名允许数字开头，
            # 但它的字符集是 ^[a-z0-9][a-z0-9-]*[a-z0-9]$（不含 `.` `_` `:`），长度 6~63。
            # 补这条守卫前，`concat(v.ossBucket,"9f01….png")` 里的**文件名**（normsib 25 个，
            # 占该库桶名 23%）和 `timeBucket: ["8:00-12:00"]` 里的**时间段**都判成了桶名，
            # 而 is_bucket_name 本身对这两个值返回 False —— 它们根本没走主链那条判据。
            elif slug_id == IDT.CLOUD_BUCKET_NAME:
                if not is_bucket_name(s, stmt):
                    continue
            # AK/SK 值侧配对判据（fix33）：1201 的正规出口是 process_ak_sk_pair，产出的值
            # **本身就是一对** `AK=…, SK=…`；本出口（裸关键词 secret_key/secretkey/secretid）
            # 从不问「这个值自己是不是一对」，于是一批「邻域里恰好出现关键词」的裸值白得一个
            # risk5 标签。这里只放行三种值（判据见 AK/SK 段的三条函数）：
            #   · 值自己就是一对（与正规出口同源的口径）；
            #   · 够得上密钥材料形态（可能是被截断/没配成对的真材料）→ 歧义残渣，留着；
            #   · 语句里看得见真配对（独立成词的关键词 / AKID… 令牌）→ 值可能只是其中一半。
            # 三条都不满足 → **显式改判** pii_noise(2304, risk0)：本函数对无标签的值本来就落
            # 这个桶，所以这叫「拿掉白得的标签」，既不新造行、也不静默丢弃、更不平移进别的
            # risk≥4 桶。普查三分（14 删 / 6 材料形态 / 2 看得见配对）与量化见
            # unit-tests/test_fix33_aksk_value_pairing.py 与 test-result/fix33/。
            elif slug_id == IDT.CLOUD_CRED_AK_SK_PAIR:
                if not (is_ak_sk_pair_value(s)
                        or is_credential_material_shape(s)
                        or has_visible_ak_sk_pair_evidence(stmt)):
                    append_result(res, IDT.PII_NOISE, s, src, sid)
                    return
            append_result(res, slug_id, s, src, sid)
            return

    append_result(res, IDT.PII_NOISE, s, src, sid)


# ---------------------------------------------------------
# fix25：server_cred_cookie 裸 cookie 出口的「多段标识符名」守卫
# ---------------------------------------------------------
# 背景（normal_quarkpan 只读全量普查，见 unit-tests/test_server_cookie_segmented_names.py）：
# CONTEXT_KEYWORDS_2 的 `"cookie"` 是本函数里唯一**没有专属判据把关**的出口（appsecret 复用
# is_secret_key、access_token 复用 is_access_token_format、cookie 只剩裸子串）。fix15 ③ 的
# `is_single_segment_identifier_name` 只覆盖**单段**名，多段那一族整族漏出：1,604 桶内 8,535
# 条链接里 5,153 条 / 1,460 个值的 `is_segmented_identifier_name` 为真，且**全部**经这条出口
# 进来（`is_server_cookie` 命中 0 条 —— 它要求值含 `=` 且长度 ≥10，够不到名字）。头部值：
# `XSRF-TOKEN`(618 链接，全绑在配置键 xsrfCookieName 上) / `PAGE_COOKIE`(231) /
# `Storage.Keys.Cookie`(136) / `quick_cookieObj`(87) / `user_token`(54) / `cookie-info`(38)。
#
# 归置：值形是「多段词形标识符名」时不再出口 —— **除非**本值绑在真正的 cookie **值**位置。
# 判据与代价见下面两个函数的注释；绑定口径直接复用 fix24 的 `_PAYMENT_VALUE_BINDING_RE`
# （同一个「紧邻本值左侧的键」写法），只换键表。
def is_segmented_identifier_name_or_prefix(s: str) -> bool:
    """多段词形标识符名，或它的**名字前缀**（尾随分隔符写法）。

    = `is_segmented_identifier_name(s)`（见其注释块）**或**「去掉尾随分隔符后仍是多段名」。
    后一支只加 `_` / `.` / `-` 三种结尾，是有界且极窄的：三库 cookie 桶全量实测额外收
    19 / 8 / 3 个值，逐个核对全是名字片段（`PAGE_COOKIE_` / `mw-cookie-` / `chat-input__` /
    `local_debug_` / `lg-token-` / `mwp.cookie.` / `setting_cookie_` / `addresslist_cookie_`），
    无一个像材料、也无一个落在 fix12/fix15 的反例矩阵上。加它的理由：真实坏值
    `f="storage"===s?"PAGE_COOKIE_"+c:"PAGE_COOKIE"` 的两个分支（带/不带尾随 `_`）
    是同一个存储键，只认前一支会留下半个病灶。
    """
    if is_segmented_identifier_name(s):
        return True
    if len(s) < 3 or s[-1] not in "_.-":
        return False
    return is_segmented_identifier_name(s.rstrip("_.-"))


# cookie **值**键：值位置绑定里，只有这两个键说明「右边坐的是 cookie 值」。
# `Cookie: "…"`（HTTP 头）/ `cookie: "…"` / `document.cookie = "…"` 都落在这个键上
# （键正则的键是 `[A-Za-z_$][\w$]*`，`.` 与 `-` 都是分隔符，`Set-Cookie` 也切成 `Cookie`）。
# **刻意不含**含 cookie 的复合键 —— `xsrfCookieName` / `COOKIE_NAME` / `cookieStorageName` /
# `loginCookieKey` / `COOKIE_KEY` / `CookiePrefixParamName` 这些键位坐的是 cookie **名**本身，
# 正是本轮要清的噪音：`xsrfCookieName: "XSRF-TOKEN"` 一条就是 610 条链接。
COOKIE_VALUE_BINDING_KEYS = ("cookie", "cookies")


def _cookie_value_key_bound_to_value(value: str, stmt: str) -> bool:
    """本值是否绑定在 cookie **值**位置（键表见 COOKIE_VALUE_BINDING_KEYS）。

    口径与 fix24 的 `_payment_param_slug_bound_to_value` 完全一致，只换键表、不做窗口搜索：
      · 只看**紧邻本值左侧**的 `键:` / `键=` / `"键":`（`键: 表达式 || "字面量"` 同一键）；
      · 本值必须**自成字面量**：前/后紧邻标识符字符（字母数字 `_` `$`）的出现不算绑定，
        否则「本值只是更长字面量的前缀/后缀」时会把那个字面量的键算到本值头上
        （`tal` 在 `cookie: "tal_token="` 里不算绑定，值 `tal_token` 才算）；
      · 扫本值的**所有**出现位置：任一处绑在 cookie 值键上即放行
        （`tal_token` 在 `cookie: "tal_token=".concat(…)` 就是这一支）。
    出现位置与紧邻键的扫描口径由 `_bound_value_keys` 提供（fix24 / fix26 共用同一台）。
    """
    return any(key.lower() in COOKIE_VALUE_BINDING_KEYS
               for key in _bound_value_keys(value, stmt))


def process_generic_alpha_prefixed_constant(s: str, stmt: str, src: str, sid: int, res: list,
                                            name_class_reject: bool = False):
    """处理字母开头的常量。

    `name_class_reject`（fix22）：该值在 `is_identifier` 里**只因命名形态排除**落选，
    即已是「已知的名字类噪音」。本函数末尾的 CONTEXT_KEYWORDS_2 是**裸关键词出口**
    （stmt 里出现 `cookie` / `appsecret` / `access_token` 就出口），它没有专属判据把关，
    于是把这类名字升级进风险桶（三库实测 1 行 / 1 次：`在线建档h5需要unionId`
    因 stmt 含 `authCookie` 被判 server_cred_cookie）。置位时改判 id_noise(2505, risk 0)。
    """
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
                # fix25：单段守卫够不到**多段**那一族（属性名 / i18n key / 存储键 / 常量名，
                # normal_quarkpan 实测 5,153 条链接 / 1,460 个值）。多段名只在**绑在真正的
                # cookie 值位置**时放行（绑定口径与 fix24 同一条），见上面两个判据的注释。
                if (is_segmented_identifier_name_or_prefix(s)
                        and not _cookie_value_key_bound_to_value(s, stmt)):
                    continue
            # fix22：只改判**这条出口本来真要产出的**标签（上面各守卫的 `continue` 一律
            # 保持原样，否则会把「本来不产出任何类型」的值也变成 id_noise —— 实测那会多改
            # 47 行，超出本轮授权）。
            if name_class_reject:
                append_result(res, IDT.ID_NOISE, s, src, sid)
                return
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

    # 6b. fix20 ③：另外几族组件引用首段（+ 项目自建源码根下的 usingComponents 语境）。
    #     放在第 8 步（敏感关键字）之前 —— 这些值里大量带 auth/login/pay/admin 段
    #     （user-authorize / authPopup / authorize / login-mask / pay-payment），
    #     正是它们把 1702/1703/1901 的头部占满的原因。
    #     页面路由形态不走这条（/src/pages/... 仍是页面路由，交给第 8/9 步），
    #     API 标记同样排除，与第 6 步口径一致。
    if not has_keyword_substring(s_lower, MINIAPP_API_PATH_PATTERNS):
        # 6b-1/6b-2：首段是组件库/自建源码根。页面路由形态不走这条
        # （/src/pages/...、/common/pages/... 仍是页面路由，交回第 8/9 步）。
        if not is_miniapp_page_route(s) and (
                s_lower.startswith(MINIAPP_COMPONENT_PREFIXES_EXT) or (
                    s_lower.startswith(MINIAPP_COMPONENT_CONTEXT_PREFIXES)
                    and has_usingcomponents_context(stmt))):
            append_result(results, IDT.MINIAPP_PATH_MODULE, s, src, sid)
            return
        # 6b-3：分包里的组件引用 —— 分包整体是「页面路由形态」，必须单独放行，
        # 所以这里不再加 is_miniapp_page_route 守卫，改由「组件目录段」区分
        # （分包里的页面 /packages/x/pages/y 不含组件目录段，不受影响）。
        if is_subpackage_component_path(s_lower) and has_usingcomponents_context(stmt):
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
    # fix40b：本轮被 fix40 闸门**否决**的配对成员下标（由两个邻居函数写入，见它们的说明）。
    # 用途有两个，都不改 consume 语义：① 成员不再参与后续配对；② 函数末尾把成员身上
    # risk>=4 的行改判 cloud_cred_noise(1207, risk0)。
    vetoed_indices = set()
    truncated_contexts = {}

    # fix23：链尾「改判」要按**源常量**判（不是按写入值判）。
    #   原因：有几个处理器写进库的不是源常量本身 —— `process_prefixed_miniapp_plugin`
    #   写的是剥掉 `plugin-private://` 的 rel_path、`process_miniapp_appid` 等也各有形态；
    #   用写入值反查 `is_compiler_file_identity` 会漏掉它们（真扫 icp 实测漏 1,684 值，
    #   它们会从 1907 掉回 1903）。所以按迭代区间记账：某条常量产出的结果全部 append 完
    #   之后，把它的标记写到这些结果的序号上。收尾时机放在**下一次迭代的开头**与循环之后，
    #   这样函数体里那几十个 `continue` 一个都不用改。
    ci_flags = {}          # res 序号 -> (是否编译器身份串, 该常量的源值)
    ci_pending = None      # (起始序号, 标记, 源值)

    for i, (s, sid, src) in enumerate(constants):
        if ci_pending is not None:
            for _k in range(ci_pending[0], len(res)):
                ci_flags[_k] = (ci_pending[1], ci_pending[2])
            ci_pending = None
        if i in processed_indices:
            continue
        assert sid < len(statements) and len(s) >= 4

        raw_stmt = statements[sid]
        if sid not in truncated_contexts:
            truncated_contexts[sid] = extract_context(raw_stmt, s, 512)
        stmt = truncated_contexts[sid]

        # 便宜的短路在前：绝大多数常量不带这三个后缀，不必进正则
        ci_pending = (len(res),
                      s.lower().endswith(MINIAPP_COMPILER_NONMODULE_EXTENSIONS)
                      and is_compiler_file_identity(s, stmt),
                      s)

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
        # 编译器身份串里的模板/样式/配置文件身份（fix20 ④ / fix23）
        # =========================================================
        # 不在链首拦截，改到**链尾改判**（见函数末尾的 final_res 循环）。原因见那里的注释。
        # 判据与量化见 is_compiler_file_identity 的注释。

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
        # fix40b：`i in vetoed_indices` ⇒ 本值是本轮被闸门否决的配对成员，**不再参与配对**
        # （否则它会在后续下标和别的邻居配成改动前不存在的组合值 —— v2 源码重扫实测 2 个
        # 反向进入 1201）。它仍按自己的分类继续走，risk>=4 的落点由函数末尾的链尾改判兜住。
        is_ak, provider = is_access_key(s, stmt)
        if is_ak and i not in vetoed_indices:
            sk_val, sk_stmt, sk_idx = find_sk_in_neighbors(i, constants, statements, vetoed_indices)
            if sk_val:
                process_ak_sk_pair(s, stmt, sk_val, sk_stmt, provider, src, sid, res)
                processed_indices.add(sk_idx)
                continue

        if is_secret_key_sk(s, stmt) and i not in vetoed_indices:
            ak_val, ak_stmt, ak_provider, ak_idx = find_ak_in_neighbors(i, constants, statements, vetoed_indices)
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

        # fix35 归置：**看着像桶名**（改动前的整条判据 = looks_like_bucket_name）但证据没绑在
        # 本值位置 → 显式改判 id_noise(2505, risk0)。同 fix32 的口径：不许只摘掉 1301 就往下走
        # —— 三库回放实测这些值（v2 54 值 / 143 次、pkgref 66 值 / 66 次）在改动后
        # **不产出任何标签**（静默丢弃），而 1301 的旧标签本来就是白得的。
        if looks_like_bucket_name(s, stmt):
            append_result(res, IDT.ID_NOISE, s, src, sid)
            continue

        # email
        if is_email(s):
            process_email(s, stmt, src, sid, res)
            continue

        # fix37：形态像邮箱（改动前的出口判据 = `is_email_shape_loose`）但**整串不是邮箱**
        # —— 隐私政策/用户协议正文整段、「客户服务电子邮箱：xxx@…」「联系方式：xxx@…」、
        # domain 带 `/` 的路径片段、RFC 2606 保留域占位。显式落 pii_noise(2304, risk0)：
        # `is_email` 判 False 之后若不接这一条，值会继续往下走凭证/标识符判据 = 平移。
        # 注意这里**不抽取**邮箱生成新值：整段文本就是一个噪声值。
        if is_email_shape_loose(s):
            append_result(res, IDT.PII_NOISE, s, src, sid)
            continue

        # map key (mapKey 格式或有地图上下文)
        if is_map_key(s, stmt) or is_map_secret_key(s, stmt):
            process_map_key(s, stmt, src, sid, res)
            continue

        # analytics key
        if is_analytics_key(s, stmt):
            # fix32：命名报送 callee 的实参（每次独立出现都未绑定 + 落在显式报送白名单里）
            # 不是统计分析 Key。归置必须是**显式**的 risk0 噪音标签，不许只摘掉 1402 就往下走
            # —— normal_quarkpan 全桶实测只摘标签会有 1,179 条链接（父任务探针口径 571）
            # 平移进 cloud_cred_password risk5。
            if is_analytics_callee_argument(s, stmt):
                append_result(res, ANALYTICS_CALLEE_NOISE_SLUG, s, src, sid)
            else:
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
        # fix22：`is_identifier` 用 id_slug == IDT.ID_NOISE 回报「只因命名形态排除落选」——
        # 这批值是**已知的名字类噪音**（见 NAME_CLASS_REJECT 的注释）。它们本身不需要
        # 任何标签，但继续往下走会被凭证判据按「值自证」接手，从而把 risk 2~3 升到 risk 5
        # （fix21 ③④ 收严后三库实测 14 行 / 17 次）。所以：**只在下面的凭证判据真要把它
        # 当凭证时**改判 id_noise(2505, risk 0)；其余情形一律保持原行为 —— 真 uid/openid/
        # 订单号、真 URL/路径/密钥都走各自判据，本闸门碰不到它们（量化见报告）。
        name_class_reject = (id_slug == IDT.ID_NOISE)

        # 云服务密码（fix43：口径 = **修复前口径 ∧ 值锚窗口口径**）
        #   为什么是「与」而不是直接把判定窗口换成值锚窗口：先行探针实测（样本 A 1,027 个
        #   文件、固定种子）—— 只换窗口会让 187 对从 risk<4 升到 risk>=4，其中 162 对正是
        #   **反向进入 1203**（旧窗口没有密码语境、值锚窗口有）。那批值今天是**不在** 1203
        #   桶里的（库内样本里它们是 `(0,a.default)(o,"KEY",…)` 一族的键名与混淆串表成员，
        #   与 1203 无关），本轮的规格是「1203 反向进入必须 0」，所以值锚窗口只用来**收窄**：
        #   修复前判 1203 的值，在值锚窗口里站不住就改判 1207（risk0，显式落库不静默消失）；
        #   修复前不判 1203 的值一行不动。
        #   `is_cloud_password_before_fix43` = 修复前口径（位置守卫关断），只多一次开关置位。
        if is_cloud_password_before_fix43(s, stmt):
            # 红线值白名单：fix12 人工核定的真阳性 / fix31c 受保护材料**不因窗口收窄而改变判定**
            #   —— 语料里真有这类值坐在「±256 字符内没有密码词」的位置上（只读投影实测：1941
            #   个去重值里有 2 个命中名单，其中一个是 fix12 点名的 base64 口令），窗口收窄不该把
            #   人工核定的真阳性一起收掉（同 fix31c 材料形豁免的红线口径）。
            if (s in CCP_POSITION_REDLINE_VALUES
                    or is_cloud_password(s, _ccp_value_anchor_context(raw_stmt, s, stmt))):
                if name_class_reject:
                    append_result(res, IDT.ID_NOISE, s, src, sid)
                else:
                    process_cloud_password(s, stmt, src, sid, res)
                continue
            append_result(res, IDT.CLOUD_CRED_NOISE, s, src, sid)
            continue

        # 服务器 Cookie
        if is_server_cookie(s, stmt):
            if name_class_reject:
                append_result(res, IDT.ID_NOISE, s, src, sid)
            else:
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
            # fix22：把「已知名字类噪音」的回报传进裸关键词出口（见该函数 docstring）
            process_generic_alpha_prefixed_constant(s, stmt, src, sid, res, name_class_reject)
        elif s[0] == ".":
            process_generic_dot_prefixed_constant(s, stmt, src, sid, res)
        elif s[0] == "/":
            process_generic_slash_prefixed_constant(s, stmt, src, sid, res)
        else:
            process_generic_unknown_constant(s, stmt, src, sid, res)

    # 收尾最后一条常量的改判标记（见循环开头的说明）
    if ci_pending is not None:
        for _k in range(ci_pending[0], len(res)):
            ci_flags[_k] = (ci_pending[1], ci_pending[2])

    # 替换 sid 为截断上下文
    # fix40b：被否决配对的**成员**不得新获得 risk>=4 标签 —— 链尾改判（时机与上面 fix20④/fix23
    #   的改判一致，理由同源：不在链首拦截，避免把那几十个 `continue` 全改一遍）。
    #   为什么会落到 risk>=4：成员的分类是「按各自原本的分类走」，而 AK id（16~36 位 alnum
    #   坐在 `accessKeyId` 语境里）会被 `is_app_key`（`has_appkey_context` 命中
    #   `accesskey` 子串、`CREDENTIAL_APP_KEY_CONTEXT_WORDS` 含 `accesskey`）判成
    #   platform_app_secret(1101, risk5)；32 位材料形的 SK 侧成员也会被 `is_secret_key` 判 1101。
    #   改动前这些值被 consume 进 `AK=…, SK=…`、**没有自己的行**，所以这是**新增**的 risk5 标签
    #   —— 用户口径「新增 risk≥4 标签不可接受」，也不许把噪音挪进别的 risk>=4 桶。
    #   归置：`改判 cloud_cred_noise(1207, risk0)` 而不是静默丢弃（同 fix32/fix39/process_cloud_token
    #   的「只摘标签 / 静默消失」禁令）。判据严格限定在**本轮被否决的成员**这一条路径上，
    #   不碰任何别的常量：非成员的 AK id 仍然照旧判 1101（没扩大成「所有 AK 形态的值都不判
    #   platform_app_secret」）。
    #   key 用 (值, 语句下标) —— 分类语境由 (语句, 值) 唯一决定，所以同一 key 的实例分类必然相同，
    #   只有配对与否不同；被拒成员的那一份不落 1101，同 key 的另一份也不该落（否则该值仍会
    #   净增一个 risk5 标签）。
    vetoed_member_keys = {(constants[_j][0], constants[_j][1]) for _j in vetoed_indices
                          if 0 <= _j < len(constants)}
    final_res = []
    for _ri, (slug_id, content, src, sid) in enumerate(res):
        if sid in truncated_contexts:
            truncated_ctx = truncated_contexts[sid]
        else:
            stmt = statements[sid] if sid < len(statements) else ""
            truncated_ctx = extract_context(stmt, content, 512)
        # =========================================================
        # fix20 ④ / fix23：编译器身份串里的模板/样式/配置文件身份 —— **链尾改判**
        # =========================================================
        # 这里**不丢弃**，改判 miniapp_noise(1907, "Miniapp internal noise", risk 0)
        # —— 值本身形态完好（是小程序的文件路径），保留便于回溯文件清单，只是它不是
        # 业务常量、更不是模块引用。`.js` 身份（编译模块 id）刻意留在原处（1906）。
        #
        # ⚠️ 口径（fix23 修的就是这一条，下一轮重扫必须按这里核对）：
        #   fix20 ④ 的**测量口径**是「1906 桶里多少个值会流出去」（icp 27,148 值 / 149,072 次），
        #   而它的**实现口径**当初是分类链**最前面**的一处拦截 —— 命中即产出 1907 并 `continue`，
        #   于是它的真实后果远大于测量：真扫 icp（code 625ea27）进 1907 的带后缀值是 122,357 个
        #   / 1,182,122 次，**4.5 倍**。差额的 90,628 值 / 976,846 次根本不是「从一个桶搬到另一个桶」
        #   —— 按 2f7fd0d（fix20 ④ 之前的真扫代码）回放，它们**本来不产出任何标签（丢弃）**，
        #   是链首拦截把它们**无中生有**地写成了 risk-0 行（归因见 test-result/fix23/b2_attrib_real.out）。
        #   实测的族谱（icp 真扫语料回放，2f7fd0d 下的原去向）：
        #       miniapp_path_module(1906)         29,053 值 / 165,878 次   ← 测量到的就是这一族
        #       miniapp_plugin_url(1903)           1,716 值 /  11,362 次
        #       miniapp_page_path_sensitive(1901)    702 值 /   2,362 次
        #       other(9901)                          258 值 /  25,674 次
        #       本来无产出（丢弃）                90,628 值 / 976,846 次   ← 无中生有的那 90k
        #   改成链尾改判后：**只把本来会产出的值换标签，不再制造新行**。这就是本处的用词
        #   「改判」的字面含义，也与 writer 侧的既有事实一致（.js 身份另有一族 —— 见上）。
        #
        # 为什么改判**不限** 1906、而覆盖所有出口（1906/1903/1901/other）：
        #   fix20 ④ 当初的链首拦截对**所有**出口一视同仁（命中即 `continue`，后面判据全不跑），
        #   所以「这条 .wxml 不是模块引用而是编译产物里的文件身份」这个**判断**对 1903/1901 同样成立。
        #   若把改判收窄成「只改 1906」，真扫 icp 会有 2,421 值 / 13,745 次**退回 risk 2~3 桶**
        #   （plugin-private://…/x.wxml → miniapp_plugin_url、pages/test/test.wxml →
        #   miniapp_page_path_sensitive），那是把 risk 桶的噪音加回去，与既有红线
        #   「不许有新噪音进 risk>0 桶」冲突。所以本轮只砍「无中生有」，不动出口集合。
        #
        # 口径一致性（fix23 的关键）：改判用的窗口 `truncated_ctx` **就是** writer 存进
        #   `source_snippet` 的那个字符串（本函数末尾把 sid 换成它再交给 writer），
        #   而判据读的 `ci_flags` 来自**源常量**（见循环开头的记账说明）—— 所以
        #   「实现看到的语境」与「量化回放看到的语境」逐字相同，回放可以当成真扫的预测。
        #
        # 写回**源常量**而不是链的产出值：与同族出口一致（`process_miniapp_appid` 与
        #   fix20 ④ 原先的链首拦截写的都是源常量 `s`）。不这样做的话，凡是链上会把值变形的
        #   处理器（`process_prefixed_miniapp_plugin` 写的是剥掉 `plugin-private://` 的
        #   rel_path）都会**顺带改掉库里存的值** —— 真扫 icp 实测那会多动 1,661 行的内容，
        #   而本轮只想砍掉「无中生有」的这一件事。
        _ci = ci_flags.get(_ri)
        if _ci and _ci[0]:
            slug_id = IDT.MINIAPP_NOISE
            content = _ci[1]
        if (content, sid) in vetoed_member_keys and is_risk4plus_slug(slug_id):
            slug_id = IDT.CLOUD_CRED_NOISE
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
