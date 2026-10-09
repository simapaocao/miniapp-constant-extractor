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

CLOUD_PASSWORD_PLACEHOLDERS = (
    "xxx", "***", "password", "123456", "admin", "root", "test",
    "null", "none", "empty", "undefined", "default",
)

SERVER_COOKIE_CONTEXT_WORDS = (
    "cookie", "cookies", "set-cookie", "setcookie", "set_cookie",
    "sessionid", "session_id", "jsessionid", "phpsessid", "asp.net_sessionid",
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


def has_user_id_context(stmt: str) -> bool:
    """USER_ID_KEYWORDS 的上下文判定：uid 收紧为「独立词/驼峰段」，其余关键词不变。

    uid 走 has_keyword_in_context_strict —— 裸子串会让 uuid / guid / skuId / menuId
    等一并命中 id_user_identifier；userid / openid / account_id 等长关键词仍走原函数。
    """
    return (has_keyword_in_context_strict(stmt, "uid", UID_LOOKALIKE_SUBSTRINGS)
            or has_keyword_in_context(stmt, USER_ID_KEYWORDS - {"uid"}))


def has_cloud_password_context(stmt: str) -> bool:
    """CLOUD_PASSWORD_CONTEXT_WORDS 的上下文判定：pwd 收紧为「独立词/驼峰段」，其余不变。

    pwd 走 has_keyword_in_context_strict —— 裸子串会让 has_paypwd / dmPwD /
    base64 随机载荷中的 "pwd" 命中；password / passwd / db_pwd 等仍走原函数。
    """
    return (has_keyword_in_context_strict(stmt, "pwd")
            or has_keyword_in_context(stmt, CLOUD_PASSWORD_CONTEXT_WORDS - {"pwd"}))

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
#   2) 含 -/_ 的纯词串（[A-Za-z0-9-_]）—— 见 is_iv_identifier_like 的说明
#   3) 驼峰 / 帕斯卡单词串 —— 每段是「大写 + ≥2 个小写」的真单词（见下方说明）
RE_IV_WORD_TOKEN = re.compile(r"^[-_A-Za-z0-9]+$")
RE_IV_SCREAMING = re.compile(r"^[A-Z0-9]+(?:_[A-Z0-9]+)*$")
RE_IV_CAMEL_WORDS = re.compile(r"^[a-z0-9]+(?:[A-Z][a-z]{2,}[a-z0-9]*)+$")
RE_IV_PASCAL_WORDS = re.compile(r"^[A-Z][a-z]{2,}[a-z0-9]*(?:[A-Z][a-z]{2,}[a-z0-9]*)+$")

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


def process_Regex_crypto_key(s: str, stmt: str, src: str, sid: int, res: list, raw_stmt: str = None):
    """处理通过正则匹配到的加密密钥（SM2公钥等）"""
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
    private_keywords = ("private", "priv", "secret", "secretkey", "privatekey")
    public_keywords = ("public", "pub", "publickey")
    is_private = has_keyword_substring(ctx_lower, private_keywords)
    is_public = has_keyword_substring(ctx_lower, public_keywords)

    slug = IDT.CRYPTO_PRIVATE_KEY if is_private and not is_public else IDT.CRYPTO_PUBLIC_KEY
    append_result(res, slug, s, src, sid)


# =========================================================
# URL 处理函数
# =========================================================
def process_prefixed_url(url_full: str, stmt: str, src: str, sid: int, res: list):
    """分类 URL"""
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
    """
    if not s:
        return False
    s_lower = s.lower()
    for prefix in CLOUD_REGION_PREFIX_WORDS:
        if s_lower.startswith(prefix):
            return len(s) < 30 and "/" not in s and "." not in s
    return False


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

    # 语义黑名单
    if has_keyword_substring(s_lower, BUCKET_VALUE_BLACKLIST):
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
def is_session_key(s: str) -> bool:
    """判断是否为微信/支付宝 Session Key"""
    if len(s) != 24 or not s.endswith("=="):
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
def is_hex_token(s: str, stmt: str = None) -> bool:
    """判断是否为 Hex Token"""
    if len(s) not in VALID_HEX_TOKEN_LENGTHS:
        return False
    if not is_hex_string(s):
        return False
    return has_min_unique_chars(s, 4)


def process_hex_token(s: str, stmt: str, src: str, sid: int, res: list):
    """分类 Hex Token"""
    stmt_lower = stmt.lower() if stmt else ""

    if has_keyword_substring(stmt_lower, HEX_TOKEN_CONTEXT_WORDS):
        append_result(res, IDT.SERVER_CRED_TOKEN, s, src, sid)
    elif has_keyword_substring(stmt_lower, HEX_SESSION_CONTEXT_WORDS):
        append_result(res, IDT.SERVER_CRED_SESSION_KEY, s, src, sid)
    else:
        append_result(res, IDT.SERVER_CRED_SESSION_KEY, s, src, sid)


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
    """检测是否为支付参数，返回 (是否匹配, 分类ID)"""
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

    for param_name, slug_id in PAYMENT_PARAM_NAMES.items():
        if param_name.lower() in stmt_lower:
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
        if has_user_id_context(stmt):
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

    if has_user_id_context(stmt):
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
    """检测是否为云服务 Token，返回 (是否匹配, 服务商)"""
    for prefix, provider in CLOUD_TOKEN_PREFIXES.items():
        if s.startswith(prefix) and check_length_range(s, 20, 200):
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
    cookie_name_keywords = (
        "sessionid", "jsessionid", "phpsessid", "cookie2", "usercookie",
        "localstorage", "sessionstorage", "visitkey", "globalmemory",
        "shshshfp", "referer", "msgreaded", "logedout", "removelogincache",
    )
    s_lower = s.lower()
    if s_lower in cookie_name_keywords:
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
def is_cloud_password(s: str, stmt: str) -> bool:
    """检测是否为云服务密码明文"""
    if not has_cloud_password_context(stmt):
        return False
    if not check_length_range(s, 6, 64):
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


def process_miniapp_api_params(s: str, stmt: str, src: str, sid: int, res: list):
    """分类小程序 API 路径"""
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


def has_aes_key_context(stmt: str) -> bool:
    """判断上下文是否包含 AES_KEY 含义"""
    return has_keyword_in_context(stmt, AES_KEY_CONTEXT_KEYWORDS)


def is_iv_identifier_like(s: str) -> bool:
    """判断值是否为「标识符/词」形态（CSS 类名、变量名、常量名、算法名）。

    这是 is_static_iv 在 base64/字符串两条路径上的身份护栏：真实 IV 是随机字节，
    不是词。每条判据都要求「分词」特征，随机串几乎不可能满足：

      1. 纯数字：12 位随机 base64 全为数字的概率 (10/64)^12 ≈ 1e-10
      2. SCREAMING_SNAKE / 全大写：22 位随机 base64 全在 [A-Z0-9_] 内 ≈ 1e-6
      3. 含 -/_ 且其余字符是字母数字：即 kebab / snake / BEM（含首尾、连续分隔符，
         如 _customer_latitude_cache / at-tab-bar__item / isEnterPictureInPicture-）。
         随机 base64 里 -/_ 只占 2/64 ≈ 3%，而标识符里它们是词边界，占比 ≥ 8%。
         代价：URL-safe 无 padding 的 IV（22 位）约 47% 会被这条挡掉；标准 base64
         （A-Za-z0-9+/=）与 hex 完全不受影响，带 padding 的 URL-safe（24 位）也不受
         影响（末尾的 '=' 不满足 ^[-_A-Za-z0-9]+$）。已量化，见报告。
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
    if ("-" in s or "_" in s) and RE_IV_WORD_TOKEN.match(s):
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
    # 排除路径格式
    if "/" in s:
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
    if not has_aes_key_context(stmt):
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
def has_appkey_context(stmt: str) -> bool:
    """检查上下文是否包含 appKey 相关关键词"""
    return has_keyword_substring(stmt.lower(), APP_KEY_CONTEXT_WORDS)


def has_secret_context(stmt: str) -> bool:
    """检查上下文是否包含 secret 相关关键词"""
    return has_keyword_in_context(stmt, APP_SECRET_CONTEXT_WORDS)


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
    if not has_appkey_context(stmt):
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
    return (True, IDT.PLATFORM_APP_SECRET)


def process_app_key(s: str, stmt: str, src: str, sid: int, slug_id: int, res: list):
    """分类 AppKey/ApiKey"""
    append_result(res, slug_id, s, src, sid)


def is_secret_key(s: str, stmt: str) -> tuple:
    """检测是否为 Secret/API Key，返回 (是否匹配, 分类ID)"""
    if not has_secret_context(stmt):
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

    # 3. 资源文件引用
    if any(s_lower.endswith(ext) for ext in MINIAPP_ASSET_EXTENSIONS):
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

    # 6. 排除组件引用路径 (/components/xxx/xxx 且不含 api/v1 等 API 特征)
    if s_lower.startswith("/components/") and not has_keyword_substring(s_lower, MINIAPP_API_PATH_PATTERNS):
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
            append_result(results, slug_id, s, src, sid)
            return

    # 9. 后端 API 路径特征判断
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
# 归入 other(9901)：
#   1) 与既有 __scopeId -> other 的处理一致，同一个 __scopeId 家族不会因为
#      值里多了 data-v-<hash> 就被拆进两个桶；
#   2) 框架产物不是个人信息，放 pii_noise(2304) 会污染 PII 分类的语义。
# 不丢弃：命中后仍 append_result，值本身照常入库（只是 risk=0），便于回溯。
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
        if is_framework_artifact(s):
            append_result(res, IDT.OTHER, s, src, sid)
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

        # session key
        if is_session_key(s):
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
