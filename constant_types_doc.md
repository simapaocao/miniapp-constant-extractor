# 常量分类体系文档

> 基于 constant_types.json v1.1，用于小程序安全敏感信息检测

---

## 风险等级 (Risk Scale)

| ID | 等级 | 说明 |
|----|------|------|
| 200 | ignore | 忽略/噪声 |
| 201 | low | 低风险 |
| 202 | medium | 中风险 |
| 203 | elevated | 需调查 |
| 204 | high | 高风险(可利用) |
| 205 | critical | 严重(立即泄露) |

---

## 处理策略 (Policy)

| ID | 策略 | 说明 |
|----|------|------|
| 300 | allow | 允许 |
| 301 | warn | 警告 |
| 302 | redact | 脱敏 |
| 303 | block | 阻断 |

---

## Token 类型 (500系列)

| ID | 类型 | 说明 | 已实现 |
|----|------|------|--------|
| 500 | jwt | JWT Token | ✅ |
| 501 | bearer | Bearer Token | ✅ |
| 502 | basic | Basic Auth Token | ✅ |
| 503 | session_key | 微信/支付宝 Session Key | ✅ |

---

## 数据分类 (大类 → 小类)

### 1. 平台凭证 platform_credential (1100系列)

> 平台API凭证，如微信/支付宝/抖音

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1101 | platform_app_secret | 5 | AppSecret/ClientSecret，可完全接管账户 | block | ✅✅ |
| 1102 | platform_session_key | 5 | 用户会话密钥，用于解密PII(手机号/生物信息)，禁止出现在前端 | block | ✅✅ |
| 1103 | platform_access_token | 5 | 后端到平台的访问令牌 | block | ✅ (JWT) |

---

### 2. 云服务凭证 cloud_credential (1200系列)

> 访问第三方云服务的密码和令牌

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1201 | cloud_cred_ak_sk_pair | 5 | AccessKey + SecretKey 密钥对 | block | ✅ |
| 1202 | cloud_cred_upload_policy_signed | 4 | 硬编码的预签名上传策略(OSS/S3) | redact | ✅ |
| 1203 | cloud_cred_password | 5 | 密码明文 | block | ✅ |
| 1204 | cloud_cred_basic_auth | 5 | Basic认证 user:pass | block | ✅ |
| 1205 | cloud_cred_token | 5 | 访问令牌 | block | ✅ |
| 1206 | cloud_cred_cookie | 4 | Cookie字符串 | redact | ✅ |
| 1207 | cloud_cred_noise | 0 | 凭证类噪声 | allow | ❌ |

---

### 3. 云存储 cloud_storage (1300系列)

> 第三方服务器上的存储位置

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1301 | cloud_bucket_name | 2 | 云存储桶名称，可暴露基础设施 | warn | ✅ |
| 1302 | cloud_region | 1 | 云区域(ap-shanghai等) | allow | ✅ |
| 1303 | cloud_storage_path | 2 | 云存储对象路径 | warn | ✅✅ |
| 1304 | cloud_upload_config | 3 | 云SDK上传配置对象 | warn | ❌ |
| 1305 | cloud_noise | 0 | 云存储噪声 | allow | ❌ |

---

### 4. SaaS凭证 saas_credential (1400系列)

> 第三方SaaS服务的API Key(地图、分析、推送)

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1401 | saas_map_key | 2 | 地图SDK Key(腾讯地图/高德/Google) | warn | ✅✅ |
| 1402 | saas_analytics_key | 1 | 分析服务ID(Mixpanel/Sentry/Bugly) | allow | ✅ |

---

### 5. Webhook URL (1500系列)

> 第三方集成的Webhook地址

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1501 | webhook_url | 5 | Webhook URL | block | ✅✅ |

---

### 6. 服务器凭证 server_credential (1600系列)

> 访问后端服务器的凭证

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1601 | server_cred_password | 5 | 用户名密码对 | block | ✅ (URL中) |
| 1602 | server_cred_token | 5 | 服务器访问令牌 | block | ✅ (Bearer) |
| 1603 | server_cred_session_key | 5 | 会话密钥 | block | ✅ (32位hex) |
| 1604 | server_cred_cookie | 5 | Cookie | block | ✅ |
| 1605 | server_cred_noise | 0 | 凭证类噪声 | allow | ❌ |

---

### 7. 服务器URL server_url (1700系列)

> 后端/服务器URL和端点

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1701 | server_url_with_credentials | 5 | 带凭证的URL | block | ✅✅ |
| 1702 | server_url_auth | 4 | 认证/登录端点 | redact | ✅✅ |
| 1703 | server_url_payment | 4 | 支付端点 | redact | ✅✅ |
| 1704 | server_url_internal | 3 | 内部环境URL | warn | ✅✅ |
| 1705 | server_url_api_plain | 1 | 普通API URL | allow | ✅✅ |
| 1706 | server_url_static | 1 | 静态资源URL | allow | ✅✅ |
| 1707 | server_url_noise | 0 | URL噪声 | allow | ❌ |

---

### 8. 后端IP backend_ip (1800系列)

> 可能暴露基础设施的IP地址

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1801 | backend_ip_public | 3 | 公网IP | warn | ✅✅ |
| 1802 | backend_ip_private | 2 | 内网IP | warn | ✅✅ |
| 1803 | backend_ip_noise | 0 | IP噪声 | allow | ✅✅ |

---

### 9. 小程序内部 miniapp_internal (1900系列)

> 小程序内部结构(页面、插件、场景参数)

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 1901 | miniapp_page_path_sensitive | 3 | 敏感页面路由(admin/test/debug/config/internal) | warn | ✅✅ |
| 1902 | miniapp_page_path | 1 | 标准页面路由 | allow | ✅✅ |
| 1903 | miniapp_plugin_url | 2 | 小程序插件URL(plugin://等) | warn | ✅✅ |
| 1904 | miniapp_scene_param | 2 | 路径中的场景参数 | warn | ✅✅ |
| 1905 | miniapp_path_asset | 1 | 资源路径 | allow | ✅✅ |
| 1906 | miniapp_path_module | 1 | 模块require/import路径 | allow | ✅✅ |
| 1907 | miniapp_noise | 0 | 小程序内部噪声 | allow | ❌ |

---

### 10. 小程序API miniapp_api (2000系列)

> 访问后端的小程序代码路径

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 2001 | miniapp_api_params | 1 | 带参数的API路径 | warn | ✅✅ |

---

### 11. 加密配置 crypto_config (2100系列)

> 访问云和后端服务器的加密配置

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 2101 | crypto_algorithm_name | 1 | 加密算法名(MD5/SHA1/AES/RSA等) | allow | ✅ |
| 2102 | crypto_private_key | 5 | 私钥 PEM/PKCS | block | ✅✅ |
| 2103 | crypto_public_key | 2 | 公钥明文 | warn | ✅✅ |
| 2104 | crypto_static_iv | 2 | 硬编码初始化向量(IV)，降低加密熵 | warn | ✅ |
| 2105 | crypto_weak_algorithm | 3 | 敏感操作使用MD5/SHA1 | warn | ✅ |
| 2106 | crypto_noise | 0 | 加密噪声 | allow | ❌ |

---

### 12. 数据编码 data_encoding (2200系列)

> 数据编码方案

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 2201 | encoding_base64 | 0 | Base64编码 | allow | ✅ ✅ (data:) |
| 2202 | encoding_url | 0 | URL编码 | allow | ✅(实现http前缀的) |
| 2203 | encoding_others | 0 | 其他编码 | allow | ❌ |

---

### 13. 个人信息 pii (2300系列)

> 个人隐私信息

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 2301 | pii_sfzid_name | 5 | 身份证号+姓名 | block | ✅ |
| 2302 | pii_phone_name | 4 | 手机号+姓名 | redact | ✅ |
| 2303 | pii_email_name | 3 | 邮箱+姓名 | redact | ✅ |
| 2304 | pii_noise | 0 | PII噪声 | allow | ✅ |

---

### 14. 支付 payment (2400系列)

> 支付操作相关信息

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 2401 | payment_request_params | 3 | requestPayment参数(timeStamp/nonceStr/package/paySign/signType) | warn | ✅ |
| 2402 | payment_nonce | 3 | 支付nonceStr | redact | ✅ |
| 2403 | payment_package | 3 | 支付package字符串(prepay_id=...) | redact | ✅ |
| 2404 | payment_sign_type | 1 | 签名类型(MD5/HMAC-SHA256等) | allow | ✅ |
| 2405 | payment_pay_sign | 4 | paySign值/签名 | redact | ✅ |
| 2406 | payment_secret | 5 | 支付密钥(商户密钥/平台密钥/签名密钥) | block | ✅ |
| 2407 | payment_noise | 0 | 支付噪声 | allow | ❌ |

---

### 15. 标识符 identifier (2500系列)

> 与隐私追踪相关的标识符

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 2501 | id_device_identifier | 3 | 设备标识(IDFA/IMEI/AndroidId/MAC/oaid) | redact | ✅ |
| 2502 | id_ad_identifier | 3 | 广告标识/广告追踪ID | redact | ✅ |
| 2503 | id_user_identifier | 3 | 用户标识(uid/userId/memberId/openid/unionid) | redact | ✅ |
| 2504 | id_order_identifier | 2 | 订单/交易ID | warn | ✅ |
| 2505 | id_noise | 0 | 标识符噪声 | allow | ❌ |

---

### 16. 其他 others (9900系列)

> 未分类但可能敏感的数据

| ID | Slug | 风险 | 说明 | 策略 | 已实现 |
|----|------|------|------|------|--------|
| 9901 | other | 0 | 未知 | allow | ❌ |

---

## 实现统计

| 分类 | 总数 | 已实现 | 完成率 |
|------|------|--------|--------|
| Token类型 | 4 | 3 | 75% |
| 平台凭证 | 3 | 1 | 33% |
| 云服务凭证 | 7 | 1 | 14% |
| 云存储 | 5 | 2 | 40% |
| SaaS凭证 | 2 | 0 | 0% |
| Webhook URL | 1 | 1 | 100% |
| 服务器凭证 | 5 | 3 | 60% |
| 服务器URL | 7 | 6 | 86% |
| 后端IP | 3 | 3 | 100% |
| 小程序内部 | 7 | 4 | 57% |
| 小程序API | 1 | 0 | 0% |
| 加密配置 | 6 | 2 | 33% |
| 数据编码 | 3 | 1 | 33% |
| 个人信息 | 4 | 4 | 100% |
| 支付 | 7 | 0 | 0% |
| 标识符 | 5 | 0 | 0% |
| 其他 | 1 | 0 | 0% |
| **总计** | **71** | **31** | **44%** |

---

## 属性定义

| 属性 | 类型 | 说明 |
|------|------|------|
| provider | string | 提供商(wechat/tencent/aliyun/aws/stripe等) |
| sensitivity | integer | 敏感度 1-4 (1=低, 4=极敏感) |
| action | string | 策略动作(allow/warn/redact/block/rotate_required) |
| scope | string | 出现位置(frontend/backend/any) |
| note | string | 人工备注 |



问题1:
支付宝小程序支付宝小程序 AppId 特征
| 特征 | 说明 | |------|------| | 长度 | 16位纯数字 | | 前缀 | 以 20 开头（年份标识，如 2021、2020） | | 格式 | 20XXXXXXXXXXXXXX |

示例
2021002129666174 ✅
2020001234567890 ✅
2019001122334455 ✅



appid,protocolId    

​        protocolId: "XY97218524089748299776",
​        jhmAppId: "e58d9a5da1b8a07afd79f7e3d42fa389",

wx886b6a5d3603ae7d
