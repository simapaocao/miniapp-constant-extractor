#!/usr/bin/env python3
r"""fix31：cloud_cred_password(1203) 的**三族结构噪音**窄口守卫 + 受保护位置矩阵。

背景（只读普查 normal_quarkpan：桶内 5341 链接 / 2311 值，其中 snippet 不含值的 1337 链接 /
1139 值、现行口径已不复现 1203 的 355 链接；复现 3649 链接）：
1203 桶里有两类完全不同的东西 —— 一是**真密码/真材料**（fix12 人工核定的红线值），
二是**语句里出现 password/pwd 词、值本身却是别的东西**（日志 tag / URL 查询片段 /
字段名）。本轮只收后者里**结构上确定**的三族，且一律**不改绑定口径**（不要求「必须绑在
密码键上才算真」）。

三族（判据都只看**本值**与它在语句里的位置，不看窗口里的关键词）：

  ① 日志/调试 callee 的实参（log call tag）
     本值自成字面量地坐在严格 callee 表的调用实参位上：
     `console.<任意> | __f__ | log | track | report | error`（callee 必须**整词命中**，
     见 RE_CCP_LOG_CALLEE）。库内头部成员：
     `console.log("=passWord==", t)` / `console.log("------onShow")` /
     `console.log("that._onHide1", …)`，以及 error/track/report/__f__/log 的同形写法。
     量化（normal_quarkpan 全桶链接口径）：563 链接 / 109 值，其中 83 链接现行口径已不判 1203。

  ② `+` 连接的 URL/查询片段（concat operand）
     本值所在字符串字面量是**拼接运算的一个分量**（字面量的一侧紧邻 `+`，跳过空白），
     **且**本值自身是 URL/查询片段形态（含 `/ \ : ? & =` 之一或以 `?` / `&` 开头）。
     第二个条件是本轮**刻意加严**：只靠「是 `+` 分量」会连**密码盐**一起收掉 ——
     `hexMD5(n + s.password + "2019userperm")` / `password: hash(o + "cndcarezIUAGNu5")` /
     `"cbs@bihu20250224"+r+"WC"` 这些值都是拼接分量，属材料，必须留在 1203
     （见 MATERIAL_CONCAT_CASES）。

  ③ 值形就是 URL 语法片段（name= / URL fragment）
     本值自身含 `/ \ : ? & =` 之一，或以 `?` / `&` 开头。库内头部成员：
     `passwd=` / `strshu=` / `&position=about` / `index.php?act=login&op=save_password` /
     `register1:10013` / `password|message:` / `display:black;`。

三条**保护**（任一命中 → 本值不是噪音，判据不碰它）：
  · **绑在键上**：本值某个自成出现位置的左侧紧邻键（共用 fix24/25/26 的 `_bound_value_keys`）
    —— 这一条同时守住「直键 password/pwd/passwd」（库内 259 链接 / 103 值）与
    「密码族后缀键 userPwd / updatePassword / multiShareMessagePasswordHint …」
    （95 链接 / 52 值）；
  · **键名位**：本值右侧跳过引号/空白后紧跟 `:`（值被当作**键名**用，例如三元表达式
    `this.hasSetPassword ? "yhbp0400o02j" : "yhbp0400m010"`）—— 库内 149 链接 / 74 值；
  · **密码名 callee 的实参**：callee token 含 password/pwd（`loginWithPassword("demo","V")`、
    `e.pwdSetSk("…")`）—— 库内 2 链接 / 2 值。

已知残留（**不在**本次射程，各有断言钉住）：
  · 严格表之外的日志 callee（`logger.warn` / `sentry.captureMessage` / `trackEvent` …）里的 tag
    仍判 1203 —— 证据只支持那六个 callee；
  · 不以 `+` 连接、也不含 URL 字符的纯词形 tag（`wechat1` / `AAAF0199` / `keyboard,`）；
  · `plain_unbound`（既不绑定、也不落三族）与 snippet 不含值的 1139 值：一行不动。

用法: .venv/bin/python -X utf8 unit-tests/test_fix31_ccp_family_guards.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

CCP = IDT.CLOUD_CRED_PASSWORD
CCP_NAME = "CLOUD_CRED_PASSWORD"
GUARD = "is_cloud_password_noise"       # 本轮的**唯一**入口（is_cloud_password 里调用）
_ID_TO_SLUG = {v: k for k, v in vars(IDT).items()
               if isinstance(v, int) and k.isupper() and not k.startswith("CTG_")}


def _classify_ids(v, stmt, guard_off=False):
    """跑一遍分类，返回标签 **id** 集合；guard_off=True 时把本轮新判据换成恒 False
    （= 改动前的代码路径）。

    只用**同一个进程内的开关**做前后对照，不依赖 git stash / checkout。
    """
    saved = getattr(C, GUARD, None)
    if saved is None:
        raise AssertionError("constants_classifier.%s 尚未实现（RED）" % GUARD)
    if guard_off:
        setattr(C, GUARD, lambda s, st_: False)
    try:
        return sorted({r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])})
    finally:
        setattr(C, GUARD, saved)


def _classify(v, stmt, guard_off=False):
    """同上，但返回标签**常量名**（`CLOUD_CRED_PASSWORD`）—— 用于报错信息与「少了一个标签」。"""
    return sorted(_ID_TO_SLUG.get(i, str(i)) for i in _classify_ids(v, stmt, guard_off))


# =========================================================
# ① 日志/调试 callee 的实参（真实链接号标在注释里）
# =========================================================
LOG_TAG_CASES = [
    # [131397] this.setData({passWord:t}), console.log("=passWord==", t)
    ("=passWord==",
     'this.setData({\n        passWord: t\n    }), console.log("=passWord==", t);'),
    # [131426] console.log("=cancelPass=="), this.setData({showPassWord:!1})
    ("=cancelPass==",
     'console.log("=cancelPass=="), this.setData({\n        showPassWord: !1\n    });'),
    # [21965154] console.log("that._onHide1", this.selectComponent("#ccInput1").isEmpty())
    ("that._onHide1",
     'console.log("hide1", o), console.log("that._onHide1", '
     'this.selectComponent("#ccInput1").isEmpty()), \n        this.setData({\n'
     '            showPassword: !1\n        });'),
    # [443955] console.log("------onShow")
    ("------onShow",
     'console.log("------onShow"),0==this.data.cardType&&this.getNumPwdList(),'
     '1==this.data.cardType&&this.getFingerPwdList()'),
    # [15461433] console.log("togglePassword...")
    ("togglePassword...",
     'console.log("togglePassword..."), this.setData({\n'
     '            showPassword: !this.data.showPassword\n        });'),
    # [21235826] console.log(e, "iriasriaisrhasirh111111as")
    ("iriasriaisrhasirh111111as",
     'console.log(n, "iriasriaisrhasirhas"), console.log(e, "iriasriaisrhasirh111111as"), '
     'o.navigateTo({ url: "/pages/image/yulan?&gid=".concat(e.id, "&password=")'
     '.concat(n.password) });'),
    # 严格表里的其余 callee：库内本桶只有 console.* 一族（--callee-samples 实测），
    # 这四条按表口径用**真实 tag 值 + 同形调用**构造，语句里保留 pwd 语境词。
    ("denglu-----",
     '0:return h=t.state,console.log("denglu-----",r),w=(b=h.signInData).verifyCode,'
     'x=b.mobileNumber,S=b.pwdCode,F=b.authType,D=b.imageCode,O=b.appCode;'),
    ("res-------777",
     'error("res-------777", e), this.setData({pwdErr: 1, passWord: t.passWord});'),
    ("---inputP----", 'log("---inputP----", this.p), this.checkPwd(this.p);'),
    ("focusInput---",
     'switch(__f__("focusInput---", e), this.focusType = e, e) { case 1: '
     'this.oldPwdErr = !1; break; case 2: this.newPwdErr = !1; }'),
    ("AuthStartTime----", 'track("AuthStartTime----", _), this.setData({pwdOk: !0});'),
]

# 严格表**之外**的 callee：证据不支持，保持在 1203（已知残留）
NON_STRICT_CALLEE_CASES = [
    ("denglu-----", 'logger.warn("denglu-----", this.data.passWord);'),
    ("---inputP----", 'sentry.captureMessage("---inputP----", {pwd: t.pwd});'),
    ("focusInput---", 'trackEvent("focusInput---", e.pwdInput, this.data.passWord);'),
]


# =========================================================
# ② `+` 连接的 URL/查询片段
# =========================================================
CONCAT_CASES = [
    # [1157993] url: "../login/login?phone=" + o.phone + "&password=" + o.form.passWord1 + "&toRoot=1"
    ("&toRoot=1",
     'url: "../login/login?phone=" + o.phone + "&password=" + o.form.passWord1 + "&toRoot=1"'),
    # [6764048] d = t.globalData.h5vod + "?account=" + g.supervise_password
    ("?account=", 'd = t.globalData.h5vod + "?account=" + g.supervise_password'),
    # [1488178] … + "&type=email&password=" + c（语句的另一支含 &password=）
    ("&type=email&password=",
     's=n?a.UAPI+"/login_c?user="+t.global.inputAccount+"&type=email&password="+c+"&client="'
     '+g.system+"-"+g.model+"&client_app="+p.client_app+"&client_id="+i.default.generateUUID()'
     '+"&token_life=604800":a.UAPI+"/login_c?user="+t.global.inputAccount+"&type=mobile'
     '&area_code=86&password="+c+"&client="+g.system'),
    # [12862798] r = a.globalData.baseUrl + "/huodong/sumbit.php?" + a.globalData.namePwd + "strshu=" + o
    ("strshu=",
     'r = a.globalData.baseUrl + "/huodong/sumbit.php?" + a.globalData.namePwd + "strshu=" + o '
     '+ "&id=" + i'),
    # [6329689] … + "&password=" + u + "&refer=null&mac=" + r
    ("&refer=null&mac=",
     'g = "https://portal.ikuai8-wifi.com/Action/webauth-up?type=1&action=release&username=" + '
     'o.user + "&password=" + u + "&refer=null&mac=" + r'),
]

# ② 的**材料保护**：同样是 `+` 分量，但是口令盐/材料 —— 必须留在 1203
MATERIAL_CONCAT_CASES = [
    # [9522029] "cbs@bihu20250224"+r+"WC"（RSA 加密的盐，紧邻 newPassWord）
    ("cbs@bihu20250224",
     'return"cbs@bihu20250224",r=Date.now(),"WC",o="cbs@bihu20250224"+r+"WC",'
     '(s=new c.default).setPublicKey(a.envConfig.RSA_PUBLIC_KEY),l=s.encrypt(o),'
     'p={phone:t.phone,newPassWord:t.newPassWord}'),
    # [8555937] o = hash(t.account + t.password + a + "Zq0s69O6YrvG090LgOg19z1l8RW99993")
    ("Zq0s69O6YrvG090LgOg19z1l8RW99993",
     'o = (0, r.default)(t.account + t.password + a + "Zq0s69O6YrvG090LgOg19z1l8RW99993")'),
    # [9723481] password: hash(o + "cndcarezIUAGNu5")
    ("cndcarezIUAGNu5", 'password: (0, u.default)(o + "cndcarezIUAGNu5")'),
    # [14376979] s.token = hexMD5(n + s.password + "2019userperm")
    ("2019userperm", 's.token = l.md5.hexMD5(n + s.password + "2019userperm")'),
    # [10020986] hexMD5("code" + sendcode + … + "wechat1" + server_key)
    ("wechat1",
     'sign = md5.hexMD5("code" + sendcode + "mobile" + mobile + "passwordtype2" + "umeng_token" + '
     'umeng_token + "wechat1" + app.constants_data.servser_key).toUpperCase()'),
    # [18762008] "AAAF0199" + decToHex_battnumset + … + decToHex_Password + …
    ("AAAF0199", 'stext = "AAAF0199" + decToHex_battnumset + decToHex_battarycap + '
                 'decToHex_AFE_VOLL_UP + decToHex_LOWSOC + decToHex_banlanceSTARTdiff + '
                 'decToHex_Password + decToHex_CPassword + decToHex_SOC100 + '
                 'decToHex_CAP_RB_SET + "00000000000000000000" + "000000000000"'),
]


# =========================================================
# ③ 值形就是 URL 语法片段
# =========================================================
URL_FRAGMENT_CASES = [
    # [1193517] return f("index.php?act=login&op=save_password", t, "post")
    ("index.php?act=login&op=save_password",
     'e.setUserPwd = function(t) {\n                return f('
     '"index.php?act=login&op=save_password", t, "post");\n            }'),
    # [15837118] passwd= （URL 查询片段）
    ("passwd=", 'a = o.baseUrl + "/usr/" + o.user + "/passwd=" + n.pwd'),
    # [509098] ruleValidate: ["required|message:".concat(…), "myCustom"]
    ("required|message:",
     'ruleValidate: [ "required|message:".concat(t.getLanguage("confirmPasswordNotNull")), '
     '"myCustom" ]'),
    # [509108]
    ("password|message:",
     'ruleValidate: [ "required|message:".concat(t.getLanguage("passwordNotNull")), '
     '"password|message:".concat(t.getLanguage("passwordFormatError")) ]'),
    # [10185958]/[4871218] 值形含 `:`（绑键之外的形态）
    ("basis:wifi_pwd", 'hotel_wifi_pwd: e.config["basis:wifi_pwd"].value'),
    # [14985341] 值形含 `::`，且旁边就有 password 语境
    ("User::PreviewChannel",
     'this.editExcelFile.password&&(o.password=this.editExcelFile.password),'
     '(0,d.doSocket)("User::PreviewChannel",null,{data:[o]},function(t){'
     'if(t.message.failed)s.util.showError({message:t.message.message});});'),
    # [892998] t.ReportError(e,"register1:10013") —— 错误码 tag
    ("register1:10013",
     't.ReportError(e,"register1:10013"),console.log(e),'
     'h.isPasswordErrorCode(e.ret_code)?o.password.fail(e.ret_code):o.password.hide();'),
    # [1170093] … .concat(t.password, "&&srdzflag=")
    ("&&srdzflag=",
     'e.login = function(t) {\n        return r.http.post("login?username=".concat(t.username, '
     '"&&type=").concat(t.type, "&&password=").concat(t.password, "&&srdzflag=").concat(t.srdzflag));\n    }'),
]


# =========================================================
# 受保护位置矩阵（前后逐位不变，且仍在 1203）
# =========================================================
DIRECT_KEY_CASES = [
    # [1990105] password: "user:login:password"
    ("user:login:password", 'password: "user:login:password"'),
    # [9074853] password:"vPYkA3HAAviBMiXnWQUxWdoPKPs="（base64 带 `=` 填充的真口令）
    ("vPYkA3HAAviBMiXnWQUxWdoPKPs=", 'password:"vPYkA3HAAviBMiXnWQUxWdoPKPs="'),
    # [3226566] URL 拼接里带 pwd 键，值绑在 inputPwd/adminAdd 三元支上
    ("&adminAdd=true",
     'url: "/pages/qn/qnContent/qnContent?qnId=" + this.data.qnId + (this.data.exampleId ? '
     '"&exampleId=" + this.data.exampleId : "") + (this.data.inputPwd ? "&pwd=" + '
     'this.data.inputPwd : "") + (this.data.adminAdd ? "&adminAdd=true" : "") + '
     '(this.data.qn.usesk2 ? "&usesk2=" + this.data.qn.usesk2 : "")'),
    ("hunter2", 'password = "hunter2"'),
    ("s3cr3t", 'pwd: "s3cr3t"'),
    # [9062211] 绑在密码族键名（key_prefix_PWD_CONNECT）上、值形含 `:`
    ("T:HWCB:PWD:C:", 'key_prefix_PWD_CONNECT: "T:HWCB:PWD:C:"'),
]

SUFFIX_KEY_CASES = [
    # [485629] multiShareMessagePasswordHint: "Password: "
    ("Password:", 'multiShareMessagePasswordHint: "Password: "'),
    # [5632556] password: "weappPassword:" + JSON.stringify(s)
    ("weappPassword:", 'password: "weappPassword:" + JSON.stringify(s)'),
    # [1488158] URL 拼接（值绑在 ""&password=" 上）
    ("&token_life=604800",
     's = n ? a.UAPI + "/login_c?user=" + t.global.inputAccount + "&type=email&password=" + c + '
     '"&client=" + g.system + "-" + g.model + "&client_app=" + p.client_app + "&client_id=" + '
     'i.default.generateUUID() + "&token_life=604800" : a.UAPI'),
    ("xXxxx9xXX9XxXXx9X9x=", 'userPwd: "xXxxx9xXX9XxXXx9X9x="'),
    # [5632555] 键是直键、值是 URL 片段形态（且是拼接分量）
    ("weappPhone:", 'password: "weappPhone:" + JSON.stringify(s)'),
]

PWD_CALLEE_ARG_CASES = [
    # [15235392] r.loginWithPassword("demo", "demo123456") —— 非首参
    ("demo123456", 'r.loginWithPassword("demo", "demo123456"); case "x": break;'),
    # [2325433] e.pwdSetSk("87AD020DC6812637B226057F0B934B09")
    ("87AD020DC6812637B226057F0B934B09",
     'return null == (e = r.value) || e.pwdSetSk("87AD020DC6812637B226057F0B934B09"), '
     'null == (t = r.value) ? void 0 : t.getoutputSM(0);'),
]

KEYNAME_POSITION_CASES = [
    # [7395] t = this.hasSetPassword ? "yhbp0400o02j" : "yhbp0400m010"（三元分支）
    ("yhbp0400o02j", 't = this.hasSetPassword ? "yhbp0400o02j" : "yhbp0400m010"'),
    # [2951846] password: s._.configService.isDebug ? "123456ts" : null
    ("123456ts", 'password: s._.configService.isDebug ? "123456ts" : null'),
    # [1488158] URL 拼接的 else 支：值右侧紧跟 `" : `（键名位 + URL 片段形态同时成立）
    ("&token_life=604800",
     's = n ? a.UAPI + "/login_c?user=" + t.global.inputAccount + "&type=email&password=" + c + '
     '"&client=" + g.system + "&client_id=" + i.default.generateUUID() + "&token_life=604800" '
     ': a.UAPI'),
]

# 绑在**非密码键**上的 URL 片段：同一条保护（`_bound_value_keys` 非空即不动）
BOUND_ANY_KEY_CASES = [
    # [3997997] authentication: "roomId=".concat(l, "&password=").concat(r)
    ("roomId=", 'authentication: "roomId=".concat(l, "&password=").concat(r)'),
    # [4340972] url: "module=".concat(i, "&Stime=").concat(this.data.Stime, "&password=")…
    ("module=",
     'url: "module=".concat(i, "&Stime=").concat(this.data.Stime, "&Etime=")'
     '.concat(this.data.Etime, "&phone=").concat(this.data.userMsg.GCID, "&password=")'
     '.concat(this.data.pwd)'),
]

# fix12 红线值（弱口令/材料形）与 fix26 的 BEM 边界
REDLINE_VALUES = [
    "password1", "password123", "admin123", "Admin123", "emoney5", "video123",
    "Nihao123", "1Passw0rd!xyz", "jia23xia4kaoshi5t2", "123456a",
    "o0IN8wTN50QMxX-V4siq_GSRFuts", "mnP7XKDCaWFjINWi", "signBoardPassword_S8hY",
]
REDLINE_STMTS = ['passWord: "%s"', 'pwd = "%s"', 'loginWithPassword("demo", "%s")']

BEM_CASES = [
    ("mt-input__icon", 'password: "mt-input__icon"'),
    ("field__error-message", "pwdStyle = '.field__error-message{color:#f00}'"),
    ("password-component--bank-navbar", 'pwd = "password-component--bank-navbar"'),
]
MATERIAL_SHAPE_CASES = [
    ("MyPwd__2024", 'password: "MyPwd__2024"'),
]

# 控制组：三族都不命中的普通值 / 值不在语句里 / 别的桶
CONTROL_CASES = [
    ("1Passw0rd!xyz", 'passWord: "1Passw0rd!xyz"'),
    ("x8Kq2mNp7Y", 'passWord = "x8Kq2mNp7Y", console.log("login failed");'),
    ("&token_life=604800", 'password: "other"'),          # 值不在语句里（snippet-absent 同形）
    ("/pages/index/index", 'url: "/pages/index/index"'),  # 别的桶（路径类）
]


def _assert_dropped(cases, family):
    """三族成员：修复前判 1203，修复后不判 1203，且**只**少这一个标签。"""
    for v, stmt in cases:
        before, after = _classify(v, stmt, guard_off=True), _classify(v, stmt)
        assert CCP_NAME in before, "[%s] 修复前本应判 1203: %r (%r)" % (family, v, before)
        assert CCP_NAME not in after, "[%s] 修复后仍判 1203: %r (%r)" % (family, v, after)
        lost = [n for n in before if n not in after]
        assert lost == [CCP_NAME], "[%s] 作用面不止 1203: %r -> %r" % (family, before, after)


def _assert_unchanged(cases, family):
    """受保护位置：前后**逐位相同**，且仍在 1203。"""
    for v, stmt in cases:
        before, after = _classify(v, stmt, guard_off=True), _classify(v, stmt)
        assert before == after, "[%s] 判定被改动: %r (%r -> %r)" % (family, v, before, after)
        assert CCP_NAME in after, "[%s] 应保持 1203: %r (%r)" % (family, v, after)


# =========================================================
# ① 家族断言
# =========================================================
def test_fix31_log_call_tag_dropped():
    _assert_dropped(LOG_TAG_CASES, "log_tag")


def test_fix31_log_call_tag_guard_is_the_change():
    """对照：把新判据换回恒 False，这些 tag 全都回到 1203（= 修复前的行为）。"""
    for v, stmt in LOG_TAG_CASES:
        assert CCP_NAME in _classify(v, stmt, guard_off=True), (v, stmt)


def test_fix31_non_strict_callee_is_known_residual():
    """严格表之外的 callee（logger./sentry./trackEvent）不命中 —— 已知残留，逐位不变。"""
    for v, stmt in NON_STRICT_CALLEE_CASES:
        before = _classify(v, stmt, guard_off=True)
        assert before == _classify(v, stmt), (v, stmt)
        assert CCP_NAME in before, (v, stmt)


# =========================================================
# ② 家族断言
# =========================================================
def test_fix31_concat_url_operand_dropped():
    _assert_dropped(CONCAT_CASES, "concat")


def test_fix31_concat_material_salts_kept():
    """`+` 分量里的口令盐/材料（memo 点名的 '@…' 那一类）必须留在 1203。"""
    _assert_unchanged(MATERIAL_CONCAT_CASES, "concat_material")


def test_fix31_concat_requires_url_shape():
    """第二个条件（URL 片段形态）是这一族的安全阀：把它去掉，材料盐会被吃掉。"""
    for v, stmt in MATERIAL_CONCAT_CASES:
        stmt_t = C.extract_context(stmt, v, 512) if hasattr(C, "extract_context") else stmt
        assert not C.is_cloud_password_url_fragment(v), (v, stmt_t)
        # 但它确实是 `+` 的分量 —— 所以只靠拼接判定就会误杀
        assert C.is_cloud_password_concat_operand(v, stmt_t), (v, stmt_t)


# =========================================================
# ③ 家族断言
# =========================================================
def test_fix31_url_fragment_value_dropped():
    _assert_dropped(URL_FRAGMENT_CASES, "url_fragment")


def test_fix31_url_fragment_shape_predicate():
    """值形判据本身：含 `/ \\ : ? & =` 之一或以 `?` / `&` 开头。"""
    for v in ("passwd=", "a=ice-ufrag:", "?site_token=", "&&srdzflag=", "roomId=", "display:black;",
              "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"):
        assert C.is_cloud_password_url_fragment(v), v
    for v in ("password1", "admin123", "o0IN8wTN50QMxX-V4siq_GSRFuts", "MyPwd__2024",
              "Zq0s69O6YrvG090LgOg19z1l8RW99993", "cbs@bihu20250224"):
        assert not C.is_cloud_password_url_fragment(v), v


# =========================================================
# 受保护位置矩阵
# =========================================================
def test_fix31_direct_password_key_kept():
    _assert_unchanged(DIRECT_KEY_CASES, "direct_key")


def test_fix31_suffix_password_key_kept():
    _assert_unchanged(SUFFIX_KEY_CASES, "suffix_key")


def test_fix31_password_callee_argument_kept():
    """`loginWithPassword("demo","V")` 的非首参 / `pwdSetSk("…")` 的实参。"""
    _assert_unchanged(PWD_CALLEE_ARG_CASES, "pwd_callee_arg")


def test_fix31_keyname_position_kept():
    """值被当作**键名**用（三元分支 / 右侧紧跟 `:`）时不受本判据影响。"""
    _assert_unchanged(KEYNAME_POSITION_CASES, "keyname_pos")


def test_fix31_bound_to_non_password_key_kept():
    """绑在**非密码键**（authentication / url …）上的 URL 片段同样不动 —— 保护口径是「有键即不动」。"""
    _assert_unchanged(BOUND_ANY_KEY_CASES, "bound_any_key")


def test_fix31_fix12_redline_values_kept():
    """fix12 人工核定的红线值：值形判据不命中，三种语境下判定逐位不变且仍在 1203。"""
    for v in REDLINE_VALUES:
        assert not C.is_segmented_identifier_name(v), v
        assert not C.is_single_segment_identifier_name(v), v
        for tmpl in REDLINE_STMTS:
            stmt = tmpl % v
            before = _classify(v, stmt, guard_off=True)
            after = _classify(v, stmt)
            assert before == after, (v, stmt, before, after)
            assert CCP_NAME in after, (v, stmt, after)


def test_fix31_bem_and_material_shapes_unchanged():
    """fix26 的 BEM 边界与 `MyPwd__2024` 这类材料形：本判据一律不碰。"""
    for v, stmt in BEM_CASES + MATERIAL_SHAPE_CASES:
        before = _classify(v, stmt, guard_off=True)
        assert before == _classify(v, stmt), (v, stmt, before)
    # BEM 三族本就不判 1203（fix26 的既有口径），这里只钉「本轮没让它回来」
    for v, stmt in BEM_CASES:
        assert CCP_NAME not in _classify(v, stmt), (v, stmt)
    # 材料形（数字段）在 1203 里：本轮也不许动它
    for v, stmt in MATERIAL_SHAPE_CASES:
        assert CCP_NAME in _classify(v, stmt), (v, stmt)


# =========================================================
# ⑦ fix31b（review 缺陷 1）：②/③ 的**材料形豁免** —— 值形规则不许单独吞真材料
# =========================================================
# 病根（review 复现）：② 要求「拼接分量 **且** URL 片段形态」，③ 又只要求「URL 片段形态」，
# 于是两条合起来等价于**只**要求 ③ —— 值里含 `/ \ : ? & =` 之一就删，② 的拼接条件什么都没
# 守住。真口令/口令盐带一个 URL 语法字符就整值掉出 1203：
#   · base64 的 `=` 填充：`vPYkA3HAAviBMiXnWQUxWdoPKPs=`（fix12 红线值）/ `Zq0s69…99993=`
#     （② 组点名保护的盐，仅在末尾补一个 `=` 就掉出）/ `2019userperm=` / `cndcarezIUAGNu5=`；
#   · 盐里的 `&` / `:`：`s3cr3tSalt&pepper` / `Admin@123:456` / `QwErTy&2024`。
# 这七条都**未绑定**在密码键上（绑定矩阵那一条保护够不到），值形规则一命中就删。
#
# 判据（新增 `is_cloud_password_material_shape`，只加在 ②/③ 之前、① 之后）：
#   a. base64 带 `=` 填充：正文 ≥12 位 b64 字母表 + 1~2 个尾 `=`；
#   b. 含材料字符（@ ! # * ^ $ % ~ +）且含数字或大写；
#   c. 大小写混排 + 含数字；
#   三支都要求值里没有 `/ \ ?`、也没有 `=`（a 支的尾填充除外）。URL 片段的语法字符
#   （路径 `/`、查询串 `?`/`&`+`=`、赋值 `key=value`）因此仍然一律按形态删。
# ① （严格日志 callee 实参）在豁免**之前**判定：日志 tag 照旧一律删，豁免不改它。
def _material_shape(v):
    fn = getattr(C, "is_cloud_password_material_shape", None)
    if fn is None:
        raise AssertionError(
            "constants_classifier.is_cloud_password_material_shape 尚未实现（RED）")
    return fn(v)


MATERIAL_UNBOUND_CASES = [
    # [8555937] o = hash(t.account + t.password + a + "Zq0s69O6YrvG090LgOg19z1l8RW99993")
    # —— ② 组同一现场，末尾补一个 base64 填充 `=`：
    ("Zq0s69O6YrvG090LgOg19z1l8RW99993=",
     'o = (0, r.default)(t.account + t.password + a + "Zq0s69O6YrvG090LgOg19z1l8RW99993=")'),
    # [9074853] fix12 红线值（base64 带 `=` 填充的真口令），坐在 `return` 位置（未绑定）：
    ("vPYkA3HAAviBMiXnWQUxWdoPKPs=",
     'c.login = function(t) { if (t.password) return "vPYkA3HAAviBMiXnWQUxWdoPKPs="; }'),
    # [14376979] s.token = hexMD5(n + s.password + "2019userperm") —— 同上，补 `=`：
    ("2019userperm=", 's.token = l.md5.hexMD5(n + s.password + "2019userperm=")'),
    # [9723481] password: hash(o + "cndcarezIUAGNu5") —— 同上，补 `=`：
    ("cndcarezIUAGNu5=", 'password: (0, u.default)(o + "cndcarezIUAGNu5=")'),
    # 盐里的 `&` / `:`（review 点名的三条；`&` / `:` 同时是 URL 语法字符，所以只看形态会被删）：
    ("s3cr3tSalt&pepper", 'if (t.password) o.setHash("s3cr3tSalt&pepper", e)'),
    ("Admin@123:456", 'if (t.password) o.sendCode("Admin@123:456", e)'),
    ("QwErTy&2024", 't.password && o.setToken("QwErTy&2024", r)'),
]

# 材料形正例（判据本身）：base64 填充 / 材料字符 / 大小写混排+数字
MATERIAL_SHAPE_POSITIVE = [
    "vPYkA3HAAviBMiXnWQUxWdoPKPs=",       # b64 填充（fix12 红线值）
    "Zq0s69O6YrvG090LgOg19z1l8RW99993=",  # b64 填充（② 组点名的盐）
    "2019userperm=", "cndcarezIUAGNu5=", "xXxxx9xXX9XxXXx9X9x=",
    "s3cr3tSalt&pepper", "Admin@123:456", "QwErTy&2024", "MyPwd__2024",
    "AbCd/EfGh/IjKlMnO1=",                 # 正文含 `/` 的标准 base64（只在尾 `=` 处放行）
    "67884E9%^&*67899A26C18DC28",          # 四库回放里唯一被豁免保住的真盐（2+1 条链接）
]
# 材料形反例：两族真删掉的片段与 URL 语法片段的通用样例，一个都不许被判成材料
MATERIAL_SHAPE_NEGATIVE = [
    "passwd=", "strshu=", "&password=", "&toRoot=1", "?account=", "?x=1", "/a/b",
    "roomId=", "module=", "&&srdzflag=", "&refer=null&mac=", "&type=email&password=",
    "index.php?act=login&op=save_password", "register1:10013", "User::PreviewChannel",
    "basis:wifi_pwd", "required|message:", "password|message:", "display:black;",
    "share-details&fromSource=1&status=4", "smsLogin----ticketToken",
    "a=ice-ufrag:", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "https://api.example.com/v1/login", "/pages/index/index", "wechat1",
    # 四库只读回放逼出来的四条窄口（都是有数字/大写、却明显不是材料的片段）：
    # 长拼写的**查询键**（正文是驼峰标识符名、一位数字都没有，别当成 base64 填充）
    "encodePhoneNumber=", "encodeUsercode=", "registerParam=",
    # 模板/占位片段（`^` 是材料字符，但没有数字 —— b 支因此要求「数字与字母都要有」）
    "^wifiState:",
]


def test_fix31b_unbound_material_values_kept():
    """未绑定的真材料（base64 填充 / 盐里的 `&` `:`）：判定逐位不变，且仍在 1203。"""
    _assert_unchanged(MATERIAL_UNBOUND_CASES, "unbound_material")


def test_fix31b_material_shape_predicate():
    """材料形判据本身的正反例。"""
    for v in MATERIAL_SHAPE_POSITIVE:
        assert _material_shape(v) is True, v
    for v in MATERIAL_SHAPE_NEGATIVE:
        assert _material_shape(v) is False, v


def test_fix31b_noise_families_are_never_material_shaped():
    """②/③ 两族真删掉的值（含横向迁移那两条），材料形判据一律为假。

    豁免排在 ②/③ **之前**，所以这条是「豁免不会挡在两族的删除前面」的不变量：
    两族射程里的值只要被判成材料，删除就会失效 —— 逐条钉住它们都不是材料。
    """
    for family, cases in (("concat", CONCAT_CASES), ("url_fragment", URL_FRAGMENT_CASES),
                          ("lateral", KNOWN_R5_LATERAL)):
        for v, _stmt in cases:
            assert _material_shape(v) is False, (family, v)


def test_fix31b_log_tags_still_dropped_despite_material_shape():
    """① 排在豁免之前：日志 callee 的实参照旧一律删（哪怕值形像材料）。"""
    _assert_dropped(LOG_TAG_CASES, "log_tag_after_material_exemption")


# =========================================================
# ⑧ fix31c（re-review 缺陷 2）：材料形豁免**过宽** —— ②/③ 的形态规则不许把
#    「标识符 / 模板名 / wxss 片段」当成材料
# =========================================================
# 病根：a/b/c 三支都只问「值自己像不像材料」，没有一支要求证据**超出 URL 语法字符本身**，
# 于是值形是 URL 片段/标识符片段的一大批噪音也被豁免，②/③ 再也删不掉它们。re-review 用
# 它自己那支度量（见下）复现：225 个「材料形」值里 76 个在新口径下仍判 1203，其中
#   · c 支「数字 + 大小写混排」把模板名/字段名片段全放进来 —— `:wxParse1` … `:wxParse11`（12）/
#     `:tmpl_0_plateKeyboard` … `:tmpl_14_plateKeyboard`（15）/ `:work-category-list-V2`；
#   · `#` 是材料字符，于是 wxss 内联片段 `phone{color:#4293f4}`、自定义属性
#     `--td-brand-color:#a36a26;` 也被当成材料；
#   · a 支只要求正文含数字，于是「驼峰标识符 + 末位序号 + `=`」的查询键
#     `encodePhoneNumber3=` / `registerParam1=` / `encodeUsercode3=` 被当成 base64 填充
#     （它们无数字的同形 `encodePhoneNumber=` / `registerParam=` / `encodeUsercode=` 反而删得掉，
#     同一个键两种结局）。
#
# 度量口径（与 re-review 完全一致，同进程可复现）：
#   TPL = 'function chk(){if(pwdOk()){return someFn("%s")}}'
#   把值放进这个**无绑定、有密码语境**的语句跑完整分类，结果含 1203 即「回到 1203」。
#   语料侧样本取自 test-result/fix31/replay_before_after.pre-fix31b.tsv 的 b/c 两族
#   （13237 个去重值；其中 225 个现行判据判为材料形，76 个在 TPL 下一律回到 1203）。
#   收窄后 32 个止住（下面逐条钉住），44 个残留（形状上与受保护 base64 **不可分**，见下）。
#
# 四条窄口（本文件逐条断言，正反两面都钉）：
#   ① URL 语法字符**打头**（`:` 模板名 / `?` `&` 查询串开头）→ 不是材料证据；
#   ② wxss/CSS 语法（`;` `{` `}` 声明分隔、`--` 前缀）→ 不是材料证据；
#   ③ a 支正文若是「纯字母 + 末位单数字、且无连续大写」（驼峰标识符 + 版本号，如
#      `encodePhoneNumber3`）→ 不是 base64 材料；受保护的 `cndcarezIUAGNu5=`（5 连大写）、
#      `2019userperm=`（数字不在末位）、`vPYkA3…PKPs=`（数字不在末位）、`AbCd/EfGh/…`（正文含 `/`）
#      四条都命不中 ③，照旧是材料；
#   ④ c 支「数字 + 大小写混排」只有在**≥2 处数字证据**时成立 —— 单个数字是 `key1:value1` /
#      `tab1&Home` 这类标识符片段的签名（库内同形噪音实测 `Stage1:Finished` / `subTemPassword2:` /
#      `KG5_GetTmpPasswd:`），而 `QwErTy&2024`（4 位数字）/ `s3cr3tSalt&pepper`（2 位）照旧是材料。
#
# 与 re-review 建议的**字面**写法不同之处（都是为了守住它自己点名的受保护值，实测见下）：
#   · 「a 支正文必须含 `+` / `/`」会把 5 个受保护 base64 一起删掉（`vPYkA3HAAviBMiXnWQUxWdoPKPs=` /
#     `Zq0s69O6YrvG090LgOg19z1l8RW99993=` / `cndcarezIUAGNu5=` / `xXxxx9xXX9XxXXx9X9x=` /
#     `2019userperm=` 的正文都只有数字、没有 `+` / `/`）—— 实测 protected 只剩 5/11；
#     本实现改用 ③ 精确挡掉「驼峰标识符 + 末位序号」这一类，protected 10/11（与基线同）。
#   · 「c 支要求材料字符或 `=` 填充」会把 `QwErTy&2024` / `s3cr3tSalt&pepper` 一起删掉（两者的
#     URL 语法证据只有中间的 `&`，既没有材料字符也没有 `=`）—— 本实现改用 ④「≥2 处数字证据」。
#
# 已知残留（**本判据无法再收窄**，本文件按集合钉死，多一个都不许）：
#   44 个混淆串（`z2v0D2LUzg93zgf0yq==` / `BgvYDc1ZDg9YywDLlwS=` …）在 TPL 下仍判 1203。它们与
#   受保护 base64（`vPYkA3HAAviBMiXnWQUxWdoPKPs=` 等）在**值形上不可分**：对 40 个值形特征做过穷举
#   （单特征阈值 0 解、两特征合取 0 解、两条规则并集 0 解），最相近的一对
#   （`xXxxx9xXX9XxXXx9X9x=` vs `l3bHz2vZl25VDgLJzvC=`）只在重复字符数/数字连续长度/熵这类统计量上
#   差 9 个特征 —— 任何一条阈值都会同时打到对面。再往下收只能靠**值邻接的绑定证据**
#   （池化数组 / 同形兄弟值），不属于本判据（只看本值）的射程。
FIX31C_TPL = 'function chk(){if(pwdOk()){return someFn("%s")}}'


def _classify_unbound(v):
    """re-review 的口径：值放进无绑定、有密码语境的语句，看是否仍判 1203。"""
    return _classify(v, FIX31C_TPL % v)


# 受保护的 10 条真材料（收窄前后都必须仍是 1203；`AbCd/EfGh/IjKlMnO1=` 不在内 —— 它在现行
# 口径下就不是 1203：`is_cloud_password` 里 `"/" in s` 那条规则先删它，与本判据无关，
# 它的断言留在 ⑦ 的 MATERIAL_SHAPE_POSITIVE（材料形判据本身）里）。
FIX31C_PROTECTED_MATERIAL = [
    "vPYkA3HAAviBMiXnWQUxWdoPKPs=",        # base64 填充的真口令（fix12 红线值）
    "Zq0s69O6YrvG090LgOg19z1l8RW99993=",   # ② 组点名的盐
    "2019userperm=", "cndcarezIUAGNu5=", "xXxxx9xXX9XxXXx9X9x=",
    "Admin@123:456", "QwErTy&2024", "s3cr3tSalt&pepper",
    "MyPwd__2024",                         # 不含 URL 语法字符（②/③ 本来碰不到它）
    "67884E9%^&*67899A26C18DC28",          # 四库回放里唯一被豁免保住的真盐
]
# 真语料里那两条 1203 证据（值是真实存在、真实判 1203 的）：
FIX31C_REAL_CORPUS_1203 = [
    # normal_17w 6720795：盐坐在 `password:` 键的拼接分量上
    ("67884E9%^&*67899A26C18DC28",
     'password:(0,u.md5)("67884E9%^&*67899A26C18DC28"+(0,c.sha)("67884E9%^&*67899A26C18DC28"+n))'),
    # normal_quarkpan / normal_17w：fix12 红线值坐在 `return` 位置（未绑定）
    ("vPYkA3HAAviBMiXnWQUxWdoPKPs=",
     'c.login = function(t) { if (t.password) return "vPYkA3HAAviBMiXnWQUxWdoPKPs="; }'),
]
# re-review 的 76 个「回到 1203」值里，收窄后**止住**的 32 个（= 它报的 77 减去受保护的盐，
# 再减去下面 KNOWN_RESIDUAL 的 44 个）：
FIX31C_NOISE_DROPPED = [
    # 28 个 `:` 打头的模板名（① 命中）
    ":wxParse0", ":wxParse1", ":wxParse2", ":wxParse3", ":wxParse4", ":wxParse5", ":wxParse6",
    ":wxParse7", ":wxParse8", ":wxParse9", ":wxParse10", ":wxParse11",
    ":tmpl_0_plateKeyboard", ":tmpl_1_plateKeyboard", ":tmpl_2_plateKeyboard",
    ":tmpl_3_plateKeyboard", ":tmpl_4_plateKeyboard", ":tmpl_5_plateKeyboard",
    ":tmpl_6_plateKeyboard", ":tmpl_7_plateKeyboard", ":tmpl_8_plateKeyboard",
    ":tmpl_9_plateKeyboard", ":tmpl_10_plateKeyboard", ":tmpl_11_plateKeyboard",
    ":tmpl_12_plateKeyboard", ":tmpl_13_plateKeyboard", ":tmpl_14_plateKeyboard",
    ":work-category-list-V2",
    # 4 个 wxss 内联片段（② 命中：`phone{…}` 有 `{}`，`--…;` 有 `;`）
    "phone{color:#4293f4}", "--td-brand-color:#a36a26;", "--td-primary-color-7:#4e509d;",
    "--van-dialog-zIndex:10000;--van-toast-zIndex:10000",
]
# re-review 点名 / 合成的同形噪声（本轮全部止住）：
FIX31C_NOISE_SYNTHETIC = [
    "wifiState:2G", "host:api2Prod", "tab1&Home", "&QwErTy2024",   # ④ / ①
    "encodePhoneNumber3=", "registerParam1=", "encodeUsercode3=",    # ③
    # 无数字同形（本轮之前就删得掉，钉住别被反向放开）：
    "encodePhoneNumber=", "registerParam=", "encodeUsercode=",
    "register1:10013", "User::PreviewChannel", "basis:wifi_pwd", "^wifiState:",
]
# 已知残留（44 个混淆串）：形状上与受保护 base64 不可分，见上方注释。集合钉死。
FIX31C_KNOWN_RESIDUAL = [
    "69hkd&AnkN*", "8JHqXAJUiar5W9sQGJmlpA==", "Ahr0CoIVT+AXGMzHAwWS5lIA5yQHuG==",
    "BgvYDc1ZDg9YywDLlwS=", "BwjVBc5PDgvYyxrVCL0=", "BxvZDcbYzxr1CM4Gysa=",
    "C2HVCfDPBMrVD0XPC3q=", "C2HVD0fSzxj0ihnOB3C=", "CMuGBM9UlwL0zxjHyMW=",
    "CNjHEsbVyMPLy3rZig0=", "CgeTyMfUAY13ENrJlwe=", "ChjPBwL0AxzLihzHBhu=",
    "D2vIDMLLDYbVBMXVywq=", "D2vIvMLLD1vYBa==", "DgvYywjSzsWGBM9Ulwe=",
    "Dw5NCMfUDfbLCM1PC3m=", "Dxn0igHHDMuGysbBu3K=", "Tq7tK2e5dJ5F4wjwisHruQ==",
    "WQBuc7DGQ5hrFNIbtUKT0Ftwn7VMpSHqLoviTckhf==", "bdUU5uB1hB4o7pg22ynUNg==",
    "ig9YzgvYihrVigjLigK=", "l3bHz2vZl25VDgLJzvC=", "l3bHz2vZl3DLyNzPzxC=",
    "mtGXq0m3nKzeouzcrtm=", "nxW0Fdb8mxWZFdz8mG==", "p3jLzgLYzwn0x3rVpq==",
    "pt09pt1HBgvYDcbJB24=", "pwDLDfDPBMrVD0rHDge=", "q291BNq9pt09pt09pt0=",
    "qKuXotu0n0i1mJG4oey=", "w2DYyw50ugvYBwLZC2K=", "w2nOzwnRu2LTCgXLoMu=",
    "w3vUz3jHBNrqzxjTAxm=", "y2HLy2TtAw1WBguGzxi=", "yMLUzgXVywq9pt09pt0=",
    "yxbWlMPZpt09pt09pt0=", "z2v0D2LUzg93zgf0yq==", "z2v0t3DUuhjVCgvYDhK=",
    "z2v0v2LUzg93rgf0yq==", "z2v0vg9KyxLtDhjPBMC=", "z3jHBNrqzxjTAxnZAw8=",
    "zsbPBNn0yw5Jzs4ksw4=", "zwj2Awv3l3DLyNzPzxC=", "zxHPDe1PBMLqCM9NCMe=",
]


def test_fix31c_review_noise_values_now_dropped():
    """re-review 的 32 个可分离值 + 合成同形噪声：收窄后一律不再判 1203。"""
    for v in FIX31C_NOISE_DROPPED + FIX31C_NOISE_SYNTHETIC:
        assert CCP_NAME not in _classify_unbound(v), (v, _classify_unbound(v))


def test_fix31c_protected_material_values_stay_1203():
    """10 条真材料在收窄后仍是 1203（本判据不许把材料一起收掉）。"""
    for v in FIX31C_PROTECTED_MATERIAL:
        labels = _classify_unbound(v)
        assert CCP_NAME in labels, (v, labels)
        assert _material_shape(v) is True, v


def test_fix31c_real_corpus_material_rows_stay_1203():
    """真语料里那两条 1203 证据（盐的拼接位 / fix12 红线值的 return 位）逐位不变。"""
    for v, stmt in FIX31C_REAL_CORPUS_1203:
        before = _classify(v, stmt, guard_off=True)
        assert before == _classify(v, stmt), (v, before)
        assert CCP_NAME in before, (v, before)


def test_fix31c_known_residual_is_exactly_pinned():
    """已知残留 = 44 个混淆串，一个不多一个不少（多出来说明豁免又被放宽了）。"""
    still = [v for v in FIX31C_NOISE_DROPPED + FIX31C_KNOWN_RESIDUAL if CCP_NAME in _classify_unbound(v)]
    assert set(still) == set(FIX31C_KNOWN_RESIDUAL), (
        sorted(set(still) - set(FIX31C_KNOWN_RESIDUAL)),
        sorted(set(FIX31C_KNOWN_RESIDUAL) - set(still)))


def test_fix31c_narrowing_rules_one_by_one():
    """四条窄口各自的证据（正反两面：窄口只挡它该挡的，不误伤对面的真材料）。"""
    # ① URL 语法字符打头
    for v in (":wxParse1", ":tmpl_1_plateKeyboard", ":work-category-list-V2", "&QwErTy2024",
              "?account=", "/a/b"):
        assert _material_shape(v) is False, ("①", v)
    assert _material_shape("QwErTy&2024") is True     # `&` 不在开头 → 不受 ① 影响
    assert _material_shape("Admin@123:456") is True   # `:` 不在开头
    # ② wxss/CSS 语法
    for v in ("phone{color:#4293f4}", "--td-brand-color:#a36a26;",
              "m-mobile{background:#0b1d2b!important}\n.", "-----eventH5BackPassword--",
              "---2--subRecord"):
        assert _material_shape(v) is False, ("②", v)
    assert _material_shape("67884E9%^&*67899A26C18DC28") is True   # 不含 `;{}`、不以 `--` 开头
    # ③ a 支：驼峰标识符 + 末位序号 不是 base64 材料
    for v in ("encodePhoneNumber3=", "registerParam1=", "encodeUsercode3="):
        assert _material_shape(v) is False, ("③", v)
    for v in ("cndcarezIUAGNu5=",        # 正文有 5 连大写
              "2019userperm=",           # 数字不在末位
              "vPYkA3HAAviBMiXnWQUxWdoPKPs=",   # 数字不在末位
              "xXxxx9xXX9XxXXx9X9x=", "Zq0s69O6YrvG090LgOg19z1l8RW99993=",
              "AbCd/EfGh/IjKlMnO1="):    # 正文含 `/`
        assert _material_shape(v) is True, ("③ 反例", v)
    # ④ c 支：只有 `&` / `:` 这类分隔证据时要求 ≥2 处数字
    for v in ("wifiState:2G", "host:api2Prod", "tab1&Home", "Stage1:Finished",
              "subTemPassword2:", "KG5_GetTmpPasswd:"):
        assert _material_shape(v) is False, ("④", v)
    for v in ("QwErTy&2024", "s3cr3tSalt&pepper"):
        assert _material_shape(v) is True, ("④ 反例", v)


def test_fix31c_predicate_not_deleted_and_no_label_upgrade():
    """豁免没被删掉（c 支仍在），且收窄不产生任何 risk>=4 的新标签。"""
    risk = _risk_by_name()
    assert _material_shape("QwErTy&2024") is True and _material_shape("s3cr3tSalt&pepper") is True
    for v in FIX31C_NOISE_DROPPED + FIX31C_NOISE_SYNTHETIC:
        before = _classify(v, FIX31C_TPL % v, guard_off=True)
        added = [n for n in _classify_unbound(v) if n not in before]
        bad = [n for n in added if (risk.get(n) or 0) >= 4]
        assert not bad, (v, bad)


# =========================================================
# 控制组 / 作用面
# =========================================================
def test_fix31_control_group_unchanged():
    for v, stmt in CONTROL_CASES:
        before = _classify(v, stmt, guard_off=True)
        assert before == _classify(v, stmt), (v, stmt, before)


def test_fix31_guard_only_reachable_from_cloud_password():
    """新判据只在 is_cloud_password 里被调用（别的桶不许经它改判）。"""
    import inspect
    src = inspect.getsource(C.is_cloud_password)
    assert GUARD in src, src
    for fn in (C.is_server_cookie, C.is_secret_key, C.is_payment_param, C.is_hex_token):
        assert GUARD not in inspect.getsource(fn), fn


# 已知**横向**迁移（risk 5 → risk 5，不是升级）：三族被拿走后，这两个值被**既存的**
# server_cred_cookie(1604) 判据接手 —— 与 fix12 的 KNOWN_R5_DRIFT 同型（修复前就在 risk 5）。
# 只读回放（test-result/fix31/replay_fix31.py，四个库）里这一类共 2 行：
#   normal_quarkpan 5808500 / normal_17w 7094065。
KNOWN_R5_LATERAL = [
    ("smsLogin----ticketToken",
     '3:if(-1!==v)return[3,4];return console.log("smsLogin----ticketToken",'
     'T=(0,g.getWXResAllCookiesMap)(k).ticketToken),this.setData({submitLoading:!1,'
     'submitDisabled:!1,ticketToken:T}),wx.navigateTo({url:"".concat((0,p.getPageUrl)'
     '("setPwd"),"?origin=").concat(h,"&t";'),
    ("share-details&fromSource=1&status=4",
     'e.shareNum>0||s.default.getItem("passwordId")&&(s.default.getItem("sessionid")?'
     '(e.shareNum+=1,e.navigateTo("/pages-user-center/web-view/index?fullUrl=".concat('
     '"https://truck.hgj.com/new-vehiclemobile/","share-details&fromSource=1&status=4")))'
     ':(e.updateRootStat()));'),
]


def _risk_by_name():
    """常量名 -> risk_level（constant_types.json 的 datatype_categories[].items[]，只读）。"""
    import json
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "constant_types.json")
    with open(path, encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"].upper()] = it.get("risk", cat.get("default_risk"))
    return out


def test_fix31_known_lateral_risk5_move_is_not_an_upgrade():
    """被拿走的噪音若落回**另一个** risk 5 桶，风险等级不变（修复前后都是 5）。

    这是本轮唯一一类「搬进 risk>=4」的行：真升级（修复前最高风险 <4）经四库回放为 0；
    横向迁移共 2 行，都落到既存的 server_cred_cookie(1604)。
    """
    risk = _risk_by_name()
    assert risk.get(CCP_NAME) == 5, risk.get(CCP_NAME)
    assert risk.get("SERVER_CRED_COOKIE") == 5, risk.get("SERVER_CRED_COOKIE")
    for v, stmt in KNOWN_R5_LATERAL:
        before = _classify(v, stmt, guard_off=True)
        after = _classify(v, stmt)
        assert CCP_NAME in before and CCP_NAME not in after, (v, before, after)
        assert after == ["SERVER_CRED_COOKIE"], (v, before, after)


def test_fix31_no_label_at_risk_4_or_higher_added():
    """三族被拿走时只少 1203：**不许**搬进任何 risk>=4 的桶（risk 表来自 constant_types.json）。

    落回 `other(0)` / `id_noise(0)` / `encoding_*` 这类低风险桶是预期目的地，
    由只读回放脚本按全桶统计（test-result/fix31/replay_fix31.py）。
    """
    risk = _risk_by_name()
    for cases in (LOG_TAG_CASES, CONCAT_CASES, URL_FRAGMENT_CASES):
        for v, stmt in cases:
            before = _classify(v, stmt, guard_off=True)
            after = _classify(v, stmt)
            added = [n for n in after if n not in before]
            bad = [n for n in added if (risk.get(n) or 0) >= 4]
            assert not bad, (v, bad, before, after)


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
    print("fix31 cloud_cred_password 三族结构守卫：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
