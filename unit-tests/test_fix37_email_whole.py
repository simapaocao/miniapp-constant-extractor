#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix37：pii_email_name(2303) 的**整串**校验。

病根
----
`is_email`（constants_classifier.py 约 L1603）只数 `@` 的个数、要求 local 非空、
domain 含点、整串以白名单后缀结尾 —— **不校验整串是不是邮箱**。于是

  · 整篇隐私政策/用户协议正文（末尾带一个邮箱）、`客户服务电子邮箱：xxx@…`、
    `联系方式：xxx@…` 这类**含中文/空格/冒号**的文本整段出口 2303（risk 3）；
    典型形态 `邮***@iwod.cn`（31 条链接）、`联***@qq.Com`；
  · domain 里带 `/` 的路径片段（`xxx@webank/wxa-webankui/component/…/upload.com`）；
  · RFC 2606/6761 保留域占位邮箱（`xxx@example.com`）。

只读普查（v2 = normal_quarkpan_v2，pkgref = unlist_package_reference_v2，
见 test-result/fix37/probe_email.py / probe_email.out）：

  · v2：2303 桶 1,269 值 / 2,798 链接 → 整串合格的 **960 值 / 2,243 链接**；
    应否定 **309 值 / 555 链接**，原因分布：含中文 188、含空白 97、保留域 11、
    含冒号 9、local 含 `*` 的掩码占位 4（保留域值合计 16 值 / 28 链接）；
  · pkgref：259 值 / 9,418 链接 → 合格 238 值 / 9,351 链接，应否定 21 值 / 67 链接
    （含空白 7、含中文 12、domain 带 `/` 2；其中 1 值 / 8 链接是保留域）。

判据（只加「整串」这条**否定**判据）
------------------------------------
  ① 整串必须是邮箱：local 只含 `[A-Za-z0-9._%+-]`，domain 由 `[A-Za-z0-9-]` 组成的
     标签以点分隔（≥1 个点），整串不含空白/中文/`/`/`:` 等；
  ② 白名单后缀（EMAIL_DOMAIN_SUFFIXES）**保留**：本轮只让出口更窄，绝不放宽；
  ③ RFC 2606/6761 保留域拒绝：`example.com` / `example.net` / `example.org`（含其子域）
     与 `.test` / `.example` / `.invalid` / `.localhost` 结尾。`test.com` 是真实域名，
     **不**按保留域处理；
  ④ 不从长文本里抽取邮箱生成新值：伪邮箱整段落 pii_noise，不产出「被抽出来的」邮箱。

归置（本轮的红线）
-----------------
  · 被否定的值**显式**落 pii_noise(2304, risk 0)：`is_email` 判 False 之后如果不接
    这一条，值会继续往下走凭证/标识符判据 = 平移；
  · 纯邮箱 100% 保留 2303（含第三方库作者邮箱，那属于另一个问题，本轮不动）；
  · 不许有值反向进入 2303（本判据只会让出口更窄，理论上不可能）。

用法: .venv/bin/python -X utf8 unit-tests/test_fix37_email_whole.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import constant_ids as IDT  # noqa: E402
import constants_classifier as C  # noqa: E402

EMAIL = IDT.PII_EMAIL_NAME
NOISE = IDT.PII_NOISE

# 关掉本轮判据 = 把出口判据还原成改动前的宽松口径
_GUARD_ATTRS = ("is_email_shape_loose",)

_HERE = os.path.dirname(os.path.abspath(__file__))


def _risks():
    with open(os.path.join(os.path.dirname(_HERE), "constant_types.json"),
              encoding="utf-8") as fh:
        tax = json.load(fh)
    out = {}
    for cat in tax.get("datatype_categories", []):
        for it in cat.get("items", []):
            out[it["slug"].lower()] = it.get("risk", cat.get("default_risk"))
    return out


RISK = _risks()


def _classify(v, stmt, guard_off=False):
    """`guard_off=True` = 改动前：整串判据不生效（等价于只有宽松口径在出口）。"""
    saved = [(n, getattr(C, n)) for n in ("is_email_strict",) if hasattr(C, n)]
    if guard_off and hasattr(C, "is_email_strict"):
        C.is_email_strict = lambda s: True
    try:
        return [r[0] for r in C.perform_constant_classifying([stmt], [(v, 0, 0)])]
    finally:
        for name, fn in reversed(saved):
            setattr(C, name, fn)


# =========================================================
# ① 伪邮箱：整串不是邮箱 → 显式落 pii_noise（合成值，形态与库内同族）
# =========================================================
# 每条 = (合成值, 语境)。语境按库里的真实形态写（`邮箱：` / 隐私政策正文 / 路径片段）。
FALSE_CASES = [
    # 隐私政策正文末尾带一个邮箱（v2 188 值含中文 + 97 值含空白的主体形态）——
    # 注意整段必须以邮箱**结尾**才会命中改动前的宽松口径（white-list 后缀是 endswith）
    ("您可以通过以下方式联系我们客户服务电子邮箱：service@example-corp.cn",
     'PRIVACY_POLICY = "您可以通过以下方式联系我们客户服务电子邮箱：service@example-corp.cn"'),
    ("客服邮箱信息 工作时间 9:00-18:00 客服邮箱 support@shop-demo.cn",
     'var tips = "客服邮箱信息 工作时间 9:00-18:00 客服邮箱 support@shop-demo.cn"'),
    # 「客户服务电子邮箱：xxx@…」形态
    ("客户服务电子邮箱：kf@demo-mall.com", '"客户服务电子邮箱：kf@demo-mall.com"'),
    # 「联系方式：xxx@…」形态
    ("联系方式：contact@demo-corp.cn", 'tips: "联系方式：contact@demo-corp.cn"'),
    # 冒号 + 空白混合
    ("联系电话: 010-00000000 邮箱: help@demo-site.com",
     'var s = "联系电话: 010-00000000 邮箱: help@demo-site.com"'),
    ("本协议适用中华人民共和国法律，如有疑问请联系 legal@demo-law.com",
     'AGREEMENT = "本协议适用中华人民共和国法律，如有疑问请联系 legal@demo-law.com"'),
    # domain 里带 `/` 的路径片段（pkgref 那一族）
    ("n@webank/wxa-webankui/component/abc/upload.com",
     'var p = "n@webank/wxa-webankui/component/abc/upload.com"'),
    # local 含 `*` 的掩码占位（v2 4 值）
    ("****@demo-mail.com", 'var masked = "****@demo-mail.com"'),
    # 保留域（RFC 2606/6761）：v2 16 值 / 28 链接
    ("zhangsan@example.com", 'customerEmail: "zhangsan@example.com"'),
    ("test@example.org", 'adminEmail = "test@example.org"'),
    ("noreply@mail.example.net", 'mailFrom: "noreply@mail.example.net"'),
    ("someone@foo.example.com", 'SUPPORT_EMAIL = "someone@foo.example.com"'),
]
# 库内应否定规模（只读普查）：values / links
DROP_SCALE = {"normal_quarkpan_v2": (309, 555), "unlist_package_reference_v2": (21, 67)}


def test_false_emails_leave_2303_and_land_risk0():
    """① 整串不是邮箱的值：不再是 2303，且显式改判 pii_noise(2304, risk 0)。"""
    assert NOISE == 2304 and RISK["pii_noise"] == 0
    assert EMAIL == 2303 and RISK["pii_email_name"] >= 3
    for v, stmt in FALSE_CASES:
        got = _classify(v, stmt)
        assert EMAIL not in got, (v, got)
        assert got == [NOISE], (v, got)


def test_demotion_destination_is_risk0_only():
    """归置红线：改判只落 risk0 的 pii_noise，不许平移进别的 risk≥3 桶。"""
    slug_of = {val: name for name, val in vars(IDT).items()
               if isinstance(val, int) and name.isupper()}
    for v, stmt in FALSE_CASES:
        got = _classify(v, stmt)
        assert got == [NOISE], (v, got)
        for label in got:
            assert RISK.get(slug_of.get(label, "").lower(), 0) == 0, (v, label)


def test_guard_is_the_change():
    """①/⑥ 关掉整串判据 = 改动前：这些值全部回到 2303。"""
    for v, stmt in FALSE_CASES:
        had = _classify(v, stmt, guard_off=True)
        assert EMAIL in had, (v, had)
        assert _classify(v, stmt) == [NOISE], (v, stmt)


def test_no_email_is_extracted_from_long_text():
    """④ 不从长文本抽取邮箱：伪邮箱**整段**落噪声，不许出现被抽出来的纯邮箱。"""
    long_text = ("本协议适用中华人民共和国法律。如您对本政策有任何疑问，请通过"
                 "客服电子邮箱 service@long-policy.com")
    got = _classify(long_text, 'PRIVACY = "%s"' % long_text)
    assert got == [NOISE], got
    assert "service@long-policy.com" not in got, got
    assert long_text not in got, got


# =========================================================
# ② 纯邮箱 100% 保留（保护集）
# =========================================================
KEEP_CASES = [
    "zhangsan@qq.com", "li.si@163.com", "wang_wu@126.com", "zhao+tag@sina.com.cn",
    "user.name@sub.domain.com.cn", "a@b.cn", "first-last@my-corp.com",
    "x.y%z@mail.qq.com", "no-reply@service.aliyun.com", "contact@test.com",
    "admin@webank.com", "dev@abc.io", "info@demo.co", "hr@corp.com",
    "third_party_author@github.io",
]


def test_pure_emails_all_kept_2303():
    """② 保护集 15 个纯邮箱（含 third-party 作者邮箱、含 test.com 真实域名）：逐条仍是 2303。"""
    assert len(KEEP_CASES) == 15, len(KEEP_CASES)
    for v in KEEP_CASES:
        got = _classify(v, 'email: "%s"' % v)
        assert got == [EMAIL], (v, got)
        assert _classify(v, 'email: "%s"' % v, guard_off=True) == got, v


def test_keep_cases_are_all_shapes_of_wild_email():
    """② 保护集覆盖库内真实形态：大写域名、`+`、`_`、`%`、连字符、多级域名。"""
    for v in ("User.Name@QQ.COM", "a+b_c%d-e@sub.mail-corp.com.cn", "U1@B2.SITE.CC"):
        assert C.is_email_shape_loose(v) is True, v
        assert C.is_email(v) is True, v
        got = _classify(v, '"%s"' % v)
        assert got == [EMAIL], (v, got)


def test_test_com_is_not_a_reserved_domain():
    """② `test.com` 是真实域名，**不**按保留域处理（本轮判据的显式边界）。"""
    for v in ("a@test.com", "user@mail.test.com"):
        assert C.is_email(v) is True, v
        assert _classify(v, 'email: "%s"' % v) == [EMAIL], v


# =========================================================
# ③ 判据本身的边界
# =========================================================
def test_predicate_boundaries():
    """③ `is_email` / `is_email_shape_loose` 的正反例。"""
    # 宽松口径（改动前的出口判据）与整串口径的差集 = 本轮改判的那批值
    loose_only = ("客户服务电子邮箱：kf@demo-mall.com", "****@demo-mail.com",
                  "x@webank/wxa/upload.com", "z@example.com")
    for v in loose_only:
        assert C.is_email_shape_loose(v) is True, v
        assert C.is_email(v) is False, v
    # 宽松口径也判不出的（`@` 多于 1 个 / 无点域名）→ 由 `is_email_shape_loose` 拦掉，
    # 不进 pii_noise（它本来就不是 2303 出口的对象，本轮不改变它的去向）
    for v in ("a@b@c.com", "not-an-email", "a@localhost", "@demo.com", "a@", ""):
        assert C.is_email_shape_loose(v) is False, v
        assert C.is_email(v) is False, v
    # 保留域（含子域）与保留 TLD
    for v in ("a@example.com", "a@EXAMPLE.ORG", "a@sub.example.net",
              "a@mail.test", "a@foo.invalid", "a@bar.localhost", "a@x.example"):
        assert C.is_email(v) is False, v
    # 纯邮箱
    for v in ("a@b.cn", "user@test.com", "a.b-c_d+e%f@sub.x-y.com.cn"):
        assert C.is_email(v) is True, v


def test_whitelist_suffix_still_required():
    """③ 白名单后缀**保留**（本轮只收窄）：不在白名单后缀的形态一律不出 2303。"""
    for v in ("a@b.xyz", "a@b.top", "a@b.site", "a@b.online", "a@b.cnx"):
        assert C.is_email_shape_loose(v) is False, v
        assert C.is_email(v) is False, v
        assert _classify(v, '"%s"' % v) == _classify(v, '"%s"' % v, guard_off=True), v


def test_email_exit_is_the_only_change():
    """③ 只有 email 出口被本轮改到：非邮箱形态的值开关无差别。"""
    for v, stmt in (("2026-04-10-1407", 'signSecretKey: "2026-04-10-1407"'),
                    ("1495550TJAxsg", 'names:["1495550TJAxsg","log"]'),
                    ("10690300000", '"10690300000"')):
        assert _classify(v, stmt) == _classify(v, stmt, guard_off=True), v


def test_corpus_scale_matches_probe():
    """⑤ 普查数字（probe_email.out）写死，防止口径漂移。"""
    assert DROP_SCALE["normal_quarkpan_v2"] == (309, 555)
    assert DROP_SCALE["unlist_package_reference_v2"] == (21, 67)


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
    print("fix37 邮箱整串判据：%d 项，通过 %d，失败 %d"
          % (len(cases), len(cases) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
