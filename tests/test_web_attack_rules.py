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


def _req(uri="/x", body="", method="GET"):
    """构造一个 http_request 事件（normalized 走真实的 normalize）。"""
    raw = f"{method} {uri} HTTP/1.1\r\nHost: shop.internal\r\n\r\n{body}"
    return HttpEvent(
        ts=__import__("datetime").datetime(2026, 11, 4, 21, 0, 0),
        ip="203.0.113.9",
        port=51234,
        method=method,
        host="shop.internal",
        uri=uri,
        body=body,
        raw=raw,
        normalized=normalize(raw),
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
]


@pytest.mark.parametrize("uri,body,method", BENIGN)
def test_benign_requests_trigger_nothing(rules, uri, body, method):
    """正常请求全规则零命中。这是这组规则能不能活下来的底线。"""
    event = _req(uri, body, method)
    assert _hits(event, rules) == [], f"误报了: {uri} {body}"


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
    """新增的 7 条都应是可导出的签名规则（阈值规则才不可导出）。"""
    new_ids = [rid for rid in by_id if rid.startswith(("http-sqli", "http-xss"))
               or rid == "http-path-traversal"]
    assert len(new_ids) == 7
    from tools.to_sigma import to_sigma
    for rid in new_ids:
        data = to_sigma(by_id[rid])
        assert data["detection"]["condition"]
        assert data["level"] in {"low", "medium", "high", "critical"}
