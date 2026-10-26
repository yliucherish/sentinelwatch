"""威胁情报（IOC）匹配测试：真阳性 + 真阴性对称设计。

覆盖：
1. 类型推断（IP / CIDR / 域名 / 哈希 / URL，以及容易误判的组合）
2. 加载层（CSV 表头与 # 注释、空行、非法类型）
3. 匹配层（五类各一条真阳性）
4. 误报层（良性日志、时间格式、相似域名、CIDR 边界）——情报匹配最怕误报
5. 告警转换（Alert 字段正确，能被现有 storage 直接入库）
"""
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from intel import IOCSet, match_events
from intel.ioc import (
    KIND_CIDR,
    KIND_DOMAIN,
    KIND_HASH,
    KIND_IP,
    KIND_URL,
    infer_kind,
)
from models import AuthEvent
from storage import Storage

SAMPLE_INTEL = Path(__file__).parent / "sample_intel.csv"
BASE_TS = datetime(2026, 10, 27, 3, 0, 0)


def _event(raw: str, ip: str | None = None) -> AuthEvent:
    return AuthEvent(ts=BASE_TS, event_type="failed_password",
                     username="root", ip=ip, raw=raw)


# ---------------- 1. 类型推断 ----------------
@pytest.mark.parametrize("value,expected", [
    ("45.9.148.37", KIND_IP),
    ("2001:db8::1", KIND_IP),
    ("203.0.113.0/24", KIND_CIDR),
    ("evil-c2.com", KIND_DOMAIN),
    ("d41d8cd98f00b204e9800998ecf8427e", KIND_HASH),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", KIND_HASH),
    ("http://c2.example/gate.php", KIND_URL),
])
def test_infer_kind(value, expected):
    assert infer_kind(value) == expected


# ---------------- 2. 加载层 ----------------
def test_load_csv_skips_header_and_comments(tmp_path):
    p = tmp_path / "ioc.csv"
    p.write_text(
        "value,kind,source,note\n"
        "# 这是一行注释\n"
        "45.9.148.37,ip,abuse.ch,Emotet C2\n"
        "\n"
        "evil-c2.com,domain,自建,钓鱼\n",
        encoding="utf-8",
    )
    s = IOCSet()
    assert s.load_file(p) == 2
    assert len(s) == 2


def test_load_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        IOCSet().load_file(tmp_path / "nope.csv")


def test_invalid_kind_raises():
    s = IOCSet()
    with pytest.raises(ValueError):
        s.add("1.2.3.4", kind="not-a-kind")


# ---------------- 3. 匹配层（真阳性）----------------
@pytest.fixture()
def sample_set() -> IOCSet:
    s = IOCSet()
    s.load_file(SAMPLE_INTEL)
    return s


def test_match_ip(sample_set):
    hits = sample_set.match("sshd: Failed password for root from 45.9.148.37 port 22")
    assert len(hits) == 1
    assert hits[0][0].value == "45.9.148.37"
    assert hits[0][0].kind == KIND_IP


def test_match_cidr(sample_set):
    hits = sample_set.match("health probe from 203.0.113.77 ok")
    assert len(hits) == 1
    assert hits[0][0].kind == KIND_CIDR


def test_match_domain_including_subdomain(sample_set):
    for line in ("dns query c2.malicious-domain.test",
                 "dns query a.b.c2.malicious-domain.test"):
        hits = sample_set.match(line)
        assert len(hits) == 1, line
        assert hits[0][0].kind == KIND_DOMAIN


def test_match_hash(sample_set):
    hits = sample_set.match(
        "file uploaded sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert len(hits) == 1
    assert hits[0][0].kind == KIND_HASH


def test_match_url(sample_set):
    hits = sample_set.match("GET http://c2.example/gate.php?id=1 HTTP/1.1")
    assert len(hits) == 1
    assert hits[0][0].kind == KIND_URL


# ---------------- 4. 误报层（真阴性）----------------
def test_no_false_positive_on_benign_logs(sample_set):
    benign = [
        "2026-10-27 03:00:00 INFO user login from 192.168.1.10 ua=Mozilla/5.0",
        "GET /api/orders?page=2 HTTP/1.1 Host: shop.example.com",
        "error: connection refused 127.0.0.1:9000",
        "upstream latency 12:34:56 ms",          # 时间格式不能被当成 IPv6
        "dns query notc2.malicious-domain.test",  # 相似域名不算命中
        "ip 203.0.114.1 outside the blocklist",   # CIDR 边界外
    ]
    for line in benign:
        assert sample_set.match(line) == [], line


def test_empty_set_matches_nothing():
    assert IOCSet().match("45.9.148.37 evil-c2.com") == []


# ---------------- 5. 告警转换 ----------------
def test_match_events_builds_alerts(sample_set):
    events = [
        _event("Failed password for root from 45.9.148.37 port 22", ip="45.9.148.37"),
        _event("normal traffic from 198.51.100.9", ip="198.51.100.9"),
    ]
    alerts = match_events(events, sample_set)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "IOC-IP"
    assert a.severity == "high"
    assert "45.9.148.37" in a.title
    assert a.source_ip == "45.9.148.37"
    assert a.event_count == 1
    assert a.window_start == BASE_TS


def test_alerts_are_storable(tmp_path, sample_set):
    """IOC 告警必须能被现有 storage 直接入库（复用告警链路的关键验证）。"""
    events = [_event("curl http://c2.example/gate.php", ip="45.9.148.37")]
    alerts = match_events(events, sample_set)

    st = Storage(tmp_path / "t.db")
    try:
        st.insert_events(events)
        assert st.insert_alerts(alerts) == len(alerts)
        rows = st.list_alerts()
        assert any(r["rule_id"].startswith("IOC-") for r in rows)
    finally:
        st.close()


# ---------------- 6. 聚合（防告警风暴）----------------
def test_match_events_aggregates_same_ioc(sample_set):
    """同一 IOC 命中多次只产一条告警——否则一次爆破就是几十条重复告警。"""
    events = [
        AuthEvent(ts=BASE_TS + timedelta(seconds=i), event_type="failed_password",
                  username="root", ip="45.9.148.37",
                  raw=f"Failed password for root from 45.9.148.37 attempt {i}")
        for i in range(5)
    ]
    alerts = match_events(events, sample_set)
    assert len(alerts) == 1, "同一 IOC 应聚合为一条"
    a = alerts[0]
    assert a.event_count == 5
    assert a.window_start == BASE_TS
    assert a.window_end == BASE_TS + timedelta(seconds=4)
    assert "命中次数=5" in a.detail


def test_match_events_distinct_iocs_not_merged(sample_set):
    """不同 IOC 不能被合并（聚合 key 必须是 kind:value）。"""
    events = [
        _event("from 45.9.148.37", ip="45.9.148.37"),
        _event("dns query c2.malicious-domain.test", ip=None),
    ]
    alerts = match_events(events, sample_set)
    assert len(alerts) == 2
    assert {a.rule_id for a in alerts} == {"IOC-IP", "IOC-DOMAIN"}
