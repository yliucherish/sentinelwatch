"""引擎测试：真阳性 + 真阴性对称设计（与 VulnHunter 的测试哲学一致）。

覆盖四层：
1. 解析层：样本日志的事件计数、无法识别的行静默跳过
2. 规则层：YAML 加载与字段校验
3. 检测层：阈值边界、窗口边界（滑动窗口的时间敏感性）
4. 存储层：事件与告警的入库/查询闭环
"""
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from collectors.auth_log import parse_file, parse_line
from engine.detector import Rule, load_rules, run_rules
from models import AuthEvent
from storage import Storage

SAMPLE = Path(__file__).parent / "sample_auth.log"
BASE_TS = datetime(2026, 10, 22, 9, 0, 0)


def _failed(ip: str, offset: float, user: str = "root") -> AuthEvent:
    return AuthEvent(ts=BASE_TS + timedelta(seconds=offset),
                     event_type="failed_password", username=user, ip=ip)


# ---------- 1. 解析层 ----------

def test_parse_sample_log():
    events = parse_file(SAMPLE)
    counts: dict[str, int] = {}
    for e in events:
        counts[e.event_type] = counts.get(e.event_type, 0) + 1
    assert counts["failed_password"] == 13
    assert counts["accepted_password"] == 3
    assert counts["invalid_user"] == 5
    assert counts["sudo"] == 1
    # 解析出的时间戳年份补齐为当前年
    assert events[0].ts.year == datetime.now().year


def test_unparsed_lines_ignored():
    # cron/内核等无关行必须静默跳过，不能让解析器崩掉
    assert parse_line("Oct 22 13:00:00 web01 CRON[2040]: (root) CMD (cd /)") is None
    assert parse_line("") is None
    assert parse_line("完全不是日志的一行") is None


# ---------- 2. 规则层 ----------

def test_rule_loading():
    rules = load_rules(Path(__file__).parent.parent / "rules" / "brute_force.yaml")
    assert len(rules) == 2
    brute = next(r for r in rules if r.id == "ssh-brute-force")
    assert brute.event_types == ("failed_password",)
    assert brute.group_by == ("ip",)
    assert brute.window_seconds == 300
    assert brute.threshold == 5
    assert brute.severity == "high"


def test_rule_missing_field_rejected():
    from engine.detector import _build_rule
    with pytest.raises(ValueError):
        _build_rule({"id": "x", "name": "缺字段的规则"})


# ---------- 3. 检测层（真阳性/真阴性对称） ----------

_RULE = Rule(id="t", name="测试规则", description="", severity="high",
             event_types=("failed_password",), group_by=("ip",),
             window_seconds=300, threshold=5, suppress_seconds=600)


def test_threshold_boundary():
    # 恰好达到阈值 → 告警（>= 语义）
    events = [_failed("1.2.3.4", i * 10) for i in range(5)]
    alerts = run_rules(events, [_RULE])
    assert len(alerts) == 1
    assert alerts[0].source_ip == "1.2.3.4"
    assert alerts[0].event_count == 5

    # 差一个 → 不告警
    events = [_failed("1.2.3.4", i * 10) for i in range(4)]
    assert run_rules(events, [_RULE]) == []


def test_window_boundary():
    # 5 次失败跨度 304 秒（> 300s 窗口）：最早的事件被滑出窗外，
    # 任何时刻窗内都不足 5 次 → 不告警
    events = [_failed("1.2.3.4", i * 76) for i in range(5)]   # 0,76,152,228,304
    assert run_rules(events, [_RULE]) == []
    # 跨度 296 秒（<= 300s 窗口，闭区间语义）→ 全部在窗内 → 告警
    events = [_failed("1.2.3.4", i * 74) for i in range(5)]   # 0,74,148,222,296
    alerts = run_rules(events, [_RULE])
    assert len(alerts) == 1


def test_slow_low_frequency_not_detected():
    # 长期低频尝试（每 10 分钟 1 次，共 6 次）：总量统计会误报，滑动窗口不会
    events = [_failed("5.6.7.8", i * 600) for i in range(6)]
    assert run_rules(events, [_RULE]) == []


def test_sample_log_end_to_end():
    events = parse_file(SAMPLE)
    rules = load_rules(Path(__file__).parent.parent / "rules" / "brute_force.yaml")
    alerts = run_rules(events, rules)
    # 两个真阳性：暴力破解突发 + 用户名枚举突发
    assert {a.source_ip for a in alerts} == {"203.0.113.9", "192.0.2.66"}
    # 慢速尝试 IP 不告警（真阴性）
    assert all(a.source_ip != "198.51.100.7" for a in alerts)
    brute = next(a for a in alerts if a.rule_id == "ssh-brute-force")
    assert brute.event_count == 5
    assert "root" in brute.detail
    # 一轮突发只告警一次（静默生效，非告警风暴）
    assert sum(1 for a in alerts if a.source_ip == "203.0.113.9") == 1


# ---------- 4. 存储层 ----------

def test_storage_roundtrip(tmp_path):
    db = tmp_path / "t.db"
    store = Storage(db)
    try:
        store.insert_events([_failed("1.2.3.4", 0), _failed("1.2.3.4", 10)])
        alerts = run_rules([_failed("1.2.3.4", i * 10) for i in range(5)], [_RULE])
        store.insert_alerts(alerts)
        assert store.event_stats()["failed_password"] == 2
        rows = store.list_alerts()
        assert len(rows) == 1
        assert rows[0]["source_ip"] == "1.2.3.4"
        assert rows[0]["severity"] == "high"
    finally:
        store.close()
