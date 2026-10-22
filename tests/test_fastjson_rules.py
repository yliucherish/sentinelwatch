"""v1.0 组件测试：Fastjson 反序列化检测规则（CNVD-2022-40233 / CVE-2022-25845）。

样本 tests/sample_fastjson.log 的 6 条攻击行全部来自
cve-research/CNVD-2022-40233-fastjson/ 七组复现实验（A/B/C/D/D2/E/F）的真实捕获，
3 条正常业务行是构造的测试陪衬——用于验证"不该告警时不告警"。

覆盖：
1. 规则引擎签名匹配：raw_contains（AND）/ raw_contains_any（OR）的语义
2. 六条规则的端到端检出（含各条对应的绕过手法）
3. 静默语义：正常业务行不产生告警
4. 检出严重级别分布与来源 IP 归因
5. CLI：import --format app 全链路
"""
from pathlib import Path

import pytest

from cli import main
from collectors.app_log import parse_file, parse_line
from engine.detector import _matches, load_rules, run_rules

_ROOT = Path(__file__).parent.parent
_RULES = _ROOT / "rules" / "fastjson.yaml"
_SAMPLE = Path(__file__).parent / "sample_fastjson.log"

# 六条规则的预期严重级别（与 fastjson.yaml 保持一致）
EXPECTED_SEVERITY = {
    "fastjson-jdbcrowset-payload": "critical",
    "fastjson-cache-bypass": "critical",
    "fastjson-expectclass-bypass": "critical",
    "fastjson-jndi-url-in-input": "critical",
    "fastjson-jndi-trigger-trace": "high",
    "fastjson-module-blocked": "medium",
}


@pytest.fixture()
def rules():
    return load_rules(_RULES)


@pytest.fixture()
def events():
    return parse_file(_SAMPLE)


# ================= 签名匹配语义 =================

def test_match_and_semantics():
    """raw_contains 是 AND：所有子串都要出现。"""
    ev = parse_line('2026-10-23 04:26:52 [HTTP-Dispatcher] INFO App - '
                    'input={"@type":"com.sun.rowset.JdbcRowSetImpl"}')
    assert _matches(ev, {"raw_contains": ["@type", "com.sun.rowset.JdbcRowSetImpl"]})
    # 只有一半特征 → 不匹配（避免 "@type" 单凭一个词就告警）
    assert not _matches(ev, {"raw_contains": ["@type", "java.lang.Class"]})


def test_match_or_semantics():
    """raw_contains_any 是 OR：任一子串出现即匹配（ldap:// 或 rmi:// 都算）。"""
    ev_ldap = parse_line('2026-10-23 04:26:52 INFO App - dataSourceName=ldap://10.0.0.9/x')
    ev_rmi = parse_line('2026-10-23 04:26:52 INFO App - dataSourceName=rmi://10.0.0.9:1099/x')
    match = {"raw_contains_any": ["ldap://", "rmi://"]}
    assert _matches(ev_ldap, match)
    assert _matches(ev_rmi, match)
    # 都不是 → 不匹配
    ev_ok = parse_line('2026-10-23 04:26:52 INFO App - dataSourceName=jdbc:mysql://db/app')
    assert not _matches(ev_ok, match)


# ================= 规则加载 =================

def test_rules_loaded(rules):
    assert {r.id for r in rules} == set(EXPECTED_SEVERITY)
    for r in rules:
        assert r.severity == EXPECTED_SEVERITY[r.id]
        assert r.match is not None, f"{r.id} 必须带签名条件（否则会误伤正常 JSON）"


# ================= 端到端检出 =================

def test_all_six_rules_fire(events, rules):
    """样本里的六类痕迹各自命中对应规则。"""
    alerts = run_rules(events, rules)
    fired = {a.rule_id for a in alerts}
    assert fired == set(EXPECTED_SEVERITY), f"未全部命中: {set(EXPECTED_SEVERITY) - fired}"


def test_severity_distribution(events, rules):
    """4 critical + 1 high + 1 medium——与规则定义一致。"""
    alerts = run_rules(events, rules)
    from collections import Counter
    dist = Counter(a.severity for a in alerts)
    assert dist["critical"] == 4
    assert dist["high"] == 1
    assert dist["medium"] == 1


def _fire(raw_line: str, rules) -> set:
    """用单独一行跑规则，返回命中的规则 ID 集合（便于精确断言每条规则）。"""
    ev = parse_line(raw_line)
    return {a.rule_id for a in run_rules([ev], rules)}


def test_each_bypass_technique_detected(rules):
    """三种绕过手法分别被对应规则命中（不靠同一条规则兜住所有情况）。

    逐行断言：每种载荷只跑它自己那一行，确认命中的是"那一条"规则，
    而不是被别的规则顺带命中——这样规则之间的边界才是清楚的。
    """
    # 主链：@type 指向 JdbcRowSetImpl
    assert "fastjson-jdbcrowset-payload" in _fire(
        '2026-10-23 04:26:52 [HTTP-Dispatcher] INFO App - input={"@type":'
        '"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1389/x",'
        '"autoCommit":true}', rules)

    # 缓存绕过（1.2.25–1.2.47，autoType 默认关闭也能打）
    assert "fastjson-cache-bypass" in _fire(
        '2026-10-23 04:27:56 [HTTP-Dispatcher] INFO App - input={"a":{"@type":'
        '"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}}', rules)

    # expectClass 绕过（1.2.48–1.2.68）
    assert "fastjson-expectclass-bypass" in _fire(
        '2026-10-23 04:31:42 [HTTP-Dispatcher] INFO App - input={"@type":'
        '"java.lang.AutoCloseable","@type":"Probe","dataSourceName":"ldap://127.0.0.1:1389/x"}',
        rules)


def test_trigger_trace_without_rce(rules):
    """set property error, autoCommit 在"未 RCE"时同样留痕——检测不依赖利用成功。

    这是本规则最有价值的一点：JVM 用 trustURLCodebase=false 挡下攻击后，
    RCE 没发生，但 setter 已经触发过 JNDI 查询，痕迹仍在。
    """
    fired = _fire('2026-10-23 04:26:52 [HTTP-Dispatcher] INFO App - '
                  'parse failed: com.alibaba.fastjson.JSONException: '
                  'set property error, autoCommit', rules)
    assert "fastjson-jndi-trigger-trace" in fired


# ================= 静默语义（误报控制） =================

def test_normal_business_lines_stay_silent(events, rules):
    """3 条正常业务 JSON 不得触发任何告警（只拿正常行跑，断言零告警）。"""
    normal = [e for e in events if "@type" not in e.raw and "ldap://" not in e.raw]
    assert len(normal) == 3, "样本应含 3 条正常业务行"
    assert run_rules(normal, rules) == [], "正常业务行被误报"


def test_plain_json_with_at_type_but_safe_class(events, rules):
    """含 @type 但指向普通业务类的 JSON 不应触发 JdbcRowSetImpl 规则。"""
    ev = parse_line('2026-10-23 04:26:52 [HTTP-Dispatcher] INFO App - '
                    'input={"@type":"com.example.Order","orderId":"SO-1"}')
    alerts = run_rules([ev], rules)
    assert not [a for a in alerts if a.rule_id == "fastjson-jdbcrowset-payload"]
    assert not [a for a in alerts if a.rule_id == "fastjson-jndi-url-in-input"]


# ================= 归因 =================

def test_source_ip_attribution(events, rules):
    """攻击行里的 IP 被提取出来用于聚合（样本中均为 127.0.0.1 本地复现地址）。"""
    alerts = run_rules(events, rules)
    assert alerts, "样本应检出告警"
    for a in alerts:
        assert a.source_ip == "127.0.0.1", f"{a.rule_id} 归因 IP 异常: {a.source_ip}"


# ================= CLI 全链路 =================

def test_cli_import_app_format(tmp_path, capsys):
    db = tmp_path / "fastjson.db"
    rc = main(["import", "--log", str(_SAMPLE), "--format", "app",
               "--db", str(db), "--reset"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "解析事件 9 条" in out          # 3 正常 + 6 攻击，保底解析器不丢行
    assert "产生 6 条告警" in out           # 六条规则各命中一次


def test_sample_matches_research_evidence():
    """样本必须来自真实复现（行内含本地回环地址与实验中的真实 payload）。"""
    text = _SAMPLE.read_text(encoding="utf-8")
    assert "@type" in text
    assert "com.sun.rowset.JdbcRowSetImpl" in text
    assert "java.lang.Class" in text            # 缓存绕过
    assert "java.lang.AutoCloseable" in text    # expectClass 绕过
    assert "127.0.0.1:1389" in text             # 本地 LDAP 服务
