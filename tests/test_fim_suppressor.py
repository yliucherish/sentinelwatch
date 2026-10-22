"""v0.2 组件测试：FIM（文件完整性）+ 抑制器（告警聚合）。

覆盖：
1. FIM：基线建立 / 变更三类检测（modified/added/deleted）/ 排除规则 /
   大文件流式哈希 / 基线可移植（相对路径）
2. 抑制器：同 IP 多规则聚合成一个 Incident / 超窗拆分 / 严重度取最高 /
   主机侧告警按对象分组 / 聚合不丢成员信息
"""
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from fim import (FileState, scan_directory, save_baseline, load_baseline,
                 compare_baseline, changes_to_alerts, sha256_file)
from models import Alert
from suppressor import aggregate


@pytest.fixture()
def monitored_dir(tmp_path):
    """构造一个被监控目录：2 个文件 + 1 个应被排除的目录。

    注意目录结构：tmp_path/monitored 是被监控对象，tmp_path/baseline.json
    在监控树之外——**基线文件必须放在被监控目录外**，否则每次刷新基线
    都会把自己算成"新增文件"（真实 FIM 部署的经典事故，CLI 已加防护）。
    """
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "keep.txt").write_text("原始内容", encoding="utf-8")
    (root / "data").mkdir()
    (root / "data" / "conf.ini").write_text("a=1", encoding="utf-8")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "junk.pyc").write_bytes(b"\x00\x01")
    return root


@pytest.fixture()
def baseline_path(tmp_path):
    return tmp_path / "baseline.json"


# ================= FIM =================

def test_fim_baseline_and_no_change(monitored_dir, baseline_path):
    states = scan_directory(monitored_dir)
    assert set(states) == {"keep.txt", "data/conf.ini"}   # __pycache__ 被排除
    save_baseline(states, baseline_path)
    assert load_baseline(baseline_path).keys() == states.keys()
    # 无变更 → 空列表
    assert compare_baseline(states, scan_directory(monitored_dir)) == []


def test_fim_detects_modified_added_deleted(monitored_dir, baseline_path):
    save_baseline(scan_directory(monitored_dir), baseline_path)

    # 三种变更各来一个
    (monitored_dir / "keep.txt").write_text("被篡改的内容", encoding="utf-8")
    (monitored_dir / "data" / "new.conf").write_text("新增文件", encoding="utf-8")
    (monitored_dir / "data" / "conf.ini").unlink()

    changes = compare_baseline(load_baseline(baseline_path), scan_directory(monitored_dir))
    by_type = {c.path: c.change_type for c in changes}
    assert by_type == {"keep.txt": "modified",
                       "data/new.conf": "added",
                       "data/conf.ini": "deleted"}
    modified = next(c for c in changes if c.change_type == "modified")
    assert modified.old_sha256 != modified.new_sha256
    assert modified.old_size != modified.new_size


def test_fim_alerts_severity(monitored_dir):
    alerts = changes_to_alerts(
        [type("C", (), {"path": "x", "change_type": "modified",
                        "old_sha256": "a" * 64, "new_sha256": "b" * 64,
                        "old_size": 1, "new_size": 2})()],
        str(monitored_dir))
    assert alerts[0].severity == "high"
    assert alerts[0].rule_id == "fim-integrity"
    assert "篡改" in alerts[0].title


def test_fim_sha256_matches_hashlib(tmp_path):
    """流式哈希的正确性：与标准库一次性哈希结果一致。"""
    import hashlib
    p = tmp_path / "big.bin"
    p.write_bytes(bytes(range(256)) * 1000)      # 256KB，跨多个读取块
    assert sha256_file(p) == hashlib.sha256(p.read_bytes()).hexdigest()


# ================= 抑制器 =================

def _alert(rule: str, sev: str, ip: str | None, offset: float,
           rule_name: str = "", events: int = 1) -> Alert:
    base = datetime(2026, 10, 22, 12, 0, 0)
    return Alert(rule_id=rule, rule_name=rule_name or rule, severity=sev,
                 title=f"{rule_name or rule}（ip={ip}）", detail="d",
                 source_ip=ip, event_count=events,
                 window_start=base + timedelta(seconds=offset),
                 window_end=base + timedelta(seconds=offset + 1))


def test_aggregate_same_ip_multiple_rules():
    """同一 IP 触发的多条规则告警 → 一个 Incident（告警降噪的核心场景）。"""
    alerts = [
        _alert("ssh-brute-force", "high", "1.2.3.4", 0, "SSH 暴力破解", 5),
        _alert("ssh-user-enumeration", "medium", "1.2.3.4", 30, "SSH 用户名枚举", 5),
        _alert("ssh-brute-force", "high", "1.2.3.4", 60, "SSH 暴力破解", 5),
    ]
    incidents = aggregate(alerts, window_seconds=600)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.alert_count == 3
    assert inc.total_events == 15
    assert set(inc.rules) == {"SSH 暴力破解", "SSH 用户名枚举"}
    assert inc.severity == "high"            # 取成员最高严重度
    assert len(inc.members) == 3             # 聚合不丢成员（可解释性）


def test_aggregate_window_split():
    """间隔超过聚合窗口 → 拆成两个 Incident（十分钟前的失败不算同一次攻击）。"""
    alerts = [
        _alert("r", "high", "1.2.3.4", 0, "暴力破解", 5),
        _alert("r", "high", "1.2.3.4", 900, "暴力破解", 5),   # 15 分钟后
    ]
    incidents = aggregate(alerts, window_seconds=600)
    assert len(incidents) == 2


def test_aggregate_host_side_alerts():
    """主机侧告警（FIM，无 source_ip）按 规则+对象 分组。"""
    a1 = Alert(rule_id="fim-integrity", rule_name="文件完整性监控",
               severity="high", title="文件篡改: /etc/passwd", detail="d",
               source_ip=None, event_count=1,
               window_start=datetime(2026, 10, 22, 12, 0, 0),
               window_end=datetime(2026, 10, 22, 12, 0, 1))
    a2 = Alert(rule_id="fim-integrity", rule_name="文件完整性监控",
               severity="medium", title="文件新增: /etc/new", detail="d",
               source_ip=None, event_count=1,
               window_start=datetime(2026, 10, 22, 12, 0, 2),
               window_end=datetime(2026, 10, 22, 12, 0, 3))
    incidents = aggregate([a1, a2])
    assert len(incidents) == 2              # 不同文件对象 → 不同事件
    assert all(i.source_ips == [] for i in incidents)


def test_aggregate_orders_by_severity():
    """低严重度的网络告警不应排在高严重度前面（分析师先看要紧的）。"""
    alerts = [
        _alert("low-rule", "low", "9.9.9.9", 0, "低危", 1),
        _alert("crit-rule", "critical", "8.8.8.8", 0, "严重", 1),
    ]
    incidents = aggregate(alerts)
    assert incidents[0].severity == "critical"
