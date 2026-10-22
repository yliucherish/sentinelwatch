"""告警聚合抑制器（Alert Correlation & Suppression）。

设计要点（面试可讲）：
- **为什么要聚合**：一次真实的暴力破解会同时触发"暴力破解"与"用户名枚举"
  两条规则，甚至叠加 FIM 告警——逐条呈现就是告警风暴，分析师会被淹没。
  SIEM 的标准做法是**关联分析**（correlation）：把时间与空间上相关的多条
  告警合并成一个"事件/ Incident"，一条呈现、一次响应。
- **聚合维度**：按 (source_ip, 时间窗) 分组。同一来源在同一个窗口内的所有
  告警归为一个 Incident；无来源的主机侧告警（FIM）按 (rule_id, 路径) 分组。
- **抑制与聚合是两件事**：引擎内的 suppress 解决"同一条规则的重复告警"；
  本模块解决"不同规则的关联呈现"。两者叠加才是完整的告警降噪。
- **可解释性**：Incident 保留成员告警的完整列表——聚合不能丢信息，
  否则就成了"藏问题"（蓝队工具的公信力基础）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from models import Alert


@dataclass
class Incident:
    """一个聚合后的事件（多条相关告警的联合呈现）。"""

    group_key: str                     # 聚合键（ip 或 主机侧规则+对象）
    title: str
    severity: str                      # 取成员中的最高严重度
    alert_count: int
    rules: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_events: int = 0              # 成员告警背后的事件总数
    members: list[Alert] = field(default_factory=list)

    @property
    def summary(self) -> str:
        span = ""
        if self.first_seen and self.last_seen:
            span = f"{self.first_seen:%H:%M:%S} ~ {self.last_seen:%H:%M:%S}"
        return (f"{self.alert_count} 条告警（{len(self.rules)} 类规则，"
                f"{self.total_events} 个事件）{span}")


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _alert_group_key(a: Alert) -> str:
    """聚合键：有网络源的按 IP；主机侧告警（FIM 等）按 规则+对象。"""
    if a.source_ip:
        return f"ip:{a.source_ip}"
    # 主机侧：取标题中的对象部分（"文件篡改: /etc/passwd" → 规则+路径）
    obj = a.title.split(":", 1)[1].strip() if ":" in a.title else a.title
    return f"host:{a.rule_id}:{obj}"


def aggregate(alerts: list[Alert],
              window_seconds: int = 600) -> list[Incident]:
    """把告警列表聚合成 Incident 列表。

    同一聚合键下，相邻告警间隔超过 window_seconds 的拆分为不同 Incident
    （一次攻击是一个连续过程，隔了十分钟的两次失败登录不该算同一次）。
    """
    incidents: list[Incident] = []
    # 按 (聚合键, 时间) 排序后顺序扫描，天然形成"连续段"
    ordered = sorted(alerts,
                     key=lambda a: (_alert_group_key(a), a.window_end or a.window_start))
    current: dict[str, Incident] = {}

    for a in ordered:
        key = _alert_group_key(a)
        ts = a.window_end or a.window_start
        inc = current.get(key)
        # 新段落的判定：没有进行中的 Incident，或与上一条间隔超窗
        if inc is None or (ts - inc.last_seen) > timedelta(seconds=window_seconds):
            inc = Incident(
                group_key=key,
                title=_incident_title(key),
                severity=a.severity,
                alert_count=0,
            )
            current[key] = inc
            incidents.append(inc)
        # 累入当前 Incident
        inc.alert_count += 1
        inc.total_events += a.event_count
        if a.rule_name not in inc.rules:
            inc.rules.append(a.rule_name)
        if a.source_ip and a.source_ip not in inc.source_ips:
            inc.source_ips.append(a.source_ip)
        if _SEV_ORDER.get(a.severity, 9) < _SEV_ORDER.get(inc.severity, 9):
            inc.severity = a.severity
        if inc.first_seen is None or ts < inc.first_seen:
            inc.first_seen = a.window_start or ts
        inc.last_seen = ts if inc.last_seen is None or ts > inc.last_seen else inc.last_seen
        inc.members.append(a)

    incidents.sort(key=lambda i: (_SEV_ORDER.get(i.severity, 9),
                                  -(i.last_seen.timestamp() if i.last_seen else 0)))
    return incidents


def _incident_title(key: str) -> str:
    """Incident 标题：直接说明"谁/什么"在出事。"""
    if key.startswith("ip:"):
        return f"来自 {key[3:]} 的关联安全事件"
    if key.startswith("host:"):
        _, rule, obj = key.split(":", 2)
        return f"主机对象 {obj} 的完整性事件"
    return key


def format_incidents(incidents: list[Incident]) -> str:
    """CLI 呈现：一条 Incident 一行摘要 + 成员缩进（信息不丢）。"""
    lines: list[str] = []
    for inc in incidents:
        lines.append(f"[{inc.severity.upper():8}] {inc.title}")
        lines.append(f"         {inc.summary}")
        for m in inc.members:
            lines.append(f"           └ {m.title}")
    return "\n".join(lines)
