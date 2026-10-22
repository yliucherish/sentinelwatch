"""规则引擎：声明式规则（YAML）加载 + 滑动窗口统计 + 阈值判定。

设计要点（面试可讲）：
- **声明式规则而非硬编码 if-else**：新增检测场景 = 加一个 YAML 文件，不改代码。
  这是与"玩具项目"拉开差距的工程化点（设计思想参照 osquery / Wazuh 的规则体系）。
- **滑动窗口而非总量统计**：暴力破解是时间密集行为。总量统计会被
  "每天试 1 次、试一年"绕过；窗口统计问的是"最近 N 秒内发生了 M 次吗"——
  窗口大小与阈值的权衡正是规则调优的核心。
- **命中后静默（suppress）**：一轮爆破会持续产生失败事件，每条都告警就是
  告警风暴。v0.1 在引擎内按分组静默 suppress_seconds；v0.2 将其抽为独立的
  抑制器（支持跨规则聚合），这里先落地最小可用版本。
- **签名匹配（v1.0 新增 match 字段）**：v0.x 的规则只能按"事件类型 + 计数"
  判定（阈值检测）；v1.0 增加可选的 match 条件（raw_contains / raw_contains_any
  在原始日志行上做子串匹配），从"纯阈值检测"升级为"阈值 + 签名"双模——
  这是真实 IDS 的标准形态：阈值检测抓行为模式（爆破），签名检测抓已知
  攻击特征（Log4Shell 的 ${jndi: 载荷）。两种判据 declaratively 共存。
- 窗口用双指针（deque）维护：O(n)，不需要把全量事件反复重扫。
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from models import Alert, AuthEvent


@dataclass
class Rule:
    """一条声明式检测规则（YAML 的结构化表示）。"""

    id: str
    name: str
    description: str
    severity: str
    event_types: tuple[str, ...]
    group_by: tuple[str, ...]
    window_seconds: int
    threshold: int
    suppress_seconds: int
    match: dict | None = None      # v1.0 可选签名条件，见 _matches()


def load_rules(path: str | Path) -> list[Rule]:
    """加载单个 YAML 规则文件（文件内含 rules: 列表，可放多条规则）。"""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return [_build_rule(item) for item in data.get("rules", [])]


def load_rules_dir(dir_path: str | Path) -> list[Rule]:
    """加载目录下全部 *.yaml 规则文件（新增规则只需丢文件进目录）。"""
    rules: list[Rule] = []
    for p in sorted(Path(dir_path).glob("*.yaml")):
        rules.extend(load_rules(p))
    return rules


def _build_rule(item: dict) -> Rule:
    required = ("id", "name", "event_types", "group_by",
                "window_seconds", "threshold")
    missing = [k for k in required if k not in item]
    if missing:
        raise ValueError(f"规则缺少必填字段 {missing}: {item}")
    return Rule(
        id=str(item["id"]),
        name=str(item["name"]),
        description=str(item.get("description", "")),
        severity=str(item.get("severity", "medium")),
        event_types=tuple(item["event_types"]),
        group_by=tuple(item["group_by"]),
        window_seconds=int(item["window_seconds"]),
        threshold=int(item["threshold"]),
        suppress_seconds=int(item.get("suppress_seconds", 600)),
        match=item.get("match"),
    )


def _matches(event: AuthEvent, match: dict) -> bool:
    """签名匹配：在原始日志行上做子串判定（v1.0）。

    - raw_contains:     列表内**全部**子串都要出现（AND，收窄匹配）
    - raw_contains_any: 列表内**任一**子串出现即算匹配（OR，同族变体）

    语义设计成 AND/OR 两个显式操作符而不是隐式混合——规则的匹配条件
    必须是可预测的（安全规则最怕"我以为它在匹配这个"）。
    """
    raw = event.raw or ""
    for sub in match.get("raw_contains") or []:
        if sub not in raw:
            return False
    any_of = match.get("raw_contains_any") or []
    if any_of and not any(sub in raw for sub in any_of):
        return False
    return True


def _group_key(event: AuthEvent, fields: tuple[str, ...]) -> tuple:
    return tuple(getattr(event, f, None) for f in fields)


def run_rules(events: list[AuthEvent], rules: list[Rule]) -> list[Alert]:
    """对事件集执行全部规则，返回告警列表（按时间排序）。"""
    alerts: list[Alert] = []
    for rule in rules:
        matched = [e for e in events if e.event_type in rule.event_types]
        if rule.match:   # v1.0：签名条件先过滤，再进滑动窗口统计
            matched = [e for e in matched if _matches(e, rule.match)]
        groups: dict[tuple, list[AuthEvent]] = {}
        for e in matched:
            groups.setdefault(_group_key(e, rule.group_by), []).append(e)

        for key, group_events in groups.items():
            group_events.sort(key=lambda e: e.ts)
            muted_until: datetime | None = None
            window: deque[AuthEvent] = deque()
            for e in group_events:
                # 滑动窗口：弹出窗口外的旧事件（双指针，O(n)）。
                # 窗口语义为闭区间 [t-window_seconds, t]：与当前事件相差
                # 恰好 window_seconds 的旧事件仍在窗内，超过才被遗忘。
                while window and (e.ts - window[0].ts).total_seconds() > rule.window_seconds:
                    window.popleft()
                window.append(e)

                if muted_until and e.ts < muted_until:
                    continue  # 静默期内不重复告警
                if len(window) >= rule.threshold:
                    alerts.append(_make_alert(rule, key, list(window)))
                    muted_until = e.ts + timedelta(seconds=rule.suppress_seconds)

    alerts.sort(key=lambda a: (a.window_end, a.rule_id))
    return alerts


def _make_alert(rule: Rule, key: tuple, window: list[AuthEvent]) -> Alert:
    """把命中的窗口打包成告警（detail 里带上目标用户名，便于分析师研判）。"""
    key_desc = ", ".join(f"{f}={v}" for f, v in zip(rule.group_by, key))
    users = sorted({e.username for e in window if e.username})
    user_desc = ", ".join(users[:5]) + ("..." if len(users) > 5 else "")
    return Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        title=f"{rule.name}（{key_desc}）",
        detail=(f"{rule.window_seconds}s 窗口内 {len(window)} 次 "
                f"{'/'.join(rule.event_types)} 事件（阈值 {rule.threshold}）；"
                f"涉及用户: {user_desc or '未知'}"),
        source_ip=key[0] if rule.group_by == ("ip",) else None,
        event_count=len(window),
        window_start=window[0].ts,
        window_end=window[-1].ts,
    )
