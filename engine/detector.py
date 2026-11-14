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
import re
from pathlib import Path

import yaml

from models import Alert, AuthEvent, HttpEvent

Event = AuthEvent | HttpEvent


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
    tags: tuple[str, ...] = ()     # v1.3 ATT&CK / CVE 标签，如 attack.t1190
    sigma: dict | None = None      # v1.3 Sigma 导出元数据（logsource/fields/falsepositives）


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
    match = item.get("match")
    if match is not None:
        _validate_match(match, str(item["id"]))
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
        match=match,
        tags=tuple(item.get("tags") or ()),
        sigma=item.get("sigma"),
    )


_MATCH_OPS = ("raw_contains", "raw_contains_any", "raw_regex")
_MATCH_FIELDS = ("raw", "normalized", "sql_view", "uri", "body", "method", "host")


def _validate_match(match: dict, rule_id: str) -> None:
    """**加载期**校验判据，而不是等匹配时才发现写错。

    安全规则最糟的失效方式不是报错，是"看起来在工作、实际永远不命中"：
    正则少个括号、字段名拼错（写成 `normalize` 而不是 `normalized`）都会让
    规则静默失效，而单测只覆盖了它该命中的样本时，谁都发现不了。所以这里
    对未知操作符、未知字段、非法正则一律直接抛错——宁可启动失败。
    """
    unknown = [k for k in match if k not in (*_MATCH_OPS, "field")]
    if unknown:
        raise ValueError(
            f"规则 {rule_id} 的 match 含未知键 {unknown}；"
            f"可用的是 {(*_MATCH_OPS, 'field')}")
    field = match.get("field", "raw")
    if field not in _MATCH_FIELDS:
        raise ValueError(
            f"规则 {rule_id} 指定了未知字段 {field!r}；可用的是 {_MATCH_FIELDS}")
    if not any(k in match for k in _MATCH_OPS):
        raise ValueError(f"规则 {rule_id} 的 match 没给任何判据操作符")
    for i, pattern in enumerate(match.get("raw_regex") or []):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"规则 {rule_id} 的 raw_regex[{i}] 不是合法正则：{exc}\n"
                f"  pattern: {pattern}") from exc


def _matches(event: Event, match: dict) -> bool:
    """签名匹配：在事件指定字段上做子串 / 正则判定（v1.0；v2.0 加正则）。

    判据只有**两组**，组间 AND、组内 OR：

    - AND 组：`raw_contains`      列表内**全部**子串都要出现
    - OR  组：`raw_contains_any`  任一子串出现即算匹配
              `raw_regex`         任一正则 `search` 命中即算匹配
              （两者合起来算同一个 OR 组：子串和正则只是"同一族里的不同写法"）
    - `field`：匹配哪个字段，默认 "raw"（原始证据）。流量规则可设为
      "normalized"（解码 + 小写）或 "sql_view"（再去掉 SQL 注释/空白噪声）。

    **`raw_regex` 为什么和 `raw_contains_any` 同组而不是自成一组**（踩过）：
    v2.0 最初把 `raw_regex` 当成独立 AND 组，结果给 XSS 规则加了
    "命名空间标签"正则之后，规则变成"必须同时出现 `<script` 和 `<x:script>`"
    ——几乎永不命中。而它表现为**误报降到 0**，看起来像好消息。
    安全规则最危险的失效不是报错，是"看起来在工作、其实不再匹配"。
    与其靠注释提醒，不如让"子串 + 正则"天然是 OR：想表达 AND 就用
    `raw_contains`，那里没有歧义。

    语义设计成显式两组而不是隐式混合——规则的匹配条件必须是可预测的
    （安全规则最怕"我以为它在匹配这个"）。

    为什么 v2.0 要加正则（而不是继续堆子串）：`union` 与 `select` 之间的
    分隔符可以是空格、`/**/`、换行、Tab，子串只能把这四种写法枚举进 YAML，
    而枚举的是**样本**、不是**语法**。正则 `un\\s*ion\\s*se\\s*lect` 表达的是
    "关键字 + 任意分隔符 + 关键字"，这一个模式覆盖整族变形——同一份判据
    在没见过的变体上仍然成立，才叫检测能力。
    """
    text = getattr(event, match.get("field", "raw"), "") or ""
    for sub in match.get("raw_contains") or []:
        if sub not in text:
            return False
    or_subs = match.get("raw_contains_any") or []
    or_regex = match.get("raw_regex") or []
    if (or_subs or or_regex) and not (
            any(sub in text for sub in or_subs)
            or any(re.search(p, text) for p in or_regex)):
        return False
    return True


def _group_key(event: Event, fields: tuple[str, ...]) -> tuple:
    return tuple(getattr(event, f, None) for f in fields)


def run_rules(events: list[Event], rules: list[Rule]) -> list[Alert]:
    """对事件集执行全部规则，返回告警列表（按时间排序）。"""
    alerts: list[Alert] = []
    for rule in rules:
        matched = [e for e in events if e.event_type in rule.event_types]
        if rule.match:   # v1.0：签名条件先过滤，再进滑动窗口统计
            matched = [e for e in matched if _matches(e, rule.match)]
        groups: dict[tuple, list[Event]] = {}
        for e in matched:
            groups.setdefault(_group_key(e, rule.group_by), []).append(e)

        for key, group_events in groups.items():
            group_events.sort(key=lambda e: e.ts)
            muted_until: datetime | None = None
            window: deque[Event] = deque()
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


def _make_alert(rule: Rule, key: tuple, window: list[Event]) -> Alert:
    """把命中的窗口打包成告警（detail 里带上用户名/请求目标，便于分析师研判）。

    v1.2：username 用 getattr 读取——流量事件（HttpEvent）没有用户概念，
    改按 HTTP 请求目标补充上下文，日志事件的行为与 v1.0 完全一致。
    """
    key_desc = ", ".join(f"{f}={v}" for f, v in zip(rule.group_by, key))
    users = sorted({getattr(e, "username", None)
                    for e in window if getattr(e, "username", None)})
    user_desc = ", ".join(users[:5]) + ("..." if len(users) > 5 else "")
    targets = list(dict.fromkeys(
        getattr(e, "uri", "") for e in window if getattr(e, "uri", "")))
    target_desc = "、".join(t[:120] for t in targets[:3])
    if len(targets) > 3:
        target_desc += " ..."
    detail = (f"{rule.window_seconds}s 窗口内 {len(window)} 次 "
              f"{'/'.join(rule.event_types)} 事件（阈值 {rule.threshold}）")
    if user_desc:
        detail += f"；涉及用户: {user_desc}"
    if target_desc:
        detail += f"；请求目标: {target_desc}"
    return Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        title=f"{rule.name}（{key_desc}）",
        detail=detail,
        source_ip=key[0] if rule.group_by == ("ip",) else None,
        event_count=len(window),
        window_start=window[0].ts,
        window_end=window[-1].ts,
    )
