"""把 IOC 命中转换成标准 Alert。

为什么复用 Alert 而不新建结构：
    告警链路（storage 入库 → web 看板 → report HTML → suppressor 抑制）全部围绕 Alert 建模。
    IOC 命中只是"另一种判据"，产出同一种告警就能直接继承这些能力——
    否则看板要改、报告要改、抑制器要改，三处都要动，是典型的重复建模。
"""
from __future__ import annotations

from models import Alert, AuthEvent

from intel.ioc import IOC, IOCSet


def match_events(events: list[AuthEvent], ioc_set: IOCSet,
                 severity: str = "high") -> list[Alert]:
    """对所有事件做情报匹配，**按 IOC 聚合**后产出告警。

    为什么必须聚合（实测踩到的坑）：
        一次 SSH 爆破里同一个恶名 IP 会出现几十次，如果每条事件都产一条告警，
        一次导入就是几十条重复 IOC 告警——正是本项目 suppressor 要解决的告警风暴。
        情报的语义是"这个实体是已知恶意"，它需要一条告警 + 命中次数 + 时间范围，
        而不是每次出现都重复喊一遍。

    匹配文本优先用原始日志行（raw）：情报指标常出现在日志任意位置
    （URL、UA、文件名），结构化字段会漏。raw 为空时退回字段拼接。
    """
    # 按 IOC 值聚合：key → 聚合状态
    agg: dict[str, dict] = {}

    for event in events:
        text = event.raw or " ".join(
            filter(None, (event.username, event.ip, event.service))
        )
        if not text:
            continue
        for ioc, field in ioc_set.match(text):
            key = f"{ioc.kind}:{ioc.value}"
            slot = agg.get(key)
            if slot is None:
                agg[key] = {
                    "ioc": ioc,
                    "fields": {field},
                    "count": 1,
                    "start": event.ts,
                    "end": event.ts,
                    "ip": event.ip,
                }
            else:
                slot["count"] += 1
                slot["fields"].add(field)
                slot["start"] = min(slot["start"], event.ts)
                slot["end"] = max(slot["end"], event.ts)
                if slot["ip"] is None and event.ip:
                    slot["ip"] = event.ip

    alerts: list[Alert] = []
    for slot in agg.values():
        ioc: IOC = slot["ioc"]
        alerts.append(
            Alert(
                rule_id=f"IOC-{ioc.kind.upper()}",
                rule_name=f"威胁情报命中（{ioc.kind}）",
                severity=severity,
                title=f"IOC 命中：{ioc.value}",
                detail=_detail(ioc, slot["fields"], slot["count"]),
                source_ip=slot["ip"],
                event_count=slot["count"],
                window_start=slot["start"],
                window_end=slot["end"],
            )
        )
    # 稳定排序：命中次数多的在前，便于看板第一眼看到最严重的
    alerts.sort(key=lambda a: (-a.event_count, a.rule_id))
    return alerts


def _detail(ioc: IOC, fields: set[str], count: int) -> str:
    parts = [f"命中片段={','.join(sorted(fields))}"]
    if count > 1:
        parts.append(f"命中次数={count}")
    if ioc.source:
        parts.append(f"情报来源={ioc.source}")
    if ioc.note:
        parts.append(f"备注={ioc.note}")
    return "；".join(parts)
