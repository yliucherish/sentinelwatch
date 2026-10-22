"""通用日志解析器（v1.0 新增）：把任意应用日志行转为事件。

为什么需要它：检测规则如果只能吃 auth.log，SentinelWatch 就只是个 SSH 审计
工具。真实环境里最值得检测的日志是各业务应用的日志——Log4Shell（CVE-2021-44228）
的痕迹就出现在应用日志里（本仓库 cve-research/CVE-2021-44228-log4shell/ 有
完整复现实证：受害应用的 logs/app.log）。

设计要点（面试可讲）：
- **宽容优先**：任何非空行都成为一个事件（event_type="app_log"），不做结构化
  假设——采集器最怕被一行没见过的格式搞崩（与 auth_log.py 相同的设计哲学，
  但覆盖面相反，见下）。
- **与 auth_log.py 的分工**：auth_log 是"领域解析器"（认识 sshd 消息结构，
  能提取 user/ip/port）；app_log 是"保底解析器"（不认识所有结构，但不丢
  任何行，能提 IP 就提）——真实 SIEM 的采集层就是这个分层：
  领域解析器给结构化字段，保底解析器保证覆盖率，签名规则在原始行上匹配。
- **时间戳尽力而为**：能解析 ISO 8601（log4j PatternLayout 默认格式）就解析，
  解析不了退回当前时间——保底解析器的已知取舍，已在 docstring 声明。
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from models import AuthEvent

# 行内 IP（用于按来源聚合；日志里没有 IP 就留空）
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# log4j PatternLayout 的 %d{ISO8601} 形如 2026-10-23T02:54:55,204（逗号是毫秒）
_ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})[.,](\d{3})")

# syslog 前缀（"Oct 22 09:02:11 host proc[pid]:"）——与 auth_log 相同的兼容
_SYSLOG_TS_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s")

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _extract_ts(line: str) -> datetime | None:
    """尽力提取行首时间戳；失败返回 None（调用方退回当前时间）。

    精度统一到秒：与 auth_log / storage（_ts 用 timespec="seconds"）保持一致，
    毫秒在入库时本来就会被截断，解析阶段保留只会造成"内存里有、库里没有"
    的不一致。
    """
    m = _ISO_TS_RE.match(line)
    if m:
        try:
            return datetime.fromisoformat(
                f"{m.group(1)}.{m.group(2)}").replace(microsecond=0)
        except ValueError:
            return None
    m = _SYSLOG_TS_RE.match(line)
    if m:
        mon, day, hhms = m.group(1).split()
        h, mi, s = (int(x) for x in hhms.split(":"))
        return datetime(datetime.now().year, _MONTHS[mon], int(day), h, mi, s)
    return None


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """解析单行应用日志为事件；空行返回 None。其余一律成为 app_log 事件。"""
    line = line.rstrip("\n")
    if not line.strip():
        return None
    ts = _extract_ts(line) or datetime.now()
    m = _IP_RE.search(line)
    return AuthEvent(
        ts=ts,
        event_type="app_log",
        ip=m.group(1) if m else None,
        service="app",
        raw=line,
    )


def parse_file(path: str | Path, year: int | None = None) -> list[AuthEvent]:
    """解析整个日志文件（保底解析器：不丢行，除了空行）。"""
    events: list[AuthEvent] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line, year=year)
            if ev:
                events.append(ev)
    return events
