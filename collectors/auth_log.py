"""auth.log 解析器：把 Linux sshd/sudo 日志行解析为结构化事件。

设计要点（面试可讲）：
- **对脏数据宽容**：真实日志里什么都有（内核消息、cron、DHCP……）。
  解析器只识别关心的行，其余静默跳过——日志采集器最怕的是被一行脏数据搞崩。
- **syslog 时间戳没有年份**（"Oct 22 09:02:11"）：按当前年份补齐。
  已知取舍：跨年日志（12 月→次年 1 月）会被算成未来时间，生产实现需要
  年界回退判断（日志时间晚于当前时间超过阈值时 year-1）。
- **先匹配结构再提取字段**：每类消息一个正则，不追求覆盖所有 sshd 消息类型，
  新增类型 = 加一条正则 + 一个 event_type（可扩展性）。

覆盖的消息类型（event_type）：
- failed_password    "Failed password for [invalid user] <user> from <ip> port <port>"
- accepted_password  "Accepted password/publickey for <user> from <ip> port <port>"
- invalid_user       "Invalid user <user> from <ip> port <port>"（用户名枚举的典型信号）
- sudo               "sudo: <user> : ... COMMAND=<cmd>"
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from models import AuthEvent

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# 公共前缀：月份 日 时间 主机名 进程名[pid]:
_PREFIX = r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hhms>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<proc>[\w\-]+)(?:\[\d+\])?:\s*"

FAILED_RE = re.compile(
    _PREFIX + r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
ACCEPTED_RE = re.compile(
    _PREFIX + r"Accepted (?:password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
INVALID_RE = re.compile(
    _PREFIX + r"Invalid user (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
SUDO_RE = re.compile(_PREFIX + r"(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")

# 消息类型 → 正则（按此顺序尝试；一条行只归入第一个匹配的类型）
_PATTERNS = [
    ("failed_password", FAILED_RE),
    ("accepted_password", ACCEPTED_RE),
    ("invalid_user", INVALID_RE),
    ("sudo", SUDO_RE),
]


def _parse_ts(mon: str, day: str, hhms: str, year: int) -> datetime:
    """syslog 时间戳 → datetime（年份取当前年，见模块 docstring 的已知取舍）。"""
    h, m, s = (int(x) for x in hhms.split(":"))
    return datetime(year, _MONTHS[mon], int(day), h, m, s)


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """解析单行日志；不是关注的事件类型时返回 None（静默跳过）。"""
    line = line.rstrip("\n")
    if not line.strip():
        return None
    year = year or datetime.now().year
    for event_type, pattern in _PATTERNS:
        m = pattern.match(line)
        if not m:
            continue
        ts = _parse_ts(m.group("mon"), m.group("day"), m.group("hhms"), year)
        return AuthEvent(
            ts=ts,
            event_type=event_type,
            username=m.group("user"),
            ip=m.groupdict().get("ip"),
            port=int(m.group("port")) if m.groupdict().get("port") else None,
            service=m.group("proc"),
            raw=line,
        )
    return None


def parse_file(path: str | Path, year: int | None = None) -> list[AuthEvent]:
    """解析整个日志文件，返回事件列表（无法识别的行不计入）。"""
    events: list[AuthEvent] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line, year=year)
            if ev:
                events.append(ev)
    return events
