"""数据模型：日志事件与告警。

设计要点（面试可讲）：
- 事件（event）是"已解析的结构化日志"，告警（alert）是"规则命出的结论"——
  两者分开建模、分开存储，数据链路与 SIEM 一致：采集→解析→规则匹配→存储→展示。
- 时间统一用 datetime，存储时转 ISO 8601 字符串。SQLite 无原生时间类型，
  ISO 字符串的字典序即时间序，排序/范围查询都可直接走字符串比较，且人类可读
  （面试时可以直接打开 .db 文件演示）。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class AuthEvent:
    """一条解析后的认证日志事件。"""

    ts: datetime
    event_type: str                 # failed_password / accepted_password / invalid_user / sudo
    username: str | None = None
    ip: str | None = None
    port: int | None = None
    service: str = "sshd"
    raw: str = ""


@dataclass
class Alert:
    """一条规则命中产生的告警。"""

    rule_id: str
    rule_name: str
    severity: str                   # low / medium / high / critical
    title: str
    detail: str
    source_ip: str | None
    event_count: int
    window_start: datetime
    window_end: datetime
