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
class HttpEvent:
    """一条从 PCAP 流量里还原的 HTTP 请求事件（v1.2 新增）。

    设计要点（面试可讲）：字段与 AuthEvent **刻意对齐**（username 恒为 None），
    所以 storage / 规则引擎 / 抑制器 / 报告 / 看板**一行都不用改**就能吃流量。
    这就是"事件模型统一"的红利——新增数据源的成本从"改五处"降到"加一个采集器"。

    raw 与 normalized 分离的理由：
    - `raw` 是原始证据（取证、复现、给分析师看原文）
    - `normalized` 是签名匹配用的归一化视图（URL 解码到不动点 + 转小写）
    判据可以归一化，证据不能——两件事分开存，才既不漏报也不失真。
    """

    ts: datetime
    event_type: str = "http_request"
    username: str | None = None          # 与 AuthEvent 对齐，流量场景恒为 None
    ip: str | None = None
    port: int | None = None
    service: str = "http"
    method: str = ""
    host: str = ""
    uri: str = ""
    body: str = ""
    raw: str = ""
    normalized: str = ""


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
