"""SQLite 存储层：事件表 + 告警表。

设计要点（面试可讲）：
- **零外部依赖**（Python 自带 sqlite3），单文件数据库——拷走即迁移，
  演示时可以直接把 .db 发给别人，轻量部署友好（对比 Elasticsearch 的部署成本）。
- 事件表建 (ip, ts) 联合索引：规则引擎按 IP + 时间范围做滑动窗口过滤。
- 时间存 ISO 8601 文本（"2026-10-22 09:02:11"）：字典序即时间序，
  排序与范围查询直接走字符串比较，且肉眼可读。
- 事件与告警分表：原始事件可回溯（"这条告警是基于哪些事件得出的"），
  这是审计类系统的基本要求——告警必须可解释、可取证。
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from models import Alert, AuthEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username   TEXT,
    ip         TEXT,
    port       INTEGER,
    service    TEXT,
    raw        TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip, ts);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT NOT NULL,
    detail       TEXT,
    source_ip    TEXT,
    event_count  INTEGER,
    window_start TEXT,
    window_end   TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
"""


def _ts(dt: datetime) -> str:
    """datetime → 可排序的 ISO 字符串（秒级精度足够审计场景）。"""
    return dt.isoformat(sep=" ", timespec="seconds")


class Storage:
    """薄封装：只做"存"与"查"，不含任何业务逻辑（单一职责，便于测试）。"""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ---------- 写入 ----------
    def insert_events(self, events: list[AuthEvent]) -> int:
        self.conn.executemany(
            "INSERT INTO events (ts, event_type, username, ip, port, service, raw)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(_ts(e.ts), e.event_type, e.username, e.ip, e.port, e.service, e.raw)
             for e in events],
        )
        self.conn.commit()
        return len(events)

    def insert_alerts(self, alerts: list[Alert]) -> int:
        now = _ts(datetime.now())
        self.conn.executemany(
            "INSERT INTO alerts (rule_id, rule_name, severity, title, detail,"
            " source_ip, event_count, window_start, window_end, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(a.rule_id, a.rule_name, a.severity, a.title, a.detail, a.source_ip,
              a.event_count, _ts(a.window_start), _ts(a.window_end), now)
             for a in alerts],
        )
        self.conn.commit()
        return len(alerts)

    # ---------- 查询 ----------
    def event_stats(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type"
        ).fetchall()
        return {r["event_type"]: r["n"] for r in rows}

    def list_alerts(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC, id DESC"
        ).fetchall()

    def reset(self) -> None:
        self.conn.execute("DELETE FROM events")
        self.conn.execute("DELETE FROM alerts")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
