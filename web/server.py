"""看板 HTTP 服务：把 SQLite 里的告警渲染成 Web 看板。

设计要点（面试可讲）：
- **零第三方依赖**：Python 标准库 http.server 直出。为什么不上 FastAPI +
  Chart.js CDN：① 安全工具常在隔离/内网环境演示，CDN 抽风整个看板就白屏；
  ② 安全工具自身加载第三方 JS 是供应链攻击面，纯内联 SVG 图表更说得通；
  ③ "拷走一个目录就能跑"的部署体验（对比 Elasticsearch + Kibana 的部署成本）。
- **数据链路闭环**：采集 → 解析 → 规则匹配 → 存储(SQLite) → 展示(本服务)。
  看板只读库，不写库——展示层与数据层解耦，DB 文件可以直接发给别人复现。
- 图表用服务端算好的聚合数据 + 前端 vanilla JS 画 SVG：折线（告警时间线）
  与柱状（TOP 源 IP）各几十行 JS，不引任何库。

用法：
    python cli.py serve --db sentinelwatch.db --port 8080
然后浏览器打开 http://127.0.0.1:8080
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from models import Alert
from storage import Storage
from suppressor import aggregate

WEB_DIR = Path(__file__).parent


def _row_to_alert(row: sqlite3.Row) -> Alert:
    """DB 行 → Alert 对象（供抑制器聚合复用）。"""
    return Alert(
        rule_id=row["rule_id"],
        rule_name=row["rule_name"],
        severity=row["severity"],
        title=row["title"],
        detail=row["detail"] or "",
        source_ip=row["source_ip"],
        event_count=row["event_count"] or 0,
        window_start=datetime.fromisoformat(row["window_start"]) if row["window_start"] else datetime.now(),
        window_end=datetime.fromisoformat(row["window_end"]) if row["window_end"] else datetime.now(),
    )


def _alert_json(a: Alert, alert_id: int | None = None) -> dict:
    return {
        "id": alert_id,
        "rule_id": a.rule_id,
        "rule_name": a.rule_name,
        "severity": a.severity,
        "title": a.title,
        "detail": a.detail,
        "source_ip": a.source_ip,
        "event_count": a.event_count,
        "window_start": a.window_start.isoformat(),
        "window_end": a.window_end.isoformat(),
    }


def _incident_json(inc) -> dict:
    return {
        "group_key": inc.group_key,
        "title": inc.title,
        "severity": inc.severity,
        "alert_count": inc.alert_count,
        "rules": inc.rules,
        "source_ips": inc.source_ips,
        "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
        "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
        "total_events": inc.total_events,
        "summary": inc.summary,
    }


def build_api_payload(db_path: str) -> dict:
    """一次查询算出看板需要的全部数据（告警/聚合/统计/时间线/TOP IP）。"""
    storage = Storage(db_path)
    try:
        rows = storage.list_alerts()
    finally:
        storage.close()

    alerts = [_row_to_alert(r) for r in rows]
    incidents = aggregate(alerts)

    # ---- 统计 ----
    sev_count: dict[str, int] = {}
    rule_count: dict[str, int] = {}
    for a in alerts:
        sev_count[a.severity] = sev_count.get(a.severity, 0) + 1
        rule_count[a.rule_name] = rule_count.get(a.rule_name, 0) + 1

    # ---- 时间线：按分钟分桶（折线图）----
    buckets: dict[str, int] = {}
    for a in alerts:
        key = a.window_end.strftime("%H:%M")
        buckets[key] = buckets.get(key, 0) + 1
    timeline = [{"t": k, "n": v} for k, v in sorted(buckets.items())]

    # ---- TOP 源 IP（柱状图；主机侧告警无 IP，归为"本机"）----
    ip_count: dict[str, int] = {}
    for a in alerts:
        ip = a.source_ip or "本机"
        ip_count[ip] = ip_count.get(ip, 0) + 1
    top_ips = sorted(ip_count.items(), key=lambda kv: -kv[1])[:8]

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "alerts": [_alert_json(a, r["id"]) for a, r in zip(alerts, rows)],
        "incidents": [_incident_json(i) for i in incidents],
        "stats": {
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
            "by_severity": sev_count,
            "by_rule": rule_count,
        },
        "timeline": timeline,
        "top_ips": [{"ip": ip, "n": n} for ip, n in top_ips],
    }


def make_handler(db_path: str):
    """工厂函数：把 DB 路径闭包进请求处理器（每个 serve 实例一个库）。"""

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # 静音默认访问日志
            pass

        def _send_json(self, payload: dict, status: int = 200):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, path: Path, content_type: str):
            try:
                body = path.read_bytes()
            except OSError:
                self._send_json({"error": "not found"}, status=404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            route = urlparse(self.path).path
            if route in ("/", "/index.html"):
                self._send_file(WEB_DIR / "dashboard.html", "text/html; charset=utf-8")
            elif route == "/api/data":
                try:
                    self._send_json(build_api_payload(db_path))
                except Exception as e:  # 库不存在/损坏时给前端可读的错误
                    self._send_json({"error": f"{type(e).__name__}: {e}"}, status=500)
            else:
                self._send_json({"error": "unknown route"}, status=404)

    return DashboardHandler


def serve(db_path: str, host: str = "127.0.0.1", port: int = 8080) -> None:
    """启动看板服务（阻塞）。默认只绑回环——安全工具不默认对外暴露。"""
    if not Path(db_path).exists():
        raise SystemExit(f"数据库不存在: {db_path}（先运行 cli.py 导入日志生成数据）")
    handler = make_handler(db_path)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"[*] 看板已启动: http://{host}:{port} （Ctrl+C 停止）")
    print(f"[*] 数据源: {db_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 已停止")
    finally:
        server.server_close()
