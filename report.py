"""告警报告导出：把 SQLite 里的告警渲染成可交付的 HTML 安全报告。

设计要点（面试可讲）：
- **零第三方依赖**：纯标准库字符串模板，不引 Jinja2 / reportlab / wkhtmltopdf。
  安全报告常在内网/隔离环境生成——依赖越多越不可交付；PDF 通过
  ``@media print`` 由浏览器"打印 → 另存为 PDF"获得，既省掉重量级依赖，
  也避开 Python PDF 库的中文字体坑（宋体/黑体嵌入是出了名的麻烦）。
- **模板与数据分离**：``build_report_data()`` 只算数（可单测），
  ``render_html()`` 只拼字符串（可整体替换模板）——两层独立测试、独立演进。
- **复用看板的聚合逻辑**：直接调用 ``web.server.build_api_payload()``——
  同一份 DB、同一套聚合实现（告警/Incident/时间线/TOP IP），
  "看板"与"报告"只是同一数据的两种消费形态（实时态势 vs 事后交付），
  避免两套聚合代码各漂各的（DRY，也是单一定义源的设计纪律）。
- **图表渲染位置的分工**：看板图表由前端 JS 画（数据驱动、可交互）；
  报告图表由服务端直接产出静态 SVG（报告是一次性产物，无需交互，
  且禁用 JS 的环境里也能看——内网隔离机的常见约束）。
- **报告生成器自己不能是 XSS 载体**：所有来自 DB 的用户可控字段
  （IP、告警标题、日志原文）进 HTML 前一律 ``html.escape``——
  安全工具的自我要求：被分析的数据本身可能是攻击载荷。
- **可解释性**：报告末尾附"检测规则清单"（本报告的结论由哪些规则、
  什么窗口/阈值得出）——审计类系统的基本要求，告警必须能回溯到规则。

用法：
    python cli.py report --db sentinelwatch.db --out report.html
    浏览器打开 report.html；Ctrl+P 可另存为 PDF（打印样式已适配）。
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from engine.detector import load_rules, load_rules_dir
from models import Alert
from storage import Storage
from web.server import build_api_payload

_DEFAULT_RULES = str(Path(__file__).parent / "rules")

_SEV_LABEL = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}
_SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c",
              "medium": "#d97706", "low": "#2563eb"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_CSS = """
:root {
  --blue: #2563eb; --blue-dark: #1e40af; --blue-bg: #eff6ff;
  --purple: #7c3aed; --purple-bg: #f5f3ff;
  --ink: #1e293b; --ink-soft: #64748b; --line: #dbeafe; --card: #ffffff;
  --crit: #dc2626; --high: #ea580c; --med: #d97706; --low: #2563eb;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  background: linear-gradient(180deg, #f8fafc 0%, #eff6ff 100%);
  color: var(--ink); min-height: 100vh; padding: 24px;
}
.wrap { max-width: 1080px; margin: 0 auto; }
header { display: flex; align-items: baseline; gap: 14px; margin-bottom: 4px; }
header h1 { font-size: 24px; color: var(--blue-dark); letter-spacing: .5px; }
header .sub { color: var(--ink-soft); font-size: 13px; }
header .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--purple); }
.meta { color: var(--ink-soft); font-size: 12px; margin-bottom: 20px; line-height: 1.7; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 18px; }
.card {
  background: var(--card); border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 18px; box-shadow: 0 1px 3px rgba(37, 99, 235, .06);
}
.card .label { font-size: 12px; color: var(--ink-soft); margin-bottom: 6px; }
.card .value { font-size: 28px; font-weight: 700; color: var(--blue); }
.card.accent .value { color: var(--purple); }
.charts { display: grid; grid-template-columns: 3fr 2fr; gap: 14px; margin-bottom: 18px; }
.panel {
  background: var(--card); border: 1px solid var(--line); border-radius: 12px;
  padding: 16px 18px; margin-bottom: 18px;
  box-shadow: 0 1px 3px rgba(37, 99, 235, .06);
}
.panel h2 { font-size: 15px; color: var(--blue-dark); margin-bottom: 12px;
            display: flex; align-items: center; gap: 8px; }
.panel h2::before { content: ""; width: 4px; height: 14px; border-radius: 2px; background: var(--purple); }
svg { width: 100%; height: auto; display: block; }
.axis { font-size: 11px; fill: var(--ink-soft); }
.grid-line { stroke: var(--line); stroke-width: 1; }
.line-path { fill: none; stroke: var(--blue); stroke-width: 2.5; stroke-linejoin: round; }
.line-area { fill: url(#areaGrad); opacity: .35; }
.bar { fill: var(--blue); }
.bar.top { fill: var(--purple); }
.bar-label { font-size: 11px; fill: var(--ink); }
.pills { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.pill { font-size: 12px; padding: 2px 10px; border-radius: 999px; color: #fff; }
.pill.rule { background: var(--blue); }
.dist-row { font-size: 13px; margin-bottom: 12px; }
.dist-row .k { color: var(--ink-soft); margin-right: 8px; }
.incident {
  border-left: 4px solid var(--blue); background: var(--blue-bg);
  border-radius: 8px; padding: 10px 14px; margin-bottom: 10px;
}
.incident.high, .incident.critical { border-left-color: var(--high); background: #fff7ed; }
.incident .t { font-weight: 600; font-size: 14px; }
.incident .s { font-size: 12px; color: var(--ink-soft); margin-top: 2px; }
.incident .members { font-size: 12px; color: var(--ink-soft); margin-top: 6px; }
.incident .members code { background: #fff; border: 1px solid var(--line);
  border-radius: 4px; padding: 1px 6px; margin-right: 6px; color: var(--blue-dark); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: var(--ink-soft); font-weight: 500; padding: 8px 10px;
     border-bottom: 2px solid var(--line); white-space: nowrap; }
td { padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
.badge { font-size: 11px; color: #fff; border-radius: 4px; padding: 2px 8px; white-space: nowrap; }
.badge.critical { background: var(--crit); } .badge.high { background: var(--high); }
.badge.medium { background: var(--med); } .badge.low { background: var(--low); }
.empty { color: var(--ink-soft); text-align: center; padding: 30px 0; font-size: 14px; }
.footer { color: var(--ink-soft); font-size: 12px; text-align: center;
          margin-top: 22px; line-height: 1.8; }
code.k { background: var(--blue-bg); border: 1px solid var(--line); border-radius: 4px;
         padding: 1px 6px; font-size: 12px; color: var(--blue-dark); }
@media print {
  @page { size: A4; margin: 12mm; }
  body { background: #fff; padding: 0; }
  .panel, .card { box-shadow: none; break-inside: avoid; }
  .charts { break-inside: avoid; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
@media (max-width: 900px) { .cards, .charts { grid-template-columns: 1fr 1fr; } }
"""


# ---------------------------------------------------------------- 数据组装

def _esc(s) -> str:
    """所有入库字段进 HTML 前必须转义——报告生成器自己不能是 XSS 载体。"""
    return html.escape(str(s if s is not None else ""))


def _rule_inventory(rules_dir: str | None) -> list[dict]:
    """加载规则清单（报告的可解释性依据：结论由哪些规则、什么阈值得出）。"""
    rules_dir = rules_dir or _DEFAULT_RULES
    path = Path(rules_dir)
    rules = load_rules_dir(path) if path.is_dir() else load_rules(path)
    return [{
        "id": r.id, "name": r.name, "severity": r.severity,
        "description": r.description, "event_types": "/".join(r.event_types),
        "window_seconds": r.window_seconds, "threshold": r.threshold,
    } for r in rules]


def build_report_data(db_path: str, title: str | None = None,
                      rules_dir: str | None = None) -> dict:
    """一次查询算出报告需要的全部数据（复用看板聚合，单一定义源）。"""
    payload = build_api_payload(db_path)

    storage = Storage(db_path)
    try:
        event_stats = storage.event_stats()
    finally:
        storage.close()

    starts = [a["window_start"] for a in payload["alerts"] if a.get("window_start")]
    ends = [a["window_end"] for a in payload["alerts"] if a.get("window_end")]

    # 报告按严重度排序（交付物的阅读顺序：最要紧的在前）；
    # 看板按时间倒序（态势感知：最新的在前）——同一数据、不同消费形态。
    alerts = sorted(
        payload["alerts"],
        key=lambda a: (_SEV_ORDER.get(a["severity"], 9), a.get("window_end") or ""),
    )

    return {
        "title": title or "SentinelWatch 安全告警报告",
        "generated_at": payload["generated_at"],
        "db_path": str(db_path),
        "stats": payload["stats"],
        "event_stats": event_stats,
        "time_range": {
            "first": min(starts) if starts else None,
            "last": max(ends) if ends else None,
        },
        "timeline": payload["timeline"],
        "top_ips": payload["top_ips"],
        "incidents": payload["incidents"],
        "alerts": alerts,
        "rules": _rule_inventory(rules_dir),
    }


# ---------------------------------------------------------------- SVG 图表（服务端静态渲染）

def _svg_timeline(points: list[dict]) -> str:
    """告警时间线折线图（与看板同款几何：宽 640 高 240）。"""
    W, H = 640, 240
    P = {"l": 36, "r": 12, "t": 14, "b": 26}
    iw, ih = W - P["l"] - P["r"], H - P["t"] - P["b"]
    if not points:
        return (f'<text x="{W/2}" y="{H/2}" text-anchor="middle" '
                f'class="axis">暂无告警</text>')
    max_n = max(p["n"] for p in points)

    def x(i: int) -> float:
        return P["l"] + (iw / 2 if len(points) == 1 else i * iw / (len(points) - 1))

    def y(v: int) -> float:
        return P["t"] + ih - (v / max_n) * ih

    grid = "".join(
        f'<line x1="{P["l"]}" y1="{gy:.1f}" x2="{W-P["r"]}" y2="{gy:.1f}" class="grid-line"/>'
        f'<text x="{P["l"]-6}" y="{gy+4:.1f}" text-anchor="end" class="axis">'
        f'{round(max_n*g/4)}</text>'
        for g, gy in ((g, P["t"] + ih - g * ih / 4) for g in range(5))
    )
    path = "".join(f'{"L" if i else "M"}{x(i):.1f},{y(p["n"]):.1f}'
                   for i, p in enumerate(points))
    area = (f'{path} L{x(len(points)-1):.1f},{P["t"]+ih:.1f} '
            f'L{x(0):.1f},{P["t"]+ih:.1f} Z')
    dots = "".join(
        f'<circle cx="{x(i):.1f}" cy="{y(p["n"]):.1f}" r="3" fill="#2563eb">'
        f'<title>{_esc(p["t"])} — {p["n"]} 条</title></circle>'
        for i, p in enumerate(points))
    labels = "".join(
        f'<text x="{x(i):.1f}" y="{H-8}" text-anchor="middle" class="axis">'
        f'{_esc(p["t"])}</text>'
        for i, p in enumerate(points))
    return (f'<defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0%" stop-color="#2563eb"/>'
            f'<stop offset="100%" stop-color="#7c3aed"/></linearGradient></defs>'
            f'{grid}<path d="{area}" class="line-area"/>'
            f'<path d="{path}" class="line-path"/>{dots}{labels}')


def _svg_top_ips(rows: list[dict]) -> str:
    """TOP 源 IP 柱状图（宽 400 高 240；第一名紫色高亮——与看板一致）。"""
    W, H = 400, 240
    P = {"l": 36, "r": 10, "t": 14, "b": 40}
    iw, ih = W - P["l"] - P["r"], H - P["t"] - P["b"]
    if not rows:
        return (f'<text x="{W/2}" y="{H/2}" text-anchor="middle" '
                f'class="axis">暂无数据</text>')
    max_n = max(r["n"] for r in rows)
    bw = iw / len(rows)
    bars = ""
    for i, r in enumerate(rows):
        bh = (r["n"] / max_n) * ih
        bx = P["l"] + i * bw + bw * 0.18
        by = P["t"] + ih - bh
        label = r["ip"]
        label = label if len(label) <= 14 else label[:13] + "…"
        bars += (f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw*0.64:.1f}" '
                 f'height="{bh:.1f}" rx="3" class="bar{" top" if i == 0 else ""}">'
                 f'<title>{_esc(r["ip"])} — {r["n"]} 条</title></rect>'
                 f'<text x="{bx + bw*0.32:.1f}" y="{by-5:.1f}" text-anchor="middle" '
                 f'class="bar-label">{r["n"]}</text>'
                 f'<text x="{bx + bw*0.32:.1f}" y="{H-24}" text-anchor="middle" '
                 f'class="axis">{_esc(label)}</text>')
    return (f'<line x1="{P["l"]}" y1="{P["t"]+ih:.1f}" x2="{W-P["r"]}" '
            f'y2="{P["t"]+ih:.1f}" class="grid-line"/>{bars}')


# ---------------------------------------------------------------- HTML 渲染

def _pills(by: dict, css_class: str = "") -> str:
    if not by:
        return '<span class="empty" style="padding:4px 0">无</span>'
    return "".join(
        f'<span class="pill {css_class}">{_esc(k)} ×{v}</span>'
        for k, v in sorted(by.items(), key=lambda kv: -kv[1]))


def _sev_pills(by_severity: dict) -> str:
    if not by_severity:
        return '<span class="empty" style="padding:4px 0">无</span>'
    return "".join(
        f'<span class="pill" style="background:{_SEV_COLOR.get(k, "#64748b")}">'
        f'{_SEV_LABEL.get(k, k)} {v}</span>'
        for k, v in sorted(by_severity.items(),
                           key=lambda kv: _SEV_ORDER.get(kv[0], 9)))


def _incidents_html(incidents: list[dict]) -> str:
    if not incidents:
        return '<div class="empty">暂无关联事件</div>'
    return "".join(
        f'<div class="incident {i["severity"]}">'
        f'<div class="t"><span class="badge {i["severity"]}">'
        f'{_SEV_LABEL.get(i["severity"], i["severity"])}</span>&nbsp;{_esc(i["title"])}</div>'
        f'<div class="s">{_esc(i["summary"])}</div>'
        f'<div class="members">'
        + "".join(f'<code>{_esc(r)}</code>' for r in i["rules"])
        + f'</div><div class="members">首次 {_esc((i["first_seen"] or "")[:19])}'
          f' ｜ 末次 {_esc((i["last_seen"] or "")[:19])}'
          f' ｜ 涉及事件 {i["total_events"]} 次</div></div>'
        for i in incidents)


def _alerts_table(alerts: list[dict]) -> str:
    if not alerts:
        return '<div class="empty">暂无告警——先导入日志或执行 FIM 扫描</div>'
    rows = "".join(
        f'<tr><td><span class="badge {a["severity"]}">'
        f'{_SEV_LABEL.get(a["severity"], a["severity"])}</span></td>'
        f'<td>{_esc(a["rule_name"])}</td><td>{_esc(a["title"])}</td>'
        f'<td>{_esc(a["source_ip"] or "本机")}</td><td>{a["event_count"]}</td>'
        f'<td style="white-space:nowrap">{_esc((a["window_start"] or "")[:19])}<br>'
        f'{_esc((a["window_end"] or "")[:19])}</td>'
        f'<td style="color:var(--ink-soft)">{_esc(a["detail"])}</td></tr>'
        for a in alerts)
    return ('<table><thead><tr><th>严重度</th><th>规则</th><th>标题</th>'
            '<th>来源</th><th>事件数</th><th>时间窗</th><th>判定依据</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')


def _rules_table(rules: list[dict]) -> str:
    if not rules:
        return '<div class="empty">未加载到规则</div>'
    rows = "".join(
        f'<tr><td><code class="k">{_esc(r["id"])}</code></td><td>{_esc(r["name"])}</td>'
        f'<td><span class="badge {r["severity"]}">'
        f'{_SEV_LABEL.get(r["severity"], r["severity"])}</span></td>'
        f'<td>{_esc(r["event_types"])}</td>'
        f'<td>{r["window_seconds"]}s / ≥{r["threshold"]}</td>'
        f'<td style="color:var(--ink-soft)">{_esc(r["description"])}</td></tr>'
        for r in rules)
    return ('<table><thead><tr><th>规则 ID</th><th>名称</th><th>级别</th>'
            '<th>事件类型</th><th>窗口/阈值</th><th>说明</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>')


def render_html(data: dict) -> str:
    """数据 → 完整 HTML 文档（内联 CSS 与 SVG，零外部引用、零 JS）。"""
    stats = data["stats"]
    tr = data["time_range"]
    span = (f'{tr["first"][:19]} ~ {tr["last"][:19]}'
            if tr["first"] and tr["last"] else "无告警数据")
    max_sev = min(stats["by_severity"], key=lambda s: _SEV_ORDER.get(s, 9)) \
        if stats["by_severity"] else None
    events_total = sum(data["event_stats"].values())
    event_desc = "，".join(f"{k} {v}" for k, v in sorted(data["event_stats"].items()))

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(data["title"])}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="dot"></span>
    <h1>{_esc(data["title"])}</h1>
    <span class="sub">SentinelWatch · 主机日志审计与入侵检测</span>
  </header>
  <div class="meta">
    生成时间：{_esc(data["generated_at"])} ｜ 数据源：<code class="k">{_esc(data["db_path"])}</code><br>
    告警 {stats["total_alerts"]} 条 ｜ 聚合事件 {stats["total_incidents"]} 起 ｜
    数据时间范围：{span} ｜ 原始事件 {events_total} 条（{event_desc or "无"}）
  </div>

  <div class="cards">
    <div class="card"><div class="label">告警总数</div>
      <div class="value">{stats["total_alerts"]}</div></div>
    <div class="card accent"><div class="label">聚合事件（Incident）</div>
      <div class="value">{stats["total_incidents"]}</div></div>
    <div class="card"><div class="label">最高严重度</div>
      <div class="value" style="font-size:22px;padding-top:4px">
        {f'<span class="badge {max_sev}">{_SEV_LABEL.get(max_sev, max_sev)}</span>' if max_sev else "—"}
      </div></div>
    <div class="card"><div class="label">原始事件（告警原料）</div>
      <div class="value">{events_total}</div></div>
  </div>

  <div class="charts">
    <div class="panel"><h2>告警时间线（按分钟）</h2>
      <svg viewBox="0 0 640 240" role="img" aria-label="告警时间线折线图">{_svg_timeline(data["timeline"])}</svg></div>
    <div class="panel"><h2>TOP 攻击源 IP</h2>
      <svg viewBox="0 0 400 240" role="img" aria-label="TOP 源 IP 柱状图">{_svg_top_ips(data["top_ips"])}</svg></div>
  </div>

  <div class="panel">
    <h2>告警分布</h2>
    <div class="dist-row"><span class="k">按严重度</span>{_sev_pills(stats["by_severity"])}</div>
    <div class="dist-row"><span class="k">按规则</span>{_pills(stats["by_rule"], "rule")}</div>
  </div>

  <div class="panel">
    <h2>关联事件（聚合 Incident）</h2>
    {_incidents_html(data["incidents"])}
  </div>

  <div class="panel">
    <h2>告警明细</h2>
    {_alerts_table(data["alerts"])}
  </div>

  <div class="panel">
    <h2>检测规则清单（本报告结论的可解释性依据）</h2>
    {_rules_table(data["rules"])}
  </div>

  <div class="footer">
    本报告由 SentinelWatch 自动生成 · 数据只读自 SQLite，未做任何修改<br>
    防御方工具——请仅用于分析你有权查看的日志；浏览器 Ctrl+P 可另存为 PDF
  </div>
</div>
</body>
</html>
"""


def export_report(db_path: str, out_path: str, title: str | None = None,
                  rules_dir: str | None = None) -> Path:
    """生成 HTML 报告并写盘，返回输出路径。"""
    db = Path(db_path)
    if not db.exists():
        raise SystemExit(f"数据库不存在: {db}（先运行 cli.py import 导入日志生成数据）")
    data = build_report_data(db, title=title, rules_dir=rules_dir)
    out = Path(out_path)
    out.write_text(render_html(data), encoding="utf-8")
    return out
