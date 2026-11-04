"""命令行入口：导入日志/流量 → 入库 → 执行规则 → 输出告警；另支持 FIM 扫描与看板服务。

用法：
    python cli.py import --log tests/sample_auth.log --db sentinelwatch.db --reset
    python cli.py traffic --pcap tests/fixtures/traffic_demo.pcap --db sentinelwatch.db
    python cli.py fim --dir ./rules --baseline fim_baseline.json --db sentinelwatch.db
    python cli.py serve --db sentinelwatch.db --port 8080
    python cli.py report --db sentinelwatch.db --out report.html

数据链路（与 SIEM 一致，面试可讲）：
    采集(collectors: auth_log / app_log / pcap) → 解析 → 规则匹配( engine/detector )
    → 存储( storage: events + alerts ) → 展示( web 看板 / 本 CLI )

v1.2 的关键点：三种采集器产出的是**同一种事件模型**，所以下面这条链路
对日志和流量完全一样——规则、存储、看板、报告一行没改。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from collectors.auth_log import parse_file
from engine.detector import load_rules, load_rules_dir, run_rules
from storage import Storage

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_DEFAULT_RULES = str(Path(__file__).parent / "rules")


def _load_rules(rules_path: str | None):
    rules_path = rules_path or _DEFAULT_RULES
    if Path(rules_path).is_dir():
        rules = load_rules_dir(rules_path)
    else:
        rules = load_rules(rules_path)
    if not rules:
        print(f"[!] 未加载到任何规则（{rules_path}）", file=sys.stderr)
        return None
    return rules


def _parse_log(path: str, fmt: str):
    """按格式选择解析器（v1.0：auth=领域解析，app=保底解析）。"""
    if fmt == "app":
        from collectors.app_log import parse_file as _parse
    else:
        _parse = parse_file          # 顶部导入的 auth_log 解析器
    return _parse(path)


def _run_intel(events, iocs_path: str | None):
    """情报匹配（可选）：把命中转换成标准 Alert，并入现有告警链路。

    与规则检测并列作为「第三层」：规则抓行为模式与已知签名，情报抓已知恶意实体
    （C2 IP / 钓鱼域名 / 恶意样本哈希）。产出同一种 Alert 的好处是——
    存储、看板、HTML 报告、抑制器全都不用改。
    """
    if not iocs_path:
        return [], 0

    from intel import IOCSet, match_events

    iocs = IOCSet()
    loaded = 0
    for p in str(iocs_path).split(","):
        p = p.strip()
        if not p:
            continue
        loaded += iocs.load_file(p)
    if len(iocs) == 0:
        print(f"[!] 情报集合为空: {iocs_path}", file=sys.stderr)
        return [], 0
    return match_events(events, iocs), loaded


def _store_and_detect(args, events, rules) -> int:
    """事件入库 → 规则匹配 → 告警入库 → 打印（日志与流量共用这一条链路）。"""
    storage = Storage(args.db)
    try:
        if args.reset:
            storage.reset()
        storage.insert_events(events)
        alerts = run_rules(events, rules)
        # 情报层（可选）：命中产出同一种 Alert，并入同一张表
        ioc_alerts, ioc_loaded = _run_intel(events, getattr(args, "iocs", None))
        alerts.extend(ioc_alerts)
        storage.insert_alerts(alerts)
    finally:
        storage.close()

    stats: dict[str, int] = {}
    for e in events:
        stats[e.event_type] = stats.get(e.event_type, 0) + 1
    print(f"[*] 解析事件 {len(events)} 条：" +
          "，".join(f"{k} {v}" for k, v in sorted(stats.items())))
    print(f"[*] 加载规则 {len(rules)} 条，数据库 {args.db}")
    if ioc_loaded:
        print(f"[*] 加载情报 {ioc_loaded} 条，IOC 命中 {len(ioc_alerts)} 条")
    return _print_alerts(alerts)


def cmd_import(args) -> int:
    """导入日志：解析 → 入库 → 规则匹配 → 告警入库。"""
    rules = _load_rules(args.rules)
    if rules is None:
        return 1

    events = _parse_log(args.log, args.format)
    if not events:
        print(f"[!] 未从 {args.log} 解析出任何事件", file=sys.stderr)
        return 1
    return _store_and_detect(args, events, rules)


def cmd_traffic(args) -> int:
    """导入 PCAP 流量：TCP 重组 + HTTP 还原 → 入库 → 规则匹配（v1.2）。

    与 import 的唯一区别是采集器：logs 进 events，traffic 也进 events，
    后面全是同一套代码——这正是"检测特征与数据源解耦"的验证点。
    """
    from collectors.pcap import PcapError, parse_file as parse_pcap

    rules = _load_rules(args.rules)
    if rules is None:
        return 1

    try:
        events = parse_pcap(args.pcap)
    except PcapError as exc:
        print(f"[!] PCAP 格式问题: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[!] 读取失败: {exc}", file=sys.stderr)
        return 1

    if not events:
        print(f"[!] 未从 {args.pcap} 还原出任何 HTTP 请求——可能原因："
              f"① 只有 HTTPS（加密流量看不到明文）；② 文件是 pcapng 格式"
              f"（先用 `tcpdump -r in.pcapng -w out.pcap` 转换）；"
              f"③ 抓包接口类型不受支持（支持 Ethernet / Raw IP / Linux SLL）",
              file=sys.stderr)
        return 1
    return _store_and_detect(args, events, rules)


def cmd_fim(args) -> int:
    """文件完整性扫描：无基线则建立基线；有基线则对比并告警。"""
    from fim import (scan_directory, load_baseline, save_baseline,
                     compare_baseline, changes_to_alerts)

    root = Path(args.dir).resolve()
    if not root.is_dir():
        print(f"[!] 目录不存在: {root}", file=sys.stderr)
        return 1

    baseline_path = Path(args.baseline).resolve()
    # 经典事故防护：基线文件若放在被监控目录内，每次刷新基线都会把自己
    # 算成"新增文件"，监控永远对不上——基线必须在监控树之外。
    if baseline_path.is_relative_to(root):
        print(f"[!] 基线文件 {baseline_path} 位于被监控目录 {root} 内——"
              f"刷新基线会把基线自己算成新增文件。请把 --baseline 放到监控目录外。",
              file=sys.stderr)
        return 1

    old = load_baseline(baseline_path)
    current = scan_directory(root)
    save_baseline(current, baseline_path)      # 基线始终刷新为最新状态

    if not old:
        print(f"[*] 已建立基线: {len(current)} 个文件 → {baseline_path}")
        print("[*] 再次运行同一命令即可检测变更（修改/新增/删除）")
        return 0

    changes = compare_baseline(old, current)
    if not changes:
        print(f"[*] 完整性校验通过：{len(current)} 个文件与基线一致")
        return 0

    alerts = changes_to_alerts(changes, str(root))
    storage = Storage(args.db)
    try:
        storage.insert_alerts(alerts)
    finally:
        storage.close()
    print(f"[!] 检测到 {len(changes)} 个文件变更（已写入 {args.db}）：")
    return _print_alerts(alerts)


def cmd_serve(args) -> int:
    """启动 Web 看板（默认只绑 127.0.0.1，安全工具不默认对外暴露）。"""
    from web.server import serve
    serve(args.db, host=args.host, port=args.port)
    return 0


def cmd_report(args) -> int:
    """导出 HTML 告警报告（事后交付物：与看板同一份 DB、同一套聚合）。"""
    from report import export_report
    out = export_report(args.db, args.out, title=args.title, rules_dir=args.rules)
    print(f"[*] 报告已生成: {out.resolve()}")
    print("[*] 浏览器打开即可查看；Ctrl+P 可另存为 PDF（打印样式已适配）")
    return 0


def _print_alerts(alerts) -> int:
    if not alerts:
        print("[*] 未产生告警。")
        return 0
    alerts = sorted(alerts, key=lambda a: _SEV_ORDER.get(a.severity, 9))
    print(f"[!] 产生 {len(alerts)} 条告警：")
    for a in alerts:
        print(f"    [{a.severity.upper():8}] {a.title}")
        print(f"               {a.detail}")
        print(f"               窗口 {a.window_start} ~ {a.window_end}"
              f"（{a.event_count} 次）")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="SentinelWatch — 主机日志审计与入侵检测（防御方工具，"
                    "仅用于分析你有权查看的日志）")
    sub = ap.add_subparsers(dest="command", required=True)

    p_imp = sub.add_parser("import", help="导入日志并执行检测规则")
    p_imp.add_argument("--log", required=True, help="日志文件路径")
    p_imp.add_argument("--format", choices=["auth", "app"], default="auth",
                       help="auth=auth.log 领域解析（默认）；app=通用应用日志保底解析")
    p_imp.add_argument("--db", default="sentinelwatch.db", help="SQLite 数据库路径")
    p_imp.add_argument("--rules", default=None,
                       help="规则 YAML 文件或目录（默认使用项目 rules/ 目录）")
    p_imp.add_argument("--reset", action="store_true", help="导入前清空数据库")
    p_imp.add_argument("--iocs", default=None,
                       help="威胁情报文件（csv/json/txt，多个用逗号分隔）；命中产出 IOC-* 告警")
    p_imp.set_defaults(func=cmd_import)

    p_tr = sub.add_parser("traffic", help="导入 PCAP 流量并执行检测规则（v1.2）")
    p_tr.add_argument("--pcap", required=True,
                      help="PCAP 文件路径（libpcap 格式；HTTPS 与 pcapng 不支持）")
    p_tr.add_argument("--db", default="sentinelwatch.db", help="SQLite 数据库路径")
    p_tr.add_argument("--rules", default=None,
                      help="规则 YAML 文件或目录（默认使用项目 rules/ 目录）")
    p_tr.add_argument("--reset", action="store_true", help="导入前清空数据库")
    p_tr.add_argument("--iocs", default=None,
                      help="威胁情报文件（csv/json/txt，多个用逗号分隔）")
    p_tr.set_defaults(func=cmd_traffic)

    p_fim = sub.add_parser("fim", help="文件完整性监控（基线/对比）")
    p_fim.add_argument("--dir", required=True, help="被监控目录")
    p_fim.add_argument("--baseline", default="fim_baseline.json", help="基线 JSON 路径")
    p_fim.add_argument("--db", default="sentinelwatch.db", help="SQLite 数据库路径")
    p_fim.set_defaults(func=cmd_fim)

    p_srv = sub.add_parser("serve", help="启动 Web 看板服务")
    p_srv.add_argument("--db", default="sentinelwatch.db", help="SQLite 数据库路径")
    p_srv.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅回环）")
    p_srv.add_argument("--port", type=int, default=8080, help="监听端口")
    p_srv.set_defaults(func=cmd_serve)

    p_rep = sub.add_parser("report", help="导出 HTML 告警报告（Ctrl+P 可另存 PDF）")
    p_rep.add_argument("--db", default="sentinelwatch.db", help="SQLite 数据库路径")
    p_rep.add_argument("--out", default="sentinelwatch_report.html", help="输出 HTML 路径")
    p_rep.add_argument("--title", default=None, help="报告标题（默认：SentinelWatch 安全告警报告）")
    p_rep.add_argument("--rules", default=None,
                       help="规则 YAML 文件或目录（默认使用项目 rules/ 目录，"
                            "用于在报告末尾附规则清单）")
    p_rep.set_defaults(func=cmd_report)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
