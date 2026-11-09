#!/usr/bin/env python3
"""窗口频次判据的**独立评测**（v1.7 / Brute Force 补强）。

为什么单独一个脚本，而不是塞进 run_benchmark.py
------------------------------------------------
逐请求混淆矩阵和窗口聚合告警是**两种粒度**：

    逐请求：「这一条请求该不该告警」→ TP / FN / FP / TN 有意义
    窗口级：「这段时间、这个 IP 的行为该不该告警」→ 只能问「这条告警对不对」

一次爆破的 200 条登录请求，无法逐条标注「哪条该告警」——它们合起来
才构成一次攻击。硬把窗口告警摊进逐请求矩阵，会同时毁掉两个指标。
所以主评测 `run_benchmark.py` 的混淆矩阵**一行不改**，本脚本只产出
告警级的 TP / FP 与「改进前 / 改进后」对照。

阈值怎么定（不背数据集）
-----------------------
阈值不是照着周四的攻击流量调出来的。做法是：

1. 在**周一 + 周二两个官方标注为全良性的工作日**上，量出「同一源 IP
   在 60 秒滑动窗口内访问登录端点的最大次数」；
2. 取一个明显留有余量、且是整数的阈值；
3. 再拿周四的攻击日验证，并同时统计周一/周二是否产生告警级误报。

`--calibrate` 只做第 1 步；`--threshold` 是标定/敏感性分析用的覆盖值，
正式评测一律用 `rules/http_brute_force.yaml` 里写死的值。

用法
----
    # 标定（纯良性语料，只看突发分布，不产出告警）
    python bench/run_frequency.py --pcap <Monday.pcap> \
        --labels bench/labels/cic_ids2017_monday_benign.json --calibrate

    # 正式评测（窗口告警级）
    python bench/run_frequency.py --pcap <Thursday.pcap> \
        --labels bench/labels/cic_ids2017_thursday_web.json \
        --out bench/results/cic_ids2017_thursday_frequency.md
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench.run_benchmark import Labels, _human_bytes  # noqa: E402
from collectors.pcap import iter_events  # noqa: E402
from engine.detector import _group_key, _matches, load_rules_dir, run_rules  # noqa: E402

DEFAULT_LABELS = ROOT / "bench" / "labels" / "cic_ids2017_thursday_web.json"
DEFAULT_RULES = ROOT / "rules"


def frequency_rules(rules_dir: Path) -> list:
    """只取「吃 HTTP 请求、有签名过滤、且是窗口聚合」的规则。

    `threshold == 1` 的是签名规则（逐请求粒度），它们归主评测管；
    SSH 的两条阈值规则不吃 http_request，这里也排除。
    """
    return [r for r in load_rules_dir(rules_dir)
            if "http_request" in r.event_types
            and r.threshold > 1
            and r.match]


def collect_matching(pcap: Path, rules: list,
                     progress_every: int = 200000) -> tuple[int, list]:
    """流式扫一遍 PCAP，只把命中频次规则 `match` 的事件攒下来。

    为什么要攒：生产逻辑 `engine.detector.run_rules()` 是批式接口。
    登录端点请求只占全天 HTTP 请求的一小部分（周四全量是 5,582/56,110），
    攒这一小撮是常量级内存；**直接复用生产窗口实现**比在评测脚本里
    另写一套滑动窗口更可靠——两套实现早晚会算出不一样的数。
    """
    picked: list = []
    total = 0
    for i, event in enumerate(iter_events(pcap), 1):
        total += 1
        for rule in rules:
            if (event.event_type in rule.event_types
                    and rule.match and _matches(event, rule.match)):
                picked.append(event)
                break
        if progress_every and i % progress_every == 0:
            print(f"  ... 已扫描 {i} 条 HTTP 请求", file=sys.stderr)
    return total, picked


def max_bursts(events: list, window_seconds: int,
               group_fields: tuple[str, ...]) -> dict[tuple, int]:
    """每个分组在任意滑动窗口内的**峰值次数**（仅用于阈值标定）。

    这是分析代码，不参与判定；判定仍然只由 `run_rules()` 做。
    窗口语义与 `run_rules()` 一致：闭区间 [t-W, t]，超过 W 才遗忘。
    """
    groups: dict[tuple, list] = {}
    for e in events:
        groups.setdefault(_group_key(e, group_fields), []).append(e)
    peaks: dict[tuple, int] = {}
    for key, group in groups.items():
        group.sort(key=lambda e: e.ts)
        window: deque = deque()
        peak = 0
        for e in group:
            while window and (e.ts - window[0].ts).total_seconds() > window_seconds:
                window.popleft()
            window.append(e)
            peak = max(peak, len(window))
        peaks[key] = peak
    return peaks


def _overlaps(alert, window) -> bool:
    """告警时间区间与标注窗是否相交（两侧都换算 epoch，与机器时区无关）。"""
    a0 = alert.window_start.timestamp()
    a1 = alert.window_end.timestamp()
    return a0 <= window.end_epoch and a1 >= window.start_epoch


@dataclass
class FrequencyResult:
    dataset: str
    pcap: str
    pcap_bytes: int
    rule_id: str
    window_seconds: int
    threshold: int
    suppress_seconds: int
    total_requests: int
    matched_requests: int
    groups: int
    peak_burst: int
    peak_group: str
    bf_windows: int
    bf_requests: int
    alerts_total: int = 0
    alert_tp: int = 0
    alert_fp: int = 0
    bf_alerts: int = 0
    bf_windows_covered: int = 0
    seconds: float = 0.0
    samples: list = None

    @property
    def alert_precision(self) -> float:
        d = self.alert_tp + self.alert_fp
        return self.alert_tp / d if d else 0.0


def evaluate(pcap: Path, labels: Labels, rules_dir: Path = DEFAULT_RULES,
             threshold: int | None = None, calibrate: bool = False,
             progress_every: int = 200000) -> FrequencyResult:
    rules = frequency_rules(rules_dir)
    if not rules:
        raise SystemExit("没有找到 HTTP 频次规则（检查 rules/ 目录）")
    if threshold is not None:
        rules = [replace(r, threshold=threshold) for r in rules]
    if len(rules) > 1:
        # 目前只有一条；显式拒绝多规则是为了避免「两条规则各报一次」被
        # 当成两次检出，指标悄悄翻倍而没人发现。
        raise SystemExit("本评测一次只支持一条频次规则，请在 --rules 里指定单文件")

    rule = rules[0]
    bf_windows = [w for w in labels.windows if "Brute Force" in w.attack]
    bf_epochs = [(w.start_epoch, w.end_epoch, set(w.src_ips)) for w in bf_windows]

    t0 = time.perf_counter()
    total, picked = collect_matching(pcap, [rule], progress_every)
    peaks = max_bursts(picked, rule.window_seconds, rule.group_by)
    peak_group, peak_value = ("", 0)
    if peaks:
        peak_group, peak_value = max(peaks.items(), key=lambda kv: kv[1])

    bf_requests = 0
    for e in picked:
        epoch = e.ts.timestamp()
        if any(a <= epoch <= b and e.ip in ips for a, b, ips in bf_epochs):
            bf_requests += 1

    result = FrequencyResult(
        dataset=labels.dataset,
        pcap=str(pcap),
        pcap_bytes=Path(pcap).stat().st_size,
        rule_id=rule.id,
        window_seconds=rule.window_seconds,
        threshold=rule.threshold,
        suppress_seconds=rule.suppress_seconds,
        total_requests=total,
        matched_requests=len(picked),
        groups=len(peaks),
        peak_burst=peak_value,
        peak_group=",".join(str(v) for v in peak_group),
        bf_windows=len(bf_windows),
        bf_requests=bf_requests,
        seconds=time.perf_counter() - t0,
        samples=[],
    )
    if calibrate:
        return result

    alerts = run_rules(picked, [rule])
    covered: set[int] = set()
    for alert in alerts:
        attacked = False
        bf_hit = False
        for idx, w in enumerate(labels.windows):
            if alert.source_ip in w.src_ips and _overlaps(alert, w):
                attacked = True
                if "Brute Force" in w.attack:
                    bf_hit = True
                    covered.add(idx)
        if attacked:
            result.alert_tp += 1
        else:
            result.alert_fp += 1
        if bf_hit:
            result.bf_alerts += 1
        if len(result.samples) < 8:
            result.samples.append({
                "start": alert.window_start.isoformat(sep=" "),
                "end": alert.window_end.isoformat(sep=" "),
                "ip": alert.source_ip,
                "count": alert.event_count,
                "verdict": "TP" if attacked else "FP",
                "bf": bf_hit,
            })
    result.alerts_total = len(alerts)
    result.bf_windows_covered = len(covered)
    return result


def render(result: FrequencyResult, labels: Labels, calibrate: bool) -> str:
    L = [
        f"# 窗口频次判据评测：{result.dataset}",
        "",
        f"- PCAP：`{result.pcap}`（{_human_bytes(result.pcap_bytes)}）",
        f"- 规则：`{result.rule_id}` — {result.window_seconds}s 滑动窗口 / "
        f"阈值 {result.threshold} 次 / 命中后静默 {result.suppress_seconds}s",
        f"- 扫描：全天 {result.total_requests} 条 HTTP 请求，其中命中登录端点 "
        f"{result.matched_requests} 条，涉及 {result.groups} 个源 IP",
        f"- 耗时 {result.seconds:.1f}s（单线程，含解析）",
        "",
        "> ⚠️ **粒度声明**：本报告的 TP/FP 是**告警（窗口）级**，"
        "不是逐请求级。它与 `bench/run_benchmark.py` 的混淆矩阵"
        "**不能相加、不能互相替换**。一次爆破的 N 条请求合起来才是一次攻击，"
        "逐条摊进矩阵会让两个指标同时失去意义。",
        "",
        "## 阈值标定依据（只看突发分布，不用攻击标签）",
        "",
        f"- 任一源 IP 在任意 {result.window_seconds}s 窗口内的**峰值**登录请求数："
        f"**{result.peak_burst}**（分组 `{result.peak_group}`）",
        f"- 本数据集标注口径：`{labels.label_granularity}`"
        + ("（全良性，无攻击窗）" if not labels.windows else
           f"（{len(labels.windows)} 个攻击窗，其中 Brute Force {result.bf_windows} 个）"),
        "",
    ]
    if calibrate:
        L += [
            "本次是 `--calibrate` 标定运行：**不产出告警，也不评估检出**。"
            "这个峰值只用来给阈值定下界，不参与任何判定。",
            "",
        ]
        return "\n".join(L)

    L += [
        "## 告警级结果（与主矩阵分开）",
        "",
        "| 指标 | 值 | 说明 |",
        "|---|---:|---|",
        f"| 产生告警 | {result.alerts_total} | 窗口级，静默期内不重复报 |",
        f"| 告警 TP | {result.alert_tp} | 告警区间与标注攻击窗相交、且源 IP 为该窗攻击源 |",
        f"| 告警 FP | {result.alert_fp} | 未与任何标注攻击窗相交（含全良性数据集上的全部告警）|",
        f"| 告警精确率 | "
        + ("—" if not result.alerts_total else f"{result.alert_precision:.2%}")
        + " | "
        + ("无告警，精确率无定义" if not result.alerts_total else "报出来的窗口告警里多少是真的")
        + " |",
        f"| 落在 Brute Force 窗的告警 | {result.bf_alerts} | 本次补强直接针对的攻击类型 |",
        f"| Brute Force 窗覆盖 | {result.bf_windows_covered}/{result.bf_windows} | "
        "每个标注窗至少有一条 TP 告警即算覆盖 |",
        f"| Brute Force 窗内登录请求 | {result.bf_requests} | "
        "改进前签名规则对它们的命中是 **0**，见 BENCHMARK.md §2.6 |",
        "",
        "## 告警样例（最多 8 条）",
        "",
    ]
    if result.samples:
        L += ["| 窗口起 | 窗口止 | 源 IP | 窗口内请求数 | 判定 | 落在 BF 窗 |",
              "|---|---|---|---:|---|---|"]
        for s in result.samples:
            L.append(f"| {s['start']} | {s['end']} | {s['ip']} | {s['count']} "
                     f"| {s['verdict']} | {'是' if s['bf'] else '否'} |")
    else:
        L.append("（无告警）")
    L += [
        "",
        "> 时间戳是采集器渲染的本地墙钟时间；与标注窗的相交判定"
        "统一在 epoch 上做，因此换时区不会改变结论。",
        "",
    ]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="评测 HTTP 登录频次窗口规则（告警级，与主混淆矩阵分开）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--labels", default=str(DEFAULT_LABELS))
    ap.add_argument("--rules", default=str(DEFAULT_RULES))
    ap.add_argument("--out", help="写一份 Markdown 报告到该路径")
    ap.add_argument("--json", action="store_true", help="同时把结果打印为 JSON")
    ap.add_argument("--threshold", type=int, help="覆盖规则阈值（仅标定/敏感性分析用）")
    ap.add_argument("--calibrate", action="store_true",
                    help="只统计良性突发分布，不产出告警")
    ap.add_argument("--progress-every", type=int, default=200000)
    args = ap.parse_args(argv)

    labels = Labels.load(Path(args.labels))
    result = evaluate(Path(args.pcap), labels, Path(args.rules),
                      args.threshold, args.calibrate, args.progress_every)
    print(render(result, labels, args.calibrate))
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render(result, labels, args.calibrate), encoding="utf-8")
        print(f"\n  → {out}")
    if args.json:
        print("\nJSON " + json.dumps({
            k: v for k, v in result.__dict__.items() if k != "samples"
        }, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
