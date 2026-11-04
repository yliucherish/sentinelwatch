#!/usr/bin/env python3
"""在第三方公开数据集上量 SentinelWatch 的流量检测层（任务 A）。

这个脚本存在的理由
------------------
自造的 8 包样本能证明"代码跑得通"，但证明不了"检测器好不好"——自己出题
自己答，永远满分。要拿外部的尺子量，才有说服力：

    检出率：第三方标注为攻击的请求，抓到了多少
    误报率：第三方标注为正常的请求，误报了多少
    吞吐：  单线程处理 PCAP 的 MB/s 与请求/s

标注口径（本脚本最重要的设计决定）
--------------------------------
数据集（如 CIC-IDS2017）的标签是**按流（flow）**打的，本工具产出的是**按
HTTP 请求**的事件。两者粒度不同，直接对齐会算错。所以本脚本不读数据集的
flow 标签，而是要求一份**自己写的标注文件**：`{时间窗, 攻击源 IP}`。

    落在某 attack_window 的时间范围内 且 源 IP 在该窗的 src_ips 里 → 应检出
    其余请求                                                      → 应放行

**口径是显式写出来的，不是猜的**——报告里必须原样印出来，否则数字没法被
别人复核。这也是为什么 `--labels` 是必填：没有口径的评测等于没有评测。

用法
----
    # 1. 先自检：用合成样本验证脚本本身是对的（不需要下载任何数据集）
    python bench/run_benchmark.py --self-test

    # 2. 再跑真实数据
    python bench/run_benchmark.py \
        --pcap data/Thursday-WorkingHours.pcap \
        --labels bench/labels/cic_ids2017_thursday_web.json \
        --out out/

数据集获取见 bench/DATASETS.md。
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.pcap import iter_events  # noqa: E402
from engine.detector import _matches, load_rules_dir  # noqa: E402

RULES_DIR = ROOT / "rules"
DEFAULT_LABELS = ROOT / "bench" / "labels" / "cic_ids2017_thursday_web.json"

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M")

# 明细 CSV 的列。显式写死而不是从第一行数据推：流式写入时没有"第一行"可推，
# 而且列序稳定才好写进文档、才好被别人用 pandas 直接读。
_ROW_FIELDS = ("ts", "src_ip", "method", "host", "uri",
               "expect", "attack", "hit_rules", "verdict")


def _parse_ts(text: str) -> datetime:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise ValueError(f"无法解析时间戳 {text!r}（支持 {_TS_FORMATS}）")


@dataclass
class AttackWindow:
    start: datetime
    end: datetime
    src_ips: tuple[str, ...]
    attack: str

    def covers(self, event) -> bool:
        return self.start <= event.ts <= self.end


@dataclass
class Labels:
    dataset: str
    source: str
    label_granularity: str
    windows: list[AttackWindow] = field(default_factory=list)
    notes: str = ""
    shift_hours: float = 0.0
    # 攻击机 IP，**按它在抓包里实际出现的样子**记。
    # CIC-IDS2017 的抓包点在防火墙内侧，外网攻击者的源 IP 已被 NAT 改写成网关
    # 地址（172.16.0.1），文档里写的 205.174.165.73 在 pcap 里一条也找不到。
    # 这个字段不参与混淆矩阵判定（判定仍是「窗 + src_ips」，口径不打折），
    # 只用来做主指标的敏感性分析：落在窗外的攻击机请求有多少、其中多少被命中。
    attacker_ips: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> "Labels":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        # 时区偏移：数据集文档给的时间通常不是 PCAP 里的时间戳。
        # CIC 的 PCAP 多为 UTC（或加拿大本地时间），而论文里的时间窗是本地
        # 时间——差 4 小时是常态。不做这一步对齐，攻击窗会整体错位、检出率
        # 直接归零，而且看起来"像是检测器坏了"。
        shift = timedelta(hours=float(data.get("pcap_time_offset_hours", 0) or 0))
        windows = [
            AttackWindow(
                start=_parse_ts(w["start"]) + shift,
                end=_parse_ts(w["end"]) + shift,
                src_ips=tuple(w.get("src_ips") or ()),
                attack=w.get("attack", "unspecified"),
            )
            for w in data.get("attack_windows", [])
        ]
        return cls(
            dataset=data.get("dataset", Path(path).stem),
            source=data.get("source", ""),
            label_granularity=data.get("label_granularity", "time_window+src_ip"),
            windows=windows,
            notes=data.get("notes", ""),
            shift_hours=float(data.get("pcap_time_offset_hours", 0) or 0),
            attacker_ips=tuple(data.get("attacker_ips") or ()),
        )

    def verdict(self, event) -> tuple[str, str]:
        """返回 (expect, attack_type)。expect ∈ {"attack", "benign"}。

        时间窗**且** IP 同时匹配才算攻击：攻击者 IP 在非攻击时段也有正常
        流量，只按 IP 判会把良性请求算成攻击，人为抬高检出率。
        """
        for w in self.windows:
            if w.covers(event) and event.ip in w.src_ips:
                return "attack", w.attack
        return "benign", ""

    def in_window_but_other_ip(self, event) -> bool:
        """诊断用：落在攻击时间窗内、却不是攻击源 IP 的请求。

        这类请求是标注口径的灰色地带（可能是同网段的正常用户，也可能是
        CIC 按 flow 标注导致的漏标）。报告里要把它的占比印出来，
        否则"误报"里混着多少是标注问题就说不清了。
        """
        return any(w.covers(event) for w in self.windows) and \
            not any(w.covers(event) and event.ip in w.src_ips for w in self.windows)

    def attacker_outside_window(self, event) -> bool:
        """诊断用：来自攻击机、却落在所有标注窗之外的请求。

        这是``in_window_but_other_ip``的反方向，用途也不一样：论文给的时段是
        四舍五入到整十分钟的，而 SQLi 窗口只有两分钟宽。标注窗若有十几分钟
        的边界误差，这些请求会被扣成「应放行」，检测器命中反而记成误报。
        把它们数出来，就能在报告里给出「窗收紧 / 窗放宽」两条口径下的检出率
        区间，而不是给一个看着精确、其实取决于边界的点估计。
        """
        if not self.attacker_ips or event.ip not in self.attacker_ips:
            return False
        return not any(w.covers(event) for w in self.windows)


_SKIP_REASON = "阈值规则（窗口聚合），粒度与逐请求指标不同，单独统计"


def signature_rules(rules) -> list:
    """只取"单条事件即判定"的签名规则。

    阈值规则（threshold > 1 或没有 match）是窗口级判据，混进逐请求混淆矩阵
    会把粒度搅乱：一次爆破的 5 条失败请求无法逐条标注"哪条该告警"。
    所以两类分开报，报告里各占一块。
    """
    return [r for r in rules if r.match and r.threshold == 1]


def _applicable(rules, seen_types: set[str]) -> list:
    """只保留 event_types 与本次数据里出现过的类型有交集的规则。

    不加这层过滤，报告会把只吃 `app_log` 的日志侧规则也列进"参与判定的规则"
    ——它们对 http_request 永远不可能命中，列出来纯属误导读者。
    """
    return [r for r in rules if seen_types & set(r.event_types)]


def hits_for(event, rules) -> list[str]:
    return [r.id for r in rules
            if event.event_type in r.event_types and _matches(event, r.match)]


@dataclass
class Tally:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    by_attack: dict = field(default_factory=dict)
    window_other_ip: int = 0
    # 落在标注窗之外、却来自攻击机的请求；以及其中被规则命中的条数。
    # 用来给检出率一个「窗放宽」的上界，见 Labels.attacker_outside_window。
    attacker_outside: int = 0
    attacker_outside_hits: int = 0
    total: int = 0

    def add(self, expect: str, hit: bool, attack: str, uri: str = "") -> None:
        self.total += 1
        if expect == "attack":
            bucket = self.by_attack.setdefault(
                attack, {"total": 0, "hit": 0, "missed": []})
            bucket["total"] += 1
            if hit:
                self.tp += 1
                bucket["hit"] += 1
            else:
                self.fn += 1
                if len(bucket["missed"]) < 5:
                    bucket["missed"].append(uri[:120])
        else:
            if hit:
                self.fp += 1
            else:
                self.tn += 1

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def recall_upper(self) -> float:
        """把「窗外的攻击机请求」也一律算作应检出时的检出率。

        是上界不是另一个点估计：它假设标注窗边界把真攻击漏在窗外了。
        两个数和主指标并列印出来，读者能自己判断结论对边界是否敏感。
        """
        d = self.tp + self.fn + self.attacker_outside
        return (self.tp + self.attacker_outside_hits) / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0


def run(pcap: Path, labels: Labels, rules_dir: Path = RULES_DIR,
        out_dir: Path | None = None, progress_every: int = 200000) -> dict:
    """主流程：流式解析 → 逐事件判定 → 混淆矩阵 → 产物。

    明细 CSV 是**边算边写**，不是攒在内存里最后一次性写。

    为什么改（2026-11-05，第一次拿 11 GB 真数据跑时）：原来的实现把每条请求
    攒成 dict 放进 `rows`，跑完才落盘。自造样本只有 5 条请求，永远发现不了；
    真数据上百万条请求 × 每条一个 dict，几 GB 内存就没了，而且这些数据
    **本来就要落盘**，攒着没有任何收益。改成流式写之后内存占用与文件大小无关。
    """
    rules = signature_rules(load_rules_dir(rules_dir))
    tally = Tally()
    seen_types: set[str] = set()

    bytes_total = Path(pcap).stat().st_size
    out = Path(out_dir) if out_dir is not None else None
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
    stem = Path(pcap).stem
    csv_fh = None
    csv_writer: csv.DictWriter | None = None
    if out is not None:
        csv_fh = open(out / f"bench_{stem}.csv", "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_fh, fieldnames=list(_ROW_FIELDS))
        csv_writer.writeheader()

    t0 = time.perf_counter()
    first_event_ts = last_event_ts = None

    try:
        for i, event in enumerate(iter_events(pcap), 1):
            seen_types.add(event.event_type)
            expect, attack = labels.verdict(event)
            hit_rules = hits_for(event, rules)
            if labels.in_window_but_other_ip(event):
                tally.window_other_ip += 1
            if labels.attacker_outside_window(event):
                tally.attacker_outside += 1
                if hit_rules:
                    tally.attacker_outside_hits += 1
            tally.add(expect, bool(hit_rules), attack, event.uri or "")
            if first_event_ts is None:
                first_event_ts = event.ts
            last_event_ts = event.ts

            if csv_writer is not None:
                csv_writer.writerow({
                    "ts": event.ts.isoformat(sep=" "),
                    "src_ip": event.ip or "",
                    "method": event.method,
                    "host": event.host,
                    "uri": (event.uri or "")[:300],
                    "expect": expect,
                    "attack": attack,
                    "hit_rules": ";".join(hit_rules),
                    "verdict": ("TP" if expect == "attack" and hit_rules else
                                "FN" if expect == "attack" else
                                "FP" if hit_rules else "TN"),
                })
            if progress_every and i % progress_every == 0:
                print(f"  ... 已处理 {i} 条请求"
                      f"（{event.ts:%Y-%m-%d %H:%M:%S}）", file=sys.stderr)
    finally:
        if csv_fh is not None:
            csv_fh.close()

    elapsed = time.perf_counter() - t0
    throughput = {
        "seconds": elapsed,
        "mb_per_s": (bytes_total / 1e6) / elapsed if elapsed else 0.0,
        "requests_per_s": tally.total / elapsed if elapsed else 0.0,
        "bytes": bytes_total,
        "requests": tally.total,
        "span": (f"{first_event_ts} ~ {last_event_ts}"
                 if first_event_ts else "无事件"),
    }

    result = {"labels": labels, "tally": tally, "throughput": throughput,
              "rules": _applicable(rules, seen_types), "pcap": str(pcap),
              "seen_types": sorted(seen_types)}

    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        stem = Path(pcap).stem
        _write_md(out / f"bench_{stem}_report.md", result)
        result["artifacts"] = [str(out / f"bench_{stem}.csv"),
                               str(out / f"bench_{stem}_report.md")]
    return result


def _write_csv(path: Path, rows: list[dict]) -> None:
    """（保留给少量行的一次性写入；主流程已改为流式，不再用它。）"""
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} GB"


def _write_md(path: Path, result: dict) -> None:
    t: Tally = result["tally"]
    tp: dict = result["throughput"]
    lb: Labels = result["labels"]

    # 分母为 0 时印 "—" 并说明原因，而不是印 0%。纯良性语料（如 CIC 周二）
    # 里检出率天然无定义，印 "0.00%" 会被读成"检测器一条都没抓到"——那是错的。
    if t.tp + t.fn:
        recall_cell = f"**{t.recall:.2%}**"
        recall_note = f"{t.tp}/{t.tp + t.fn} 条攻击请求被抓到"
    else:
        recall_cell = "—"
        recall_note = "本数据集无标注攻击请求，检出率无定义"
    if t.fp + t.tn:
        fpr_cell = f"**{t.fpr:.4%}**"
        fpr_note = f"{t.fp}/{t.fp + t.tn} 条正常请求被误判"
    else:
        fpr_cell = "—"
        fpr_note = "无正常请求样本"
    if t.tp + t.fp:
        precision_cell = f"{t.precision:.2%}"
        precision_note = "报出来的告警里多少是真的"
    else:
        precision_cell = "—"
        precision_note = "没有产生任何告警，精确率无定义"

    L: list[str] = [
        f"# 基准评测：{lb.dataset}",
        "",
        f"- PCAP：`{result['pcap']}`（{_human_bytes(tp['bytes'])}，"
        f"时间跨度 {tp['span']}）",
        f"- 数据来源：{lb.source or '未注明'}",
        f"- 标注口径：`{lb.label_granularity}` —— " + (
            "本文件不含攻击时间窗，全部请求标为「应放行」。"
            "**这份数据只用于测误报率与吞吐，不产出检出率**"
            if not lb.windows else
            "落在攻击时间窗**且**源 IP 为攻击源 IP 的请求记为应检出，其余记为应放行"),
    ]
    if lb.notes:
        L.append(f"- 备注：{lb.notes}")
    L += [
        "",
        "> ⚠️ 数据集标签通常是**按流**打的，本工具产出的是**按请求**的事件。"
        "两者粒度不同，所以本报告不使用数据集自带的 flow 标签，"
        "而是用「时间窗 + 攻击源 IP」这个显式口径对齐。"
        "**口径写在上面，别人可以照着复核**——这是这份报告能被采信的前提。",
        "",
        "## 混淆矩阵（逐请求，签名规则）",
        "",
        "| | 判定为攻击 | 判定为正常 |",
        "|---|---|---|",
        f"| **标注为攻击** | TP {t.tp} | FN {t.fn} |",
        f"| **标注为正常** | FP {t.fp} | TN {t.tn} |",
        "",
        "## 三个数",
        "",
        "| 指标 | 值 | 说明 |",
        "|---|---|---|",
        f"| 检出率（Recall） | {recall_cell} | {recall_note} |",
        f"| 误报率（FPR） | {fpr_cell} | {fpr_note} |",
        f"| 精确率（Precision） | {precision_cell} | {precision_note} |",
        f"| 吞吐 | **{tp['mb_per_s']:.2f} MB/s**，"
        f"{tp['requests_per_s']:.0f} 请求/s | 单线程，解析 + 检测合计 {tp['seconds']:.1f}s |",
        "",
        "## 分攻击类型",
        "",
        "| 攻击类型 | 总数 | 检出 | 检出率 |",
        "|---|---|---|---|",
    ]
    for name, b in sorted(t.by_attack.items()):
        rate = b["hit"] / b["total"] if b["total"] else 0.0
        L.append(f"| {name} | {b['total']} | {b['hit']} | {rate:.2%} |")
    if not t.by_attack:
        L.append("| （无标注为攻击的请求） | 0 | 0 | — |")

    L += [
        "",
        "## 参与判定的规则",
        "",
        "只统计**签名规则**（单条请求即可判定），且只列 `event_types` 与本次数据"
        f"（{'/'.join(result.get('seen_types') or ['无'])}）有交集的规则——"
        "只吃应用日志的规则对流量永不命中，列进来纯属误导。",
        "",
        "阈值规则（窗口聚合）没有进混淆矩阵：一次爆破的 5 条失败请求无法逐条"
        "标注\"哪条该告警\"，粒度不同不能混算。",
        "",
    ]
    for r in result["rules"]:
        L.append(f"- `{r.id}`（{r.severity}）— {r.name}")
    L += [
        "",
        "## 标注灰色地带",
        "",
        f"- 落在攻击时间窗内、但源 IP 不是攻击源的请求：**{t.window_other_ip} 条**"
        f"（占全部 {t.total} 条的 {t.window_other_ip / t.total:.2%}）"
        if t.total else "- 无事件",
        "",
        "  这类请求被记为「应放行」。它们可能是同网段的正常用户，也可能是"
        "数据集按 flow 标注导致的漏标。**把它印出来而不是藏起来**，"
        "是因为它直接决定了误报率的分母是否干净——读的人有权知道。",
        "",
    ]
    if lb.attacker_ips:
        L += [
            f"- 来自攻击机（`{'`, `'.join(lb.attacker_ips)}`，抓包点 NAT 后的地址）"
            f"但落在所有攻击时间窗之外的请求：**{t.attacker_outside} 条**，"
            f"其中 {t.attacker_outside_hits} 条被规则命中",
            "",
            "  论文给的攻击时段四舍五入到整十分钟，而 SQLi 窗只有两分钟宽，"
            "所以标注窗必然有边界误差。这些请求被记为「应放行」，"
            "检测器若命中反而计入误报。把窗放宽到「攻击机的流量一律算攻击」，"
            f"检出率上界为 **{t.recall_upper:.2%}**（主口径 {t.recall:.2%}）。"
            "两个数都给出，是因为单独任一个都在替读者做判断。",
            "",
        ]
    path.write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------
# 自检：不依赖任何外部数据集，用合成 PCAP 验证脚本本身
# --------------------------------------------------------------------------
def selftest_labels(records: list[tuple[float, bytes]]) -> dict:
    """按合成样本自身的时间戳构造自检用的标注。

    单独抽成函数是为了能被测试直接调用——如果把它写在 self_test 里面，
    就只能靠"跑一遍看退出码"来验证，而那种验证在本地永远通过、
    在别的时区才失败（正是这个 bug 曾经躲过 CI 除外的所有检查的原因）。

    关键点：窗口用 datetime.fromtimestamp() 从 epoch 推出来，和
    collectors.pcap.iter_events() 渲染事件时间用的是同一个函数、同一个本地时区，
    因此**在任何时区下窗口都包住样本**。写字面时间就做不到这一点。
    """
    first_ts = min(ts for ts, _ in records)
    win_start = datetime.fromtimestamp(first_ts)
    win_end = datetime.fromtimestamp(first_ts + 10)
    return {
        "dataset": "self-test（合成样本，非真实数据集）",
        "source": "tools/pcapgen.py demo_records()",
        "label_granularity": "time_window+src_ip",
        "notes": "2 条正常（10.0.0.12）+ 3 条攻击（10.0.0.66/77/88）",
        "attack_windows": [{
            "start": win_start.strftime("%Y-%m-%d %H:%M:%S"),
            "end": win_end.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ips": ["10.0.0.66", "10.0.0.77", "10.0.0.88"],
            "attack": "Log4Shell / Fastjson / WebShell",
        }],
    }


def self_test() -> int:
    """用 pcapgen 的演示样本跑一遍，断言评测逻辑给出的数是对的。

    为什么要有这个：真实数据集动辄几 GB、还可能下不下来。如果连评测脚本
    本身有 bug 都不知道，跑出来的数就没意义。自检保证"脚本是对的"，
    剩下的事才是"数据是什么样"。
    """
    import tempfile

    from tools.pcapgen import demo_records, pcap_bytes

    records = demo_records()

    tmp = Path(tempfile.mkdtemp(prefix="bench_selftest_"))
    pcap = tmp / "selftest.pcap"
    pcap.write_bytes(pcap_bytes(records))

    labels_path = tmp / "labels.json"
    labels_path.write_text(
        json.dumps(selftest_labels(records), ensure_ascii=False), encoding="utf-8")

    result = run(pcap, Labels.load(labels_path), out_dir=tmp / "out")
    t: Tally = result["tally"]

    print("自检结果")
    print(f"  事件 {t.total} 条：TP={t.tp} FN={t.fn} FP={t.fp} TN={t.tn}")
    print(f"  检出率 {t.recall:.0%}，误报率 {t.fpr:.0%}")
    print(f"  产物：{result['artifacts']}")

    expected = {"total": 5, "tp": 3, "fn": 0, "fp": 0, "tn": 2}
    actual = {"total": t.total, "tp": t.tp, "fn": t.fn, "fp": t.fp, "tn": t.tn}
    if actual != expected:
        print(f"[!] 自检失败：期望 {expected}，实得 {actual}", file=sys.stderr)
        return 1
    print("[+] 自检通过：脚本的判定与计数逻辑正确，可以拿去跑真实数据集")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="在公开数据集上评测 SentinelWatch 流量检测层",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--pcap", help="待评测的 PCAP 文件")
    ap.add_argument("--labels", default=str(DEFAULT_LABELS),
                    help="标注文件（JSON：时间窗 + 攻击源 IP）")
    ap.add_argument("--rules", default=str(RULES_DIR), help="规则目录")
    ap.add_argument("--out", default=str(ROOT / "out"), help="产物输出目录")
    ap.add_argument("--self-test", action="store_true",
                    help="用合成样本自检脚本（不需要数据集）")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.pcap:
        ap.error("需要 --pcap（或 --self-test）")

    labels = Labels.load(Path(args.labels))
    result = run(Path(args.pcap), labels, Path(args.rules), Path(args.out))
    t: Tally = result["tally"]
    tp: dict = result["throughput"]

    # 分母为 0 时印 "—"。纯良性语料（如周二）检出率无定义，印 0% 会被读成
    # "一条都没抓到"，那是把"没有攻击样本"说成了"检测失败"。
    recall = f"{t.recall:.2%}" if (t.tp + t.fn) else "—（无攻击样本）"
    fpr = f"{t.fpr:.4%}" if (t.fp + t.tn) else "—（无良性样本）"
    precision = f"{t.precision:.2%}" if (t.tp + t.fp) else "—（无告警）"

    print(f"\n{labels.dataset}")
    print(f"  请求 {t.total} 条 | TP {t.tp} FN {t.fn} FP {t.fp} TN {t.tn}")
    print(f"  检出率 {recall} | 误报率 {fpr} | 精确率 {precision}")
    print(f"  吞吐 {tp['mb_per_s']:.2f} MB/s，{tp['requests_per_s']:.0f} 请求/s")
    print(f"  时间跨度 {tp['span']}")
    for p in result["artifacts"]:
        print(f"  → {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
