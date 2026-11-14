#!/usr/bin/env python3
"""给一条规则算「误报代价」：在真实良性流量上数命中，而不是上线后数投诉。

## 为什么需要这个脚本

v1.8 / v1.9 加改规则时，验证方式是"跑一遍全量主矩阵，看 FP 有没有涨"。
那条路是对的，但**太慢**：三份 CIC-IDS2017 全量 30.2 GB，一遍约 6 分钟，
而设计一条签名要试十几次——每次都等 6 分钟，人就会开始"凭感觉写，
最后跑一次看总数"。**凭感觉写规则**是误报的来源。

所以把两件事拆开：

1. **解析只做一次**（`--build-cache`）：三份 PCAP → 逐请求的
   `(ts, ip, 请求行, 头部, body)` 存成 JSONL。这不是"另写一份解析"，
   缓存里存的是**构造事件的原料**，重建时仍然调用生产的
   `collectors.pcap._build_event()`——归一化、`sql_view`、uri 抽取
   都走同一份代码。评测口径与线上不一致，评测就没有意义。
2. **评估做很多次**（默认）：读缓存 → 重建事件 → 逐规则数命中。
   三份全量 15.9 万请求，一次评估十几秒。

## 输出怎么读

每行六个数字：

```
规则                              TP    FP   其中噪声   真误报  真误报/10万
http-sqli-union-select             0     0        0      0        0.00
```

- `TP`：命中的**攻击**请求（只有周四那份语料有攻击标注，周一/周二恒为 0）
- `FP`：命中的标注为良性的请求
- `其中噪声`：这些命中里有几条来自「攻击机在标注窗之外的流量」——它们是真实
  攻击工具的流量，标成良性只是标注口径的结果
- `真误报 = FP − 其中噪声`，以及按 10 万条良性命中的量纲（便于跨语料比较）

**必须看样例**：同一批误报可能是同一个原因（比如富文本提交 HTML），也可能是
几个完全不同的原因。前者是「判据窄一档」能解决的，后者说明规则思路错了。
样例会标 `[语料/窗外攻击机]` 或 `[语料/真良性]`，只有后者才是规则的账。

## 一条硬规矩

`真误报` 必须是 0 才允许合入，除非在 BENCHMARK 里写清楚为什么值得接受。
检测改动提高检出却把误报带上去，没资格叫改进——这条在 v1.9 的提交信息里
写过一次，这里是它的工具化。
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from collectors.pcap import _build_event, _split_head, iter_events  # noqa: E402
from engine.detector import _matches, load_rules_dir  # noqa: E402
# 「哪些规则算逐请求签名」这个口径只在 run_benchmark 里定义一次：
# 这里再写一遍 `threshold == 1` 就成了两处真相，哪天口径变了必然漏改。
from bench.run_benchmark import signature_rules  # noqa: E402

DEFAULT_CACHE = ROOT / "bench" / ".cache"
CORPORA = {
    "monday": ("cic_ids2017_monday_benign.json", "Monday-WorkingHours.pcap"),
    "tuesday": ("cic_ids2017_tuesday_benign.json", "Tuesday-WorkingHours.pcap"),
    "thursday": ("cic_ids2017_thursday_web.json", "Thursday-WorkingHours.pcap"),
}
# PCAP 的实际位置因机器而异：样本随仓库带一份（data/），全量通常是下载来的。
# 不做"猜路径"的魔法，列出来让人一眼看到在哪找、没找到该放哪。
PCAP_DIRS = (ROOT / "data", Path("D:/Downloads"), Path.home() / "Downloads")


@dataclass
class Corpus:
    name: str
    pcap: Path
    labels: Path

    @property
    def cache_file(self) -> Path:
        return DEFAULT_CACHE / f"{self.name}.jsonl.gz"


def resolve_corpora(which: list[str], pcap_dir: str | None = None) -> list[Corpus]:
    """把名字映射成 (pcap, labels)。pcap 允许放在仓库外。"""
    dirs = ([Path(pcap_dir)] if pcap_dir else []) + list(PCAP_DIRS)
    out: list[Corpus] = []
    for name in which:
        if name not in CORPORA:
            raise SystemExit(f"未知语料 {name!r}；可用：{', '.join(CORPORA)}")
        labels_name, pcap_name = CORPORA[name]
        labels = ROOT / "bench" / "labels" / labels_name
        for d in dirs:
            cand = d / pcap_name
            if cand.exists():
                pcap = cand
                break
        else:
            raise SystemExit(
                f"找不到 {pcap_name}；找过："
                f"{', '.join(str(d) for d in dirs)}（用 --pcap-dir 指定）")
        out.append(Corpus(name, pcap, labels))
    return out


def build_cache(corpus: Corpus) -> int:
    """解析一次，把**构造事件的原料**落盘。

    为什么存原料而不是解析结果：`normalized` / `sql_view` 这些派生字段会随
    代码变，存死了就等于把旧代码的判定固化进缓存。存 `(请求行, 头部, body)`
    则相反——改了归一化，重跑评估立刻反映新行为，不用重新解析 30 GB。

    存头部也是个务实的选择：JNDI、XSS 这类载荷常放在 User-Agent / Referer
    里，只存 URI 会系统性低估误报（规则在 UA 上误命中，这里看不见）。

    **body 必须完整存，不能截断。** 第一版给 body 加了 1000 字符上限，理由是
    「正常请求体远小于此，截断只会让误报少算，保守」。这个判断是错的：周一
    3 条 `POST /ar.logger.php`（content-length 18,856，`<script>` 在 URL 编码的
    广告素材里很靠后）因此一条都没命中，工具报出「真误报 0」——**一个让人
    安心的假结果**。评测工具漏算误报，比规则漏检更危险：它会让「先量代价
    再写规则」的整套流程变成自我安慰。压缩后三份 body 合计只有几 MB，
    没有省的必要。
    """
    from bench.run_benchmark import Labels        # 延迟导入，避免循环
    labels = Labels.load(corpus.labels)
    corpus.cache_file.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(corpus.cache_file, "wt", encoding="utf-8") as fh:
        for event in iter_events(corpus.pcap):
            expect, attack = labels.verdict(event)
            raw = event.raw or ""
            head_end = raw.find("\r\n\r\n")
            head_block = raw if head_end < 0 else raw[:head_end]
            first, _, rest = head_block.partition("\r\n")
            fh.write(json.dumps({
                "ts": event.ts.timestamp(),
                "ip": event.ip,
                "port": event.port,
                "line": first,
                "head": rest,
                "body": event.body or "",
                "expect": expect,
                "attack": attack,
            }, ensure_ascii=False) + "\n")
            n += 1
    return n


def load_rows(corpus: Corpus) -> list[dict]:
    with gzip.open(corpus.cache_file, "rt", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def rebuild(row: dict):
    """用生产的 `_build_event()` 重建事件。

    这里曾经想"省点事，直接构造 HttpEvent 填 normalized"——那样评测脚本
    会有一份自己的归一化，改生产代码时评测不同步，量出来的误报就不是
    线上误报。缓存的原料就是为这条服务的。
    """
    line = (row.get("line") or "GET / HTTP/1.1").encode("latin-1", "replace")
    head = (row.get("head") or "").encode("latin-1", "replace")
    request_line, headers = _split_head(line + (b"\r\n" + head if head else b""))
    body = (row.get("body") or "").encode("utf-8", "replace")
    return _build_event(
        datetime.fromtimestamp(row["ts"]),
        row.get("ip") or "0.0.0.0",
        row.get("port") or 0,
        request_line,
        headers,
        body,
    )


def evaluate(corpora: list[Corpus], rules_dir: Path, only: str | None) -> None:
    from bench.run_benchmark import Labels
    rules = signature_rules(load_rules_dir(rules_dir))
    if only:
        rules = [r for r in rules if only in r.id]
    if not rules:
        raise SystemExit("没有要评估的规则")

    # 每条规则：TP / FP 计数与误报样例
    tp = {r.id: 0 for r in rules}
    fp = {r.id: 0 for r in rules}
    # 误报要分两类，否则结论是错的：CIC-IDS2017 的攻击机在标注窗之外也在发
    # 真实攻击工具的流量（周四 287 条），标成"良性"只是标注口径的结果。
    # 把它们与"真正良性来源"混成一个数字，等于拿标注误差指控规则。
    fp_noise = {r.id: 0 for r in rules}
    samples: dict[str, list[str]] = {r.id: [] for r in rules}
    benign_total = 0
    noise_total = 0

    for corpus in corpora:
        if not corpus.cache_file.exists():
            raise SystemExit(f"缺少缓存 {corpus.cache_file.name}；"
                             f"先跑 --build-cache {corpus.name}")
        labels = Labels.load(corpus.labels)
        for row in load_rows(corpus):
            event = rebuild(row)
            is_attack = row["expect"] == "attack"
            if not is_attack:
                benign_total += 1
                outside = labels.attacker_outside_window(event)
                noise_total += int(outside)
            else:
                outside = False
            for rule in rules:
                if not _matches(event, rule.match):
                    continue
                if is_attack:
                    tp[rule.id] += 1
                else:
                    fp[rule.id] += 1
                    fp_noise[rule.id] += int(outside)
                    if len(samples[rule.id]) < 3:
                        tag = "窗外攻击机" if outside else "真良性"
                        samples[rule.id].append(
                            f"[{corpus.name}/{tag}] {event.uri[:100]}")

    scale = 100_000 / benign_total if benign_total else 0.0
    print(f"良性标注请求：{benign_total:,}"
          f"（其中窗外攻击机流量 {noise_total:,}，属标注口径噪声）\n")
    head = (f"{'规则':32} {'TP':>5} {'FP':>5} {'其中噪声':>8} "
            f"{'真误报':>6} {'真误报/10万':>11}")
    print(head)
    print("-" * len(head))
    for rule in rules:
        real = fp[rule.id] - fp_noise[rule.id]
        print(f"{rule.id:32} {tp[rule.id]:5d} {fp[rule.id]:5d} "
              f"{fp_noise[rule.id]:8d} {real:6d} {real * scale:11.2f}")
    print()
    for rule in rules:
        if not samples[rule.id]:
            continue
        print(f"--- {rule.id} 的误报样例 ---")
        for s in samples[rule.id]:
            print(f"    {s}")
        print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpora", nargs="+", default=list(CORPORA),
                    help="要评估的语料（monday/tuesday/thursday）")
    ap.add_argument("--build-cache", action="store_true",
                    help="只解析并写缓存，不做评估")
    ap.add_argument("--rules", default=str(ROOT / "rules"), help="规则目录")
    ap.add_argument("--only", help="只评估 id 含该子串的规则")
    ap.add_argument("--pcap-dir", help="PCAP 所在目录（默认查 data/ 与 Downloads）")
    args = ap.parse_args(argv)

    corpora = resolve_corpora(args.corpora, args.pcap_dir)
    if args.build_cache:
        for c in corpora:
            n = build_cache(c)
            print(f"{c.name:10} {c.pcap.name} → {n:,} 条请求 "
                  f"({c.cache_file.name})")
        return 0
    evaluate(corpora, Path(args.rules), args.only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
