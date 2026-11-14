#!/usr/bin/env python3
"""跨项目交叉评测：拿 bypasslab 的攻击语料去打 sentinelwatch 的检测规则。

这是「矛与盾」的交叉验证，两个项目各自的自测都覆盖不到这一格：

    bypasslab 测的是「WAF 拦不拦」，载荷过不过只看 WAF 自己；
    sentinelwatch 测的是真实数据集，但那是**别人打别人**的流量。

谁都没测过：**bypasslab 专门为绕过检测而构造的载荷，sentinelwatch 认不认。**
这批载荷的难点在于它们是照着检测逻辑设计的——URL 编码、双重编码、大小写扰动、
注释拆分——正好压在最容易被写坏的归一化层上。

口径（三条，缺一条数字就不可信）
--------------------------------
1. **只测签名规则**。`threshold > 1` 的窗口规则要多次事件才成立，单条样本无法
   评测；本报告不覆盖它们，这不等于漏检，别混算。
2. **能力边界显式声明**。sentinelwatch 没有 RCE / SSRF 规则，这两类记
   `unsupported` 并**不计入检出率分母**——把「没有这个能力」算成「检出率 0%」，
   是用分母惩罚自己，也是骗自己。
3. **构造事件复用生产实现**。直接调 `collectors.pcap._build_event()`，连 raw
   拼接、`normalized` 归一化、uri 抽取都用线上同一份代码。评测脚本里另写一套
   归一化，早晚会算出和线上不一样的数。

holdout 纪律
------------
bypasslab 的 Holdout 是**冻结语料**：读代码的人不许看明细，否则会忍不住针对性改规则。
本报告对 `set == "holdout"` 的样本**只报总数、不列 ID 与名称**，与那条纪律保持一致。

用法
----
    # 1) 在 bypasslab 导出完整语料（out/*.csv 会截断载荷到 200 字符并丢 UA）
    cd ../bypasslab && go run ./cmd/export -out out/corpus_full.json

    # 2) 回到 sentinelwatch 跑评测
    python bench/run_crosscheck.py \
        --corpus ../bypasslab/out/corpus_full.json \
        --out bench/results/crosscheck_bypasslab.md
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.pcap import _build_event  # noqa: E402
from engine.detector import load_rules_dir, run_rules  # noqa: E402

DEFAULT_CORPUS = ROOT.parent / "bypasslab" / "out" / "corpus_full.json"
DEFAULT_RULES = ROOT / "rules"
DEFAULT_UA = "bypasslab-crosscheck/1.0"
SRC_IP = "198.51.100.10"      # 文档保留段，避免看起来像真实内网地址
BASE_EPOCH = 1793797200.0     # 固定基准时间，保证结果可复现

# category -> (是否在 sentinelwatch 检测范围, 依据)
# 这张表是**人工声明**，不是从规则里猜的：能力边界必须写明白，读者才知道
# 某个百分比的分母到底包含什么。
COVERAGE: dict[str, tuple[bool, str]] = {
    "sqli": (True, "http-sqli-* 4 条签名规则"),
    "xss": (True, "http-xss-* 2 条签名规则"),
    "path-traversal": (True, "http-path-traversal"),
    "deserialization": (True, "fastjson 系列 + log4shell JNDI"),
    "rce": (False, "无命令注入规则（能力缺口，不是漏检）"),
    "ssrf": (False, "无 SSRF 规则（能力缺口，不是漏检）"),
    "benign": (False, "负样本，只测误报"),
    # scanner 是 8 条**攻击**样本（sqlmap/Nikto/nmap 等 UA 指纹，IsAttack=true），
    # 不是良性对照——这里没有扫描器 UA 规则，属于能力缺口。
    "scanner": (False, "无扫描器 UA 指纹规则（能力缺口，不是漏检）"),
}


@dataclass
class Row:
    case: dict
    hits: list[str]
    # 归因用：这条样本在「补上 `+` 解码」后能否被现有规则抓到。
    whatif_hit: bool = False

    @property
    def detected(self) -> bool:
        return bool(self.hits)


@dataclass
class CatStat:
    category: str
    supported: bool
    basis: str
    attacks: int = 0
    detected: int = 0
    benign: int = 0
    false_positives: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0

    @property
    def fpr(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0


@dataclass
class SetStat:
    name: str
    attacks: int = 0
    detected: int = 0
    benign: int = 0
    false_positives: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0

    @property
    def fpr(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0


@dataclass
class Result:
    corpus: str
    total_cases: int
    rules_used: int
    window_rules_skipped: int
    cats: dict[str, CatStat] = field(default_factory=dict)
    sets: dict[str, SetStat] = field(default_factory=dict)
    miss_samples: list[Row] = field(default_factory=list)
    fp_samples: list[Row] = field(default_factory=list)
    miss_total: int = 0
    fp_total: int = 0
    holdout_attacks: int = 0
    holdout_detected: int = 0
    # 归因分析：假设归一化层补上 form-urlencoded 的 `+`→空格，检出数会是多少。
    # 只用于定位缺口，不改变生产实现，也不并入上面的正式数字。
    whatif_detected: int = 0
    whatif_cats: dict[str, int] = field(default_factory=dict)

    @property
    def supported_attacks(self) -> int:
        return sum(c.attacks for c in self.cats.values() if c.supported)

    @property
    def supported_detected(self) -> int:
        return sum(c.detected for c in self.cats.values() if c.supported)

    @property
    def recall(self) -> float:
        d = self.supported_attacks
        return self.supported_detected / d if d else 0.0

    @property
    def unsupported_attacks(self) -> int:
        return sum(c.attacks for c in self.cats.values() if not c.supported)

    @property
    def benign_total(self) -> int:
        return sum(c.benign for c in self.cats.values())

    @property
    def false_positives(self) -> int:
        return sum(c.false_positives for c in self.cats.values())


def build_event(case: dict, idx: int, form_plus: bool = False):
    """把一条 bypasslab Case 还原成生产格式的 HttpEvent。

    刻意调用 `_build_event()` 而不是自己拼 dataclass：raw 的拼接顺序、
    normalized 的归一化轮数、uri 的抽取方式都在那个函数里，复用它才不会
    出现「评测归一化和线上归一化不是一回事」。

    `form_plus` 只服务归因分析（what-if），**不改变生产实现**：
    application/x-www-form-urlencoded 里 `+` 等价于空格，而当前
    `normalize()` 只做 `unquote()`、不处理 `+`。打开它等于预先替归一化层
    补上这一步，用来量化「这一个缺口值多少个百分点」。注意只替换字面 `+`，
    `%2B`（真正的加号）不受影响。
    """
    method = (case.get("method") or "GET").upper()
    path = case.get("path") or "/"
    query = case.get("query") or ""
    body = case.get("body") or ""
    if form_plus:
        query = query.replace("+", " ")
        body = body.replace("+", " ")
    target = f"{path}?{query}" if query else path

    # 头名统一小写：_build_event / _split_head 都按小写取值，
    # 大小写混着写会让 host / user-agent 取不到。
    headers = {
        "host": "crosscheck.local",
        "user-agent": case.get("ua") or DEFAULT_UA,
    }
    for k, v in (case.get("headers") or {}).items():
        headers[k.lower()] = v
    if body:
        headers["content-length"] = str(len(body.encode("utf-8")))

    return _build_event(
        datetime.fromtimestamp(BASE_EPOCH + idx),
        SRC_IP,
        40000 + idx % 20000,
        f"{method} {target} HTTP/1.1".encode("utf-8"),
        headers,
        body.encode("utf-8"),
    )


def evaluate(corpus_path: Path, rules_dir: Path = DEFAULT_RULES,
             miss_limit: int = 12) -> Result:
    data = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    all_rules = load_rules_dir(rules_dir)
    rules = [r for r in all_rules if r.threshold == 1]

    # 报告里**只写文件名**：路径对读者没有价值（他们用命令自己生成），
    # 而任何形式的路径都可能泄露开发机目录。
    # 这里不要用 os.path.relpath：在 POSIX 上它会返回 `../../../../tmp/...`，
    # 结果里仍然包含绝对路径片段，测试里一旦断言"不含 tmp_path"就会在
    # Linux 红、Windows 绿（Windows 跨盘符会抛 ValueError 走另一个分支）。
    display_path = Path(corpus_path).name

    res = Result(
        corpus=display_path,
        total_cases=len(data.get("cases", [])),
        rules_used=len(rules),
        window_rules_skipped=len(all_rules) - len(rules),
    )

    for idx, case in enumerate(data.get("cases", [])):
        event = build_event(case, idx)
        alerts = run_rules([event], rules)
        row = Row(case=case, hits=[a.rule_id for a in alerts])

        cat_name = case.get("category") or "unknown"
        supported, basis = COVERAGE.get(cat_name, (False, "未声明类别"))
        cat = res.cats.setdefault(cat_name, CatStat(cat_name, supported, basis))
        st = res.sets.setdefault(case.get("set") or "unknown", SetStat(case.get("set") or "unknown"))

        # 只在检测范围内做归因：范围外本来就没有规则，算 what-if 没有意义。
        if supported:
            row.whatif_hit = bool(run_rules([build_event(case, idx, form_plus=True)], rules))

        if case.get("is_attack"):
            cat.attacks += 1
            st.attacks += 1
            if row.detected:
                cat.detected += 1
                st.detected += 1
            elif supported:
                res.miss_total += 1
                # holdout 是 bypasslab 的**冻结语料**，那边有明确纪律：只报总数、
                # 不报明细（否则读代码的人会针对性改规则，泛化测试就废了）。
                # 这里必须显式排除，不能靠"它恰好排在后面"。
                if case.get("set") != "holdout" and len(res.miss_samples) < miss_limit:
                    res.miss_samples.append(row)
            if supported and row.whatif_hit:
                res.whatif_detected += 1
                res.whatif_cats[cat_name] = res.whatif_cats.get(cat_name, 0) + 1
        else:
            cat.benign += 1
            st.benign += 1
            if row.detected:
                cat.false_positives += 1
                st.false_positives += 1
                res.fp_total += 1
                if len(res.fp_samples) < miss_limit:
                    res.fp_samples.append(row)

        if case.get("set") == "holdout" and case.get("is_attack"):
            res.holdout_attacks += 1
            if row.detected:
                res.holdout_detected += 1

    return res


def render(res: Result) -> str:
    sqli_now = res.cats["sqli"].detected if "sqli" in res.cats else 0
    sqli_all = res.cats["sqli"].attacks if "sqli" in res.cats else 0
    sqli_whatif = res.whatif_cats.get("sqli", 0)
    gain = res.whatif_detected - res.supported_detected
    L = [
        "# 跨项目交叉评测：bypasslab 语料 × sentinelwatch 规则",
        "",
        f"- 语料：`{res.corpus}`（{res.total_cases} 条样本；由 bypasslab 的 "
        f"`go run ./cmd/export` 生成）",
        f"- 参与评测的签名规则：{res.rules_used} 条；"
        f"另有 {res.window_rules_skipped} 条窗口/阈值规则未参与（见下方口径）",
        "",
        "> ⚠️ **两条口径，缺一条数字就不可信**：",
        "> 1. 只测**签名规则**。`threshold > 1` 的窗口规则要多次事件才成立，"
        "单条样本无法评测——它们不参与本报告，**不等于漏检**。",
        "> 2. **能力边界不计入分母**：本工具没有 RCE / SSRF 规则，这两类记"
        "`unsupported` 并排除在检出率之外。把「没有这个能力」算成 0% 命中，"
        "是拿分母惩罚自己。",
        "",
        "## 按攻击类别",
        "",
        "| 类别 | 在检测范围 | 依据 | 攻击样本 | 检出 | 检出率 | 良性样本 | 误报 |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for name in sorted(res.cats):
        c = res.cats[name]
        if c.attacks == 0 and c.benign == 0:
            continue
        recall = "—" if not c.attacks else f"{c.recall:.1%}"
        if not c.supported and c.attacks:
            recall = "不计入"
        L.append(
            f"| `{name}` | {'✅' if c.supported else '—'} | {c.basis} | {c.attacks} | "
            f"{c.detected} | {recall} | {c.benign} | {c.false_positives} |"
        )

    L += [
        "",
        f"**检测范围内合计**：{res.supported_detected}/{res.supported_attacks} = "
        f"**{res.recall:.1%}**；范围外（RCE / SSRF / 扫描器指纹）另有 "
        f"{res.unsupported_attacks} 条攻击样本未计入。",
        "",
        "## 按语料集（泛化能力）",
        "",
        "同一套规则在不同来源的语料上表现不同，这个差异比总分更有信息量："
        "`corpus` / `hard` 是项目自己迭代过的，`crs` 是 OWASP 第三方基准，"
        "`holdout` 是冻结的泛化集。",
        "",
        "| 语料集 | 攻击样本 | 检出 | 检出率 | 良性样本 | 误报 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name in sorted(res.sets):
        s = res.sets[name]
        recall = "—" if not s.attacks else f"{s.recall:.1%}"
        L.append(f"| `{name}` | {s.attacks} | {s.detected} | {recall} | "
                 f"{s.benign} | {s.false_positives} |")

    L += [
        "",
        "## 根因归因：缺口分三类，性质完全不同",
        "",
        "### 1. 归一化缺口：`+` 没有按 form 编码还原成空格（可修）",
        "",
        "`collectors/pcap.py` 的 `normalize()` 只做 `unquote()`（URL 解码到不动点）"
        "再转小写，**不处理 `+`**。但 query string 和 `application/x-www-form-urlencoded` "
        "的 body 里，`+` 的语义就是空格——`id=1+UNION+SELECT+...` 是最常见的注入写法之一，"
        "归一化后仍是 `1+union+select`，规则里的 `union select` 自然匹配不到。",
        "",
        f"量化：只把 query / body 里的字面 `+` 换成空格（其余一律不动），"
        f"检测范围内检出率 **{res.recall:.1%} → "
        f"{res.whatif_detected / res.supported_attacks:.1%}**"
        f"（{res.supported_detected} → {res.whatif_detected} 条），"
        f"SQLi **{sqli_now}/{sqli_all} → {sqli_whatif}/{sqli_all}**。"
        f"这 {gain} 条不需要改任何规则，只是把同一语义的另一种编码解出来。",
        "",
        "> **本轮不修，是有意为之**：它会改动已发布的全部指标（9.56% / 98.84% / 误报 4 条），"
        "必须带着三份 CIC-IDS2017 全量回归单独做一次，否则「评测结论」和「规则版本」"
        "对不上，别人复核时数字会互相矛盾。这条记入下一步。",
        "",
        "### 2. 规则覆盖缺口：无引号恒真式、非 UNION 形态（要加规则）",
        "",
        "例如 `1234 OR 1=1`（`CRS-942100-01`）：`http-sqli-boolean-blind` 只认带引号的 "
        "`' or '1'='1` 形态。这是判据覆盖面问题，不是编码问题——加规则能解，"
        "但要看误报代价。",
        "",
        "### 3. 能力缺口：RCE / SSRF 没有规则（不是漏检）",
        "",
        f"`rce` {res.cats['rce'].attacks if 'rce' in res.cats else 0} 条、"
        f"`ssrf` {res.cats['ssrf'].attacks if 'ssrf' in res.cats else 0} 条攻击样本"
        "**全部不计入分母**。这是没有这个检测能力，不是「检出了 0%」。"
        "真要补，属于新增检测面（命令注入/SSRF 特征），不是改现有规则。",
        "",
        "## 漏检明细",
        "",
    ]
    if res.miss_samples:
        rescued = sum(1 for r in res.miss_samples if r.whatif_hit)
        L += ["| ID | 类别 | 名称 | 补 `+` 解码后能否命中 |", "|---|---|---|---|"]
        for r in res.miss_samples:
            c = r.case
            L.append(f"| `{c.get('id')}` | {c.get('category')} | {c.get('name')} | "
                     f"{'✅ 能' if r.whatif_hit else '— 不能'} |")
        L += ["", f"上表最多列 12 条；检测范围内共漏检 **{res.miss_total}** 条，"
                  f"其中所列的 {rescued} 条只要补上 `+` 解码就能命中"
                  "（属于第 1 类缺口，不是规则没写）。"]
    else:
        L.append("（检测范围内无漏检）")

    L += [
        "",
        "> `holdout` 集的漏检**不在此列出**。bypasslab 对这份冻结语料有明确纪律："
        "只报总数、不报明细，否则读代码的人会针对性改规则，泛化测试就失效了。"
        f"本集结果：{res.holdout_detected}/{res.holdout_attacks}。",
        "",
        "## 误报样例",
        "",
    ]
    if res.fp_samples:
        L += ["| ID | 类别 | 名称 | 命中规则 |", "|---|---|---|---|"]
        for r in res.fp_samples:
            c = r.case
            L.append(f"| `{c.get('id')}` | {c.get('category')} | {c.get('name')} | "
                     f"{', '.join(f'`{h}`' for h in r.hits)} |")
    else:
        L.append("（良性样本零误报）")

    L += [
        "",
        "> 事件构造直接复用生产 `collectors.pcap._build_event()`：raw 拼接、"
        "`normalized` 归一化（URL 解码到不动点 + 转小写）、uri 抽取与线上同一份代码。"
        "样本时间戳从固定 epoch 递增，结果可复现。",
        "",
    ]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="用 bypasslab 语料评测 sentinelwatch 签名规则（跨项目交叉评测）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                    help="bypasslab 导出的 corpus_full.json")
    ap.add_argument("--rules", default=str(DEFAULT_RULES))
    ap.add_argument("--out", help="写一份 Markdown 报告到该路径")
    ap.add_argument("--json", action="store_true", help="同时打印汇总 JSON")
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    if not corpus.exists():
        print(f"找不到语料 {corpus}\n先运行：cd ../bypasslab && go run ./cmd/export -out out/corpus_full.json",
              file=sys.stderr)
        return 2

    res = evaluate(corpus, Path(args.rules))
    text = render(res)
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"\n  → {out}")
    if args.json:
        print("\nJSON " + json.dumps({
            "total_cases": res.total_cases,
            "rules_used": res.rules_used,
            "window_rules_skipped": res.window_rules_skipped,
            "supported_attacks": res.supported_attacks,
            "supported_detected": res.supported_detected,
            "recall": round(res.recall, 4),
            "unsupported_attacks": res.unsupported_attacks,
            "benign_total": res.benign_total,
            "false_positives": res.false_positives,
            "holdout": [res.holdout_detected, res.holdout_attacks],
            # 归因用的假设值，不是正式结果
            "whatif_form_plus": [res.whatif_detected, res.supported_attacks],
        }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
