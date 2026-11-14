#!/usr/bin/env python3
"""在 OWASP CRS 全量回归集上评测 sentinelwatch 的签名规则。

这份报告回答一个问题：**把外部样本从 59 条扩到 2503 条，检出率会变成多少？**

为什么单独一份报告，而不并进 `run_crosscheck.py` 的主矩阵
-----------------------------------------------------------
主矩阵的分母在 v1.8→v2.1 之间从 117 变到 184，每次变都有一句「不能直接比」，
能比的只剩四列**分母没动过**的分类。再把 2503 条混进去，那四列也保不住了。
所以这里是独立测量：自己的分母、自己的结论、摆着看，不参与主矩阵的加减。

三条口径，每一条都被实测纠正过
------------------------------
1. **只有 `expect_ids` / `log.match_regex` 算「该检出」**。
   CRS 的 `no_expect_ids` 说的是「这条不该触发**这一个规则**」，不是「这条是良性」。
   第一版把它当良性，跑出「563 条反例上误报 4.44%」，看上去像个可用的误报率——
   而其中第一批「误报」就包括 `'||(select(pg_sleep(15))where(true))||'`
   这种货真价实的注入，`desc` 写着 "GH issue 1816 - Known false positive"
   （CRS 承认误报、于是故意不报）。**一个让人安心的假指标。**

2. **两种判据范式分开报**。CRS 的 `942430/942431/942432` 用字符频率计分，
   打一个 `'` 就报。那是 scoring + paranoia 模型，与签名式判据是两种东西。

3. **命中一条就算检出**。CRS 的 rule id 与本项目的 rule id 没有对应关系，
   不做逐规则对齐——硬对齐会造出一个假的精确率。

误报在哪里测
------------
不在这份语料里。真实流量的误报是 CIC-IDS2017 那 150,262 条请求上的 4 条
（BENCHMARK §2.10）。这份语料的样本是**照着规则写的测试用例**，没有业务形态，
测不出「正常流量长什么样」。

用法
----
    python bench/import_crs.py --src /tmp/coreruleset/tests/regression/tests \\
        --out bench/corpus/crs_regression.json      # 已提交，通常不需要重跑
    python bench/run_crs_bench.py                       # 打印报告
    python bench/run_crs_bench.py --out bench/results/crs_regression.md
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.run_crosscheck import DEFAULT_RULES, build_event  # noqa: E402
from engine.detector import load_rules_dir, run_rules  # noqa: E402

DEFAULT_CORPUS = ROOT / "bench" / "corpus" / "crs_regression.json"


@dataclass
class CatResult:
    category: str
    attacks: int = 0
    detected: int = 0
    no_expect: int = 0
    no_expect_hit: int = 0
    # 异常字符族单独计数（kind == "anomaly"），用来切两种口径
    anomaly_attacks: int = 0
    anomaly_detected: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0


@dataclass
class RuleResult:
    rule: int
    category: str
    kind: str
    attacks: int = 0
    detected: int = 0

    @property
    def recall(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0


@dataclass
class Result:
    corpus: str
    commit: str
    total: int = 0
    cats: dict[str, CatResult] = field(default_factory=dict)
    rules: dict[int, RuleResult] = field(default_factory=dict)
    rule_msgs: dict[str, str] = field(default_factory=dict)
    misses_by_rule: Counter = field(default_factory=Counter)
    # no_expect 命中按 negative_kind 分桶：explicit 才值得看
    ne_hit_by_kind: Counter = field(default_factory=Counter)
    ne_total_by_kind: Counter = field(default_factory=Counter)
    ne_hit_samples: list[dict] = field(default_factory=list)
    miss_samples: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    rules_used: int = 0
    window_rules_skipped: int = 0

    @property
    def attacks(self) -> int:
        return sum(c.attacks for c in self.cats.values())

    @property
    def detected(self) -> int:
        return sum(c.detected for c in self.cats.values())

    @property
    def no_expect(self) -> int:
        return sum(c.no_expect for c in self.cats.values())

    @property
    def no_expect_hit(self) -> int:
        return sum(c.no_expect_hit for c in self.cats.values())

    def recall(self) -> float:
        return self.detected / self.attacks if self.attacks else 0.0

    def sig_only(self) -> tuple[int, int, float]:
        a = self.attacks - sum(c.anomaly_attacks for c in self.cats.values())
        d = self.detected - sum(c.anomaly_detected for c in self.cats.values())
        return a, d, (d / a if a else 0.0)


def evaluate(corpus_path: Path, rules_dir: Path = DEFAULT_RULES,
             miss_limit: int = 8) -> Result:
    data = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    all_rules = load_rules_dir(rules_dir)
    rules = [r for r in all_rules if r.threshold == 1]

    res = Result(
        corpus=Path(corpus_path).name,
        commit=(data.get("commit") or "")[:12],
        total=len(data.get("cases") or []),
        rules_used=len(rules),
        window_rules_skipped=len(all_rules) - len(rules),
        rule_msgs=data.get("rule_msgs") or {},
    )

    for idx, case in enumerate(data.get("cases") or []):
        event = build_event(case, idx)
        alerts = run_rules([event], rules)
        hits = [a.rule_id for a in alerts]
        detected = bool(hits)

        cat_name = case.get("category") or "unknown"
        cat = res.cats.setdefault(cat_name, CatResult(cat_name))
        src_rule = int(case.get("source_rule") or 0)
        rr = res.rules.setdefault(
            src_rule, RuleResult(src_rule, cat_name, case.get("kind") or "signature"))

        if case.get("is_attack"):
            cat.attacks += 1
            rr.attacks += 1
            if case.get("kind") == "anomaly":
                cat.anomaly_attacks += 1
            if detected:
                cat.detected += 1
                rr.detected += 1
                if case.get("kind") == "anomaly":
                    cat.anomaly_detected += 1
            else:
                # 计数不受 miss_samples 的上限影响——样本只留前几条给人看，
                # 但**归因必须覆盖全部漏检**，否则百分比是按展示条数算的。
                res.misses_by_rule[src_rule] += 1
                if len(res.miss_samples[cat_name]) < miss_limit:
                    res.miss_samples[cat_name].append({
                        "id": case.get("id"), "rule": src_rule,
                        "method": case.get("method"), "path": case.get("path"),
                        "query": case.get("query"), "body": case.get("body"),
                    })
        else:
            kind = case.get("negative_kind") or "unclassified"
            cat.no_expect += 1
            res.ne_total_by_kind[kind] += 1
            if detected:
                cat.no_expect_hit += 1
                res.ne_hit_by_kind[kind] += 1
                if len(res.ne_hit_samples) < 20:
                    res.ne_hit_samples.append({
                        "id": case.get("id"), "rule": src_rule, "kind": kind,
                        "hits": hits, "desc": (case.get("desc") or "")[:70],
                        "method": case.get("method"), "path": case.get("path"),
                        "query": case.get("query"), "body": case.get("body"),
                    })

    return res


def _short(s: str, n: int = 78) -> str:
    s = (s or "").replace("\n", "\\n").replace("|", "\\|")
    return s if len(s) <= n else s[: n - 1] + "…"


def _payload_of(c: dict) -> str:
    return c.get("query") or c.get("body") or c.get("path") or ""


def render(res: Result) -> str:
    L: list[str] = []
    A = L.append

    A("# 外部基准：OWASP CRS 全量回归集 × sentinelwatch 规则")
    A("")
    A(f"- 语料：`{res.corpus}`（coreruleset `{res.commit or 'commit 未知'}`）")
    A(f"- 样本：**{res.total:,}** 条（该检出 {res.attacks:,} / "
      f"「不该触发本规则」 {res.no_expect:,}）")
    A(f"- 参与评测：{res.rules_used} 条签名规则"
      f"（另有 {res.window_rules_skipped} 条窗口阈值规则不适用单样本评测）")
    A("- 生成：`python bench/run_crs_bench.py`")
    A("")
    A("> 这份报告与 `crosscheck_bypasslab.md` **不可互换**：那边是自造语料 + 手抄的 "
      "59 条 CRS 子集，这边是 CRS 全量回归集。两边分母不同，数字不能相加，"
      "也不能直接比大小。")
    A("")

    # ---------------------------------------------------------------- 总表
    A("## 1. 总表：按类别")
    A("")
    A("| 类别 | 该检出 | 检出 | 检出率 | 「不该触发本规则」 | 其中被我们命中 |")
    A("|---|---:|---:|---:|---:|---:|")
    for name in sorted(res.cats, key=lambda k: -res.cats[k].attacks):
        c = res.cats[name]
        A(f"| `{name}` | {c.attacks:,} | {c.detected:,} | {c.recall:.1%} "
          f"| {c.no_expect:,} | {c.no_expect_hit:,} |")
    A(f"| **合计** | **{res.attacks:,}** | **{res.detected:,}** | **{res.recall():.1%}** "
      f"| **{res.no_expect:,}** | **{res.no_expect_hit:,}** |")
    A("")
    A(f"**检出率 {res.recall():.1%}**，分母 {res.attacks:,} 条。")
    A("")
    A("这个数字比手抄 59 条时的 54.2% 难看得多，而**难看才是对的**：那 59 条挑的是四个"
      "方法文件（`942100`/`941100`/`930100`/`932130`），都是 libinjection 那几条"
      "「形状最接近正则」的规则。全量里有 148 个规则文件，包含大量靠解析层能力"
      "（`REQUEST_METHOD`、XML 解析、`%uXXXX` best-fit、字符频率计分）判定的样本，"
      "本项目只做请求文本上的签名匹配。**扩样本量不是为了让数字变好，是为了让数字可信。**")
    A("")

    # ---------------------------------------------------------------- 两种口径
    sig_a, sig_d, sig_r = res.sig_only()
    A("## 2. 两种口径：签名型 vs CRS 全量")
    A("")
    A("CRS 的 `942430`/`942431`/`942432`（*Restricted SQL Character Anomaly "
      "Detection*）按**字符频率计分**判定——打一个 `'` 或 `;` 就算可疑。"
      "复现它得引入 paranoia level + 阈值模型，会改掉整个引擎的性格。")
    A("")
    A("| 口径 | 分母 | 检出 | 检出率 |")
    A("|---|---:|---:|---:|")
    A(f"| CRS 全量（含异常字符族） | {res.attacks:,} | {res.detected:,} "
      f"| **{res.recall():.1%}** |")
    A(f"| 仅签名型（排除 `94243x`） | {sig_a:,} | {sig_d:,} | **{sig_r:.1%}** |")
    A("")
    A(f"两者只差 {(res.recall() - sig_r) * 100:.1f} 个百分点——**说明差距不在那三条"
      "异常字符规则上**。这是一个有用的否证：原本很容易把「16%」归咎于"
      "「我们不做计分模型」，数据说不是。")
    A("")

    # ---------------------------------------------------------------- 逐规则
    A("## 3. 逐规则：148 个 CRS 规则文件，哪些覆盖了、哪些没有")
    A("")
    A("这是这份语料真正的价值：**从「一个百分比」变成「一张分布图」**。"
      "百分比只能说明整体水平，逐规则表能说明「差在哪种判据上」。")
    A("")
    worst = sorted((r for r in res.rules.values() if r.attacks >= 3),
                   key=lambda r: (r.recall, -r.attacks))[:18]
    A("### 3.1 最弱的 18 个规则族（样本数 ≥ 3）")
    A("")
    A("| CRS 规则 | 类别 | 性质 | 样本 | 检出 | 检出率 |")
    A("|---|---|---|---:|---:|---:|")
    for r in worst:
        A(f"| `{r.rule}` | {r.category} | {r.kind} | {r.attacks} | {r.detected} "
          f"| {r.recall:.0%} |")
    A("")
    zero = [r for r in res.rules.values() if r.attacks and r.detected == 0]
    A(f"### 3.2 完全零命中的规则族：**{len(zero)} / {len(res.rules)}**")
    A("")
    A("这些是「CRS 能抓、我们一条抓不到」的规则族。列出来而不是藏起来——"
      "它们就是下一步该补什么的最直接线索。")
    A("")
    A("| CRS 规则 | 类别 | 样本数 |")
    A("|---|---|---:|")
    for r in sorted(zero, key=lambda r: (r.category, -r.attacks))[:24]:
        A(f"| `{r.rule}` | {r.category} | {r.attacks} |")
    if len(zero) > 24:
        A(f"| … | | 另 {len(zero) - 24} 个 |")
    A("")
    best = sorted((r for r in res.rules.values() if r.attacks >= 3),
                  key=lambda r: -r.recall)[:10]
    A("### 3.3 覆盖最好的 10 个规则族")
    A("")
    A("| CRS 规则 | 类别 | 样本 | 检出 | 检出率 |")
    A("|---|---|---:|---:|---:|")
    for r in best:
        A(f"| `{r.rule}` | {r.category} | {r.attacks} | {r.detected} | {r.recall:.0%} |")
    A("")

    # ---------------------------------------------------------------- no_expect
    A(f"## 4. 「不该触发本规则」的 {res.no_expect:,} 条：我们命中了 "
      f"{res.no_expect_hit:,} 条")
    A("")
    A("**这个数字不是误报率。** CRS 的 `no_expect_ids` 是规则维度的期望，含义有三种，"
      "混在同一批样本里。分桶之后信号才清楚：")
    A("")
    A("| 分桶 | `desc` 的写法 | 含义 | 样本 | 我们命中 |")
    A("|---|---|---|---:|---:|")
    names = {
        "explicit": ("`NEGATIVE:` / `Don't match`",
                     "**这条本就不该匹配**。命中它 = 判据过宽",),
        "known_fp": ("`Known false positive`",
                     "**这条看着就是攻击**、CRS 为控误报故意放过。命中它 = 我们更激进",),
        "unclassified": ("其它自由文本",
                         "多为攻击描述（别的规则该抓）或上下文说明",),
        "undocumented": ("没写 `desc`", "无从判断",),
    }
    for k in ("explicit", "known_fp", "unclassified", "undocumented"):
        if res.ne_total_by_kind.get(k):
            label, meaning = names[k]
            A(f"| `{k}` | {label} | {meaning} | {res.ne_total_by_kind[k]:,} "
              f"| {res.ne_hit_by_kind.get(k, 0):,} |")
    A("")
    hit_explicit = res.ne_hit_by_kind.get("explicit", 0)
    hit_known = res.ne_hit_by_kind.get("known_fp", 0)
    A("把两个桶分开是**必需**的，因为它们的含义相反：")
    A("")
    A(f"- `explicit` 桶命中 **{hit_explicit}** 条，这才是「判据可能过宽」的信号，"
      f"要逐条看；")
    A(f"- `known_fp` 桶命中 **{hit_known}** 条，方向相反——`desc` 写着 "
      f"`Known false positive` 的样本本身就是攻击（比如 "
      f"`'||(select(pg_sleep(15))where(true))||'`），CRS 为了控误报故意放过，我们抓了。"
      f"**这不是错，是取舍不同。**")
    A("")
    A("第一版把这两个桶混成一个「反例」桶，得到的结论是「误报 25 条、4.44%」——"
      "**一个方向都指反了的指标**。")
    A("")
    if res.ne_hit_samples:
        A("命中的样本（最多 20 条，供逐条判断）：")
        A("")
        A("| 样本 | 桶 | CRS 规则 | 命中的我们的规则 | `desc` | 载荷 |")
        A("|---|---|---|---|---|---|")
        for s in res.ne_hit_samples:
            A(f"| `{s['id']}` | {s['kind']} | `{s['rule']}` "
              f"| {', '.join(f'`{h}`' for h in s['hits'])} "
              f"| {_short(s['desc'], 40)} | `{_short(_payload_of(s), 46)}` |")
        A("")

    # ---------------------------------------------------------------- 归因
    total_miss = sum(res.misses_by_rule.values())
    # 标题里的数字必须算出来。v2.4 之前这里写的是 "1627 条"，靠 `--out` 落盘时
    # 报告标题与正文（`{total_miss}`）就已经对不上了——**生成器自己吐旧数，
    # 报告新鲜度测试抓不到**（`render()` 每次重跑都会产出同样的错标题）。
    A(f"## 5. 漏检归因：{total_miss:,} 条漏在哪，按 CRS 规则族排序")
    A("")
    A(f"这是把 {res.recall():.1%} 从「一个数字」变成「一个可解释的现象」的那一步。"
      "归因不靠猜载荷特征——第一版那么试过，**89.9% 归不进任何桶**，"
      "因为真正的规律在规则编号上：`930120` 判「是否提到敏感文件名」，"
      "与载荷长什么样无关。所以直接按上游 `msg` 归类。")
    A("")
    A(f"漏检合计 **{total_miss:,}** 条，分布在前 {len(res.misses_by_rule)} 个规则族上。"
      "下表按漏检条数排序：")
    A("")
    A("| CRS 规则 | 类别 | CRS 侧判据（上游 `msg`） | 该族样本 | 漏检 | 占总漏检 |")
    A("|---|---|---|---:|---:|---:|")
    top = res.misses_by_rule.most_common(15)
    for rid, n in top:
        r = res.rules.get(rid)
        msg = res.rule_msgs.get(str(rid), "—")
        A(f"| `{rid}` | {r.category if r else '—'} | {_short(msg, 52)} "
          f"| {r.attacks if r else 0} | {n} | {n / total_miss:.1%} |")
    A("")
    covered = sum(n for _, n in top)
    A(f"**前 15 个规则族占了 {covered:,}/{total_miss:,} = {covered / total_miss:.1%} 的漏检**，"
      "其余 130 多个规则族各自只有个位数。这条分布说明：差距不是「整体判据都松」，"
      "而是**集中在少数几个我们根本没做的检测方向上**。")
    A("")

    # 两组规则族的归类来自上游 msg 的字面语义（"command without evasion" /
    # "SQL function name detected" / "SQL Operator Detected"），不是按漏检数挑的
    # ——**先分组再求和，不能先看谁漏得多再给它编一个理由**。
    rce_word = [932235, 932236, 932239, 932260]
    sql_word = [942120, 942151, 942190, 942210, 942362, 942380, 942390, 942410]
    win_batch = [932140]
    groups = [
        ("Unix 命令词检测", rce_word),
        ("SQL 词法 / 算子检测", sql_word),
        ("Windows batch 语法", win_batch),
    ]
    # 先算再写标题：标题里的百分比必须是算出来的（v2.4 之前写死 "41%"，
    # 加了 cmdline 判据后实际是 41.2%，标题却还停在 41%）。
    gm = sum(res.misses_by_rule.get(k, 0) for _, ids in groups for k in ids)
    gn = sum(res.rules[k].attacks for _, ids in groups for k in ids if k in res.rules)
    A(f"### 5.1 三组规则族造成了 {gm / total_miss:.0%} 的漏检")
    A("")
    A("按上游 `msg` 的字面语义分组（`command without evasion` / `SQL function name "
      "detected` / `SQL Operator Detected` / `Windows FOR/IF`）：")
    A("")
    A("| 组 | 规则族 | 该组样本 | 漏检 | 占总漏检 |")
    A("|---|---|---:|---:|---:|")
    for label, ids in groups:
        m = sum(res.misses_by_rule.get(k, 0) for k in ids)
        n = sum(res.rules[k].attacks for k in ids if k in res.rules)
        A(f"| {label} | `{'`、`'.join(str(k) for k in ids)}` "
          f"| {n} | {m} | {m / total_miss:.1%} |")
    A(f"| **合计** | | **{gn}** | **{gm}** | **{gm / total_miss:.1%}** |")
    A("")
    A("前两组描述的是同一件事：")
    A("")
    A("> **CRS 判「出现了危险词」，本项目判「出现了注入语法结构」。**")
    A("")
    A("`foo=cat /etc/passwd` 在 CRS 侧命中 `932236`（参数里出现了命令词）；"
      "在本项目侧，v2.3 时它不命中，因为命令注入判据要求**四个语法位置**之一"
      "（`$(cmd)` / 反引号 / `;` `&&` `||` + 命令名 + 命令上下文 / 单管道 + 参数）；"
      "**v2.4 补上第五个位置之后它命中了**——但判据仍然不是「参数里有命令词」，"
      "而是「参数值整段是命令行」（命令名后面紧跟选项或路径），"
      "见 `bench/results/cmd_syntax_curve.md`。"
      "SQL 侧同理：`pay=RegExp`、`var2=LIKE NULL` 是 CRS `942120`「算子检测」的菜，"
      "我们的判据要求出现 `union select`、布尔盲注比较、报错函数这类**语法结构**。")
    A("")
    A("这不是新发现，是 v2.1 那条「判据要描述形状、不要枚举写法」的**账单**："
      "收紧形状换来了 CIC 真实流量上的 4/150,262 误报，代价就是在 token 级样本上大量漏检。"
      "**两份数字必须一起看**——只看这一份会得出「引擎很弱」，只看 CIC 会得出「引擎很准」，"
      "两个结论都是片面的。")
    A("")
    A("第三组是纯粹的覆盖面问题：命令注入判据按 Unix shell 写，Windows batch 的 "
      "`FOR`/`IF` 是另一套语法，`932140` 的 154 条样本**一条都没考虑过**。")
    A("")
    A("### 5.2 其余缺口：解析层与编码层")
    A("")
    rest = [(rid, n) for rid, n in top if rid not in
            {k for _, ids in groups for k in ids}][:6]
    if rest:
        A("| CRS 规则 | 上游 `msg` | 漏检 | 缺口性质 |")
        A("|---|---|---:|---|")
        notes = {
            942550: "JSON 结构化载体——本项目只读请求文本，不解析 JSON",
            930120: "敏感文件名单（`/.ssh/id_rsa`、`.docker/secrets`）——只有形状判据，没有名单",
            930130: "同上",
            942130: "SQL 报错关键字——依赖数据库错误指纹库",
            930110: "路径遍历的 Windows 反斜杠与 multipart 文件名变体",
            932130: "这一类**我们做了**（36 条样本检出 8）：漏的是方括号 glob、"
                    "`${IFS}`、`$[2+2]` 这些 shell 词法特性，是 v2.1 写明的已知边界",
        }
        for rid, n in rest:
            A(f"| `{rid}` | {_short(res.rule_msgs.get(str(rid), '—'), 46)} | {n} "
              f"| {notes.get(rid, '—')} |")
        A("")

    # ---------------------------------------------------------------- 漏检
    A("## 6. 漏检抽样：每类最典型的 8 条")
    A("")
    for cat in sorted(res.miss_samples):
        A(f"### `{cat}`")
        A("")
        A("| 样本 | CRS 规则 | 请求 | 载荷 |")
        A("|---|---|---|---|")
        for s in res.miss_samples[cat]:
            A(f"| `{s['id']}` | `{s['rule']}` | {s['method']} `{_short(s['path'], 26)}` "
              f"| `{_short(_payload_of(s), 62)}` |")
        A("")

    # ---------------------------------------------------------------- 边界
    A("## 7. 边界与口径")
    A("")
    A("- **命中一条就算检出**。CRS 的 rule id 与本项目的 rule id 没有对应关系，"
      "不做逐规则对齐——硬对齐会造出一个假的精确率。")
    A("- **多阶段用例只取第一段**。导入时记了 `multi_stage`，不单独统计。")
    A("- **解析层能力打不到是架构差异**。CRS 大量用例靠 `REQUEST_METHOD`、"
      "`REQUEST_PROTOCOL`、XML/JSON 解析、`%uXXXX` best-fit 判定，"
      "本项目只做请求文本上的签名匹配。这不是判据松紧的问题，换判据解决不了。")
    A("- **误报不在这里测**。真实流量误报见 BENCHMARK §2.10（CIC-IDS2017 "
      "150,262 条请求上 4 条）。这份语料没有业务形态。")
    A("- **和 `crs.go` 那 59 条的关系**：那 59 条是这四个方法文件里的子集，"
      "导入器在同样 4 个文件上重现了**完全相同的 32 条检出**（分母 65 而非 59，"
      "因为补上了当初「暂未转写」的 6 条 Cookie 载体样本）。这是导入器的自校验。")
    A("")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="在 OWASP CRS 全量回归集上评测 sentinelwatch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                    help="import_crs.py 生成的语料")
    ap.add_argument("--rules", default=str(DEFAULT_RULES))
    ap.add_argument("--out", help="写一份 Markdown 报告到该路径")
    ap.add_argument("--json", action="store_true", help="把汇总 JSON 打到 stderr")
    args = ap.parse_args(argv)

    corpus = Path(args.corpus)
    if not corpus.is_file():
        print(f"找不到语料 {corpus}\n先运行：python bench/import_crs.py --src "
              "<coreruleset>/tests/regression/tests --out bench/corpus/crs_regression.json",
              file=sys.stderr)
        return 2

    res = evaluate(corpus, Path(args.rules))
    report = render(res)
    # 用 write 而不是 print：print 会多补一个换行，导致 `--out` 落盘的字节
    # 与打到 stdout 的字节不一致，`run_crs_bench.py | diff - 报告.md` 这种
    # 「报告是否最新」的校验就没法用了。
    sys.stdout.write(report)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        print(f"报告写入 {out}", file=sys.stderr)
    if args.json:
        print(json.dumps({
            "attacks": res.attacks,
            "detected": res.detected,
            "recall": round(res.recall(), 4),
            "signature_only": {"attacks": res.sig_only()[0],
                               "detected": res.sig_only()[1],
                               "recall": round(res.sig_only()[2], 4)},
            "no_expect": res.no_expect,
            "no_expect_hit": res.no_expect_hit,
            "by_category": {
                k: {"attacks": c.attacks, "detected": c.detected,
                    "no_expect": c.no_expect, "no_expect_hit": c.no_expect_hit}
                for k, c in res.cats.items()
            },
        }, ensure_ascii=False, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
