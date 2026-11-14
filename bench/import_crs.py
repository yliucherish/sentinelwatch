#!/usr/bin/env python3
"""把 OWASP CRS 的回归测试集导入成本项目可直接评测的语料。

为什么要有这个脚本
------------------
`bypasslab/internal/payloads/crs.go` 里那 59 条是**手工转写**的：挑 4 个规则文件
（942100 / 941100 / 930100 / 932130），逐条抄进 Go 源码。当时这么做的理由很实际——
一次抓取、立刻可用、不用往仓库里塞半个 MB 的数据。但它有个天花板：

    我们声称的四类里，CRS 全量回归集一共 **2503 条用例**（148 个规则文件），
    手抄只覆盖了其中 **59 条 = 2.4%**。

59 条时「CRS 32/59 = 54.2%」这个数字被写进了 README。样本量这么小，一条多抓
或少抓就是 ±1.7 个百分点，而且这 4 个文件挑的都是 libinjection 那几条**最像正则
能抓的形状**的规则——数字偏乐观不是意外，是挑样本的必然结果。

手抄扩到 2503 条不可行（42 倍工作量，且人工转写必然引入不一致）。所以改成解析。

为什么产物要提交进仓库
----------------------
1. 下游 `bench/run_crs_bench.py` 必须离线可跑：它不该要求使用者先 clone 一个
   7 MB 的第三方仓库、再装 PyYAML，才能复现一个数字。
2. 第三方仓库随时会变。评测必须钉在**一个具体 commit** 上，否则「上个月 54%、
   这个月 61%」可能只是因为上游改了测试集。
3. 产物是小体积的纯文本 JSON，可 diff、可 code review。

所以：导入脚本 + 生成物**都**进仓库，生成物头部记来源 commit。骨架里有测试
（`tests/test_crs_corpus.py`）守着「生成物没被手改、计数没漂移」。

为什么不并进那 184 条的主矩阵
-----------------------------
主矩阵的分母从 v1.8 到 v2.1 一直在变（117 → 184），每次变都有人问「能不能直接
比」。能比的是那四列**分母没变过**的分类（SQLi / XSS / 路径遍历 / 反序列化）。
把 2503 条再混进去，这四列也会被冲掉，等于把唯一可比的东西弄没了。

所以它是一份**独立测量**：自己的分母、自己的报告（`results/crs_regression.md`）、
在主矩阵旁边列出来，不参与主矩阵的加减。

关于 no_expect_ids（563 条）——**这是最容易搞错的一处口径**
-----------------------------------------------------------
第一版导入器把 `output.log.no_expect_ids` 当成「良性样本」，跑出「563 条反例上
误报 25 条 = 4.44%」，看上去像个可用的误报率。**它是错的。**

抽出来看第一批「误报」：

    CRS-942360-30   '||(select(pg_sleep(15))where(true))||'/investigate
    CRS-942360-31   UNION ALL SELECT NULL,NULL,CONCAT(CONCAT('qqkjq',...

这两条是货真价实的 SQL 注入，`desc` 写的是 **"GH issue 1816 - Known false positive"**
——意思是 CRS 自己承认这里会误报、于是**故意不报**，不是「这条是良性流量」。

`no_expect_ids` 的语义是**规则维度**的：这条样本不该触发**这一个**规则
（因为应该由另一条规则抓，或者已知误报被接受）。它不提供样本维度的攻击/良性标签。
把它当良性用，会同时错两件事：低估自己的检出率，并把「我们比 CRS 更激进」误报成
「我们误报多」。

所以本语料只承认一种「该检出」：`expect_ids` 或 `log.match_regex`。563 条
`no_expect_ids` 单独成桶，既不进检出率分母，也不进误报率分母，报告里单列一节说明
「我们在这批『不该触发本规则』的样本上命中了多少」。

真实流量的误报仍然是 CIC-IDS2017 那 150,262 条请求上的 4 条（BENCHMARK §2.10）。
两者不可互替：那边的样本有真实业务形态，这边是指着规则写的测试用例。

用法
----
    git clone --depth 1 git@github.com:coreruleset/coreruleset.git /tmp/coreruleset
    python bench/import_crs.py \\
        --src /tmp/coreruleset/tests/regression/tests \\
        --out bench/corpus/crs_regression.json

    # 只看统计不写文件
    python bench/import_crs.py --src /tmp/coreruleset/tests/regression/tests --dry-run
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# 只导入**我们声称有判据**的四类。其余目录（931 RFI / 933 PHP / 944 Java /
# 920 协议校验 / 913 扫描器…）不进语料：把「没有这个能力」的样本算进分母，
# 是用分母惩罚自己。将来补了哪一类，再往这张表里加一行。
#
# category 必须等于 sentinelwatch 侧的 `crosscheck.COVERAGE` 键，否则那条用例
# 会被当成「未声明类别」静默踢出分母——**这种静默正是最该防的**，所以
# `tests/test_crs_corpus.py` 断言这里每个值都在 COVERAGE 里。
FAMILIES = {
    "REQUEST-930-APPLICATION-ATTACK-LFI": "path-traversal",
    "REQUEST-941-APPLICATION-ATTACK-XSS": "xss",
    "REQUEST-942-APPLICATION-ATTACK-SQLI": "sqli",
    "REQUEST-932-APPLICATION-ATTACK-RCE": "rce",
}

# CRS 里「异常字符分布」这一族规则（942430/942431/942432，
# *Restricted SQL Character Anomaly Detection*）用**字符频率计分**判定，
# 打一个 `'` 或 `;` 就算可疑。它们和本项目的签名式判据是两种范式：
# 要复现它们得引入 paranoia level + 阈值模型，那会改掉整个引擎的性格。
#
# 它们仍然进语料（数据不该被删），但打上 kind 标记，报告里单列一行：
# 「按签名型规则口径」与「按 CRS 全量口径」两个数字都给出来，读者自己判断。
ANOMALY_RULES = {942430, 942431, 942432}

_ID_RE = re.compile(r"^(\d+)\.yaml$")


def _as_text(v) -> str:
    """CRS 的 input.data 可能是字符串、字典（表单）或多行块。统一成线格式。"""
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        from urllib.parse import urlencode

        return urlencode({k: _as_text(x) for k, x in v.items()})
    return str(v)


def _split_uri(uri: str) -> tuple[str, str]:
    if not uri:
        return "/", ""
    path, sep, query = uri.partition("?")
    return (path or "/"), (query if sep else "")


def rule_messages(src: Path) -> dict[str, str]:
    """从 CRS 的规则文件里取 `id:N, ... msg:'...'`，做成 id → 描述。

    为什么要这个：漏检归因最容易变成「我猜这条规则大概是干什么的」。CRS 自己在
    `.conf` 里写着 `msg`，那是**上游给的权威描述**，比我的正则猜测靠谱一个量级。
    第一版归因用载荷特征猜（`%u` / XML / 宽字符…），结果 **89.9% 归不进任何桶**
    ——因为真正的规律在规则编号上（`930120` = 敏感文件访问，判据是一张文件名单，
    与载荷长什么样无关）。

    取不到就返回空字典，报告里相应位置留空，**不编造描述**。
    """
    # src = <repo>/tests/regression/tests
    rules_dir = src.parents[2] / "rules"
    if not rules_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    rx = re.compile(r"id:(\d{6}),(?:[^']*?)msg:'((?:[^']|\\')*)'", re.DOTALL)
    for fp in sorted(rules_dir.glob("REQUEST-9*.conf")):
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for rid, msg in rx.findall(text):
            out.setdefault(rid.lstrip("0") or rid, msg.strip())
    # 规则文件里的 id 是 930120 这种；语料里也是 int，键统一成 str(int)
    return {str(int(k)): v for k, v in out.items() if k.isdigit()}


def _git_commit(src: Path) -> str:
    """向上找 .git，取 HEAD。拿不到就返回空串——**不编一个假的**。"""
    d = src.resolve()
    for parent in [d, *d.parents]:
        if (parent / ".git").exists():
            try:
                out = subprocess.run(
                    ["git", "-C", str(parent), "rev-parse", "HEAD"],
                    capture_output=True, text=True, timeout=20, check=False,
                )
                if out.returncode == 0:
                    return out.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return ""
            return ""
    return ""


def load_yaml(p: Path):
    try:
        import yaml  # noqa: PLC0415 — 只有这个脚本需要它，运行时零依赖
    except ModuleNotFoundError:  # pragma: no cover - 环境问题，不是逻辑分支
        sys.exit("需要 PyYAML：pip install pyyaml（只有导入脚本需要，不影响运行时）")
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


_NEG_KNOWN_FP = re.compile(r"known false positive|accepted false positive|"
                           r"gh issue \d+ - known", re.IGNORECASE)
_NEG_EXPLICIT = re.compile(
    r"negative|don'?t match|do not match|false[ -]?positive|\bfp\b|"
    r"should not match|no false positive|not expected",
    re.IGNORECASE,
)


def _negative_kind(desc: str) -> str:
    """给 `no_expect_ids` 样本分桶。**这是启发式，不是判定。**

    实测 563 条 `no_expect_ids` 的 `desc` 至少三种写法：

        "NEGATIVE: Chinese text (should not match - no false positive)"  真反例
        "Don't match on natural english sentences in quotes"             真反例
        "GH issue 1816 - Known false positive"                           CRS 自己认了的误报
        "SQL Injection Attack: SQL Tautology"                            攻击样本，
                                                                        只是不该由
                                                                        **这一条**规则抓

    第 3 与第 2 必须分开：前者是「这条**看起来就是攻击**、CRS 为了控误报故意放过」，
    我们抓了是**更激进**；后者是「这条本就不该匹配」，我们抓了是**判据过宽**。
    混成一个桶，就会把「我们更激进」误读成「我们有 bug」。

    最后一种说明了 `no_expect_ids` 的真正语义：它是**规则维度**的期望，不是样本维度
    的标签。所以这个函数只能粗分，报告里必须写明是启发式——把自由文本 desc
    当权威标签用，等于用一个更不可靠的东西替代 CRS 原本就不提供的信息。
    """
    if not desc:
        return "undocumented"
    if _NEG_KNOWN_FP.search(desc):
        return "known_fp"
    return "explicit" if _NEG_EXPLICIT.search(desc) else "unclassified"


def import_family(fam_dir: Path, category: str, stats: Counter,
                  per_rule: Counter, unreadable: list[str]) -> list[dict]:
    cases: list[dict] = []
    for fp in sorted(fam_dir.iterdir()):
        m = _ID_RE.match(fp.name)
        if not m:
            continue                     # .yml 备份、README 之类
        rule_id = int(m.group(1))
        try:
            doc = load_yaml(fp)
        except OSError as e:
            # 某些样本会被本机安全软件拦读（实测 933 下有两个文件，933 不在范围内）。
            # **记下来并继续**，而不是静默少算——静默少算会让分母变小、检出率变好看。
            unreadable.append(f"{fp.parent.name}/{fp.name}: {e}")
            stats["unreadable_files"] += 1
            continue
        if not isinstance(doc, dict):
            stats["skipped_bad_doc"] += 1
            continue

        for t in doc.get("tests") or []:
            stages = t.get("stages") or []
            if not stages:
                stats["skipped_no_stage"] += 1
                continue
            st = stages[0]
            inp = st.get("input") or {}
            out = st.get("output") or {}
            log = out.get("log") or {}

            expect = log.get("expect_ids") or []
            no_expect = log.get("no_expect_ids") or []
            # CRS 有第二种正例写法：不断言规则 id，而是断言日志里出现了某个片段
            # （`log.match_regex`）。实测 932200-13 与 932207-07 就是这种，
            # 内容都是货真价实的命令注入。只认 expect_ids 会把它们当成「期望未知」
            # 丢掉——**丢两条正例等于把漏检洗成不存在**。
            match_regex = log.get("match_regex")
            if no_expect:
                is_attack = False
            elif expect or match_regex:
                is_attack = True
            else:
                # 既没 expect 也没 no_expect：这条用例考的是状态码而非规则命中，
                # 归到「不知道」，不算进分母。**猜一个方向比丢掉更糟。**
                stats["skipped_unknown_expectation"] += 1
                continue

            method = str(inp.get("method") or "GET").upper()
            path, query = _split_uri(_as_text(inp.get("uri")))
            body = _as_text(inp.get("data"))
            headers = {}
            for k, v in (inp.get("headers") or {}).items():
                headers[str(k)] = _as_text(v)
            # CRS 的 Host 是 "localhost"，对本项目无意义，去掉让下游自己填。
            headers.pop("Host", None)
            headers.pop("host", None)

            multi = len(stages) > 1
            test_id = t.get("test_id")
            desc = str(t.get("desc") or "").strip()
            cases.append({
                "id": f"CRS-{rule_id}-{test_id}",
                "set": "crs-regression",
                "category": category,
                "name": (desc or f"{rule_id} test {test_id}")[:160],
                "is_attack": is_attack,
                # `expectation` 比 `is_attack` 更准确：CRS 的 `no_expect_ids` 说的
                # 是「这条**不该触发这个规则**」，不是「这条是良性」。见文件头
                # 「关于 no_expect_ids」那一节——把两者混为一谈会得到一个
                # 完全错误的误报率。
                "expectation": "should_match" if is_attack else "should_not_match",
                "negative_kind": (None if is_attack else _negative_kind(desc)),
                "desc": desc,
                "method": method,
                "path": path,
                "query": query,
                "body": body,
                "ua": "",
                "headers": headers,
                "source_rule": rule_id,
                "kind": "anomaly" if rule_id in ANOMALY_RULES else "signature",
                "multi_stage": multi,
            })
            stats["test"] += 1
            stats["attack" if is_attack else "no_expect"] += 1
            if not is_attack:
                stats["negative_" + _negative_kind(desc)] += 1
            if rule_id in ANOMALY_RULES:
                stats["anomaly"] += 1
            per_rule[rule_id] += 1
    return cases


def _dump(payload: dict) -> str:
    """把语料序列化成「头部缩进、**一条样本一行**」的 JSON。

    为什么不直接用 `json.dumps(indent=1)`：2,503 条样本会摊成 5.5 万行，
    想看清「哪条样本变了」要在 diff 里翻半天，等于放弃了「纯文本可 review」
    这个把产物放进仓库的唯一理由。

    为什么不干脆不缩进：整份压成一行，diff 只会显示「第 1 行变了」。

    一条样本一行是这两者之间唯一可用的点：`git diff` 直接告诉你哪几条用例
    新增/删除/改动，其余行纹丝不动。仍然是合法 JSON。
    """
    head = {k: v for k, v in payload.items() if k != "cases"}
    lines = ["{"]
    for k, v in head.items():
        lines.append(" " + json.dumps(k, ensure_ascii=False) + ": "
                     + json.dumps(v, ensure_ascii=False) + ",")
    cases = payload["cases"]
    lines.append(' "cases": [')
    for i, c in enumerate(cases):
        sep = "," if i < len(cases) - 1 else ""
        lines.append("  " + json.dumps(c, ensure_ascii=False) + sep)
    lines.append(" ]")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="导入 OWASP CRS 回归测试集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--src", required=True,
                    help="coreruleset 仓库的 tests/regression/tests 目录")
    ap.add_argument("--out", help="输出 JSON 路径")
    ap.add_argument("--dry-run", action="store_true", help="只打印统计")
    args = ap.parse_args(argv)

    src = Path(args.src)
    if not src.is_dir():
        print(f"找不到目录 {src}", file=sys.stderr)
        return 2

    stats: Counter = Counter()
    per_rule: Counter = Counter()
    unreadable: list[str] = []
    by_family: dict[str, Counter] = defaultdict(Counter)
    all_cases: list[dict] = []

    for dirname, category in FAMILIES.items():
        d = src / dirname
        if not d.is_dir():
            print(f"缺少家族目录 {dirname}（跳过错，但计数会不对）", file=sys.stderr)
            stats["missing_family"] += 1
            continue
        got = import_family(d, category, stats, per_rule, unreadable)
        for c in got:
            by_family[category]["attack" if c["is_attack"] else "no_expect"] += 1
            if c["kind"] == "anomaly":
                by_family[category]["anomaly"] += 1
        all_cases.extend(got)

    # 同一个 id 出现两次会让下游按 id 聚合时静默合并两条样本，
    # 分母就错了。直接失败。
    ids = Counter(c["id"] for c in all_cases)
    dup = [i for i, n in ids.items() if n > 1]
    if dup:
        print(f"重复 id：{dup[:5]}", file=sys.stderr)
        return 3

    print(f"{'category':16} {'attack':>7} {'no_exp':>7} {'total':>7} {'anomaly':>8}")
    for cat in FAMILIES.values():
        c = by_family[cat]
        print(f"{cat:16} {c['attack']:7} {c['no_expect']:7} "
              f"{c['attack'] + c['no_expect']:7} {c['anomaly']:8}")
    print(f"{'TOTAL':16} {stats['attack']:7} {stats['no_expect']:7} {stats['test']:7} "
          f"{stats['anomaly']:8}")
    print(f"规则文件数 {len(per_rule)}")
    for k in sorted(k for k in stats if k.startswith("negative_")):
        print(f"  no_expect 分桶 {k[len('negative_'):]}: {stats[k]}")
    for k in ("skipped_unknown_expectation", "skipped_no_stage",
              "skipped_bad_doc", "unreadable_files", "missing_family"):
        if stats[k]:
            print(f"  {k}: {stats[k]}")
    for u in unreadable:
        print(f"  不可读: {u}")

    if args.dry_run or not args.out:
        return 0

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    msgs = rule_messages(src)
    payload = {
        "source": "coreruleset/coreruleset tests/regression/tests",
        "commit": _git_commit(src),
        # 上游 msg：让「漏检归因」有权威描述可引用，而不是靠猜载荷特征
        "rule_msgs": {str(k): msgs[str(k)] for k in per_rule if str(k) in msgs},
        "imported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "families": {cat: dict(by_family[cat]) for cat in FAMILIES.values()},
        "counts": {
            "total": stats["test"],
            "attack": stats["attack"],
            "no_expect": stats["no_expect"],
            "anomaly": stats["anomaly"],
            "rules": len(per_rule),
        },
        "skipped": {k: v for k, v in stats.items()
                    if k.startswith("skipped_") or k in
                    ("unreadable_files", "missing_family")},
        "unreadable": unreadable,
        "cases": all_cases,
    }
    out.write_text(_dump(payload), encoding="utf-8")
    print(f"\n写入 {out}  ({out.stat().st_size:,} 字节, "
          f"{_dump(payload).count(chr(10)):,} 行)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
