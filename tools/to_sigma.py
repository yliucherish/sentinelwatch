#!/usr/bin/env python3
"""把 SentinelWatch 的检测规则导出为 Sigma YAML（v1.3）。

为什么做这件事（面试可讲）
--------------------------
Sigma 是检测规则的"通用语"——类比 YARA 之于文件、Snort 之于流量。一条规则
能转成 Sigma，就等于能被 Splunk / Elastic / Sentinel / QRadar 等几十个后端
直接消费。这是"检测逻辑能在社区里流通"的最低门槛，也是给上游提 PR、把自己的
判据并入行业标准库的前置条件（任务 B）。

但转换不是格式翻译，而是**语义对齐**。两边的表达能力不完全相同：

    SentinelWatch                            Sigma
    ---------------------------------------  -----------------------------
    match.raw_contains（全部子串都出现）      all of selection*
    match.raw_contains_any（任一出现）        1 of selection*
    threshold: 1 + 签名（单条即告警）          可直接表达
    threshold: N（窗口内 N 次才告警）          **无法表达**——Sigma 原生没有
                                              "时间窗内计数"语法，要靠 SIEM 侧
                                              correlation 规则
    大小写敏感的子串匹配                       |contains 默认**不区分**大小写

所以本工具的核心设计决定是：**宁可不转，不转错**。阈值规则直接抛
`NotConvertible` 并说明原因，而不是悄悄生成一条阈值=1 的规则——那条规则上线
后会在真实环境里刷屏，比没有规则更糟。大小写差异用 `--cased` 显式消解。

用法
----
    python tools/to_sigma.py                    # 全部可转规则 → sigma/
    python tools/to_sigma.py --check            # 只看哪些能转、哪些不能
    python tools/to_sigma.py --out build/sigma  # 换个输出目录
    python tools/to_sigma.py --cased            # |contains|cased，与源规则严格等价
    python tools/to_sigma.py --date 2026-11-04  # 固定 date 字段（可复现构建）

导出结果用官方工具校验：
    sigma check sigma/            # 需要 pip install sigma-cli
"""
from __future__ import annotations

import argparse
import sys
import uuid
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.detector import Rule, load_rules  # noqa: E402

DEFAULT_RULES = ROOT / "rules"
DEFAULT_OUT = ROOT / "sigma"
PROJECT_URL = "https://github.com/yliucherish/sentinelwatch"
AUTHOR = "yliucherish"

# Sigma 的 level 合法取值（超出范围的 severity 一律降级到 medium，
# 而不是让生成的 YAML 带着非法值出门）。
_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}

# event_type → Sigma 侧字段名。SentinelWatch 的 raw 是"整行日志"，normalized
# 是"归一化后的完整请求"；Sigma 没有"整个请求"这种字段，只能落在一个具体字段
# 上。这里给的是**最常用的近似**，导出文件的头部注释会提醒按后端 schema 改。
_FIELD_BY_EVENT = {
    "http_request": "cs-uri-query",
    "app_log": "message",
}
_LOGSURCE_BY_EVENT = {
    "http_request": {"category": "webserver"},
    "app_log": {"category": "webserver"},
}


class NotConvertible(Exception):
    """该规则无法等价表达为 Sigma 规则（原因写在异常消息里）。"""


def _default_field(rule: Rule) -> str:
    for et in rule.event_types:
        if et in _FIELD_BY_EVENT:
            return _FIELD_BY_EVENT[et]
    return "message"


def _default_logsource(rule: Rule) -> dict:
    for et in rule.event_types:
        if et in _LOGSURCE_BY_EVENT:
            return dict(_LOGSURCE_BY_EVENT[et])
    return {"category": "webserver"}


def _check_convertible(rule: Rule) -> None:
    """不能转的情况集中在这里判定（错误消息要能直接贴进 issue）。"""
    if not rule.match:
        raise NotConvertible(
            f"规则 `{rule.id}` 是纯阈值规则（threshold={rule.threshold}，无 match "
            "签名条件）。Sigma 原生不支持\"时间窗内计数\"，要拆成两步："
            "① Sigma 产出单条事件告警；② 在 SIEM 侧用 correlation 规则做窗口聚合。"
        )
    if rule.threshold > 1:
        raise NotConvertible(
            f"规则 `{rule.id}` 的 threshold={rule.threshold} > 1，需要窗口聚合，"
            "Sigma 无法表达（同上：需 SIEM 侧 correlation）。"
        )
    if not (rule.match.get("raw_contains") or rule.match.get("raw_contains_any")):
        raise NotConvertible(
            f"规则 `{rule.id}` 的 match 里没有 raw_contains / raw_contains_any，"
            "本工具只认这两种判据。"
        )


def _uuid_for(rule: Rule) -> str:
    """确定性 UUID：同一条规则每次导出得到同一个 id。

    Sigma 要求 id 是 UUID 且**跨仓库唯一**。用 uuid5（基于名字的散列）而不是
    uuid4（随机），是为了让重复导出结果字节一致——否则每次跑 CI 都会产生
    "规则被改动"的假 diff，review 无法进行。
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{PROJECT_URL}/{rule.id}"))


def _references(rule: Rule, meta: dict) -> list[str]:
    """CVE 标签自动补 NVD 链接（cve.2021-44228 → CVE-2021-44228）。

    ⚠️ Sigma 的 CVE tag 规范是 `cve.YYYY-NNNN`（**连字符**），不是
    `cve.YYYY.NNNN`。这个细节是跑官方 `sigma check` 时才发现的：它的
    CVETagValidator 正则是 `^\\d+-\\d+$`，写成点号会报 InvalidPatternTagIssue。
    """
    refs = [str(r) for r in (meta.get("references") or [])]
    for tag in rule.tags:
        if not tag.startswith("cve."):
            continue
        parts = tag[4:].split("-", 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            cve = f"CVE-{parts[0]}-{parts[1]}"
            url = f"https://nvd.nist.gov/vuln/detail/{cve}"
            if url not in refs:
                refs.append(url)
    return refs


def _detection(rule: Rule, field: str, cased: bool) -> dict:
    """把 match 的 AND / OR 两个操作符映射到 Sigma 的 selection + condition。

    Sigma 里"同一个 key 下给列表"是 OR 语义，所以 AND 必须拆成多个独立
    selection（`all of selection_all_*`），不能塞进同一个 key——这是最容易
    把 AND 写成 OR 的地方，也是本函数唯一需要小心的地方。
    """
    modifier = f"{field}|contains|cased" if cased else f"{field}|contains"
    det: dict = {}
    conds: list[str] = []

    for i, sub in enumerate(rule.match.get("raw_contains") or [], 1):
        det[f"selection_all_{i}"] = {modifier: sub}
    if det:
        conds.append("all of selection_all_*")

    any_sel = {}
    for i, sub in enumerate(rule.match.get("raw_contains_any") or [], 1):
        any_sel[f"selection_any_{i}"] = {modifier: sub}
    det.update(any_sel)
    if any_sel:
        conds.append("1 of selection_any_*")

    det["condition"] = " and ".join(conds)
    return det


def to_sigma(rule: Rule, *, cased: bool = False, today: date | None = None) -> dict:
    """单条规则 → Sigma 规则 dict（字段顺序按 SigmaHQ 仓库的惯例）。"""
    _check_convertible(rule)
    meta = rule.sigma or {}
    field = str(meta.get("field") or _default_field(rule))
    level = rule.severity if rule.severity in _SIGMA_LEVELS else "medium"

    data: dict = {
        "title": rule.name,
        "id": _uuid_for(rule),
        # experimental = 已在自建语料/靶场验证，未在真实生产环境跑过。
        # Sigma 的状态取值（stable/test/experimental/deprecated/unsupported）
        # 就是对"验证到哪一步"的诚实标注，不该为了好看写 stable。
        "status": "experimental",
        "description": rule.description or rule.name,
    }
    refs = _references(rule, meta)
    if refs:
        data["references"] = refs
    data["author"] = AUTHOR
    data["date"] = (today or date.today()).isoformat()
    if rule.tags:
        data["tags"] = list(rule.tags)
    data["logsource"] = dict(meta.get("logsource") or _default_logsource(rule))
    data["detection"] = _detection(rule, field, cased)
    data["falsepositives"] = [str(x) for x in (meta.get("falsepositives") or ["Unknown"])]
    data["level"] = level
    return data


def to_yaml_text(rule: Rule, *, cased: bool = False, today: date | None = None) -> str:
    """带溯源注释的 YAML 文本（SigmaHQ 的 PR 模板要求说明来源）。"""
    meta = rule.sigma or {}
    field = str(meta.get("field") or _default_field(rule))
    matched_on = str(rule.match.get("field", "raw")) if rule.match else "raw"
    lines = [
        f"# 由 SentinelWatch tools/to_sigma.py 从规则 `{rule.id}` 生成，请勿手改。",
        f"# 源规则：rules/*.yaml（{PROJECT_URL}）",
        f"# 字段映射：源规则在 `{matched_on}` 上做子串匹配，Sigma 侧落在 `{field}`。",
        "#   移植到具体后端时按目标 schema 替换，例如",
        "#   Elastic → url.query / http.request.body.content；Splunk → uri_query / _raw。",
    ]
    if not cased:
        lines.append(
            "# 大小写：Sigma 的 |contains 默认不区分大小写，比源规则（大小写敏感）宽松；"
        )
        lines.append("#   需要严格等价请用 `python tools/to_sigma.py --cased` 重新生成。")
    body = yaml.safe_dump(
        to_sigma(rule, cased=cased, today=today),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=200,  # 中文描述不折行，便于人读
    )
    return "\n".join(lines) + "\n" + body


def convert_dir(
    rules_dir: Path = DEFAULT_RULES,
    out_dir: Path | None = DEFAULT_OUT,
    *,
    cased: bool = False,
    today: date | None = None,
    dry_run: bool = False,
) -> tuple[list[Path], list[tuple[Rule, str]]]:
    """批量转换目录下所有规则文件，返回 (已写出的文件, [(跳过的规则, 原因)])。"""
    written: list[Path] = []
    skipped: list[tuple[Rule, str]] = []
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        for rule in load_rules(path):
            try:
                text = to_yaml_text(rule, cased=cased, today=today)
            except NotConvertible as exc:
                skipped.append((rule, str(exc)))
                continue
            if not dry_run and out_dir is not None:
                Path(out_dir).mkdir(parents=True, exist_ok=True)
                target = Path(out_dir) / f"{rule.id}.yml"
                target.write_text(text, encoding="utf-8")
                written.append(target)
            else:
                written.append(Path(f"{rule.id}.yml"))
    return written, skipped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="把 SentinelWatch 规则导出为 Sigma YAML",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--rules", default=str(DEFAULT_RULES), help="规则目录（默认 rules/）")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="输出目录（默认 sigma/）")
    ap.add_argument("--cased", action="store_true",
                    help="用 |contains|cased，与源规则的大小写敏感语义严格等价")
    ap.add_argument("--date", dest="date_str", default=None,
                    help="固定 Sigma date 字段（YYYY-MM-DD），用于可复现构建")
    ap.add_argument("--check", action="store_true",
                    help="只报告可转/不可转，不写文件")
    args = ap.parse_args(argv)

    today = None
    if args.date_str:
        from datetime import datetime
        today = datetime.strptime(args.date_str, "%Y-%m-%d").date()

    written, skipped = convert_dir(
        Path(args.rules), Path(args.out),
        cased=args.cased, today=today, dry_run=args.check,
    )

    verb = "可转换" if args.check else "已写出"
    print(f"[+] {verb} {len(written)} 条规则")
    if not args.check:
        assert args.out is not None
        print(f"    输出目录: {Path(args.out).resolve()}")
    if skipped:
        print(f"[!] 跳过 {len(skipped)} 条（无法等价表达为 Sigma）：")
        for rule, reason in skipped:
            print(f"    - {rule.id}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
