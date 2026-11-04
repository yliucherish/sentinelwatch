#!/usr/bin/env python3
"""统计 SentinelWatch 的 ATT&CK 覆盖情况（v1.3 / 任务 C）。

为什么要自己定义"分母"（面试可讲，也是本文档最重要的设计决定）
------------------------------------------------------------
说"我覆盖了 ATT&CK"是没有信息量的：企业矩阵有 200+ 技术，任何单点检测
项目的"覆盖率"都不到 0.x%，这个数字既不诚实也无法改进。

真正有意义的问法是：**在我声明要解决的威胁模型里，我覆盖了多少？**
所以本工具把 ATT&CK 技术分成三类，分母只取第一类：

    in-scope      三个数据源（认证日志 / 应用日志 / HTTP 流量）+ FIM
                  在原理上能看见的技术——这是分母，也是"该做的事"清单
    out-of-scope  同一条链路上但数据源看不见的技术（如需要 EDR 的内存注入）
                  ——写清原因，不用来充数，也不用来自责
    uncovered     in-scope 里当前还没做的——直接就是后续 backlog

覆盖率从规则文件的 `tags` **动态统计**，不是手抄的数字：删掉一条规则的
`attack.*` 标签，覆盖率会立刻下降。这样报告才是活的。

用法
----
    python tools/attack_coverage.py                 # 控制台表格
    python tools/attack_coverage.py --md reports/attack_coverage.md
    python tools/attack_coverage.py --json          # 机器可读
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.detector import load_rules_dir  # noqa: E402

DEFAULT_RULES = ROOT / "rules"


@dataclass(frozen=True)
class Technique:
    """in-scope 技术，以及"为什么它在范围内"。

    why 回答"数据源为什么看得见"（决定它该不该进分母），
    gap 回答"还没覆盖的话缺什么"（直接就是 backlog 条目）——
    两个问题分开写，避免把"看得见"当成"已经做了"。
    """

    id: str
    tactic: str
    name: str
    why: str   # 为什么三个数据源能看见它
    gap: str = ""  # 未覆盖时：缺什么才能补上


# ---- 检测范围声明（分母）----------------------------------------------------
# 只收"认证攻击 + Web 应用攻击"这条链路上、且现有数据源原理上可见的技术。
# 判断标准：攻击者做这个动作时，会不会在 sshd 日志 / 应用日志 / HTTP 报文
# 里留下可判定的痕迹。会 → in-scope；不会 → out-of-scope（见下表）。
IN_SCOPE: tuple[Technique, ...] = (
    Technique("T1110", "credential-access", "Brute Force",
              "sshd 的 Failed password 逐条落盘"),
    Technique("T1110.001", "credential-access", "Password Guessing",
              "同上，单账户密集失败"),
    Technique("T1110.003", "credential-access", "Password Spraying",
              "同一源 IP 对多账户各试少量密码",
              "加\"横向\"判据：按 IP 聚合后统计 distinct(username) ≥ N 且"
              "单账户失败次数低于爆破阈值——现有规则只按 IP 计数，喷一个账户和"
              "喷一百个账户出来的数一样"),
    Technique("T1110.004", "credential-access", "Credential Stuffing",
              "与泄露凭据库比对后才能判定，需外部情报",
              "接外部泄露凭据情报（HIBP / 内部 IOCs 库）做账号比对；纯日志侧无法"
              "区分\"撞库成功\"和\"用户打错密码\""),
    Technique("T1078", "defense-evasion", "Valid Accounts",
              "Accepted password 落在认证日志里，需基线才判异常",
              "需登录成功的行为基线（首见的主机/时段/源段组合），当前没有历史"
              "行为建模，任何 accepted_password 都看着一样"),
    Technique("T1087", "discovery", "Account Discovery",
              "sshd 对不存在用户返回 Invalid user，可计数"),
    Technique("T1087.001", "discovery", "Local Account",
              "Invalid user 枚举的目标就是本地账户",
              "检测能力已具备（ssh-user-enumeration 就是这条），只差在规则上补"
              "attack.t1087.001 标签——属于标注粒度问题，不是能力缺失"),
    Technique("T1046", "discovery", "Network Service Discovery",
              "PCAP 里能看到 SYN 探测，但当前解析器只提 HTTP",
              "解析器目前只提取完整 HTTP 事务，需加\"SYN 发出后无三次握手\"的"
              "半开连接统计，才能识别端口扫描"),
    Technique("T1190", "initial-access", "Exploit Public-Facing Application",
              "应用日志回显载荷、PCAP 里有原始请求"),
    Technique("T1059", "execution", "Command and Scripting Interpreter",
              "WebShell 请求体里带 Runtime.exec / system("),
    Technique("T1059.004", "execution", "Unix Shell",
              "一句话木马执行的多为 /bin/sh 命令",
              "在 webshell 规则里补 shell 元字符判据（/bin/sh、bash -c、$("),
    Technique("T1505.003", "persistence", "Web Shell",
              "落地请求的 body 带 eval($_POST 等特征"),
    Technique("T1071.001", "command-and-control", "Web Protocols",
              "C2 走 HTTP，PCAP 可见，需周期性判据",
              "需 beacon 周期检测：同一 URI 等间隔请求的间隔方差分析——"
              "这是时序统计，与现有\"子串匹配\"完全不同的判据类型"),
    Technique("T1041", "exfiltration", "Exfiltration Over C2 Channel",
              "响应体大小可见，当前未统计出站字节",
              "解析器丢弃了服务端响应体，需保留响应字节数并按源 IP 聚合出站量，"
              "再对\"单会话出站远超入站\"设阈值"),
    Technique("T1565.001", "impact", "Stored Data Manipulation",
              "FIM 基线比对能发现文件被改写",
              "FIM 已能报\"文件变了\"，但没接成 ATT&CK 判据也没打标签；"
              "需把被改路径限定到关键配置/二进制目录才能算这条"),
)

# ---- 明确不在范围内（不充数，写清原因）--------------------------------------
OUT_OF_SCOPE: tuple[tuple[str, str, str], ...] = (
    ("T1055", "Process Injection", "需要 EDR 的内存/进程回调视图，三个数据源都看不到"),
    ("T1003", "OS Credential Dumping", "需要主机侧进程访问 / 内存读取"),
    ("T1547", "Boot or Logon Autostart Execution", "需要注册表或 systemd 单元的写入监控"),
    ("T1486", "Data Encrypted for Impact", "需要文件熵值/批量改写检测，FIM 只能报单文件变更"),
    ("T1566", "Phishing", "邮件网关不在这套数据源里"),
    ("T1552", "Unsecured Credentials", "需要主机文件系统读取权限"),
)

# 子技术 → 父技术归并（用于"父技术层覆盖率"这个口径）
def _parent(tid: str) -> str:
    return tid.split(".")[0]


def collect_tags(rules) -> dict[str, list[str]]:
    """ATT&CK 技术 ID（大写） → 声明了该技术的规则 id 列表。"""
    index: dict[str, list[str]] = {}
    for rule in rules:
        for tag in rule.tags:
            if not tag.startswith("attack."):
                continue
            index.setdefault(tag[len("attack."):].upper(), []).append(rule.id)
    return index


def build_report(rules) -> dict:
    """算出两种口径的覆盖率 + 明细。

    为什么要两个数字：子技术层看"判据细不细"，父技术层看"场景全不全"。
    只报一个都容易被追问时站不住——两个都给出并说明口径，才经得起问。
    """
    index = collect_tags(rules)
    covered: list[Technique] = []
    uncovered: list[Technique] = []
    for tech in IN_SCOPE:
        (covered if tech.id in index else uncovered).append(tech)

    parents = {_parent(t.id) for t in IN_SCOPE}
    parents_covered = {_parent(t.id) for t in covered}

    extra = sorted(set(index) - {t.id for t in IN_SCOPE})

    return {
        "covered": covered,
        "uncovered": uncovered,
        "index": index,
        "extra_tags": extra,
        "sub_total": len(IN_SCOPE),
        "sub_covered": len(covered),
        "sub_rate": len(covered) / len(IN_SCOPE) if IN_SCOPE else 0.0,
        "parent_total": len(parents),
        "parent_covered": len(parents_covered),
        "parent_rate": len(parents_covered) / len(parents) if parents else 0.0,
    }


def _tactic_rows(report: dict) -> dict[str, list[Technique]]:
    rows: dict[str, list[Technique]] = {}
    for tech in IN_SCOPE:
        rows.setdefault(tech.tactic, []).append(tech)
    return rows


def render_console(report: dict) -> str:
    out: list[str] = []
    out.append("SentinelWatch ATT&CK 覆盖（分母 = 声明的检测范围）")
    out.append("=" * 78)
    for tactic, techs in _tactic_rows(report).items():
        out.append(f"\n[{tactic}]")
        for t in techs:
            mark = "✓" if t.id in report["index"] else "·"
            rules = ", ".join(report["index"].get(t.id, []))
            suffix = f"  ← {rules}" if rules else "  ← 未覆盖"
            out.append(f"  {mark} {t.id:<12} {t.name}{suffix}")
    out.append("")
    out.append("=" * 78)
    r = report
    out.append(f"子技术层：{r['sub_covered']}/{r['sub_total']} = {r['sub_rate']:.1%}"
               "（判据细不细）")
    out.append(f"父技术层：{r['parent_covered']}/{r['parent_total']} = {r['parent_rate']:.1%}"
               "（场景全不全）")
    out.append(f"不在范围：{len(OUT_OF_SCOPE)} 条技术（数据源原理上看不见，不计入分母）")
    if r["extra_tags"]:
        out.append(f"⚠️ 规则里有范围外的技术标签：{', '.join(r['extra_tags'])}"
                   "（要么补进 IN_SCOPE，要么删标签）")
    return "\n".join(out)


def render_md(report: dict) -> str:
    r = report
    lines = [
        "# SentinelWatch ATT&CK 覆盖报告",
        "",
        "> 本文件由 `tools/attack_coverage.py` 生成，请勿手改。"
        "覆盖率从规则文件的 `attack.*` 标签动态统计。",
        "",
        "## 覆盖率（两种口径）",
        "",
        "| 口径 | 覆盖 | 总数 | 覆盖率 | 看的是什么 |",
        "|---|---|---|---|---|",
        f"| 子技术层 | {r['sub_covered']} | {r['sub_total']} | "
        f"{r['sub_rate']:.1%} | 判据是否细化到子技术 |",
        f"| 父技术层 | {r['parent_covered']} | {r['parent_total']} | "
        f"{r['parent_rate']:.1%} | 攻击场景是否齐全 |",
        "",
        "**分母定义**：三个数据源（认证日志 / 应用日志 / HTTP 流量）+ FIM "
        "在原理上能看见的技术。不是全量 ATT&CK 矩阵——那个分母下任何单点项目"
        "都不到 1%，数字没有改进意义。",
        "",
        "## 明细",
        "",
        "| 技术 | 名称 | 战术 | 状态 | 对应规则 |",
        "|---|---|---|---|---|",
    ]
    for tech in IN_SCOPE:
        rules = r["index"].get(tech.id)
        state = "✅ 已覆盖" if rules else "⬜ 未覆盖"
        lines.append(
            f"| {tech.id} | {tech.name} | {tech.tactic} | {state} | "
            f"{', '.join(rules) if rules else '—'} |"
        )
    lines += [
        "",
        "## 未覆盖项与补法（backlog）",
        "",
        "| 技术 | 名称 | 需要补什么 |",
        "|---|---|---|",
    ]
    for tech in r["uncovered"]:
        lines.append(f"| {tech.id} | {tech.name} | {tech.gap or tech.why} |")
    lines += [
        "",
        "## 明确不在范围",
        "",
        "| 技术 | 名称 | 为什么不做 |",
        "|---|---|---|",
    ]
    for tid, name, why in OUT_OF_SCOPE:
        lines.append(f"| {tid} | {name} | {why} |")
    lines.append("")
    return "\n".join(lines)


def to_json(report: dict) -> dict:
    return {
        "sub_coverage": {"covered": report["sub_covered"],
                         "total": report["sub_total"],
                         "rate": round(report["sub_rate"], 4)},
        "parent_coverage": {"covered": report["parent_covered"],
                            "total": report["parent_total"],
                            "rate": round(report["parent_rate"], 4)},
        "covered": [{"id": t.id, "name": t.name, "tactic": t.tactic,
                     "rules": report["index"].get(t.id, [])}
                    for t in report["covered"]],
        "uncovered": [{"id": t.id, "name": t.name, "tactic": t.tactic,
                       "why_visible": t.why, "gap": t.gap}
                      for t in report["uncovered"]],
        "out_of_scope": [{"id": i, "name": n, "why": w} for i, n, w in OUT_OF_SCOPE],
        "tags_outside_scope": report["extra_tags"],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="统计 ATT&CK 覆盖（分母 = 声明的检测范围）",
    )
    ap.add_argument("--rules", default=str(DEFAULT_RULES), help="规则目录")
    ap.add_argument("--md", default=None, help="把 markdown 报告写到该路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    rules = load_rules_dir(args.rules)
    if not rules:
        print(f"[!] 没加载到规则（{args.rules}）", file=sys.stderr)
        return 1

    report = build_report(rules)

    if args.json:
        print(json.dumps(to_json(report), ensure_ascii=False, indent=2))
    else:
        print(render_console(report))

    if args.md:
        target = Path(args.md)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_md(report), encoding="utf-8")
        print(f"\n[+] markdown 报告：{target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
