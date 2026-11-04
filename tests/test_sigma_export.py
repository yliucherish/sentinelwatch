"""规则 → Sigma 转换与 ATT&CK 覆盖的测试（v1.3 / 任务 C）。

这批测试要守住四件事，任何一条破了都意味着"导出的东西不能信"：

1. **元数据完整**：15 条规则全部带 `tags`，且 tag 格式符合 Sigma 规范
   （`attack.tXXXX` / `cve.YYYY-NNNN`）——规范细节是跑官方 `sigma check`
   才发现的（写点号会报 InvalidPatternTagIssue）。
2. **不能转的必须报错**：阈值规则要抛 `NotConvertible`，绝不允许悄悄生成
   一条 threshold=1 的规则——那种规则上线后会刷屏，比没有规则更糟。
3. **判据语义等价**：转换后的 Sigma 规则对同一批样本的判定结果，必须与
   引擎的 `_matches` 一致（大小写差异单独测，见最后两个用例）。
4. **仓库里的 sigma/ 与规则同步**：改了 rules 忘了重新生成，测试就红。

第 3 点是这批测试里最有价值的部分：大多数"规则转换器"只测"生成的 YAML
长得对不对"，不测"判定结果变没变"——而后者才是转换器的全部意义。
"""
import re
from datetime import date
from pathlib import Path

import pytest
import yaml

from engine.detector import _matches, load_rules_dir
from tools.attack_coverage import IN_SCOPE, OUT_OF_SCOPE, build_report
from tools.to_sigma import NotConvertible, convert_dir, to_sigma, to_yaml_text

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
SIGMA_DIR = ROOT / "sigma"

# Sigma 的 tag 规范（与 pySigma 的 TagFormat / CVE 校验器一致）
_TAG_OK = re.compile(r"^(attack\.t\d{4}(\.\d{3})?|cve\.\d{4}-\d+)$")


@pytest.fixture(scope="module")
def rules():
    return load_rules_dir(RULES)


@pytest.fixture(scope="module")
def by_id(rules):
    return {r.id: r for r in rules}


class _Ev:
    """假事件：raw / normalized 都给同一个串，让 field 设置不影响判据。"""

    def __init__(self, text: str):
        self.raw = text
        self.normalized = text


def _sigma_eval(rule_dict: dict, text: str) -> bool:
    """按 Sigma 的 condition 语义求值（只支持本项目会生成的两种子句）。

    之所以自己写而不是调 pySigma 的 backend：本项目坚持零依赖，pySigma 是
    可选开发依赖；而且这个小求值器能逐字对照 spec 的语义，比"交给 backend
    再猜它怎么解释"更可控。
    """
    det = dict(rule_dict["detection"])
    cond = det.pop("condition")
    text_l = text.lower()

    def hits(prefix: str) -> list[bool]:
        out = []
        for name, sel in det.items():
            if not name.startswith(prefix):
                continue
            for key, val in sel.items():
                parts = key.split("|")
                mods = parts[1:]
                vals = val if isinstance(val, list) else [val]
                cased = "cased" in mods
                out.append(any(
                    (str(v) in text) if cased else (str(v).lower() in text_l)
                    for v in vals
                ))
        return out

    for clause in cond.split(" and "):
        m = re.match(r"^(all|1) of (\w+)\*$", clause.strip())
        assert m, f"本求值器不认识的 condition 子句: {clause}"
        mode, prefix = m.group(1), m.group(2)
        got = hits(prefix)
        assert got, f"condition 引用了不存在的 selection 前缀: {prefix}"
        if mode == "all" and not all(got):
            return False
        if mode == "1" and not any(got):
            return False
    return True


def _samples(rule) -> list[tuple[str, str]]:
    """从规则自身的字面量构造正/负/变形样本，返回 [(标签, 文本)]。"""
    ands = list(rule.match.get("raw_contains") or [])
    ors = list(rule.match.get("raw_contains_any") or [])
    hit_all = " ".join(ands + ors[:1])
    out = [("全命中", hit_all), ("无关请求", "GET /index.html HTTP/1.1 200 OK")]
    if len(ands) > 1:
        # 少一个 AND 字面量 → 必须不命中（这条专门抓"把 AND 写成 OR"的 bug）
        out.append(("缺一个AND", " ".join(ands[:-1] + ors[:1])))
    if len(ors) > 1:
        out.append(("仅命中OR末项", ands and " ".join(ands) + " " + ors[-1] or ors[-1]))
    return out


# --------------------------------------------------------------------------
# 1. 元数据完整性与格式
# --------------------------------------------------------------------------
def test_all_fifteen_rules_carry_attack_tags(rules):
    assert len(rules) == 15
    missing = [r.id for r in rules if not r.tags]
    assert not missing, f"这些规则没有 tags: {missing}"


def test_every_tag_matches_sigma_format(rules):
    bad = [(r.id, t) for r in rules for t in r.tags if not _TAG_OK.match(t)]
    assert not bad, f"tag 格式不符合 Sigma 规范（attack.tXXXX / cve.YYYY-NNNN）: {bad}"


def test_cve_tags_use_hyphen_not_dot(rules):
    """官方 sigma check 的 CVETagValidator 正则是 ^\\d+-\\d+$，点号会报错。"""
    for r in rules:
        for t in r.tags:
            if t.startswith("cve."):
                assert "-" in t, f"{r.id} 的 CVE tag 用了点号: {t}"


# --------------------------------------------------------------------------
# 2. 阈值规则必须显式拒绝
# --------------------------------------------------------------------------
def test_threshold_rules_are_rejected(by_id):
    for rid in ("ssh-brute-force", "ssh-user-enumeration"):
        with pytest.raises(NotConvertible) as exc:
            to_sigma(by_id[rid])
        assert "correlation" in str(exc.value)


def test_rejection_message_names_the_rule(by_id):
    with pytest.raises(NotConvertible) as exc:
        to_sigma(by_id["ssh-brute-force"])
    assert "ssh-brute-force" in str(exc.value)


def test_convert_dir_counts_match_and_skips(rules):
    written, skipped = convert_dir(RULES, out_dir=None, dry_run=True)
    assert len(written) == 13
    assert len(skipped) == 2
    assert {r.id for r, _ in skipped} == {"ssh-brute-force", "ssh-user-enumeration"}


# --------------------------------------------------------------------------
# 3. AND / OR 映射与语义等价
# --------------------------------------------------------------------------
def test_and_conditions_become_all_of(by_id):
    """raw_contains 是 AND，Sigma 侧必须拆成多个 selection + all of。"""
    data = to_sigma(by_id["fastjson-jdbcrowset-payload"])
    det = data["detection"]
    assert det["condition"] == "all of selection_all_*"
    assert len([k for k in det if k.startswith("selection_all_")]) == 2


def test_or_conditions_become_one_of(by_id):
    data = to_sigma(by_id["log4shell-jndi-obfuscated"])
    det = data["detection"]
    assert det["condition"] == "1 of selection_any_*"
    assert len([k for k in det if k.startswith("selection_any_")]) == 5


def test_mixed_and_or_joins_with_and(by_id):
    """raw_contains + raw_contains_any 同时存在时，两者之间是 AND。"""
    data = to_sigma(by_id["http-fastjson-autotype"])
    cond = data["detection"]["condition"]
    assert cond == "all of selection_all_* and 1 of selection_any_*"


@pytest.mark.parametrize("rid", [
    "log4shell-jndi-payload",
    "log4shell-jndi-obfuscated",
    "fastjson-jdbcrowset-payload",
    "fastjson-jndi-url-in-input",
    "http-log4shell-jndi",
    "http-fastjson-autotype",
    "http-webshell-body-markers",
])
def test_sigma_semantics_match_engine_exactly_when_cased(by_id, rid):
    """--cased 版本必须与引擎判定**逐样本完全一致**（含否定样本）。

    这是整个转换器正确性的核心断言：AND 写成 OR、OR 写成 AND、漏了某个
    字面量，都会在这里被抓住。
    """
    rule = by_id[rid]
    data = to_sigma(rule, cased=True)
    for label, text in _samples(rule):
        expect = _matches(_Ev(text), rule.match)
        assert _sigma_eval(data, text) is expect, f"{rid} / {label} 判定不一致"


@pytest.mark.parametrize("rid", [
    "log4shell-jndi-payload",
    "fastjson-jdbcrowset-payload",
    "http-log4shell-jndi",
])
def test_uncased_sigma_never_misses_engine_hits(by_id, rid):
    """默认版本比源规则宽松（大小写不敏感），但**不许反向漏报**。

    宽松是可接受的（宁可多报再调），漏报是不可接受的。所以断言的是
    "引擎命中 ⇒ Sigma 也命中"这个方向，而不是双向相等。
    """
    rule = by_id[rid]
    data = to_sigma(rule, cased=False)
    for _label, text in _samples(rule):
        if _matches(_Ev(text), rule.match):
            assert _sigma_eval(data, text), f"{rid} 在 {text!r} 上出现漏报"


def test_cased_flag_adds_modifier(by_id):
    assert "|contains|cased" in str(to_sigma(by_id["log4shell-jndi-payload"],
                                             cased=True)["detection"])
    assert "|contains|cased" not in str(to_sigma(by_id["log4shell-jndi-payload"],
                                                cased=False)["detection"])


# --------------------------------------------------------------------------
# 4. 确定性、溯源信息与仓库同步
# --------------------------------------------------------------------------
def test_uuid_is_deterministic(by_id):
    a = to_sigma(by_id["http-log4shell-jndi"], today=date(2026, 11, 4))
    b = to_sigma(by_id["http-log4shell-jndi"], today=date(2026, 11, 4))
    assert a["id"] == b["id"]
    assert len(a["id"]) == 36  # UUID 形式


def test_uuids_are_unique_across_rules(rules):
    ids = [to_sigma(r)["id"] for r in rules if r.match and r.threshold == 1]
    assert len(ids) == len(set(ids))


def test_cve_tag_generates_nvd_reference(by_id):
    data = to_sigma(by_id["http-log4shell-jndi"])
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" in data["references"]


def test_yaml_text_carries_provenance_header(by_id):
    text = to_yaml_text(by_id["http-log4shell-jndi"])
    assert text.startswith("# 由 SentinelWatch tools/to_sigma.py")
    assert "请勿手改" in text


def test_committed_sigma_files_are_up_to_date(by_id):
    """仓库里的 sigma/*.yml 必须与当前规则一致（防止改了规则忘记重生成）。"""
    files = sorted(SIGMA_DIR.glob("*.yml"))
    assert len(files) == 13, f"sigma/ 应有 13 个文件，实得 {len(files)}"
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule = by_id[path.stem]
        fresh = to_sigma(rule, today=date.fromisoformat(data["date"]))
        assert fresh == data, f"{path.name} 与 rules/ 不同步，请重跑 tools/to_sigma.py"


# --------------------------------------------------------------------------
# 5. ATT&CK 覆盖统计
# --------------------------------------------------------------------------
def test_coverage_numbers_come_from_tags(rules):
    report = build_report(rules)
    assert report["sub_total"] == len(IN_SCOPE)
    assert report["sub_covered"] == len(report["covered"])
    # 每个"已覆盖"都必须真的能在规则 tags 里找到，不是硬编码的
    for tech in report["covered"]:
        assert tech.id in report["index"]
    for tech in report["uncovered"]:
        assert tech.id not in report["index"]


def test_coverage_rate_is_consistent(rules):
    report = build_report(rules)
    assert report["sub_rate"] == pytest.approx(
        report["sub_covered"] / report["sub_total"])
    assert report["parent_rate"] == pytest.approx(
        report["parent_covered"] / report["parent_total"])


def test_no_tags_outside_declared_scope(rules):
    """规则里出现了 IN_SCOPE 之外的技术 → 要么补进范围声明，要么删标签。"""
    assert build_report(rules)["extra_tags"] == []


def test_out_of_scope_entries_all_have_reason():
    assert OUT_OF_SCOPE
    for tid, name, why in OUT_OF_SCOPE:
        assert re.match(r"^T\d{4}$", tid), tid
        assert name and why
        assert tid not in {t.id.split(".")[0] for t in IN_SCOPE}


def test_every_uncovered_technique_has_gap_note(rules):
    """未覆盖项必须写清"缺什么"，否则报告就只是自曝短板而不给方案。"""
    report = build_report(rules)
    for tech in report["uncovered"]:
        assert tech.gap, f"{tech.id} 没有 gap 说明"


# --------------------------------------------------------------------------
# 6. 可选：官方 pySigma 解析（本机装了就跑，没装就跳过）
# --------------------------------------------------------------------------
def test_rules_parse_with_official_pysigma(by_id):
    sigma_collection = pytest.importorskip("sigma.collection")
    for rid in ("http-log4shell-jndi", "fastjson-jdbcrowset-payload",
                "log4shell-jndi-obfuscated"):
        text = to_yaml_text(by_id[rid], today=date(2026, 11, 4))
        coll = sigma_collection.SigmaCollection.from_yaml(text)
        assert len(coll.rules) == 1
        assert coll.rules[0].title == by_id[rid].name
