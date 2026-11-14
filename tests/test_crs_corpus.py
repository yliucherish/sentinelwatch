"""OWASP CRS 全量回归集语料（`bench/corpus/crs_regression.json`）的口径守卫。

这份语料是**第三方数据落进仓库**，它有两个特有的失效方式，都不会报错：

1. **被人手改**。117 万字符的 JSON，改一条 `is_attack` 只需要按一下键，
   而「16.1%」会安静地变成「16.3%」。作者自己也说不清哪个对。
2. **口径被写反**。这一条已经发生过一次：第一版把 CRS 的 `no_expect_ids`
   当成「良性样本」，跑出「563 条反例上误报 4.44%」，而那批「误报」里包含
   `'||(select(pg_sleep(15))where(true))||'` 这种货真价实的注入。一个让人安心的
   假指标，方向完全指反。

所以这里守两类东西：
- **数据完整性**：计数、id 唯一、类别都在 `COVERAGE` 里声明过；
- **口径不变式**：`no_expect` 永远不进检出率分母、永远不被算作良性。

`no_expect` 的语义细节见 `bench/import_crs.py` 的模块 docstring。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import import_crs  # noqa: E402
from bench import run_crs_bench as crs  # noqa: E402
from bench.run_crosscheck import COVERAGE  # noqa: E402

CORPUS = ROOT / "bench" / "corpus" / "crs_regression.json"


@pytest.fixture(scope="module")
def corpus() -> dict:
    if not CORPUS.is_file():
        pytest.skip(f"语料未生成：{CORPUS}")
    return json.loads(CORPUS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def result(corpus) -> crs.Result:
    return crs.evaluate(CORPUS)


# ---------------------------------------------------------------- 数据完整性


def test_declared_counts_match_the_cases(corpus):
    """头部 `counts` 与实际条数必须一致。

    报告里所有百分比都读 `counts`，而 `counts` 是导入器算完写死的。
    改数据不改头，报告就会用一个错误的分子配一个正确的分母。
    """
    cases = corpus["cases"]
    counts = corpus["counts"]
    assert counts["total"] == len(cases)
    assert counts["attack"] == sum(1 for c in cases if c["is_attack"])
    assert counts["no_expect"] == sum(1 for c in cases if not c["is_attack"])
    assert counts["rules"] == len({c["source_rule"] for c in cases})


def test_family_totals_match_declared(corpus):
    by_cat: dict[str, int] = {}
    for c in corpus["cases"]:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    for cat, v in corpus["families"].items():
        assert by_cat[cat] == v["attack"] + v["no_expect"], cat


def test_case_ids_are_unique(corpus):
    """重复 id 会让下游按 id 聚合时静默合并两条样本，分母就错了。"""
    ids = [c["id"] for c in corpus["cases"]]
    assert len(ids) == len(set(ids))


def test_every_category_is_declared_in_coverage(corpus):
    """语料里的类别必须在 `COVERAGE` 里声明过且算「有判据」。

    否则 `run_crosscheck.COVERAGE.get(cat, (False, ...))` 会把它当未声明类别
    **静默踢出分母**——检出率会因为多了些样本而变好看。这种静默最该防。
    """
    cats = {c["category"] for c in corpus["cases"]}
    for cat in cats:
        assert cat in COVERAGE, f"{cat} 未在 COVERAGE 声明"
        supported, basis = COVERAGE[cat]
        assert supported is True, f"{cat} 被声明为范围外，不该进这份语料：{basis}"


def test_every_rule_has_an_upstream_message(corpus):
    """每个规则族都要有上游 `msg`。

    归因表靠它写「CRS 侧判据是什么」。缺一条，报告里就会出现一行 `—`，
    而读者没法判断那是「这条规则没描述」还是「我们没抓到描述」。
    """
    rules = {str(c["source_rule"]) for c in corpus["cases"]}
    missing = rules - set(corpus["rule_msgs"])
    assert not missing, f"缺 msg 的规则族：{sorted(missing)[:5]}"


def test_provenance_is_recorded(corpus):
    """没有 commit 就没有可复现性：上游一改测试集，数字就漂。"""
    assert corpus["commit"], "没记 coreruleset commit"
    assert len(corpus["commit"]) >= 7
    assert "coreruleset" in corpus["source"]


def test_match_regex_cases_are_counted_as_attacks(corpus):
    """CRS 有第二种正例写法：断言日志片段（`log.match_regex`）而非规则 id。

    实测 `932200-13`（"Test correct logging"）与 `932207-07`（Referer 里的命令注入）
    都是这种。第一版只认 `expect_ids`，把它们当「期望未知」丢了——**丢两条正例
    等于把漏检洗成不存在**。
    """
    by_id = {c["id"]: c for c in corpus["cases"]}
    for cid in ("CRS-932200-13", "CRS-932207-7"):
        assert cid in by_id, f"{cid} 丢了"
        assert by_id[cid]["is_attack"] is True


# ---------------------------------------------------------------- 口径不变式


def test_attack_and_expectation_are_consistent(corpus):
    for c in corpus["cases"]:
        expected = "should_match" if c["is_attack"] else "should_not_match"
        assert c["expectation"] == expected, c["id"]


def test_no_expect_cases_are_bucketed(corpus):
    """每条 no_expect 都要有分桶，否则报告里会少算一行而没人发现。"""
    for c in corpus["cases"]:
        if c["is_attack"]:
            assert c["negative_kind"] is None, c["id"]
        else:
            assert c["negative_kind"] in ("explicit", "known_fp",
                                          "unclassified", "undocumented"), c["id"]


def test_no_expect_never_enters_the_attack_denominator(corpus):
    """核心不变式：563 条 `no_expect_ids` 不计入检出率分母。

    它们不是良性样本（其中混着真注入），所以也不能当误报分母用。
    两个分母都不进，单独成桶——这是这份语料唯一诚实的处理方式。
    """
    a = sum(1 for c in corpus["cases"] if c["is_attack"])
    assert corpus["counts"]["attack"] == a
    assert a + corpus["counts"]["no_expect"] == corpus["counts"]["total"]


def test_known_fp_bucket_holds_real_attacks(corpus):
    """`known_fp` 桶里必须有「看起来就是攻击」的样本。

    这是分桶存在的理由：CRS 的 `Known false positive` 意思是「我们认了误报、
    故意不报」，不是「这条良性」。若这个桶里全是无害输入，说明分桶白分了。
    """
    known = [c for c in corpus["cases"] if c["negative_kind"] == "known_fp"]
    assert known, "known_fp 桶为空——分桶规则可能失效"
    payloads = " ".join((c["query"] or "") + (c["body"] or "") for c in known)
    assert "pg_sleep" in payloads.lower(), (
        "known_fp 桶里没找到 pg_sleep 那条已知误报样本，"
        "说明分桶或语料变了，报告 §4 的论述需要重新核对"
    )


def test_anomaly_rules_are_marked(corpus):
    """字符频率计分那一族（942430/431/432）必须标出来。

    报告 §2 的「两种口径」靠这个字段切分。标记丢了，两个数字会变成同一个。
    """
    anomaly = {c["source_rule"] for c in corpus["cases"] if c["kind"] == "anomaly"}
    assert anomaly == import_crs.ANOMALY_RULES
    for c in corpus["cases"]:
        assert c["kind"] in ("signature", "anomaly")


# ---------------------------------------------------------------- 评测口径


def test_denominators_match_the_corpus(result, corpus):
    assert result.attacks == corpus["counts"]["attack"]
    assert result.no_expect == corpus["counts"]["no_expect"]
    assert result.total == corpus["counts"]["total"]


def test_no_expect_hits_do_not_inflate_recall(result):
    """在「不该触发」样本上命中，绝不能加进检出数。

    两个桶的命中都要单独记——它们不进 `detected`。
    """
    assert 0 <= result.no_expect_hit <= result.no_expect
    assert result.detected <= result.attacks
    assert result.recall() <= 1.0


def test_signature_only_recall_is_not_better_by_accident(result):
    """排除异常字符族之后，分母和分子都要同步减小。

    第一版只减分母不减分子（或反之），会让「签名型口径」凭空变好看。
    """
    a, d, r = result.sig_only()
    assert a <= result.attacks
    assert d <= result.detected
    assert a > 0 and r <= 1.0
    assert (result.attacks - a) == sum(c.anomaly_attacks for c in result.cats.values())


def test_every_rule_result_maps_to_a_known_category(result):
    for rid, rr in result.rules.items():
        assert rr.category in COVERAGE, rid
        assert rr.detected <= rr.attacks, rid


def test_report_renders_the_headline_numbers(result):
    md = crs.render(result)
    assert "不可互换" in md          # 与主矩阵的分母隔离声明
    assert "不是误报率" in md        # no_expect 口径声明
    assert f"{result.attacks:,}" in md
    assert "漏检归因" in md


def test_committed_report_is_up_to_date(result):
    """落盘的报告必须与当前代码 + 当前语料跑出来的一模一样。

    与 `test_sigma_export.py::test_committed_sigma_files_are_up_to_date` 同样的
    理由：数字进了 README 和简历，一份过期报告比没有报告更坏——它看起来是
    实证，其实是历史快照。改了判据或语料却忘了重跑，这条会红。
    """
    report = ROOT / "bench" / "results" / "crs_regression.md"
    if not report.is_file():
        pytest.skip("报告未生成")
    assert report.read_text(encoding="utf-8") == crs.render(result), (
        "报告与脚本输出不一致，重跑：python bench/run_crs_bench.py --out "
        "bench/results/crs_regression.md"
    )


# ---------------------------------------------------------------- 导入器纯函数


def test_split_uri_keeps_query():
    assert import_crs._split_uri("/get?a=1&b=2") == ("/get", "a=1&b=2")
    assert import_crs._split_uri("/get") == ("/get", "")
    assert import_crs._split_uri("") == ("/", "")
    assert import_crs._split_uri("?x=1") == ("/", "x=1")


def test_as_text_joins_form_dicts():
    assert import_crs._as_text({"a": "1 2", "b": "3"}) == "a=1+2&b=3"
    assert import_crs._as_text(None) == ""
    assert import_crs._as_text("raw") == "raw"


@pytest.mark.parametrize("desc,kind", [
    ("NEGATIVE: Chinese text (should not match - no false positive)", "explicit"),
    ("Don't match on natural english sentences in quotes", "explicit"),
    ("GH issue 1816 - Known false positive", "known_fp"),
    ("Test correct logging", "unclassified"),
    ("", "undocumented"),
])
def test_negative_kind_buckets(desc, kind):
    """分桶方向必须对：`known_fp` 与 `explicit` 的含义是相反的。

    混成一个桶，会把「我们比 CRS 更激进」误报成「我们判据过宽」——
    这正是第一版犯的错。
    """
    assert import_crs._negative_kind(desc) == kind
