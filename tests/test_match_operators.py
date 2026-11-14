"""match 判据语义测试（v2.0）：两组判据、正则、加载期校验。

这组测试守的是**引擎语义**，不是某条规则能不能报。原因是 v2.0 踩了一个
很贵的坑：给 XSS 规则加了一条"命名空间标签"正则之后，规则悄悄变成了
「必须同时出现 `<script` 和 `<x:script>`」——几乎永不命中，而它在评测里
的表现是**误报降到 0**，看起来像好消息。

所以这里固定三件事：

1. AND 组只有 `raw_contains`；OR 组是 `raw_contains_any` + `raw_regex`。
   子串和正则**不叠加**，任一方命中即可。
2. 判据写错（非法正则、字段名拼错、未知操作符）必须在**加载时**报错。
   规则的静默失效比报错危险得多——报错会有人修，静默失效只会让人以为
   "这条规则很准，从来不误报"。
3. `field` 真的选到了那个视图：规则写到 `sql_view`，事件里没有这个字段
   （比如手工构造事件时漏填）就该命中不了。这条断言能把"忘了填视图"
   这类集成错误在测试里暴露出来。
"""
from pathlib import Path

import pytest

from engine.detector import load_rules
from models import HttpEvent

TS = __import__("datetime").datetime(2026, 11, 14, 21, 0, 0)


def _rule_yaml(tmp_path: Path, match: str, rid: str = "t-rule") -> Path:
    p = tmp_path / "r.yaml"
    p.write_text(f"""
rules:
  - id: {rid}
    name: 测试规则
    event_types: [http_request]
    group_by: [ip]
    window_seconds: 60
    threshold: 1
    match:
{match}
""", encoding="utf-8")
    return p


def _event(text: str, *, sql_view: str = "") -> HttpEvent:
    return HttpEvent(ts=TS, ip="203.0.113.1", raw=text,
                     normalized=text.lower(), sql_view=sql_view)


def _hit(tmp_path: Path, match: str, event: HttpEvent) -> bool:
    from engine.detector import _matches
    rule = load_rules(_rule_yaml(tmp_path, match))[0]
    return _matches(event, rule.match)


# ---------------------------------------------------------------- OR 组语义

def test_regex_and_substring_share_one_or_group(tmp_path):
    """`raw_contains_any` 与 `raw_regex` 是**同一个 OR 组**：任一命中即可。

    如果哪天有人把正则改回独立 AND 组，这条会红——那正是想要的保护。
    """
    match = """      field: normalized
      raw_contains_any:
        - "alpha"
      raw_regex:
        - 'beta\\d+'"""
    assert _hit(tmp_path, match, _event("only alpha here")), "只命中子串也算"
    assert _hit(tmp_path, match, _event("only beta42 here")), "只命中正则也算"
    assert not _hit(tmp_path, match, _event("neither of them"))


def test_raw_contains_is_the_and_group(tmp_path):
    """`raw_contains` 是 AND 组：少一个就不算。"""
    match = """      field: normalized
      raw_contains:
        - "alpha"
        - "beta\""""
    assert _hit(tmp_path, match, _event("alpha and beta"))
    assert not _hit(tmp_path, match, _event("alpha only"))


def test_and_group_combines_with_or_group(tmp_path):
    """两组之间是 AND：`raw_contains` 全中，且 OR 组至少中一个。"""
    match = """      field: normalized
      raw_contains:
        - "host:"
      raw_contains_any:
        - "alpha"
      raw_regex:
        - 'beta\\d+'"""
    assert _hit(tmp_path, match, _event("host: x alpha"))
    assert _hit(tmp_path, match, _event("host: x beta7"))
    assert not _hit(tmp_path, match, _event("host: x gamma")), "OR 组一个都没中"


# ---------------------------------------------------------------- field 语义

def test_field_really_selects_the_view(tmp_path):
    """规则写 `field: sql_view` 就必须真的读 sql_view。

    手工构造 HttpEvent 时漏填 sql_view 是很容易犯的集成错误——这里把它
    变成一条会红的断言，而不是"线上规则静默失效"。
    """
    match = """      field: sql_view
      raw_contains_any:
        - "union select\""""
    ev_without = _event("union select 1")                    # sql_view 为空
    ev_with = _event("union select 1", sql_view="union select 1")
    assert not _hit(tmp_path, match, ev_without)
    assert _hit(tmp_path, match, ev_with)


# ---------------------------------------------------------------- 加载期校验

def test_invalid_regex_fails_at_load(tmp_path):
    """非法正则必须在加载时报错，不能等匹配时才炸（更糟：永不匹配）。"""
    bad = "      raw_regex:\n        - 'unclosed (group'"
    with pytest.raises(ValueError, match="不是合法正则"):
        load_rules(_rule_yaml(tmp_path, bad))


def test_unknown_field_fails_at_load(tmp_path):
    """字段名拼错（`normalize` vs `normalized`）是最隐蔽的失效方式。"""
    bad = "      field: normalize\n      raw_contains_any:\n        - 'x'"
    with pytest.raises(ValueError, match="未知字段"):
        load_rules(_rule_yaml(tmp_path, bad))


def test_unknown_operator_fails_at_load(tmp_path):
    """自定义操作符（如 `raw_startswith`）不该被静默忽略。"""
    bad = "      raw_startswith:\n        - 'x'"
    with pytest.raises(ValueError, match="未知键"):
        load_rules(_rule_yaml(tmp_path, bad))


def test_match_without_any_operator_fails_at_load(tmp_path):
    """只写了 field、没写任何判据——空 match 会匹配一切，必须拦下。"""
    bad = "      field: normalized"
    with pytest.raises(ValueError, match="没给任何判据"):
        load_rules(_rule_yaml(tmp_path, bad))
