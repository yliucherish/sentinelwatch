"""`bench/proposed/` 里的判据：**测过但没上线**的决策守卫。

这个目录存的是「判据写好了、量过了、但不进 `rules/`」的东西。它不是垃圾堆，
是决策记录——所以需要测试守着两件事：

    ① 它**确实没有**被上线（`rules/` 里不能出现同名规则）；
    ② 它**仍然是对的**（正则还能命中当初那些路径，且不命中已知的良性对照）。

第二件事是防「腐烂」：一条不加载的规则没人跑，半年前后改坏了也没人知道。
第一件事是防「顺手补上」：`bench/proposed/` 看起来就像待办，最难抵抗的诱惑
就是把它 `git mv` 进 `rules/`——那会让 §2.12 里记的权衡一次性失效。

为什么路径判据没上线（哪怕它的精度比 UA 判据好一个数量级）：
它在三份 CIC 全量上命中 8 次，全是 `/.git/HEAD` 与 `/HNAP1`，都是真探测，
但语料把这 8 条标成良性。上线它会让「真实误报 4/150,262」变成 12，而唯一
能让数字不变差的办法是改标注——这条规则本来就是照着这些路径写的，
改标注等于拿尺子当训练集。详见 BENCHMARK §2.12。
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from collectors.pcap import _build_event
from engine.detector import _matches, load_rules_dir, load_rules_dir as _load_dir

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
PROPOSED = ROOT / "bench" / "proposed" / "http_sensitive_path.yaml"
RULE_ID = "http-sensitive-path-probe"


@pytest.fixture(scope="module")
def live_ids():
    return {r.id for r in load_rules_dir(RULES)}


@pytest.fixture(scope="module")
def proposed():
    assert PROPOSED.exists(), "proposed 规则文件不在了——是搬进 rules/ 了还是被删了？"
    rules = load_rules_dir(PROPOSED.parent)
    return {r.id: r for r in rules}[RULE_ID]


def _req(uri):
    """只给路径，其余字段保持最小——这条判据只看 `uri`。"""
    return _build_event(
        datetime(2026, 11, 14, 12, 0, 0),
        "192.168.10.8",
        40000,
        f"GET {uri} HTTP/1.1".encode(),
        {"host": "intranet.local"},
        b"",
    )


def test_rule_is_not_shipped(live_ids):
    """决策守卫：这条规则不许出现在 `rules/` 里。

    如果它哪天要上线，正确的做法是**先满足 §2.12 的解锁条件**（独立的扫描
    标注 + 真实环境良性流量 + 源 IP 例外机制），然后连同这一行断言一起改——
    让「上线」这个动作留下痕迹，而不是顺手一个 mv。
    """
    assert RULE_ID not in live_ids


def test_proposed_dir_is_not_scanned_as_rules():
    """`bench/proposed/` 不能被 `load_rules_dir(rules/)` 扫到——两个目录分开。"""
    assert {p.parent.name for p in RULES.glob("*.yaml")} == {"rules"}


@pytest.mark.parametrize("uri", [
    "/.git/HEAD",          # 版本控制目录：最经典的源码泄露探测
    "/.git/config",
    "/HNAP1",              # D-Link 等家用路由的固定入口
    "/.env",
    "/.env.production",
    "/.htaccess",
    "/aws/.aws/credentials",
    "/phpmyadmin/index.php",
    "/adminer.php",
    "/server-status",
    "/phpinfo.php",
    "/manager/html",
    "/actuator/env",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/backup.sql",
    "/wp-config.php.bak",
])
def test_known_probe_paths_still_match(proposed, uri):
    """判据没腐烂：当初认定「不该被公开访问」的路径仍然命中。"""
    assert _matches(_req(uri), proposed.match), f"应当命中：{uri}"


@pytest.mark.parametrize("uri", [
    # 爬虫的正常入口
    "/robots.txt",
    "/favicon.ico",
    "/sitemap.xml",
    # 正规做安全联系人的方式——报它等于惩罚做对了的人
    "/.well-known/security.txt",
    # 合法的广告跟踪路径（第一版误报 74 条的那个）
    "/cgi-bin/m?ci=us-rocketfuel&cg=768215589297219286&cc=1",
    # WordPress 的正常端点与登录页
    "/wp-admin/admin-ajax.php?action=refresh_scoreboard&security=5891b099dd",
    "/wp-login.php",
    "/wp-content/uploads/2026/11/photo.jpg",
    # 普通业务路径
    "/",
    "/index.php",
    "/api/v2/orders?page=2",
])
def test_benign_paths_do_not_match(proposed, uri):
    """反向断言：把「像个后台」当判据就会误报，这里守着收窄的边界。"""
    assert not _matches(_req(uri), proposed.match), f"不该命中：{uri}"


def test_path_match_is_case_insensitive(proposed):
    """`uri` 视图不转小写（`normalized` 才转），所以正则自带 `(?i)`。

    `/HNAP1` 与 `/hnap1` 是同一个路径；漏掉大小写就是白写一条规则。
    """
    assert _matches(_req("/HNAP1"), proposed.match)
    assert _matches(_req("/hnap1"), proposed.match)
    assert _matches(_req("/.GIT/HEAD"), proposed.match)


def test_rule_only_looks_at_the_path(proposed):
    """判据落在 `uri` 上，不是 `normalized`。

    这条不是洁癖：`normalized` 是「请求行 + 头部 + body」的归一化全文，
    一篇讲源码泄露的博客在 body 里提到 `/.git/HEAD` 就会误报。实测里
    `http-sensitive-path-probe` 用 `normalized` 时会命中一篇技术文档。
    """
    ev = _build_event(
        datetime(2026, 11, 14, 12, 0, 0),
        "203.0.113.9", 40001,
        b"POST /comment HTTP/1.1",
        {"host": "blog.local", "content-type": "application/json"},
        '{"text": "攻击者会尝试读取 /.git/HEAD 与 /.env 来拿源码与密钥"}'.encode(),
    )
    assert not _matches(ev, proposed.match), "body 里提到这些路径，不该当成探测"
