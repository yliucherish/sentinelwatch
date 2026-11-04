"""标注口径的回归测试。

为什么值得单独一个文件：这份标注里有三个数字**看着像配置、其实是实测结论**，
任何一个被"顺手改回看起来更对的写法"，评测结果就会静默失真——而且失真的方式
是"检出率 0%"，与"检测器坏了"长得一模一样。

1. `pcap_time_offset_hours = 3`：按常识会填 4（UNB 在加拿大，众所周知是 EDT）。
   但抓包实测是 ADT=UTC−3。填 4 会让 2 分钟宽的 SQLi 窗整体错位一小时。
2. `src_ips = ["172.16.0.1"]`：按文档会填公网攻击机 205.174.165.73。但抓包点在
   防火墙内侧，攻击者源 IP 已被 NAT 改写，公网地址在 pcap 里一条都没有。
3. `attacker_ips` 与各窗口的 `src_ips` 必须一致：前者只用于敏感性分析，
   若两者漂移，报告里的"检出率上界"就不是同一个攻击者的口径了。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench" / "run_benchmark.py"
LABELS = ROOT / "bench" / "labels" / "cic_ids2017_thursday_web.json"


def _load_bench():
    spec = importlib.util.spec_from_file_location("bench_labels_under_test", BENCH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod       # @dataclass 要回查 sys.modules
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def bench():
    return _load_bench()


@pytest.fixture(scope="module")
def labels(bench):
    return bench.Labels.load(LABELS)


def _ev(ts: datetime, ip: str = "172.16.0.1"):
    return SimpleNamespace(ts=ts, ip=ip)


# ---------------------------------------------------------------- 配置守卫

def test_offset_is_three_hours_not_four(labels):
    """3 是实测值（ADT），4 是按 EDT 推断的错值。"""
    assert labels.shift_hours == 3.0, (
        "时区偏移被改成 %r。CIC-IDS2017 的 PCAP 时间戳是 UTC，"
        "文档时段是 ADT（UTC−3），实测三条独立证据都指向 +3h；"
        "填 4 会让两分钟宽的 SQLi 窗整段错位。见 DATASETS.md 坑二。"
        % labels.shift_hours)


def test_attacker_ip_is_the_natted_gateway(labels):
    """标注里必须用抓包中可见的 NAT 地址，不能用文档里的公网 IP。"""
    for w in labels.windows:
        assert "205.174.165.73" not in w.src_ips, (
            "205.174.165.73 在 pcap 里不存在（抓包点在防火墙内侧，已被 NAT "
            "改写成 172.16.0.1）。这样填会让所有窗口一条都匹配不到，"
            "检出率恒为 0%。见 DATASETS.md 坑一。")
        assert "172.16.0.1" in w.src_ips


def test_attacker_ips_cover_every_window(labels):
    """敏感性分析用的 attacker_ips 必须覆盖各窗口的 src_ips。"""
    window_ips = {ip for w in labels.windows for ip in w.src_ips}
    assert window_ips <= set(labels.attacker_ips)


def test_windows_are_offset_applied(labels):
    """JSON 里写 09:20，加载后应是 12:20（+3h），而不是原样 09:20。"""
    bf = min(labels.windows, key=lambda w: w.start)
    assert bf.attack == "Web Attack - Brute Force"
    assert (bf.start.hour, bf.start.minute) == (12, 20)


# ---------------------------------------------------------------- 判定语义

def test_attack_requires_both_window_and_ip(bench, labels):
    """窗内 + 攻击源 → 攻击；窗内 + 别的源 → 良性（不靠 IP 单独判定）。"""
    w = labels.windows[0]
    inside = w.start
    assert labels.verdict(_ev(inside, "172.16.0.1"))[0] == "attack"
    assert labels.verdict(_ev(inside, "192.168.10.5"))[0] == "benign"


def test_outside_window_is_benign_but_counted_as_sensitivity(labels):
    """窗外的攻击机请求：主口径记良性，但要被敏感性诊断数出来。"""
    w = labels.windows[0]
    early = w.start - timedelta(minutes=1)
    ev = _ev(early, "172.16.0.1")
    assert labels.verdict(ev)[0] == "benign"
    assert labels.attacker_outside_window(ev) is True

    inside = _ev(w.start, "172.16.0.1")
    assert labels.attacker_outside_window(inside) is False


def test_other_ip_is_never_counted_as_attacker(labels):
    """内网客户端的请求不该被算进敏感性诊断。"""
    w = labels.windows[0]
    assert labels.attacker_outside_window(_ev(w.start, "192.168.10.5")) is False


# ---------------------------------------------------------------- 上界计算

def test_recall_upper_accounts_for_window_boundary_error(bench):
    """窗放宽后的上界：把窗外的攻击机请求也算作应检出。"""
    t = bench.Tally()
    t.tp, t.fn = 8, 2                       # 主口径 80%
    t.attacker_outside, t.attacker_outside_hits = 10, 9
    assert t.recall == pytest.approx(0.80)
    # (8+9) / (8+2+10) = 17/20
    assert t.recall_upper == pytest.approx(0.85)


def test_recall_upper_equals_recall_when_no_boundary_error(bench):
    t = bench.Tally()
    t.tp, t.fn = 3, 1
    assert t.recall_upper == pytest.approx(t.recall)


def test_recall_upper_is_undefined_safe(bench):
    """分母全零时不能抛 ZeroDivisionError（报告要能印 '—'）。"""
    t = bench.Tally()
    assert t.recall_upper == 0.0


def test_tuesday_labels_still_parse(bench):
    """周二那份是全良性语料，不得因新字段而解析失败。"""
    lb = bench.Labels.load(ROOT / "bench" / "labels" / "cic_ids2017_tuesday_benign.json")
    assert lb.windows == []
    assert lb.attacker_ips == ()
    assert lb.label_granularity == "all-benign"


def test_label_json_is_valid_utf8_and_has_keys():
    data = json.loads(LABELS.read_text(encoding="utf-8"))
    for key in ("dataset", "label_granularity", "pcap_time_offset_hours",
                "attacker_ips", "attack_windows"):
        assert key in data
    assert len(data["attack_windows"]) == 3
