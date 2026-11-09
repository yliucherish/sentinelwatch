"""窗口频次判据的回归测试（v1.7 / Brute Force 补强）。

守住四件容易被「顺手改坏」的事：

1. 频次规则只能是「吃 http_request + threshold > 1」的规则，签名规则
   一旦被算进来，逐请求矩阵和窗口告警就会混成一个数。
2. 滑动窗口是**闭区间**（相差恰好 W 秒仍在窗内），边界不能凭感觉改成开区间。
3. 全良性语料上的告警必须计为告警级 FP，不能因为「没有攻击窗」就略过。
4. 告警窗与标注窗的相交判定必须在 epoch 上做，换时区结论不能变——
   这个项目已经被时区问题坑过两次（self_test 三版本全红、周四首跑 TP=0）。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import run_frequency as freq  # noqa: E402
from tools.pcapgen import http_request, pcap_bytes, tcp_frame  # noqa: E402

BASE_EPOCH = 1793797200.0
ATTACKER = "172.16.0.1"
BENIGN = "192.168.10.5"


def _utc_naive(epoch: float) -> datetime:
    """标注窗按 UTC 基准渲染（与真实标注文件约定一致）。"""
    return datetime.fromtimestamp(epoch, timezone.utc).replace(tzinfo=None)


def _records() -> list[tuple[float, bytes]]:
    """35 次攻击者登录 + 5 次正常登录 + 1 次非登录请求。"""
    records: list[tuple[float, bytes]] = []
    for i in range(35):
        records.append((BASE_EPOCH + i * 0.4, tcp_frame(
            ATTACKER, "192.168.10.80", 40000 + i, 80, 1_000_000 + i * 2000,
            http_request("POST", "/dv/login.php", "dv.internal",
                         body=b"username=admin&password=guess"))))
    for i in range(5):
        records.append((BASE_EPOCH + 1 + i, tcp_frame(
            BENIGN, "192.168.10.80", 41000 + i, 80, 2_000_000 + i * 2000,
            http_request("POST", "/dv/login.php", "dv.internal",
                         body=b"username=alice&password=hunter2"))))
    records.append((BASE_EPOCH + 2, tcp_frame(
        BENIGN, "192.168.10.80", 42000, 80, 3_000_000,
        http_request("GET", "/index.html", "dv.internal"))))
    return records


def _labels(tmp: Path, with_window: bool) -> Path:
    data = {
        "dataset": "synthetic frequency test",
        "source": "tools/pcapgen.py",
        "label_granularity": "time_window+src_ip" if with_window else "all-benign",
        "pcap_time_offset_hours": 0,
        "attacker_ips": [ATTACKER],
    }
    if with_window:
        data["attack_windows"] = [{
            "start": _utc_naive(BASE_EPOCH - 2).strftime("%Y-%m-%d %H:%M:%S"),
            "end": _utc_naive(BASE_EPOCH + 30).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ips": [ATTACKER],
            "attack": "Web Attack - Brute Force",
        }]
    p = tmp / ("labels_attack.json" if with_window else "labels_benign.json")
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("freq")
    pcap = tmp / "login_burst.pcap"
    pcap.write_bytes(pcap_bytes(_records()))
    return pcap, _labels(tmp, True), _labels(tmp, False)


def _load(path: Path):
    from bench.run_benchmark import Labels
    return Labels.load(path)


# ---------------------------------------------------------------- 规则选择


def test_frequency_rules_only_http_window_rules():
    rules = freq.frequency_rules(ROOT / "rules")
    ids = {r.id for r in rules}
    assert "http-login-brute-force" in ids
    assert "ssh-brute-force" not in ids
    for r in rules:
        assert "http_request" in r.event_types
        assert r.threshold > 1
        assert r.match, "没有签名过滤的纯计数规则会把全天流量都算进来"


# ---------------------------------------------------------------- 滑动窗口


def test_max_bursts_uses_closed_interval():
    def ev(sec, ip="1.2.3.4"):
        return SimpleNamespace(ts=datetime.fromtimestamp(BASE_EPOCH + sec), ip=ip)

    peaks = freq.max_bursts([ev(0), ev(10), ev(60), ev(61)], 60, ("ip",))
    # 相差恰好 60 秒仍在窗内 → 0/10/60 三条；61 秒时 0 被遗忘，10/60/61 三条。
    assert peaks[("1.2.3.4",)] == 3


def test_max_bursts_groups_by_ip():
    def ev(sec, ip):
        return SimpleNamespace(ts=datetime.fromtimestamp(BASE_EPOCH + sec), ip=ip)
    evs = [ev(i, "1.1.1.1") for i in range(7)] + [ev(i, "2.2.2.2") for i in range(3)]
    peaks = freq.max_bursts(evs, 60, ("ip",))
    assert peaks == {("1.1.1.1",): 7, ("2.2.2.2",): 3}


# ---------------------------------------------------------------- 端到端


def test_burst_is_detected_at_alert_level(synthetic):
    pcap, attack_labels, _ = synthetic
    r = freq.evaluate(pcap, _load(attack_labels))
    assert r.matched_requests == 40, "只应收集登录端点请求，非登录请求不进窗口"
    assert r.groups == 2
    assert r.peak_burst == 35
    assert r.bf_requests == 35
    assert r.alerts_total == 1, "35 次在一分钟内只应产生 1 条告警（静默期抑制）"
    assert r.alert_tp == 1
    assert r.alert_fp == 0
    assert r.bf_alerts == 1
    assert r.bf_windows_covered == 1
    assert r.alert_precision == pytest.approx(1.0)


def test_benign_low_volume_ip_never_alerts(synthetic):
    """5 次登录不该触发阈值 30；这条守的是「别为了刷检出率调低阈值」。"""
    pcap, attack_labels, _ = synthetic
    r = freq.evaluate(pcap, _load(attack_labels))
    assert all(s["ip"] == ATTACKER for s in r.samples)


def test_all_benign_labels_count_alerts_as_fp(synthetic):
    pcap, _, benign_labels = synthetic
    r = freq.evaluate(pcap, _load(benign_labels))
    assert r.alerts_total == 1
    assert r.alert_tp == 0
    assert r.alert_fp == 1
    assert r.bf_windows == 0


def test_threshold_above_peak_produces_no_alert(synthetic):
    pcap, attack_labels, _ = synthetic
    r = freq.evaluate(pcap, _load(attack_labels), threshold=100)
    assert r.alerts_total == 0
    assert r.peak_burst == 35, "标定数据与阈值覆盖无关"


def test_calibrate_skips_alert_eval(synthetic):
    pcap, attack_labels, _ = synthetic
    r = freq.evaluate(pcap, _load(attack_labels), calibrate=True)
    assert r.alerts_total == 0
    assert r.peak_burst == 35


def test_render_declares_granularity(synthetic):
    pcap, attack_labels, _ = synthetic
    r = freq.evaluate(pcap, _load(attack_labels))
    text = freq.render(r, _load(attack_labels), False)
    assert "告警（窗口）级" in text
    assert "不能相加" in text


# ---------------------------------------------------------------- 时区


_TZ_PROBE = r'''
import datetime as dt, sys
from pathlib import Path
from types import SimpleNamespace
ROOT = Path(r"{root}")
sys.path.insert(0, str(ROOT))
from bench.run_frequency import _overlaps
from bench.run_benchmark import AttackWindow
start = dt.datetime.fromtimestamp({epoch}, dt.timezone.utc).replace(tzinfo=None)
w = AttackWindow(start, start + dt.timedelta(seconds=30), ("172.16.0.1",), "BF")
a = SimpleNamespace(
    window_start=dt.datetime.fromtimestamp({epoch} + 5),
    window_end=dt.datetime.fromtimestamp({epoch} + 10),
    source_ip="172.16.0.1")
print("LOCAL", a.window_start.isoformat())
print("OVERLAP", _overlaps(a, w))
'''.replace("{root}", str(ROOT)).replace("{epoch}", str(BASE_EPOCH))


def _tz_has_effect() -> bool:
    probe = "import datetime;print(datetime.datetime.fromtimestamp(1793797200).hour)"
    vals = []
    for tz in ("UTC", "Asia/Shanghai"):
        out = subprocess.run([sys.executable, "-c", probe],
                             env=dict(os.environ, TZ=tz),
                             capture_output=True, text=True, timeout=60)
        vals.append(out.stdout.strip())
    return len(set(vals)) == 2


@pytest.mark.parametrize("tz", ["UTC", "Asia/Shanghai", "America/New_York",
                                "Europe/Berlin"])
def test_overlap_is_timezone_independent(tz):
    if not _tz_has_effect():
        pytest.skip("当前平台忽略 TZ 环境变量，子进程换时区无效")
    out = subprocess.run([sys.executable, "-c", _TZ_PROBE], cwd=str(ROOT),
                         env=dict(os.environ, TZ=tz, PYTHONIOENCODING="utf-8"),
                         capture_output=True, text=True, timeout=120)
    text = (out.stdout or "") + (out.stderr or "")
    assert out.returncode == 0, f"TZ={tz} 探针失败：\n{text}"
    assert "OVERLAP True" in text, f"TZ={tz} 下窗口相交判定错位：\n{text}"
