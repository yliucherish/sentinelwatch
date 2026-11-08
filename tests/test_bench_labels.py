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
import os
import subprocess
import sys
from datetime import datetime
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


def _at(epoch: float, ip: str = "172.16.0.1"):
    """用 epoch 构造事件时间，模拟采集器 datetime.fromtimestamp() 的本地渲染。

    测试里绝不能直接拿 w.start（UTC 基准的 naive）当事件时间——那样事件本身
    就带上了本机时区，等于把被测的 bug 写进测试前提里。
    """
    return _ev(datetime.fromtimestamp(epoch), ip)


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
    assert labels.verdict(_at(w.start_epoch))[0] == "attack"
    assert labels.verdict(_at(w.start_epoch, "192.168.10.5"))[0] == "benign"


def test_outside_window_is_benign_but_counted_as_sensitivity(labels):
    """窗外的攻击机请求：主口径记良性，但要被敏感性诊断数出来。"""
    w = labels.windows[0]
    ev = _at(w.start_epoch - 60)
    assert labels.verdict(ev)[0] == "benign"
    assert labels.attacker_outside_window(ev) is True

    assert labels.attacker_outside_window(_at(w.start_epoch)) is False


def test_other_ip_is_never_counted_as_attacker(labels):
    """内网客户端的请求不该被算进敏感性诊断。"""
    w = labels.windows[0]
    assert labels.attacker_outside_window(
        _at(w.start_epoch, "192.168.10.5")) is False


# ---------------------------------------------------------------- 时区无关

# 2017-07-06 13:17:16 UTC = 10:17:16 ADT，落在论文的 XSS 窗 10:15–10:35 内。


_TZ_PROBE = r'''
import datetime as dt, importlib.util, sys
from pathlib import Path
from types import SimpleNamespace
ROOT = Path(r"{root}")
spec = importlib.util.spec_from_file_location("b", ROOT / "bench" / "run_benchmark.py")
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)
lb = m.Labels.load(ROOT / "bench" / "labels" / "cic_ids2017_thursday_web.json")
epoch = dt.datetime(2017, 7, 6, 13, 17, 16, tzinfo=dt.timezone.utc).timestamp()
ts = dt.datetime.fromtimestamp(epoch)
ev = SimpleNamespace(ts=ts, ip="172.16.0.1")
print("LOCAL", ts.isoformat())
print("VERDICT", *lb.verdict(ev))
'''.replace("{root}", str(ROOT))


def _tz_has_effect() -> bool:
    """Windows 会忽略 TZ 环境变量，先探测再决定要不要跳过。"""
    probe = "import datetime;print(datetime.datetime.fromtimestamp(1499342236).hour)"
    vals = []
    for tz in ("UTC", "Asia/Shanghai"):
        env = dict(os.environ, TZ=tz)
        out = subprocess.run([sys.executable, "-c", probe], env=env,
                             capture_output=True, text=True, timeout=60)
        vals.append(out.stdout.strip())
    return len(set(vals)) == 2


@pytest.mark.parametrize("tz", ["UTC", "Asia/Shanghai", "America/New_York",
                                "Europe/Berlin"])
def test_window_matching_is_timezone_independent(tz):
    """同一个 epoch 的事件，在四种时区下必须判为同一类攻击。

    回归背景：旧代码用 ``self.start <= event.ts <= self.end`` 直接比 naive
    datetime——窗口是 UTC 基准、事件是本地墙钟，在 UTC+8 上差 8 小时，
    攻击窗整段落空，TP/FN 全 0，真攻击的 895 次命中全被记成误报。
    注意这条测试必须包含非 UTC 时区：旧代码在 UTC 机器上恰好也能过。
    """
    if not _tz_has_effect():
        pytest.skip("当前平台忽略 TZ 环境变量，子进程换时区无效")
    env = dict(os.environ, TZ=tz, PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-c", _TZ_PROBE], cwd=str(ROOT),
                          env=env, capture_output=True, text=True, timeout=120)
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0, f"TZ={tz} 下探针失败：\n{out}"
    assert "VERDICT attack Web Attack - XSS" in out, \
        f"TZ={tz} 下窗口判定错位：\n{out}"


# ---------------------------------------------------------------- 统计器


def test_by_shape_uses_uri_syntax_not_rule_output(bench):
    """分层只看 URI 语法：带载荷但没命中，仍算「有非空 query」。"""
    t = bench.Tally()
    t.add("attack", True, "XSS", "/dv/xss_r/?name=%3Cscript%3E")
    t.add("attack", False, "XSS", "/dv/xss_r/?name=plain")   # 有 query，未命中
    t.add("attack", False, "Brute", "/dv/login.php")          # 无 query
    t.add("benign", False, "Benign", "/favicon.ico")
    assert t.by_shape[("attack", "有非空 query")] == {"total": 2, "hit": 1}
    assert t.by_shape[("attack", "无 query")] == {"total": 1, "hit": 0}
    assert t.by_shape[("benign", "无 query")] == {"total": 1, "hit": 0}


def test_by_shape_treats_trailing_question_mark_as_no_query(bench):
    t = bench.Tally()
    t.add("attack", False, "XSS", "/dv/xss_r/?")
    assert "有非空 query" not in {shape for _, shape in t.by_shape}




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
