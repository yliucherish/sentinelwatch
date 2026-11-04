"""bench/run_benchmark.py 自检的时区回归测试。

背景（一次真实的"本地永远绿、CI 永远红"）
---------------------------------------
self_test() 曾经把攻击窗硬编码成字面时间 "2026-11-04 21:00:00"——那是开发机
（UTC+8）把 PCAP 里的 epoch 1793797200 渲染出来的样子。GitHub Actions 跑在
UTC，同一批样本被 `datetime.fromtimestamp()` 渲染成 13:00，而窗口还是 21:00，
于是"落在窗口内 **且** 源 IP 是攻击源"两个条件永不成立：

    TP=0 -> 自检断言 expected tp=3 失败 -> 三个 Python 版本全红

本地怎么跑都过，因为本地就是 UTC+8。这类 bug 靠"再跑一遍"永远发现不了，
只能靠"换一个时区跑"或者"直接断言它与时区无关"。

这里用两层防守：
  1. 单元层：窗口必须包住每一条样本（用和 collector 完全相同的渲染函数），
     且验证 Labels 走完 JSON 往返后判定仍然正确——纯内存，不依赖 TZ；
  2. 端到端层：把 --self-test 放进子进程，用 UTC / 上海 / 纽约三个时区各跑一次。
     子进程能真正改掉 TZ（进程内改 TZ 在 Windows 上无效），所以这一层在
     Linux CI 上是有牙齿的。
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench" / "run_benchmark.py"


def _load_bench():
    """按文件路径加载 bench/run_benchmark.py。

    bench/ 不是包（没有 __init__.py，也不该有——它是个可执行脚本目录），
    所以不能用 `import bench.run_benchmark`。用 importlib 显式加载可以保证
    "测的就是 CI 里跑的那个文件"，而不是某个被复制过一份的影子模块。

    注意必须先塞进 sys.modules 再 exec_module：脚本里有 @dataclass，而
    dataclasses 处理注解时要回查 `sys.modules[cls.__module__]`，不注册就是
    `NoneType has no attribute __dict__`。
    """
    spec = importlib.util.spec_from_file_location("bench_run_benchmark", BENCH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


bench = _load_bench()

TZ_CASES = ["UTC", "Asia/Shanghai", "America/New_York"]


def test_window_brackets_every_synthetic_record():
    """标注窗口必须包住全部样本，无论本机在哪个时区。

    这条断言就是当初那个 bug 的最小复现：窗口若写死字面量，只要本机 TZ 和
    写代码时的 TZ 不同，`min(ts)` 渲染出来的时间就会落到窗口外。
    """
    from tools.pcapgen import demo_records

    records = demo_records()
    labels = bench.Labels.load(_write_labels(records))

    assert labels.windows, "自检标注里没有攻击窗，判定期望无从谈起"

    win = labels.windows[0]
    ts_list = [datetime.fromtimestamp(ts) for ts, _ in records]
    assert win.start <= min(ts_list), (
        f"窗口下界 {win.start} 晚于最早的样本 {min(ts_list)}")
    assert win.end >= max(ts_list), (
        f"窗口上界 {win.end} 早于最晚的样本 {max(ts_list)}")


def test_window_matches_collector_renderer():
    """窗口边界必须与 collectors.pcap 渲染事件时间用的是同一个坐标系。

    这是"窗口包住样本"能成立的**唯一**理由：标注侧用
    `datetime.fromtimestamp()` + strftime 写字符串，评测侧用 `datetime.strptime()`
    读回，采集侧也用 `datetime.fromtimestamp()`。三处都落在本地时区，所以
    无论 TZ 是什么，二者一定对齐。任何一个环节换成 UTC 都会立刻破。
    """
    from tools.pcapgen import demo_records, pcap_bytes

    records = demo_records()
    labels = bench.Labels.load(_write_labels(records))
    win = labels.windows[0]

    with tempfile.TemporaryDirectory(prefix="bench_tz_") as tmp:
        pcap = Path(tmp) / "selftest.pcap"
        pcap.write_bytes(pcap_bytes(records))
        events = list(bench.iter_events(pcap))

    assert events, "合成 PCAP 解析不出任何事件"
    for ev in events:
        assert win.start <= ev.ts <= win.end, (
            f"事件 {ev.ts} 落在攻击窗外 [{win.start}, {win.end}]")
        # 攻击源 IP 都必须被判成 attack，良性 IP 必须判成 benign
        expect, _ = labels.verdict(ev)
        want = "attack" if ev.ip in win.src_ips else "benign"
        assert expect == want, f"{ev.ip} 判定为 {expect}，期望 {want}"


def test_selftest_tally_is_timezone_independent():
    """走完 bench.run() 全流程，四格矩阵必须与写代码时所处的时区无关。"""
    from tools.pcapgen import demo_records, pcap_bytes

    records = demo_records()
    with tempfile.TemporaryDirectory(prefix="bench_tz_") as tmp:
        tmp_path = Path(tmp)
        pcap = tmp_path / "selftest.pcap"
        pcap.write_bytes(pcap_bytes(records))
        labels = bench.Labels.load(_write_labels(records))
        result = bench.run(pcap, labels, out_dir=tmp_path / "out")

    t = result["tally"]
    assert (t.total, t.tp, t.fn, t.fp, t.tn) == (5, 3, 0, 0, 2), (
        f"四格矩阵 {t.total}/{t.tp}/{t.fn}/{t.fp}/{t.tn}，期望 5/3/0/0/2")


@pytest.mark.parametrize("tz", TZ_CASES)
def test_self_test_cli_in_other_timezone(tz: str):
    """在子进程里换 TZ 跑 --self-test：这才是 CI 上真正发生的事。

    进程内改 TZ 在 Windows 上不生效，所以必须起子进程。若当前平台压根不
    认 TZ 环境变量（探测方式：两个时区渲染出的本地时间相同），则跳过——
    跳过是诚实的，假装通过才是骗人。Linux CI 一定会真的跑。
    """
    if not _tz_has_effect():
        pytest.skip(f"当前平台忽略 TZ 环境变量（{sys.platform}），子进程换时区无效")

    env = dict(os.environ, TZ=tz, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, str(BENCH), "--self-test"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=180,
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0, f"TZ={tz} 下自检失败：\n{out}"
    assert "TP=3" in out, f"TZ={tz} 下四格矩阵不对：\n{out}"


# --------------------------------------------------------------------------
# 辅助
# --------------------------------------------------------------------------
def _write_labels(records) -> Path:
    """把 selftest_labels() 的产物落到临时文件，让 Labels.load 走真实 JSON 路径。

    不直接构造 Labels 对象，是因为当初的 bug 有一半出在"字符串 <-> datetime"
    的往返上：写的时候是本地时间文本、读的时候按本地时间解析。跳过这一步
    就等于跳过了 bug 的现场。
    """
    tmp = Path(tempfile.mkdtemp(prefix="bench_labels_"))
    path = tmp / "labels.json"
    path.write_text(
        json.dumps(bench.selftest_labels(records), ensure_ascii=False),
        encoding="utf-8")
    return path


def _tz_has_effect() -> bool:
    """探测：同一时刻在 UTC 与 Asia/Shanghai 下渲染出的本地时间是否不同。"""
    probe = (
        "import datetime,os;"
        "print(datetime.datetime.fromtimestamp(1793797200).isoformat())"
    )
    seen = set()
    for tz in ("UTC", "Asia/Shanghai"):
        env = dict(os.environ, TZ=tz)
        try:
            out = subprocess.run([sys.executable, "-c", probe], env=env,
                                 capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return False
        seen.add((out.stdout or "").strip())
    return len(seen) == 2 and "" not in seen


def test_labels_shift_is_applied():
    """pcap_time_offset_hours 必须整体平移窗口，别让它变成摆设。

    CIC 的 PCAP 时间戳和论文里的本地时间常常差几小时，这个字段是对齐手段。
    平移量算错会让攻击窗整体错位、检出率归零，症状和"检测器坏了"一模一样。
    """
    from tools.pcapgen import demo_records

    path = _write_labels(demo_records())
    data = json.loads(path.read_text(encoding="utf-8"))
    data["pcap_time_offset_hours"] = -4
    shifted_path = path.parent / "shifted.json"
    shifted_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    base = bench.Labels.load(path)
    shifted = bench.Labels.load(shifted_path)
    delta = shifted.windows[0].start - base.windows[0].start
    assert delta == timedelta(hours=-4), f"偏移未生效，实际平移 {delta}"
