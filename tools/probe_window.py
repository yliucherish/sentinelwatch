"""反推 PCAP 时间戳与论文时间窗的偏移。

用法：
    python tools/probe_window.py data/Tuesday-WorkingHours.pcap 21 22

做法：扫全量包，统计目标端口（默认 21/22）的每分钟包数，打印最密集的若干段。
把打印出来的"墙钟时间"与论文给出的攻击时段对齐，差值就是 pcap_time_offset_hours。

为什么需要这个工具：CIC-IDS2017 的 pcap 时间戳与论文/标注里写的时间窗
不是同一个基准。不实测就填偏移，唯一的下场是攻击窗落在空地上、检出率 0%。
"""

from __future__ import annotations

import argparse
import datetime as dt
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collectors.pcap import _iter_records  # noqa: E402

_ETH_IPV4 = 0x0800


def _tcp_ports(frame: bytes, linktype: int):
    """返回 (src_port, dst_port) 或 None。只认以太网/IPv4/TCP，够用就行。"""
    if linktype == 1:  # EN10MB
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            return None
        off = 14
    elif linktype == 101:  # RAW IP
        if len(frame) < 20:
            return None
        off = 0
    else:
        return None

    if frame[off] >> 4 != 4:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if frame[off + 9] != 6:  # proto != TCP
        return None
    tcp_off = off + ihl
    if len(frame) < tcp_off + 4:
        return None
    return struct.unpack(">HH", frame[tcp_off:tcp_off + 4])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("ports", nargs="*", type=int, default=[21, 22])
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    path = Path(args.pcap)
    if not path.is_file():
        print(f"文件不存在：{path}", file=sys.stderr)
        return 2

    per_min: Counter[int] = Counter()
    total = 0
    hit = 0
    for ts, linktype, frame in _iter_records(path):
        total += 1
        got = _tcp_ports(frame, linktype)
        if got is None:
            continue
        sp, dp = got
        if sp in args.ports or dp in args.ports:
            hit += 1
            per_min[int(ts.timestamp()) // 60] += 1

    print(f"总包数 {total:,}  命中端口 {args.ports} 的包 {hit:,}"
          f"（{hit / total:.3%}）" if total else "空文件")

    if not per_min:
        print("没有任何命中，端口选错了？")
        return 1

    # 输出：epoch 分钟 -> 该分钟包数，按密集度排序，并给出两种基准下的墙钟时间
    print("\n最密集的 %d 个分钟（pkts: 该分钟包数）" % args.top)
    print(f"{'epoch(UTC基准)':<22}{'EDT基准(UTC-4)':<22}{'pkts':>8}")
    for minute, n in per_min.most_common(args.top):
        as_utc = dt.datetime.fromtimestamp(minute * 60, dt.timezone.utc)
        as_edt = as_utc - dt.timedelta(hours=4)
        print(f"{as_utc.strftime('%Y-%m-%d %H:%M'):<22}"
              f"{as_edt.strftime('%Y-%m-%d %H:%M'):<22}{n:>8}")

    span = (max(per_min) - min(per_min))
    print(f"\n命中流量覆盖跨度：{span} 分钟")
    print("把上面某一段与论文时间窗对齐，差值即 pcap_time_offset_hours。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
