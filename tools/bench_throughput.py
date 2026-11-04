"""解析器吞吐标定：回答"7.8 GB 的 pcap 要跑多久"。

用法::

    python tools/bench_throughput.py          # 默认 64 MB 样本
    python tools/bench_throughput.py 128      # 指定样本大小（MB）

为什么需要这个脚本：真实数据集单文件 7.8–11 GB，如果解析器慢到要跑一整夜，
那"跑全量"这个决定就得重新做。先量出来再决定，不靠猜。

**样本是合成的**，所以它衡量的是"代码的解析速度"，不是"数据集的性质"。
结论里必须写清这一点，否则就成了拿合成数据冒充数据集结果。

为什么每条请求都用独立的 5 元组：如果复用少数几条流，绝大多数字节只会进
TCP 重组缓冲区，直到流被回收才做一次 HTTP 解析——量出来的吞吐会虚高好几倍。
真实抓包里每条连接通常只承载一两个请求，必须照这个形态造才有意义。
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collectors.pcap import iter_events  # noqa: E402
from tools.pcapgen import (  # noqa: E402
    http_request,
    http_response,
    pcap_bytes,
    tcp_frame,
)

DEFAULT_MB = 64.0

PATHS = (
    "/", "/index.html", "/api/v1/items?page=1", "/static/app.css",
    "/static/app.js", "/login", "/api/v1/user/profile", "/images/logo.png",
    "/about", "/api/v1/search?q=book", "/favicon.ico", "/api/v1/health",
)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

SERVER = "10.0.0.10"

# 真实数据集体积（GB），用于推算。数字来自官网表格，见 bench/DATASETS.md。
DATASETS = (("周四（含 Web 攻击）", 7.8), ("周一（纯良性）", 11.0))


def build(target_bytes: int) -> bytes:
    """造一个 target_bytes 量级的合成 pcap，每条请求占用独立的 5 元组。"""
    records: list[tuple[float, bytes]] = []
    total = 0
    ts = 1_500_000_000.0
    i = 0
    while total < target_bytes:
        sport = 1024 + (i % 60000)
        client = f"192.168.{(i // 60000) % 250}.{1 + i % 200}"
        req = http_request("GET", PATHS[i % len(PATHS)], SERVER, ua=UA)
        resp = http_response(body=b'{"ok":true,"n":%d}' % (i % 1000))

        # 请求方向
        frame = tcp_frame(client, SERVER, sport, 80, 1, req)
        records.append((ts, frame))
        total += len(frame) + 16
        ts += 0.25

        # 响应方向（seq 接在请求之后，保证重组顺序正确）
        frame = tcp_frame(SERVER, client, 80, sport, 1 + len(req), resp)
        records.append((ts, frame))
        total += len(frame) + 16
        ts += 0.25
        i += 1
    return pcap_bytes(records)


def main(argv: list[str]) -> int:
    target_mb = float(argv[1]) if len(argv) > 1 else DEFAULT_MB

    payload = build(int(target_mb * 1024 * 1024))
    path = Path("out/_throughput_sample.pcap")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    mb = len(payload) / 1024 / 1024

    try:
        t0 = time.perf_counter()
        events = sum(1 for _ in iter_events(str(path)))
        elapsed = time.perf_counter() - t0
    finally:
        path.unlink(missing_ok=True)

    rate = mb / elapsed
    print("解析器吞吐标定（合成样本）")
    print(f"  样本体积   {mb:.1f} MB")
    print(f"  解析事件   {events} 条")
    print(f"  耗时       {elapsed:.2f} s")
    print(f"  吞吐       {rate:.1f} MB/s   （{events / elapsed:.0f} 请求/s）")
    if rate > 0:
        print("  推算真实数据集：")
        for label, size_gb in DATASETS:
            minutes = size_gb * 1024 / rate / 60
            print(f"    {label:<18} {size_gb:>4} GB → 约 {minutes:.0f} 分钟")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
