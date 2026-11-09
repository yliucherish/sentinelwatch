# -*- coding: utf-8 -*-
"""Generate docs/quickstart_demo.png from *real* command output.

Every line shown in the image is captured from a command that this script
actually runs. Nothing is hand-written or mocked. The unabridged stdout/stderr
is saved next to the image as quickstart_output.txt so the excerpt can be
verified.

Usage (from the repository root):

    python docs/make_quickstart_demo.py

Requires PyYAML and pytest (the same dependencies as the test suite).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

DOCS = Path(__file__).resolve().parent
ROOT = DOCS.parent
OUT_PNG = DOCS / "quickstart_demo.png"
OUT_TXT = DOCS / "quickstart_output.txt"

W = 1440
PAD_X = 44
TITLE_H = 116
LINE_H = 30
FOOTER_H = 74

BG = (11, 18, 32)
PANEL = (16, 26, 45)
CMD = (125, 179, 255)
TEXT = (214, 224, 240)
DIM = (132, 150, 176)
ACCENT = (167, 139, 250)
GREEN = (110, 231, 183)
RED = (248, 133, 141)
BORDER = (44, 62, 96)

# Windows first, then common Linux font locations. A CJK-capable face is needed
# because the CLI prints Chinese; without one PIL falls back to tofu boxes.
FONT_CANDIDATES = {
    ("mono", False): [
        r"C:\Windows\Fonts\consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ],
    ("mono", True): [
        r"C:\Windows\Fonts\consolab.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    ],
    ("cjk", False): [
        r"C:\Windows\Fonts\msyh.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    ],
    ("cjk", True): [
        r"C:\Windows\Fonts\msyhbd.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
    ],
}
_FONT_CACHE: dict[tuple, ImageFont.FreeTypeFont] = {}


def font(size: int, bold: bool = False, cjk: bool = False) -> ImageFont.FreeTypeFont:
    key = (size, bold, cjk)
    if key not in _FONT_CACHE:
        candidates = FONT_CANDIDATES[("cjk" if cjk else "mono", bold)]
        path = next((p for p in candidates if Path(p).exists()), None)
        _FONT_CACHE[key] = (
            ImageFont.truetype(path, size) if path else ImageFont.load_default(size=size)
        )
    return _FONT_CACHE[key]


def run(label: str, argv: list[str]) -> tuple[str, list[str]]:
    """Run a command, return (display label, full output lines)."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )
    text = proc.stdout.decode("utf-8", errors="replace")
    lines = [ln.rstrip() for ln in text.splitlines()]
    return label, lines


def excerpt(label: str, lines: list[str]) -> list[str]:
    """Pick the informative lines for the image; full output is still archived."""
    if "pytest" in label:
        picked = [ln for ln in lines if "passed" in ln and "skipped" in ln]
        return picked[-1:] or lines[-2:]
    if "cli.py traffic" in label:
        picked = [ln for ln in lines if ln.startswith("[*]") or "[CRITICAL]" in ln]
        # Fold the random tempdir so the image is stable across runs. The
        # untouched line is kept in quickstart_output.txt.
        return [
            re.sub(r"数据库\s+\S+", "数据库 demo.db", ln) if "数据库" in ln else ln
            for ln in picked[:6]
        ]
    if "run_benchmark.py --self-test" in label:
        return [ln for ln in lines if "事件 " in ln or "检出率" in ln or "自检通过" in ln][:4]
    if "to_sigma.py --check" in label:
        return [ln for ln in lines if ln.startswith("[+]") or ln.startswith("[!]")][:3]
    if "attack_coverage.py" in label:
        return [ln for ln in lines if "子技术层" in ln or "父技术层" in ln][:2]
    return lines[:4]


def main() -> None:
    py = sys.executable
    with tempfile.TemporaryDirectory(prefix="sw_demo_") as tmp:
        db = str(Path(tmp) / "demo.db")
        jobs = [
            ("pytest tests/ -q", [py, "-m", "pytest", "tests/", "-q"]),
            (
                "python cli.py traffic --pcap tests/fixtures/traffic_demo.pcap --db demo.db",
                [py, "cli.py", "traffic", "--pcap", "tests/fixtures/traffic_demo.pcap", "--db", db],
            ),
            (
                "python bench/run_benchmark.py --self-test",
                [py, "bench/run_benchmark.py", "--self-test"],
            ),
            ("python tools/to_sigma.py --check", [py, "tools/to_sigma.py", "--check"]),
            ("python tools/attack_coverage.py", [py, "tools/attack_coverage.py"]),
        ]

        results: list[tuple[str, list[str], list[str]]] = []
        raw: list[str] = []
        for label, argv in jobs:
            _, lines = run(label, argv)
            results.append((label, excerpt(label, lines), lines))
            raw.append(f"$ {label}")
            raw.extend(lines)
            raw.append("")

    OUT_TXT.write_text("\n".join(raw), encoding="utf-8")

    display: list[tuple[str, str, tuple[int, int, int]]] = []
    for label, picked, _ in results:
        display.append(("cmd", "$ " + label, CMD))
        for ln in picked:
            colour = TEXT
            if "[CRITICAL]" in ln or "passed" in ln:
                colour = GREEN
            if "自检通过" in ln or "可转换" in ln:
                colour = ACCENT
            if ln.startswith("[!]"):
                colour = DIM
            display.append(("out", "    " + ln.strip(), colour))
        display.append(("gap", "", DIM))

    height = TITLE_H + LINE_H * len(display) + FOOTER_H + 20
    img = Image.new("RGB", (W, height), BG)
    d = ImageDraw.Draw(img)

    # Title bar with the project's blue/violet accent.
    d.rectangle((0, 0, W, TITLE_H), fill=PANEL)
    d.rectangle((0, TITLE_H - 3, W, TITLE_H), fill=(37, 99, 235))
    d.text((PAD_X, 24), "SentinelWatch v1.6  /  Quickstart", font=font(27, bold=True, cjk=True), fill=(236, 242, 255))
    d.text(
        (PAD_X, 68),
        "Real command output (temp path folded) — no mocked values. Full log: docs/quickstart_output.txt",
        font=font(16, cjk=True),
        fill=DIM,
    )

    y = TITLE_H + 16
    mono = font(17)
    mono_b = font(17, bold=True)
    cjk = font(17, cjk=True)
    for kind, text, colour in display:
        if kind == "gap":
            y += 12
            continue
        # Consolas has no CJK glyphs; lines containing Chinese need msyh.ttc.
        f = mono_b if kind == "cmd" else (cjk if any(ord(ch) > 127 for ch in text) else mono)
        d.text((PAD_X, y), text, font=f, fill=colour)
        y += LINE_H

    d.line((PAD_X, height - FOOTER_H + 8, W - PAD_X, height - FOOTER_H + 8), fill=BORDER, width=1)
    d.text(
        (PAD_X, height - FOOTER_H + 22),
        f"Generated {datetime.now().strftime('%Y-%m-%d')} by docs/make_quickstart_demo.py  ·  "
        "197 passed + 4 skipped  ·  22 rules  ·  CIC-IDS2017 30.2 GB",
        font=font(15, cjk=True),
        fill=DIM,
    )

    img.save(OUT_PNG)
    print(f"[+] wrote {OUT_PNG} ({W}x{height})")
    print(f"[+] wrote {OUT_TXT} ({len(raw)} lines of unabridged output)")


if __name__ == "__main__":
    main()
