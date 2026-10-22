"""文件完整性监控（FIM, File Integrity Monitoring）。

设计要点（面试可讲）：
- **基线 + 定期对比**是 FIM 的通用形态（参照 Tripwire / Wazuh / osquery）：
  首次运行对目标目录计算每个文件的 SHA256 并存为基线；之后每次扫描与基线
  对比，输出 added / modified / deleted 三类变更。
- **哈希而非 mtime**：mtime 可以被 `touch` 伪造，SHA256 不行——
  攻击者改内容必然改哈希（除非碰撞）。这是"完整性"与"存在性检查"的本质区别。
- **排除规则**：.git/__pycache__/临时文件等自身就在变的目录必须排除，
  否则基线永远对不上——真实 FIM 部署的第一课就是"先定义什么不算变更"。
- **告警即事件**：FIM 的变更直接转成 Alert 对象入库，与认证类告警走同一条
  存储/展示链路——数据链路统一是 SIEM 的基本形态。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

from models import Alert

# 默认排除：版本控制/缓存/数据库等"自身就在变"的目录
DEFAULT_EXCLUDES = (".git", "__pycache__", ".pytest_cache", "node_modules",
                    ".venv", "*.db", "*.db-journal", "*.pyc")

# change_type → 中文描述（Alert.title 对人类可读）
_CHANGE_DESC = {"added": "新增", "modified": "篡改", "deleted": "删除"}


@dataclass
class FileState:
    """一个文件的完整性状态。"""

    path: str        # 相对被监控根的路径（基线可移植，不绑死机器）
    sha256: str
    size: int
    mtime: float     # 仅作参考信息，判定依据是 sha256


@dataclass
class FileChange:
    """一次扫描与基线对比出的单个变更。"""

    path: str
    change_type: str             # added / modified / deleted
    old_sha256: str | None = None
    new_sha256: str | None = None
    old_size: int | None = None
    new_size: int | None = None


def _is_excluded(rel_path: str, excludes: tuple[str, ...]) -> bool:
    parts = Path(rel_path).parts
    for pat in excludes:
        if pat.startswith("*"):
            if Path(rel_path).match(pat):
                return True
        elif pat in parts:
            return True
    return False


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """流式计算文件 SHA256——大文件不占内存（安全工具的基本功）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def scan_directory(root: str | Path,
                   excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> dict[str, FileState]:
    """递归扫描目录，返回 {相对路径: FileState}。"""
    root = Path(root).resolve()
    states: dict[str, FileState] = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue          # 符号链接本身就可疑，但不跟踪其目标（防逃逸）
        rel = p.relative_to(root).as_posix()
        if _is_excluded(rel, excludes):
            continue
        try:
            st = p.stat()
            states[rel] = FileState(path=rel, sha256=sha256_file(p),
                                    size=st.st_size, mtime=st.st_mtime)
        except OSError:
            continue          # 权限不足/文件扫描期间被删：跳过而非崩溃
    return states


def save_baseline(states: dict[str, FileState], path: str | Path) -> None:
    """基线落盘为 JSON（人类可读、可 diff、可手改——运维友好）。"""
    payload = {
        "version": 1,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "files": {k: asdict(v) for k, v in states.items()},
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def load_baseline(path: str | Path) -> dict[str, FileState]:
    """读取基线 JSON；文件不存在返回空基线（首次运行的正常路径）。"""
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    return {k: FileState(**v) for k, v in data.get("files", {}).items()}


def compare_baseline(old: dict[str, FileState],
                     new: dict[str, FileState]) -> list[FileChange]:
    """对比两份状态，输出变更列表（按路径排序，结果稳定可复现）。"""
    changes: list[FileChange] = []
    for path, st in new.items():
        prev = old.get(path)
        if prev is None:
            changes.append(FileChange(path=path, change_type="added",
                                      new_sha256=st.sha256, new_size=st.size))
        elif prev.sha256 != st.sha256:
            changes.append(FileChange(path=path, change_type="modified",
                                      old_sha256=prev.sha256, new_sha256=st.sha256,
                                      old_size=prev.size, new_size=st.size))
    for path, prev in old.items():
        if path not in new:
            changes.append(FileChange(path=path, change_type="deleted",
                                      old_sha256=prev.sha256, old_size=prev.size))
    changes.sort(key=lambda c: c.path)
    return changes


def changes_to_alerts(changes: list[FileChange],
                      monitored_root: str) -> list[Alert]:
    """把文件变更转成 Alert——与认证类告警统一入库/统一展示。

    严重度分级（面试可讲）：modified/deleted 直接破坏完整性 → high；
    added 可能是正常新增 → medium。真实系统还会按"被监控目录的敏感度"
    再分级（/etc、二进制目录 vs 日志目录）。
    """
    now = datetime.now().replace(microsecond=0)   # 与认证类告警一致的秒级精度
    alerts: list[Alert] = []
    for c in changes:
        severity = "high" if c.change_type in ("modified", "deleted") else "medium"
        desc = _CHANGE_DESC.get(c.change_type, c.change_type)
        if c.change_type == "modified":
            detail = (f"SHA256 {c.old_sha256[:16]}… → {c.new_sha256[:16]}…，"
                      f"大小 {c.old_size} → {c.new_size} 字节")
        elif c.change_type == "added":
            detail = f"新文件 SHA256 {c.new_sha256[:16]}…，{c.new_size} 字节"
        else:
            detail = f"文件消失（基线 SHA256 {c.old_sha256[:16]}…）"
        alerts.append(Alert(
            rule_id="fim-integrity",
            rule_name="文件完整性监控",
            severity=severity,
            title=f"文件{desc}: {c.path}",
            detail=f"被监控目录 {monitored_root}：{detail}",
            source_ip=None,          # 主机侧事件，无网络源
            event_count=1,
            window_start=now,
            window_end=now,
        ))
    return alerts
