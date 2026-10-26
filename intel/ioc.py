"""威胁情报 IOC 集合与匹配。

设计要点（面试可讲）：
- **情报与规则分离**：规则（rules/*.yaml）描述"行为模式"，情报（IOC）描述"已知恶意实体"。
  前者相对稳定、要人工调；后者天天变、可直接订阅（abuse.ch Feodo / URLhaus）。
  混在一起会让规则目录变成情报垃圾桶，所以单独建 intel/ 包。
- **只做匹配，不做告警**：本模块返回 `(IOC, 命中字段)`，由 matcher 层转成 Alert。
  这样 IOC 匹配能复用现有告警链路（存储 / 看板 / 报告 / 抑制器），不必另起一套。
- **误报优先控制**：域名做后缀边界匹配（notevil-c2.com 不命中 evil-c2.com），
  哈希按长度校验（32/40/64），时间格式 12:34:56 不会被当成 IPv6。
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path

# 支持的 IOC 类型
KIND_IP = "ip"
KIND_CIDR = "cidr"
KIND_DOMAIN = "domain"
KIND_HASH = "hash"
KIND_URL = "url"

_KINDS = {KIND_IP, KIND_CIDR, KIND_DOMAIN, KIND_HASH, KIND_URL}

# 提取用正则（只在对应集合非空时执行）
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)
_RE_HASH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
_RE_CLOCK = re.compile(r"^\d{2}:\d{2}:\d{2}$")


@dataclass(frozen=True)
class IOC:
    """一条威胁情报指标。"""

    value: str
    kind: str
    source: str = ""
    note: str = ""


def infer_kind(value: str) -> str:
    """按值的形态推断 IOC 类型。判断顺序重要：URL 必须先判，否则含斜杠会被当 CIDR。"""
    low = value.lower()
    if low.startswith(("http://", "https://")):
        return KIND_URL
    try:
        ip_address(value)
        return KIND_IP
    except ValueError:
        pass
    try:
        ip_network(value, strict=False)
        return KIND_CIDR
    except ValueError:
        pass
    if _is_hash(value):
        return KIND_HASH
    return KIND_DOMAIN


def _is_hash(v: str) -> bool:
    return len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v)


class IOCSet:
    """情报集合：加载 + 匹配。"""

    def __init__(self) -> None:
        self._ips: dict[str, IOC] = {}
        self._nets: list[tuple[object, IOC]] = []
        self._domains: dict[str, IOC] = {}
        self._hashes: dict[str, IOC] = {}
        self._urls: list[tuple[str, IOC]] = []

    def __len__(self) -> int:
        return (
            len(self._ips) + len(self._nets) + len(self._domains)
            + len(self._hashes) + len(self._urls)
        )

    def add(self, value: str, kind: str = "", source: str = "", note: str = "") -> None:
        v = value.strip()
        if not v:
            raise ValueError("空的 IOC 值")
        k = (kind or infer_kind(v)).lower()
        if k not in _KINDS:
            raise ValueError(f"未知 IOC 类型 {k!r}（可选 {sorted(_KINDS)}）")
        ioc = IOC(value=v, kind=k, source=source, note=note)
        if k == KIND_IP:
            self._ips[v] = ioc
        elif k == KIND_CIDR:
            self._nets.append((ip_network(v, strict=False), ioc))
        elif k == KIND_DOMAIN:
            self._domains[v.lower().rstrip(".")] = ioc
        elif k == KIND_HASH:
            self._hashes[v.lower()] = ioc
        else:
            self._urls.append((v.lower(), ioc))

    # ---------- 加载 ----------
    def load_csv(self, path: str | Path) -> int:
        """加载 CSV（value,kind,source,note；表头与 # 注释自动跳过）。"""
        n = 0
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                v = row[0].strip()
                if not v or v.lower() == "value" or v.startswith("#"):
                    continue
                self.add(
                    v,
                    kind=row[1] if len(row) > 1 else "",
                    source=row[2] if len(row) > 2 else "",
                    note=row[3] if len(row) > 3 else "",
                )
                n += 1
        return n

    def load_json(self, path: str | Path) -> int:
        """加载 JSON 数组：[{"value":..., "kind":..., "source":..., "note":...}]"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("JSON 情报必须是数组")
        for item in data:
            self.add(
                item["value"],
                kind=item.get("kind", ""),
                source=item.get("source", ""),
                note=item.get("note", ""),
            )
        return len(data)

    def load_lines(self, path: str | Path) -> int:
        """加载纯文本（每行一个，## 开头为注释）。"""
        n = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                v = line.strip()
                if not v or v.startswith("#"):
                    continue
                self.add(v)
                n += 1
        return n

    def load_file(self, path: str | Path) -> int:
        """按扩展名选择解析器。"""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"情报文件不存在: {p}")
        suffix = p.suffix.lower()
        if suffix == ".csv":
            return self.load_csv(p)
        if suffix == ".json":
            return self.load_json(p)
        return self.load_lines(p)

    # ---------- 匹配 ----------
    def match(self, text: str) -> list[tuple[IOC, str]]:
        """在任意文本中匹配情报，返回 [(IOC, 命中字段)]，去重。"""
        if not text:
            return []
        hits: list[tuple[IOC, str]] = []
        seen: set[str] = set()

        # 1) IP 与 CIDR
        if self._ips or self._nets:
            for token in self._extract_ips(text):
                ioc = self._ips.get(token)
                if ioc is not None and token not in seen:
                    seen.add(token)
                    hits.append((ioc, token))
                    continue
                if self._nets:
                    try:
                        ip = ip_address(token)
                    except ValueError:
                        continue
                    for net, nioc in self._nets:
                        if ip in net and nioc.value not in seen:
                            seen.add(nioc.value)
                            hits.append((nioc, token))
                            break

        # 2) 域名（后缀边界匹配，支持子域）
        if self._domains:
            for token in self._extract_domains(text):
                low = token.lower().rstrip(".")
                for dom, ioc in self._domains.items():
                    if (low == dom or low.endswith("." + dom)) and dom not in seen:
                        seen.add(dom)
                        hits.append((ioc, token))
                        break

        # 3) 文件哈希
        if self._hashes:
            for token in self._extract_hashes(text):
                ioc = self._hashes.get(token.lower())
                if ioc is not None and ioc.value not in seen:
                    seen.add(ioc.value)
                    hits.append((ioc, token))

        # 4) URL 片段
        if self._urls:
            low = text.lower()
            for frag, ioc in self._urls:
                if frag in low and ioc.value not in seen:
                    seen.add(ioc.value)
                    hits.append((ioc, ioc.value))

        return hits

    # ---------- 提取 ----------
    @staticmethod
    def _extract_ips(text: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for m in _RE_IPV4.findall(text):
            if m not in seen:
                seen.add(m)
                out.append(m)
        for m in _RE_IPV6.findall(text):
            if m in seen or len(m) < 3 or _RE_CLOCK.match(m):
                continue  # 排除 12:34:56 这类时间戳
            try:
                ip_address(m)
            except ValueError:
                continue
            seen.add(m)
            out.append(m)
        return out

    @staticmethod
    def _extract_domains(text: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for m in _RE_DOMAIN.findall(text):
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out

    @staticmethod
    def _extract_hashes(text: str) -> list[str]:
        return [m for m in _RE_HASH.findall(text) if len(m) in (32, 40, 64)]
