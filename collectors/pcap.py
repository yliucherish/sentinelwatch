"""流量采集器（v1.2 新增）：PCAP → TCP 重组 → HTTP 请求 → 事件。

为什么需要它（面试可讲）：
v1.0/v1.1 的 SentinelWatch 只能吃日志——它是"主机侧"的。但同一场攻击在
**主机日志**和**网络流量**里留下的痕迹不一样，各有盲区：

    攻击手法            日志侧看得到吗      流量侧看得到吗
    ------------------  ------------------  ------------------
    Log4Shell           只有应用真的打了日志  请求头/URL 里的载荷必现
    被 WAF 拦下的请求    看不到（没到应用）    看得到（拦在网络层）
    日志被清洗/截断      看不到                看得到原始字节
    Fastjson autoType   只有异常栈时才可见    POST body 里必现

所以真实 IDS 是"日志 + 流量"双数据源。本模块把流量也变成**同一种事件模型**，
下游规则引擎/存储/看板/报告一行不改——这是本项目最想讲的一个设计：
**检测特征与数据源解耦**（同一份签名，既能吃日志，也能吃流量）。

实现要点（全部标准库，无 scapy 依赖）：
1. **手写 libpcap 解析**：全局头 24 字节（magic 区分大小端 + 微秒/纳秒精度），
   每包 16 字节记录头 + 链路层帧。支持 Ethernet(1) / Raw IP(101) / Linux SLL(113)
   三种链路类型——现实里 `tcpdump -i any` 产出的是 SLL，只支持 Ethernet 会踩坑。
2. **TCP 重组**：按五元组（方向敏感）+ 序号重排。乱序、重传、重叠都要处理，
   否则"攻击载荷被拆成两个包"就永远匹配不到——**攻击者拆分载荷本身就是一种绕过**。
3. **HTTP 还原**：请求行 + 头部 + 按 Content-Length 取 body；同一条连接上的
   keep-alive 多请求循环解析。只解析**客户端→服务端**方向（以方法名开头判定），
   服务端响应不进事件（响应侧检测是另一件事，见"已知限制"）。
4. **归一化视图**：`%24%7Bjndi%3A` 这类 URL 编码、`${JNDI:` 这类大小写变形，
   直接对原文做签名匹配必然漏。事件同时携带 `raw`（原始证据，取证用）和
   `normalized`（解码到不动点 + 转小写，签名匹配用）——**判据与证据分离**。
   这与 BypassLab 的归一化管道是同一个设计思想。

已知限制（写清楚比藏着强）：
- 只支持未加密 HTTP/1.x；HTTPS 需要密钥或解密代理，不在本项目范围。
- 不支持 chunked 编码与 gzip body（按 Content-Length 取体；chunked 请求当前会被跳过）。
- 不做完整 TCP 状态机（不跟踪握手/挥手/FIN 回收），只按序号拼数据——
  对离线 PCAP 分析足够，对在线旁路抓包需要补状态机。
- IPv4 only（IPv6 报文跳过）。
"""
from __future__ import annotations

import socket
import struct
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

from models import HttpEvent

# pcap 全局头 magic → 时间戳小数部分的时间单位（秒）
#   0xa1b2c3d4 微秒精度；0xa1b23c4d 纳秒精度（tcpdump 4.99+ 默认）
_MAGIC_SCALE = {0xA1B2C3D4: 1e-6, 0xA1B23C4D: 1e-9}

_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW_IP = 101
_LINKTYPE_LINUX_SLL = 113

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_VLAN = 0x8100
_ETHERTYPE_QINQ = 0x88A8

_IPPROTO_TCP = 6

_METHODS = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH",
     b"TRACE", b"CONNECT"}
)

# body 上限：防止畸形 Content-Length 把内存吃光（真实 WAF 同样要设上限）
_MAX_BODY = 1 << 20

# 单帧上限：jumbo frame 最大 9KB，留到 256KB 已经极宽松。
# 存在的意义是挡住"文件损坏导致 incl_len 是垃圾值"——不设上限的话
# 一次 f.read(4GB) 就能把进程打死。
_MAX_FRAME = 1 << 18

# 流空闲多久后回收（秒）。流式解析时内存只保留"活跃流"：
# 不回收的话，一天的流量会在内存里留下几十万条流的状态。
_FLOW_IDLE_SECONDS = 300.0

# 每隔多少个包检查一次空闲流（每包都扫字典太贵）
_FLOW_SWEEP_EVERY = 20000


class PcapError(ValueError):
    """PCAP 文件格式错误（不支持的版本/链路类型/文件截断）。"""


# ---------------------------------------------------------------- PCAP 解析

def _iter_records(path: str | Path):
    """产出 (timestamp, linktype, frame_bytes)，按文件顺序（流式）。

    全局头结构（24 字节，全部按文件字节序）：
        magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
    记录头结构（16 字节）：ts_sec(4) ts_frac(4) incl_len(4) orig_len(4)

    v1.4：**改成逐条记录从文件读取**。原来用 `read_bytes()` 一次性读入，
    在公开数据集（CIC-IDS2017 单日 7.7–12 GB）上直接 OOM——这是做基准评测
    时才暴露的问题：自造的 8 包样本永远发现不了"你的解析器有没有内存上界"。
    PCAP 的记录头自带长度，天然可分帧，流式读不需要任何妥协。
    """
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise PcapError(f"文件过短，不是合法 PCAP: {path}")

        scale = None
        endian = ""
        for candidate in (">", "<"):
            magic = struct.unpack(candidate + "I", head[:4])[0]
            if magic in _MAGIC_SCALE:
                scale = _MAGIC_SCALE[magic]
                endian = candidate
                break
        if scale is None:
            raise PcapError(f"未知 magic {head[:4].hex()}（不是 libpcap 格式；"
                            f"pcapng 请先 `tcpdump -r in.pcapng -w out.pcap` 转换）")

        network = struct.unpack(endian + "I", head[20:24])[0]
        if network not in (_LINKTYPE_ETHERNET, _LINKTYPE_RAW_IP, _LINKTYPE_LINUX_SLL):
            raise PcapError(f"不支持的链路类型 linktype={network}"
                            f"（支持 1=Ethernet / 101=Raw IP / 113=Linux SLL）")

        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return                     # 正常 EOF，或文件被截断
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
                endian + "IIII", rec)
            if incl_len > _MAX_FRAME:
                raise PcapError(f"记录长度异常 incl_len={incl_len}"
                                f"（> {_MAX_FRAME}，文件可能已损坏）")
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                return                     # 文件被截断：已读部分照常返回
            yield datetime.fromtimestamp(ts_sec + ts_frac * scale), network, frame


def _ipv4_payload(linktype: int, frame: bytes) -> bytes | None:
    """剥链路层，返回 IPv4 报文（含 IP 头）；非 IPv4 返回 None。"""
    if linktype == _LINKTYPE_RAW_IP:
        return frame
    if linktype == _LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        off = 14
        # 802.1Q / QinQ：每层 VLAN 标签 4 字节，ethertype 在标签之后
        while ethertype in (_ETHERTYPE_VLAN, _ETHERTYPE_QINQ):
            if len(frame) < off + 4:
                return None
            ethertype = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if ethertype == _ETHERTYPE_IPV4 else None
    # Linux SLL：16 字节头，协议号在 14:16
    if len(frame) < 16:
        return None
    proto = struct.unpack(">H", frame[14:16])[0]
    return frame[16:] if proto == _ETHERTYPE_IPV4 else None


def _parse_ipv4(pkt: bytes):
    """返回 (proto, src, dst, payload)；非 TCP / 非首片 / 畸形报文返回 None。"""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    total_len = struct.unpack(">H", pkt[2:4])[0]
    proto = pkt[9]
    frag_field = struct.unpack(">H", pkt[6:8])[0]
    if frag_field & 0x1FFF:
        return None                      # 非首片：无 TCP 头，无法处理
    src = socket.inet_ntoa(pkt[12:16])
    dst = socket.inet_ntoa(pkt[16:20])
    body = pkt[ihl:total_len] if ihl < total_len <= len(pkt) else pkt[ihl:]
    return proto, src, dst, body


def _parse_tcp(seg: bytes):
    """返回 (sport, dport, seq, payload)；畸形返回 None。"""
    if len(seg) < 20:
        return None
    sport, dport, seq = struct.unpack(">HHI", seg[:8])
    data_off = (seg[12] >> 4) * 4
    if data_off < 20 or len(seg) < data_off:
        return None
    return sport, dport, seq, seg[data_off:]


class _Flow:
    """单向 TCP 流：按序号重排拼接，容忍乱序 / 重传 / 部分重叠。

    实现选择：**先收齐再拼**，而不是边收边吐。原因：攻击者把载荷拆成两个包
    时，后半个包可能先到；若以"先到的包"为基准做流式拼接，先到的是后半段，
    前半个包因为序号更小而永远拼不进去——真实的 out-of-order 场景会直接丢数据。
    离线 PCAP 分析本来就有全量数据，收集完按 seq 排序再拼最稳。

    空洞（真正丢包造成的 seq 跳变）不伪造字节：直接拼接并保留空洞，文档已声明
    这一取舍——宁可让该请求解析失败，也不能编造不存在的字节去"凑"一次命中。
    """

    __slots__ = ("segs",)

    def __init__(self) -> None:
        self.segs: dict[int, bytes] = {}

    def add(self, seq: int, payload: bytes) -> None:
        if payload:
            self.segs[seq] = payload    # 重传覆盖：同 seq 以新数据为准

    def data(self) -> bytes:
        if not self.segs:
            return b""
        out = bytearray()
        next_seq: int | None = None
        for seq in sorted(self.segs):
            chunk = self.segs[seq]
            if next_seq is None:
                out += chunk
                next_seq = seq + len(chunk)
                continue
            end = seq + len(chunk)
            if end <= next_seq:         # 完全重复（重传/重叠）
                continue
            if seq < next_seq:          # 部分重叠：只取未覆盖的尾部
                out += chunk[next_seq - seq:]
            else:                       # 空洞：拼接但不补齐
                out += chunk
            next_seq = end
        return bytes(out)


# ---------------------------------------------------------------- HTTP 还原

def _split_head(head: bytes):
    """解析请求头：返回 (request_line, {小写头名: 值})。"""
    lines = head.split(b"\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        key = name.strip().lower().decode("latin-1")
        val = value.strip().decode("latin-1")
        # 同名头保留首个（Cookie/Content-Length 重复属异常请求，不做合并）
        headers.setdefault(key, val)
    return request_line, headers


def normalize(text: str) -> str:
    """签名匹配用的归一化视图：URL 解码到不动点 + 转小写。

    为什么必须做（面试可讲）：`${jndi:ldap://x/}` 在 HTTP 里可以写成
    `%24%7Bjndi%3Aldap%3A%2F%2Fx%2F%7D`（URL 编码）、`${JNDI:`（大小写）、
    甚至多重编码。签名规则如果只对原始字节匹配，一个 `%24` 就绕过。
    注意 raw 字段保留原文——**判据可以归一化，证据不能**。
    """
    out = text
    for _ in range(3):                  # 多轮：处理二次/三次编码
        decoded = unquote(out)
        if decoded == out:
            break
        out = decoded
    return out.lower()


def _iter_http_requests(stream: bytes):
    """从一条流里切出 HTTP 请求：(request_line, headers, body, consumed)。"""
    pos = 0
    n = len(stream)
    while pos < n:
        head_end = stream.find(b"\r\n\r\n", pos)
        if head_end < 0:
            return
        head = stream[pos:head_end]
        if not head:
            return
        request_line, headers = _split_head(head)
        method = request_line.split(b" ")[0]
        if method not in _METHODS:
            return                      # 服务端响应或非 HTTP：本方向不产生事件
        try:
            length = int(headers.get("content-length", "0") or 0)
        except ValueError:
            length = 0
        if length < 0 or length > _MAX_BODY:
            return                      # 畸形长度：放弃该流剩余部分
        body_start = head_end + 4
        if body_start + length > n:
            return                      # body 未到齐（后续包还没来）
        body = stream[body_start:body_start + length]
        yield request_line, headers, body
        pos = body_start + length


def _build_event(ts: datetime, ip: str, port: int, request_line: bytes,
                 headers: dict[str, str], body: bytes) -> HttpEvent:
    try:
        line_txt = request_line.decode("utf-8", "replace")
        body_txt = body.decode("utf-8", "replace")
    except Exception:                   # pragma: no cover - decode 已带 replace
        line_txt, body_txt = "", ""
    head_txt = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    raw = f"{line_txt}\r\n{head_txt}\r\n\r\n{body_txt}" if body_txt else \
          f"{line_txt}\r\n{head_txt}"
    parts = line_txt.split(" ")
    uri = parts[1] if len(parts) > 1 else ""
    return HttpEvent(
        # 精度统一到秒：存储层 timespec="seconds"，保留微秒只会造成
        # "内存里有、库里没有"的不一致（与 app_log 的处理一致）
        ts=ts.replace(microsecond=0),
        ip=ip,
        port=port,
        service="http",
        method=parts[0] if parts else "",
        host=headers.get("host", ""),
        uri=uri,
        body=body_txt,
        raw=raw,
        normalized=normalize(raw),
    )


def iter_events(path: str | Path, idle_seconds: float = _FLOW_IDLE_SECONDS):
    """流式产出 HttpEvent：内存只保留活跃流，不随文件大小线性增长。

    为什么需要这个（v1.4，做公开数据集评测时补的）：
    `parse_file` 先把**全部流**缓存起来、最后统一拼装，这在自造的 8 包样本上
    毫无问题，但 CIC-IDS2017 一天 7.7 GB、几十万条并发流——所有流的段数据
    同时驻留内存，根本跑不完。流式的做法是：一条流空闲超过 `idle_seconds`
    就当场拼装产出并释放，内存上界由"活跃流数量"决定，不再由文件大小决定。

    ⚠️ 产出顺序**不保证全局按时间递增**（流的回收顺序取决于空闲顺序）。
    需要全局有序请用 `parse_file`，或在消费端自行排序。

    空闲阈值取 300 秒的依据：一个 HTTP 请求（含 body 传输）不会跨越 5 分钟；
    keep-alive 长连接会被切成多段流，但因为请求边界在流内清晰，分段不影响
    单条请求的还原——除非某个请求真的传了 5 分钟。
    """
    flows: dict[tuple[str, int, str, int], _Flow] = {}
    last_ts: dict[tuple[str, int, str, int], datetime] = {}
    since_sweep = 0

    def drain(key) -> list[HttpEvent]:
        """把一条流拼装成事件并释放（可能不止一条：keep-alive 会在一条流里跑多个请求）。"""
        flow = flows.pop(key, None)
        t = last_ts.pop(key, None)
        if flow is None or t is None:
            return []
        stream = flow.data()
        if not stream:
            return []
        src, sport, _dst, _dport = key
        return [_build_event(t, src, sport, request_line, headers, body)
                for request_line, headers, body in _iter_http_requests(stream)]

    for ts, linktype, frame in _iter_records(path):
        pkt = _ipv4_payload(linktype, frame)
        if pkt is None:
            continue
        parsed = _parse_ipv4(pkt)
        if parsed is None:
            continue
        proto, src, dst, body = parsed
        if proto != _IPPROTO_TCP:
            continue
        tcp = _parse_tcp(body)
        if tcp is None:
            continue
        sport, dport, seq, payload = tcp
        key = (src, sport, dst, dport)
        flows.setdefault(key, _Flow()).add(seq, payload)
        last_ts[key] = ts

        since_sweep += 1
        if since_sweep >= _FLOW_SWEEP_EVERY:
            since_sweep = 0
            stale = [k for k, t in last_ts.items()
                     if (ts - t).total_seconds() > idle_seconds]
            for k in stale:
                yield from drain(k)

    for key in list(flows):
        yield from drain(key)


def parse_file(path: str | Path) -> list[HttpEvent]:
    """解析 PCAP，返回按时间排序的 HTTP 请求事件（全量驻留内存）。

    适合中小文件；GB 级文件请用 `iter_events`。
    """
    flows: dict[tuple[str, int, str, int], _Flow] = {}
    last_ts: dict[tuple[str, int, str, int], datetime] = {}

    for ts, linktype, frame in _iter_records(path):
        pkt = _ipv4_payload(linktype, frame)
        if pkt is None:
            continue
        parsed = _parse_ipv4(pkt)
        if parsed is None:
            continue
        proto, src, dst, body = parsed
        if proto != _IPPROTO_TCP:
            continue
        tcp = _parse_tcp(body)
        if tcp is None:
            continue
        sport, dport, seq, payload = tcp
        key = (src, sport, dst, dport)
        flows.setdefault(key, _Flow()).add(seq, payload)
        last_ts[key] = ts

    events: list[HttpEvent] = []
    for key, flow in flows.items():
        stream = flow.data()
        if not stream:
            continue
        src, sport, _dst, _dport = key
        for request_line, headers, body in _iter_http_requests(stream):
            events.append(_build_event(last_ts[key], src, sport,
                                       request_line, headers, body))
    events.sort(key=lambda e: e.ts)
    return events
