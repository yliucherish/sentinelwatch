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
1. **手写 libpcap / pcapng 解析**：全局头 24 字节（magic 区分大小端 + 微秒/纳秒精度），
   每包 16 字节记录头 + 链路层帧。支持 Ethernet(1) / Raw IP(101) / Linux SLL(113)
   三种链路类型——现实里 `tcpdump -i any` 产出的是 SLL，只支持 Ethernet 会踩坑。
   **同时支持 pcapng**（Section Header / Interface Description / Enhanced Packet 块，
   含 `if_tsresol` 时间精度选项）：CIC-IDS2017 现在官方发的是 pcapng，只认老 pcap
   就必须先装 tcpdump 转一道——本项目坚持"标准库能吃原始文件"，不引入这个前置条件。
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

# pcapng：Section Header Block 的块类型字节序中立（0x0A0D0D0A），
# 所以文件头 4 字节可以直接和字面量比，不需要先判断端序。
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"      # 字节序魔数的大端写法
_PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"
_PCAPNG_BLOCK_IDB = 0x00000001
_PCAPNG_BLOCK_PB = 0x00000002             # 已废弃但仍会出现在老文件里
_PCAPNG_BLOCK_EPB = 0x00000006
_PCAPNG_DEFAULT_TSRESOL = 1e-6            # 未声明 if_tsresol 时按微秒

# 单个 pcapng 块的上限：snaplen 通常 64KB~256KB，留到 64MB 只为挡损坏文件
_MAX_BLOCK = 1 << 26

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

    两种容器格式共用这一个出口，上层（TCP 重组 / HTTP 还原）完全不知道
    文件是 pcap 还是 pcapng —— 格式差异被收敛在这里。

    经典 PCAP 全局头结构（24 字节，全部按文件字节序）：
        magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
    记录头结构（16 字节）：ts_sec(4) ts_frac(4) incl_len(4) orig_len(4)

    v1.4：**改成逐条记录从文件读取**。原来用 `read_bytes()` 一次性读入，
    在公开数据集（CIC-IDS2017 单日 7.7–12 GB）上直接 OOM——这是做基准评测
    时才暴露的问题：自造的 8 包样本永远发现不了"你的解析器有没有内存上界"。
    PCAP 的记录头自带长度，天然可分帧，流式读不需要任何妥协。

    v1.5：识别 pcapng。判据是文件头 4 字节 —— pcapng 的 Section Header Block
    类型 0x0A0D0D0A 是**字节序中立**的，所以 4 字节直接比对即可，不必先猜端序。
    """
    with open(path, "rb") as f:
        magic4 = f.read(4)
        f.seek(0)
        if magic4 == _PCAPNG_SHB:
            yield from _iter_pcapng(f)
            return

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
            raise PcapError(f"未知 magic {head[:4].hex()}（既不是 libpcap 也不是 pcapng）")

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


def _iter_pcapng(f):
    """解析 pcapng，产出与 `_iter_records` 相同的三元组。

    pcapng 与 pcap 的本质区别：它是**分块**的，而且
    - 每个 Section 可以有自己的字节序（由 Section Header 里的字节序魔数决定）；
    - 链路类型不再全局唯一，而是每个 Interface Description Block 一个，
      包只带 interface_id —— 所以必须按接口记住 linktype 和时间精度；
    - 时间戳被拆成高/低 32 位，精度由接口选项 `if_tsresol` 决定（默认微秒）。
      这一点最容易漏：默认按微秒处理的前提是"抓包工具没改过"，一旦
      `tcpdump --time-stamp-precision=nano` 抓的包按微秒算，时间会偏 1000 倍，
      而症状是"攻击窗对不上"——看起来像检测器坏了。

    只处理与检测相关的块（SHB / IDB / EPB / 老式 PB）。SPB 没有时间戳，跳过。
    """
    endian: str | None = None
    linktypes: list[int] = []
    tsresol: list[float] = []             # 每个接口：一个时间戳单位等于多少秒

    while True:
        head = f.read(12)                 # type(4) + total_len(4) + body 前 4 字节
        if len(head) < 12:
            return                        # EOF 或截断

        if head[:4] == _PCAPNG_SHB:
            bom = head[8:12]
            if bom == _PCAPNG_BOM_BE:
                endian = ">"
            elif bom == _PCAPNG_BOM_LE:
                endian = "<"
            else:
                raise PcapError(f"pcapng Section Header 的字节序魔数异常: {bom.hex()}")
            total = struct.unpack(endian + "I", head[4:8])[0]
            rest = _pcapng_rest(f, total)
            if rest is None:
                return
            # 新 Section 意味着接口表重来。一个文件里出现多个 Section 很少见，
            # 但格式允许，不重置的话长文件的接口索引会串。
            linktypes, tsresol = [], []
            continue

        if endian is None:
            raise PcapError("pcapng 首个块不是 Section Header Block，文件可能已损坏")

        btype, total = struct.unpack(endian + "II", head[:8])
        rest = _pcapng_rest(f, total)
        if rest is None:
            return
        body = head[8:12] + rest[:-4]     # rest 的最后 4 字节是重复的块长度

        if btype == _PCAPNG_BLOCK_IDB:
            if len(body) < 8:
                raise PcapError("pcapng Interface Description Block 过短")
            linktypes.append(struct.unpack(endian + "H", body[0:2])[0])
            tsresol.append(_pcapng_tsresol(body[8:], endian))
            continue

        if btype in (_PCAPNG_BLOCK_EPB, _PCAPNG_BLOCK_PB):
            if btype == _PCAPNG_BLOCK_EPB:
                if len(body) < 20:
                    raise PcapError("pcapng Enhanced Packet Block 过短")
                ifid = struct.unpack(endian + "I", body[0:4])[0]
                ts_high, ts_low = struct.unpack(endian + "II", body[4:12])
                caplen = struct.unpack(endian + "I", body[12:16])[0]
                data_off = 20
            else:                          # 已废弃的 Packet Block（16 位接口号）
                if len(body) < 20:
                    raise PcapError("pcapng Packet Block 过短")
                ifid = struct.unpack(endian + "H", body[0:2])[0]
                ts_high, ts_low = struct.unpack(endian + "II", body[4:12])
                caplen = struct.unpack(endian + "I", body[12:16])[0]
                data_off = 20

            if ifid >= len(linktypes):
                raise PcapError(f"pcapng 包引用了未声明的接口 id={ifid}"
                                f"（已声明 {len(linktypes)} 个）")
            if caplen > _MAX_FRAME:
                raise PcapError(f"pcapng 包长度异常 caplen={caplen}")
            frame = body[data_off:data_off + caplen]
            if len(frame) < caplen:
                return                     # 截断：已读部分照常返回
            ts = ((ts_high << 32) | ts_low) * tsresol[ifid]
            yield datetime.fromtimestamp(ts), linktypes[ifid], frame
            continue

        # Simple Packet Block（无时间戳）与自定义块：跳过，不影响后续块
        continue


def _pcapng_rest(f, total: int) -> bytes | None:
    """读完一个块剩下的 total-12 字节；块长度非法则抛错，文件截断返回 None。"""
    if total < 12 or total % 4 or total > _MAX_BLOCK:
        raise PcapError(f"pcapng 块长度非法 total_length={total}")
    rest = f.read(total - 12)
    return rest if len(rest) == total - 12 else None


def _pcapng_tsresol(options: bytes, endian: str) -> float:
    """从 IDB 选项里读 if_tsresol（code=9），缺省按微秒。

    该字节最高位为 1 时表示 2 的负幂，否则表示 10 的负幂。
    """
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[off:off + 4])
        if code == 0:                     # opt_endofopt
            break
        value = options[off + 4:off + 4 + length]
        if code == 9 and length >= 1 and value:
            exp = value[0]
            return (2.0 ** -(exp & 0x7F)) if exp & 0x80 else (10.0 ** -exp)
        off += 4 + length + ((4 - length % 4) % 4)
    return _PCAPNG_DEFAULT_TSRESOL


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

    这里**不处理** form 编码里的 `+`：`normalize()` 只拿到一段文本，不知道
    哪部分是 query、哪部分是 body，更不知道 Content-Type。整段 replace 会把
    `/a+b` 改成 `/a b`，那是另一种失真。`+` 的处理放在 `_judgement_text()`
    里做，那里有上下文。顺序也有讲究：**必须在 unquote 之前**换成空格，
    否则 `%2B`（字面加号）会先被解码成 `+`、再被误换成空格。
    """
    out = text
    for _ in range(3):                  # 多轮：处理二次/三次编码
        decoded = unquote(out)
        if decoded == out:
            break
        out = decoded
    return out.lower()


_FORM_URLENCODED = "application/x-www-form-urlencoded"


def _query_view(line_txt: str) -> str:
    """把请求行 query 里代表空格的 `+` 还原成空格；path 部分一个字不动。

    为什么只动 query（面试可讲）：`+` 只在 query string 与
    `application/x-www-form-urlencoded` body 里代表空格；在 path、Header、
    JSON body 里它就是字面的加号。`GET /a+b?x=1+2` 里只能动 `1+2`。
    """
    parts = line_txt.split(" ")
    if len(parts) < 2 or "?" not in parts[1]:
        return line_txt
    path, _, query = parts[1].partition("?")
    parts[1] = f"{path}?{query.replace('+', ' ')}"
    return " ".join(parts)


def _judgement_text(line_txt: str, head_txt: str, body_txt: str,
                    headers: dict[str, str]) -> str:
    """构造归一化视图的输入：`raw` 原样保留，这里只给它做"可解释副本"。

    v1.9 补的缺口（做跨项目交叉评测时发现的）：`normalize()` 只做 unquote +
    转小写，而 query 与 form body 里 `+` 的语义就是空格。于是
    `id=1+UNION+SELECT+pw+FROM+users` 归一化后仍是 `1+union+select`，
    规则里的 `union select` 匹配不到——**form 编码成了一个天然的绕过语法**。
    bypasslab 语料里这种载荷很多，v1.8 交叉评测的 49.6% 里有一块就是这个缺口。

    只在 Content-Type 明确是 form-urlencoded 时才动 body：multipart 与 JSON
    里的 `+` 是字面量，动了就是引入误报。
    """
    line_view = _query_view(line_txt)
    body_view = body_txt
    if _FORM_URLENCODED in (headers.get("content-type") or "").lower():
        body_view = body_txt.replace("+", " ")
    if body_view:
        return f"{line_view}\r\n{head_txt}\r\n\r\n{body_view}"
    return f"{line_view}\r\n{head_txt}"


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
        normalized=normalize(
            _judgement_text(line_txt, head_txt, body_txt, headers)
        ),
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
