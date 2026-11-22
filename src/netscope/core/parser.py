"""报文解析：链路层（阶段 1）+ 网络层（阶段 2）+ 传输层（阶段 3）。

只解析首部字段，不做应用层识别、不做分片重组、不校验校验和。
所有偏移都是"帧内偏移"，界面层据此展示、统计层据此计数。

边界处理：
- 帧短于 14 字节：``eth=None`` 并标记截断；
- VLAN 标签不完整：保留已读字段，标记截断；
- IPv4 选项：按 IHL×4 跳过，否则 TCP 端口会读错位置；
- IPv6 扩展头：逐跳/路由/分片/目的选项/AH 逐层遍历，ESP 停止；
- IPv6 分片（片偏移 > 0）：没有传输层头，端口置空；
- 截断帧：能填多少填多少，标记 ``truncated``，不崩。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import Frame

VLAN_TYPES = (0x8100, 0x88A8, 0x9100)
MAX_VLAN_TAGS = 2

ETHER_TYPES = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
    0x0806: "ARP",
    0x8035: "RARP",
    0x88CC: "LLDP",
    0x8864: "PPPoE",
    0x8847: "MPLS",
    0x8100: "802.1Q",
    0x88A8: "802.1ad",
    0x9100: "QinQ",
}

IP_PROTOCOLS = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    59: "No Next Header",
    89: "OSPF",
    132: "SCTP",
}

# 需要逐层遍历的 IPv6 扩展头
IPV6_EXT_HEADERS = {
    0: "逐跳选项",
    43: "路由头",
    44: "分片头",
    51: "AH",
    60: "目的选项",
}

# TCP 标志位（界面只展示 SYN/ACK/FIN/RST，其余用于判定）
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMPV6_ECHO_REQUEST = 128
ICMPV6_ECHO_REPLY = 129

MAX_EXT_HEADERS = 16


def ether_type_name(ether_type: int) -> str:
    return ETHER_TYPES.get(ether_type, f"0x{ether_type:04x}")


def ip_protocol_name(protocol: int) -> str:
    return IP_PROTOCOLS.get(protocol, str(protocol))


def _mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


def _ipv4(value: bytes) -> str:
    return str(ipaddress.IPv4Address(value))


def _ipv6(value: bytes) -> str:
    return str(ipaddress.IPv6Address(value))


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "big")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "big")


# ==================================================================== 数据
@dataclass(frozen=True, slots=True)
class EthernetInfo:
    dst_mac: str
    src_mac: str
    outer_type: int
    ether_type: int
    vlan_ids: tuple[int, ...]
    payload_offset: int


@dataclass(frozen=True, slots=True)
class IPv4Info:
    version: int = 4
    ihl: int = 20                 # 首部长度（字节）
    tos: int = 0
    total_length: int = 0         # 声明的 IP 分组总长度（主统计口径）
    identification: int = 0
    flags: int = 0                # DF=0x4000 / MF=0x2000
    fragment_offset: int = 0      # 字节
    ttl: int = 0
    protocol: int = 0
    header_checksum: int = 0
    src: str = ""
    dst: str = ""
    payload_offset: int = 0       # 传输层头在帧中的偏移

    @property
    def df(self) -> bool:
        return bool(self.flags & 0x4000)

    @property
    def mf(self) -> bool:
        return bool(self.flags & 0x2000)

    @property
    def fragmented(self) -> bool:
        return self.mf or self.fragment_offset > 0


@dataclass(frozen=True, slots=True)
class IPv6Info:
    version: int = 6
    traffic_class: int = 0
    flow_label: int = 0
    payload_length: int = 0
    next_header: int = 0          # 最终传输层协议号
    hop_limit: int = 0
    src: str = ""
    dst: str = ""
    payload_offset: int = 0       # 传输层头在帧中的偏移
    extension_headers: tuple[str, ...] = ()
    fragment_offset: int = 0      # 字节；>0 表示非首片
    more_fragments: bool = False

    @property
    def fragmented(self) -> bool:
        return self.more_fragments or self.fragment_offset > 0


@dataclass(frozen=True, slots=True)
class TransportInfo:
    protocol: int = 0
    name: str = ""                # TCP / UDP / ICMP / ICMPv6 / 其它
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int = 0            # 原始标志字节
    seq: int | None = None
    ack: int | None = None
    window: int | None = None
    data_offset: int | None = None  # TCP 首部长度（字节）
    icmp_type: int | None = None
    icmp_code: int | None = None
    payload_offset: int = 0       # 应用层载荷在帧中的偏移

    @property
    def tcp_syn(self) -> bool:
        return bool(self.tcp_flags & TCP_SYN)

    @property
    def tcp_ack(self) -> bool:
        return bool(self.tcp_flags & TCP_ACK)

    @property
    def tcp_fin(self) -> bool:
        return bool(self.tcp_flags & TCP_FIN)

    @property
    def tcp_rst(self) -> bool:
        return bool(self.tcp_flags & TCP_RST)

    @property
    def is_echo_request(self) -> bool:
        return (self.protocol == 1 and self.icmp_type == ICMP_ECHO_REQUEST) or (
            self.protocol == 58 and self.icmp_type == ICMPV6_ECHO_REQUEST
        )

    @property
    def is_echo_reply(self) -> bool:
        return (self.protocol == 1 and self.icmp_type == ICMP_ECHO_REPLY) or (
            self.protocol == 58 and self.icmp_type == ICMPV6_ECHO_REPLY
        )


@dataclass(frozen=True, slots=True)
class ParsedFrame:
    frame: Frame
    eth: EthernetInfo | None
    ipv4: IPv4Info | None = None
    ipv6: IPv6Info | None = None
    transport: TransportInfo | None = None
    truncated: bool = False
    malformed: bool = False

    # ------------------------------------------------------------ 派生字段
    @property
    def protocol(self) -> str:
        """列表"协议"列：优先传输层协议名，其次网络层/链路层类型。"""
        if self.transport is not None:
            return self.transport.name
        if self.ipv4 is not None:
            return "IPv4"
        if self.ipv6 is not None:
            return "IPv6"
        if self.eth is None:
            return "截断"
        return ether_type_name(self.eth.ether_type)

    @property
    def ip_version(self) -> int:
        if self.ipv4 is not None:
            return 4
        if self.ipv6 is not None:
            return 6
        return 0

    @property
    def ip_length(self) -> int:
        """IP 分组长度（主统计口径）。

        IPv4 取总长度；IPv6 取 40 + 载荷长度；非 IP 退回帧长。
        声明的长度不可能小于首部本身，否则按畸形退回帧长。
        """
        if self.ipv4 is not None:
            if self.ipv4.total_length >= self.ipv4.ihl:
                return self.ipv4.total_length
            return self.frame.origlen
        if self.ipv6 is not None:
            if self.ipv6.payload_length > 0:
                return 40 + self.ipv6.payload_length
            return self.frame.origlen
        return self.frame.origlen

    @property
    def src_ip(self) -> str | None:
        if self.ipv4 is not None:
            return self.ipv4.src
        if self.ipv6 is not None:
            return self.ipv6.src
        return None

    @property
    def dst_ip(self) -> str | None:
        if self.ipv4 is not None:
            return self.ipv4.dst
        if self.ipv6 is not None:
            return self.ipv6.dst
        return None


# ==================================================================== 解析
def parse_frame(frame: Frame) -> ParsedFrame:
    """解析以太网 → 网络层 → 传输层；失败时尽量返回已读出的字段。"""
    data = frame.data
    if len(data) < 14:
        return ParsedFrame(frame=frame, eth=None, truncated=True)

    dst_mac = _mac(data[0:6])
    src_mac = _mac(data[6:12])
    outer_type = _u16(data, 12)
    ether_type = outer_type
    vlan_ids: list[int] = []
    offset = 12  # 当前 EtherType 的位置
    truncated = False

    while ether_type in VLAN_TYPES and len(vlan_ids) < MAX_VLAN_TAGS:
        if len(data) < offset + 6:
            # 有标签类型，但 TCI 或内层类型不完整
            truncated = True
            break
        tci = _u16(data, offset + 2)
        vlan_ids.append(tci & 0x0FFF)
        ether_type = _u16(data, offset + 4)
        offset += 4

    payload_offset = offset + 2
    if payload_offset > len(data):
        truncated = True

    malformed = ether_type in VLAN_TYPES and not truncated

    eth = EthernetInfo(
        dst_mac=dst_mac,
        src_mac=src_mac,
        outer_type=outer_type,
        ether_type=ether_type,
        vlan_ids=tuple(vlan_ids),
        payload_offset=payload_offset,
    )

    parsed = ParsedFrame(
        frame=frame,
        eth=eth,
        truncated=truncated,
        malformed=malformed,
    )
    if truncated:
        return parsed

    if ether_type == 0x0800:
        parsed = _parse_ipv4(frame, payload_offset, parsed)
    elif ether_type == 0x86DD:
        parsed = _parse_ipv6(frame, payload_offset, parsed)

    if parsed.ipv4 is not None or parsed.ipv6 is not None:
        parsed = _parse_transport(frame, parsed)
    return parsed


def _parse_ipv4(frame: Frame, offset: int, parsed: ParsedFrame) -> ParsedFrame:
    data = frame.data
    if offset + 20 > len(data):
        return ParsedFrame(
            frame=frame, eth=parsed.eth,
            truncated=True, malformed=parsed.malformed,
        )

    first = data[offset]
    version = first >> 4
    if version != 4:
        # EtherType 是 IPv4 但首部版本号不对：标记畸形，不往下解
        return ParsedFrame(
            frame=frame, eth=parsed.eth,
            truncated=parsed.truncated, malformed=True,
        )

    ihl = (first & 0x0F) * 4
    if ihl < 20:
        return ParsedFrame(
            frame=frame, eth=parsed.eth,
            truncated=parsed.truncated, malformed=True,
        )

    total_length = _u16(data, offset + 2)
    flags_frag = _u16(data, offset + 6)
    ipv4 = IPv4Info(
        version=4,
        ihl=ihl,
        tos=data[offset + 1],
        total_length=total_length,
        identification=_u16(data, offset + 4),
        flags=flags_frag & 0xE000,
        fragment_offset=(flags_frag & 0x1FFF) * 8,
        ttl=data[offset + 8],
        protocol=data[offset + 9],
        header_checksum=_u16(data, offset + 10),
        src=_ipv4(data[offset + 12:offset + 16]),
        dst=_ipv4(data[offset + 16:offset + 20]),
        payload_offset=offset + ihl,
    )
    truncated = parsed.truncated or offset + ihl > len(data)
    return ParsedFrame(
        frame=frame, eth=parsed.eth, ipv4=ipv4,
        truncated=truncated, malformed=parsed.malformed,
    )


def _parse_ipv6(frame: Frame, offset: int, parsed: ParsedFrame) -> ParsedFrame:
    data = frame.data
    if offset + 40 > len(data):
        return ParsedFrame(
            frame=frame, eth=parsed.eth,
            truncated=True, malformed=parsed.malformed,
        )

    first = _u32(data, offset)
    version = first >> 28
    if version != 6:
        return ParsedFrame(
            frame=frame, eth=parsed.eth,
            truncated=parsed.truncated, malformed=True,
        )

    payload_length = _u16(data, offset + 4)
    next_header = data[offset + 6]
    hop_limit = data[offset + 7]

    ext_names: list[str] = []
    fragment_offset = 0
    more_fragments = False
    cursor = offset + 40
    truncated = False

    for _ in range(MAX_EXT_HEADERS):
        if next_header not in IPV6_EXT_HEADERS:
            break
        if next_header == 44:  # 分片头：固定 8 字节
            if cursor + 8 > len(data):
                truncated = True
                break
            frag_field = _u16(data, cursor + 2)
            fragment_offset = ((frag_field >> 3) & 0x1FFF) * 8
            more_fragments = bool(frag_field & 0x0001)
            ext_names.append("分片头")
            next_header = data[cursor]
            cursor += 8
            continue
        if cursor + 2 > len(data):
            truncated = True
            break
        # AH(51) 的长度字段单位是 4 字节且不含首 8 字节；其余扩展头是 8 字节单位
        if next_header == 51:
            header_len = (data[cursor + 1] + 2) * 4
        else:
            header_len = (data[cursor + 1] + 1) * 8
        ext_names.append(IPV6_EXT_HEADERS[next_header])
        next_header = data[cursor]
        cursor += header_len
        if cursor > len(data):
            truncated = True
            break
    else:
        malformed = True  # 扩展头层数超限
        return ParsedFrame(
            frame=frame, eth=parsed.eth,
            truncated=parsed.truncated, malformed=True,
        )

    ipv6 = IPv6Info(
        version=6,
        traffic_class=(first >> 20) & 0xFF,
        flow_label=first & 0xFFFFF,
        payload_length=payload_length,
        next_header=next_header,
        hop_limit=hop_limit,
        src=_ipv6(data[offset + 8:offset + 24]),
        dst=_ipv6(data[offset + 24:offset + 40]),
        payload_offset=cursor,
        extension_headers=tuple(ext_names),
        fragment_offset=fragment_offset,
        more_fragments=more_fragments,
    )
    truncated = truncated or cursor > len(data)
    return ParsedFrame(
        frame=frame, eth=parsed.eth, ipv6=ipv6,
        truncated=truncated, malformed=parsed.malformed,
    )


def _parse_transport(frame: Frame, parsed: ParsedFrame) -> ParsedFrame:
    """根据网络层协议号解析 TCP/UDP/ICMP；非 IP 或解析失败保持原样。"""
    if parsed.ipv4 is not None:
        protocol = parsed.ipv4.protocol
        offset = parsed.ipv4.payload_offset
        if protocol == 0:  # HOPOPT：IPv4 里视为无传输层
            return parsed
        if parsed.ipv4.fragment_offset > 0:
            # 非首片：没有传输层头
            return _with_transport(parsed, TransportInfo(
                protocol=protocol, name="IPv4 分片",
                payload_offset=offset,
            ))
    else:
        protocol = parsed.ipv6.next_header
        offset = parsed.ipv6.payload_offset
        if protocol == 59:  # No Next Header
            return _with_transport(parsed, TransportInfo(
                protocol=protocol, name="No Next Header",
                payload_offset=offset,
            ))
        if parsed.ipv6.fragment_offset > 0:
            return _with_transport(parsed, TransportInfo(
                protocol=protocol, name="IPv6 分片",
                payload_offset=offset,
            ))
        if protocol in (50,):  # ESP：加密，不可解析
            return _with_transport(parsed, TransportInfo(
                protocol=protocol, name="ESP",
                payload_offset=offset,
            ))

    data = frame.data
    truncated = parsed.truncated

    if protocol == 6:  # TCP
        if offset + 20 > len(data):
            truncated = True
            transport = TransportInfo(protocol=6, name="TCP", payload_offset=offset)
        else:
            data_offset = (data[offset + 12] >> 4) * 4
            transport = TransportInfo(
                protocol=6,
                name="TCP",
                sport=_u16(data, offset),
                dport=_u16(data, offset + 2),
                tcp_flags=data[offset + 13],
                seq=_u32(data, offset + 4),
                ack=_u32(data, offset + 8),
                window=_u16(data, offset + 14),
                data_offset=data_offset,
                payload_offset=offset + data_offset,
            )
            if data_offset < 20:
                truncated = True
            elif offset + data_offset > len(data):
                truncated = True
        return _with_transport(parsed, transport, truncated=truncated)

    if protocol == 17:  # UDP
        if offset + 8 > len(data):
            truncated = True
            transport = TransportInfo(protocol=17, name="UDP", payload_offset=offset)
        else:
            udp_length = _u16(data, offset + 4)
            transport = TransportInfo(
                protocol=17,
                name="UDP",
                sport=_u16(data, offset),
                dport=_u16(data, offset + 2),
                payload_offset=offset + 8,
            )
            if udp_length > 0 and offset + udp_length > len(data):
                truncated = True
        return _with_transport(parsed, transport, truncated=truncated)

    if protocol in (1, 58):  # ICMP / ICMPv6
        name = "ICMP" if protocol == 1 else "ICMPv6"
        if offset + 4 > len(data):
            truncated = True
            transport = TransportInfo(protocol=protocol, name=name, payload_offset=offset)
        else:
            transport = TransportInfo(
                protocol=protocol,
                name=name,
                icmp_type=data[offset],
                icmp_code=data[offset + 1],
                payload_offset=offset + 4,
            )
        return _with_transport(parsed, transport, truncated=truncated)

    # 其它传输层协议：只给协议名
    return _with_transport(parsed, TransportInfo(
        protocol=protocol,
        name=ip_protocol_name(protocol),
        payload_offset=offset,
    ))


def _with_transport(
    parsed: ParsedFrame,
    transport: TransportInfo,
    *,
    truncated: bool | None = None,
) -> ParsedFrame:
    return ParsedFrame(
        frame=parsed.frame,
        eth=parsed.eth,
        ipv4=parsed.ipv4,
        ipv6=parsed.ipv6,
        transport=transport,
        truncated=parsed.truncated if truncated is None else truncated,
        malformed=parsed.malformed,
    )
