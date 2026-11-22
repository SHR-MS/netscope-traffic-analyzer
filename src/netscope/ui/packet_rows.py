"""把 ParsedFrame 转成界面显示行：三层字段按需求逐字段展开。

必显字段（docs/解析清单.md）：

- 链路层：源 MAC、目的 MAC、以太网类型；
- 网络层：源 IP、目的 IP、IP 版本、TTL（IPv6 为跳数限制）、协议号；
- 传输层：TCP/UDP 源端口、目的端口；TCP 标志位（SYN/ACK/FIN/RST）。

附加信息默认折叠展示；非 TCP/UDP 的端口显示"不适用"。
"""

from __future__ import annotations

from ..core.models import Frame
from ..core.parser import ParsedFrame, ether_type_name, ip_protocol_name
from .models import PacketRow

FLAG_NAMES = [("SYN", 0x02), ("ACK", 0x10), ("FIN", 0x01), ("RST", 0x04)]


def _type_text(ether_type: int) -> str:
    return f"{ether_type_name(ether_type)} (0x{ether_type:04x})"


def _flags_text(flags: int) -> str:
    return " ".join(f"{name}={1 if flags & bit else 0}" for name, bit in FLAG_NAMES)


def _protocol_text(protocol: int) -> str:
    return f"{protocol} ({ip_protocol_name(protocol)})"


def _tcp_info(parsed: ParsedFrame) -> str:
    transport = parsed.transport
    assert transport is not None
    sport = transport.sport
    dport = transport.dport
    ports = (
        f"{sport} → {dport}"
        if sport is not None and dport is not None
        else "端口不适用"
    )
    names = [name for name, bit in FLAG_NAMES if transport.tcp_flags & bit]
    flags = f"[{', '.join(names)}]" if names else ""
    parts = [ports, flags]
    if transport.seq is not None:
        parts.append(f"Seq={transport.seq}")
    if transport.ack is not None and (transport.tcp_flags & 0x10):
        parts.append(f"Ack={transport.ack}")
    payload_len = parsed.ip_length - (transport.payload_offset - parsed.eth.payload_offset)
    parts.append(f"Len={max(0, payload_len)}")
    return " ".join(part for part in parts if part)


def _udp_info(parsed: ParsedFrame) -> str:
    transport = parsed.transport
    assert transport is not None
    if transport.sport is None or transport.dport is None:
        return "端口不适用"
    return f"{transport.sport} → {transport.dport}"


_ICMP_NAMES = {
    (0, None): "Echo (ping) reply",
    (8, None): "Echo (ping) request",
    (3, None): "Destination unreachable",
    (11, None): "TTL exceeded",
    (129, None): "Echo (ping) reply",
    (128, None): "Echo (ping) request",
    (135, None): "Neighbor solicitation",
    (136, None): "Neighbor advertisement",
}


def _icmp_info(parsed: ParsedFrame) -> str:
    transport = parsed.transport
    assert transport is not None
    if transport.icmp_type is None:
        return "ICMP"
    name = _ICMP_NAMES.get((transport.icmp_type, None), None)
    if name is None:
        return f"type={transport.icmp_type} code={transport.icmp_code}"
    return f"{name}  code={transport.icmp_code}"


def build_packet_row(parsed: ParsedFrame, seq: int) -> PacketRow:
    frame: Frame = parsed.frame
    eth = parsed.eth

    if eth is None:
        layers = [
            ("数据链路层（Ethernet II）", [("状态", "帧头截断")]),
            ("网络层", [("状态", "不适用")]),
            ("传输层", [("状态", "不适用")]),
            (
                "附加信息",
                [
                    ("帧长", f"{frame.origlen} B"),
                    ("抓包长度", f"{frame.caplen} B"),
                    ("截断", "是"),
                ],
            ),
        ]
        return PacketRow(
            seq=seq,
            ts=frame.ts,
            src="—",
            dst="—",
            protocol="截断",
            length=frame.origlen,
            info=f"截断帧  {frame.origlen} B",
            raw=frame.data,
            layers=layers,
            version=0,
        )

    # ------------------------------------------------------------ 链路层
    link_fields: list[tuple[str, str]] = [
        ("目的 MAC", eth.dst_mac),
        ("源 MAC", eth.src_mac),
        ("类型", _type_text(eth.outer_type)),
    ]
    if eth.vlan_ids:
        link_fields.append(("VLAN ID", ", ".join(str(vlan) for vlan in eth.vlan_ids)))
        link_fields.append(("内层类型", _type_text(eth.ether_type)))

    # ------------------------------------------------------------ 网络层
    if parsed.ipv4 is not None:
        ip = parsed.ipv4
        network_fields: list[tuple[str, str]] = [
            ("版本", "4"),
            ("源 IP", ip.src),
            ("目的 IP", ip.dst),
            ("TTL", str(ip.ttl)),
            ("协议号", _protocol_text(ip.protocol)),
        ]
        extra_ip: list[tuple[str, str]] = [
            ("首部长度", f"{ip.ihl} B"),
            ("总长度", f"{ip.total_length} B"),
            ("标识", f"0x{ip.identification:04x}"),
            ("DF", "1" if ip.df else "0"),
            ("MF", "1" if ip.mf else "0"),
            ("片偏移", f"{ip.fragment_offset} B"),
        ]
        network_title = "网络层（IPv4）"
    elif parsed.ipv6 is not None:
        ip = parsed.ipv6
        network_fields = [
            ("版本", "6"),
            ("源 IP", ip.src),
            ("目的 IP", ip.dst),
            ("跳数限制", str(ip.hop_limit)),
            ("协议号", _protocol_text(ip.next_header)),
        ]
        extra_ip = [
            ("载荷长度", f"{ip.payload_length} B"),
            ("流量类别", str(ip.traffic_class)),
            ("流标签", f"0x{ip.flow_label:05x}"),
        ]
        if ip.extension_headers:
            extra_ip.append(("扩展头", " → ".join(ip.extension_headers)))
        if ip.fragmented:
            extra_ip.append(("片偏移", f"{ip.fragment_offset} B"))
            extra_ip.append(("更多分片", "1" if ip.more_fragments else "0"))
        network_title = "网络层（IPv6）"
    elif eth.ether_type in (0x0800, 0x86DD):
        network_fields = [("状态", "IP 首部无效或截断")]
        extra_ip = []
        network_title = "网络层"
    else:
        network_fields = [
            ("类型", ether_type_name(eth.ether_type)),
            ("说明", "非 IP 数据（计入“其它”）"),
        ]
        extra_ip = []
        network_title = "网络层"

    # ------------------------------------------------------------ 传输层
    transport = parsed.transport
    if transport is None:
        transport_fields: list[tuple[str, str]] = [("状态", "不适用")]
        extra_transport: list[tuple[str, str]] = []
        transport_title = "传输层"
    elif transport.name == "TCP":
        transport_fields = [
            ("源端口", _port_text(transport.sport)),
            ("目的端口", _port_text(transport.dport)),
            ("标志位", _flags_text(transport.tcp_flags)),
        ]
        extra_transport = [
            ("序号", str(transport.seq) if transport.seq is not None else "—"),
            ("确认号", str(transport.ack) if transport.ack is not None else "—"),
            ("首部长度", f"{transport.data_offset} B" if transport.data_offset else "—"),
            ("窗口", str(transport.window) if transport.window is not None else "—"),
        ]
        transport_title = "传输层（TCP）"
    elif transport.name == "UDP":
        transport_fields = [
            ("源端口", _port_text(transport.sport)),
            ("目的端口", _port_text(transport.dport)),
        ]
        extra_transport = []
        transport_title = "传输层（UDP）"
    elif transport.name in ("ICMP", "ICMPv6"):
        transport_fields = [
            ("类型", _icmp_type_text(transport.icmp_type)),
            ("代码", str(transport.icmp_code) if transport.icmp_code is not None else "—"),
            ("端口", "不适用"),
        ]
        extra_transport = []
        transport_title = f"传输层（{transport.name}）"
    else:
        transport_fields = [("状态", transport.name)]
        extra_transport = []
        transport_title = "传输层"

    # ------------------------------------------------------------ 附加信息
    extra_fields: list[tuple[str, str]] = [
        ("帧长", f"{frame.origlen} B"),
        ("抓包长度", f"{frame.caplen} B"),
        ("网络层偏移", f"{eth.payload_offset} B"),
    ]
    if parsed.ip_version:
        extra_fields.append(("IP 分组长度", f"{parsed.ip_length} B"))
    extra_fields.extend(extra_ip)
    extra_fields.extend(extra_transport)
    if parsed.truncated:
        extra_fields.append(("截断", "是"))
    if parsed.malformed:
        extra_fields.append(("畸形", "首部异常"))

    layers = [
        ("数据链路层（Ethernet II）", link_fields),
        (network_title, network_fields),
        (transport_title, transport_fields),
        ("附加信息", extra_fields),
    ]

    # ------------------------------------------------------------ 列与摘要
    src = parsed.src_ip or eth.src_mac
    dst = parsed.dst_ip or eth.dst_mac

    if transport is None:
        info = f"{ether_type_name(eth.ether_type)}  {frame.origlen} B"
    elif transport.name == "TCP":
        info = _tcp_info(parsed)
    elif transport.name == "UDP":
        info = _udp_info(parsed)
    elif transport.name in ("ICMP", "ICMPv6"):
        info = _icmp_info(parsed)
    else:
        info = f"{transport.name}  {frame.origlen} B"

    suffix = ""
    if eth.vlan_ids:
        suffix = "  VLAN " + "/".join(str(vlan) for vlan in eth.vlan_ids)
    if parsed.truncated:
        suffix += "  [截断]"
    info += suffix

    return PacketRow(
        seq=seq,
        ts=frame.ts,
        src=src,
        dst=dst,
        protocol=parsed.protocol,
        length=parsed.ip_length,
        info=info,
        raw=frame.data,
        layers=layers,
        version=parsed.ip_version,
    )


def _port_text(port: int | None) -> str:
    return str(port) if port is not None else "不适用"


def _icmp_type_text(icmp_type: int | None) -> str:
    if icmp_type is None:
        return "—"
    names = {
        0: "0 (Echo Reply)",
        3: "3 (Destination Unreachable)",
        8: "8 (Echo Request)",
        11: "11 (Time Exceeded)",
        128: "128 (Echo Request)",
        129: "129 (Echo Reply)",
        135: "135 (Neighbor Solicitation)",
        136: "136 (Neighbor Advertisement)",
    }
    return names.get(icmp_type, str(icmp_type))
