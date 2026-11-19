"""把 ParsedFrame 转成界面显示行（阶段 1：只显示链路层）。"""

from __future__ import annotations

from ..core.models import Frame
from ..core.parser import ParsedFrame, ether_type_name
from .models import PacketRow


def _type_text(ether_type: int) -> str:
    return f"{ether_type_name(ether_type)} (0x{ether_type:04x})"


def build_packet_row(parsed: ParsedFrame, seq: int) -> PacketRow:
    frame: Frame = parsed.frame
    eth = parsed.eth

    if eth is None:
        layers = [
            ("数据链路层（Ethernet II）", [("状态", "帧头截断")]),
            ("网络层", [("状态", "待解析（阶段 2）")]),
            ("传输层", [("状态", "待解析（阶段 3）")]),
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

    link_fields: list[tuple[str, str]] = [
        ("目的 MAC", eth.dst_mac),
        ("源 MAC", eth.src_mac),
        ("类型", _type_text(eth.outer_type)),
    ]
    if eth.vlan_ids:
        link_fields.append(("VLAN ID", ", ".join(str(vlan) for vlan in eth.vlan_ids)))
        link_fields.append(("内层类型", _type_text(eth.ether_type)))

    extra_fields: list[tuple[str, str]] = [
        ("帧长", f"{frame.origlen} B"),
        ("抓包长度", f"{frame.caplen} B"),
        ("网络层偏移", f"{eth.payload_offset} B"),
    ]
    if parsed.truncated:
        extra_fields.append(("截断", "是"))
    if parsed.malformed:
        extra_fields.append(("畸形", "VLAN 标签异常"))

    layers = [
        ("数据链路层（Ethernet II）", link_fields),
        ("网络层", [("状态", "待解析（阶段 2）")]),
        ("传输层", [("状态", "待解析（阶段 3）")]),
        ("附加信息", extra_fields),
    ]

    name = parsed.protocol
    suffix = ""
    if eth.vlan_ids:
        suffix = "  VLAN " + "/".join(str(vlan) for vlan in eth.vlan_ids)
    if parsed.truncated:
        suffix += "  [截断]"
    info = f"{name}  {frame.origlen} B{suffix}"

    return PacketRow(
        seq=seq,
        ts=frame.ts,
        src=eth.src_mac,
        dst=eth.dst_mac,
        protocol=name,
        length=frame.origlen,
        info=info,
        raw=frame.data,
        layers=layers,
        version=parsed.ip_version,
    )
