"""采集阶段的轻量预览：只解以太网头，生成列表/详情可显示的行。

完整的三层字段解析在下一阶段（``core/parser.py``）实现；
这里明确标注“待解析”，避免把预览值当成最终结果。
"""

from __future__ import annotations

from ..core.models import Frame
from .models import PacketRow

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

VLAN_TYPES = (0x8100, 0x88A8, 0x9100)


def _mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


def _type_text(ether_type: int) -> str:
    name = ETHER_TYPES.get(ether_type)
    return f"{name} (0x{ether_type:04x})" if name else f"0x{ether_type:04x}"


def build_preview_row(frame: Frame, seq: int) -> PacketRow:
    """把原始帧转成界面行；只读前 14~22 字节。"""
    data = frame.data
    dst_mac = src_mac = "—"
    outer_type = inner_type = 0
    vlan_ids: list[int] = []

    if len(data) >= 14:
        dst_mac = _mac(data[0:6])
        src_mac = _mac(data[6:12])
        outer_type = int.from_bytes(data[12:14], "big")
        inner_type = outer_type
        offset = 12
        while inner_type in VLAN_TYPES and len(data) >= offset + 6:
            tci = int.from_bytes(data[offset + 2:offset + 4], "big")
            vlan_ids.append(tci & 0x0FFF)
            inner_type = int.from_bytes(data[offset + 4:offset + 6], "big")
            offset += 4

    name = ETHER_TYPES.get(inner_type, f"0x{inner_type:04x}")
    version = 4 if inner_type == 0x0800 else 6 if inner_type == 0x86DD else 0

    link_fields: list[tuple[str, str]] = [
        ("目的 MAC", dst_mac),
        ("源 MAC", src_mac),
        ("类型", _type_text(outer_type) if outer_type else "—"),
    ]
    if vlan_ids:
        link_fields.append(("VLAN ID", ", ".join(str(vlan) for vlan in vlan_ids)))
        link_fields.append(("内层类型", _type_text(inner_type)))

    layers: list[tuple[str, list[tuple[str, str]]]] = [
        ("数据链路层（Ethernet II）", link_fields),
        ("网络层", [("状态", "待解析（采集阶段）")]),
        ("传输层", [("状态", "待解析（采集阶段）")]),
        (
            "附加信息",
            [
                ("帧长", f"{frame.origlen} B"),
                ("抓包长度", f"{frame.caplen} B"),
            ],
        ),
    ]

    if len(data) < 14:
        info = f"截断帧  {frame.origlen} B"
    else:
        suffix = f"  VLAN {vlan_ids[0]}" if vlan_ids else ""
        info = f"{name}  {frame.origlen} B{suffix}"

    return PacketRow(
        seq=seq,
        ts=frame.ts,
        src=src_mac,
        dst=dst_mac,
        protocol=name,
        length=frame.origlen,
        info=info,
        raw=data,
        layers=layers,
        version=version,
    )
