"""链路层解析（阶段 1）。

只负责把一个原始帧拆成以太网头：MAC、EtherType、VLAN 标签、载荷偏移。
网络层/传输层在后续阶段加入 ``ParsedFrame``，界面层不需要重写。

边界处理：
- 帧短于 14 字节：``eth=None`` 并标记截断；
- VLAN 标签不完整：保留已读字段，标记截断；
- 超过两层的标签：按 QoS/实验环境处理，标记畸形。
"""

from __future__ import annotations

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


def ether_type_name(ether_type: int) -> str:
    return ETHER_TYPES.get(ether_type, f"0x{ether_type:04x}")


def _mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


@dataclass(frozen=True, slots=True)
class EthernetInfo:
    dst_mac: str
    src_mac: str
    outer_type: int
    ether_type: int
    vlan_ids: tuple[int, ...]
    payload_offset: int


@dataclass(frozen=True, slots=True)
class ParsedFrame:
    frame: Frame
    eth: EthernetInfo | None
    truncated: bool = False
    malformed: bool = False

    @property
    def protocol(self) -> str:
        if self.eth is None:
            return "截断"
        return ether_type_name(self.eth.ether_type)

    @property
    def ip_version(self) -> int:
        if self.eth is None:
            return 0
        if self.eth.ether_type == 0x0800:
            return 4
        if self.eth.ether_type == 0x86DD:
            return 6
        return 0


def parse_frame(frame: Frame) -> ParsedFrame:
    """解析以太网头；失败时尽量返回已读出的字段。"""
    data = frame.data
    if len(data) < 14:
        return ParsedFrame(frame=frame, eth=None, truncated=True)

    dst_mac = _mac(data[0:6])
    src_mac = _mac(data[6:12])
    outer_type = int.from_bytes(data[12:14], "big")
    ether_type = outer_type
    vlan_ids: list[int] = []
    offset = 12  # 当前 EtherType 的位置
    truncated = False

    while ether_type in VLAN_TYPES and len(vlan_ids) < MAX_VLAN_TAGS:
        if len(data) < offset + 6:
            # 有标签类型，但 TCI 或内层类型不完整
            truncated = True
            break
        tci = int.from_bytes(data[offset + 2:offset + 4], "big")
        vlan_ids.append(tci & 0x0FFF)
        ether_type = int.from_bytes(data[offset + 4:offset + 6], "big")
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
    return ParsedFrame(
        frame=frame,
        eth=eth,
        truncated=truncated,
        malformed=malformed,
    )
