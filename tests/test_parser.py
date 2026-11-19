"""链路层解析与界面行构造的单元测试。"""

from __future__ import annotations

import unittest

from netscope.core.models import Frame
from netscope.core.parser import ether_type_name, parse_frame
from netscope.ui.packet_rows import build_packet_row

HEADER = bytes.fromhex("00112233445566778899aabb")


def make_frame(data: bytes, ts: float = 1.0) -> Frame:
    return Frame(ts=ts, caplen=len(data), origlen=len(data), data=data)


class LinkParserTests(unittest.TestCase):
    def test_basic_ethernet(self) -> None:
        data = HEADER + (0x0800).to_bytes(2, "big") + b"\x45" + b"\x00" * 19
        parsed = parse_frame(make_frame(data))

        self.assertIsNotNone(parsed.eth)
        eth = parsed.eth
        assert eth is not None
        self.assertEqual(eth.dst_mac, "00:11:22:33:44:55")
        self.assertEqual(eth.src_mac, "66:77:88:99:aa:bb")
        self.assertEqual(eth.outer_type, 0x0800)
        self.assertEqual(eth.ether_type, 0x0800)
        self.assertEqual(eth.vlan_ids, ())
        self.assertEqual(eth.payload_offset, 14)
        self.assertFalse(parsed.truncated)
        self.assertEqual(parsed.protocol, "IPv4")
        self.assertEqual(parsed.ip_version, 4)

    def test_single_vlan(self) -> None:
        data = HEADER + (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
        data += (0x0800).to_bytes(2, "big") + b"\x45" + b"\x00" * 19
        parsed = parse_frame(make_frame(data))

        eth = parsed.eth
        assert eth is not None
        self.assertEqual(eth.outer_type, 0x8100)
        self.assertEqual(eth.ether_type, 0x0800)
        self.assertEqual(eth.vlan_ids, (100,))
        self.assertEqual(eth.payload_offset, 18)

    def test_qinq(self) -> None:
        data = HEADER + (0x88A8).to_bytes(2, "big") + (200).to_bytes(2, "big")
        data += (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
        data += (0x86DD).to_bytes(2, "big") + b"\x60" + b"\x00" * 39
        parsed = parse_frame(make_frame(data))

        eth = parsed.eth
        assert eth is not None
        self.assertEqual(eth.outer_type, 0x88A8)
        self.assertEqual(eth.ether_type, 0x86DD)
        self.assertEqual(eth.vlan_ids, (200, 100))
        self.assertEqual(eth.payload_offset, 22)
        self.assertEqual(parsed.ip_version, 6)

    def test_unknown_ether_type(self) -> None:
        data = HEADER + (0x88CC).to_bytes(2, "big") + b"\x00" * 10
        parsed = parse_frame(make_frame(data))

        self.assertEqual(parsed.protocol, "LLDP")
        self.assertEqual(parsed.ip_version, 0)
        self.assertEqual(ether_type_name(0x1234), "0x1234")

    def test_truncated_ethernet(self) -> None:
        parsed = parse_frame(make_frame(b"\x00" * 10))
        self.assertIsNone(parsed.eth)
        self.assertTrue(parsed.truncated)
        self.assertEqual(parsed.protocol, "截断")

    def test_truncated_vlan_header(self) -> None:
        data = HEADER + (0x8100).to_bytes(2, "big") + b"\x00\x64"
        parsed = parse_frame(make_frame(data))
        eth = parsed.eth
        assert eth is not None
        self.assertTrue(parsed.truncated)
        self.assertEqual(eth.vlan_ids, ())
        self.assertEqual(eth.ether_type, 0x8100)

    def test_exact_header_no_payload(self) -> None:
        data = HEADER + (0x0800).to_bytes(2, "big")
        parsed = parse_frame(make_frame(data))
        eth = parsed.eth
        assert eth is not None
        self.assertFalse(parsed.truncated)
        self.assertEqual(eth.payload_offset, 14)


class PacketRowTests(unittest.TestCase):
    def test_row_from_ethernet(self) -> None:
        data = HEADER + (0x0800).to_bytes(2, "big") + b"\x45" + b"\x00" * 19
        row = build_packet_row(parse_frame(make_frame(data)), 7)

        self.assertEqual(row.seq, 7)
        self.assertEqual(row.protocol, "IPv4")
        self.assertEqual(row.version, 4)
        self.assertEqual(row.src, "66:77:88:99:aa:bb")
        self.assertEqual(row.dst, "00:11:22:33:44:55")
        self.assertEqual(row.length, len(data))
        self.assertIn("数据链路层", row.layers[0][0])
        self.assertEqual(row.layers[1][1][0], ("状态", "待解析（阶段 2）"))

    def test_row_with_vlan(self) -> None:
        data = HEADER + (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
        data += (0x0800).to_bytes(2, "big") + b"\x45" + b"\x00" * 19
        row = build_packet_row(parse_frame(make_frame(data)), 1)

        link = dict(row.layers[0][1])
        self.assertEqual(link["VLAN ID"], "100")
        self.assertIn("VLAN 100", row.info)

    def test_row_truncated(self) -> None:
        row = build_packet_row(parse_frame(make_frame(b"\x00" * 10)), 2)
        self.assertEqual(row.protocol, "截断")
        self.assertTrue(row.info.startswith("截断帧"))
        self.assertEqual(row.src, "—")


if __name__ == "__main__":
    unittest.main()
