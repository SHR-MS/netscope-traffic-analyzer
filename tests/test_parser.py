"""链路层 / 网络层 / 传输层解析与界面行构造的单元测试。"""

from __future__ import annotations

import struct
import unittest

from netscope.core.models import Frame
from netscope.core.parser import ether_type_name, parse_frame
from netscope.ui.packet_rows import build_packet_row

HEADER = bytes.fromhex("00112233445566778899aabb")


def make_frame(data: bytes, ts: float = 1.0) -> Frame:
    return Frame(ts=ts, caplen=len(data), origlen=len(data), data=data)


def eth(payload: bytes, ether_type: int = 0x0800) -> bytes:
    return HEADER + ether_type.to_bytes(2, "big") + payload


def ipv4(src: str, dst: str, protocol: int, payload: bytes,
         ttl: int = 64, total_length: int | None = None,
         flags_frag: int = 0x4000, ihl: int = 5) -> bytes:
    total = 20 + len(payload) if total_length is None else total_length
    return struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl, 0, total, 0x1234, flags_frag, ttl, protocol, 0,
        __import__("socket").inet_aton(src),
        __import__("socket").inet_aton(dst),
    ) + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    import socket
    return struct.pack(
        "!IHBB16s16s",
        6 << 28, len(payload), next_header, hop_limit,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    ) + payload


def tcp(sport: int, dport: int, flags: int, seq: int = 100, ack: int = 0) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(icmp_type: int, code: int, payload: bytes = b"") -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + payload


class LinkParserTests(unittest.TestCase):
    def test_basic_ethernet(self) -> None:
        data = eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1234, 80, 0x02)))
        parsed = parse_frame(make_frame(data))

        self.assertIsNotNone(parsed.eth)
        eth_info = parsed.eth
        assert eth_info is not None
        self.assertEqual(eth_info.dst_mac, "00:11:22:33:44:55")
        self.assertEqual(eth_info.src_mac, "66:77:88:99:aa:bb")
        self.assertEqual(eth_info.outer_type, 0x0800)
        self.assertEqual(eth_info.ether_type, 0x0800)
        self.assertEqual(eth_info.vlan_ids, ())
        self.assertEqual(eth_info.payload_offset, 14)
        self.assertFalse(parsed.truncated)
        self.assertEqual(parsed.protocol, "TCP")
        self.assertEqual(parsed.ip_version, 4)
        self.assertEqual(parsed.ip_length, 40)
        self.assertEqual(parsed.src_ip, "10.0.0.1")
        self.assertEqual(parsed.dst_ip, "10.0.0.2")

    def test_single_vlan(self) -> None:
        data = HEADER + (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
        data += (0x0800).to_bytes(2, "big") + ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 0x10))
        parsed = parse_frame(make_frame(data))

        eth_info = parsed.eth
        assert eth_info is not None
        self.assertEqual(eth_info.outer_type, 0x8100)
        self.assertEqual(eth_info.ether_type, 0x0800)
        self.assertEqual(eth_info.vlan_ids, (100,))
        self.assertEqual(eth_info.payload_offset, 18)
        self.assertEqual(parsed.ip_version, 4)

    def test_qinq(self) -> None:
        data = HEADER + (0x88A8).to_bytes(2, "big") + (200).to_bytes(2, "big")
        data += (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
        data += (0x86DD).to_bytes(2, "big") + ipv6("2001:db8::1", "2001:db8::2", 59, b"")
        parsed = parse_frame(make_frame(data))

        eth_info = parsed.eth
        assert eth_info is not None
        self.assertEqual(eth_info.outer_type, 0x88A8)
        self.assertEqual(eth_info.ether_type, 0x86DD)
        self.assertEqual(eth_info.vlan_ids, (200, 100))
        self.assertEqual(eth_info.payload_offset, 22)
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
        eth_info = parsed.eth
        assert eth_info is not None
        self.assertTrue(parsed.truncated)
        self.assertEqual(eth_info.vlan_ids, ())
        self.assertEqual(eth_info.ether_type, 0x8100)

    def test_truncated_ip_header(self) -> None:
        data = eth(b"\x45\x00\x00")  # 只有 3 字节 IP 头
        parsed = parse_frame(make_frame(data))
        self.assertIsNone(parsed.ipv4)
        self.assertTrue(parsed.truncated)
        self.assertEqual(parsed.protocol, "IPv4")


class NetworkParserTests(unittest.TestCase):
    def test_ipv4_tcp(self) -> None:
        data = eth(ipv4("192.168.1.23", "93.184.216.34", 6, tcp(51432, 443, 0x02)))
        parsed = parse_frame(make_frame(data))

        ip = parsed.ipv4
        assert ip is not None
        self.assertEqual(ip.version, 4)
        self.assertEqual(ip.src, "192.168.1.23")
        self.assertEqual(ip.dst, "93.184.216.34")
        self.assertEqual(ip.ttl, 64)
        self.assertEqual(ip.protocol, 6)
        self.assertEqual(ip.total_length, 40)
        self.assertFalse(ip.fragmented)

        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "TCP")
        self.assertEqual(transport.sport, 51432)
        self.assertEqual(transport.dport, 443)
        self.assertTrue(transport.tcp_syn)
        self.assertFalse(transport.tcp_ack)
        self.assertEqual(parsed.protocol, "TCP")

    def test_ipv4_options_are_skipped(self) -> None:
        # IHL=6（24 字节头），选项 4 字节
        header = struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | 6, 0, 20 + 4 + 20, 0x1234, 0x4000, 64, 6, 0,
            __import__("socket").inet_aton("1.1.1.1"),
            __import__("socket").inet_aton("2.2.2.2"),
        ) + b"\x01\x01\x01\x01"
        data = eth(header + tcp(8080, 80, 0x10))
        parsed = parse_frame(make_frame(data))

        ip = parsed.ipv4
        transport = parsed.transport
        assert ip is not None and transport is not None
        self.assertEqual(ip.ihl, 24)
        self.assertEqual(transport.sport, 8080)  # 没把选项当端口读
        self.assertEqual(transport.dport, 80)

    def test_ipv4_udp(self) -> None:
        data = eth(ipv4("10.0.0.1", "10.0.0.53", 17, udp(53012, 53, b"\x01\x02")))
        parsed = parse_frame(make_frame(data))

        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "UDP")
        self.assertEqual(transport.sport, 53012)
        self.assertEqual(transport.dport, 53)
        self.assertEqual(parsed.ip_length, 20 + 8 + 2)

    def test_ipv4_icmp(self) -> None:
        data = eth(ipv4("192.168.1.1", "93.184.216.34", 1, icmp(8, 0, b"ping")))
        parsed = parse_frame(make_frame(data))

        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "ICMP")
        self.assertEqual(transport.icmp_type, 8)
        self.assertTrue(transport.is_echo_request)

    def test_ipv4_fragment_no_transport(self) -> None:
        # 非首片：片偏移 1480，没有传输层头
        data = eth(ipv4("10.0.0.1", "10.0.0.2", 6, b"", flags_frag=0x2000 | (1480 // 8)))
        parsed = parse_frame(make_frame(data))

        ip = parsed.ipv4
        assert ip is not None
        self.assertTrue(ip.fragmented)
        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "IPv4 分片")
        self.assertIsNone(transport.sport)

    def test_ipv6_udp(self) -> None:
        data = eth(
            ipv6("2001:db8::23", "2001:4860:4860::8888", 17, udp(53013, 53, b"")),
            0x86DD,
        )
        parsed = parse_frame(make_frame(data))

        ip = parsed.ipv6
        assert ip is not None
        self.assertEqual(ip.version, 6)
        self.assertEqual(ip.src, "2001:db8::23")
        self.assertEqual(ip.hop_limit, 64)
        self.assertEqual(ip.next_header, 17)
        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "UDP")
        self.assertEqual(parsed.ip_length, 40 + 8)
        self.assertEqual(parsed.ip_version, 6)

    def test_ipv6_hop_by_hop_extension(self) -> None:
        # 逐跳扩展头 8 字节：next=17, len=0 → 8 字节；其后是 UDP
        ext = bytes([17, 0]) + b"\x00" * 6
        data = eth(ipv6("::1", "::2", 0, ext + udp(5353, 5353, b"")), 0x86DD)
        parsed = parse_frame(make_frame(data))

        ip = parsed.ipv6
        assert ip is not None
        self.assertIn("逐跳选项", ip.extension_headers)
        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "UDP")
        self.assertEqual(transport.sport, 5353)

    def test_ipv6_fragment_no_ports(self) -> None:
        # 分片头：next=17, 偏移>0 → 不应解析端口
        frag = struct.pack("!BBHI", 17, 0, (8 // 8) << 3, 0x12345678)
        data = eth(ipv6("::1", "::2", 44, frag + b"\x00" * 8), 0x86DD)
        parsed = parse_frame(make_frame(data))

        ip = parsed.ipv6
        assert ip is not None
        self.assertTrue(ip.fragmented)
        self.assertEqual(ip.fragment_offset, 8)
        transport = parsed.transport
        assert transport is not None
        self.assertEqual(transport.name, "IPv6 分片")
        self.assertIsNone(transport.sport)

    def test_ipv4_bad_version(self) -> None:
        data = eth(b"\x60" + b"\x00" * 19)  # EtherType IPv4 但版本号是 6
        parsed = parse_frame(make_frame(data))
        self.assertIsNone(parsed.ipv4)
        self.assertTrue(parsed.malformed)


class PacketRowTests(unittest.TestCase):
    def test_row_tcp(self) -> None:
        data = eth(ipv4("192.168.1.23", "93.184.216.34", 6, tcp(51432, 443, 0x02)))
        row = build_packet_row(parse_frame(make_frame(data)), 7)

        self.assertEqual(row.seq, 7)
        self.assertEqual(row.protocol, "TCP")
        self.assertEqual(row.version, 4)
        self.assertEqual(row.src, "192.168.1.23")
        self.assertEqual(row.dst, "93.184.216.34")
        self.assertEqual(row.length, 40)  # IP 分组长度主口径
        self.assertIn("51432 → 443", row.info)
        self.assertIn("[SYN]", row.info)

        self.assertEqual(row.layers[0][0], "数据链路层（Ethernet II）")
        self.assertEqual(row.layers[1][0], "网络层（IPv4）")
        self.assertEqual(row.layers[2][0], "传输层（TCP）")

        network = dict(row.layers[1][1])
        self.assertEqual(network["版本"], "4")
        self.assertEqual(network["源 IP"], "192.168.1.23")
        self.assertEqual(network["TTL"], "64")
        self.assertEqual(network["协议号"], "6 (TCP)")

        transport = dict(row.layers[2][1])
        self.assertEqual(transport["源端口"], "51432")
        self.assertEqual(transport["目的端口"], "443")
        self.assertEqual(transport["标志位"], "SYN=1 ACK=0 FIN=0 RST=0")

    def test_row_udp_flags_text(self) -> None:
        data = eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp(1, 2, 0x12)))  # SYN+ACK
        row = build_packet_row(parse_frame(make_frame(data)), 1)
        transport = dict(row.layers[2][1])
        self.assertEqual(transport["标志位"], "SYN=1 ACK=1 FIN=0 RST=0")

    def test_row_arp_uses_mac(self) -> None:
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1,
                          bytes.fromhex("3c52821a2b3c"),
                          bytes.fromhex("c0a80117"),
                          b"\x00" * 6,
                          bytes.fromhex("c0a80101"))
        data = eth(arp, 0x0806)
        row = build_packet_row(parse_frame(make_frame(data)), 3)

        self.assertEqual(row.protocol, "ARP")
        self.assertEqual(row.version, 0)
        self.assertEqual(row.src, "66:77:88:99:aa:bb")
        network = dict(row.layers[1][1])
        self.assertEqual(network["类型"], "ARP")

    def test_row_with_vlan(self) -> None:
        data = HEADER + (0x8100).to_bytes(2, "big") + (100).to_bytes(2, "big")
        data += (0x0800).to_bytes(2, "big") + ipv4("1.1.1.1", "2.2.2.2", 6, tcp(1, 2, 0x10))
        row = build_packet_row(parse_frame(make_frame(data)), 1)

        link = dict(row.layers[0][1])
        self.assertEqual(link["VLAN ID"], "100")
        self.assertIn("VLAN 100", row.info)

    def test_row_truncated(self) -> None:
        row = build_packet_row(parse_frame(make_frame(b"\x00" * 10)), 2)
        self.assertEqual(row.protocol, "截断")
        self.assertTrue(row.info.startswith("截断帧"))
        self.assertEqual(row.src, "—")

    def test_row_icmp_ports_na(self) -> None:
        data = eth(ipv4("10.0.0.1", "10.0.0.2", 1, icmp(8, 0)))
        row = build_packet_row(parse_frame(make_frame(data)), 1)
        transport = dict(row.layers[2][1])
        self.assertEqual(transport["端口"], "不适用")
        self.assertIn("Echo", row.info)


if __name__ == "__main__":
    unittest.main()
