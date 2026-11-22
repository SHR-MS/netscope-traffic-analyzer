"""TrafficStats 累加器测试。"""

from __future__ import annotations

import unittest

from netscope.core.models import Frame
from netscope.core.parser import parse_frame
from netscope.core.stats import TrafficStats

HEADER = bytes.fromhex("00112233445566778899aabb")


def frame(data: bytes, ts: float = 1.0) -> Frame:
    return Frame(ts=ts, caplen=len(data), origlen=len(data), data=data)


def eth_ipv4(total_length: int) -> bytes:
    payload = b"\x00" * (total_length - 20)
    total = total_length.to_bytes(2, "big")
    return HEADER + bytes.fromhex("0800") + b"\x45\x00" + total + b"\x00" * 16 + payload


class TrafficStatsTests(unittest.TestCase):
    def test_buckets_and_versions(self) -> None:
        stats = TrafficStats()
        stats.add(parse_frame(frame(eth_ipv4(40))))    # ≤46 → IPv4
        stats.add(parse_frame(frame(eth_ipv4(40))))
        stats.add(parse_frame(frame(eth_ipv4(100))))   # 47–1500
        stats.add(parse_frame(frame(eth_ipv4(1400))))
        # 非 IP：ARP 帧 60 字节 → 计入"其它"，长度按帧长
        arp = HEADER + bytes.fromhex("0806") + b"\x00" * 46
        stats.add(parse_frame(frame(arp)))

        snapshot = stats.snapshot()
        self.assertEqual(snapshot["buckets"], (2, 3, 0))
        self.assertEqual(snapshot["ip_versions"], (4, 0, 1))
        self.assertEqual(snapshot["total_packets"], 5)
        self.assertEqual(snapshot["length_hist"][40], 2)
        self.assertEqual(snapshot["length_hist"][60], 1)

    def test_over_1500(self) -> None:
        stats = TrafficStats()
        stats.add(parse_frame(frame(eth_ipv4(1500))))
        stats.add(parse_frame(frame(eth_ipv4(1501))))
        snapshot = stats.snapshot()
        self.assertEqual(snapshot["buckets"], (0, 1, 1))

    def test_reset(self) -> None:
        stats = TrafficStats()
        stats.add(parse_frame(frame(eth_ipv4(40))))
        stats.reset()
        snapshot = stats.snapshot()
        self.assertEqual(snapshot["total_packets"], 0)
        self.assertEqual(snapshot["buckets"], (0, 0, 0))
        self.assertEqual(snapshot["length_hist"], {})


if __name__ == "__main__":
    unittest.main()
