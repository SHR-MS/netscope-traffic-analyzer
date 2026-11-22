"""AlertEngine 异常检测测试：SYN 泛洪、ICMP 回声异常。"""

from __future__ import annotations

import struct
import unittest

from netscope.config import AlertConfig
from netscope.core.alerts import AlertEngine
from netscope.core.models import Frame
from netscope.core.parser import parse_frame

HEADER = bytes.fromhex("00112233445566778899aabb")


def make_frame(data: bytes, ts: float) -> Frame:
    return Frame(ts=ts, caplen=len(data), origlen=len(data), data=data)


def tcp_frame(sport: int, dport: int, flags: int, ts: float, dst: str = "192.168.1.50") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 100, 0, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
        __import__("socket").inet_aton("10.0.0.9"),
        __import__("socket").inet_aton(dst),
    )
    return HEADER + bytes.fromhex("0800") + ip + tcp


def icmp_frame(icmp_type: int, payload: bytes, ts: float, src: str = "10.0.0.9") -> bytes:
    icmp = struct.pack("!BBH", icmp_type, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(icmp), 1, 0x4000, 64, 1, 0,
        __import__("socket").inet_aton(src),
        __import__("socket").inet_aton("93.184.216.34"),
    )
    return HEADER + bytes.fromhex("0800") + ip + icmp


class SynFloodTests(unittest.TestCase):
    def test_flood_detected(self) -> None:
        engine = AlertEngine(AlertConfig(syn_min=50))
        alerts = []
        for index in range(60):
            alert = engine.ingest(parse_frame(make_frame(
                tcp_frame(20000 + index % 100, 80, 0x02, 10.0 + index / 100), 10.0 + index / 100)))
            if alert:
                alerts.append(alert)
        self.assertTrue(alerts)
        self.assertEqual(alerts[0]["rule"], "SYN_FLOOD")
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[0]["target"], "192.168.1.50:80")

    def test_synack_ratio_suppresses(self) -> None:
        # SYN 与 SYN-ACK 数量接近（正常握手），不应告警
        engine = AlertEngine(AlertConfig(syn_min=50, syn_ratio=3.0))
        alerts = []
        for index in range(50):
            flags = 0x02 if index % 2 == 0 else 0x12
            alert = engine.ingest(parse_frame(make_frame(
                tcp_frame(20000 + index % 100, 80, flags, 10.0 + index / 100), 10.0 + index / 100)))
            if alert:
                alerts.append(alert)
        self.assertEqual(alerts, [])

    def test_cooldown_suppresses_duplicate(self) -> None:
        engine = AlertEngine(AlertConfig(syn_min=50, cooldown_s=30.0))
        alerts = []
        for index in range(60):
            alert = engine.ingest(parse_frame(make_frame(
                tcp_frame(20000 + index % 100, 80, 0x02, 10.0 + index / 100), 10.0 + index / 100)))
            if alert:
                alerts.append(alert)
        self.assertEqual(len(alerts), 1)  # 冷却期内只报一次

        # 冷却期过后再次泛洪可再次告警
        for index in range(60):
            alert = engine.ingest(parse_frame(make_frame(
                tcp_frame(20000 + index % 100, 80, 0x02, 100.0 + index / 100), 100.0 + index / 100)))
            if alert:
                alerts.append(alert)
        self.assertEqual(len(alerts), 2)


class IcmpTests(unittest.TestCase):
    def test_echo_flood_detected(self) -> None:
        engine = AlertEngine(AlertConfig(icmp_min=30))
        alerts = []
        for index in range(40):
            alert = engine.ingest(parse_frame(make_frame(
                icmp_frame(8, b"ping", 10.0 + index / 100), 10.0 + index / 100)))
            if alert:
                alerts.append(alert)
        self.assertTrue(alerts)
        self.assertEqual(alerts[0]["rule"], "ICMP_ECHO_FLOOD")
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_orphan_reply_detected(self) -> None:
        engine = AlertEngine(AlertConfig(orphan_replies_min=10, orphan_requests_max=2))
        alerts = []
        for index in range(15):
            alert = engine.ingest(parse_frame(make_frame(
                icmp_frame(0, b"pong", 10.0 + index / 100), 10.0 + index / 100)))
            if alert:
                alerts.append(alert)
        self.assertTrue(alerts)
        self.assertEqual(alerts[0]["rule"], "ICMP_ORPHAN_REPLY")
        self.assertEqual(alerts[0]["severity"], "warning")

    def test_normal_reply_no_alert(self) -> None:
        # 有请求的应答不算异常
        engine = AlertEngine(AlertConfig())
        alerts = []
        for index in range(15):
            engine.ingest(parse_frame(make_frame(
                icmp_frame(8, b"ping", 10.0 + index / 100), 10.0 + index / 100)))
            alert = engine.ingest(parse_frame(make_frame(
                icmp_frame(0, b"pong", 10.0 + index / 100 + 0.01), 10.0 + index / 100 + 0.01)))
            if alert:
                alerts.append(alert)
        self.assertEqual(alerts, [])

    def test_big_echo_detected(self) -> None:
        engine = AlertEngine(AlertConfig(big_echo_bytes=800))
        alert = engine.ingest(parse_frame(make_frame(
            icmp_frame(8, b"x" * 900, 10.0), 10.0)))
        self.assertIsNotNone(alert)
        assert alert is not None
        self.assertEqual(alert["rule"], "ICMP_BIG_ECHO")
        self.assertEqual(alert["severity"], "info")

    def test_small_echo_no_alert(self) -> None:
        engine = AlertEngine(AlertConfig(big_echo_bytes=800))
        alert = engine.ingest(parse_frame(make_frame(
            icmp_frame(8, b"ping", 10.0), 10.0)))
        self.assertIsNone(alert)


if __name__ == "__main__":
    unittest.main()
