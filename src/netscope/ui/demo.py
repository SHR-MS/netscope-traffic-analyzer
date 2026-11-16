"""演示数据源：让界面在没有接抓包后端时也能看到效果。

重要：这里的数据全部是伪造的，仅用于展示界面与交互。
真实实现请继承 :class:`CaptureController`，把解析结果按同样的结构发出来。
"""

from __future__ import annotations

import random
import socket
import struct
import time
from collections import deque

from PySide6.QtCore import QTimer

from .controller import CaptureController, DeviceOption
from .models import PacketRow

CLIENT_MAC = "3c:52:82:1a:2b:3c"
GATEWAY_MAC = "a4:5e:60:de:f0:11"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CLIENT_IP = "192.168.1.23"
SERVER_IP = "93.184.216.34"
GATEWAY_IP = "192.168.1.1"
CLIENT_IP6 = "2001:db8::23"
DNS_IP6 = "2001:4860:4860::8888"

TCP_FLAGS = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08), ("ACK", 0x10)]
FLAG_DISPLAY = [("SYN", 0x02), ("ACK", 0x10), ("FIN", 0x01), ("RST", 0x04)]


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _flags_text(flags: int) -> str:
    return " ".join(f"{name}={1 if flags & bit else 0}" for name, bit in FLAG_DISPLAY)


def _eth(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, protocol: int, payload: bytes, ttl: int = 64) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        random.randint(1, 65535),
        0x4000,
        ttl,
        protocol,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + payload


def _ipv6(src: str, dst: str, next_header: int, payload: bytes, hop_limit: int = 64) -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        hop_limit,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    )
    return header + payload


def _tcp(sport: int, dport: int, flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return header + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp(icmp_type: int, code: int, payload: bytes) -> bytes:
    return struct.pack("!BBH", icmp_type, code, 0) + payload


def _layers_eth(dst_mac: str, src_mac: str, type_text: str):
    return [
        ("目的 MAC", dst_mac),
        ("源 MAC", src_mac),
        ("类型", type_text),
    ]


def _layers_ipv4(src: str, dst: str, protocol: int, ttl: int = 64):
    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, str(protocol))
    return [
        ("版本", "4"),
        ("源 IP", src),
        ("目的 IP", dst),
        ("TTL", str(ttl)),
        ("协议号", f"{protocol} ({proto_name})"),
    ]


def _layers_tcp(sport: int, dport: int, flags: int, seq: int = 0, ack: int = 0):
    # 只保留需求要求的关键字段；序号/确认号属于附加信息，默认不展开
    return [
        ("源端口", str(sport)),
        ("目的端口", str(dport)),
        ("标志位", _flags_text(flags)),
    ]


class DemoController(CaptureController):
    """生成假报文的控制器，接口与真实后端一致。"""

    demo = True

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._running = False
        self._seq = 0
        self._received = 0
        self._hist: dict[int, int] = {}
        self._versions = [0, 0, 0]
        self._recent: deque[tuple[float, int]] = deque()
        self._started_at = time.time()

        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(240)
        self._tick_timer.timeout.connect(self._tick)

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(500)
        self._stats_timer.timeout.connect(self._emit_stats)

        self._alert_timer = QTimer(self)
        self._alert_timer.setInterval(13000)
        self._alert_timer.timeout.connect(self._emit_alert)

        self._alert_rules = [
            ("SYN_FLOOD", "critical", "192.168.1.50:80", "SYN 620/s，SYN-ACK 12/s"),
            ("ICMP_ECHO_FLOOD", "critical", "192.168.1.88", "echo request 340/s"),
            ("ICMP_ORPHAN_REPLY", "warning", "10.0.0.6", "5 秒内 37 条无请求 reply"),
            ("ICMP_BIG_ECHO", "info", "192.168.1.77", "载荷 1400 B，MF=1"),
        ]

    # ---------------------------------------------------------------- 设备
    def list_devices(self) -> list[DeviceOption]:
        return [
            DeviceOption("demo-eth", "以太网 2（演示）"),
            DeviceOption("demo-wlan", "WLAN（演示）"),
            DeviceOption("demo-loop", "Npcap Loopback（演示）"),
        ]

    # ---------------------------------------------------------------- 启停
    def start(self, device_key: str, bpf: str = "") -> None:
        if self._running:
            return
        self._reset()
        self._running = True
        self.state_changed.emit("running", f"抓包中（演示数据）：{device_key}")
        self._tick_timer.start()
        self._stats_timer.start()
        self._alert_timer.start()
        self._emit_stats()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._tick_timer.stop()
        self._stats_timer.stop()
        self._alert_timer.stop()
        self.state_changed.emit("idle", "已停止")
        self._emit_stats()

    def shutdown(self) -> None:
        self.stop()

    # ---------------------------------------------------------------- 文件
    def save_as(self, path: str) -> None:
        raise NotImplementedError("演示模式不支持保存")

    def open_file(self, path: str) -> None:
        raise NotImplementedError("演示模式不支持打开文件")

    # ---------------------------------------------------------------- 内部
    def _reset(self) -> None:
        self._seq = 0
        self._received = 0
        self._hist.clear()
        self._versions = [0, 0, 0]
        self._recent.clear()
        self._started_at = time.time()

    def _tick(self) -> None:
        rows = []
        for _ in range(random.randint(1, 4)):
            self._seq += 1
            rows.append(self._make_row(self._seq))
        if rows:
            self.packets_received.emit(rows)
            # 演示数据每批都刷新统计，避免状态栏"包数"落后于列表
            self._emit_stats()

    def _endpoints(self, kind: str) -> tuple[str, str]:
        if kind == "synack":
            return SERVER_IP, CLIENT_IP
        if kind == "icmp":
            return GATEWAY_IP, SERVER_IP
        if kind == "arp":
            return CLIENT_IP, GATEWAY_IP
        if kind == "ipv6":
            return CLIENT_IP6, DNS_IP6
        return CLIENT_IP, SERVER_IP

    def _make_row(self, seq: int) -> PacketRow:
        kind = random.choices(
            ["syn", "synack", "ack", "http", "dns", "icmp", "arp", "ipv6"],
            weights=[18, 12, 30, 10, 10, 8, 7, 5],
        )[0]
        raw, protocol, length, info, version, layers = self._build(kind)
        src, dst = self._endpoints(kind)

        now = time.time()
        self._received += 1
        self._hist[length] = self._hist.get(length, 0) + 1
        self._versions[0 if version == 4 else 1 if version == 6 else 2] += 1
        self._recent.append((now, length))
        while self._recent and now - self._recent[0][0] > 1.0:
            self._recent.popleft()

        return PacketRow(
            seq=seq,
            ts=now,
            src=src,
            dst=dst,
            protocol=protocol,
            length=length,
            info=info,
            raw=raw,
            layers=layers,
            version=version,
        )

    def _build(self, kind: str):
        if kind == "syn":
            seq = random.randint(1000, 9000)
            tcp = _tcp(51432, 443, 0x02, seq, 0)
            raw = _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800, _ipv4(CLIENT_IP, SERVER_IP, 6, tcp))
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(GATEWAY_MAC, CLIENT_MAC, "IPv4 (0x0800)")),
                ("网络层（IPv4）", _layers_ipv4(CLIENT_IP, SERVER_IP, 6)),
                ("传输层（TCP）", _layers_tcp(51432, 443, 0x02, seq)),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            return raw, "TCP", 40, f"51432 → 443 [SYN] Seq={seq} Len=0", 4, layers

        if kind == "synack":
            tcp = _tcp(443, 51432, 0x12, 0, 1001)
            raw = _eth(CLIENT_MAC, GATEWAY_MAC, 0x0800, _ipv4(SERVER_IP, CLIENT_IP, 6, tcp))
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(CLIENT_MAC, GATEWAY_MAC, "IPv4 (0x0800)")),
                ("网络层（IPv4）", _layers_ipv4(SERVER_IP, CLIENT_IP, 6)),
                ("传输层（TCP）", _layers_tcp(443, 51432, 0x12, 0, 1001)),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            return raw, "TCP", 40, "443 → 51432 [SYN, ACK] Seq=0 Ack=1001 Len=0", 4, layers

        if kind == "ack":
            tcp = _tcp(51432, 443, 0x10, 1001, 1)
            raw = _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800, _ipv4(CLIENT_IP, SERVER_IP, 6, tcp))
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(GATEWAY_MAC, CLIENT_MAC, "IPv4 (0x0800)")),
                ("网络层（IPv4）", _layers_ipv4(CLIENT_IP, SERVER_IP, 6)),
                ("传输层（TCP）", _layers_tcp(51432, 443, 0x10, 1001, 1)),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            return raw, "TCP", 40, "51432 → 443 [ACK] Seq=1001 Ack=1 Len=0", 4, layers

        if kind == "http":
            payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            tcp = _tcp(51432, 443, 0x18, 1001, 1, payload)
            raw = _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800, _ipv4(CLIENT_IP, SERVER_IP, 6, tcp))
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(GATEWAY_MAC, CLIENT_MAC, "IPv4 (0x0800)")),
                ("网络层（IPv4）", _layers_ipv4(CLIENT_IP, SERVER_IP, 6)),
                ("传输层（TCP）", _layers_tcp(51432, 443, 0x18, 1001, 1)),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            info = f"51432 → 443 [PSH, ACK] Seq=1001 Ack=1 Len={len(payload)}"
            return raw, "TCP", 20 + len(tcp), info, 4, layers

        if kind == "dns":
            payload = (
                b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01"
            )
            udp = _udp(53012, 53, payload)
            raw = _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800, _ipv4(CLIENT_IP, SERVER_IP, 17, udp))
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(GATEWAY_MAC, CLIENT_MAC, "IPv4 (0x0800)")),
                ("网络层（IPv4）", _layers_ipv4(CLIENT_IP, SERVER_IP, 17)),
                ("传输层（UDP）", [("源端口", "53012"), ("目的端口", "53"), ("长度", str(8 + len(payload)))]),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            return raw, "UDP", 20 + len(udp), "53012 → 53 Standard query A example.com", 4, layers

        if kind == "icmp":
            payload = b"abcdefghijklmnopqrstuvwxyz012345"
            icmp = _icmp(8, 0, payload)
            raw = _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800, _ipv4(GATEWAY_IP, SERVER_IP, 1, icmp))
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(GATEWAY_MAC, CLIENT_MAC, "IPv4 (0x0800)")),
                ("网络层（IPv4）", _layers_ipv4(GATEWAY_IP, SERVER_IP, 1)),
                ("传输层（ICMP）", [("类型", "8 (Echo Request)"), ("代码", "0"), ("端口", "不适用")]),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            return raw, "ICMP", 20 + len(icmp), "Echo (ping) request id=0x0001 seq=1 ttl=64", 4, layers

        if kind == "arp":
            arp = struct.pack(
                "!HHBBH6s4s6s4s",
                1,
                0x0800,
                6,
                4,
                1,
                _mac(CLIENT_MAC),
                socket.inet_aton(CLIENT_IP),
                b"\x00" * 6,
                socket.inet_aton(GATEWAY_IP),
            )
            raw = _eth(BROADCAST_MAC, CLIENT_MAC, 0x0806, arp)
            layers = [
                ("数据链路层（Ethernet II）", _layers_eth(BROADCAST_MAC, CLIENT_MAC, "ARP (0x0806)")),
                ("网络层", [("类型", "ARP"), ("说明", "IPv4 地址解析")]),
                ("传输层", [("说明", "不适用")]),
                ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
            ]
            return raw, "ARP", len(raw), "Who has 192.168.1.1? Tell 192.168.1.23", 0, layers

        # ipv6 DNS
        payload = (
            b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x1c\x00\x01"
        )
        udp = _udp(53013, 53, payload)
        raw = _eth(GATEWAY_MAC, CLIENT_MAC, 0x86DD, _ipv6(CLIENT_IP6, DNS_IP6, 17, udp))
        layers = [
            ("数据链路层（Ethernet II）", _layers_eth(GATEWAY_MAC, CLIENT_MAC, "IPv6 (0x86DD)")),
            (
                "网络层（IPv6）",
                [
                    ("版本", "6"),
                    ("源 IP", CLIENT_IP6),
                    ("目的 IP", DNS_IP6),
                    ("跳数限制", "64"),
                    ("协议号", "17 (UDP)"),
                ],
            ),
            ("传输层（UDP）", [("源端口", "53013"), ("目的端口", "53"), ("长度", str(8 + len(payload)))]),
            ("附加信息", [("帧长", f"{len(raw)} B"), ("抓包长度", f"{len(raw)} B")]),
        ]
        return raw, "UDP", 40 + len(udp), "53013 → 53 Standard query AAAA example.com", 6, layers

    def _emit_stats(self) -> None:
        now = time.time()
        while self._recent and now - self._recent[0][0] > 1.0:
            self._recent.popleft()

        buckets = [
            sum(count for length, count in self._hist.items() if length <= 46),
            sum(count for length, count in self._hist.items() if 46 < length <= 1500),
            sum(count for length, count in self._hist.items() if length > 1500),
        ]
        pps = float(len(self._recent))
        mbps = sum(size for _, size in self._recent) * 8 / 1_000_000

        self.stats_updated.emit(
            {
                "received": self._received,
                "displayed": self._received,
                "dropped": 0,
                "pps": pps,
                "mbps": mbps,
                "uptime_s": time.time() - self._started_at,
                "length_hist": dict(self._hist),
                "buckets": tuple(buckets),
                "ip_versions": tuple(self._versions),
            }
        )

    def _emit_alert(self) -> None:
        if not self._running:
            return
        rule, severity, target, evidence = random.choice(self._alert_rules)
        self.alert_raised.emit(
            {
                "time": time.time(),
                "rule": rule,
                "severity": severity,
                "target": target,
                "evidence": evidence,
                "count": 1,
            }
        )
