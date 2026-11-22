"""演示数据源：让界面在没有接真实后端时也能看到完整效果。

说明：这里的报文是伪造的，但全部是**结构合法的真实字节**，走与真实抓包
完全相同的链路（parse_frame → TrafficStats → AlertEngine → build_packet_row），
因此列表、详情树、统计图表与告警的行为与真实抓包一致。

除普通流量外，每 30 秒轮换演示一次异常场景（SYN 泛洪 / ICMP 回声泛洪 /
无请求应答 / 大包回声），让告警面板能看到真实检测引擎的判定。
"""

from __future__ import annotations

import random
import socket
import struct
import time
from collections import deque
from pathlib import Path

from PySide6.QtCore import QTimer

from ..config import AlertConfig
from ..core.alerts import AlertEngine
from ..core.models import Frame
from ..core.parser import parse_frame
from ..core.pcapio import PcapError, PcapWriter, read_frames
from ..core.stats import TrafficStats
from .controller import CaptureController, DeviceOption
from .packet_rows import build_packet_row

CLIENT_MAC = "3c:52:82:1a:2b:3c"
GATEWAY_MAC = "a4:5e:60:de:f0:11"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CLIENT_IP = "192.168.1.23"
SERVER_IP = "93.184.216.34"
GATEWAY_IP = "192.168.1.1"
FLOOD_TARGET = "192.168.1.50"
CLIENT_IP6 = "2001:db8::23"
DNS_IP6 = "2001:4860:4860::8888"

BURST_INTERVAL_MS = 30000      # 每 30 秒演示一种异常
MAX_DEMO_FRAMES = 50_000       # 演示模式内存里保留的帧数上限


def _mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def _eth(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


def _ipv4(src: str, dst: str, protocol: int, payload: bytes,
          ttl: int = 64, flags: int = 0x4000) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        random.randint(1, 65535),
        flags,
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


class DemoController(CaptureController):
    """生成合法字节流并走真实解析/统计/告警链路的演示控制器。"""

    demo = True

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._running = False
        self._seq = 0
        self._stats = TrafficStats()
        self._alerts = AlertEngine(AlertConfig())
        self._frames: list[Frame] = []
        self._recent: deque[tuple[float, int]] = deque()
        self._started_at = time.time()

        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(240)
        self._tick_timer.timeout.connect(self._tick)

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(500)
        self._stats_timer.timeout.connect(self._emit_stats)

        # 异常演示：每 30 秒轮换一种
        self._burst_timer = QTimer(self)
        self._burst_timer.setInterval(BURST_INTERVAL_MS)
        self._burst_timer.timeout.connect(self._begin_burst)

        self._burst_tick = QTimer(self)
        self._burst_tick.setInterval(8)
        self._burst_tick.timeout.connect(self._burst_step)

        self._burst_kinds = ["syn_flood", "icmp_flood", "orphan_reply", "big_echo"]
        self._burst_index = 0
        self._burst_remaining = 0
        self._burst_builder = None

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
        self._burst_timer.start()
        self._emit_stats()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._tick_timer.stop()
        self._stats_timer.stop()
        self._burst_timer.stop()
        self._burst_tick.stop()
        self.state_changed.emit("idle", "已停止（演示数据未落盘）")
        self._emit_stats()

    def shutdown(self) -> None:
        self.stop()

    # ---------------------------------------------------------------- 文件
    def save_as(self, path: str) -> None:
        if not self._frames:
            raise PcapError("演示会话还没有数据，无可保存内容")
        writer = PcapWriter(path)
        try:
            for frame in self._frames:
                writer.write(frame)
        finally:
            writer.close()

    def open_file(self, path: str) -> None:
        self.stop()
        frames = read_frames(path)
        self._reset()
        self._running = False
        rows = []
        for frame in frames:
            rows.append(self._process(frame, count_frame=True))
        if rows:
            self.packets_received.emit(rows)
        self._emit_stats()
        self.state_changed.emit("idle", f"已打开 {Path(path).name}（{len(rows)} 个报文）")

    # ---------------------------------------------------------------- 内部
    def _reset(self) -> None:
        self._seq = 0
        self._stats.reset()
        self._alerts.reset()
        self._frames.clear()
        self._recent.clear()
        self._started_at = time.time()

    def _tick(self) -> None:
        rows = []
        for _ in range(random.randint(1, 4)):
            self._seq += 1
            rows.append(self._process(self._to_frame(self._make_packet()), count_frame=True))
        if rows:
            self.packets_received.emit(rows)
            self._emit_stats()

    # ---------------------------------------------------------------- 报文
    def _make_packet(self) -> bytes:
        kind = random.choices(
            ["syn", "synack", "ack", "http", "dns", "icmp", "arp", "ipv6"],
            weights=[18, 12, 30, 10, 10, 4, 7, 5],
        )[0]
        if kind == "syn":
            return _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800,
                        _ipv4(CLIENT_IP, SERVER_IP, 6,
                              _tcp(51432, 443, 0x02, random.randint(1000, 9000), 0)))
        if kind == "synack":
            return _eth(CLIENT_MAC, GATEWAY_MAC, 0x0800,
                        _ipv4(SERVER_IP, CLIENT_IP, 6,
                              _tcp(443, 51432, 0x12, random.randint(1000, 9000), 1001)))
        if kind == "ack":
            return _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800,
                        _ipv4(CLIENT_IP, SERVER_IP, 6,
                              _tcp(51432, 443, 0x10, 1001, 1)))
        if kind == "http":
            payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            return _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800,
                        _ipv4(CLIENT_IP, SERVER_IP, 6,
                              _tcp(51432, 443, 0x18, 1001, 1, payload)))
        if kind == "dns":
            payload = (
                b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x07example\x03com\x00\x00\x01\x00\x01"
            )
            return _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800,
                        _ipv4(CLIENT_IP, SERVER_IP, 17, _udp(53012, 53, payload)))
        if kind == "icmp":
            payload = b"abcdefghijklmnopqrstuvwxyz012345"
            return _eth(GATEWAY_MAC, CLIENT_MAC, 0x0800,
                        _ipv4(GATEWAY_IP, SERVER_IP, 1, _icmp(8, 0, payload)))
        if kind == "arp":
            arp = struct.pack(
                "!HHBBH6s4s6s4s",
                1, 0x0800, 6, 4, 1,
                _mac(CLIENT_MAC), socket.inet_aton(CLIENT_IP),
                b"\x00" * 6, socket.inet_aton(GATEWAY_IP),
            )
            return _eth(BROADCAST_MAC, CLIENT_MAC, 0x0806, arp)
        # ipv6 DNS
        payload = (
            b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x03com\x00\x00\x1c\x00\x01"
        )
        return _eth(GATEWAY_MAC, CLIENT_MAC, 0x86DD,
                    _ipv6(CLIENT_IP6, DNS_IP6, 17, _udp(53013, 53, payload)))

    def _process(self, frame: Frame, count_frame: bool = False):
        parsed = parse_frame(frame)
        self._stats.add(parsed)
        alert = self._alerts.ingest(parsed)
        if alert is not None:
            self.alert_raised.emit(alert)
        if count_frame:
            self._frames.append(frame)
            if len(self._frames) > MAX_DEMO_FRAMES:
                del self._frames[:MAX_DEMO_FRAMES // 2]
            now = time.time()
            self._recent.append((now, frame.origlen))
            while self._recent and now - self._recent[0][0] > 1.0:
                self._recent.popleft()
        self._seq += 1
        return build_packet_row(parsed, self._seq)

    @staticmethod
    def _to_frame(raw: bytes) -> Frame:
        return Frame(ts=time.time(), caplen=len(raw), origlen=len(raw), data=raw)

    # ---------------------------------------------------------------- 异常演示
    def _begin_burst(self) -> None:
        if self._burst_remaining > 0:
            return
        kind = self._burst_kinds[self._burst_index % len(self._burst_kinds)]
        self._burst_index += 1
        seq = random.randint(1000, 9000)

        if kind == "syn_flood":
            self._burst_remaining = 360
            self._burst_builder = lambda: _eth(  # noqa: E731
                GATEWAY_MAC, CLIENT_MAC, 0x0800,
                _ipv4(CLIENT_IP, FLOOD_TARGET, 6,
                      _tcp(random.randint(20000, 60000), 80, 0x02, seq, 0)),
            )
        elif kind == "icmp_flood":
            self._burst_remaining = 200
            self._burst_builder = lambda: _eth(  # noqa: E731
                GATEWAY_MAC, CLIENT_MAC, 0x0800,
                _ipv4(GATEWAY_IP, SERVER_IP, 1, _icmp(8, 0, b"ping" * 8)),
            )
        elif kind == "orphan_reply":
            self._burst_remaining = 30
            self._burst_builder = lambda: _eth(  # noqa: E731
                GATEWAY_MAC, CLIENT_MAC, 0x0800,
                _ipv4(GATEWAY_IP, SERVER_IP, 1, _icmp(0, 0, b"pong" * 8)),
            )
        else:  # big_echo：1400 B 载荷 + MF 分片
            self._burst_remaining = 1
            self._burst_builder = lambda: _eth(  # noqa: E731
                GATEWAY_MAC, CLIENT_MAC, 0x0800,
                _ipv4(GATEWAY_IP, SERVER_IP, 1, _icmp(8, 0, b"x" * 1400),
                      flags=0x2000),
            )
        self._burst_tick.start()

    def _burst_step(self) -> None:
        for _ in range(min(3, self._burst_remaining)):
            self._seq += 1
            row = self._process(self._to_frame(self._burst_builder()), count_frame=True)
            self.packets_received.emit([row])
        self._burst_remaining -= min(3, self._burst_remaining)
        if self._burst_remaining <= 0:
            self._burst_tick.stop()

    # ---------------------------------------------------------------- 统计
    def _emit_stats(self) -> None:
        now = time.time()
        while self._recent and now - self._recent[0][0] > 1.0:
            self._recent.popleft()

        snapshot = self._stats.snapshot()
        pps = float(len(self._recent))
        mbps = sum(size for _, size in self._recent) * 8 / 1_000_000

        self.stats_updated.emit(
            {
                "received": snapshot["total_packets"],
                "displayed": snapshot["total_packets"],
                "dropped": 0,
                "pps": pps,
                "mbps": mbps,
                "uptime_s": time.time() - self._started_at,
                "started_at": self._started_at,
                "length_hist": snapshot["length_hist"],
                "buckets": snapshot["buckets"],
                "ip_versions": snapshot["ip_versions"],
                "protocol_counts": snapshot["protocol_counts"],
            }
        )
