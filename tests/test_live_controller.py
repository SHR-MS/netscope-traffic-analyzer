"""LiveController 与界面的桥接测试（offscreen，不依赖 Npcap）。"""

from __future__ import annotations

import os
import struct
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from netscope.config import CaptureConfig
from netscope.core.models import DeviceInfo, Frame
from netscope.ui.live_controller import LiveController

HEADER = bytes.fromhex("00112233445566778899aabb")


def tcp_syn_frame() -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 51432, 443, 100, 0, 5 << 4, 0x02, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0,
        __import__("socket").inet_aton("192.168.1.23"),
        __import__("socket").inet_aton("93.184.216.34"),
    )
    return HEADER + bytes.fromhex("0800") + ip + tcp


def udp_frame() -> bytes:
    udp = struct.pack("!HHHH", 53012, 53, 8, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
        __import__("socket").inet_aton("192.168.1.23"),
        __import__("socket").inet_aton("8.8.8.8"),
    )
    return HEADER + bytes.fromhex("0800") + ip + udp


class FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.opened = False
        self.on_frame = None

    def preflight(self) -> None:
        return

    def list_devices(self) -> list[DeviceInfo]:
        return [DeviceInfo(key="fake0", description="Fake NIC", ips=("192.0.2.1",))]

    def open(self, *, device, bpf, snaplen, promisc, buffer_mb, on_frame) -> None:
        self.opened = True
        self.on_frame = on_frame

    def close(self) -> None:
        self.opened = False
        self.on_frame = None

    def emit(self, frame: Frame) -> None:
        if self.on_frame is not None:
            self.on_frame(frame)


class LiveControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.backend = FakeBackend()
        config = CaptureConfig(capture_dir=Path(self.tmp.name))
        self.controller = LiveController(config=config, backend=self.backend)
        self.rows = []
        self.stats = []
        self.states = []
        self.alerts = []
        self.controller.packets_received.connect(self.rows.extend)
        self.controller.stats_updated.connect(self.stats.append)
        self.controller.state_changed.connect(lambda state, _msg: self.states.append(state))
        self.controller.alert_raised.connect(self.alerts.append)

    def tearDown(self) -> None:
        self.controller.shutdown()
        self.tmp.cleanup()

    def test_devices(self) -> None:
        devices = self.controller.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertIn("192.0.2.1", devices[0].label)

    def test_frames_become_rows_with_real_stats(self) -> None:
        self.controller.start("fake0")
        frames = [
            Frame(ts=time.time(), caplen=len(tcp_syn_frame()),
                  origlen=len(tcp_syn_frame()), data=tcp_syn_frame()),
            Frame(ts=time.time(), caplen=len(udp_frame()),
                  origlen=len(udp_frame()), data=udp_frame()),
        ]
        for frame in frames:
            self.backend.emit(frame)

        QTest.qWait(300)
        self.assertEqual(len(self.rows), 2)
        self.assertEqual([row.seq for row in self.rows], [1, 2])
        self.assertEqual(self.rows[0].protocol, "TCP")
        self.assertEqual(self.rows[0].version, 4)
        self.assertEqual(self.rows[0].src, "192.168.1.23")
        self.assertEqual(self.rows[0].dst, "93.184.216.34")
        self.assertEqual(self.rows[1].protocol, "UDP")

        self.controller.stop()
        self.assertTrue(self.stats)
        last = self.stats[-1]
        self.assertEqual(last["received"], 2)
        self.assertEqual(last["ip_versions"], (2, 0, 0))
        self.assertEqual(sum(last["buckets"]), 2)
        self.assertEqual(sum(last["length_hist"].values()), 2)
        self.assertIn("running", self.states)
        self.assertIn("idle", self.states)

    def test_capture_rolls_to_disk_and_save_as(self) -> None:
        self.controller.start("fake0")
        for _ in range(5):
            self.backend.emit(Frame(
                ts=time.time(), caplen=len(tcp_syn_frame()),
                origlen=len(tcp_syn_frame()), data=tcp_syn_frame()))
        QTest.qWait(300)
        self.controller.stop()

        session = self.controller.session_dir()
        self.assertIsNotNone(session)
        assert session is not None
        self.assertTrue(session.is_dir())
        segments = list(session.glob("capture-*.pcap"))
        self.assertTrue(segments)

        target = Path(self.tmp.name) / "saved.pcap"
        self.controller.save_as(str(target))
        self.assertTrue(target.is_file())
        from netscope.core.pcapio import read_frames
        self.assertEqual(len(read_frames(target)), 5)

    def test_open_file_replays(self) -> None:
        self.controller.start("fake0")
        for _ in range(3):
            self.backend.emit(Frame(
                ts=time.time(), caplen=len(tcp_syn_frame()),
                origlen=len(tcp_syn_frame()), data=tcp_syn_frame()))
        QTest.qWait(300)
        self.controller.stop()

        target = Path(self.tmp.name) / "saved.pcap"
        self.controller.save_as(str(target))

        self.controller.open_file(str(target))
        QTest.qWait(400)
        self.assertEqual(len(self.rows), 6)  # 3 条实抓 + 3 条回放
        self.assertEqual(self.rows[-1].protocol, "TCP")
        self.assertEqual(self.stats[-1]["received"], 3)  # 回放模式按解析行数

    def test_save_without_capture_raises(self) -> None:
        from netscope.core.pcapio import PcapError
        with self.assertRaises(PcapError):
            self.controller.save_as(str(Path(self.tmp.name) / "empty.pcap"))

    def test_stop_without_start_is_safe(self) -> None:
        self.controller.stop()


if __name__ == "__main__":
    unittest.main()
