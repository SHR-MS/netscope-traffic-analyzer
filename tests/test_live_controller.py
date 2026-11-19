"""LiveController 与界面的桥接测试（offscreen，不依赖 Npcap）。"""

from __future__ import annotations

import os
import time
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from netscope.core.models import DeviceInfo, Frame
from netscope.ui.live_controller import LiveController

ETH_IPV4 = bytes.fromhex("00112233445566778899aabb0800") + b"\x00" * 20


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
        self.backend = FakeBackend()
        self.controller = LiveController(backend=self.backend)
        self.rows = []
        self.stats = []
        self.states = []
        self.controller.packets_received.connect(self.rows.extend)
        self.controller.stats_updated.connect(self.stats.append)
        self.controller.state_changed.connect(lambda state, _msg: self.states.append(state))

    def tearDown(self) -> None:
        self.controller.shutdown()

    def test_devices(self) -> None:
        devices = self.controller.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertIn("192.0.2.1", devices[0].label)

    def test_frames_become_rows(self) -> None:
        self.controller.start("fake0")
        for _ in range(3):
            self.backend.emit(
                Frame(ts=time.time(), caplen=len(ETH_IPV4), origlen=len(ETH_IPV4), data=ETH_IPV4)
            )

        QTest.qWait(300)
        self.assertEqual(len(self.rows), 3)
        self.assertEqual([row.seq for row in self.rows], [1, 2, 3])
        self.assertEqual(self.rows[0].protocol, "IPv4")
        self.assertEqual(self.rows[0].version, 4)
        self.assertEqual(self.rows[0].src, "66:77:88:99:aa:bb")

        self.controller.stop()
        self.assertTrue(self.stats)
        self.assertEqual(self.stats[-1]["received"], 3)
        self.assertIn("running", self.states)
        self.assertIn("idle", self.states)

    def test_stop_without_start_is_safe(self) -> None:
        self.controller.stop()


if __name__ == "__main__":
    unittest.main()
