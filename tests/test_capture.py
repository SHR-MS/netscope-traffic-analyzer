"""抓包链路单元测试：引擎、Scapy 后端映射、预览、环境自检。

运行（在 base 目录）::

    ..\\.venv\\Scripts\\python.exe -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import time
import unittest
from types import SimpleNamespace
from unittest import mock

import netscope.core.diagnostics as diagnostics
from netscope.config import CaptureConfig
from netscope.core.capture import CaptureEngine, ScapyBackend
from netscope.core.errors import CaptureError, CaptureStartError, CaptureUnavailable
from netscope.core.models import CaptureState, CaptureStats, DeviceInfo, Frame
from netscope.ui.preview import build_preview_row


def make_frame(ts: float = 1.0, size: int = 60) -> Frame:
    return Frame(ts=ts, caplen=size, origlen=size, data=b"\x00" * size)


class FakeBackend:
    name = "fake"

    def __init__(self, *, fail_open: bool = False, fail_preflight: bool = False) -> None:
        self.fail_open = fail_open
        self.fail_preflight = fail_preflight
        self.opened = False
        self.closed = False
        self.params: dict = {}
        self.on_frame = None

    def preflight(self) -> None:
        if self.fail_preflight:
            raise CaptureUnavailable("缺少测试依赖")

    def list_devices(self) -> list[DeviceInfo]:
        return [DeviceInfo(key="fake0", description="Fake NIC")]

    def open(self, *, device, bpf, snaplen, promisc, buffer_mb, on_frame) -> None:
        if self.fail_open:
            raise RuntimeError("device busy")
        self.opened = True
        self.closed = False
        self.params = {
            "device": device,
            "bpf": bpf,
            "snaplen": snaplen,
            "promisc": promisc,
            "buffer_mb": buffer_mb,
        }
        self.on_frame = on_frame

    def close(self) -> None:
        self.opened = False
        self.closed = True
        self.on_frame = None

    def emit(self, frame: Frame) -> None:
        if self.on_frame is not None:
            self.on_frame(frame)


class ModelTests(unittest.TestCase):
    def test_frame_rejects_mismatched_caplen(self) -> None:
        with self.assertRaises(ValueError):
            Frame(ts=1.0, caplen=10, origlen=10, data=b"\x00" * 5)

    def test_stats_rates(self) -> None:
        stats = CaptureStats(received=100, bytes=1_000_000, started_at=time.time() - 10)
        self.assertAlmostEqual(stats.elapsed, 10.0, delta=0.5)
        self.assertAlmostEqual(stats.avg_pps, 10.0, delta=0.6)


class ConfigTests(unittest.TestCase):
    def test_bpf_stripped(self) -> None:
        self.assertEqual(CaptureConfig(bpf=" tcp ").bpf, "tcp")

    def test_bad_queue(self) -> None:
        with self.assertRaises(ValueError):
            CaptureConfig(queue_size=0)


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeBackend()
        self.states: list[CaptureState] = []
        self.engine = CaptureEngine(
            CaptureConfig(queue_size=8),
            self.backend,
            on_state=lambda state, _msg: self.states.append(state),
        )

    def tearDown(self) -> None:
        self.engine.stop()

    def test_start_stop_lifecycle(self) -> None:
        self.engine.start(device="fake0")
        self.assertIs(self.engine.state, CaptureState.RUNNING)
        self.assertTrue(self.backend.opened)
        self.assertEqual(self.backend.params["device"], "fake0")

        self.engine.stop()
        self.assertIs(self.engine.state, CaptureState.IDLE)
        self.assertTrue(self.backend.closed)
        self.assertEqual(
            self.states,
            [
                CaptureState.STARTING,
                CaptureState.RUNNING,
                CaptureState.STOPPING,
                CaptureState.IDLE,
            ],
        )

    def test_frames_delivered_and_counted(self) -> None:
        self.engine.start()
        self.backend.emit(make_frame(ts=10.0, size=100))
        self.backend.emit(make_frame(ts=11.0, size=50))

        frames = self.engine.drain()
        self.assertEqual(len(frames), 2)
        stats = self.engine.stats()
        self.assertEqual(stats.received, 2)
        self.assertEqual(stats.bytes, 150)

    def test_queue_full_drops(self) -> None:
        self.engine = CaptureEngine(CaptureConfig(queue_size=2), self.backend)
        self.engine.start()
        for _ in range(5):
            self.backend.emit(make_frame())

        stats = self.engine.stats()
        self.assertEqual(stats.received, 5)
        self.assertEqual(stats.dropped, 3)
        self.assertEqual(len(self.engine.drain()), 2)

    def test_double_start_rejected(self) -> None:
        self.engine.start()
        with self.assertRaises(CaptureError):
            self.engine.start()

    def test_open_failure_sets_error(self) -> None:
        backend = FakeBackend(fail_open=True)
        engine = CaptureEngine(CaptureConfig(), backend)
        with self.assertRaises(CaptureStartError):
            engine.start()
        self.assertIs(engine.state, CaptureState.ERROR)
        self.assertTrue(backend.closed)

    def test_preflight_failure(self) -> None:
        backend = FakeBackend(fail_preflight=True)
        engine = CaptureEngine(CaptureConfig(), backend)
        with self.assertRaises(CaptureUnavailable):
            engine.start()
        self.assertIs(engine.state, CaptureState.ERROR)

    def test_restart_clears_stats(self) -> None:
        self.engine.start()
        self.backend.emit(make_frame())
        self.engine.drain()
        self.engine.stop()
        self.engine.start()
        self.assertEqual(self.engine.stats().received, 0)
        self.assertEqual(self.engine.drain(), [])


GUID = "11111111-2222-3333-4444-555555555555"

ENTRIES = [
    {
        "name": "以太网 2",
        "description": "Intel(R) Ethernet",
        "guid": "{" + GUID + "}",
        "mac": "aa:bb:cc:dd:ee:ff",
        "ips": ["192.168.1.5"],
        "ipv4_metric": 20,
    },
    {
        "name": "VirtualBox Host-Only",
        "description": "VirtualBox Host-Only Ethernet Adapter",
        "guid": "{22222222-2222-3333-4444-555555555555}",
        "mac": "0a:00:27:00:00:0f",
        "ips": ["192.168.56.1"],
        "ipv4_metric": 1,
    },
    {
        "name": "以太网",
        "description": "Realtek PCIe GbE",
        "guid": "{33333333-2222-3333-4444-555555555555}",
        "mac": "aa:bb:cc:dd:ee:11",
        "ips": ["169.254.123.208"],
        "ipv4_metric": 5,
    },
]


class FakeConf:
    def __init__(self) -> None:
        self.verb = 1
        self.sniff_promisc = False
        self.bufsize = 0


class FakeAsyncSniffer:
    instances: list["FakeAsyncSniffer"] = []
    fail = False

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.running = False
        self.exception = None
        self.thread = None
        self.stopped = False
        FakeAsyncSniffer.instances.append(self)

    def start(self) -> None:
        if FakeAsyncSniffer.fail:
            self.exception = OSError("could not open adapter")
            return
        self.running = True

    def stop(self, join: bool = True) -> None:
        self.running = False
        self.stopped = True


class StubScapyBackend(ScapyBackend):
    def __init__(self, fail: bool = False) -> None:
        super().__init__()
        self._fail = fail

    def preflight(self) -> None:
        return

    def _load(self):
        FakeAsyncSniffer.fail = self._fail
        return SimpleNamespace(conf=FakeConf()), (lambda: list(ENTRIES)), FakeAsyncSniffer


class ScapyBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeAsyncSniffer.instances.clear()
        FakeAsyncSniffer.fail = False

    def test_device_mapping_and_order(self) -> None:
        devices = StubScapyBackend().list_devices()
        self.assertEqual(devices[0].key, rf"\Device\NPF_{{{GUID}}}")
        self.assertTrue(devices[0].ips)
        self.assertFalse(devices[0].virtual)
        self.assertTrue(devices[1].virtual)
        # 169.254 的 APIPA 地址不算可用 IPv4，排最后
        self.assertTrue(devices[2].ips[0].startswith("169.254."))
        # 有 IPv4 的物理网卡排最前
        self.assertIn("Intel", devices[0].description)

    def test_open_passes_expected_kwargs(self) -> None:
        engine = CaptureEngine(CaptureConfig(bpf="tcp port 443"), StubScapyBackend())
        engine.start(device=r"\Device\NPF_{" + GUID + "}")

        sniffer = FakeAsyncSniffer.instances[-1]
        self.assertEqual(sniffer.kwargs["iface"], r"\Device\NPF_{" + GUID + "}")
        self.assertEqual(sniffer.kwargs["filter"], "tcp port 443")
        self.assertFalse(sniffer.kwargs["store"])
        self.assertTrue(sniffer.kwargs["promisc"])
        self.assertNotIn("snaplen", sniffer.kwargs)
        self.assertTrue(sniffer.running)

        engine.stop()
        self.assertTrue(sniffer.stopped)

    def test_dispatch_to_frame(self) -> None:
        backend = StubScapyBackend()
        grabbed: list[Frame] = []
        backend.open(
            device="x", bpf="", snaplen=65535, promisc=True, buffer_mb=1, on_frame=grabbed.append
        )

        class FakePacket:
            time = 1.5
            wirelen = 64

            def __bytes__(self) -> bytes:
                return b"\x00" * 60

        backend._dispatch(FakePacket())
        self.assertEqual(len(grabbed), 1)
        self.assertEqual(grabbed[0].caplen, 60)
        self.assertEqual(grabbed[0].origlen, 64)
        self.assertEqual(grabbed[0].ts, 1.5)

    def test_open_failure_becomes_start_error(self) -> None:
        engine = CaptureEngine(CaptureConfig(), StubScapyBackend(fail=True))
        with self.assertRaises(CaptureStartError):
            engine.start()
        self.assertIs(engine.state, CaptureState.ERROR)


class PreviewTests(unittest.TestCase):
    @staticmethod
    def ethernet(ether_type: int = 0x0800, vlan: int | None = None) -> bytes:
        header = bytes.fromhex("00112233445566778899aabb")
        if vlan is None:
            return header + ether_type.to_bytes(2, "big") + b"\x45" + b"\x00" * 19
        return (
            header
            + (0x8100).to_bytes(2, "big")
            + vlan.to_bytes(2, "big")
            + ether_type.to_bytes(2, "big")
            + b"\x45"
            + b"\x00" * 19
        )

    def test_ipv4_preview(self) -> None:
        data = self.ethernet()
        frame = Frame(ts=1.0, caplen=len(data), origlen=len(data), data=data)
        row = build_preview_row(frame, 7)

        self.assertEqual(row.seq, 7)
        self.assertEqual(row.protocol, "IPv4")
        self.assertEqual(row.version, 4)
        self.assertEqual(row.src, "66:77:88:99:aa:bb")
        self.assertEqual(row.dst, "00:11:22:33:44:55")
        self.assertEqual(row.length, len(data))
        self.assertIn("数据链路层", row.layers[0][0])

    def test_vlan_preview(self) -> None:
        data = self.ethernet(vlan=100)
        frame = Frame(ts=1.0, caplen=len(data), origlen=len(data), data=data)
        row = build_preview_row(frame, 1)
        link_fields = dict(row.layers[0][1])
        self.assertEqual(link_fields["VLAN ID"], "100")
        self.assertEqual(row.protocol, "IPv4")

    def test_truncated_preview(self) -> None:
        data = b"\x00" * 10
        frame = Frame(ts=1.0, caplen=len(data), origlen=len(data), data=data)
        row = build_preview_row(frame, 2)
        self.assertTrue(row.info.startswith("截断帧"))
        self.assertEqual(row.protocol, "0x0000")


class DiagnosticsTests(unittest.TestCase):
    def test_missing_npcap_reported(self) -> None:
        with (
            mock.patch.object(diagnostics, "is_windows", return_value=True),
            mock.patch.object(diagnostics, "scapy_available", return_value=True),
            mock.patch.object(diagnostics, "npcap_installed", return_value=False),
            mock.patch.object(diagnostics, "is_admin", return_value=True),
        ):
            codes = [issue.code for issue in diagnostics.check_environment()]
        self.assertEqual(codes, ["npcap"])

    def test_ensure_raises(self) -> None:
        with (
            mock.patch.object(diagnostics, "is_windows", return_value=True),
            mock.patch.object(diagnostics, "scapy_available", return_value=False),
            mock.patch.object(diagnostics, "npcap_installed", return_value=True),
            mock.patch.object(diagnostics, "is_admin", return_value=True),
        ):
            with self.assertRaises(CaptureUnavailable):
                diagnostics.ensure_environment()


if __name__ == "__main__":
    unittest.main()
