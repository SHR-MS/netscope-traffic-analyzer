"""把采集引擎接到界面：QTimer 批量取帧，转成 PacketRow 发信号。"""

from __future__ import annotations

import time

from PySide6.QtCore import QTimer

from ..config import CaptureConfig
from ..core.capture import CaptureBackend, CaptureEngine
from ..core.models import CaptureState
from .controller import CaptureController, DeviceOption
from .preview import build_preview_row

STATE_MAP = {
    CaptureState.IDLE: "idle",
    CaptureState.STARTING: "starting",
    CaptureState.RUNNING: "running",
    CaptureState.STOPPING: "stopping",
    CaptureState.ERROR: "error",
}


class LiveController(CaptureController):
    """真实抓包后端。"""

    demo = False

    def __init__(
        self,
        config: CaptureConfig | None = None,
        parent=None,
        backend: CaptureBackend | None = None,
    ) -> None:
        super().__init__(parent)
        self._engine = CaptureEngine(
            config or CaptureConfig(),
            backend=backend,
            on_state=self._on_engine_state,
        )
        self._seq = 0

        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(100)
        self._drain_timer.timeout.connect(self._drain)

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(500)
        self._stats_timer.timeout.connect(self._emit_stats)

        self._prev_time = time.monotonic()
        self._prev_received = 0
        self._prev_bytes = 0
        self._last_uptime = 0.0

    # ---------------------------------------------------------------- 设备
    def list_devices(self) -> list[DeviceOption]:
        try:
            devices = self._engine.list_devices()
        except Exception:  # noqa: BLE001 - 枚举失败只显示空列表
            return []
        return [DeviceOption(device.key, device.display()) for device in devices]

    # ---------------------------------------------------------------- 启停
    def start(self, device_key: str, bpf: str = "") -> None:
        self._seq = 0
        self._engine.start(device_key, bpf)

        self._prev_time = time.monotonic()
        stats = self._engine.stats()
        self._prev_received = stats.received
        self._prev_bytes = stats.bytes
        self._last_uptime = 0.0

        self._drain_timer.start()
        self._stats_timer.start()

    def stop(self) -> None:
        self._drain_timer.stop()
        self._stats_timer.stop()
        self._engine.stop()
        self._emit_stats()

    def shutdown(self) -> None:
        self._drain_timer.stop()
        self._stats_timer.stop()
        self._engine.close()

    # ---------------------------------------------------------------- 文件
    def save_as(self, path: str) -> None:
        raise NotImplementedError("pcap 保存将在下一阶段接入")

    def open_file(self, path: str) -> None:
        raise NotImplementedError("pcap 回放将在下一阶段接入")

    # ---------------------------------------------------------------- 内部
    def _on_engine_state(self, state: CaptureState, message: str) -> None:
        self.state_changed.emit(STATE_MAP.get(state, "idle"), message)

    def _drain(self) -> None:
        frames = self._engine.drain(max_items=2000)
        if not frames:
            return

        rows = []
        for frame in frames:
            self._seq += 1
            rows.append(build_preview_row(frame, self._seq))
        self.packets_received.emit(rows)

    def _emit_stats(self) -> None:
        stats = self._engine.stats()
        now = time.monotonic()
        delta_time = now - self._prev_time
        if delta_time > 0:
            pps = (stats.received - self._prev_received) / delta_time
            mbps = (stats.bytes - self._prev_bytes) * 8 / 1_000_000 / delta_time
        else:
            pps = 0.0
            mbps = 0.0

        self._prev_time = now
        self._prev_received = stats.received
        self._prev_bytes = stats.bytes
        self._last_uptime = stats.elapsed

        self.stats_updated.emit(
            {
                "received": stats.received,
                "displayed": stats.received,
                "dropped": stats.dropped,
                "pps": max(0.0, pps),
                "mbps": max(0.0, mbps),
                "uptime_s": self._last_uptime,
                # 统计模块下一阶段接入，先给空数据
                "length_hist": {},
                "buckets": (0, 0, 0),
                "ip_versions": (0, 0, 0),
            }
        )
