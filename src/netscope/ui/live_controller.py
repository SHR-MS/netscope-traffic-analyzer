"""把采集引擎接到界面：QTimer 批量取帧，解析 → 统计 → 告警 → 落盘。

数据流::

    Npcap → AsyncSniffer 回调 → Frame → 有界队列
          → QTimer(100ms) 取帧
          → parser.parse_frame（三层解析）
          → stats.add / alerts.ingest / pcap 滚动落盘
          → packet_rows.build_packet_row → packets_received 信号

统计每 500ms 发一次快照；告警触发即发。原始报文自动滚动落盘到
``capture_dir``（默认 文档/NetScope/capture-时间戳），可运行 1 天以上
而不占内存；"另存为"把落盘数据合并成一个 pcap 文件。
"""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QTimer

from ..config import CaptureConfig
from ..core.alerts import AlertEngine
from ..core.capture import CaptureBackend, CaptureEngine
from ..core.models import CaptureState, Frame
from ..core.parser import parse_frame
from ..core.pcapio import (
    PcapError,
    RollingPcapWriter,
    default_capture_dir,
    new_session_dir,
    read_frames,
)
from ..core.stats import TrafficStats
from .controller import CaptureController, DeviceOption
from .packet_rows import build_packet_row

STATE_MAP = {
    CaptureState.IDLE: "idle",
    CaptureState.STARTING: "starting",
    CaptureState.RUNNING: "running",
    CaptureState.STOPPING: "stopping",
    CaptureState.ERROR: "error",
}

LOAD_CHUNK = 2000  # 打开文件时每次定时器处理的帧数


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
        self._config = config or CaptureConfig()
        self._engine = CaptureEngine(
            self._config,
            backend=backend,
            on_state=self._on_engine_state,
        )
        self._seq = 0

        self._stats_agg = TrafficStats()
        self._alerts = AlertEngine(self._config.alert)

        self._session_dir: Path | None = None
        self._pcap: RollingPcapWriter | None = None
        self._loaded_file: Path | None = None

        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(100)
        self._drain_timer.timeout.connect(self._drain)

        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(500)
        self._stats_timer.timeout.connect(self._emit_stats)

        self._load_timer = QTimer(self)
        self._load_timer.setInterval(0)
        self._load_timer.timeout.connect(self._load_next_chunk)
        self._load_frames = None      # PcapReader 惰性迭代器
        self._load_total = 0
        self._load_path: Path | None = None

        self._prev_time = time.monotonic()
        self._prev_received = 0
        self._prev_bytes = 0
        self._last_uptime = 0.0
        self._started_at = 0.0

    # ---------------------------------------------------------------- 设备
    def list_devices(self) -> list[DeviceOption]:
        # 枚举失败（例如当前解释器没装 Scapy）时让异常向上抛，
        # 由界面把原因显示出来，而不是静默返回空列表。
        devices = self._engine.list_devices()
        return [DeviceOption(device.key, device.display()) for device in devices]

    # ---------------------------------------------------------------- 抓包
    def start(self, device_key: str, bpf: str = "") -> None:
        self._load_timer.stop()
        self._load_frames = None
        self._load_total = 0
        self._load_path = None
        self._seq = 0
        self._stats_agg.reset()
        self._alerts.reset()
        self._loaded_file = None

        base = self._config.capture_dir or default_capture_dir()
        self._session_dir = new_session_dir(base)
        self._pcap = RollingPcapWriter(
            self._session_dir, "capture", self._config.rotate_bytes
        )

        self._engine.start(device_key, bpf)

        self._prev_time = time.monotonic()
        stats = self._engine.stats()
        self._prev_received = stats.received
        self._prev_bytes = stats.bytes
        self._last_uptime = 0.0
        self._started_at = stats.started_at or time.time()

        self._drain_timer.start()
        self._stats_timer.start()

    def stop(self) -> None:
        self._drain_timer.stop()
        self._stats_timer.stop()
        self._engine.stop()
        if self._pcap is not None:
            self._pcap.close()
            self._pcap = None
        self._emit_stats()

    def shutdown(self) -> None:
        self._drain_timer.stop()
        self._stats_timer.stop()
        self._load_timer.stop()
        self._engine.close()
        if self._pcap is not None:
            self._pcap.close()
            self._pcap = None

    # ---------------------------------------------------------------- 文件
    def session_dir(self) -> Path | None:
        return self._session_dir

    def save_as(self, path: str) -> None:
        """把已捕获的原始数据另存为 pcap 文件。"""
        target = Path(path)
        if self._pcap is not None:
            self._pcap.flush()
            copied = self._pcap.copy_to(target)
            if copied == 0:
                raise PcapError("本次捕获还没有数据，无可保存内容")
            return
        if self._loaded_file is not None and self._loaded_file.resolve() != target.resolve():
            target.write_bytes(self._loaded_file.read_bytes())
            return
        if self._session_dir is not None:
            # 抓包已停止：直接合并落盘的段文件
            segments = sorted(Path(self._session_dir).glob("capture-*.pcap"))
            if segments:
                helper = RollingPcapWriter(
                    self._session_dir, "capture", self._config.rotate_bytes
                )
                try:
                    helper.copy_to(target)
                finally:
                    helper.close()
                return
        raise PcapError("当前没有可保存的捕获数据：请先开始抓包或打开文件")

    def open_file(self, path: str) -> None:
        """打开 pcap 文件并回放展示（分块加载，不卡界面）。"""
        if self._engine.is_running:
            self.stop()
        self._load_timer.stop()

        frames = read_frames(path)
        self._seq = 0
        self._stats_agg.reset()
        self._alerts.reset()
        self._loaded_file = Path(path)
        self._load_total = len(frames)
        self._load_frames = iter(frames)
        self._load_path = Path(path)
        self._started_at = 0.0
        self._last_uptime = 0.0
        self.state_changed.emit("idle", f"正在读取文件：{self._load_path.name} …")
        self._load_timer.start()

    def _load_next_chunk(self) -> None:
        assert self._load_frames is not None
        rows = []
        count = 0
        for frame in self._load_frames:
            rows.append(self._process_frame(frame))
            count += 1
            if count >= LOAD_CHUNK:
                break
        if rows:
            self.packets_received.emit(rows)
            self._emit_stats()
        if count < LOAD_CHUNK:
            self._finish_load()
            return

    def _finish_load(self) -> None:
        self._load_timer.stop()
        self._load_frames = None
        total = self._load_total
        path = self._load_path
        self._load_total = 0
        self._load_path = None
        self._emit_stats()
        self.state_changed.emit(
            "idle", f"已打开 {path.name}（{total} 个报文，数据未落盘）"
        )

    # ---------------------------------------------------------------- 内部
    def _on_engine_state(self, state: CaptureState, message: str) -> None:
        self.state_changed.emit(STATE_MAP.get(state, "idle"), message)

    def _process_frame(self, frame: Frame):
        """解析一条帧：统计、告警、落盘、生成显示行。"""
        parsed = parse_frame(frame)
        self._stats_agg.add(parsed)
        alert = self._alerts.ingest(parsed)
        if alert is not None:
            self.alert_raised.emit(alert)
        if self._pcap is not None:
            try:
                self._pcap.write(frame)
            except OSError:
                # 磁盘异常不能拖垮抓包展示；状态栏可看到丢落盘提示
                self.state_changed.emit("running", "警告：捕获文件写入失败")
                self._pcap = None
        self._seq += 1
        return build_packet_row(parsed, self._seq)

    def _drain(self) -> None:
        frames = self._engine.drain(max_items=2000)
        if not frames:
            return

        rows = []
        for frame in frames:
            rows.append(self._process_frame(frame))
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

        snapshot = self._stats_agg.snapshot()
        if self._loaded_file is not None:
            # 文件回放模式：包数以已解析行数为准，无运行时长
            received = self._seq
            uptime = 0.0
        else:
            received = stats.received
            uptime = stats.elapsed

        self.stats_updated.emit(
            {
                "received": received,
                "displayed": received,
                "dropped": stats.dropped,
                "pps": max(0.0, pps),
                "mbps": max(0.0, mbps),
                "uptime_s": uptime,
                "started_at": self._started_at,
                "length_hist": snapshot["length_hist"],
                "buckets": snapshot["buckets"],
                "ip_versions": snapshot["ip_versions"],
                "protocol_counts": snapshot["protocol_counts"],
            }
        )
