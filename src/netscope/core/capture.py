"""采集模块：Npcap/Scapy 收包 → 有界队列。

设计要点：

- 抓包回调只做 ``bytes(pkt)`` 和入队，不做解析、不碰界面；
- 队列满时丢新包并计数，不反压驱动；
- 后端可替换（测试用假实现）；
- 启动前做环境自检（Npcap、管理员、Scapy）。

Scapy 2.8 的 pcap 监听 socket 固定使用 65535 的 snaplen，
因此 ``CaptureConfig.snaplen`` 目前只是预留字段。
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable, Protocol, runtime_checkable

from ..config import CaptureConfig
from .diagnostics import ensure_environment
from .errors import CaptureError, CaptureStartError, CaptureUnavailable
from .models import CaptureState, CaptureStats, DeviceInfo, Frame

log = logging.getLogger(__name__)

StateCallback = Callable[[CaptureState, str], None]
FrameCallback = Callable[[Frame], None]

_VIRTUAL_WORDS = (
    "virtual",
    "vpn",
    "loopback",
    "vmware",
    "virtualbox",
    "hyper-v",
    "hyperv",
    "tap",
    "tun",
    "wintun",
    "wi-fi direct",
    "bluetooth",
    "radmin",
)


@runtime_checkable
class CaptureBackend(Protocol):
    name: str

    def preflight(self) -> None: ...

    def list_devices(self) -> list[DeviceInfo]: ...

    def open(
        self,
        *,
        device: str | None,
        bpf: str,
        snaplen: int,
        promisc: bool,
        buffer_mb: int,
        on_frame: FrameCallback,
    ) -> None: ...

    def close(self) -> None: ...


class ScapyBackend:
    """基于 Scapy + Npcap 的后端。"""

    name = "scapy"

    def __init__(self) -> None:
        self._sniffer = None
        self._on_frame: FrameCallback | None = None
        self._components = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 环境
    def preflight(self) -> None:
        ensure_environment(require_admin=True)

    # ------------------------------------------------------------------ 组件
    def _load(self):
        if self._components is not None:
            return self._components
        try:
            import scapy.all as scapy_all  # type: ignore[import-not-found]
            from scapy.sendrecv import AsyncSniffer  # type: ignore
        except Exception as exc:  # noqa: BLE001
            raise CaptureUnavailable("无法导入 Scapy，请先执行 pip install scapy") from exc

        lister = None
        try:
            from scapy.arch.windows import get_windows_if_list as lister  # type: ignore
        except Exception:  # noqa: BLE001
            lister = None

        self._components = (scapy_all, lister, AsyncSniffer)
        return self._components

    # ------------------------------------------------------------------ 设备
    def list_devices(self) -> list[DeviceInfo]:
        scapy_all, lister, _ = self._load()

        entries: list[dict] = []
        if lister is not None:
            try:
                entries = list(lister())
            except Exception as exc:  # noqa: BLE001
                log.warning("枚举 Windows 网卡失败：%s", exc)

        devices = [self._device_from_entry(entry) for entry in entries]
        devices = [device for device in devices if device.key]

        if not devices:
            try:
                for iface in scapy_all.conf.ifaces.values():
                    devices.append(
                        DeviceInfo(
                            key=str(getattr(iface, "name", "") or ""),
                            description=str(getattr(iface, "description", "") or ""),
                            name=str(getattr(iface, "name", "") or ""),
                            mac=str(getattr(iface, "mac", "") or ""),
                            ips=self._flatten_ips(getattr(iface, "ips", None)),
                            virtual=self._is_virtual(
                                str(getattr(iface, "description", ""))
                            ),
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                log.warning("枚举 Scapy 接口失败：%s", exc)

        devices = [device for device in devices if device.key]
        devices.sort(key=self._rank)
        return devices

    @staticmethod
    def _flatten_ips(value) -> tuple[str, ...]:
        if not value:
            return ()
        if isinstance(value, dict):
            return tuple(str(ip) for group in value.values() for ip in (group or ()))
        return tuple(str(ip) for ip in value)

    @staticmethod
    def _is_virtual(text: str) -> bool:
        lowered = text.lower()
        return any(word in lowered for word in _VIRTUAL_WORDS)

    @classmethod
    def _device_from_entry(cls, entry: dict) -> DeviceInfo:
        name = str(entry.get("name") or "").strip()
        description = str(entry.get("description") or name).strip()
        guid = str(entry.get("guid") or "").strip()
        mac = str(entry.get("mac") or "").strip()
        ips = tuple(str(ip) for ip in (entry.get("ips") or ()))

        key = name
        if guid and not name.startswith("\\Device"):
            if not guid.startswith("{"):
                guid = "{" + guid + "}"
            key = rf"\Device\NPF_{guid}"

        try:
            metric = int(entry.get("ipv4_metric") or 9999)
        except (TypeError, ValueError):
            metric = 9999

        return DeviceInfo(
            key=key,
            description=description or name or key,
            name=name,
            mac=mac,
            ips=ips,
            virtual=cls._is_virtual(f"{description} {name}"),
            metric=metric,
        )

    @staticmethod
    def _rank(device: DeviceInfo):
        """有可用 IPv4 的排前面，物理网卡优先，metric 小的优先。

        169.254.x.x 是 APIPA（没拿到 DHCP 时的地址），不算可用 IPv4，
        否则未插网线的有线网卡会排在正在用的 Wi-Fi 前面。
        """
        has_usable_ipv4 = any(
            "." in ip and not ip.startswith("169.254.") and ip != "0.0.0.0"
            for ip in device.ips
        )
        return (
            0 if has_usable_ipv4 else 1,
            1 if device.virtual else 0,
            device.metric,
            device.description.lower(),
        )

    # ------------------------------------------------------------------ 开关
    def open(
        self,
        *,
        device: str | None,
        bpf: str,
        snaplen: int,
        promisc: bool,
        buffer_mb: int,
        on_frame: FrameCallback,
    ) -> None:
        scapy_all, _, AsyncSniffer = self._load()
        conf = getattr(scapy_all, "conf", None)
        if conf is not None:
            for attr, value in (
                ("verb", 0),
                ("sniff_promisc", promisc),
                ("bufsize", int(buffer_mb) * 1024 * 1024 if buffer_mb else 0),
            ):
                if hasattr(conf, attr):
                    try:
                        setattr(conf, attr, value)
                    except Exception:  # noqa: BLE001
                        pass

        # 注意：L2pcapListenSocket 不接受 snaplen 参数，它固定用 65535；
        # 这里不传 snaplen，避免 TypeError。
        kwargs = {
            "iface": device or None,
            "prn": self._dispatch,
            "store": False,
            "filter": bpf or None,
            "promisc": promisc,
        }

        self._on_frame = on_frame
        sniffer = None
        try:
            sniffer = AsyncSniffer(**kwargs)
            sniffer.start()
        except Exception as exc:  # noqa: BLE001
            self._on_frame = None
            raise CaptureStartError(f"打开抓包设备失败：{exc}") from exc

        self._sniffer = sniffer
        try:
            self._wait_started(sniffer, device)
        except CaptureStartError:
            self._teardown(sniffer)
            self._sniffer = None
            self._on_frame = None
            raise

    def _wait_started(self, sniffer, device: str | None) -> None:
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            exc = getattr(sniffer, "exception", None)
            if exc is not None:
                raise CaptureStartError(f"打开抓包设备失败：{exc}")
            if getattr(sniffer, "running", False):
                return
            time.sleep(0.02)

        thread = getattr(sniffer, "thread", None)
        alive = thread is not None and getattr(thread, "is_alive", lambda: False)()
        if alive and getattr(sniffer, "exception", None) is None:
            return
        name = device or "默认网卡"
        raise CaptureStartError(f"抓包线程未能启动（{name}），请检查网卡与 Npcap 是否可用")

    def close(self) -> None:
        with self._lock:
            sniffer, self._sniffer = self._sniffer, None
            self._on_frame = None
        if sniffer is not None:
            self._teardown(sniffer)

    @staticmethod
    def _teardown(sniffer) -> None:
        stop = getattr(sniffer, "stop", None)
        if callable(stop):
            try:
                stop(join=False)
            except TypeError:
                try:
                    stop()
                except Exception:  # noqa: BLE001
                    log.debug("停止 sniffer 失败", exc_info=True)
            except Exception:  # noqa: BLE001
                log.debug("停止 sniffer 失败", exc_info=True)
        thread = getattr(sniffer, "thread", None)
        if thread is not None and getattr(thread, "is_alive", lambda: False)():
            thread.join(timeout=2.0)

    # ------------------------------------------------------------------ 回调
    def _dispatch(self, pkt) -> None:
        callback = self._on_frame
        if callback is None:
            return
        try:
            data = bytes(pkt)
        except Exception:  # noqa: BLE001
            return
        if not data:
            return

        try:
            ts = float(pkt.time)
        except Exception:  # noqa: BLE001
            ts = time.time()
        if ts <= 0:
            ts = time.time()

        wirelen = getattr(pkt, "wirelen", None)
        origlen = int(wirelen) if isinstance(wirelen, int) and wirelen > 0 else len(data)
        if origlen < len(data):
            origlen = len(data)

        try:
            callback(Frame(ts=ts, caplen=len(data), origlen=origlen, data=data))
        except Exception:  # noqa: BLE001
            log.exception("帧回调执行失败")


class CaptureEngine:
    """采集引擎：管理后端生命周期，向上提供帧队列与统计。"""

    def __init__(
        self,
        config: CaptureConfig | None = None,
        backend: CaptureBackend | None = None,
        *,
        on_state: StateCallback | None = None,
    ) -> None:
        self._config = config or CaptureConfig()
        self._backend: CaptureBackend = backend or ScapyBackend()
        self._on_state = on_state

        self._queue: queue.Queue[Frame] = queue.Queue(maxsize=self._config.queue_size)
        self._stats = CaptureStats()
        self._state = CaptureState.IDLE
        self._lock = threading.RLock()
        self._op_lock = threading.RLock()
        self._stats_lock = threading.Lock()
        self._device: str | None = None
        self._bpf = ""
        self._last_error = ""

    # ------------------------------------------------------------------ 属性
    @property
    def backend_name(self) -> str:
        return getattr(self._backend, "name", "unknown")

    @property
    def state(self) -> CaptureState:
        return self._state

    @property
    def is_running(self) -> bool:
        return self._state is CaptureState.RUNNING

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def frame_queue(self) -> "queue.Queue[Frame]":
        return self._queue

    @property
    def device(self) -> str | None:
        return self._device

    @property
    def bpf(self) -> str:
        return self._bpf

    # ------------------------------------------------------------------ 设备
    def list_devices(self) -> list[DeviceInfo]:
        return self._backend.list_devices()

    # ------------------------------------------------------------------ 启停
    def start(self, device: str | None = None, bpf: str | None = None) -> None:
        """开始抓包；失败时抛 :class:`CaptureError` 子类，状态置 ERROR。"""
        with self._op_lock:
            with self._lock:
                if self._state in (
                    CaptureState.STARTING,
                    CaptureState.RUNNING,
                    CaptureState.STOPPING,
                ):
                    raise CaptureError(f"当前状态为 {self._state.label}，不能重复启动")
                self._device = device if device is not None else self._config.device
                self._bpf = (bpf if bpf is not None else self._config.bpf).strip()
                self._state = CaptureState.STARTING
            self._emit(CaptureState.STARTING, "正在检查环境并打开设备")

            # 状态回调里可能调用了 stop()
            with self._lock:
                if self._state is not CaptureState.STARTING:
                    return

            try:
                self._backend.preflight()
                self._reset_stats()
                self._drain_all()
                self._backend.open(
                    device=self._device,
                    bpf=self._bpf,
                    snaplen=self._config.snaplen,
                    promisc=self._config.promisc,
                    buffer_mb=self._config.buffer_mb,
                    on_frame=self._deliver,
                )
            except CaptureError as exc:
                self._fail(str(exc))
                raise
            except Exception as exc:  # noqa: BLE001
                message = f"启动抓包失败：{exc}"
                self._fail(message)
                raise CaptureStartError(message) from exc

            with self._lock:
                cancelled = self._state is not CaptureState.STARTING
                if not cancelled:
                    self._state = CaptureState.RUNNING
            if cancelled:
                try:
                    self._backend.close()
                except Exception:  # noqa: BLE001
                    log.debug("取消启动时关闭后端失败", exc_info=True)
                return
            self._emit(CaptureState.RUNNING, "抓包中")

    def stop(self) -> None:
        """停止抓包；可重复调用。"""
        with self._op_lock:
            with self._lock:
                if self._state is CaptureState.IDLE:
                    return
                if self._state not in (
                    CaptureState.RUNNING,
                    CaptureState.ERROR,
                    CaptureState.STARTING,
                ):
                    return
                self._state = CaptureState.STOPPING
            self._emit(CaptureState.STOPPING, "正在停止")

            try:
                self._backend.close()
            except Exception:  # noqa: BLE001
                log.exception("关闭抓包后端失败")
            finally:
                with self._lock:
                    self._state = CaptureState.IDLE
                self._emit(CaptureState.IDLE, "已停止")

    def close(self) -> None:
        self.stop()

    def __enter__(self) -> "CaptureEngine":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # ------------------------------------------------------------------ 数据
    def drain(self, max_items: int | None = 1000, timeout: float = 0.0) -> list[Frame]:
        if max_items is not None and max_items <= 0:
            return []

        items: list[Frame] = []
        deadline = time.monotonic() + timeout if timeout and timeout > 0 else None

        while max_items is None or len(items) < max_items:
            try:
                if deadline is None:
                    items.append(self._queue.get_nowait())
                else:
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        items.append(self._queue.get(timeout=remaining))
                    else:
                        items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def stats(self) -> CaptureStats:
        with self._stats_lock:
            return self._stats.snapshot()

    # ------------------------------------------------------------------ 内部
    def _deliver(self, frame: Frame) -> None:
        with self._stats_lock:
            self._stats.received += 1
            self._stats.bytes += frame.origlen
            self._stats.last_frame_at = frame.ts
        try:
            self._queue.put_nowait(frame)
        except queue.Full:
            with self._stats_lock:
                self._stats.dropped += 1

    def _reset_stats(self) -> None:
        with self._stats_lock:
            self._stats = CaptureStats(started_at=time.time())

    def _drain_all(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def _fail(self, message: str) -> None:
        self._last_error = message
        try:
            self._backend.close()
        except Exception:  # noqa: BLE001
            log.debug("失败清理时关闭后端出错", exc_info=True)
        with self._lock:
            self._state = CaptureState.ERROR
        self._emit(CaptureState.ERROR, message)

    def _emit(self, state: CaptureState, message: str = "") -> None:
        callback = self._on_state
        if callback is None:
            return
        try:
            callback(state, message)
        except Exception:  # noqa: BLE001
            log.exception("状态回调执行失败")
