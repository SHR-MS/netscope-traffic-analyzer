"""抓包链路的公共数据模型。"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from enum import Enum


class CaptureState(str, Enum):
    """采集引擎状态机。"""

    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"

    @property
    def label(self) -> str:
        return {
            CaptureState.IDLE: "空闲",
            CaptureState.STARTING: "启动中",
            CaptureState.RUNNING: "抓包中",
            CaptureState.STOPPING: "停止中",
            CaptureState.ERROR: "错误",
        }[self]


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """一块可抓包的网卡。

    ``key`` 是传给 Scapy 的标识（Windows 下为 ``\\Device\\NPF\\{GUID}``），
    ``description`` 是给人看的名称。
    """

    key: str
    description: str
    name: str = ""
    mac: str = ""
    ips: tuple[str, ...] = ()
    virtual: bool = False
    metric: int = 9999

    def display(self) -> str:
        text = self.description or self.name or self.key
        ipv4 = next((ip for ip in self.ips if "." in ip), "")
        if ipv4:
            text = f"{text}  ({ipv4})"
        if self.virtual:
            text = f"{text}  [虚拟]"
        return text


@dataclass(frozen=True, slots=True)
class Frame:
    """一个捕获到的原始以太网帧。"""

    ts: float
    caplen: int
    origlen: int
    data: bytes

    def __post_init__(self) -> None:
        if self.caplen != len(self.data):
            raise ValueError(f"caplen={self.caplen} 与 data 长度 {len(self.data)} 不一致")
        if self.origlen <= 0:
            raise ValueError("origlen 必须为正数")


@dataclass(slots=True)
class CaptureStats:
    """采集侧计数器。"""

    received: int = 0
    dropped: int = 0
    bytes: int = 0
    started_at: float | None = None
    last_frame_at: float | None = None

    @property
    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        return max(0.0, time.time() - self.started_at)

    @property
    def avg_pps(self) -> float:
        elapsed = self.elapsed
        return self.received / elapsed if elapsed > 1e-9 else 0.0

    @property
    def avg_mbps(self) -> float:
        elapsed = self.elapsed
        return (self.bytes * 8 / 1_000_000) / elapsed if elapsed > 1e-9 else 0.0

    def snapshot(self) -> "CaptureStats":
        return replace(self)
