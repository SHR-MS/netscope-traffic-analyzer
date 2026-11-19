"""采集配置。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields


@dataclass(slots=True)
class CaptureConfig:
    """采集参数。

    ``snaplen`` 目前是预留字段：Scapy 的 pcap 监听 socket 固定用 65535。
    """

    device: str | None = None
    bpf: str = ""
    snaplen: int = 65535
    promisc: bool = True
    buffer_mb: int = 32
    queue_size: int = 20_000

    def __post_init__(self) -> None:
        self.snaplen = int(self.snaplen)
        self.queue_size = int(self.queue_size)
        self.buffer_mb = int(self.buffer_mb)
        if not 64 <= self.snaplen <= 262_144:
            raise ValueError("snaplen 必须在 64~262144 之间")
        if not 1 <= self.queue_size <= 1_000_000:
            raise ValueError("queue_size 必须在 1~1000000 之间")
        if not 0 <= self.buffer_mb <= 1024:
            raise ValueError("buffer_mb 必须在 0~1024 之间")
        self.bpf = (self.bpf or "").strip()
        if self.device is not None:
            self.device = str(self.device).strip() or None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CaptureConfig":
        known = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})
