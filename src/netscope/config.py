"""采集与检测配置。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AlertConfig:
    """异常检测阈值。阈值按 5 秒滑动窗口设计，可按实验环境调整。"""

    syn_window_s: float = 5.0        # SYN 统计窗口
    syn_min: int = 100               # 窗口内 SYN 达到该数量才判定
    syn_ratio: float = 3.0           # SYN / SYN-ACK 超过该比值判定泛洪
    icmp_window_s: float = 5.0       # ICMP 统计窗口
    icmp_min: int = 50               # 窗口内 echo request 达到该数量判定泛洪
    orphan_replies_min: int = 20     # 无请求应答：窗口内 reply 数量
    orphan_requests_max: int = 5     # 无请求应答：窗口内 request 上限
    big_echo_bytes: int = 800        # echo request 载荷超过该字节数提示
    cooldown_s: float = 60.0         # 同一规则同一目标的告警冷却时间

    def __post_init__(self) -> None:
        if self.syn_window_s <= 0 or self.icmp_window_s <= 0:
            raise ValueError("检测窗口必须为正数")
        if self.cooldown_s <= 0:
            raise ValueError("冷却时间必须为正数")


@dataclass(slots=True)
class CaptureConfig:
    """采集参数。

    ``snaplen`` 目前是预留字段：Scapy 的 pcap 监听 socket 固定用 65535。
    ``capture_dir`` 为 None 时使用默认捕获目录（文档/NetScope）。
    """

    device: str | None = None
    bpf: str = ""
    snaplen: int = 65535
    promisc: bool = True
    buffer_mb: int = 32
    queue_size: int = 20_000
    capture_dir: Path | None = None          # 自动落盘目录
    rotate_bytes: int = 64 * 1024 * 1024     # pcap 单段最大字节数
    alert: AlertConfig = field(default_factory=AlertConfig)

    def __post_init__(self) -> None:
        self.snaplen = int(self.snaplen)
        self.queue_size = int(self.queue_size)
        self.buffer_mb = int(self.buffer_mb)
        self.rotate_bytes = int(self.rotate_bytes)
        if not 64 <= self.snaplen <= 262_144:
            raise ValueError("snaplen 必须在 64~262144 之间")
        if not 1 <= self.queue_size <= 1_000_000:
            raise ValueError("queue_size 必须在 1~1000000 之间")
        if not 0 <= self.buffer_mb <= 1024:
            raise ValueError("buffer_mb 必须在 0~1024 之间")
        if not 1_048_576 <= self.rotate_bytes <= 1 << 30:
            raise ValueError("rotate_bytes 必须在 1MB~1GB 之间")
        if self.capture_dir is not None:
            self.capture_dir = Path(self.capture_dir)
        self.bpf = (self.bpf or "").strip()
        if self.device is not None:
            self.device = str(self.device).strip() or None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CaptureConfig":
        known = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})
