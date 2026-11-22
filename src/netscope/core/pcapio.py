"""pcap 文件读写与滚动落盘（数据持久化）。

自实现经典 pcap 格式（magic、端序、微秒/纳秒时间戳），不依赖 Scapy，
保证"另存为"的文件能被本软件及其它抓包工具（Wireshark 等）打开；
pcapng 文件回放时优先尝试 Scapy 的 rdpcap。

经典 pcap 文件头（24 字节）：magic(4) major(2) minor(2) thiszone(4)
sigfigs(4) snaplen(4) network(4)；其后每条记录：ts_sec(4) ts_frac(4)
incl_len(4) orig_len(4) + 数据。
"""

from __future__ import annotations

import struct
import time
from pathlib import Path

from .models import Frame

PCAP_MAGIC_US = 0xA1B2C3D4          # 微秒时间戳
PCAP_MAGIC_NS = 0xA1B23C4D          # 纳秒时间戳
PCAPNG_MAGIC = 0x0A0D0D0A
LINKTYPE_ETHERNET = 1

# (magic 小端读出的值, 说明, 是否字节序交换, 是否纳秒)
_MAGIC_VARIANTS = {
    PCAP_MAGIC_US: ("经典 pcap（微秒）", False, False),
    PCAP_MAGIC_NS: ("经典 pcap（纳秒）", False, True),
    # 大端文件读出来是字节反序的
    0xD4C3B2A1: ("经典 pcap（微秒，大端）", True, False),
    0x4D3CB2A1: ("经典 pcap（纳秒，大端）", True, True),
}


class PcapError(Exception):
    """pcap 读写错误。"""


class PcapWriter:
    """追加式经典 pcap 写入器（小端、微秒、链路类型以太网）。"""

    SNAPLEN = 262_144

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._path.open("wb")
        self._count = 0
        self._bytes_written = 0
        self._file.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_US, 2, 4, 0, 0, self.SNAPLEN, LINKTYPE_ETHERNET,
        ))

    @property
    def path(self) -> Path:
        return self._path

    @property
    def count(self) -> int:
        return self._count

    @property
    def size(self) -> int:
        """已写入的字节数（含缓冲区内未落盘的数据）。"""
        return self._bytes_written + 24

    def write(self, frame: Frame) -> None:
        data = frame.data
        sec = int(frame.ts)
        usec = int((frame.ts - sec) * 1_000_000)
        if usec >= 1_000_000:  # 浮点取整越界保护
            sec += 1
            usec -= 1_000_000
        self._file.write(struct.pack(
            "<IIII", sec, usec, len(data), frame.origlen,
        ))
        self._file.write(data)
        self._count += 1
        self._bytes_written += 16 + len(data)

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        try:
            self._file.flush()
        finally:
            self._file.close()


class PcapReader:
    """经典 pcap 读取器；``frames()`` 是惰性迭代器。"""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._file = self._path.open("rb")
        header = self._file.read(24)
        if len(header) < 24:
            self._file.close()
            raise PcapError("文件太短，不是有效的 pcap 文件")

        magic = struct.unpack("<I", header[:4])[0]
        if magic == PCAPNG_MAGIC:
            self._file.close()
            raise PcapError(
                "pcapng 文件暂不支持内建解析，请用 Wireshark 另存为经典 pcap，"
                "或安装 Scapy 后重试"
            )
        variant = _MAGIC_VARIANTS.get(magic)
        if variant is None:
            self._file.close()
            raise PcapError(f"无法识别的文件格式（magic 0x{magic:08x}）")

        _, self._swap, self._nano = variant
        self._format = ">" if self._swap else "<"
        network = struct.unpack(
            self._format + "I", header[20:24]
        )[0]
        self._linktype = network
        self._caplen_scale = 1_000_000_000 if self._nano else 1_000_000

    @property
    def path(self) -> Path:
        return self._path

    @property
    def linktype(self) -> int:
        return self._linktype

    @property
    def is_nanosecond(self) -> bool:
        return self._nano

    def frames(self):
        """逐条产出 :class:`Frame`；文件损坏时停止（已读出的不丢）。"""
        fmt = self._format + "IIII"
        record_size = struct.calcsize(fmt)
        while True:
            record = self._file.read(record_size)
            if not record:
                return
            if len(record) < record_size:
                return
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(fmt, record)
            data = self._file.read(incl_len)
            if len(data) < incl_len:
                return
            ts = ts_sec + ts_frac / self._caplen_scale
            try:
                yield Frame(ts=ts, caplen=len(data), origlen=orig_len or len(data), data=data)
            except ValueError:
                continue

    def read_all(self) -> list[Frame]:
        return list(self.frames())

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def read_frames(path: Path | str) -> list[Frame]:
    """读取 pcap（或借助 Scapy 读取 pcapng）为帧列表。"""
    try:
        reader = PcapReader(path)
    except PcapError as exc:
        if "pcapng" in str(exc):
            return _read_via_scapy(path)
        raise
    try:
        return reader.read_all()
    finally:
        reader.close()


def _read_via_scapy(path: Path | str) -> list[Frame]:
    try:
        from scapy.utils import rdpcap  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        raise PcapError("读取 pcapng 需要 Scapy：python -m pip install scapy") from exc
    try:
        packets = rdpcap(str(path))
    except Exception as exc:  # noqa: BLE001
        raise PcapError(f"Scapy 读取失败：{exc}") from exc

    frames: list[Frame] = []
    for pkt in packets:
        try:
            data = bytes(pkt)
        except Exception:  # noqa: BLE001
            continue
        if not data:
            continue
        try:
            ts = float(getattr(pkt, "time", 0) or 0)
        except (TypeError, ValueError):
            ts = 0.0
        wirelen = getattr(pkt, "wirelen", None)
        origlen = int(wirelen) if isinstance(wirelen, int) and wirelen > 0 else len(data)
        frames.append(Frame(ts=ts, caplen=len(data), origlen=max(origlen, len(data)), data=data))
    return frames


class RollingPcapWriter:
    """滚动落盘：单段超过 ``max_bytes`` 自动切到新文件。

    段文件命名 ``{prefix}-{序号:04d}.pcap``；``copy_to`` 把已落盘的
    全部报文合并另存为一个文件（可边抓边存）。
    """

    def __init__(self, directory: Path | str, prefix: str, max_bytes: int = 64 * 1024 * 1024) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)
        self._prefix = prefix
        self._max_bytes = int(max_bytes)
        self._segment_index = 0
        self._current: PcapWriter | None = None
        self._total = 0

    @property
    def total_packets(self) -> int:
        return self._total

    def write(self, frame: Frame) -> None:
        if self._current is None or self._current.size >= self._max_bytes:
            self._rotate()
        assert self._current is not None
        self._current.write(frame)
        self._total += 1

    def flush(self) -> None:
        if self._current is not None:
            self._current.flush()

    def close(self) -> None:
        if self._current is not None:
            self._current.close()
            self._current = None

    def segments(self) -> list[Path]:
        pattern = f"{self._prefix}-*.pcap"
        return sorted(self._directory.glob(pattern))

    def copy_to(self, target: Path | str) -> int:
        """把全部段合并写入 ``target``，返回报文总数。"""
        target_path = Path(target)
        writer = PcapWriter(target_path)
        copied = 0
        try:
            for segment in self.segments():
                with PcapReader(segment) as reader:
                    for frame in reader.frames():
                        writer.write(frame)
                        copied += 1
            writer.flush()
        finally:
            writer.close()
        return copied

    def _rotate(self) -> None:
        if self._current is not None:
            self._current.close()
        self._segment_index += 1
        name = f"{self._prefix}-{self._segment_index:04d}.pcap"
        self._current = PcapWriter(self._directory / name)


def default_capture_dir() -> Path:
    """默认捕获目录：文档/NetScope（不存在文档目录则退回用户主目录）。"""
    home = Path.home()
    documents = home / "Documents"
    root = documents if documents.is_dir() else home
    return root / "NetScope"


def new_session_dir(base: Path | None = None, ts: float | None = None) -> Path:
    """创建本次抓包的会话目录：capture-YYYYMMDD-HHMMSS。"""
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(ts))
    directory = (base or default_capture_dir()) / f"capture-{stamp}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory
