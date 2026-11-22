"""pcap 读写与滚动落盘测试。"""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from netscope.core.models import Frame
from netscope.core.pcapio import (
    PcapError,
    PcapReader,
    PcapWriter,
    RollingPcapWriter,
    read_frames,
)

DATA = bytes.fromhex("00112233445566778899aabb08004500") + b"\x00" * 26


def sample_frame(ts: float = 1700000000.123456, origlen: int | None = None) -> Frame:
    return Frame(
        ts=ts,
        caplen=len(DATA),
        origlen=origlen or len(DATA),
        data=DATA,
    )


class PcapRoundTripTests(unittest.TestCase):
    def test_write_read_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.pcap"
            writer = PcapWriter(path)
            frames = [
                sample_frame(1700000000.1, origlen=100),
                sample_frame(1700000001.25),
                sample_frame(1700000002.999999),
            ]
            for frame in frames:
                writer.write(frame)
            writer.close()

            self.assertGreater(path.stat().st_size, 24 + 3 * 16)

            read = read_frames(path)
            self.assertEqual(len(read), 3)
            self.assertEqual(read[0].data, DATA)
            self.assertEqual(read[0].origlen, 100)
            self.assertEqual(read[0].caplen, len(DATA))
            self.assertAlmostEqual(read[0].ts, 1700000000.1, places=5)
            self.assertAlmostEqual(read[2].ts, 1700000002.999999, places=5)

    def test_reader_handles_big_endian_file(self) -> None:
        # 手工构造大端（magic 0xa1b2c3d4 大端写入）文件
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "be.pcap"
            payload = sample_frame(1700000000.5)
            with path.open("wb") as f:
                f.write(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                f.write(struct.pack(">IIII", 1700000000, 500000, len(payload.data), payload.origlen))
                f.write(payload.data)

            read = read_frames(path)
            self.assertEqual(len(read), 1)
            self.assertAlmostEqual(read[0].ts, 1700000000.5, places=5)

    def test_truncated_file_is_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.pcap"
            writer = PcapWriter(path)
            writer.write(sample_frame())
            writer.close()
            # 掐掉最后 5 字节，读取不应抛异常
            data = path.read_bytes()
            path.write_bytes(data[:-5])

            read = read_frames(path)
            self.assertEqual(len(read), 0)

    def test_bad_magic_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.pcap"
            path.write_bytes(b"\xde\xad\xbe\xef" + b"\x00" * 20)
            with self.assertRaises(PcapError):
                read_frames(path)

    def test_short_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "short.pcap"
            path.write_bytes(b"\x00" * 10)
            with self.assertRaises(PcapError):
                read_frames(path)


class RollingWriterTests(unittest.TestCase):
    def test_rotation_and_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "session"
            rolling = RollingPcapWriter(directory, "capture", max_bytes=1024)
            frames = [sample_frame(1700000000.0 + index) for index in range(30)]
            for frame in frames:
                rolling.write(frame)
            rolling.close()

            segments = rolling.segments()
            self.assertGreater(len(segments), 1)

            merged = Path(tmp) / "merged.pcap"
            copied = rolling.copy_to(merged)
            self.assertEqual(copied, 30)

            read = read_frames(merged)
            self.assertEqual(len(read), 30)
            self.assertEqual(read[0].data, DATA)
            self.assertEqual(read[-1].data, DATA)

    def test_copy_while_writing(self) -> None:
        # 边写边另存：已落盘的数据应完整可读
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "session"
            rolling = RollingPcapWriter(directory, "capture", max_bytes=10 * 1024 * 1024)
            for frame in [sample_frame(1700000000.0 + index) for index in range(10)]:
                rolling.write(frame)
            rolling.flush()

            merged = Path(tmp) / "snapshot.pcap"
            copied = rolling.copy_to(merged)
            self.assertEqual(copied, 10)

            rolling.write(sample_frame(1700000010.0))
            rolling.close()
            self.assertEqual(rolling.total_packets, 11)


if __name__ == "__main__":
    unittest.main()
