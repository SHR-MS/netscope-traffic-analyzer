"""流量统计累加器：长度分布、三段长度、IP 版本、协议分布。

供界面统计面板使用，契约见 :class:`netscope.ui.controller.CaptureController`。

口径（与 docs/解析清单.md 一致）：
- ``length_hist``：按 **IP 分组长度**（``ParsedFrame.ip_length``）计频次；
- ``buckets``：≤46 / 47–1500 / >1500 三段的数量；
- ``ip_versions``：IPv4 / IPv6 / 其它；
- 键值数量有界（长度 ≤ 65535 或帧长上限），长时间运行内存稳定。
"""

from __future__ import annotations

from .parser import ParsedFrame

BUCKET_LE = 46
BUCKET_GT = 1500


class TrafficStats:
    """累积统计；``snapshot()`` 返回界面契约要求的 dict。"""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._hist: dict[int, int] = {}
        self._le46 = 0
        self._mid = 0
        self._gt1500 = 0
        self._versions = [0, 0, 0]          # IPv4 / IPv6 / 其它
        self._protocols: dict[str, int] = {}
        self._bytes = 0
        self._count = 0

    # ---------------------------------------------------------------- 累计
    def add(self, parsed: ParsedFrame) -> None:
        length = parsed.ip_length
        self._hist[length] = self._hist.get(length, 0) + 1
        if length <= BUCKET_LE:
            self._le46 += 1
        elif length <= BUCKET_GT:
            self._mid += 1
        else:
            self._gt1500 += 1

        version = parsed.ip_version
        index = 0 if version == 4 else 1 if version == 6 else 2
        self._versions[index] += 1

        protocol = parsed.protocol
        self._protocols[protocol] = self._protocols.get(protocol, 0) + 1

        self._bytes += parsed.frame.origlen
        self._count += 1

    # ---------------------------------------------------------------- 快照
    def snapshot(self) -> dict:
        return {
            "length_hist": dict(self._hist),
            "buckets": (self._le46, self._mid, self._gt1500),
            "ip_versions": tuple(self._versions),
            "protocol_counts": dict(self._protocols),
            "total_bytes": self._bytes,
            "total_packets": self._count,
        }

    @property
    def total_packets(self) -> int:
        return self._count
