"""界面与抓包后端之间的接口层。

界面只依赖这里定义的信号和数据结构，不直接碰 Scapy / pcap。
真实后端接入时，继承 :class:`CaptureController`，把解析结果转换成
``PacketRow`` / ``stats`` / ``alert`` 发出来即可（见 src/README.md）。
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal


@dataclass(frozen=True, slots=True)
class DeviceOption:
    """下拉框里的一个网卡选项。"""

    key: str          # 传给后端的设备名，如 \Device\NPF_{GUID}
    label: str        # 界面上显示的文字


class CaptureController(QObject):
    """抓包后端接口（UI 侧契约）。

    信号约定::

        packets_received(list[PacketRow])   一批新报文
        stats_updated(dict)                 统计快照，键见下
        state_changed(str, str)             状态 + 说明
        alert_raised(dict)                  一条告警

    ``stats`` 至少包含::

        received, displayed, dropped, pps, mbps, uptime_s,
        length_hist: dict[int, int],        # 长度 -> 次数
        buckets: tuple[int, int, int],      # ≤46 / 47-1500 / >1500
        ip_versions: tuple[int, int, int],  # IPv4 / IPv6 / 其它

    ``alert`` 至少包含::

        time: float, rule: str, severity: str,
        target: str, evidence: str, count: int
    """

    packets_received = Signal(list)
    stats_updated = Signal(dict)
    state_changed = Signal(str, str)
    alert_raised = Signal(dict)

    #: 是否演示数据源；界面会据此显示"演示数据"标记
    demo: bool = False

    # ---------------------------------------------------------------- 设备
    def list_devices(self) -> list[DeviceOption]:
        return []

    # ---------------------------------------------------------------- 抓包
    def start(self, device_key: str, bpf: str = "") -> None:
        raise NotImplementedError("抓包后端尚未接入")

    def stop(self) -> None:
        raise NotImplementedError("抓包后端尚未接入")

    # ---------------------------------------------------------------- 文件
    def save_as(self, path: str) -> None:
        raise NotImplementedError("文件保存后端尚未接入")

    def open_file(self, path: str) -> None:
        raise NotImplementedError("文件读取后端尚未接入")

    def session_dir(self):
        """本次捕获的自动落盘目录；未捕获时返回 None。"""
        return None

    # ---------------------------------------------------------------- 退出
    def shutdown(self) -> None:
        """主窗口关闭时调用，释放线程/句柄。"""
