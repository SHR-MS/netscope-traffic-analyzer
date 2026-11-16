"""报文列表的数据结构、表格模型与显示过滤器。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

COLUMNS = ["序号", "时间", "源地址", "目的地址", "协议", "长度", "信息"]

PROTOCOL_COLORS = {
    "TCP": "#1d4ed8",
    "UDP": "#047857",
    "ICMP": "#b45309",
    "ICMPv6": "#b45309",
    "ARP": "#7c3aed",
    "IGMP": "#64748b",
}


@dataclass(slots=True)
class PacketRow:
    """界面显示的一条报文；由后端解析后填充。"""

    seq: int
    ts: float                      # 抓包时间戳（epoch 秒）
    src: str
    dst: str
    protocol: str                  # TCP / UDP / ICMP / ARP ...
    length: int                    # 网络层分组长度（用于统计）
    info: str                      # 摘要，如 "51432 → 443 [SYN]"
    raw: bytes = b""               # 原始字节，供十六进制视图
    layers: list[tuple[str, list[tuple[str, str]]]] = field(default_factory=list)
    version: int = 0               # 4 / 6 / 0（非 IP）


def format_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


class PacketTableModel(QAbstractTableModel):
    """只保留最近 N 条，避免长时间运行内存无限增长。"""

    MAX_ROWS = 5000

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[PacketRow] = []

    # ------------------------------------------------------------ Qt 接口
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return str(row.seq)
            if column == 1:
                return format_time(row.ts)
            if column == 2:
                return row.src
            if column == 3:
                return row.dst
            if column == 4:
                return row.protocol
            if column == 5:
                return str(row.length)
            if column == 6:
                return row.info
        elif role == Qt.ItemDataRole.ForegroundRole and column == 4:
            color = PROTOCOL_COLORS.get(row.protocol)
            return QColor(color) if color else None
        elif role == Qt.ItemDataRole.TextAlignmentRole and column in (0, 5):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        elif role == Qt.ItemDataRole.ToolTipRole:
            return f"{row.protocol}  {row.length} B\n{row.info}"
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return int(Qt.AlignmentFlag.AlignCenter)
        return None

    # ------------------------------------------------------------ 数据操作
    def append_rows(self, rows: list[PacketRow]) -> None:
        if not rows:
            return

        overflow = max(0, len(self._rows) + len(rows) - self.MAX_ROWS)
        if overflow:
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            del self._rows[:overflow]
            self.endRemoveRows()

        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
        self._rows.extend(rows)
        self.endInsertRows()

    def row_at(self, source_row: int) -> PacketRow | None:
        if 0 <= source_row < len(self._rows):
            return self._rows[source_row]
        return None

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()


class PacketFilterProxy(QSortFilterProxyModel):
    """显示过滤器：在源/目的/协议/摘要里做子串匹配（不区分大小写）。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._needle = ""

    def set_filter(self, text: str) -> None:
        needle = (text or "").strip().lower()
        if needle != self._needle:
            self._needle = needle
            self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if not self._needle:
            return True
        model = self.sourceModel()
        row = model.row_at(source_row) if hasattr(model, "row_at") else None
        if row is None:
            return True
        haystack = f"{row.src} {row.dst} {row.protocol} {row.info}".lower()
        return self._needle in haystack
