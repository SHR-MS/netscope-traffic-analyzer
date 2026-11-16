"""详情树、十六进制视图、告警表格。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
)

from .models import PacketRow, format_time


class DetailTree(QTreeWidget):
    """三层字段详情（数据链路层 / 网络层 / 传输层 + 附加信息）。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(["字段", "值"])
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setRootIsDecorated(True)
        header = self.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.setColumnWidth(0, 260)
        self.setIndentation(16)

    def show_packet(self, row: PacketRow | None) -> None:
        self.clear()
        if row is None:
            return

        root = QTreeWidgetItem([f"帧 #{row.seq}", f"{len(row.raw)} B"])
        self.addTopLevelItem(root)

        summary = QTreeWidgetItem(["帧信息", ""])
        summary.addChild(QTreeWidgetItem(["时间", format_time(row.ts)]))
        summary.addChild(QTreeWidgetItem(["长度", f"{row.length} B"]))
        summary.addChild(QTreeWidgetItem(["协议", row.protocol]))
        root.addChild(summary)

        for layer_name, fields in row.layers:
            layer = QTreeWidgetItem([layer_name, ""])
            font = layer.font(0)
            font.setBold(True)
            layer.setFont(0, font)
            for key, value in fields:
                layer.addChild(QTreeWidgetItem([key, str(value)]))
            root.addChild(layer)

        self.expandAll()


class HexView(QPlainTextEdit):
    """按 16 字节一行显示原始报文。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        font = QFont("Consolas", 9)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setPlaceholderText("选中一条报文后，这里显示它的十六进制内容")
        self.setMinimumWidth(320)

    def set_data(self, data: bytes) -> None:
        if not data:
            self.clear()
            return
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk)
            text_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
            lines.append(f"{offset:08x}  {hex_part:<47}  {text_part}")
        self.setPlainText("\n".join(lines))


SEVERITY_COLORS = {
    "critical": ("#b91c1c", "#fef2f2"),
    "warning": ("#b45309", "#fffbeb"),
    "info": ("#1d4ed8", "#eff6ff"),
}


class AlertsView(QTableWidget):
    """告警列表，最新一条在最上面。"""

    MAX_ROWS = 500

    def __init__(self, parent=None) -> None:
        super().__init__(0, 6, parent)
        self.setHorizontalHeaderLabels(["时间", "规则", "级别", "目标", "证据", "次数"])
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

    def add_alert(self, alert: dict) -> None:
        self.insertRow(0)
        timestamp = alert.get("time")
        time_text = format_time(float(timestamp)) if timestamp else "-"
        values = [
            time_text,
            str(alert.get("rule", "-")),
            str(alert.get("severity", "-")),
            str(alert.get("target", "-")),
            str(alert.get("evidence", "")),
            str(alert.get("count", 1)),
        ]
        foreground, background = SEVERITY_COLORS.get(
            str(alert.get("severity", "")), ("#334155", "#ffffff")
        )
        for column, text in enumerate(values):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(foreground))
            item.setBackground(QColor(background))
            if column in (2, 5):
                item.setTextAlignment(int(Qt.AlignmentFlag.AlignCenter))
            self.setItem(0, column, item)
        self.setRowHeight(0, 22)

        while self.rowCount() > self.MAX_ROWS:
            self.removeRow(self.rowCount() - 1)
