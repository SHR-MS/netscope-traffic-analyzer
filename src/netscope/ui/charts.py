"""轻量图表控件：长度分布折线图、柱状图。

不依赖 QtCharts / pyqtgraph，直接用 QPainter 绘制，减少额外依赖。
真实数据由控制器通过 stats 信号提供，这里只负责画。
"""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

GRID_COLOR = "#e5e9ef"
TEXT_COLOR = "#64748b"
EMPTY_COLOR = "#94a3b8"


class _ChartBase(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(160)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMouseTracking(True)

    def _draw_empty(self, painter: QPainter) -> None:
        painter.setPen(QColor(EMPTY_COLOR))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "暂无数据")


class LineChart(_ChartBase):
    """按长度统计频次的折线图，支持线性/对数纵轴。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._points: list[tuple[int, int]] = []   # (bin_index, count)
        self._bin_size = 8
        self._x_max = 1600
        self._log = True

    def set_histogram(self, hist: dict[int, int], bin_size: int = 8, x_max: int | None = None) -> None:
        raw_hist = {}
        for length, count in (hist or {}).items():
            try:
                length = int(length)
                count = int(count)
            except (TypeError, ValueError):
                continue
            if length <= 0 or count <= 0:
                continue
            raw_hist[length] = raw_hist.get(length, 0) + count

        if x_max is None:
            max_len = max(raw_hist) if raw_hist else 0
            # 只展示实际出现过的长度范围，避免小包全挤在坐标轴最左边
            x_max = max(120, min(9000, ((max_len // 50) + 1) * 50))

        bins: dict[int, int] = {}
        for length, count in raw_hist.items():
            key = min(length // bin_size, max(1, x_max // bin_size))
            bins[key] = bins.get(key, 0) + count

        self._bin_size = bin_size
        self._x_max = x_max
        self._points = sorted(bins.items())
        self.update()

    def set_log(self, enabled: bool) -> None:
        self._log = bool(enabled)
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), QColor("#ffffff"))

        if not self._points:
            self._draw_empty(painter)
            painter.end()
            return

        plot = QRectF(self.rect()).adjusted(52, 18, -14, -32)
        if plot.width() < 30 or plot.height() < 30:
            painter.end()
            return

        max_count = max(count for _, count in self._points)
        y_max = math.log10(max_count + 1) if self._log else float(max_count)
        y_max = y_max or 1.0

        small = QFont(self.font().family(), 8)
        grid_pen = QPen(QColor(GRID_COLOR))
        grid_pen.setWidthF(1.0)
        text_pen = QColor(TEXT_COLOR)

        # 横向网格 + 纵轴刻度
        for step in range(5):
            ratio = step / 4
            y = plot.bottom() - plot.height() * ratio
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))

            if self._log:
                value = 10 ** (y_max * ratio) - 1
            else:
                value = y_max * ratio
            painter.setPen(text_pen)
            painter.setFont(small)
            painter.drawText(
                QRectF(plot.left() - 48, y - 8, 42, 16),
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                f"{int(round(value)):,}",
            )

        # 横轴
        painter.setPen(grid_pen)
        painter.drawLine(QPointF(plot.left(), plot.bottom()), QPointF(plot.right(), plot.bottom()))
        for step in range(5):
            x_value = int(self._x_max * step / 4)
            x = plot.left() + plot.width() * step / 4
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(x, plot.bottom()), QPointF(x, plot.bottom() + 4))
            painter.setPen(text_pen)
            painter.setFont(small)
            painter.drawText(
                QRectF(x - 24, plot.bottom() + 6, 48, 14),
                int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop),
                str(x_value),
            )
        painter.setPen(text_pen)
        painter.setFont(small)
        painter.drawText(
            QRectF(plot.right() - 60, plot.bottom() + 18, 60, 14),
            int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignTop),
            "长度 (B)",
        )

        # 折线与填充
        points: list[QPointF] = []
        for bin_index, count in self._points:
            x = plot.left() + (bin_index * self._bin_size / self._x_max) * plot.width()
            raw = math.log10(count + 1) if self._log else count
            y = plot.bottom() - (raw / y_max) * plot.height()
            points.append(QPointF(x, y))

        if len(points) >= 2:
            polygon = QPolygonF(points)
            polygon.append(QPointF(points[-1].x(), plot.bottom()))
            polygon.append(QPointF(points[0].x(), plot.bottom()))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(37, 99, 235, 26))
            painter.drawPolygon(polygon)
            painter.setBrush(Qt.BrushStyle.NoBrush)

        line_pen = QPen(QColor("#2563eb"))
        line_pen.setWidthF(1.6)
        painter.setPen(line_pen)
        painter.drawPolyline(QPolygonF(points))
        painter.end()


class BarChart(_ChartBase):
    """通用柱状图：三段长度、IP 版本等。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._labels: list[str] = []
        self._values: list[int] = []
        self._colors: list[str] = []
        self._hitboxes: list[tuple[QRectF, str, int]] = []

    def set_values(self, labels: list[str], values: list[int], colors: list[str] | None = None) -> None:
        self._labels = [str(label) for label in labels]
        self._values = [int(value) for value in values]
        if colors and len(colors) >= len(self._values):
            self._colors = [str(color) for color in colors]
        else:
            palette = ["#2563eb", "#0891b2", "#94a3b8", "#7c3aed", "#f59e0b"]
            self._colors = [palette[index % len(palette)] for index in range(len(self._values))]
        self.update()

    def _draw_value(self, painter: QPainter, rect: QRectF, value: int, color: str, font: QFont) -> None:
        painter.setFont(font)
        painter.setPen(QColor(color))
        painter.drawText(
            QRectF(rect.left() - 10, rect.top() - 18, rect.width() + 20, 16),
            int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom),
            f"{value:,}",
        )

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), QColor("#ffffff"))

        if not self._values:
            self._draw_empty(painter)
            painter.end()
            return

        plot = QRectF(self.rect()).adjusted(46, 26, -16, -30)
        if plot.width() < 30 or plot.height() < 30:
            painter.end()
            return

        v_max = max(self._values) or 1
        small = QFont(self.font().family(), 8)
        label_font = QFont(self.font().family(), 8)
        text_color = QColor(TEXT_COLOR)
        grid_pen = QPen(QColor(GRID_COLOR))
        grid_pen.setWidthF(1.0)

        for step in range(5):
            ratio = step / 4
            y = plot.bottom() - plot.height() * ratio
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(text_color)
            painter.setFont(small)
            painter.drawText(
                QRectF(plot.left() - 42, y - 8, 36, 16),
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                f"{int(round(v_max * ratio)):,}",
            )

        self._hitboxes = []
        count = len(self._values)
        slot = plot.width() / count
        bar_width = min(76.0, slot * 0.52)

        for index, value in enumerate(self._values):
            height = plot.height() * value / v_max if v_max else 0.0
            bar = QRectF(
                plot.left() + slot * index + (slot - bar_width) / 2,
                plot.bottom() - height,
                bar_width,
                max(height, 1.0),
            )
            color = self._colors[index]
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(bar, 3, 3)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            self._draw_value(painter, bar, value, color, label_font)

            painter.setPen(text_color)
            painter.setFont(small)
            painter.drawText(
                QRectF(plot.left() + slot * index, plot.bottom() + 6, slot, 16),
                int(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop),
                self._labels[index],
            )
            self._hitboxes.append((bar.adjusted(-6, -20, 6, 6), self._labels[index], value))

        painter.end()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        position = event.position()
        for rect, label, value in self._hitboxes:
            if rect.contains(position):
                QToolTip.showText(
                    event.globalPosition().toPoint(),
                    f"{label}：{value:,} 个",
                    self,
                )
                return
        QToolTip.hideText()
        super().mouseMoveEvent(event)
