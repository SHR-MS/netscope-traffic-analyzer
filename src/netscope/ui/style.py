"""浅色主题样式表（接近 Wireshark 的清爽风格）。"""

from __future__ import annotations

from PySide6.QtGui import QColor, QPalette

STYLE_SHEET = """
QMainWindow {
    background: #f5f7fa;
}
QMenuBar {
    background: #ffffff;
    border-bottom: 1px solid #e2e8f0;
    padding: 2px 4px;
}
QMenuBar::item {
    padding: 4px 10px;
    background: transparent;
    border-radius: 4px;
}
QMenuBar::item:selected {
    background: #eef2f7;
}
QMenu {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    padding: 4px;
}
QMenu::item {
    padding: 5px 24px 5px 12px;
    border-radius: 4px;
}
QMenu::item:selected {
    background: #eef2f7;
}
QToolBar {
    background: #ffffff;
    border: none;
    border-bottom: 1px solid #dfe3e8;
    spacing: 4px;
    padding: 3px 8px;
}
QToolBar QLabel {
    color: #475569;
}
QToolButton {
    padding: 4px 7px;
    border-radius: 4px;
    background: transparent;
}
QToolButton:hover {
    background: #eef2f7;
}
QToolButton:pressed {
    background: #e2e8f0;
}
QToolButton:disabled {
    color: #cbd5e1;
}
QLineEdit, QComboBox {
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 3px 6px;
    background: #ffffff;
    selection-background-color: #bfdbfe;
}
QLineEdit:focus, QComboBox:focus {
    border-color: #60a5fa;
}
QComboBox::drop-down {
    border: none;
    width: 18px;
}
QTableView, QTableWidget {
    background: #ffffff;
    alternate-background-color: #f8fafc;
    gridline-color: #eef2f7;
    selection-background-color: #dbeafe;
    selection-color: #0f172a;
    border: 1px solid #e2e8f0;
}
QHeaderView::section {
    background: #f1f5f9;
    color: #334155;
    padding: 4px 6px;
    border: none;
    border-right: 1px solid #e2e8f0;
    border-bottom: 1px solid #e2e8f0;
    font-weight: 600;
}
QTreeWidget, QPlainTextEdit {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    selection-background-color: #dbeafe;
    selection-color: #0f172a;
}
QTabWidget::pane {
    border: 1px solid #e2e8f0;
    background: #ffffff;
    top: -1px;
}
QTabBar::tab {
    background: #eef2f7;
    color: #475569;
    padding: 5px 12px;
    border: 1px solid #e2e8f0;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #0f172a;
}
QStatusBar {
    background: #ffffff;
    border-top: 1px solid #dfe3e8;
}
QStatusBar QLabel {
    color: #475569;
    padding: 0 6px;
}
QDockWidget::title {
    background: #f1f5f9;
    padding: 6px;
    border-bottom: 1px solid #e2e8f0;
}
QSplitter::handle {
    background: #eef2f7;
}
QSplitter::handle:horizontal {
    width: 3px;
}
QSplitter::handle:vertical {
    height: 3px;
}
QCheckBox {
    color: #475569;
    spacing: 5px;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #cbd5e1;
    border-radius: 4px;
    min-height: 24px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
}
QScrollBar::handle:horizontal {
    background: #cbd5e1;
    border-radius: 4px;
    min-width: 24px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}
QToolTip {
    background: #0f172a;
    color: #f8fafc;
    border: none;
    padding: 4px 6px;
}
"""


def light_palette() -> QPalette:
    """显式浅色调色板，避免 Windows 深色模式把未覆盖的控件染黑。"""
    palette = QPalette()
    window = QColor("#f5f7fa")
    base = QColor("#ffffff")
    text = QColor("#0f172a")
    palette.setColor(QPalette.ColorRole.Window, window)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#dbeafe"))
    palette.setColor(QPalette.ColorRole.HighlightedText, text)
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#0f172a"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#94a3b8"))
    return palette


def apply_theme(app) -> None:
    """统一入口：Fusion 风格 + 浅色调色板 + QSS。"""
    app.setStyle("Fusion")
    app.setPalette(light_palette())
    app.setStyleSheet(STYLE_SHEET)
