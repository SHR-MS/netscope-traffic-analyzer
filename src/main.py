"""NetScope GUI 入口。

用法::

    python src/main.py            # 默认加载演示数据
    python src/main.py --no-demo  # 空界面，等待后端接入
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _missing_pyside() -> int:
    print("未安装 PySide6，无法启动图形界面。")
    print("请在终端执行：python -m pip install PySide6")
    return 2


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)

    try:
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QFont, QGuiApplication
        from PySide6.QtWidgets import QApplication
    except ImportError:
        return _missing_pyside()

    if hasattr(QGuiApplication, "setHighDpiScaleFactorRoundingPolicy"):
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

    app = QApplication([argv[0]] if argv else ["netscope"])
    app.setApplicationName("NetScope")
    app.setOrganizationName("NetScope")
    app.setFont(QFont("Microsoft YaHei UI", 9))

    from netscope.ui.style import apply_theme

    apply_theme(app)

    from netscope.ui.main_window import MainWindow

    window = MainWindow(demo="--no-demo" not in argv)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
