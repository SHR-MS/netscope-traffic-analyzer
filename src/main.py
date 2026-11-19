"""NetScope GUI 入口。

用法::

    python src/main.py            # 真实抓包（需要 Npcap + 管理员）
    python src/main.py --demo     # 演示数据，只看界面
    python src/main.py --list     # 只列出网卡，不开界面
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


def _list_devices() -> int:
    from netscope.core.capture import ScapyBackend

    try:
        devices = ScapyBackend().list_devices()
    except Exception as exc:  # noqa: BLE001
        print(f"枚举网卡失败：{exc}")
        return 2

    if not devices:
        print("没有找到可用网卡。")
        return 2

    print(f"共 {len(devices)} 块网卡：")
    for index, device in enumerate(devices, start=1):
        print(f"{index:>2}. {device.display()}")
        print(f"    key: {device.key}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)

    if "--list" in argv:
        return _list_devices()

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

    window = MainWindow(demo="--demo" in argv)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
