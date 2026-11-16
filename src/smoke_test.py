"""界面冒烟测试：不接后端，构造主窗口跑 2 秒演示数据。

用法::

    python src/smoke_test.py              # 无显示环境（offscreen）
    python src/smoke_test.py --show       # 真正弹出窗口看一眼
    python src/smoke_test.py --shot out.png

主要验证：窗口能构造、模型能收数据、详情树/图表/告警控件不报错。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    argv = sys.argv[1:]
    shot = ""
    if "--shot" in argv:
        index = argv.index("--shot")
        if index + 1 < len(argv):
            shot = argv[index + 1]

    if "--show" not in argv:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtCore import QTimer
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication

    try:
        from netscope.ui.main_window import MainWindow
        from netscope.ui.style import apply_theme
    except ImportError as exc:
        print(f"无法导入界面：{exc}")
        print("请先安装依赖：python -m pip install -r requirements.txt")
        return 2

    app = QApplication(["smoke"])
    app.setFont(QFont("Microsoft YaHei UI", 9))
    apply_theme(app)
    window = MainWindow(demo=True)
    window.show()

    def finish() -> None:
        if shot:
            window.grab().save(shot)
            print(f"截图已保存：{shot}")
        app.quit()

    QTimer.singleShot(2200, finish)
    app.exec()

    print(f"列表行数：{window.model.rowCount()}")
    print(f"告警行数：{window.alerts.rowCount()}")
    print(f"当前图表页：{window.tabs.currentIndex()}")
    print("SMOKE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
