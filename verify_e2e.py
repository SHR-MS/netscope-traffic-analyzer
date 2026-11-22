"""端到端功能验证（带异常捕获与看门狗）。"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from netscope.ui.main_window import MainWindow
from netscope.ui.style import apply_theme

app = QApplication(["verify"])
apply_theme(app)
window = MainWindow(demo=True)
window.show()

result: dict = {"alerts": [], "rows": 0, "stats": None, "saved": 0, "replayed": 0, "stage": "init"}
window.controller.alert_raised.connect(lambda a: result["alerts"].append(a))
window.controller.stats_updated.connect(lambda s: result.__setitem__("stats", s))

tmpdir = tempfile.mkdtemp(prefix="netscope-e2e-")
save_path = Path(tmpdir) / "demo.pcap"


def safe(fn, stage: str):
    def wrapped() -> None:
        result["stage"] = stage
        try:
            fn()
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            print(f"[FAIL at stage {stage}]")
            app.quit()
    return wrapped


def phase1() -> None:
    QTimer.singleShot(2500, phase2)


def phase2() -> None:
    result["rows"] = window.model.rowCount()
    controller = window.controller
    controller._burst_kinds = ["syn_flood", "icmp_flood", "orphan_reply", "big_echo"]
    controller._burst_index = 0
    controller._begin_burst()
    QTimer.singleShot(2500, phase3)


def phase3() -> None:
    result["alerts_seen"] = [alert["rule"] for alert in result["alerts"]]
    window.controller.save_as(str(save_path))
    result["saved"] = save_path.stat().st_size
    window._clear_all()
    window.controller.open_file(str(save_path))
    QTimer.singleShot(1500, finish)


def finish() -> None:
    result["replayed"] = window.model.rowCount()
    stats = result["stats"] or {}
    print("--- 验证结果 ---")
    print(f"普通流量列表行数: {result['rows']}")
    print(f"告警: {result['alerts_seen']}")
    print(f"统计快照 buckets: {stats.get('buckets')}")
    print(f"统计快照 ip_versions: {stats.get('ip_versions')}")
    print(f"length_hist 条目数: {len(stats.get('length_hist', {}))}")
    print(f"另存文件大小: {result['saved']} B @ {save_path}")
    print(f"回放后列表行数: {result['replayed']}")
    shutil.rmtree(tmpdir, ignore_errors=True)
    app.quit()


phase1 = safe(phase1, "phase1")
phase2 = safe(phase2, "phase2")
phase3 = safe(phase3, "phase3")
finish = safe(finish, "finish")

QTimer.singleShot(1500, phase1)
QTimer.singleShot(20000, lambda: (print(f"[TIMEOUT at stage {result['stage']}]"), app.quit()))
app.exec()

ok = (
    result["rows"] > 0
    and "SYN_FLOOD" in result.get("alerts_seen", [])
    and bool((result["stats"] or {}).get("length_hist"))
    and result["saved"] > 24
    and result["replayed"] > 0
)
print("E2E:", "PASS" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
