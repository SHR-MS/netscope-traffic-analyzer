"""主窗口：仿抓包软件的列表 + 详情 + 十六进制 + 统计面板布局。

界面只通过 :class:`CaptureController` 的信号拿数据；
默认接真实采集（:class:`LiveController`），``--demo`` 时用演示数据源。

长时间运行（1 天以上）支持：
- 状态栏实时显示运行时长与开始时间；
- 每秒采样本进程 CPU / 内存占用，每 5 秒写入捕获目录下的
  ``资源占用.csv``，供"观察并记录系统消耗资源"的实验报告使用；
- 报文列表、告警、统计均有界，原始数据滚动落盘，内存不随运行增长。
"""

from __future__ import annotations

import csv
import time
from pathlib import Path

from PySide6.QtCore import QModelIndex, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStyle,
    QTabWidget,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from .charts import BarChart, LineChart
from .controller import CaptureController
from .demo import DemoController
from .live_controller import LiveController
from .models import PacketFilterProxy, PacketRow, PacketTableModel
from .widgets import AlertsView, DetailTree, HexView

try:
    import psutil as _psutil
except ImportError:  # psutil 是可选依赖，缺失时资源面板显示提示
    _psutil = None

RESOURCE_SAMPLE_S = 5  # 资源占用 CSV 的写入间隔（秒）


class MainWindow(QMainWindow):
    def __init__(self, controller: CaptureController | None = None, demo: bool = False, parent=None) -> None:
        super().__init__(parent)
        if controller is not None:
            self.controller = controller
        elif demo:
            self.controller = DemoController(self)
        else:
            self.controller = LiveController(parent=self)

        self._alert_count = 0
        self._follow = True
        self._pinned = False        # 用户是否手动钉住了某一行
        self._auto_selecting = False
        self._stats: dict = {}
        self._capturing = False
        self._resource_csv = None          # 打开中的资源占用 CSV 文件
        self._resource_writer = None
        self._resource_csv_started = 0.0
        self._resource_rows_written = 0
        self._process = None               # psutil.Process
        self._proc_cpu_total = 0.0
        self._proc_samples = 0

        self.setWindowTitle("NetScope 网络流量分析系统")
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.resize(1360, 860)
        self.setMinimumSize(1024, 680)
        self.setDockNestingEnabled(False)

        self._build_actions()
        self._build_menu()
        self._build_toolbar()
        self._build_central()
        self._build_dock()
        self._build_statusbar()
        self._wire()
        self._refresh_devices()
        self._update_state("idle", "")

        self._resource_timer = QTimer(self)
        self._resource_timer.setInterval(1000)
        self._resource_timer.timeout.connect(self._on_resource_tick)
        self._resource_timer.start()

        if self.controller.demo:
            QTimer.singleShot(350, self._on_start)

    # ================================================================ 构建
    def _build_actions(self) -> None:
        style = self.style()

        self.act_start = QAction(style.standardIcon(QStyle.StandardPixmap.SP_MediaPlay), "开始", self)
        self.act_start.setShortcut(QKeySequence("F5"))
        self.act_start.setToolTip("开始抓包（F5）")
        self.act_start.triggered.connect(self._on_start)

        self.act_stop = QAction(style.standardIcon(QStyle.StandardPixmap.SP_MediaStop), "停止", self)
        self.act_stop.setShortcut(QKeySequence("Shift+F5"))
        self.act_stop.setToolTip("停止抓包（Shift+F5）")
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self._on_stop)

        self.act_open = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogOpenButton), "打开...", self)
        self.act_open.setShortcut(QKeySequence("Ctrl+O"))
        self.act_open.triggered.connect(self._on_open)

        self.act_save = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogSaveButton), "另存为...", self)
        self.act_save.setShortcut(QKeySequence("Ctrl+S"))
        self.act_save.triggered.connect(self._on_save)

        self.act_capture_dir = QAction("打开捕获目录...", self)
        self.act_capture_dir.setEnabled(False)
        self.act_capture_dir.triggered.connect(self._on_open_capture_dir)

        self.act_refresh = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), "刷新网卡", self)
        self.act_refresh.triggered.connect(self._refresh_devices)

        self.act_clear = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DialogResetButton), "清空列表", self)
        self.act_clear.triggered.connect(self._clear_all)

        self.act_quit = QAction("退出", self)
        self.act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        self.act_quit.triggered.connect(self.close)

        self.act_dock = QAction("统计面板", self)
        self.act_dock.setCheckable(True)
        self.act_dock.setChecked(True)

        self.act_hex = QAction("十六进制", self)
        self.act_hex.setCheckable(True)
        self.act_hex.setChecked(True)

        self.act_about = QAction("关于", self)
        self.act_about.triggered.connect(self._show_about)

        self.act_usage = QAction("使用说明", self)
        self.act_usage.triggered.connect(self._show_usage)

    def _build_menu(self) -> None:
        bar = self.menuBar()

        file_menu = bar.addMenu("文件(&F)")
        file_menu.addAction(self.act_open)
        file_menu.addAction(self.act_save)
        file_menu.addSeparator()
        file_menu.addAction(self.act_capture_dir)
        file_menu.addSeparator()
        file_menu.addAction(self.act_quit)

        capture_menu = bar.addMenu("抓包(&C)")
        capture_menu.addAction(self.act_start)
        capture_menu.addAction(self.act_stop)
        capture_menu.addSeparator()
        capture_menu.addAction(self.act_refresh)
        capture_menu.addAction(self.act_clear)

        view_menu = bar.addMenu("视图(&V)")
        view_menu.addAction(self.act_dock)
        view_menu.addAction(self.act_hex)

        help_menu = bar.addMenu("帮助(&H)")
        help_menu.addAction(self.act_usage)
        help_menu.addAction(self.act_about)

    def _build_toolbar(self) -> None:
        toolbar = QToolBar("主工具栏", self)
        toolbar.setObjectName("mainToolBar")
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(18, 18))
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel(" 网卡 "))
        self.device_combo = QComboBox(self)
        self.device_combo.setMinimumWidth(250)
        toolbar.addWidget(self.device_combo)

        toolbar.addSeparator()
        toolbar.addAction(self.act_start)
        toolbar.addAction(self.act_stop)
        toolbar.addSeparator()
        toolbar.addAction(self.act_open)
        toolbar.addAction(self.act_save)
        toolbar.addSeparator()

        toolbar.addWidget(QLabel(" 显示过滤 "))
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText("如 tcp / 192.168 / arp")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.setMinimumWidth(220)
        self.filter_edit.setMaximumWidth(360)
        toolbar.addWidget(self.filter_edit)

    def _build_central(self) -> None:
        self.model = PacketTableModel(self)
        self.proxy = PacketFilterProxy(self)
        self.proxy.setSourceModel(self.model)

        self.table = QTableView(self)
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(23)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((70, 105, 150, 150, 70, 70)):
            self.table.setColumnWidth(column, width)

        self.detail = DetailTree(self)
        self.hex = HexView(self)

        bottom = QSplitter(Qt.Orientation.Horizontal, self)
        bottom.addWidget(self.detail)
        bottom.addWidget(self.hex)
        bottom.setSizes([640, 480])
        bottom.setStretchFactor(0, 3)
        bottom.setStretchFactor(1, 2)

        splitter = QSplitter(Qt.Orientation.Vertical, self)
        splitter.addWidget(self.table)
        splitter.addWidget(bottom)
        splitter.setSizes([500, 360])
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self.setCentralWidget(splitter)

    def _build_dock(self) -> None:
        self.dock = QDockWidget("统计", self)
        self.dock.setObjectName("statsDock")
        self.dock.setAllowedAreas(
            Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.LeftDockWidgetArea
        )
        self.dock.setMinimumWidth(330)

        self.tabs = QTabWidget(self)

        line_page = QWidget(self)
        line_layout = QVBoxLayout(line_page)
        line_layout.setContentsMargins(6, 6, 6, 6)
        line_layout.setSpacing(4)
        line_header = QHBoxLayout()
        line_header.addWidget(QLabel("按 8 字节分箱"))
        line_header.addStretch(1)
        self.log_check = QCheckBox("对数纵轴")
        self.log_check.setChecked(True)
        line_header.addWidget(self.log_check)
        line_layout.addLayout(line_header)
        self.line_chart = LineChart(line_page)
        line_layout.addWidget(self.line_chart, 1)
        self.tabs.addTab(line_page, "长度分布")

        self.bucket_chart = BarChart(self)
        self.tabs.addTab(self.bucket_chart, "长度分段")

        self.version_chart = BarChart(self)
        self.tabs.addTab(self.version_chart, "IP 版本")

        self.alerts = AlertsView(self)
        self.tabs.addTab(self.alerts, "告警 (0)")

        self.dock.setWidget(self.tabs)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.dock)

    def _build_statusbar(self) -> None:
        bar = self.statusBar()

        self.state_label = QLabel("● 就绪")
        self.state_label.setStyleSheet("color: #64748b; padding: 0 6px;")
        bar.addWidget(self.state_label)

        self.demo_label = QLabel("演示数据")
        self.demo_label.setStyleSheet(
            "color: #92400e; background: #fef3c7; border-radius: 3px; padding: 1px 6px;"
        )
        self.demo_label.setVisible(bool(self.controller.demo))
        bar.addWidget(self.demo_label)

        self.count_label = QLabel("包数 0")
        self.shown_label = QLabel("显示 0")
        self.drop_label = QLabel("丢包 0")
        self.rate_label = QLabel("0 pkt/s")
        self.start_label = QLabel("开始 --:--:--")
        self.start_label.setToolTip("本次抓包的开始时间")
        self.uptime_label = QLabel("运行 0天 00:00:00")
        self.uptime_label.setToolTip("本次抓包运行时长")
        self.res_label = QLabel("资源 —")
        self.res_label.setToolTip("本进程 CPU / 内存占用（需要 psutil，每 5 秒记入资源占用.csv）")
        for label in (
            self.count_label,
            self.shown_label,
            self.drop_label,
            self.rate_label,
            self.start_label,
            self.uptime_label,
            self.res_label,
        ):
            bar.addPermanentWidget(label)

    # ================================================================ 信号
    def _wire(self) -> None:
        self.controller.packets_received.connect(self._on_packets)
        self.controller.stats_updated.connect(self._on_stats)
        self.controller.state_changed.connect(self._update_state)
        self.controller.alert_raised.connect(self._on_alert)

        self.filter_edit.textChanged.connect(self.proxy.set_filter)
        self.table.selectionModel().currentRowChanged.connect(self._on_current_row_changed)
        self.table.verticalScrollBar().valueChanged.connect(self._on_scroll)
        self.log_check.toggled.connect(self.line_chart.set_log)

        self.act_dock.toggled.connect(self.dock.setVisible)
        self.dock.visibilityChanged.connect(self.act_dock.setChecked)
        self.act_hex.toggled.connect(self.hex.setVisible)

    # ================================================================ 设备
    def _refresh_devices(self) -> None:
        self.device_combo.blockSignals(True)
        self.device_combo.clear()

        error = ""
        try:
            devices = self.controller.list_devices()
        except Exception as exc:  # noqa: BLE001 - 枚举失败不应让界面崩
            devices = []
            error = str(exc)

        for device in devices:
            self.device_combo.addItem(device.label, device.key)

        if not devices:
            label = "（无可用网卡）" if not error else "（网卡枚举失败，见下方提示）"
            self.device_combo.addItem(label, None)
            self.device_combo.setToolTip(error)
            self.statusBar().showMessage(
                f"网卡枚举失败：{error}" if error else "没有可用网卡，请检查 Npcap 与 Scapy",
                15000,
            )
        else:
            self.device_combo.setToolTip("")
            self.statusBar().showMessage(f"共 {len(devices)} 块网卡", 3000)

        self.device_combo.blockSignals(False)

    # ================================================================ 数据
    def _on_packets(self, rows: list[PacketRow]) -> None:
        if not rows:
            return
        self.model.append_rows(rows)
        if self._follow:
            self.table.scrollToBottom()
            # 跟随模式且用户没有手动钉住某行时，选中最新一条，
            # 让详情树/十六进制始终显示最新报文（列表只保留最近 5000 行，
            # 旧行被挤出后选中会停在中途，这里主动纠正）。
            if not self._pinned and self.proxy.rowCount():
                self._auto_selecting = True
                try:
                    self.table.setCurrentIndex(
                        self.proxy.index(self.proxy.rowCount() - 1, 0)
                    )
                finally:
                    self._auto_selecting = False
        self.shown_label.setText(f"显示 {self.proxy.rowCount():,}")

    def _on_stats(self, stats: dict) -> None:
        stats = stats or {}
        self._stats = stats

        self.count_label.setText(f"包数 {int(stats.get('received', 0)):,}")
        self.drop_label.setText(f"丢包 {int(stats.get('dropped', 0)):,}")
        self.rate_label.setText(f"{float(stats.get('pps', 0.0)):,.0f} pkt/s")
        started_at = stats.get("started_at") or 0.0
        if started_at > 0:
            self.start_label.setText(
                f"开始 {time.strftime('%H:%M:%S', time.localtime(started_at))}"
            )
        else:
            self.start_label.setText("开始 --:--:--")
        self.uptime_label.setText(f"运行 {self._fmt_uptime(float(stats.get('uptime_s', 0.0)))}")
        self.shown_label.setText(f"显示 {self.proxy.rowCount():,}")

        directory = self.controller.session_dir()
        self.act_capture_dir.setEnabled(directory is not None)

        self.line_chart.set_histogram(stats.get("length_hist") or {}, 8)

        buckets = list(stats.get("buckets") or (0, 0, 0))
        self.bucket_chart.set_values(
            ["≤46 B", "47–1500 B", ">1500 B"],
            buckets,
            ["#0ea5e9", "#2563eb", "#7c3aed"],
        )

        versions = list(stats.get("ip_versions") or (0, 0, 0))
        self.version_chart.set_values(
            ["IPv4", "IPv6", "其它"],
            versions,
            ["#2563eb", "#0891b2", "#94a3b8"],
        )

    def _on_alert(self, alert: dict) -> None:
        self.alerts.add_alert(alert)
        self._alert_count += 1
        self.tabs.setTabText(3, f"告警 ({self._alert_count})")
        self.statusBar().showMessage(
            f"告警：{alert.get('rule', '-')} → {alert.get('target', '-')}", 5000
        )

    def _on_current_row_changed(self, current: QModelIndex, previous: QModelIndex) -> None:
        if not self._auto_selecting and self._follow:
            # 用户主动选中某行：暂停自动跟随，避免每批新报文都抢走选择
            self._pinned = True
        if not current.isValid():
            self.detail.show_packet(None)
            self.hex.set_data(b"")
            return
        source = self.proxy.mapToSource(current)
        row = self.model.row_at(source.row())
        self.detail.show_packet(row)
        self.hex.set_data(row.raw if row else b"")

    def _on_scroll(self, value: int) -> None:
        bar = self.table.verticalScrollBar()
        self._follow = value >= bar.maximum() - 4
        if self._follow:
            # 滚回底部：恢复跟随最新报文
            self._pinned = False

    # ================================================================ 动作
    def _on_start(self) -> None:
        device = self.device_combo.currentData()
        if not device:
            reason = self.device_combo.toolTip()
            message = "没有可用网卡，请先刷新设备列表。"
            if reason:
                message += f"\n\n原因：{reason}"
            QMessageBox.warning(self, "无法开始", message)
            return
        try:
            self.controller.start(str(device), "")
        except NotImplementedError:
            QMessageBox.information(
                self,
                "后端未接入",
                "当前只有界面骨架，抓包后端尚未连接。\n"
                "接入方法见 src/README.md 的“后端接入”一节。",
            )
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "启动失败", str(exc))
            return

        # 新一次抓包从干净列表开始
        self._clear_all()

    def _on_stop(self) -> None:
        try:
            self.controller.stop()
        except NotImplementedError:
            QMessageBox.information(self, "后端未接入", "抓包后端尚未连接。")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "停止失败", str(exc))

    def _on_open(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "打开抓包文件", "", "抓包文件 (*.pcap *.pcapng);;所有文件 (*)"
        )
        if not path:
            return
        try:
            self.controller.open_file(path)
            self.statusBar().showMessage(f"已打开：{path}", 5000)
        except NotImplementedError:
            QMessageBox.information(self, "后端未接入", "文件读取后端尚未连接。")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "打开失败", str(exc))

    def _on_save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "另存为", "capture.pcap", "抓包文件 (*.pcap);;所有文件 (*)"
        )
        if not path:
            return
        try:
            self.controller.save_as(path)
            self.statusBar().showMessage(f"已保存：{path}", 5000)
        except NotImplementedError:
            QMessageBox.information(self, "后端未接入", "文件保存后端尚未连接。")
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "保存失败", str(exc))

    def _clear_all(self) -> None:
        self.model.clear()
        self.line_chart.set_histogram({})
        self.bucket_chart.set_values([], [])
        self.version_chart.set_values([], [])
        self.alerts.setRowCount(0)
        self._alert_count = 0
        self.tabs.setTabText(3, "告警 (0)")
        self.detail.show_packet(None)
        self.hex.set_data(b"")
        self.count_label.setText("包数 0")
        self.shown_label.setText("显示 0")
        self.drop_label.setText("丢包 0")
        self.rate_label.setText("0 pkt/s")
        self.start_label.setText("开始 --:--:--")
        self.uptime_label.setText("运行 0天 00:00:00")
        self.act_capture_dir.setEnabled(False)

    # ================================================================ 状态
    def _update_state(self, state: str, message: str) -> None:
        mapping = {
            "idle": ("● 就绪", "#64748b"),
            "running": ("● 抓包中", "#16a34a"),
            "stopping": ("● 停止中", "#d97706"),
            "error": ("● 错误", "#dc2626"),
        }
        text, color = mapping.get(state, ("● 就绪", "#64748b"))
        self.state_label.setText(text)
        self.state_label.setStyleSheet(f"color: {color}; padding: 0 6px;")

        running = state == "running"
        self._capturing = running
        self.act_start.setEnabled(not running)
        self.act_stop.setEnabled(running)
        if not running:
            self._close_resource_csv()
        if message:
            self.statusBar().showMessage(message, 5000)

    @staticmethod
    def _fmt_uptime(seconds: float) -> str:
        total = max(0, int(seconds))
        days, remainder = divmod(total, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{days}天 {hours:02d}:{minutes:02d}:{secs:02d}"

    def _on_open_capture_dir(self) -> None:
        directory = self.controller.session_dir()
        if directory is None or not Path(directory).is_dir():
            QMessageBox.information(
                self, "捕获目录", "还没有开始抓包，暂时没有捕获目录。\n开始抓包后自动落盘的 pcap 与资源占用.csv 会保存在这里。"
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory)))

    # ================================================================ 资源
    def _on_resource_tick(self) -> None:
        if _psutil is None:
            self.res_label.setText("资源 需安装 psutil")
            return
        if self._process is None:
            try:
                self._process = _psutil.Process()
            except Exception:  # noqa: BLE001
                self.res_label.setText("资源 —")
                return

        try:
            cpu = self._process.cpu_percent(None)
            rss_mb = self._process.memory_info().rss / 1024 / 1024
        except Exception:  # noqa: BLE001
            self.res_label.setText("资源 —")
            return

        # cpu_percent 首次调用返回 0，累计几次再显示，避免误导
        self._proc_cpu_total += cpu
        self._proc_samples += 1
        shown_cpu = self._proc_cpu_total / max(1, self._proc_samples)
        self.res_label.setText(f"CPU {shown_cpu:.1f}%  内存 {rss_mb:.1f} MB")

        if not self._capturing:
            self._close_resource_csv()
            return
        directory = self.controller.session_dir()
        if directory is None:
            self._close_resource_csv()
            return
        self._open_resource_csv(directory)
        if self._resource_writer is None:
            return
        elapsed = time.time() - self._resource_csv_started
        if self._resource_rows_written * RESOURCE_SAMPLE_S > elapsed:
            return
        self._append_resource_row(shown_cpu, rss_mb)

    def _open_resource_csv(self, directory) -> None:
        if self._resource_csv is not None:
            return
        try:
            path = Path(directory) / "资源占用.csv"
            self._resource_csv = path.open("a", newline="", encoding="utf-8-sig")
            self._resource_writer = csv.writer(self._resource_csv)
            if path.stat().st_size == 0:
                self._resource_writer.writerow(
                    ["时间", "运行时长(秒)", "包数", "CPU(%)", "内存(MB)"]
                )
            self._resource_csv_started = time.time()
            self._resource_rows_written = 0
        except OSError:
            self._resource_csv = None
            self._resource_writer = None

    def _append_resource_row(self, cpu: float, rss_mb: float) -> None:
        self._open_resource_csv(self.controller.session_dir())
        if self._resource_writer is None:
            return
        stats = self._stats or {}
        try:
            self._resource_writer.writerow(
                [
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    round(float(stats.get("uptime_s", 0.0)), 1),
                    int(stats.get("received", 0)),
                    round(cpu, 1),
                    round(rss_mb, 1),
                ]
            )
            self._resource_csv.flush()
            self._resource_rows_written += 1
        except OSError:
            self._close_resource_csv()

    def _close_resource_csv(self) -> None:
        if self._resource_csv is not None:
            try:
                self._resource_csv.flush()
                self._resource_csv.close()
            except OSError:
                pass
        self._resource_csv = None
        self._resource_writer = None
        self._resource_rows_written = 0

    # ================================================================ 其他
    def _show_about(self) -> None:
        mode = "演示数据" if self.controller.demo else "真实抓包（需要 Npcap + 管理员）"
        QMessageBox.about(
            self,
            "关于 NetScope",
            "<b>NetScope 网络流量分析系统</b><br><br>"
            "PySide6 界面 + Scapy/Npcap 采集：报文列表、三层字段详情（MAC/IP/TTL/协议号/"
            "端口/TCP 标志）、十六进制、长度分布 / 长度分段 / IP 版本统计图表、"
            "pcap 保存与回放、SYN 泛洪 / ICMP 异常告警、资源占用记录。<br><br>"
            f"当前模式：{mode}。<br>"
            "抓包时原始数据自动滚动落盘（文档/NetScope），可运行 1 天以上。",
        )

    def _show_usage(self) -> None:
        QMessageBox.information(
            self,
            "使用说明",
            "1. 工具栏选择网卡，F5 开始 / Shift+F5 停止。\n"
            "2. 点击报文行，下方显示链路层/网络层/传输层字段与十六进制。\n"
            "3. 右侧“统计”面板：长度分布折线、长度分段柱状、IP 版本柱状、告警。\n"
            "4. 顶部“显示过滤”只过滤列表，不影响抓包。\n"
            "5. 文件菜单：“另存为”把捕获数据保存为 pcap；“打开”回放 pcap/pcapng；\n"
            "   “打开捕获目录”查看自动落盘文件与资源占用.csv。\n"
            "6. 状态栏显示包数、丢包、速率、开始时间与运行时长、CPU/内存占用。\n\n"
            "没有 Npcap 或不是管理员时，启动会给出提示；\n"
            "只想看界面可用 --demo 启动演示数据（含异常流量告警演示）。",
        )

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        self._resource_timer.stop()
        self._close_resource_csv()
        try:
            self.controller.shutdown()
        except Exception:  # noqa: BLE001
            pass
        super().closeEvent(event)
