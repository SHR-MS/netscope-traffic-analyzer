# NetScope 界面骨架（base）

仿 Wireshark 的主界面：工具栏 + 报文列表 + 三层字段详情 + 十六进制 + 右侧统计面板。
**只有界面，没有抓包逻辑**；抓包、解析、统计、存盘通过 `CaptureController` 接口接入。

![界面预览](../docs/ui-preview.png)

## 运行

```powershell
python -m pip install -r requirements.txt
python src/main.py            # 默认加载演示数据，直接能看到效果
python src/main.py --no-demo  # 空界面，等后端接入
```

当前机器若没装 PySide6，`main.py` 会提示安装命令后退出，不会抛一堆 traceback。

## 界面内容

| 区域 | 内容 |
|---|---|
| 菜单 | 文件（打开/另存为/退出）、抓包（开始/停止/刷新网卡/清空）、视图（统计面板/十六进制）、帮助 |
| 工具栏 | 网卡下拉、开始/停止、打开/另存、**显示过滤** |
| 报文列表 | 序号、时间、源地址、目的地址、协议、长度、信息；最多 5000 行；协议按颜色区分 |
| 详情树 | 帧信息 + 数据链路层 / 网络层 / 传输层 + 附加信息（完全按需求字段组织） |
| 十六进制 | 16 字节一行，偏移 + hex + ASCII |
| 统计面板 | 长度分布（折线，可切对数纵轴）、长度分段（≤46 / 47–1500 / >1500）、IP 版本（IPv4/IPv6/其它）、告警 |
| 状态栏 | 状态灯、演示标记、包数、显示数、丢包、pps、运行时长 |

快捷键：F5 开始、Shift+F5 停止、Ctrl+O 打开、Ctrl+S 另存、Ctrl+Q 退出。

## 目录结构

```
src/
├─ main.py                    # 入口：创建 QApplication、应用样式、开窗
├─ smoke_test.py              # 冒烟测试，可截图
├─ requirements.txt           # 在 base/ 下
└─ netscope/
   ├─ ui/
   │  ├─ controller.py        # 后端接口（信号 + 数据结构约定）
   │  ├─ models.py            # PacketRow、表格模型、显示过滤器
   │  ├─ widgets.py           # 详情树、十六进制、告警表
   │  ├─ charts.py            # 折线图、柱状图（QPainter 自绘）
   │  ├─ demo.py              # 演示数据源（假报文）
   │  ├─ main_window.py       # 主窗口装配
   │  └─ style.py             # QSS 浅色主题
   └─ __init__.py
```

## 后端接入契约

界面只认 `CaptureController` 的四个信号，不 import Scapy：

```python
packets_received(list[PacketRow])    # 一批新报文
stats_updated(dict)                  # 统计快照
state_changed(str, str)              # 状态 + 说明
alert_raised(dict)                   # 一条告警
```

### PacketRow（`netscope/ui/models.py`）

```python
PacketRow(
    seq=1, ts=1700000000.123, src="192.168.1.23", dst="93.184.216.34",
    protocol="TCP", length=40, info="51432 → 443 [SYN] Seq=0",
    raw=b"...",                      # 原始帧，十六进制视图用
    layers=[                         # (层名, [(字段, 值), ...])
        ("数据链路层（Ethernet II）", [("目的 MAC", "..."), ("源 MAC", "..."), ("类型", "IPv4 (0x0800)")]),
        ("网络层（IPv4）", [("版本", "4"), ("源 IP", "..."), ("目的 IP", "..."), ("TTL", "64"), ("协议号", "6 (TCP)")]),
        ("传输层（TCP）", [("源端口", "51432"), ("目的端口", "443"), ("标志位", "SYN=1 ACK=0 FIN=0 RST=0")]),
    ],
    version=4,                       # 4 / 6 / 0（非 IP），IP 版本柱状图用
)
```

### stats（每秒一次即可）

```python
{
    "received": 1234, "displayed": 1234, "dropped": 0,
    "pps": 120.5, "mbps": 1.2, "uptime_s": 65.0,
    "length_hist": {40: 800, 74: 300, 1514: 12},   # 长度 -> 次数
    "buckets": (800, 434, 0),                       # ≤46 / 47–1500 / >1500
    "ip_versions": (1200, 30, 4),                   # IPv4 / IPv6 / 其它
}
```

### alert

```python
{"time": 1700000000.0, "rule": "SYN_FLOOD", "severity": "critical",
 "target": "192.168.1.50:80", "evidence": "SYN 620/s", "count": 1}
```

### 控制器示例

```python
from netscope.ui.controller import CaptureController, DeviceOption
from netscope.ui.models import PacketRow
from netscope.ui.main_window import MainWindow

class ScapyController(CaptureController):
    def list_devices(self):
        return [DeviceOption(key=r"\Device\NPF_{...}", label="WLAN")]

    def start(self, device_key, bpf=""):
        # 在这里启动你的抓包线程；
        # 回调里解析成 PacketRow 后：self.packets_received.emit([row])
        # 定时器里：self.stats_updated.emit({...})
        self.state_changed.emit("running", "抓包中")

    def stop(self):
        # 停止线程、关闭句柄
        self.state_changed.emit("idle", "已停止")

window = MainWindow(controller=ScapyController())
window.show()
```

## 演示数据说明

`demo.py` 每秒生成若干**假报文**（TCP 握手、HTTP、DNS、ICMP、ARP、IPv6），
用于展示界面、图表和告警交互。数据结构与真实后端完全一致，替换控制器即可，
界面代码一行不用改。状态栏会显示“演示数据”标记，避免误认为在真抓包。

## 冒烟测试

```powershell
python src/smoke_test.py                 # offscreen，无窗口
python src/smoke_test.py --show          # 弹出窗口看 2 秒
python src/smoke_test.py --shot ui.png   # 保存截图
```

## 已知限制（后续可加）

- 列表不支持点击表头排序（排序会打乱“序号”的时序含义）；
- “显示过滤”是子串匹配，不是 Wireshark 的显示过滤语法；
- 列表只保留最近 5000 行，完整数据以后端/文件为准；
- 未实现抓包选项对话框、列显示设置、图表导出、深浅主题切换。

## 与设计文档对应

| 设计文档 | 代码 |
|---|---|
| 4.7.1 整体布局 | `main_window.py` |
| 4.7.2 报文列表 | `models.py` + `QTableView` |
| 4.7.3 详情树 | `widgets.DetailTree` |
| 4.7.4 图表页 | `charts.py` + 右侧 dock |
| 4.7.5 状态栏 | `_build_statusbar` |

> 设计文档 3.6 的示例目录写的是 `app/`，实际代码在 `base/src/`，答辩时按实际路径说明即可。
