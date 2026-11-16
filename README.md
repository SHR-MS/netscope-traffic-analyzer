# NetScope 网络流量分析系统

个人电脑上的报文抓取与流量分析工具（计算机网络课程设计）。界面仿 Wireshark：报文列表、三层字段详情、十六进制、统计图表与告警面板。

![界面预览](docs/ui-preview.png)

> 当前进度：**界面骨架已完成**，使用演示数据展示交互；抓包、解析、统计、持久化等逻辑通过 `CaptureController` 接口接入，尚未实现。

## 已实现

- 仿抓包软件主界面：菜单栏、工具栏、网卡下拉、显示过滤、状态栏
- 报文列表：序号 / 时间 / 源地址 / 目的地址 / 协议 / 长度 / 信息，协议着色，最多 5000 行
- 三层字段详情：数据链路层（MAC、以太网类型）、网络层（IP、版本、TTL、协议号）、传输层（端口、TCP 标志）
- 十六进制视图：偏移 + hex + ASCII
- 统计面板：长度分布折线（可切对数纵轴）、长度分段柱状（≤46 / 47–1500 / >1500）、IP 版本柱状、告警列表
- 运行时长、包数、丢包、pps 状态展示
- 与抓包后端解耦的接口层，附带演示数据源，方便先看界面

## 目录结构

```
.
├─ src/
│  ├─ main.py                 # 入口
│  ├─ smoke_test.py           # 界面冒烟测试（可截图）
│  ├─ README.md               # 界面说明与后端接入契约
│  └─ netscope/ui/
│     ├─ controller.py        # 后端接口（信号 + 数据结构）
│     ├─ models.py            # PacketRow、表格模型、过滤器
│     ├─ widgets.py           # 详情树、十六进制、告警表
│     ├─ charts.py            # 折线图、柱状图（QPainter 自绘）
│     ├─ demo.py              # 演示数据源
│     ├─ main_window.py       # 主窗口
│     └─ style.py             # 浅色主题
├─ docs/ui-preview.png        # 界面截图
├─ requirements.txt
└─ .gitignore
```

## 运行

需要 Windows 10/11、Python 3.11+。

```powershell
python -m pip install -r requirements.txt
python src/main.py            # 默认加载演示数据
python src/main.py --no-demo  # 空界面，等待后端接入
```

如果访问 PyPI 较慢，可用国内镜像：

```powershell
python -m pip install -r requirements.txt -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
```

冒烟测试（无显示环境）：

```powershell
python src/smoke_test.py
python src/smoke_test.py --show --shot ui.png
```

## 后端接入

界面只依赖 `CaptureController` 的四个信号：

```python
packets_received(list[PacketRow])
stats_updated(dict)
state_changed(str, str)
alert_raised(dict)
```

继承 `CaptureController`，实现 `list_devices / start / stop / save_as / open_file`，再把解析结果填成 `PacketRow` 发出来即可；界面代码无需修改。字段与统计结构详见 [src/README.md](src/README.md)。

## 后续计划

- [ ] Npcap + Scapy 采集线程、有界队列与丢包计数
- [ ] 以太网 / VLAN / IPv4 / IPv6 / TCP / UDP 解析，接入列表与详情树
- [ ] 长度直方图、三段统计、IP 版本统计接入真实数据
- [ ] pcap 滚动落盘、另存与回放
- [ ] SYN 泛洪、ICMP 回声异常检测与告警
- [ ] 24 小时运行、资源占用记录与自恢复

## 说明

- 演示数据（`src/netscope/ui/demo.py`）为伪造报文，仅用于展示界面，状态栏会显示“演示数据”。
- 抓包需要管理员权限与 Npcap 驱动，当前版本尚未接入。
