# NetScope 网络流量分析系统

个人电脑上的报文抓取与流量分析工具（计算机网络课程设计）。界面仿 Wireshark：报文列表、三层字段详情、十六进制、统计图表与告警面板。

![界面预览](docs/ui-preview.png)

> 当前进度：**界面 + 采集链路**。已能枚举网卡、启停抓包、把原始帧送进界面；
> 三层字段解析、统计、pcap 存取、告警还在后续阶段。

## 已实现

- 仿抓包软件主界面：菜单栏、工具栏、网卡下拉、显示过滤、状态栏
- 真实抓包：Scapy + Npcap，设备枚举、状态机、有界队列、丢包计数、环境自检
- 报文列表：序号 / 时间 / 源地址 / 目的地址 / 协议 / 长度 / 信息，协议着色，最多 5000 行
- 十六进制视图：偏移 + hex + ASCII
- 链路层解析：解出以太网头（MAC、VLAN 标签、EtherType、载荷偏移），网络/传输层标注“待解析”
- 解析范围与后续计划见 [docs/解析清单.md](docs/解析清单.md)
- 统计面板：长度分布折线、长度分段柱状、IP 版本柱状、告警列表（等待统计模块接入）
- 运行时长、包数、丢包、pps 状态展示
- `--demo` 演示数据模式，方便没有 Npcap 时查看界面

## 目录结构

```
.
├─ src/
│  ├─ main.py                 # 入口（默认真实抓包，--demo / --list）
│  ├─ smoke_test.py           # 界面冒烟测试（可截图）
│  ├─ README.md               # 界面与后端接入说明
│  └─ netscope/
│     ├─ config.py            # CaptureConfig
│     ├─ core/
│     │  ├─ diagnostics.py    # Scapy / Npcap / 管理员自检
│     │  ├─ errors.py
│     │  ├─ models.py         # CaptureState / DeviceInfo / Frame / CaptureStats
│     │  ├─ capture.py        # CaptureEngine + ScapyBackend
│     │  └─ parser.py         # 链路层解析（阶段 1）
│     └─ ui/
│        ├─ live_controller.py# 采集引擎 → Qt 信号
│        ├─ packet_rows.py    # ParsedFrame → PacketRow
│        ├─ controller.py     # 后端接口
│        ├─ models.py         # PacketRow、表格模型、过滤器
│        ├─ widgets.py        # 详情树、十六进制、告警表
│        ├─ charts.py         # 折线图、柱状图
│        ├─ demo.py           # 演示数据源
│        ├─ main_window.py    # 主窗口
│        └─ style.py          # 浅色主题
├─ tests/                     # unittest，不需要 Npcap
├─ docs/
│  ├─ ui-preview.png
│  └─ 解析清单.md              # 解析范围、边界、阶段计划
├─ requirements.txt
└─ .gitignore
```

## 运行

需要 Windows 10/11、Python 3.11+、Npcap；抓包要用**管理员**终端。

```powershell
python -m pip install -r requirements.txt

python src/main.py --list     # 只列网卡（不需要管理员）
python src/main.py            # 真实抓包（需要 Npcap + 管理员）
python src/main.py --demo     # 演示数据，只看界面
```

国内镜像：

```powershell
python -m pip install -r requirements.txt -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
```

Npcap 下载：<https://npcap.com/#download>。安装时取消 “Restrict Npcap driver's access to Administrators only”，装完重启。

## 测试

```powershell
python -m unittest discover -s tests -t . -v
```

覆盖：引擎状态机、队列丢弃、统计计数、Scapy 设备映射、启动失败、链路层解析（以太网/VLAN/QinQ/截断）、环境自检、LiveController 到界面的信号桥接。

冒烟测试（无显示环境）：

```powershell
python src/smoke_test.py
python src/smoke_test.py --show --shot ui.png
```

## 采集设计

- 抓包回调只做 `bytes(pkt)` → `Frame` → 入队，解析和界面都在别的线程/定时器里；
- 队列默认 20000 条，满则丢新包并计入 `dropped`，不反压驱动；
- 状态机 `IDLE → STARTING → RUNNING → STOPPING → IDLE`，失败进 `ERROR`；
- 启动前检查 Scapy、`wpcap.dll`、管理员权限，缺什么直接给可操作提示；
- 设备按“有 IPv4、物理网卡、metric 小”排序，默认选中第一块。

## 后续计划

- [x] 设备枚举、启停、有界队列、丢包计数、环境自检
- [ ] 以太网 / VLAN / IPv4 / IPv6 / TCP / UDP 解析，接入列表与详情树
- [ ] 长度直方图、三段统计、IP 版本统计接入真实数据
- [ ] pcap 滚动落盘、另存与回放
- [ ] SYN 泛洪、ICMP 回声异常检测与告警
- [ ] 24 小时运行、资源占用记录与自恢复

## 说明

- 当前详情树只显示链路层，网络层/传输层标注“待解析”，不是最终效果。
- 演示数据（`src/netscope/ui/demo.py`）为伪造报文，状态栏会显示“演示数据”。
- 没有 Npcap 时 `--list` 仍可用（Scapy 通过系统接口枚举），但启动抓包会给出提示。
