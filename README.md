# NetScope 网络流量分析系统

计算机网络课程设计。在个人电脑上抓取进出本机的报文，解析三层关键字段，
做长度分布、IP 版本等统计并画图，支持把原始数据存成 pcap 再打开回放，
另外做了 SYN 泛洪、ICMP 回声异常等简单的告警检测。

界面用 PySide6（仿 Wireshark 的布局），抓包靠 Scapy + Npcap。

![界面预览](docs/ui-preview.png)

## 功能

- **抓包**：网卡枚举、开始/停止、显示过滤、有界队列、丢包计数、环境自检
- **三层字段解析**
  - 链路层：源/目的 MAC、以太网类型、VLAN / QinQ 标签
  - 网络层：IPv4 / IPv6 源目的 IP、版本、TTL（IPv6 为跳数限制）、协议号，
    支持 IPv4 选项、分片、IPv6 扩展头
  - 传输层：TCP / UDP 源目的端口、TCP 标志位（SYN/ACK/FIN/RST）、ICMP 类型代码
- **统计图表**：长度分布折线图（8 字节分箱，可切对数轴）、长度三段柱状图
  （≤46 / 47–1500 / >1500 字节）、IP 版本柱状图（IPv4 / IPv6 / 其它）
- **数据持久化**：抓包时原始报文自动滚动落盘（单段 64 MB），支持另存为一个
  pcap 文件、分块打开回放，格式是标准 pcap，Wireshark 也能打开
- **长时间运行**：状态栏显示开始时间与运行时长（X天 HH:MM:SS，按程序启动算起，断网后重新抓包也不清零），每秒刷新
  进程 CPU/内存，抓包期间每 5 秒写入 `资源占用.csv`，方便做资源消耗分析
- **异常告警（扩展）**：SYN 泛洪、ICMP 回声请求泛洪、无请求应答、大包/分片回声；
  同规则同目标 60 秒冷却，阈值在 `src/netscope/config.py` 的 `AlertConfig` 里

## 目录结构

```
.
├─ src/
│  ├─ main.py                  # 入口：--list / 真实抓包 / --demo
│  ├─ smoke_test.py            # 界面冒烟测试（可截图）
│  └─ netscope/
│     ├─ config.py             # CaptureConfig / AlertConfig
│     ├─ core/
│     │  ├─ diagnostics.py     # Scapy / Npcap / 管理员自检
│     │  ├─ capture.py         # 采集引擎 + Scapy 后端
│     │  ├─ parser.py          # 链路 / 网络 / 传输层解析
│     │  ├─ stats.py           # 长度直方图、三段、IP 版本统计
│     │  ├─ alerts.py          # SYN 泛洪 / ICMP 异常检测
│     │  ├─ pcapio.py          # pcap 读写、滚动落盘
│     │  ├─ models.py          # Frame / CaptureStats 等数据模型
│     │  └─ errors.py
│     └─ ui/                   # 主窗口、表格模型、图表、详情树、演示数据
├─ tests/                      # 63 个 unittest，不需要 Npcap
├─ tools/                      # 辅助脚本（环境检查、异常流量生成、pcap 摘要）
├─ scripts/                    # Windows 下双击即可用的启动/测试脚本
├─ docs/                       # 解析清单、测试指南、测试记录、界面截图
├─ verify_e2e.py               # 端到端验证（告警 + 另存 + 回放）
└─ requirements.txt
```

## 快速开始

需要 Windows 10/11、Python 3.11+、Npcap；真实抓包要用管理员权限。

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

.venv\Scripts\python.exe src\main.py --list     # 只列网卡
.venv\Scripts\python.exe src\main.py            # 真实抓包（Npcap + 管理员）
.venv\Scripts\python.exe src\main.py --demo     # 演示数据，只看界面
```

装好依赖后也可以直接双击：

| 脚本 | 作用 |
|---|---|
| `scripts\启动NetScope.bat` | 申请管理员权限并启动程序 |
| `scripts\环境检查.bat` | 检查 Python / Scapy / Npcap / 权限是否就绪 |
| `scripts\运行自动化测试.bat` | 依次跑单元测试、冒烟测试、端到端验证 |
| `scripts\告警测试.bat` | 自动发四种异常流量，验证告警功能 |

国内装依赖可以用镜像：

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
```

Npcap 下载：https://npcap.com/#download 。安装时取消勾选
“Restrict Npcap driver's access to Administrators only”，装完重启。

## 测试

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -t . -v   # 63 项单元测试
.venv\Scripts\python.exe src\smoke_test.py                       # 界面冒烟
.venv\Scripts\python.exe verify_e2e.py                           # 端到端
```

详细步骤见 [docs/测试指南.md](docs/测试指南.md)，本次实际测试结果见
[docs/测试记录.md](docs/测试记录.md)。

`tools/` 里几个辅助脚本：

- `检查环境.py`：一次性检查 Python、Scapy、wpcap.dll、Npcap 服务、管理员权限
- `异常流量生成.py`：生成 SYN 泛洪 / ICMP 泛洪 / 大包回声 / 孤立应答，用于验证告警；
  只允许私有地址，单次最多 3000 包
- `pcap摘要.py`：读一个 pcap，打印报文数、时长、协议分布、长度分段和几条示例

## 实现说明

```
Npcap → AsyncSniffer 回调 → Frame → 有界队列 → QTimer(100ms)
      → parser.parse_frame         # 三层字段
      → stats.add                  # 长度直方图 / 三段 / IP 版本
      → alerts.ingest              # 异常检测
      → pcapio 滚动落盘
      → packet_rows.build_packet_row → 列表 / 详情树 / 十六进制
```

几点设计上的取舍：

- 抓包回调里只做 `bytes(pkt)` 和入队，解析和界面都在别的线程/定时器里做，
  避免回调变慢导致驱动丢包；
- 队列满时丢新包并计入丢包数，不反压驱动；
- 列表只保留最近 5000 行，告警最多 500 行，统计是计数，内存不随运行时长增长；
- 原始报文全部落盘，所以"列表里没有的历史数据"在 pcap 文件里；
- 长度统计用 IP 分组长度（IPv4 总长度 / IPv6 40+载荷长度 / 非 IP 用帧长），
  详情里同时给出帧长和抓包长度。

## 开发过程

按课设进度分几步做，每步都能单独运行：

1. 先搭界面骨架和采集链路（设备枚举、状态机、队列、丢包统计、环境自检）；
2. 补链路层解析（以太网、VLAN、QinQ、截断处理）；
3. 补网络层和传输层解析，把字段接到列表和详情树；
4. 统计模块接入真实数据，画三张图；
5. 做 pcap 落盘、另存、回放；
6. 加异常检测和告警列表；
7. 加运行时长与资源占用记录，准备 1 天稳定性测试。

过程中踩过几个坑，记在 [docs/测试记录.md](docs/测试记录.md) 第六节，简单说：

- pcap 分段大小用文件 `stat` 判断不生效（写入有缓冲还没落盘），改成内部累计字节；
- IPv6 分片头的偏移字段单位是 8 字节，一开始多乘了一次 8；
- Windows 批处理里 `if (...)` 块中出现带 `)` 的路径会解析失败，得改用 goto 标签；
- 写测试工具时 `IP()/ICMP()/b"ping" * 8` 因为运算符优先级变成了"包 × 8"，
  scapy 返回列表导致发送报错，加括号解决；
- 列表超过 5000 行后选中行会漂移，改成"跟随最新报文、手动选中后暂停、滚回底部恢复"。

## 1 天运行说明

课设要求在一台组员电脑上连续运行 1 天以上并观察资源消耗，做法：

1. 管理员终端关掉休眠：`powercfg /change standby-timeout-ac 0`
2. 双击 `scripts\启动NetScope.bat`，选正在联网的网卡，F5 开始
3. 正常使用电脑，程序在后台抓包，不影响上网和办公
4. 第二天看状态栏的“运行 X天 HH:MM:SS”（按程序启动算起；校园网半夜掉线不影响计时，重连后按 F5 继续抓包即可），并到捕获目录取资源占用.csv
5. CSV 里是每 5 秒一行的时间 / 运行时长 / 包数 / CPU% / 内存 MB，可直接画曲线

## 已知限制

- 列表不能点表头排序（排序会打乱“序号”的时序含义）；
- 显示过滤是子串匹配，不是 Wireshark 的过滤语法；
- pcapng 的解析交给 Scapy，未安装 Scapy 时只能读经典 pcap；
- 不做应用层协议识别、分片重组和校验和验证；
- 未做抓包选项对话框、列显示设置、图表导出、深浅主题切换；
- 无线网卡若开启了接收端聚合（RSC），抓到的部分报文会超过 1500 字节，
  这是网卡合并的结果，不影响按 IP 头总长度统计的口径。
