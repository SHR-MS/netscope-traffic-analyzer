"""异常流量生成器：验证 NetScope 的告警检测功能（仅限本机/局域网自测）。

前提：
- 管理员终端（发送原始报文需要）
- 已安装 Npcap
- 用项目虚拟环境运行：.venv\\Scripts\\python.exe 异常流量生成.py ...

用法示例：
  .venv\\Scripts\\python.exe 异常流量生成.py syn     --target 192.168.1.50 --port 80 --count 600
  .venv\\Scripts\\python.exe 异常流量生成.py icmp    --target 192.168.1.1  --count 300
  .venv\\Scripts\\python.exe 异常流量生成.py bigecho --target 192.168.1.1
  .venv\\Scripts\\python.exe 异常流量生成.py orphan  --target 192.168.1.23 --count 40

对应告警规则（阈值在 src/netscope/config.py 的 AlertConfig）：
  syn     -> SYN_FLOOD         5 秒内 SYN ≥100 且 SYN/SYN-ACK ≥3
  icmp    -> ICMP_ECHO_FLOOD   5 秒内 echo request ≥50
  bigecho -> ICMP_BIG_ECHO     echo request 载荷 >800 B 或分片
  orphan  -> ICMP_ORPHAN_REPLY 5 秒内 echo reply ≥20 且 request ≤5

安全限制：
- 目标地址只允许私有网段 / 环回 / 链路本地，拒绝公网地址；
- 单次最多 3000 个包，发送间隔不小于 1 ms。
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys

MAX_COUNT = 3000
MIN_INTERVAL = 0.001


def check_target(text: str) -> str:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        raise SystemExit(f"目标地址格式不对：{text}")
    if not (addr.is_private or addr.is_loopback or addr.is_link_local):
        raise SystemExit(
            f"拒绝发送：{text} 不是私有/环回/链路本地地址。\n"
            "本工具只用于验证自己的检测程序，请勿对公网地址使用。"
        )
    return str(addr)


def load_scapy():
    try:
        from scapy.all import send  # noqa: F401
        from scapy.layers.inet import ICMP, IP, TCP  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(
            "无法导入 Scapy 或 Npcap 不可用。请先安装 Npcap 并用管理员终端运行。\n"
            f"错误：{exc}"
        )
    return send, IP, TCP, ICMP


def main() -> int:
    parser = argparse.ArgumentParser(description="NetScope 告警检测测试流量生成器")
    parser.add_argument("kind", choices=["syn", "icmp", "bigecho", "orphan"])
    parser.add_argument("--target", required=True, help="目标 IP（必须是私有/环回地址）")
    parser.add_argument("--port", type=int, default=80, help="SYN 模式的目标端口，默认 80")
    parser.add_argument("--count", type=int, default=200, help="发送包数，默认 200")
    parser.add_argument("--interval", type=float, default=0.002, help="发包间隔秒，默认 0.002")
    args = parser.parse_args()

    target = check_target(args.target)
    count = max(1, min(MAX_COUNT, args.count))
    interval = max(MIN_INTERVAL, args.interval)

    send, IP, TCP, ICMP = load_scapy()

    if args.kind == "syn":
        if not (0 < args.port < 65536):
            raise SystemExit("端口必须在 1~65535 之间")
        packets = [
            IP(dst=target) / TCP(sport=random.randint(1024, 65535), dport=args.port, flags="S")
            for _ in range(count)
        ]
        print(f"发送 {count} 个 SYN -> {target}:{args.port}，预期告警 SYN_FLOOD")
    elif args.kind == "icmp":
        packets = [IP(dst=target) / ICMP(type=8) / (b"ping" * 8) for _ in range(count)]
        print(f"发送 {count} 个 echo request -> {target}，预期告警 ICMP_ECHO_FLOOD")
    elif args.kind == "bigecho":
        packets = [IP(dst=target, flags="MF") / ICMP(type=8) / (b"x" * 1400)]
        count = 1
        print(f"发送 1 个 1400 B 分片 echo request -> {target}，预期告警 ICMP_BIG_ECHO")
    else:  # orphan
        packets = [IP(dst=target) / ICMP(type=0) / (b"pong" * 8) for _ in range(count)]
        print(f"发送 {count} 个 echo reply（无请求） -> {target}，预期告警 ICMP_ORPHAN_REPLY")

    print("开始发送，请同时观察 NetScope 的“告警”页……")
    send(packets, inter=interval, verbose=0)
    print("发送完成。如果界面没有告警，按提示检查：是否在抓同一块网卡、"
          "NetScope 是否正在运行、阈值是否被调高。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
