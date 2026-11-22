"""分析一个 pcap 文件：用于验证 NetScope 的解析与统计是否正确。"""

from __future__ import annotations

from pathlib import Path

import sys
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netscope.core.parser import parse_frame
from netscope.core.pcapio import read_frames
from netscope.core.stats import TrafficStats
from netscope.ui.packet_rows import build_packet_row


def main() -> int:
    path = sys.argv[1]
    frames = read_frames(path)
    print(f"报文数      : {len(frames):,}")
    if not frames:
        return 1

    span = frames[-1].ts - frames[0].ts
    print(f"时间跨度    : {span:.1f} 秒")
    print(f"平均包长    : {sum(len(f.data) for f in frames) / len(frames):.1f} B")

    stats = TrafficStats()
    protocols: Counter = Counter()
    lengths: Counter = Counter()
    truncated = malformed = 0
    samples = []

    for index, frame in enumerate(frames):
        parsed = parse_frame(frame)
        stats.add(parsed)
        protocols[parsed.protocol] += 1
        lengths[parsed.ip_length] += 1
        truncated += int(parsed.truncated)
        malformed += int(parsed.malformed)
        if index < 5:
            samples.append(build_packet_row(parsed, index + 1))

    snapshot = stats.snapshot()
    print(f"IP 版本统计 : IPv4={snapshot['ip_versions'][0]:,}  "
          f"IPv6={snapshot['ip_versions'][1]:,}  其它={snapshot['ip_versions'][2]:,}")
    print(f"三段长度    : ≤46={snapshot['buckets'][0]:,}  "
          f"47~1500={snapshot['buckets'][1]:,}  >1500={snapshot['buckets'][2]:,}")
    print(f"协议分布    : {', '.join(f'{k}={v:,}' for k, v in protocols.most_common(10))}")
    print(f"截断/畸形   : {truncated} / {malformed}")
    print(f"最常见的长度: {', '.join(f'{k}B×{v:,}' for k, v in lengths.most_common(8))}")

    print("\n前 5 条报文（界面列表会这样显示）：")
    for row in samples:
        print(f"  [{row.seq}] {row.protocol:8s} {row.src:15s} -> {row.dst:15s} "
              f"len={row.length:4d}  {row.info}")
        layers = {name: dict(fields) for name, fields in row.layers}
        transport = next((v for k, v in layers.items() if "传输层" in k), {})
        network = next((v for k, v in layers.items() if "网络层" in k), {})
        print(f"      网络层: 版本={network.get('版本')} TTL={network.get('TTL', network.get('跳数限制'))} "
              f"协议号={network.get('协议号')}")
        print(f"      传输层: 源端口={transport.get('源端口')} 目的端口={transport.get('目的端口')} "
              f"标志位={transport.get('标志位', transport.get('类型'))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
