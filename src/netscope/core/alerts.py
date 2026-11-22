"""异常流量检测与告警：SYN 泛洪、ICMP 回声异常（扩展功能）。

基于滑动窗口的速率检测，全部在内存中完成，不依赖外部库：

- ``SYN_FLOOD``：窗口内某目标（IP:端口）SYN 数超过阈值，且 SYN/SYN-ACK
  比值过高（正常握手每个 SYN 都应有应答）；
- ``ICMP_ECHO_FLOOD``：窗口内来自同一源的 echo request 速率超过阈值；
- ``ICMP_ORPHAN_REPLY``：echo reply 明显多于近期 echo request（无请求的应答，
  常见于扫描/探测）；
- ``ICMP_BIG_ECHO``：echo request 载荷过大或分片（大包 ping 探测）。

同一条规则对同一目标在冷却时间内只报一次，避免刷屏。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from ..config import AlertConfig
from .parser import ParsedFrame, TCP_ACK, TCP_SYN

RULES = {
    "SYN_FLOOD": ("critical", "SYN 泛洪"),
    "ICMP_ECHO_FLOOD": ("critical", "ICMP 回声请求泛洪"),
    "ICMP_ORPHAN_REPLY": ("warning", "ICMP 无请求应答异常"),
    "ICMP_BIG_ECHO": ("info", "ICMP 大包回声请求"),
}

# 每处理多少条报文做一次过期清理，保证长时间运行内存有界
PRUNE_EVERY = 1000


@dataclass
class _TargetState:
    """一个被观察目标的滑动窗口计数。"""

    syn: deque[float] = field(default_factory=deque)
    synack: deque[float] = field(default_factory=deque)
    last_seen: float = 0.0


@dataclass
class _EchoState:
    requests: deque[float] = field(default_factory=deque)
    replies: deque[float] = field(default_factory=deque)
    last_seen: float = 0.0


class AlertEngine:
    """逐条消化解析结果，返回新产生的告警（可能为空）。"""

    def __init__(self, config: AlertConfig | None = None) -> None:
        self._config = config or AlertConfig()
        self.reset()

    def reset(self) -> None:
        self._syn_targets: dict[tuple[str, int], _TargetState] = {}
        self._echo_sources: dict[str, _EchoState] = {}
        self._last_alert: dict[tuple[str, str], float] = {}   # (rule, target) -> ts
        self._processed = 0

    # ---------------------------------------------------------------- 入口
    def ingest(self, parsed: ParsedFrame) -> dict | None:
        """消化一条报文；触发规则时返回告警 dict，否则返回 None。"""
        self._processed += 1
        if self._processed % PRUNE_EVERY == 0:
            self._prune(parsed.frame.ts)

        transport = parsed.transport
        if transport is None:
            return None
        ts = parsed.frame.ts

        if transport.protocol == 6:
            return self._check_syn(parsed, ts)

        if transport.protocol in (1, 58):
            return self._check_icmp(parsed, ts)

        return None

    # ---------------------------------------------------------------- SYN
    def _check_syn(self, parsed: ParsedFrame, ts: float) -> dict | None:
        transport = parsed.transport
        assert transport is not None
        flags = transport.tcp_flags
        if not (flags & TCP_SYN):
            return None

        dst_ip = parsed.dst_ip
        if dst_ip is None or transport.dport is None:
            return None
        key = (dst_ip, transport.dport)
        state = self._syn_targets.get(key)
        if state is None:
            state = self._syn_targets[key] = _TargetState()
        state.last_seen = ts

        if flags & TCP_ACK:
            state.synack.append(ts)
        else:
            state.syn.append(ts)

        window = self._config.syn_window_s
        self._prune_deque(state.syn, ts - window)
        self._prune_deque(state.synack, ts - window)

        syn_count = len(state.syn)
        if syn_count < self._config.syn_min:
            return None
        synack_count = len(state.synack)
        ratio = syn_count / max(1, synack_count)
        if ratio < self._config.syn_ratio:
            return None

        target = f"{dst_ip}:{transport.dport}"
        if not self._allow("SYN_FLOOD", target, ts):
            return None
        return {
            "time": ts,
            "rule": "SYN_FLOOD",
            "severity": "critical",
            "target": target,
            "evidence": (
                f"{window:.0f}s 内 SYN {syn_count} 个"
                f"（{syn_count / window:.0f}/s），SYN-ACK {synack_count} 个，比值 {ratio:.1f}"
            ),
            "count": syn_count,
        }

    # ---------------------------------------------------------------- ICMP
    def _check_icmp(self, parsed: ParsedFrame, ts: float) -> dict | None:
        transport = parsed.transport
        assert transport is not None
        if transport.icmp_type is None:
            return None

        src_ip = parsed.src_ip
        if src_ip is None:
            return None
        state = self._echo_sources.get(src_ip)
        if state is None:
            state = self._echo_sources[src_ip] = _EchoState()
        state.last_seen = ts

        window = self._config.icmp_window_s

        if transport.is_echo_request:
            state.requests.append(ts)
            self._prune_deque(state.requests, ts - window)
            self._prune_deque(state.replies, ts - window)

            # 大包 / 分片回声请求（info 级）
            payload_len = self._icmp_payload_len(parsed)
            fragmented = (parsed.ipv4 is not None and parsed.ipv4.fragmented) or (
                parsed.ipv6 is not None and parsed.ipv6.fragmented
            )
            if payload_len > self._config.big_echo_bytes or fragmented:
                if self._allow("ICMP_BIG_ECHO", src_ip, ts):
                    return {
                        "time": ts,
                        "rule": "ICMP_BIG_ECHO",
                        "severity": "info",
                        "target": src_ip,
                        "evidence": f"echo request 载荷 {payload_len} B"
                        + ("，且分片" if fragmented else ""),
                        "count": 1,
                    }

            # 回声请求泛洪
            request_count = len(state.requests)
            if request_count >= self._config.icmp_min:
                if self._allow("ICMP_ECHO_FLOOD", src_ip, ts):
                    return {
                        "time": ts,
                        "rule": "ICMP_ECHO_FLOOD",
                        "severity": "critical",
                        "target": src_ip,
                        "evidence": (
                            f"{window:.0f}s 内 echo request {request_count} 个"
                            f"（{request_count / window:.0f}/s）"
                        ),
                        "count": request_count,
                    }
            return None

        if transport.is_echo_reply:
            state.replies.append(ts)
            self._prune_deque(state.requests, ts - window)
            self._prune_deque(state.replies, ts - window)

            replies = len(state.replies)
            requests = len(state.requests)
            if (
                replies >= self._config.orphan_replies_min
                and requests <= self._config.orphan_requests_max
                and self._allow("ICMP_ORPHAN_REPLY", src_ip, ts)
            ):
                return {
                    "time": ts,
                    "rule": "ICMP_ORPHAN_REPLY",
                    "severity": "warning",
                    "target": src_ip,
                    "evidence": (
                        f"{window:.0f}s 内 echo reply {replies} 个，"
                        f"而 echo request 仅 {requests} 个"
                    ),
                    "count": replies,
                }
        return None

    @staticmethod
    def _icmp_payload_len(parsed: ParsedFrame) -> int:
        """ICMP 载荷长度：IP 分组长度减去各层首部（近似）。"""
        length = parsed.ip_length
        transport = parsed.transport
        if transport is None:
            return 0
        header_len = transport.payload_offset - (parsed.eth.payload_offset if parsed.eth else 0)
        return max(0, length - header_len - 4)

    # ---------------------------------------------------------------- 冷却
    def _allow(self, rule: str, target: str, ts: float) -> bool:
        key = (rule, target)
        last = self._last_alert.get(key)
        if last is not None and ts - last < self._config.cooldown_s:
            return False
        self._last_alert[key] = ts
        return True

    @staticmethod
    def _prune_deque(items: deque, cutoff: float) -> None:
        while items and items[0] < cutoff:
            items.popleft()

    def _prune(self, ts: float) -> None:
        """清理长时间无活动的目标，避免去重键无限增长。"""
        syn_cutoff = ts - self._config.syn_window_s - self._config.cooldown_s
        for key in [k for k, v in self._syn_targets.items() if v.last_seen < syn_cutoff]:
            del self._syn_targets[key]

        icmp_cutoff = ts - self._config.icmp_window_s - self._config.cooldown_s
        for key in [k for k, v in self._echo_sources.items() if v.last_seen < icmp_cutoff]:
            del self._echo_sources[key]

        for key in [k for k, v in self._last_alert.items() if v < ts - self._config.cooldown_s * 10]:
            del self._last_alert[key]
