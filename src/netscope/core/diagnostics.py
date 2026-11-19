"""环境自检：Scapy、Npcap 驱动、管理员权限。"""

from __future__ import annotations

import ctypes
import importlib.util
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

from .errors import CaptureUnavailable

NPCAP_DOWNLOAD = "https://npcap.com/#download"


@dataclass(frozen=True, slots=True)
class Issue:
    code: str
    message: str
    hint: str = ""


def is_windows() -> bool:
    return sys.platform == "win32"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def scapy_available() -> bool:
    try:
        return importlib.util.find_spec("scapy") is not None
    except (ImportError, ValueError):
        return False


def npcap_candidates() -> list[Path]:
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return [
        root / "System32" / "Npcap" / "wpcap.dll",
        root / "SysWOW64" / "Npcap" / "wpcap.dll",
        root / "System32" / "wpcap.dll",
        root / "SysWOW64" / "wpcap.dll",
    ]


def find_npcap() -> Path | None:
    for path in npcap_candidates():
        try:
            if path.is_file():
                return path
        except OSError:
            continue
    return None


def npcap_installed() -> bool:
    return find_npcap() is not None


def check_environment(require_admin: bool = True) -> list[Issue]:
    """返回全部环境问题；空列表表示可以尝试抓包。"""
    issues: list[Issue] = []
    if not is_windows():
        issues.append(
            Issue(
                "os",
                f"当前系统为 {platform.system()}，本阶段只支持 Windows 10/11。",
                "如需跨平台，请改用 libpcap 后端。",
            )
        )
    if not scapy_available():
        issues.append(Issue("scapy", "未安装 Scapy，无法调用抓包接口。", "pip install scapy"))
    if is_windows() and not npcap_installed():
        issues.append(
            Issue(
                "npcap",
                "未检测到 Npcap 驱动（wpcap.dll）。",
                f"安装 Npcap 后重启：{NPCAP_DOWNLOAD}",
            )
        )
    if require_admin and is_windows() and not is_admin():
        issues.append(
            Issue(
                "admin",
                "当前进程不是管理员权限，无法打开抓包设备。",
                "右键程序/终端 → 以管理员身份运行。",
            )
        )
    return issues


def ensure_environment(require_admin: bool = True) -> None:
    issues = check_environment(require_admin=require_admin)
    if not issues:
        return
    detail = "；".join(f"{issue.message}（{issue.hint}）" if issue.hint else issue.message for issue in issues)
    raise CaptureUnavailable(detail, issues=issues)
