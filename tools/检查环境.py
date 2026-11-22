"""NetScope 环境检查：Python / Scapy / Npcap / wpcap.dll / 管理员权限。"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys


def main() -> int:
    print("=" * 46)
    print(" NetScope 环境检查")
    print("=" * 46)

    print(f"Python      : {sys.version.split()[0]}")
    print(f"解释器      : {sys.executable}")

    scapy_ok = False
    try:
        import scapy.all as scapy_all  # noqa: F401
        import scapy  # noqa: F401

        version = getattr(scapy, "__version__", "unknown")
        print(f"Scapy       : {version}")
        try:
            count = len(scapy_all.conf.ifaces)
            print(f"网卡数量    : {count}")
            scapy_ok = count > 0
        except Exception as exc:  # noqa: BLE001
            print(f"网卡枚举失败: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"Scapy       : 不可用（{exc}）")

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    dll = os.path.join(system_root, "System32", "wpcap.dll")
    dll_ok = os.path.exists(dll)
    print(f"wpcap.dll   : {'存在' if dll_ok else '不存在（装 Npcap 时勾选 WinPcap 兼容模式）'}")

    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True, text=True, errors="ignore", timeout=10,
        )
        output = result.stdout or ""
        if "RUNNING" in output:
            npcap_state = "服务运行中"
        elif "STOPPED" in output:
            npcap_state = "服务已安装但未运行"
        else:
            npcap_state = "未安装"
    except Exception:  # noqa: BLE001
        npcap_state = "无法查询"
    print(f"Npcap 服务  : {npcap_state}")

    try:
        admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001
        admin = False
    print(f"管理员权限  : {'是' if admin else '否（真实抓包需要管理员）'}")

    print("-" * 46)
    if scapy_ok and dll_ok:
        print("结论：环境可用，可以开始真实抓包测试。")
    elif scapy_ok and not dll_ok:
        print("结论：Scapy 可用但缺 wpcap.dll，请重装 Npcap 并勾选 WinPcap 兼容模式后重启。")
    else:
        print("结论：Scapy/Npcap 尚未就绪，请安装 Npcap 并重启电脑。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
