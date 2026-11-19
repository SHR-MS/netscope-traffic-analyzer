"""抓包相关异常。"""

from __future__ import annotations

from typing import Iterable


class CaptureError(RuntimeError):
    """抓包相关错误的基类。"""


class CaptureUnavailable(CaptureError):
    """运行环境不满足抓包条件（缺驱动、缺依赖、无管理员权限等）。"""

    def __init__(self, message: str, issues: Iterable[object] = ()) -> None:
        super().__init__(message)
        self.issues = tuple(issues)


class CaptureStartError(CaptureError):
    """设备打开失败或启动过程中出错。"""
