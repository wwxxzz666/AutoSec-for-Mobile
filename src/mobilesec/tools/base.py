"""工具执行基类"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class ToolResult:
    """工具执行结果"""

    def __init__(self, success: bool, stdout: str = "", stderr: str = "", data: Any = None):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.data = data


def run_command(cmd: list[str], timeout: int = 300, cwd: str | None = None, **kwargs) -> ToolResult:
    """执行命令行工具，返回结果"""
    logger.info("执行: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            **kwargs,
        )
        return ToolResult(
            success=result.returncode == 0,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    except FileNotFoundError:
        logger.error("工具未安装: %s", cmd[0])
        return ToolResult(success=False, stderr=f"工具未安装: {cmd[0]}")
    except subprocess.TimeoutExpired:
        logger.error("工具执行超时: %s", cmd[0])
        return ToolResult(success=False, stderr=f"执行超时 ({timeout}s)")
    except Exception as e:
        logger.error("工具执行失败: %s - %s", cmd[0], e)
        return ToolResult(success=False, stderr=str(e))


def check_tool_available(name: str) -> bool:
    """检查工具是否可用"""
    return shutil.which(name) is not None


def parse_json_output(stdout: str) -> list[dict] | dict | None:
    """尝试解析 JSON 输出"""
    try:
        return json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return None
