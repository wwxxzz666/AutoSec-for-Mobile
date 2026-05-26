"""SQLMap SQL 注入测试工具封装"""

from __future__ import annotations

import logging

from mobilesec.models import Finding, Severity, StageName
from mobilesec.tools.base import check_tool_available, run_command

logger = logging.getLogger(__name__)


def run(
    target_url: str,
    data: str | None = None,
    cookie: str | None = None,
    token: str | None = None,
    level: int = 3,
    risk: int = 2,
) -> list[Finding]:
    """运行 SQLMap 注入测试"""
    if not check_tool_available("sqlmap"):
        logger.warning("sqlmap 未安装，跳过 SQL 注入测试")
        return []

    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",
        "--level", str(level),
        "--risk", str(risk),
        "--timeout", "30",
        "--retries", "1",
    ]
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if token:
        cmd.extend(["--token", token])

    result = run_command(cmd, timeout=600)
    if not result.success and not result.stdout:
        return []

    findings = _parse_output(result.stdout)
    logger.info("SQLMap 发现 %d 个注入点", len(findings))
    return findings


def _parse_output(stdout: str) -> list[Finding]:
    findings = []
    current_param = None
    current_type = None

    for line in stdout.splitlines():
        line = line.strip()
        if "Parameter:" in line:
            current_param = line.split("Parameter:")[1].strip()
        elif "Type:" in line and current_param:
            current_type = line.split("Type:")[1].strip()
        elif "is vulnerable" in line.lower():
            findings.append(Finding(
                stage=StageName.DAST,
                severity=Severity.CRITICAL,
                title=f"SQL 注入漏洞 ({current_param or 'unknown'})",
                description=f"参数 {current_param} 存在 {current_type or ''} SQL 注入漏洞",
                remediation="使用参数化查询或 ORM 框架，禁止拼接 SQL 语句",
            ))
            current_param = None
            current_type = None

    return findings
