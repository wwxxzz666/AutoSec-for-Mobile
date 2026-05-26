"""Bandit Python 安全检查工具封装"""

from __future__ import annotations

import json
import logging

from mobilesec.models import Finding, Severity, StageName
from mobilesec.tools.base import check_tool_available, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def run(target_dir: str) -> list[Finding]:
    """运行 Bandit 扫描"""
    if not check_tool_available("bandit"):
        logger.warning("bandit 未安装，跳过 Python 安全检查")
        return []

    cmd = [
        "bandit",
        "-r", target_dir,
        "-f", "json",
        "--quiet",
    ]
    result = run_command(cmd, timeout=300)
    if not result.stdout:
        return []

    findings = _parse_results(result.stdout)
    logger.info("Bandit 发现 %d 个问题", len(findings))
    return findings


def _parse_results(stdout: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for issue in data.get("results", []):
        severity = SEVERITY_MAP.get(issue.get("issue_severity", "LOW"), Severity.LOW)

        findings.append(Finding(
            stage=StageName.SAST,
            severity=severity,
            title=issue.get("test_id", "unknown"),
            description=issue.get("issue_text", ""),
            file_path=issue.get("filename", ""),
            line_number=issue.get("line_number"),
            cwe_id=issue.get("issue_cwe", {}).get("id"),
            remediation=issue.get("more_info", ""),
        ))
    return findings
