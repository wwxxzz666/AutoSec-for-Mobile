"""Trivy 依赖扫描工具封装"""

from __future__ import annotations

import json
import logging

from mobilesec.models import Finding, Severity, StageName
from mobilesec.tools.base import check_tool_available, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def run(target_dir: str) -> list[Finding]:
    """运行 Trivy 文件系统扫描"""
    if not check_tool_available("trivy"):
        logger.warning("trivy 未安装，跳过依赖扫描")
        return []

    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--quiet",
        "--skip-dirs", ".git",
        str(target_dir),
    ]
    result = run_command(cmd, timeout=600)
    if not result.stdout:
        return []

    findings = _parse_results(result.stdout)
    logger.info("Trivy 发现 %d 个漏洞", len(findings))
    return findings


def _parse_results(stdout: str) -> list[Finding]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        target_type = result.get("Type", "")
        for vuln in result.get("Vulnerabilities", []):
            sev_str = vuln.get("Severity", "UNKNOWN")
            severity = SEVERITY_MAP.get(sev_str, Severity.INFO)

            findings.append(Finding(
                stage=StageName.DEPENDENCY,
                severity=severity,
                title=vuln.get("Title", vuln.get("VulnerabilityID", "unknown")),
                description=vuln.get("Description", ""),
                package=vuln.get("PkgName"),
                fix_version=vuln.get("FixedVersion"),
                cve_id=vuln.get("VulnerabilityID"),
                remediation=(
                    f"更新 {vuln.get('PkgName', target)} 到 {vuln['FixedVersion']}"
                    if vuln.get("FixedVersion")
                    else "暂无修复版本"
                ),
                references=vuln.get("References", [])[:3],
                raw_output=json.dumps(vuln, ensure_ascii=False),
            ))
    return findings
