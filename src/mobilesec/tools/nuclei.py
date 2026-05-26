"""Nuclei 漏洞扫描工具封装"""

from __future__ import annotations

import json
import logging

from mobilesec.models import Finding, Severity, StageName
from mobilesec.tools.base import check_tool_available, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def run(target_url: str, tags: list[str] | None = None, templates: str | None = None) -> list[Finding]:
    """运行 Nuclei 漏洞扫描"""
    if not check_tool_available("nuclei"):
        logger.warning("nuclei 未安装，跳过漏洞扫描")
        return []

    cmd = [
        "nuclei",
        "-u", target_url,
        "-json",
        "-silent",
    ]
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    if templates:
        cmd.extend(["-t", templates])

    result = run_command(cmd, timeout=600)
    if not result.stdout:
        return []

    findings = _parse_results(result.stdout)
    logger.info("Nuclei 发现 %d 个漏洞", len(findings))
    return findings


def _parse_results(stdout: str) -> list[Finding]:
    findings = []
    for line in stdout.strip().splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        sev_str = info.get("severity", "info")
        severity = SEVERITY_MAP.get(sev_str.lower(), Severity.INFO)

        findings.append(Finding(
            stage=StageName.DAST,
            severity=severity,
            title=info.get("name", "unknown"),
            description=info.get("description", ""),
            cve_id=_extract_cve(info),
            remediation=info.get("remediation", ""),
            references=info.get("reference", [])[:3],
            raw_output=json.dumps(data, ensure_ascii=False),
        ))
    return findings


def _extract_cve(info: dict) -> str | None:
    for tag in info.get("tags", []):
        if isinstance(tag, str) and tag.upper().startswith("CVE-"):
            return tag
    return None
