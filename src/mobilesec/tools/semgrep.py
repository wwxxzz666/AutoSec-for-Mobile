"""Semgrep 静态分析工具封装"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from mobilesec.models import Finding, Severity, StageName
from mobilesec.tools.base import check_tool_available, run_command

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}


def run(target_dir: str, rules: str | None = None) -> list[Finding]:
    """运行 Semgrep 扫描"""
    if not check_tool_available("semgrep"):
        logger.warning("semgrep 未安装，跳过 SAST 扫描")
        return []

    cmd = [
        "semgrep", "scan",
        "--json",
        "--config", rules or "auto",
        "--quiet",
        str(target_dir),
    ]
    result = run_command(cmd, timeout=600, cwd=target_dir)
    if not result.success and not result.stdout:
        logger.error("semgrep 执行失败: %s", result.stderr)
        return []

    findings = _parse_results(result.stdout)
    logger.info("Semgrep 发现 %d 个问题", len(findings))
    return findings


def _parse_results(stdout: str) -> list[Finding]:
    data = json.loads(stdout) if stdout else None
    if not data or "results" not in data:
        return []

    findings = []
    for r in data["results"]:
        sev_str = r.get("extra", {}).get("severity", "INFO")
        severity = SEVERITY_MAP.get(sev_str, Severity.INFO)

        findings.append(Finding(
            stage=StageName.SAST,
            severity=severity,
            title=r.get("check_id", "unknown").split(".")[-1],
            description=r.get("extra", {}).get("message", ""),
            file_path=r.get("path", ""),
            line_number=r.get("start", {}).get("line"),
            cwe_id=_extract_cwe(r),
            remediation=r.get("extra", {}).get("fix", "") or "",
            raw_output=json.dumps(r, ensure_ascii=False),
        ))
    return findings


def _extract_cwe(result: dict) -> str | None:
    metadata = result.get("extra", {}).get("metadata", {})
    cwe = metadata.get("cwe") or metadata.get("owasp")
    if isinstance(cwe, list):
        return cwe[0] if cwe else None
    return cwe
