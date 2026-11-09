"""SARIF 2.1.0 输出。

为什么需要：Markdown 报告只能挂在 Actions artifact 里，没人点开就不会看。
输出 SARIF 后 GitHub 会把每条发现直接标注在 PR 的 diff 行上，
并进入 Security -> Code scanning 面板，能被分支保护规则拦截。

参考：https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path

from mobilesec.models import Finding, ScanReport, Severity

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF 只有 error/warning/note 三档
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub Code Scanning 用 security-severity 排序（0.0 - 10.0）
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _slug(text: str) -> str:
    """把规则标题转成稳定的 ASCII 规则 id。

    中文标题经正则后为空，用标题哈希兜底，保证同一条规则在多次扫描间
    得到相同的 id（否则 GitHub 会把每次扫描当成新规则，历史告警无法收敛）。
    """
    ascii_part = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]
    return f"mobilesec/{ascii_part}-{digest}" if ascii_part else f"mobilesec/{digest}"


def _relative_uri(file_path: str | None, project_root: Path | None) -> str | None:
    """SARIF 的 artifactLocation.uri 要求是仓库相对路径（URL 编码前的 POSIX 形式）。"""
    if not file_path:
        return None
    path = Path(file_path)
    if project_root:
        try:
            path = path.resolve().relative_to(project_root.resolve())
        except ValueError:
            pass
    return path.as_posix()


def build_sarif(report: ScanReport, project_root: str | Path | None = None) -> dict:
    """把 ScanReport 转成 SARIF 2.1.0 字典。"""
    root = Path(project_root) if project_root else None
    findings: list[Finding] = report.all_findings

    # 按标题聚合规则（同一规则多次命中共用一条 rule）
    rules: dict[str, dict] = {}
    for finding in findings:
        rule_id = _slug(finding.title)
        if rule_id in rules:
            # 取更严重的等级
            existing = rules[rule_id]["properties"]["security-severity"]
            incoming = _SECURITY_SEVERITY.get(finding.severity, "0.0")
            if float(incoming) > float(existing):
                rules[rule_id]["properties"]["security-severity"] = incoming
                rules[rule_id]["defaultConfiguration"]["level"] = _LEVEL.get(finding.severity, "note")
            continue

        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "help": {
                "text": finding.remediation or "参见扫描报告",
                **({"markdown": finding.remediation} if finding.remediation else {}),
            },
            "defaultConfiguration": {"level": _LEVEL.get(finding.severity, "note")},
            "properties": {
                "security-severity": _SECURITY_SEVERITY.get(finding.severity, "0.0"),
                "tags": ["security", finding.stage.value],
                **({"cwe": [finding.cwe_id]} if finding.cwe_id else {}),
            },
        }

    results = []
    for finding in findings:
        result: dict = {
            "ruleId": _slug(finding.title),
            "level": _LEVEL.get(finding.severity, "note"),
            "message": {
                "text": finding.description or finding.title,
            },
            "properties": {
                "stage": finding.stage.value,
                "severity": finding.severity.value,
            },
        }

        uri = _relative_uri(finding.file_path, root)
        if uri:
            location: dict = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            if finding.line_number:
                location["physicalLocation"]["region"] = {"startLine": finding.line_number}
            result["locations"] = [location]

        if finding.cve_id:
            result["properties"]["cve"] = finding.cve_id
        if finding.package:
            result["properties"]["package"] = finding.package
            if finding.fix_version:
                result["properties"]["fixVersion"] = finding.fix_version
        if finding.references:
            result["relatedLocations"] = [
                {"id": i, "physicalLocation": {"artifactLocation": {"uri": ref}}}
                for i, ref in enumerate(finding.references[:3], 1)
                if ref.startswith(("http://", "https://"))
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mobilesec",
                        "fullName": "AutoSec for Mobile",
                        "version": _version(),
                        "informationUri": "https://github.com/wwxxzz666/AutoSec-for-Mobile",
                        "rules": list(rules.values()),
                    }
                },
                "originalUriBaseIds": (
                    {"%SRCROOT%": {"uri": root.as_posix() + "/"}} if root else {}
                ),
                "results": results,
            }
        ],
    }


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("mobilesec-agent")
    except Exception:
        return "0.1.0"


def run(
    report: ScanReport,
    output_dir: str = ".",
    project_root: str | Path | None = None,
) -> str:
    """生成 .sarif 文件，返回文件路径。"""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    payload = build_sarif(report, project_root)
    path = output / f"security-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.sarif"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    logger.info(
        "SARIF 报告已生成: %s (%d 条发现)", path, len(payload["runs"][0]["results"])
    )
    return str(path)
