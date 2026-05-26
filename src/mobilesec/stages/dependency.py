"""Stage 1: 依赖审计"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.knowledge import KnowledgeBase
from mobilesec.models import Finding, Severity, StageName, StageResult
from mobilesec.tools import trivy

logger = logging.getLogger(__name__)


def run(config: ScanConfig, kb: KnowledgeBase | None = None) -> StageResult:
    """执行依赖审计"""
    findings: list[Finding] = []

    # 1. Trivy 文件系统扫描（覆盖多语言依赖）
    backend_dir = Path(config.backend.source_dir)
    if backend_dir.exists():
        findings.extend(trivy.run(str(backend_dir)))

    mobile_dir = Path(config.mobile.source_dir)
    if mobile_dir.exists():
        findings.extend(trivy.run(str(mobile_dir)))

    # 2. Python 专项: pip-audit
    findings.extend(_run_pip_audit(config.backend.source_dir))

    # 3. Node.js 专项: npm audit
    findings.extend(_run_npm_audit(config.mobile.source_dir))

    # 4. 从 AboutSecurity Vuln/ 匹配已知漏洞
    if kb and kb.exists:
        findings.extend(_match_known_vulns(config, kb))

    # 去重（相同 CVE 不重复报）
    seen_cves = set()
    unique = []
    for f in findings:
        key = f.cve_id or f"{f.title}:{f.file_path}:{f.line_number}"
        if key not in seen_cves:
            seen_cves.add(key)
            unique.append(f)

    return StageResult(
        stage=StageName.DEPENDENCY,
        success=True,
        findings=unique,
    )


def _run_pip_audit(source_dir: str) -> list[Finding]:
    """pip-audit 扫描 Python 依赖"""
    from mobilesec.tools.base import check_tool_available

    if not check_tool_available("pip-audit"):
        return []

    req_files = list(Path(source_dir).glob("requirements*.txt"))
    if not req_files:
        return []

    findings = []
    for req in req_files:
        try:
            result = subprocess.run(
                ["pip-audit", "-r", str(req), "--format", "json"],
                capture_output=True, text=True, timeout=120,
            )
            if not result.stdout:
                continue
            data = json.loads(result.stdout)
            for vuln in data.get("vulnerabilities", []):
                findings.append(Finding(
                    stage=StageName.DEPENDENCY,
                    severity=Severity.HIGH,
                    title=vuln.get("advisory", "已知依赖漏洞"),
                    description=vuln.get("description", ""),
                    package=vuln.get("package", {}).get("name"),
                    fix_version=", ".join(vuln.get("fix_versions", [])),
                    cve_id=vuln.get("aliases", [None])[0],
                    remediation=f"更新到修复版本: {', '.join(vuln.get('fix_versions', ['未知']))}",
                ))
        except Exception as e:
            logger.debug("pip-audit 扫描 %s 失败: %s", req, e)

    return findings


def _run_npm_audit(source_dir: str) -> list[Finding]:
    """npm audit 扫描 Node.js 依赖"""
    from mobilesec.tools.base import check_tool_available

    if not check_tool_available("npm"):
        return []

    pkg_json = Path(source_dir) / "package.json"
    if not pkg_json.exists():
        return []

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True, text=True, timeout=120,
            cwd=source_dir,
        )
        if not result.stdout:
            return []

        data = json.loads(result.stdout)
        findings = []
        for vuln in data.get("vulnerabilities", {}).values():
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            findings.append(Finding(
                stage=StageName.DEPENDENCY,
                severity=severity_map.get(vuln.get("severity", "low"), Severity.LOW),
                title=vuln.get("title", "npm 依赖漏洞"),
                description=vuln.get("url", ""),
                package=vuln.get("name"),
                remediation=f"运行 npm audit fix 修复",
            ))
        return findings
    except Exception as e:
        logger.debug("npm audit 失败: %s", e)
        return []


def _match_known_vulns(config: ScanConfig, kb: KnowledgeBase) -> list[Finding]:
    """从 AboutSecurity Vuln/ 数据库匹配已知漏洞"""
    findings = []

    # 根据后端框架匹配
    framework_map = {
        "django": "django",
        "flask": "flask",
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
    }
    for framework in [config.backend.framework] + list(framework_map.keys()):
        entries = kb.search_vulns(product=framework)
        for entry in entries[:10]:  # 限制数量
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            findings.append(Finding(
                stage=StageName.DEPENDENCY,
                severity=severity_map.get(entry.severity, Severity.INFO),
                title=entry.title,
                cve_id=entry.id,
                description=f"产品 {entry.product} 存在已知漏洞",
                remediation="查看漏洞详情获取修复建议",
                references=[str(entry.path)],
            ))

    return findings
