"""数据模型定义"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StageName(str, Enum):
    DEPENDENCY = "dependency"
    SAST = "sast"
    DAST = "dast"
    MOBILE = "mobile"


class Finding(BaseModel):
    """单个安全发现"""

    stage: StageName
    severity: Severity
    title: str
    description: str = ""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    package: Optional[str] = None
    fix_version: Optional[str] = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    raw_output: Optional[str] = None


class StageResult(BaseModel):
    """单个阶段的执行结果"""

    stage: StageName
    success: bool = True
    findings: list[Finding] = Field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0


class ScanReport(BaseModel):
    """完整扫描报告"""

    target: str = ""
    backend_framework: str = ""
    mobile_framework: str = ""
    results: list[StageResult] = Field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for r in self.results:
            findings.extend(r.findings)
        return findings

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        grouped: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.all_findings:
            grouped[f.severity].append(f)
        return grouped

    @property
    def summary(self) -> dict[str, int]:
        return {s.value: len(fs) for s, fs in self.findings_by_severity.items()}
