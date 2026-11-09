"""数据模型定义"""

from __future__ import annotations

from enum import Enum
from typing import Callable, Optional

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
    skipped: bool = False
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


def dedupe_findings(
    findings: list[Finding],
    key: Callable[[Finding], object] | None = None,
) -> list[Finding]:
    """按 key 去重，保留首次出现的顺序。

    默认按 (title, file_path, line_number) 去重；依赖审计阶段会传入
    以 cve_id 优先的 key（同一个 CVE 在多个依赖文件里出现只报一次）。

    原来这段去重逻辑在 dependency / sast / mobile 三个阶段各抄了一遍。
    """
    if key is None:
        def key(f: Finding) -> object:  # noqa: E306
            return (f.title, f.file_path, f.line_number)

    seen: set[object] = set()
    unique: list[Finding] = []
    for finding in findings:
        k = key(finding)
        if k in seen:
            continue
        seen.add(k)
        unique.append(finding)
    return unique
