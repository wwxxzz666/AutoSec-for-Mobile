"""Stage 5: 报告生成"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.knowledge import KnowledgeBase
from mobilesec.models import Finding, ScanReport, Severity, StageResult

logger = logging.getLogger(__name__)


def run(report: ScanReport, config: ScanConfig, output_dir: str = ".") -> str:
    """生成安全扫描报告，返回报告文件路径"""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    content = _render_markdown(report, config)
    report_path = output / f"security-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    report_path.write_text(content, encoding="utf-8")

    logger.info("报告已生成: %s", report_path)
    return str(report_path)


def _render_markdown(report: ScanReport, config: ScanConfig) -> str:
    sections = []

    # ── 标题 ──
    sections.append(f"# 安全扫描报告\n")
    sections.append(f"- **扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    sections.append(f"- **后端框架**: {config.backend.framework}")
    sections.append(f"- **移动端框架**: {config.mobile.framework}")
    sections.append(f"- **API 目标**: {config.backend.api_base_url or '未配置'}\n")

    # ── 执行摘要 ──
    sections.append("## 执行摘要\n")
    summary = report.summary
    total = sum(summary.values())
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)

    if crit > 0 or high > 0:
        sections.append(f"**结论**: 发现 {crit} 个严重漏洞和 {high} 个高危漏洞，需要立即修复。\n")
    elif total == 0:
        sections.append("**结论**: 未发现安全问题，安全状况良好。\n")
    else:
        sections.append(f"**结论**: 发现 {total} 个中低危问题，建议在后续迭代中修复。\n")

    sections.append(f"| 严重度 | 数量 |")
    sections.append(f"|--------|------|")
    for sev in Severity:
        count = summary.get(sev.value, 0)
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev.value, "")
        sections.append(f"| {emoji} {sev.value.upper()} | {count} |")
    sections.append("")

    # ── 各阶段结果 ──
    for stage_result in report.results:
        stage_name = {
            "dependency": "依赖审计",
            "sast": "静态代码分析",
            "dast": "API 安全测试",
            "mobile": "移动端安全测试",
        }.get(stage_result.stage.value, stage_result.stage.value)

        sections.append(f"## {stage_name}\n")

        if stage_result.error:
            sections.append(f"> ⚠️ {stage_result.error}\n")

        if not stage_result.findings:
            sections.append("未发现问题。\n")
            continue

        # 按严重度排序
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            stage_result.findings,
            key=lambda f: sev_order.get(f.severity.value, 5),
        )

        for i, f in enumerate(sorted_findings, 1):
            sections.append(f"### [{f.severity.value.upper()}] {f.title}\n")
            if f.description:
                sections.append(f"**描述**: {f.description}\n")
            if f.file_path:
                sections.append(f"**文件**: `{f.file_path}`")
                if f.line_number:
                    sections.append(f" (第 {f.line_number} 行)")
                sections.append("\n")
            if f.cve_id:
                sections.append(f"**CVE**: {f.cve_id}\n")
            if f.package:
                sections.append(f"**依赖包**: {f.package}")
                if f.fix_version:
                    sections.append(f" → 修复版本: {f.fix_version}")
                sections.append("\n")
            if f.remediation:
                sections.append(f"**修复建议**: {f.remediation}\n")
            if f.references:
                sections.append("**参考**: " + ", ".join(f"[[{j+1}]({r})]" for j, r in enumerate(f.references[:3])) + "\n")
            sections.append("---\n")

    # ── 修复优先级建议 ──
    sections.append("## 修复优先级建议\n")
    crit_high = [f for f in report.all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if crit_high:
        sections.append("### 立即修复\n")
        for f in crit_high:
            sections.append(f"- [ ] **{f.title}** — {f.remediation or '参见上方详情'}")
        sections.append("")

    medium = [f for f in report.all_findings if f.severity == Severity.MEDIUM]
    if medium:
        sections.append("### 计划修复\n")
        for f in medium:
            sections.append(f"- [ ] **{f.title}** — {f.remediation or '参见上方详情'}")
        sections.append("")

    return "\n".join(sections)
