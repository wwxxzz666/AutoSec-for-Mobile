"""CLI 入口"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.knowledge import KnowledgeBase
from mobilesec.models import ScanReport, StageName
from mobilesec.sarif import run as run_sarif
from mobilesec.stages import dast, dependency, mobile, report, sast

logger = logging.getLogger("mobilesec")

STAGE_MAP = {
    "dependency": StageName.DEPENDENCY,
    "sast": StageName.SAST,
    "dast": StageName.DAST,
    "mobile": StageName.MOBILE,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mobilesec",
        description="移动应用安全扫描 Agent",
    )
    parser.add_argument(
        "--config", "-c",
        default=".mobilesec/config.yaml",
        help="配置文件路径 (默认: .mobilesec/config.yaml)",
    )
    parser.add_argument(
        "--project-root", "-r",
        default=".",
        help="项目根目录 (默认: 当前目录)",
    )
    parser.add_argument(
        "--output", "-o",
        default="./security-reports",
        help="报告输出目录 (默认: ./security-reports)",
    )
    parser.add_argument(
        "--format", "-f",
        default="markdown",
        choices=["markdown", "sarif", "both"],
        help="报告格式 (默认: markdown)。sarif 可直接上传 GitHub Code Scanning",
    )
    parser.add_argument(
        "--stages", "-s",
        default="dependency,sast,mobile,dast",
        help="要执行的阶段，逗号分隔 (默认: dependency,sast,mobile,dast)",
    )
    parser.add_argument(
        "--aboutsecurity-path",
        default=None,
        help="AboutSecurity 知识库路径",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="详细日志输出",
    )
    args = parser.parse_args()

    # 日志配置
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # 加载配置
    project_root = Path(args.project_root).resolve()
    config = ScanConfig.load(project_root, args.config)

    # AboutSecurity 知识库路径: CLI 参数 > 配置文件 > 环境变量
    as_path = args.aboutsecurity_path or config.pipeline.aboutsecurity_path
    kb = KnowledgeBase(as_path) if as_path else None

    if kb and kb.exists:
        kb.load()
        logger.info("AboutSecurity 知识库已加载: %s", as_path)
    elif as_path:
        logger.warning("AboutSecurity 路径无效: %s", as_path)
        kb = None

    # 确定执行阶段
    requested_stages = [s.strip() for s in args.stages.split(",")]
    skip_stages = config.pipeline.skip_stages
    active_stages = [s for s in requested_stages if s not in skip_stages]

    logger.info("=" * 60)
    logger.info("MobileSec Agent 启动")
    logger.info("项目根目录: %s", project_root)
    logger.info("后端框架: %s", config.backend.framework)
    logger.info("移动端框架: %s", config.mobile.framework)
    logger.info("执行阶段: %s", ", ".join(active_stages))
    logger.info("=" * 60)

    # 执行扫描
    scan_report = ScanReport(
        target=str(project_root),
        backend_framework=config.backend.framework,
        mobile_framework=config.mobile.framework,
    )

    stage_runners = {
        "dependency": dependency.run,
        "sast": sast.run,
        "dast": dast.run,
        "mobile": mobile.run,
    }

    has_critical = False

    for stage_name in active_stages:
        runner = stage_runners.get(stage_name)
        if not runner:
            logger.warning("未知阶段: %s", stage_name)
            continue

        logger.info("-" * 40)
        logger.info("执行阶段: %s", stage_name)
        start = time.time()

        try:
            result = runner(config, kb)
            result.duration_seconds = time.time() - start
            scan_report.results.append(result)

            # 检查是否有严重漏洞
            for f in result.findings:
                if f.severity in ("critical", "high"):
                    has_critical = True

            logger.info(
                "阶段 %s 完成 (%.1fs): %d 个发现",
                stage_name, result.duration_seconds, len(result.findings),
            )
        except Exception as e:
            logger.error("阶段 %s 执行失败: %s", stage_name, e)
            from mobilesec.models import StageResult
            scan_report.results.append(StageResult(
                stage=STAGE_MAP.get(stage_name, StageName.DEPENDENCY),
                success=False,
                error=str(e),
            ))

    # 生成报告
    logger.info("-" * 40)
    report_path = ""
    sarif_path = ""
    if args.format in ("markdown", "both"):
        report_path = report.run(scan_report, config, args.output)
        logger.info("Markdown 报告已生成: %s", report_path)
    if args.format in ("sarif", "both"):
        sarif_path = run_sarif(scan_report, args.output, project_root)
        logger.info("SARIF 报告已生成: %s", sarif_path)

    # 汇总
    total = len(scan_report.all_findings)
    summary = scan_report.summary
    logger.info("=" * 60)
    logger.info("扫描完成: 共 %d 个发现", total)
    for sev, count in summary.items():
        if count > 0:
            logger.info("  %s: %d", sev.upper(), count)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as output:
            output.write(f"report_path={report_path}\n")
            output.write(f"sarif_path={sarif_path}\n")
            output.write(f"total_findings={total}\n")

    logger.info("=" * 60)

    # Exit with status 1 for critical findings or stage failures.
    has_stage_error = any(not result.success for result in scan_report.results)
    if has_critical or has_stage_error:
        logger.error("发现严重或高危漏洞，请立即修复！")
        sys.exit(1)


if __name__ == "__main__":
    main()
