"""Stage 2: 静态代码分析 (SAST)"""

from __future__ import annotations

import logging
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.knowledge import KnowledgeBase
from mobilesec.models import Finding, Severity, StageName, StageResult
from mobilesec.tools import bandit, semgrep

logger = logging.getLogger(__name__)


def run(config: ScanConfig, kb: KnowledgeBase | None = None) -> StageResult:
    """执行静态代码分析"""
    findings: list[Finding] = []

    backend_dir = Path(config.backend.source_dir)
    mobile_dir = Path(config.mobile.source_dir)

    # 1. Semgrep 多语言扫描
    if backend_dir.exists():
        findings.extend(semgrep.run(str(backend_dir)))
    if mobile_dir.exists():
        findings.extend(semgrep.run(str(mobile_dir)))

    # 2. Bandit Python 专项扫描
    if backend_dir.exists():
        findings.extend(bandit.run(str(backend_dir)))

    # 3. 硬编码敏感信息检查（快速正则扫描）
    if backend_dir.exists():
        findings.extend(_check_secrets(backend_dir))

    # 4. Python 框架特定的安全检查
    if backend_dir.exists():
        findings.extend(_check_framework_security(backend_dir, config.backend.framework))

    # 去重
    seen = set()
    unique = []
    for f in findings:
        key = f"{f.title}:{f.file_path}:{f.line_number}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    logger.info("SAST 共发现 %d 个问题", len(unique))
    return StageResult(stage=StageName.SAST, success=True, findings=unique)


def _check_secrets(root: Path) -> list[Finding]:
    """检查硬编码的敏感信息"""
    import re

    patterns = [
        (r'(?i)(API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN)\s*[=:]\s*["\'][^"\']{8,}', "硬编码密钥"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}', "硬编码密码"),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', "硬编码私钥"),
        (r'(?i)mongodb(\+srv)?://[^\s"\']+', "硬编码数据库连接串"),
        (r'(?i)mysql://[^\s"\']+', "硬编码数据库连接串"),
        (r'(?i)redis://[^\s"\']+:', "硬编码 Redis 连接串"),
    ]

    findings = []
    extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".dart", ".vue", ".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini"}

    skip_dirs = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build", ".gradle"}

    for fp in root.rglob("*"):
        if any(d in fp.parts for d in skip_dirs):
            continue
        if fp.suffix not in extensions:
            continue

        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern, title in patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    stage=StageName.SAST,
                    severity=Severity.HIGH,
                    title=f"硬编码敏感信息: {title}",
                    file_path=str(fp),
                    line_number=line_num,
                    remediation="将敏感信息移至环境变量或密钥管理服务",
                ))

    return findings


def _check_framework_security(root: Path, framework: str) -> list[Finding]:
    """框架特定的安全配置检查"""
    findings = []

    if framework == "django":
        findings.extend(_check_django(root))
    elif framework == "flask":
        findings.extend(_check_flask(root))
    elif framework == "fastapi":
        findings.extend(_check_fastapi(root))

    return findings


def _check_django(root: Path) -> list[Finding]:
    findings = []

    settings_files = list(root.rglob("settings.py")) + list(root.rglob("settings/*.py"))
    for sf in settings_files:
        try:
            content = sf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if 'DEBUG = True' in content:
            findings.append(Finding(
                stage=StageName.SAST,
                severity=Severity.MEDIUM,
                title="Django DEBUG 模式开启",
                file_path=str(sf),
                remediation="生产环境设置 DEBUG = False",
            ))

        if "ALLOWED_HOSTS" in content and "*" in content.split("ALLOWED_HOSTS")[1][:50]:
            findings.append(Finding(
                stage=StageName.SAST,
                severity=Severity.MEDIUM,
                title="Django ALLOWED_HOSTS 包含通配符",
                file_path=str(sf),
                remediation="限制 ALLOWED_HOSTS 为具体域名",
            ))

        if 'SECRET_KEY' in content and 'os.environ' not in content.split('SECRET_KEY')[1][:100]:
            findings.append(Finding(
                stage=StageName.SAST,
                severity=Severity.HIGH,
                title="Django SECRET_KEY 硬编码",
                file_path=str(sf),
                remediation="从环境变量读取 SECRET_KEY",
            ))

    return findings


def _check_flask(root: Path) -> list[Finding]:
    findings = []

    for py in root.rglob("*.py"):
        try:
            content = py.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if 'app.secret_key' in content and 'os.environ' not in content.split('app.secret_key')[1][:100]:
            findings.append(Finding(
                stage=StageName.SAST,
                severity=Severity.HIGH,
                title="Flask secret_key 硬编码",
                file_path=str(py),
                remediation="从环境变量读取 secret_key",
            ))

        if 'app.debug = True' in content or 'run(debug=True)' in content:
            findings.append(Finding(
                stage=StageName.SAST,
                severity=Severity.MEDIUM,
                title="Flask DEBUG 模式开启",
                file_path=str(py),
                remediation="生产环境关闭 debug 模式",
            ))

    return findings


def _check_fastapi(root: Path) -> list[Finding]:
    findings = []

    for py in root.rglob("*.py"):
        try:
            content = py.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if 'docs_url=None' not in content and 'FastAPI(' in content:
            # 检查是否有裸露的文档端点
            if 'docs_url' not in content:
                findings.append(Finding(
                    stage=StageName.SAST,
                    severity=Severity.LOW,
                    title="FastAPI 文档端点未禁用",
                    file_path=str(py),
                    remediation="生产环境设置 docs_url=None 和 redoc_url=None",
                ))

    return findings
