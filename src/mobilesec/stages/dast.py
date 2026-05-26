"""Stage 3: API 安全测试 (DAST)"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from urllib.parse import urljoin

from mobilesec.config import ScanConfig
from mobilesec.knowledge import KnowledgeBase
from mobilesec.models import Finding, Severity, StageName, StageResult
from mobilesec.tools import nuclei, sqlmap

logger = logging.getLogger(__name__)


def run(config: ScanConfig, kb: KnowledgeBase | None = None) -> StageResult:
    """执行 API 安全测试"""
    api_url = config.backend.api_base_url
    if not api_url:
        return StageResult(
            stage=StageName.DAST,
            success=True,
            findings=[],
            error="未配置 API 地址，跳过 DAST 阶段",
        )

    findings: list[Finding] = []

    # 1. Nuclei 已知漏洞扫描
    tags = _get_nuclei_tags(config)
    findings.extend(nuclei.run(api_url, tags=tags))

    # 2. API 端点发现
    endpoints = _discover_endpoints(config)

    # 3. SQL 注入测试
    auth_token = os.environ.get(config.auth.token_env_var, "")
    findings.extend(_run_sqli_tests(endpoints, api_url, auth_token))

    # 4. 认证与授权测试
    findings.extend(_run_auth_tests(api_url, config, auth_token))

    # 5. 从 AboutSecurity 加载 Payload 进行 Fuzz
    if kb and kb.exists:
        findings.extend(_run_payload_fuzz(api_url, config, kb))

    return StageResult(stage=StageName.DAST, success=True, findings=findings)


def _get_nuclei_tags(config: ScanConfig) -> list[str]:
    """根据框架生成 Nuclei 扫描标签"""
    tag_map = {
        "django": ["django"],
        "flask": ["flask"],
        "fastapi": ["openapi"],
    }
    tags = tag_map.get(config.backend.framework, [])
    tags.extend(["jwt", "cors", "misconfig"])
    return tags


def _discover_endpoints(config: ScanConfig) -> list[dict]:
    """从项目源码中提取 API 端点"""
    import re

    endpoints = []
    backend_dir = Path(config.backend.source_dir)
    if not backend_dir.exists():
        return endpoints

    framework = config.backend.framework
    patterns = []

    if framework == "django":
        patterns.append(r'path\(["\']([^"\']+)["\']')
        patterns.append(r're_path\(["\']([^"\']+)["\']')
    elif framework == "flask":
        patterns.append(r'@app\.route\(["\']([^"\']+)["\']')
        patterns.append(r'@blueprint\.route\(["\']([^"\']+)["\']')
    elif framework == "fastapi":
        patterns.append(r'@(router|app)\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']')

    for py in backend_dir.rglob("*.py"):
        if any(d in py.parts for d in {"__pycache__", "venv", ".venv", "migrations"}):
            continue
        try:
            content = py.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for pattern in patterns:
            for match in re.finditer(pattern, content):
                path = match.group(1) if framework != "fastapi" else match.group(3)
                method = "GET"
                if framework == "fastapi":
                    method = match.group(2).upper()
                elif "post" in match.group(0).lower():
                    method = "POST"
                endpoints.append({"path": path, "method": method})

    return endpoints


def _run_sqli_tests(endpoints: list[dict], base_url: str, token: str) -> list[Finding]:
    """对发现的端点进行 SQL 注入测试"""
    findings = []
    for ep in endpoints[:20]:  # 限制扫描数量
        path = ep["path"]
        if "{" in path:  # 跳过带路径参数的
            path = path.split("{")[0]
        url = urljoin(base_url + "/", path.lstrip("/"))
        cookie = f"token={token}" if token else None
        findings.extend(sqlmap.run(url, cookie=cookie))
    return findings


def _run_auth_tests(base_url: str, config: ScanConfig, token: str) -> list[Finding]:
    """测试认证与授权"""
    import urllib.request
    import urllib.error

    findings = []

    if not token:
        return findings

    # 测试: 无 Token 访问
    try:
        req = urllib.request.Request(base_url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                findings.append(Finding(
                    stage=StageName.DAST,
                    severity=Severity.MEDIUM,
                    title="API 端点未做认证保护",
                    description=f"不带认证信息可直接访问 {base_url}",
                    remediation="确保所有 API 端点都有认证中间件保护",
                ))
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            pass  # 正确行为
        else:
            logger.debug("认证测试异常: %s", e)
    except Exception:
        pass

    # 测试: CORS 配置
    try:
        req = urllib.request.Request(base_url)
        req.add_header("Origin", "https://evil.com")
        with urllib.request.urlopen(req, timeout=10) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if "evil.com" in acao or acao == "*":
                findings.append(Finding(
                    stage=StageName.DAST,
                    severity=Severity.MEDIUM,
                    title="CORS 配置过于宽松",
                    description="API 允许任意来源的跨域请求",
                    remediation="限制 Access-Control-Allow-Origin 为可信域名",
                ))
    except Exception:
        pass

    return findings


def _run_payload_fuzz(base_url: str, config: ScanConfig, kb: KnowledgeBase) -> list[Finding]:
    """使用 AboutSecurity Payload 进行基础 Fuzz 测试"""
    findings = []

    # 加载通用注入 payload
    sqli_payloads = kb.load_payload_content("sqli", "payload.txt")
    if sqli_payloads:
        payloads = [p.strip() for p in sqli_payloads.splitlines() if p.strip()][:50]
        findings.extend(_fuzz_with_payloads(base_url, payloads, "SQL 注入"))

    # 加载 XSS payload
    xss_payloads = kb.load_payload_content("xss", "xss-payload.txt")
    if xss_payloads:
        payloads = [p.strip() for p in xss_payloads.splitlines() if p.strip()][:50]
        findings.extend(_fuzz_with_payloads(base_url, payloads, "XSS"))

    return findings


def _fuzz_with_payloads(base_url: str, payloads: list[str], vuln_type: str) -> list[Finding]:
    """对 URL 进行 payload Fuzz（基础版：检测反射）"""
    import urllib.request
    import urllib.parse
    import urllib.error

    findings = []
    test_url = base_url.rstrip("/")

    for payload in payloads[:20]:  # 限制数量
        try:
            encoded = urllib.parse.urlencode({"q": payload})
            url = f"{test_url}?{encoded}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                # 简单的反射检测
                if payload in body and any(c in payload for c in ("<", ">", "'", '"')):
                    findings.append(Finding(
                        stage=StageName.DAST,
                        severity=Severity.MEDIUM,
                        title=f"可能的 {vuln_type} 反射",
                        description=f"Payload 在响应中被反射",
                        remediation=f"对用户输入进行编码和过滤",
                    ))
                    break  # 发现一个就够了
        except Exception:
            continue

    return findings
