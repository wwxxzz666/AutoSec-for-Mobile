"""MobSF 移动端分析工具封装"""

from __future__ import annotations

import json
import logging
from typing import Any

from mobilesec.models import Finding, Severity, StageName
from mobilesec.tools.base import logger as base_logger

logger = logging.getLogger(__name__)


class MobSFClient:
    """MobSF REST API 客户端"""

    def __init__(self, server_url: str = "http://localhost:8000", api_key: str = ""):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key

    def _request(self, method: str, endpoint: str, data: dict | None = None) -> dict | None:
        """发送 HTTP 请求到 MobSF"""
        import urllib.request
        import urllib.error

        url = f"{self.server_url}/api/v1/{endpoint}"
        headers = {"X-Mobsf-Api-Key": self.api_key, "Authorization": self.api_key}
        body = None
        if data:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read())
        except urllib.error.URLError as e:
            logger.error("MobSF 请求失败: %s", e)
            return None
        except Exception as e:
            logger.error("MobSF 错误: %s", e)
            return None

    def scan_apk(self, file_path: str) -> dict | None:
        """上传并扫描 APK"""
        return self._request("POST", "android scan", {"file": file_path})

    def scan_ipa(self, file_path: str) -> dict | None:
        """上传并扫描 IPA"""
        return self._request("POST", "ios scan", {"file": file_path})

    def scan_source(self, file_path: str, platform: str = "android") -> dict | None:
        """扫描源码"""
        endpoint = "android scan" if platform == "android" else "ios scan"
        return self._request("POST", endpoint, {"file": file_path})


def run_source_scan(source_dir: str, platform: str = "android", mobsf_url: str = "") -> list[Finding]:
    """通过 MobSF 进行源码扫描"""
    if not mobsf_url:
        logger.info("未配置 MobSF 地址，跳过移动端动态分析")
        return []

    client = MobSFClient(mobsf_url)
    result = client.scan_source(source_dir, platform)
    if not result:
        return []

    return _parse_mobsf_result(result)


def run_static_checks(source_dir: str) -> list[Finding]:
    """不依赖 MobSF 的静态安全检查（纯文件扫描）"""
    from pathlib import Path

    findings = []
    root = Path(source_dir)

    if not root.exists():
        return findings

    # 检查硬编码的敏感信息
    findings.extend(_check_hardcoded_secrets(root))

    # 检查不安全的存储使用
    findings.extend(_check_insecure_storage(root))

    # 检查不安全的网络配置
    findings.extend(_check_network_security(root))

    return findings


def _check_hardcoded_secrets(root) -> list[Finding]:
    """检查硬编码的密钥/Token"""
    import re

    findings = []
    patterns = {
        r'(?i)(api[_-]?key|secret[_-]?key|private[_-]?key)\s*[=:]\s*["\'][^"\']{8,}': "硬编码的密钥/Token",
        r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}': "硬编码的密码",
        r'(?i)AIza[0-9A-Za-z\-_]{35}': "硬编码的 Google API Key",
        r'(?i)sk-[a-zA-Z0-9]{20,}': "硬编码的 OpenAI API Key",
        r'(?i)AKIA[0-9A-Z]{16}': "硬编码的 AWS Access Key",
    }

    extensions = {".js", ".ts", ".jsx", ".tsx", ".dart", ".vue", ".py", ".json", ".yaml", ".yml", ".env", ".properties", ".xml", ".plist"}

    for fp in _iter_source_files(root, extensions):
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pattern, desc in patterns.items():
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.HIGH,
                    title=desc,
                    description=f"在文件中发现硬编码的敏感信息",
                    file_path=str(fp),
                    line_number=line_num,
                    remediation="将敏感信息移至环境变量或安全的密钥管理服务",
                ))

    return findings


def _check_insecure_storage(root) -> list[Finding]:
    """检查不安全的数据存储"""
    findings = []
    extensions = {".js", ".ts", ".jsx", ".tsx", ".dart", ".vue"}

    insecure_patterns = [
        ("AsyncStorage", "React Native AsyncStorage 存储敏感数据", "使用 flutter_secure_storage 或 Keychain/Keystore"),
        ("shared_preferences", "Flutter SharedPreferences 存储敏感数据", "使用 flutter_secure_storage"),
        ("uni.setStorageSync", "UniApp 本地存储敏感数据", "对敏感数据加密后再存储"),
    ]

    for fp in _iter_source_files(root, extensions):
        try:
            content = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pattern, desc, fix in insecure_patterns:
            if pattern in content:
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.MEDIUM,
                    title=desc,
                    file_path=str(fp),
                    remediation=fix,
                ))

    return findings


def _check_network_security(root) -> list[Finding]:
    """检查网络安全配置"""
    from pathlib import Path
    findings = []

    # 检查 Android Network Security Config
    nsc_files = list(root.rglob("network_security_config.xml"))
    for nsc in nsc_files:
        content = nsc.read_text(encoding="utf-8", errors="ignore")
        if "cleartextTrafficPermitted=\"true\"" in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.HIGH,
                title="Android 允许明文流量",
                file_path=str(nsc),
                remediation="设置 cleartextTrafficPermitted 为 false",
            ))

    # 检查 iOS ATS
    plist_files = list(root.rglob("Info.plist"))
    for plist in plist_files:
        content = plist.read_text(encoding="utf-8", errors="ignore")
        if "NSAppTransportSecurity" in content and "NSAllowsArbitraryLoads" in content:
            if "true" in content.split("NSAllowsArbitraryLoads")[1][:50]:
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.HIGH,
                    title="iOS ATS 允许不安全连接",
                    file_path=str(plist),
                    remediation="关闭 NSAllowsArbitraryLoads，仅对必要域名配置例外",
                ))

    return findings


def _parse_mobsf_result(data: dict) -> list[Finding]:
    findings = []
    # MobSF 返回的跟踪器和安全问题
    for issue in data.get("security", []) + data.get("trackers", {}).get("trackers", []):
        findings.append(Finding(
            stage=StageName.MOBILE,
            severity=Severity.MEDIUM,
            title=issue.get("title", issue.get("name", "unknown")),
            description=issue.get("description", ""),
            remediation=issue.get("recommendation", ""),
        ))
    return findings


def _iter_source_files(root, extensions):
    """遍历源码文件，跳过 node_modules 等"""
    skip_dirs = {"node_modules", ".git", "vendor", "build", "dist", "__pycache__", ".gradle", ".idea"}
    for fp in root.rglob("*"):
        if any(skip in fp.parts for skip in skip_dirs):
            continue
        if fp.suffix in extensions:
            yield fp
