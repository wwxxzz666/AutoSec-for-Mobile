"""Stage 4: 移动端安全测试"""

from __future__ import annotations

import logging
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.knowledge import KnowledgeBase
from mobilesec.models import Finding, Severity, StageName, StageResult
from mobilesec.tools import mobsf

logger = logging.getLogger(__name__)


def run(config: ScanConfig, kb: KnowledgeBase | None = None) -> StageResult:
    """执行移动端安全测试"""
    findings: list[Finding] = []
    mobile_dir = Path(config.mobile.source_dir)

    if not mobile_dir.exists():
        return StageResult(
            stage=StageName.MOBILE,
            success=True,
            findings=[],
            error=f"移动端代码目录不存在: {mobile_dir}",
        )

    # 1. MobSF 静态安全检查（不依赖 MobSF 服务）
    findings.extend(mobsf.run_static_checks(str(mobile_dir)))

    # 2. 框架专项检查
    framework = config.mobile.framework
    if framework == "react-native":
        findings.extend(_check_react_native(mobile_dir))
    elif framework == "flutter":
        findings.extend(_check_flutter(mobile_dir))
    elif framework == "uniapp":
        findings.extend(_check_uniapp(mobile_dir))

    # 3. 通用移动端安全检查
    findings.extend(_check_android_manifest(mobile_dir))
    findings.extend(_check_ios_plist(mobile_dir))

    # 去重
    seen = set()
    unique = []
    for f in findings:
        key = f"{f.title}:{f.file_path}:{f.line_number}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    logger.info("移动端安全测试发现 %d 个问题", len(unique))
    return StageResult(stage=StageName.MOBILE, success=True, findings=unique)


def _check_react_native(root: Path) -> list[Finding]:
    """React Native 专项安全检查"""
    findings = []

    # 检查 Android 网络安全配置
    android_dir = root / "android"
    if android_dir.exists():
        nsc_files = list(android_dir.rglob("network_security_config.xml"))
        for nsc in nsc_files:
            content = nsc.read_text(encoding="utf-8", errors="ignore")
            if "cleartextTrafficPermitted" in content and "true" in content.lower():
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.HIGH,
                    title="允许明文 HTTP 流量",
                    file_path=str(nsc),
                    remediation="设置 cleartextTrafficPermitted=false",
                ))

    # 检查 WebView 安全配置
    for js_file in root.rglob("*.js"):
        if "node_modules" in js_file.parts:
            continue
        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if "javaScriptEnabled=true" in content or "javaScriptEnabled: true" in content:
            if "onMessage" not in content and "injectedJavaScript" not in content:
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.MEDIUM,
                    title="WebView 启用 JavaScript 但未设置安全通信",
                    file_path=str(js_file),
                    remediation="配置 WebView 的 onMessage 或 injectedJavaScript",
                ))

        if "allowFileAccess" in content and "true" in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.MEDIUM,
                title="WebView 允许文件访问",
                file_path=str(js_file),
                remediation="设置 allowFileAccess=false",
            ))

    return findings


def _check_flutter(root: Path) -> list[Finding]:
    """Flutter 专项安全检查"""
    findings = []

    # 检查 pubspec.yaml 依赖
    pubspec = root / "pubspec.yaml"
    if pubspec.exists():
        content = pubspec.read_text(encoding="utf-8", errors="ignore")
        insecure_deps = [
            ("http:", "使用不安全的 HTTP 包（应使用 dio 或 http 配合 HTTPS）"),
            ("shared_preferences:", "使用 SharedPreferences 可能存储敏感数据"),
        ]
        for dep, desc in insecure_deps:
            if dep in content and "flutter_secure_storage" not in content:
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.LOW,
                    title=desc,
                    file_path=str(pubspec),
                    remediation="使用 flutter_secure_storage 存储敏感数据",
                ))

    # 检查 Dart 代码中的 HTTP 明文请求
    for dart in root.rglob("*.dart"):
        try:
            content = dart.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if "http://" in content and "localhost" not in content and "127.0.0.1" not in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.MEDIUM,
                title="使用明文 HTTP 通信",
                file_path=str(dart),
                remediation="全部使用 HTTPS 通信",
            ))

    return findings


def _check_uniapp(root: Path) -> list[Finding]:
    """UniApp 专项安全检查"""
    findings = []

    manifest = root / "src" / "manifest.json"
    if not manifest.exists():
        manifest = root / "manifest.json"

    if manifest.exists():
        import json
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            data = {}

        # 检查权限声明
        perms = data.get("app-plus", {}).get("distribute", {}).get("android", {}).get("permissions", {})
        if isinstance(perms, dict):
            sensitive = {"READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE", "CAMERA"}
            declared_sensitive = sensitive & set(perms.keys())
            if declared_sensitive:
                findings.append(Finding(
                    stage=StageName.MOBILE,
                    severity=Severity.INFO,
                    title=f"声明了敏感权限: {', '.join(declared_sensitive)}",
                    file_path=str(manifest),
                    remediation="确认这些权限是必要的，非必要权限应移除",
                ))

    # 检查 WebView 配置
    for vue in root.rglob("*.vue"):
        try:
            content = vue.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        if "<web-view" in content and "http://" in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.MEDIUM,
                title="WebView 加载不安全的 HTTP 页面",
                file_path=str(vue),
                remediation="使用 HTTPS 加载 WebView 页面",
            ))

    return findings


def _check_android_manifest(root: Path) -> list[Finding]:
    """Android Manifest 安全检查"""
    findings = []

    manifests = list(root.rglob("AndroidManifest.xml"))
    for mf in manifests:
        if "build" in mf.parts:
            continue
        try:
            content = mf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # 检查 exported 组件
        if 'android:exported="true"' in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.MEDIUM,
                title="存在导出的 Android 组件",
                file_path=str(mf),
                remediation="检查所有 exported=true 的组件是否有权限保护",
            ))

        # 检查 allowBackup
        if 'android:allowBackup="true"' in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.LOW,
                title="允许 ADB 备份",
                file_path=str(mf),
                remediation="设置 android:allowBackup=false",
            ))

        # 检查 debuggable
        if 'android:debuggable="true"' in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.HIGH,
                title="应用标记为可调试",
                file_path=str(mf),
                remediation="发布版本移除 android:debuggable=true",
            ))

    return findings


def _check_ios_plist(root: Path) -> list[Finding]:
    """iOS Info.plist 安全检查"""
    findings = []

    plists = list(root.rglob("Info.plist"))
    for pl in plists:
        if "build" in pl.parts:
            continue
        try:
            content = pl.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # 检查 ATS
        if "NSAllowsArbitraryLoads" in content:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.HIGH,
                title="iOS App Transport Security 允许不安全连接",
                file_path=str(pl),
                remediation="配置 ATS 仅对必要域名放行",
            ))

        # 检查越狱检测
        if "canOpenURL" in content and any(s in content for s in ["cydia", "substrate"]):
            pass  # 有越狱检测
        else:
            findings.append(Finding(
                stage=StageName.MOBILE,
                severity=Severity.LOW,
                title="未实现越狱检测",
                file_path=str(pl),
                remediation="实现基础的越狱检测机制",
            ))

    return findings
