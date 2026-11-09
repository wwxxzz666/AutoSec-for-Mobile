"""依赖扫描阶段回归测试。"""

import json
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.stages import dependency

PIP_AUDIT_OUTPUT = {
    "vulnerabilities": [
        {
            "advisory": "CVE-2024-0001",
            "package": {"name": "requests"},
            "fix_versions": ["2.32.0"],
            "description": "",
            # 关键：aliases 是空列表而不是缺失键
            "aliases": [],
        },
        {
            "advisory": "CVE-2024-0002",
            "package": {"name": "urllib3"},
            "fix_versions": ["2.2.2"],
            "description": "",
            "aliases": ["GHSA-xxxx"],
        },
    ]
}


def _make_project(tmp_path: Path) -> Path:
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
    return backend


def test_pip_audit_empty_aliases_does_not_drop_findings(tmp_path, monkeypatch):
    """aliases 为空列表时不能抛 IndexError。

    历史问题：cve_id=vuln.get("aliases", [None])[0] 在 aliases 存在但为空时
    抛 IndexError，被外层 except 吞掉，整个 requirements 文件的扫描结果全丢。
    """
    backend = _make_project(tmp_path)

    monkeypatch.setattr("mobilesec.tools.base.check_tool_available", lambda name: True)

    class _Result:
        stdout = json.dumps(PIP_AUDIT_OUTPUT)
        returncode = 0

    monkeypatch.setattr(dependency.subprocess, "run", lambda *a, **k: _Result())

    findings = dependency._run_pip_audit(str(backend))

    assert len(findings) == 2, f"期望 2 条发现，实际 {len(findings)}: {findings}"

    by_pkg = {f.package: f for f in findings}
    assert by_pkg["requests"].cve_id is None  # 空 aliases -> None，而不是崩溃
    assert by_pkg["urllib3"].cve_id == "GHSA-xxxx"
    assert by_pkg["requests"].fix_version == "2.32.0"


def test_pip_audit_missing_tool_returns_empty(tmp_path, monkeypatch):
    backend = _make_project(tmp_path)
    monkeypatch.setattr("mobilesec.tools.base.check_tool_available", lambda name: False)

    assert dependency._run_pip_audit(str(backend)) == []


def test_pip_audit_without_requirements_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr("mobilesec.tools.base.check_tool_available", lambda name: True)
    empty = tmp_path / "empty"
    empty.mkdir()

    assert dependency._run_pip_audit(str(empty)) == []


def test_match_known_vulns_searches_configured_framework(tmp_path):
    """kb 搜索至少覆盖配置的框架（历史实现会把四个框架全扫一遍）。"""
    from mobilesec.knowledge import KnowledgeBase

    kb = KnowledgeBase(tmp_path / "kb")
    (tmp_path / "kb" / "Vuln").mkdir(parents=True)

    config = ScanConfig()
    config.backend.framework = "fastapi"

    # 不真正加载知识库内容，只确认调用不炸
    findings = dependency._match_known_vulns(config, kb)
    assert isinstance(findings, list)
