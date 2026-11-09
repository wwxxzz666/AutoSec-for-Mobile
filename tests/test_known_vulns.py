"""漏洞库匹配的范围回归测试。

历史问题：_match_known_vulns 把配置的框架加上 django/flask/fastapi/uvicorn
四个框架全都搜一遍，任何项目都会拿到其他框架的漏洞（纯噪声）。
"""

from dataclasses import dataclass, field
from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.stages import dependency


@dataclass
class _FakeEntry:
    id: str
    title: str
    product: str
    severity: str = "HIGH"
    tags: list[str] = field(default_factory=list)
    fingerprint: list[str] = field(default_factory=list)
    path: Path = Path("/tmp/vuln.md")


class _FakeKB:
    exists = True

    def __init__(self):
        self.calls: list[str | None] = []

    def search_vulns(self, product=None, fingerprint=None):
        self.calls.append(product)
        return [_FakeEntry(id=f"CVE-{product}", title=f"{product} 漏洞", product=product or "")]


def test_only_configured_framework_is_searched():
    kb = _FakeKB()
    config = ScanConfig()
    config.backend.framework = "fastapi"

    findings = dependency._match_known_vulns(config, kb)

    assert kb.calls == ["fastapi"], f"实际搜索了: {kb.calls}"
    assert len(findings) == 1
    assert findings[0].title == "fastapi 漏洞"
    assert findings[0].cve_id == "CVE-fastapi"


def test_empty_framework_searches_nothing():
    kb = _FakeKB()
    config = ScanConfig()
    config.backend.framework = ""

    assert dependency._match_known_vulns(config, kb) == []
    assert kb.calls == []


def test_framework_is_normalized():
    kb = _FakeKB()
    config = ScanConfig()
    config.backend.framework = "  Django  "

    dependency._match_known_vulns(config, kb)

    assert kb.calls == ["django"]


def test_unknown_severity_falls_back_to_info():
    kb = _FakeKB()

    class _KB(_FakeKB):
        def search_vulns(self, product=None, fingerprint=None):
            return [_FakeEntry(id="X", title="t", product="fastapi", severity="WHATEVER")]

    config = ScanConfig()
    config.backend.framework = "fastapi"

    findings = dependency._match_known_vulns(config, _KB())

    from mobilesec.models import Severity

    assert findings[0].severity is Severity.INFO
