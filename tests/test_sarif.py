"""SARIF 输出测试。"""

import json
from pathlib import Path

from mobilesec.models import Finding, ScanReport, Severity, StageName, StageResult
from mobilesec.sarif import build_sarif, run


def _finding(title="硬编码密钥", path="backend/app.py", line=3, severity=Severity.HIGH, **kw):
    return Finding(
        stage=StageName.SAST,
        severity=severity,
        title=title,
        file_path=path,
        line_number=line,
        **kw,
    )


def _report(*findings) -> ScanReport:
    return ScanReport(
        target="/proj",
        results=[StageResult(stage=StageName.SAST, findings=list(findings))],
    )


def test_minimal_structure():
    doc = build_sarif(_report(_finding()))

    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    run0 = doc["runs"][0]
    assert run0["tool"]["driver"]["name"] == "mobilesec"
    assert isinstance(run0["tool"]["driver"]["rules"], list)
    assert len(run0["results"]) == 1


def test_rule_is_shared_across_same_title():
    doc = build_sarif(_report(_finding(line=1), _finding(line=9)))
    run0 = doc["runs"][0]

    assert len(run0["tool"]["driver"]["rules"]) == 1, "同一标题应共用一条 rule"
    assert len(run0["results"]) == 2, "两条命中应是两条 result"


def test_rule_id_is_stable_across_builds():
    id1 = build_sarif(_report(_finding()))["runs"][0]["tool"]["driver"]["rules"][0]["id"]
    id2 = build_sarif(_report(_finding()))["runs"][0]["tool"]["driver"]["rules"][0]["id"]

    assert id1 == id2, "规则 id 必须稳定，否则 GitHub 无法收敛历史告警"
    assert id1.startswith("mobilesec/")


def test_severity_mapping():
    cases = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    for severity, expected in cases.items():
        doc = build_sarif(_report(_finding(severity=severity)))
        assert doc["runs"][0]["results"][0]["level"] == expected, severity


def test_security_severity_numeric():
    doc = build_sarif(_report(_finding(severity=Severity.CRITICAL)))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert float(rules[0]["properties"]["security-severity"]) >= 9.0


def test_same_rule_takes_highest_severity():
    doc = build_sarif(
        _report(
            _finding(severity=Severity.LOW, line=1),
            _finding(severity=Severity.CRITICAL, line=2),
        )
    )
    rules = doc["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1
    assert float(rules[0]["properties"]["security-severity"]) >= 9.0
    assert rules[0]["defaultConfiguration"]["level"] == "error"


def test_file_path_made_relative_to_project_root(tmp_path):
    target = tmp_path / "backend" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_text("x=1", encoding="utf-8")

    doc = build_sarif(_report(_finding(path=str(target))), project_root=tmp_path)

    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"]
    assert uri == "backend/app.py", uri
    assert "\\" not in uri, "SARIF uri 必须是 POSIX 分隔符"


def test_line_number_emitted():
    doc = build_sarif(_report(_finding(line=42)))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42


def test_no_location_when_finding_has_no_file():
    doc = build_sarif(_report(_finding(path=None, line=None)))
    assert "locations" not in doc["runs"][0]["results"][0]


def test_cwe_cve_package_properties():
    doc = build_sarif(
        _report(
            _finding(
                cwe_id="CWE-798",
                cve_id="CVE-2024-0001",
                package="requests",
                fix_version="2.32.0",
            )
        )
    )
    run0 = doc["runs"][0]
    rule = run0["tool"]["driver"]["rules"][0]
    result = run0["results"][0]

    assert rule["properties"]["cwe"] == ["CWE-798"]
    assert result["properties"]["cve"] == "CVE-2024-0001"
    assert result["properties"]["package"] == "requests"
    assert result["properties"]["fixVersion"] == "2.32.0"


def test_references_skips_non_http():
    doc = build_sarif(
        _report(_finding(references=["https://example.com/a", "/local/path.md"]))
    )
    related = doc["runs"][0]["results"][0].get("relatedLocations", [])
    uris = [r["physicalLocation"]["artifactLocation"]["uri"] for r in related]

    assert uris == ["https://example.com/a"]


def test_run_writes_valid_json_file(tmp_path):
    path = run(_report(_finding()), output_dir=str(tmp_path), project_root=tmp_path)

    assert path.endswith(".sarif")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_empty_report_is_valid_sarif():
    doc = build_sarif(ScanReport())

    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
