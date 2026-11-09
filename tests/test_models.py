"""Finding 去重逻辑测试（原先在三个阶段各抄了一份）。"""

from mobilesec.models import Finding, Severity, StageName, dedupe_findings


def _f(title="t", path="a.py", line=1, cve=None):
    return Finding(
        stage=StageName.SAST,
        severity=Severity.HIGH,
        title=title,
        file_path=path,
        line_number=line,
        cve_id=cve,
    )


def test_default_key_dedupes_by_title_path_line():
    a = _f("x", "a.py", 1)
    b = _f("x", "a.py", 1)
    c = _f("x", "a.py", 2)

    assert dedupe_findings([a, b, c]) == [a, c]


def test_keeps_first_occurrence_order():
    a = _f("first", "a.py", 1)
    b = _f("second", "b.py", 1)

    assert dedupe_findings([b, a, b]) == [b, a]


def test_empty_input():
    assert dedupe_findings([]) == []


def test_no_duplicates_returns_all():
    items = [_f(f"t{i}", f"{i}.py", 1) for i in range(5)]
    assert dedupe_findings(items) == items


def test_custom_key_prefers_cve():
    """依赖阶段：同一个 CVE 出现在多个文件里只报一次。"""
    a = _f("CVE-1 title", "requirements.txt", 1, cve="CVE-1")
    b = _f("CVE-1 another title", "package-lock.json", 9, cve="CVE-1")
    c = _f("CVE-2", "requirements.txt", 5, cve="CVE-2")

    result = dedupe_findings(
        [a, b, c],
        key=lambda f: f.cve_id or (f.title, f.file_path, f.line_number),
    )

    assert result == [a, c]


def test_custom_key_falls_back_when_no_cve():
    a = _f("same", "a.py", 1, cve=None)
    b = _f("same", "a.py", 1, cve=None)
    c = _f("other", "a.py", 2, cve=None)

    result = dedupe_findings(
        [a, b, c],
        key=lambda f: f.cve_id or (f.title, f.file_path, f.line_number),
    )

    assert result == [a, c]
