"""SAST 阶段回归测试。"""

from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.models import StageName
from mobilesec.stages import sast


def test_missing_dirs_reports_readable_message(tmp_path):
    """目录都不存在时，skipped 信息必须是可读文本。

    历史问题：sast.py 里这段 error 字符串被写成了 19 个问号
    （"???????????????????"），任何报告里都会出现这串乱码。
    """
    config = ScanConfig()
    config.backend.source_dir = str(tmp_path / "no-backend")
    config.mobile.source_dir = str(tmp_path / "no-mobile")

    result = sast.run(config)

    assert result.stage is StageName.SAST
    assert result.skipped is True
    assert result.error
    assert "?" not in result.error, f"错误信息仍是乱码/占位符: {result.error!r}"
    assert result.error.isprintable()


# ---------------- _check_secrets ----------------

from mobilesec.stages import sast as _sast  # noqa: E402


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_check_secrets_reports_accurate_line_numbers(tmp_path):
    """逐行扫描后行号必须精确（旧实现靠回数换行符，代价 O(n×m)）。"""
    _write(
        tmp_path / "app.py",
        "\n".join([
            "import os",
            "x = 1",
            "y = 2",
            'API_KEY = "abcdefghijklmn"',   # 第 4 行
            "z = 3",
            "print(z)",
        ]),
    )

    findings = _sast._check_secrets(tmp_path)

    assert len(findings) == 1
    assert findings[0].line_number == 4
    assert "API_KEY" not in findings[0].title
    assert "硬编码密钥" in findings[0].title


def test_check_secrets_no_duplicate_findings_per_line(tmp_path):
    """同一条规则在一行里命中多次不该重复报（旧实现按 match 逐条产出）。"""
    _write(
        tmp_path / "conf.py",
        'password = "hunter2hunter2"; other = "anotherpassword"\n',
    )

    findings = _sast._check_secrets(tmp_path)
    titles = [_f.title for _f in findings]

    assert len(titles) == 1, titles
    assert len(set(titles)) == len(titles)


def test_check_secrets_skips_excluded_dirs(tmp_path):
    _write(tmp_path / "node_modules/pkg/secret.js", 'API_KEY = "abcdefghijklmn"')
    _write(tmp_path / "venv/lib/secret.py", 'API_KEY = "abcdefghijklmn"')

    assert _sast._check_secrets(tmp_path) == []


def test_check_secrets_skips_binary_suffix(tmp_path):
    _write(tmp_path / "image.png", 'API_KEY = "abcdefghijklmn"')

    assert _sast._check_secrets(tmp_path) == []


def test_check_secrets_multiple_files(tmp_path):
    _write(tmp_path / "a.py", 'SECRET_KEY = "0123456789abcdef"')
    _write(tmp_path / "b.js", 'const ACCESS_TOKEN = "abcdefghijklmnop"')

    findings = _sast._check_secrets(tmp_path)
    files = {f.file_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] for f in findings}

    assert files == {"a.py", "b.js"}
