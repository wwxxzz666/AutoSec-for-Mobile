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
