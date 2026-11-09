from pathlib import Path

from mobilesec.config import ScanConfig
from mobilesec.models import StageName
from mobilesec.stages import dast, mobile


def test_load_resolves_relative_paths_from_project_root(tmp_path, monkeypatch):
    project = tmp_path / "project"
    (project / ".mobilesec").mkdir(parents=True)
    (project / "backend").mkdir()
    (project / "mobile").mkdir()
    (project / "custom.yaml").write_text(
        "backend:\n  source_dir: ./backend\nmobile:\n  source_dir: ./mobile\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    config = ScanConfig.load(project, "custom.yaml")

    assert Path(config.backend.source_dir) == (project / "backend").resolve()
    assert Path(config.mobile.source_dir) == (project / "mobile").resolve()


def test_dast_without_target_is_explicitly_skipped():
    result = dast.run(ScanConfig())

    assert result.stage is StageName.DAST
    assert result.success is True
    assert result.skipped is True


def test_mobile_missing_directory_is_explicitly_skipped(tmp_path):
    config = ScanConfig()
    config.mobile.source_dir = str(tmp_path / "missing-mobile")

    result = mobile.run(config)

    assert result.stage is StageName.MOBILE
    assert result.success is True
    assert result.skipped is True
