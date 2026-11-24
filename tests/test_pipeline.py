from __future__ import annotations

from pathlib import Path

from apk_forensics.cli import main
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ExitCode, InvalidApkError
from apk_forensics.pipeline import run_pipeline
import pytest


def test_full_pipeline_synthetic(synthetic_apk: Path, tmp_path: Path, sample_profile: Path) -> None:
    report, outputs, warnings = run_pipeline(
        synthetic_apk,
        tmp_path / "out",
        config=AnalysisConfig(formats=("all",)),
        profile_path=str(sample_profile),
    )
    assert report.input.is_zip is True
    assert report.analysis.status in {"complete", "partial"}
    assert outputs["json"].exists()
    assert outputs["markdown"].exists()
    kinds = {f.kind for f in report.findings}
    assert "api" in kinds or "uuid" in kinds
    assert any(f.profile_matches for f in report.findings) or report.profile_matches


def test_pipeline_without_optional_deps(synthetic_apk: Path, tmp_path: Path) -> None:
    # Tool must run regardless of androguard/pyelftools presence.
    report, _, _ = run_pipeline(
        synthetic_apk,
        tmp_path / "out",
        config=AnalysisConfig(formats=("json",)),
    )
    scanner_names = {s["name"] for s in report.analysis.scanners}
    assert "manifest_analyzer" in scanner_names
    assert "native_analyzer" in scanner_names
    assert report.analysis.status in {"complete", "partial"}


def test_invalid_apk_exit_code(tmp_path: Path) -> None:
    bad = tmp_path / "not.apk"
    bad.write_bytes(b"this is not a zip")
    code = main(["scan", str(bad), "--output", str(tmp_path / "out")])
    assert code == ExitCode.INVALID_APK


def test_invalid_apk_raises(tmp_path: Path) -> None:
    bad = tmp_path / "not.apk"
    bad.write_bytes(b"this is not a zip")
    with pytest.raises(InvalidApkError):
        run_pipeline(bad, tmp_path / "out", config=AnalysisConfig(formats=("json",)))


def test_cli_help() -> None:
    with pytest.raises(SystemExit) as exc:
        # argparse --help exits 0
        from apk_forensics.cli import build_parser

        build_parser().parse_args(["--help"])
    assert exc.value.code == 0
