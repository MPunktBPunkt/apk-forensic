from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from apk_forensics import __version__
from apk_forensics.config import AnalysisConfig
from apk_forensics.pipeline import run_pipeline


def test_shallow_scan_remains_schema_0_1(synthetic_apk: Path, tmp_path: Path) -> None:
    report, outputs, _ = run_pipeline(
        synthetic_apk,
        tmp_path / "out",
        config=AnalysisConfig(formats=("json", "markdown")),
    )
    assert report.schema_version == "0.1"
    assert report.dex_context is None
    payload = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert "dex_context" not in payload
    assert payload["tool"]["version"] == __version__


def test_dex_context_without_androguard_is_skipped(synthetic_apk: Path, tmp_path: Path) -> None:
    with patch("apk_forensics.dex_context_runner.is_androguard_available", return_value=False):
        report, outputs, _ = run_pipeline(
            synthetic_apk,
            tmp_path / "out",
            config=AnalysisConfig(formats=("json", "markdown"), dex_context=True, max_dex_context_results=10),
        )
    assert report.schema_version == "0.2"
    assert report.dex_context is not None
    assert report.dex_context["enabled"] is True
    assert report.dex_context["status"] == "skipped"
    assert any("androguard" in w.lower() for w in report.dex_context["warnings"])
    md = outputs["markdown"].read_text(encoding="utf-8")
    assert "DEX Context Analysis" in md
