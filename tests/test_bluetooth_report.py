from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from apk_forensics.config import AnalysisConfig
from apk_forensics.pipeline import run_pipeline


def test_bluetooth_path_skipped_without_androguard(synthetic_apk: Path, tmp_path: Path) -> None:
    with patch("apk_forensics.bluetooth_path.is_androguard_available", return_value=False):
        report, outputs, _ = run_pipeline(
            synthetic_apk,
            tmp_path / "out",
            config=AnalysisConfig(formats=("json", "markdown"), bluetooth_path=True),
        )
    assert report.schema_version == "0.3"
    assert report.bluetooth_path is not None
    assert report.bluetooth_path["enabled"] is True
    assert report.bluetooth_path["status"] == "skipped"
    payload = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert "bluetooth_path" in payload
    md = outputs["markdown"].read_text(encoding="utf-8")
    assert "Bluetooth RFCOMM Path Analysis" in md


def test_shallow_unaffected(synthetic_apk: Path, tmp_path: Path) -> None:
    report, _, _ = run_pipeline(
        synthetic_apk,
        tmp_path / "out",
        config=AnalysisConfig(formats=("json",)),
    )
    assert report.schema_version == "0.1"
    assert report.bluetooth_path is None
