from __future__ import annotations

import json
from pathlib import Path

from apk_forensics import __version__
from apk_forensics.config import AnalysisConfig
from apk_forensics.pipeline import run_pipeline


def test_reports_written(synthetic_apk: Path, tmp_path: Path, sample_profile: Path) -> None:
    out = tmp_path / "out"
    report, outputs, _ = run_pipeline(
        synthetic_apk,
        out,
        config=AnalysisConfig(formats=("json", "markdown")),
        profile_path=str(sample_profile),
    )
    assert outputs["json"].exists()
    assert outputs["markdown"].exists()
    payload = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert payload["input"]["sha256"] == report.input.sha256
    assert payload["tool"]["version"] == __version__
    assert payload["analysis"]["scanners"]
    assert payload["findings"]
    # deterministic display ids
    display_ids = [f["display_id"] for f in payload["findings"]]
    assert display_ids == sorted(display_ids) or display_ids == [f"F{i:06d}" for i in range(1, len(display_ids) + 1)]
    assert display_ids[0] == "F000001"
    md = outputs["markdown"].read_text(encoding="utf-8")
    assert report.input.sha256 in md
    assert __version__ in md


def test_report_schema(synthetic_apk: Path, tmp_path: Path) -> None:
    jsonschema = pytest_import_jsonschema()
    out = tmp_path / "out"
    _, outputs, _ = run_pipeline(
        synthetic_apk,
        out,
        config=AnalysisConfig(formats=("json",)),
    )
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    payload = json.loads(outputs["json"].read_text(encoding="utf-8"))
    jsonschema.validate(instance=payload, schema=schema)


def pytest_import_jsonschema():
    import jsonschema

    return jsonschema
