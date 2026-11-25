from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from apk_forensics.cli import main
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ExitCode
from apk_forensics.pipeline import run_pipeline
from apk_forensics.search_plan import (
    PlanValidationError,
    apply_search_plan_to_config,
    compute_plan_sha256,
    load_search_plan,
    validate_and_normalize,
)


PLANS = Path(__file__).resolve().parents[1] / "plans"


def _write_plan(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _minimal_plan(**overrides) -> dict:
    data = {
        "schema_version": "1.0",
        "plan": {
            "name": "t",
            "description": "test",
            "modules": ["manifest", "dex", "candidate"],
        },
    }
    data.update(overrides)
    return data


def test_valid_example_plans() -> None:
    for name in (
        "bluetooth_rfcomm.yaml",
        "native_static.yaml",
        "communication_stack.yaml",
        "communication_evidence.yaml",
        "static_runtime_correlation.yaml",
    ):
        plan = load_search_plan(PLANS / name)
        assert plan.schema_version == "1.0"
        assert plan.plan_sha256
        assert len(plan.modules) >= 1


def test_missing_schema_version(tmp_path: Path) -> None:
    raw = _minimal_plan()
    del raw["schema_version"]
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("schema_version" in e for e in exc.value.errors)


def test_unknown_module(tmp_path: Path) -> None:
    raw = _minimal_plan()
    raw["plan"]["modules"] = ["manifest", "foo"]
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("unknown module: foo" in e for e in exc.value.errors)


def test_unknown_field(tmp_path: Path) -> None:
    raw = _minimal_plan()
    raw["surprise"] = True
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("unknown field: surprise" in e for e in exc.value.errors)


def test_invalid_xref_depth() -> None:
    raw = _minimal_plan()
    raw["dex_context"] = {"enabled": True, "xref_depth": 9}
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("xref_depth" in e for e in exc.value.errors)


def test_invalid_limits() -> None:
    raw = _minimal_plan()
    raw["limits"] = {"max_results": 0}
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("max_results" in e for e in exc.value.errors)


def test_forbidden_shell_directive() -> None:
    raw = _minimal_plan()
    raw["shell"] = "rm -rf /"
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("forbidden" in e or "unknown field" in e for e in exc.value.errors)


def test_nested_exec_rejected() -> None:
    raw = _minimal_plan()
    raw["search"] = {"terms": ["x"], "exec": "os.system('id')"}
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("forbidden" in e or "unknown field" in e for e in exc.value.errors)


def test_output_path_blocked() -> None:
    raw = _minimal_plan()
    raw["output"] = {"format": ["json"], "path": "/tmp/evil"}
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("path" in e.lower() for e in exc.value.errors)


def test_profile_path_traversal_blocked() -> None:
    raw = _minimal_plan()
    raw["profile"] = {"path": "../../etc/passwd"}
    with pytest.raises(PlanValidationError) as exc:
        validate_and_normalize(raw)
    assert any("traversal" in e for e in exc.value.errors)


def test_terms_not_auto_regex() -> None:
    raw = _minimal_plan()
    raw["search"] = {"terms": ["createRfcommSocket.*"]}
    plan = validate_and_normalize(raw)
    assert plan.search_terms == ["createRfcommSocket.*"]
    assert plan.search_regex == []


def test_uuid_normalization_casefold() -> None:
    raw = _minimal_plan()
    raw["search"] = {
        "uuids": [
            "00001101-0000-1000-8000-00805F9B34FB",
            "00001101-0000-1000-8000-00805f9b34fb",
        ]
    }
    plan = validate_and_normalize(raw)
    assert plan.search_uuids == ["00001101-0000-1000-8000-00805f9b34fb"]


def test_normalization_stable_hash() -> None:
    a = _minimal_plan()
    a["search"] = {"terms": ["B", "A"], "api_patterns": ["usb", "bluetooth"]}
    a["plan"]["modules"] = ["candidate", "dex", "manifest"]
    b = _minimal_plan()
    b["search"] = {"terms": ["A", "B"], "api_patterns": ["bluetooth", "usb"]}
    b["plan"]["modules"] = ["manifest", "dex", "candidate"]
    pa = validate_and_normalize(a)
    pb = validate_and_normalize(b)
    assert pa.to_canonical_dict() == pb.to_canonical_dict()
    assert pa.plan_sha256 == pb.plan_sha256
    assert compute_plan_sha256(pa.to_canonical_dict()) == pa.plan_sha256


def test_cli_plan_validate_and_show() -> None:
    code = main(["plan", "validate", str(PLANS / "bluetooth_rfcomm.yaml")])
    assert code == ExitCode.SUCCESS
    code = main(["plan", "show", str(PLANS / "native_static.yaml"), "--json"])
    assert code == ExitCode.SUCCESS


def test_cli_plan_invalid(tmp_path: Path) -> None:
    path = _write_plan(tmp_path, _minimal_plan(plan={"name": "x", "modules": ["nope"]}))
    code = main(["plan", "validate", str(path)])
    assert code == ExitCode.INVALID_ARGS


def test_scan_with_plan(synthetic_apk: Path, tmp_path: Path) -> None:
    plan_path = _write_plan(
        tmp_path,
        {
            "schema_version": "1.0",
            "plan": {
                "name": "synth",
                "modules": ["manifest", "zip_inventory", "dex", "strings", "uuid", "candidate", "native"],
            },
            "search": {
                "terms": ["createRfcommSocketToServiceRecord", "BCL"],
                "api_patterns": ["bluetooth"],
            },
            "output": {"format": ["json"]},
        },
    )
    code = main(
        [
            "scan",
            str(synthetic_apk),
            "--plan",
            str(plan_path),
            "--output",
            str(tmp_path / "out"),
            "--format",
            "json",
        ]
    )
    assert code in {ExitCode.SUCCESS, ExitCode.PARTIAL_OR_WARNINGS}
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["analysis"].get("plan_sha256")
    assert report["search_plan"]["plan"]["name"] == "synth"
    # Plan terms produced searchable findings without inventing classifications
    plan_hits = [f for f in report["findings"] if "plan_term" in (f.get("tags") or [])]
    assert plan_hits
    assert all(f["classification"] in {"FACT", "CORRELATION", "INFERENCE", "UNKNOWN"} for f in plan_hits)


def test_scan_without_plan_still_works(synthetic_apk: Path, tmp_path: Path) -> None:
    report, _, _ = run_pipeline(
        synthetic_apk,
        tmp_path / "out",
        config=AnalysisConfig(formats=("json",)),
    )
    assert report.search_plan is None
    assert report.analysis.plan_sha256 is None
    assert report.findings


def test_apply_plan_to_config() -> None:
    plan = load_search_plan(PLANS / "bluetooth_rfcomm.yaml")
    cfg = AnalysisConfig()
    apply_search_plan_to_config(plan, cfg)
    assert cfg.bluetooth_path is True
    assert cfg.dex_context is True
    assert cfg.xref_depth == 2
    assert cfg.search_plan_sha256 == plan.plan_sha256
    assert "bluetooth" in (cfg.enabled_modules or set())
