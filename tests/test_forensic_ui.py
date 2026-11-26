"""Read-only Forensic UI snapshot tests — no APK analysis, no invented classifications."""

from __future__ import annotations

import json
from pathlib import Path

from apk_forensics.ui.snapshot import (
    SNAPSHOT_SCHEMA,
    build_ui_snapshot,
    write_ui_snapshot,
)
from apk_forensics.ui.server import STATIC_DIR

ROOT = Path(__file__).resolve().parents[1]


def _has(rel: str) -> bool:
    return (ROOT / rel).is_file()


def test_static_assets_present() -> None:
    assert (STATIC_DIR / "index.html").is_file()
    assert (STATIC_DIR / "app.js").is_file()
    assert (STATIC_DIR / "styles.css").is_file()


def test_bmw_snapshot_loads_and_keeps_v001_fact() -> None:
    if not _has("output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json"):
        return
    snap = build_ui_snapshot(root=ROOT, case="bmw-connected")
    assert snap["schema"] == SNAPSHOT_SCHEMA
    assert snap["focus_value_id"] == "VALUE-V001"
    assert snap["analysis_status"]["PROTOCOL_SEMANTICS"] == "UNKNOWN"
    assert snap["analysis_status"]["RUNTIME_EXECUTION"] == "INPUT_MISSING"
    v001 = next(v for v in snap["values"] if v["value_id"] == "VALUE-V001")
    assert v001["classification"] == "FACT"
    assert v001["semantic_label"] is None
    assert v001["protocol_semantics"] == "UNKNOWN"
    node = next(n for n in snap["nodes"] if n["id"] == "n-decodeversion")
    assert node["classification"] == "FACT"
    assert "BIG_ENDIAN" in json.dumps(node.get("details") or {})
    # counters from reports, not hardcoded invent
    assert snap["counters"]["structured_values"] == 24
    assert snap["counters"]["rfcomm_targets"] == 4
    assert snap["counters"]["evidence_paths"] == 13
    assert snap["correlation_graph"]["full_chain_present"] is False
    assert snap["runtime_wire"]["WIRE"] == "AVAILABLE"
    assert "same-session" in (snap["runtime_wire"].get("warning") or "").lower() or "LAB_B3" in (
        snap["runtime_wire"].get("wire_artefact") or ""
    )


def test_classifications_not_upgraded() -> None:
    if not _has("output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json"):
        return
    snap = build_ui_snapshot(root=ROOT, case="bmw-connected")
    assert snap["closing_assessment"]["Runtime_V001_execution"] in {
        "INPUT_MISSING",
        "INPUT_MISSING".lower(),
    } or "INPUT_MISSING" in str(snap["closing_assessment"]["Runtime_V001_execution"])
    oe = {e["id"]: e for e in snap["open_edges"]}
    assert oe["oe-runtime"]["status"] == "INPUT_MISSING"
    assert "NOT_FOUND" not in oe["oe-runtime"]["status"]
    assert oe["oe-outbound"]["status"] == "NOT_PROVEN"
    assert oe["oe-dynamic-dispatch"]["status"] == "DYNAMIC_DISPATCH"
    assert oe["oe-semantics"]["status"] == "UNKNOWN"
    assert snap["correlation_graph"]["full_chain_present"] is False


def test_session_mismatch_rule_visible() -> None:
    if not _has("output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json"):
        return
    snap = build_ui_snapshot(root=ROOT, case="bmw-connected")
    ex = snap["correlation_graph"]["session_mismatch_example"]
    assert "REJECTED" in str(ex.get("result"))


def test_wire_not_presented_as_runtime() -> None:
    if not _has("output/v16-runtime-capture/runtime_evidence.v1.json"):
        return
    snap = build_ui_snapshot(root=ROOT, case="bmw-connected")
    assert snap["runtime_wire"]["RUNTIME"] == "INPUT_MISSING"
    assert snap["runtime_wire"]["CORRELATION"] == "NOT_EXECUTED"
    # no fake runtime nodes
    assert not any(n.get("kind") == "RUNTIME_EVENT" for n in snap["nodes"])


def test_bimmerlink_partial_case() -> None:
    if not _has("output/bimmerlink-2381/META.json"):
        return
    snap = build_ui_snapshot(root=ROOT, case="bimmerlink")
    assert snap["schema"] == SNAPSHOT_SCHEMA
    assert snap["counters"]["structured_values"] in {0, None} or snap["counters"]["structured_values"] == 0
    # META says 0 structured values
    assert snap["apk"]["package"] == "io.sgsoftware.bimmerlink"
    assert snap["analysis_status"]["PROTOCOL_SEMANTICS"] == "UNKNOWN"
    assert snap["correlation_graph"]["full_chain_present"] is False


def test_serial_bt_case() -> None:
    if not _has("output/serial-bt-terminal-152/v15-flow/APPLICATION_FLOW_EVIDENCE_REPORT.json"):
        return
    snap = build_ui_snapshot(root=ROOT, case="serial-bt")
    assert snap["schema"] == SNAPSHOT_SCHEMA
    assert isinstance(snap["values"], list)
    assert snap["analysis_status"]["PROTOCOL_SEMANTICS"] == "UNKNOWN"


def test_empty_values_case_synthetic(tmp_path: Path) -> None:
    # Minimal synthetic reports: no structured values
    app = tmp_path / "app.json"
    app.write_text(
        json.dumps(
            {
                "schema": "apk_forensics.application_flow_evidence_report.v1",
                "answers": {"1_structured_values_from_s4": {"catalog_count": 0, "sample_ids": []}},
                "value_catalog": [],
                "provenance": {"apk": "synthetic.apk", "postprocessing_version": "1.6.1"},
            }
        ),
        encoding="utf-8",
    )
    flow = tmp_path / "flow.json"
    flow.write_text(
        json.dumps({"schema": "apk_forensics.structured_value_flow.v1", "value_catalog": [], "counts": {"catalog_values": 0}}),
        encoding="utf-8",
    )
    snap = build_ui_snapshot(
        root=tmp_path,
        case=None,
        sources={
            "application_flow": "app.json",
            "structured_value_flow": "flow.json",
        },
        label="synthetic-empty",
        focus_value_id=None,
    )
    # case None with custom sources — CASE_PRESETS empty; build with sources only via case override
    # build_ui_snapshot requires case from presets OR sources — we passed sources with case=None
    assert snap["values"] == []
    assert snap["nodes"] == []
    assert snap["correlation_graph"]["full_chain_present"] is False


def test_write_snapshot_deterministic(tmp_path: Path) -> None:
    if not _has("output/bimmerlink-2381/META.json"):
        return
    a = build_ui_snapshot(root=ROOT, case="bimmerlink")
    b = build_ui_snapshot(root=ROOT, case="bimmerlink")
    assert a["content_sha256"] == b["content_sha256"]
    path = write_ui_snapshot(a, tmp_path / "snap.json")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["schema"] == SNAPSHOT_SCHEMA
