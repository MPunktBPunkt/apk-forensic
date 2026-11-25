"""v1.6 static ↔ runtime ↔ wire correlation: fixtures V0–V7 + offline BMW baseline."""

from __future__ import annotations

import json
from pathlib import Path

from apk_forensics.runtime_wire_evidence import (
    inventory_external_artefacts,
    load_runtime_evidence,
    load_static_evidence_from_application_flow,
    load_wire_evidence,
)
from apk_forensics.search_plan import load_search_plan
from apk_forensics.static_runtime_correlation import (
    CLASS_CORRELATION,
    CLASS_INFERENCE,
    CLASS_REJECTED,
    CLASS_UNKNOWN,
    RESULT_MATCH_AMBIGUOUS,
    RESULT_MATCH_CONFIRMED,
    RESULT_REJECTED,
    STRENGTH_AMBIGUOUS,
    STRENGTH_EXACT,
    correlate_end_to_end,
    correlate_runtime_wire,
    correlate_static_runtime,
    estimate_correlation_work,
    run_correlation,
    write_correlation_reports,
)

ROOT = Path(__file__).resolve().parents[1]
PLANS = ROOT / "plans"


def _static(*values: dict) -> dict:
    return load_static_evidence_from_application_flow(
        {
            "value_catalog": list(values),
            "flow_counts": {"catalog_values": len(values), "field_stores": 0},
        }
    )


def _val(vid: str, method: str, **kwargs) -> dict:
    return {
        "value_id": vid,
        "source_method": method,
        "source_api": kwargs.get("source_api", method),
        "source_kind": "DECODE_RETURN_PRIMITIVE",
        "stored_field": kwargs.get("field"),
        "classification": "FACT",
        "protocol_semantics": "UNKNOWN",
        "value_class": kwargs.get("value_class", "V2_CONSUMED"),
        "consumers": kwargs.get("consumers") or [],
        "lineage": [],
    }


def test_inventory_none_or_candidates_only() -> None:
    inv = inventory_external_artefacts([ROOT / "artifacts", ROOT / "output"])
    assert inv["status"] in {"NONE_IN_REPO", "CANDIDATES_FOUND"}
    assert "Filename inventory" in inv["note"]


def test_fixture_v0_exact_static_runtime_method(tmp_path: Path) -> None:
    method = "Lcom/ex/P;->decode([B)V"
    static = _static(_val("VALUE-V001", method, field="Lcom/ex/P;->mX I"))
    rt_path = tmp_path / "runtime.json"
    rt_path.write_text(
        json.dumps(
            {
                "schema": "apk_forensics.runtime_evidence.v1",
                "events": [
                    {
                        "id": "R-0001",
                        "type": "RUNTIME_METHOD",
                        "method": method,
                        "timestamp_ms": 1000,
                        "value_id": "VALUE-V001",
                    }
                ],
            }
        )
    )
    runtime = load_runtime_evidence(rt_path)
    links = correlate_static_runtime(static, runtime)
    assert links
    assert links[0]["classification"] == CLASS_CORRELATION
    assert links[0]["runtime_id"] == "R-0001"
    assert "method_identity" in links[0]["correlation_keys"] or "value_id" in links[0]["correlation_keys"]


def test_fixture_v1_runtime_wire_exact_bytes(tmp_path: Path) -> None:
    rt = load_runtime_evidence(None)
    # build inline
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-10",
                "type": "RUNTIME_READ",
                "timestamp_ms": 500,
                "direction": "IN",
                "app_direction": "IN",
                "length": 4,
                "bytes_hex": "aabbccdd",
            }
        ],
        "counts": {"events": 1},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-10",
                "type": "WIRE_PACKET",
                "timestamp_ms": 502,
                "direction": "HU_TO_PHONE",
                "app_direction": "IN",
                "length": 4,
                "bytes_hex": "aabbccdd",
            }
        ],
        "counts": {"packets": 1},
    }
    links = correlate_runtime_wire(runtime, wire, timestamp_window_ms=50)
    assert links
    assert links[0]["strength"] == STRENGTH_EXACT
    assert links[0]["classification"] == CLASS_CORRELATION
    assert links[0]["result"] == RESULT_MATCH_CONFIRMED


def test_fixture_v2_end_to_end(tmp_path: Path) -> None:
    method = "Lcom/ex/P;->decode([B)V"
    static = _static(_val("VALUE-V007", method, field="Lcom/ex/P;->mCmd I"))
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-42",
                "type": "RUNTIME_READ",
                "method": method,
                "timestamp_ms": 2000,
                "direction": "IN",
                "app_direction": "IN",
                "length": 4,
                "bytes_hex": "01020304",
                "value_id": "VALUE-V007",
            }
        ],
        "counts": {"events": 1},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-99",
                "type": "WIRE_PACKET",
                "timestamp_ms": 1998,
                "direction": "IN",
                "app_direction": "IN",
                "length": 4,
                "bytes_hex": "01020304",
            }
        ],
        "counts": {"packets": 1},
    }
    sr = correlate_static_runtime(static, runtime)
    rw = correlate_runtime_wire(runtime, wire)
    e2e = correlate_end_to_end(sr, rw)
    assert any(x["classification"] == CLASS_CORRELATION for x in e2e)
    hit = next(x for x in e2e if x["classification"] == CLASS_CORRELATION)
    assert hit["static_id"] == "VALUE-V007"
    assert hit["wire_id"] == "W-99"
    assert hit["protocol_semantics"] == "UNKNOWN"


def test_fixture_v3_ambiguous_not_fact() -> None:
    method = "Lcom/ex/P;->decode([B)V"
    static = _static(_val("VALUE-V003", method))
    runtime = {
        "status": "OK",
        "events": [
            {"id": "R-A", "type": "RUNTIME_METHOD", "method": method, "timestamp_ms": 1},
            {"id": "R-B", "type": "RUNTIME_METHOD", "method": method, "timestamp_ms": 2},
        ],
        "counts": {"events": 2},
    }
    links = correlate_static_runtime(static, runtime)
    assert links
    assert all(x["classification"] != "FACT" for x in links)
    assert any(x["strength"] == STRENGTH_AMBIGUOUS or x["result"] == RESULT_MATCH_AMBIGUOUS for x in links)
    assert any(x["classification"] == CLASS_INFERENCE for x in links)


def test_fixture_v4_false_positive_rejected() -> None:
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-FP",
                "type": "RUNTIME_READ",
                "method_name": "decode",
                "timestamp_ms": 100,
                "direction": "IN",
                "app_direction": "IN",
                "length": 4,
                "bytes_hex": "aaaaaaaa",
            }
        ],
        "counts": {"events": 1},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-FP",
                "type": "WIRE_PACKET",
                "timestamp_ms": 105,
                "direction": "IN",
                "app_direction": "IN",
                "length": 4,
                "bytes_hex": "bbbbbbbb",
            }
        ],
        "counts": {"packets": 1},
    }
    links = correlate_runtime_wire(runtime, wire, timestamp_window_ms=50)
    assert links
    assert links[0]["classification"] == CLASS_REJECTED
    assert links[0]["result"] == RESULT_REJECTED


def test_fixture_v5_direction_mismatch() -> None:
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-DIR",
                "type": "RUNTIME_READ",
                "timestamp_ms": 50,
                "direction": "IN",
                "app_direction": "IN",
                "length": 2,
                "bytes_hex": "abcd",
            }
        ],
        "counts": {"events": 1},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-DIR",
                "type": "WIRE_PACKET",
                "timestamp_ms": 51,
                "direction": "OUT",
                "app_direction": "OUT",
                "length": 2,
                "bytes_hex": "abcd",
            }
        ],
        "counts": {"packets": 1},
    }
    links = correlate_runtime_wire(runtime, wire)
    assert links
    assert links[0]["classification"] == CLASS_REJECTED
    assert "direction" in (links[0].get("notes") or [""])[0] or links[0]["result"] == RESULT_REJECTED


def test_fixture_v6_fragmentation() -> None:
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-FRAG",
                "type": "RUNTIME_READ",
                "timestamp_ms": 300,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "00112233",
                "length": 4,
            }
        ],
        "counts": {"events": 1},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-F1",
                "type": "WIRE_PACKET",
                "timestamp_ms": 298,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "0011",
                "length": 2,
            },
            {
                "id": "W-F2",
                "type": "WIRE_PACKET",
                "timestamp_ms": 299,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "2233",
                "length": 2,
            },
        ],
        "counts": {"packets": 2},
    }
    links = correlate_runtime_wire(runtime, wire, timestamp_window_ms=50)
    frag = [x for x in links if x.get("fragmentation")]
    assert frag
    assert frag[0]["classification"] == CLASS_CORRELATION
    assert frag[0]["strength"] == STRENGTH_EXACT


def test_fixture_v7_aggregation() -> None:
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-A1",
                "type": "RUNTIME_READ",
                "timestamp_ms": 400,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "aa",
                "length": 1,
            },
            {
                "id": "R-A2",
                "type": "RUNTIME_READ",
                "timestamp_ms": 401,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "bb",
                "length": 1,
            },
            {
                "id": "R-A3",
                "type": "RUNTIME_READ",
                "timestamp_ms": 402,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "cc",
                "length": 1,
            },
        ],
        "counts": {"events": 3},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-AGG",
                "type": "WIRE_PACKET",
                "timestamp_ms": 401,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "aabbcc",
                "length": 3,
            }
        ],
        "counts": {"packets": 1},
    }
    links = correlate_runtime_wire(runtime, wire, timestamp_window_ms=50)
    agg = [x for x in links if x.get("aggregation")]
    assert agg
    assert agg[0]["classification"] == CLASS_CORRELATION


def test_missing_external_unknown(tmp_path: Path) -> None:
    flow = {
        "value_catalog": [_val("VALUE-V001", "Lcom/ex/P;->decode([B)V")],
        "flow_counts": {
            "catalog_values": 1,
            "field_stores": 8,
            "field_loads": 63,
            "parameters": 191,
            "returns": 5,
            "branches": 36,
            "state_mutations": 6,
            "collections": 2,
            "roundtrip_candidates": 13,
        },
    }
    baseline = {
        "catalog_values": 24,
        "field_stores": 8,
        "field_loads": 63,
        "parameters": 191,
        "returns": 5,
        "branches": 36,
        "state_mutations": 6,
        "collections": 2,
        "roundtrip_candidates": 13,
        "path_comm": 12,
        "max_field_hops": 2,
    }
    run = run_correlation(
        static_flow=flow,
        runtime_path=None,
        wire_path=None,
        baseline=baseline,
        static_source="test",
    )
    assert run["executed"] is True
    assert run["runtime"]["status"] == "INPUT_MISSING"
    assert run["wire"]["status"] == "INPUT_MISSING"
    assert run["answers"]["20_missing_external_only"] is True
    assert run["answers"]["protocol_semantics"] == "UNKNOWN"
    assert run["answers"]["baseline_v15_unchanged"]["path_comm"] == 12
    # static↔runtime links are UNKNOWN (no runtime)
    assert all(x["classification"] in {CLASS_UNKNOWN, CLASS_REJECTED} or x.get("runtime_id") is None for x in run["static_runtime"])

    written = write_correlation_reports(tmp_path, run)
    assert (tmp_path / "CORRELATION_FORENSIC_REPORT.json").is_file()
    assert (tmp_path / "CORRELATION_TABLE.json").is_file()
    assert "STATIC_RUNTIME_CORRELATION_REPORT.json" in written


def test_bmw_baseline_offline_no_mutation() -> None:
    meta_path = ROOT / "output/v16-baseline/BASELINE_META.json"
    flow_path = ROOT / "output/v15-application-flow/APPLICATION_FLOW_EVIDENCE_REPORT.json"
    if not meta_path.is_file() or not flow_path.is_file():
        return  # skip if artefacts absent in minimal checkout
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    flow = json.loads(flow_path.read_text(encoding="utf-8"))
    run = run_correlation(
        static_flow=flow,
        runtime_path=None,
        wire_path=None,
        baseline=meta,
        static_source=str(flow_path),
    )
    assert run["executed"]
    b = run["answers"]["baseline_v15_unchanged"]
    assert b["catalog_values"] == 24
    assert b["field_stores"] == 8
    assert b["field_loads"] == 63
    assert b["parameters"] == 191
    assert b["returns"] == 5
    assert b["branches"] == 36
    assert b["state_mutations"] == 6
    assert b["collections"] == 2
    assert b["roundtrip_candidates"] == 13
    assert b["path_comm"] == 12
    assert b["max_field_hops"] == 2
    assert run["static"]["counts"]["catalog_values"] == 24
    assert run["answers"]["protocol_semantics"] == "UNKNOWN"
    assert run["answers"]["16_semantic_evidence"] is False


def test_correlation_plan_loads() -> None:
    plan = load_search_plan(PLANS / "static_runtime_correlation.yaml")
    assert plan.correlation_enabled is True
    assert plan.correlation_max_runtime_events >= 1
    assert plan.plan_sha256


def test_estimate_indexed_not_cartesian() -> None:
    est = estimate_correlation_work(
        static_count=24,
        runtime_count=1000,
        wire_count=1000,
        max_runtime_events=10_000,
        max_wire_packets=10_000,
        max_correlations=500,
        timestamp_window_ms=50,
    )
    assert est["probes"] < 1000 * 1000  # not full cartesian
    assert est["risk"] in {"ok", "warning"}


def test_length_only_no_e2e() -> None:
    static = _static(_val("VALUE-V010", "Lcom/ex/P;->decode([B)V"))
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R-L",
                "type": "RUNTIME_READ",
                "method": "Lcom/ex/P;->decode([B)V",
                "timestamp_ms": 10,
                "direction": "IN",
                "app_direction": "IN",
                "length": 8,
                # no bytes
            }
        ],
        "counts": {"events": 1},
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W-L",
                "type": "WIRE_PACKET",
                "timestamp_ms": 12,
                "direction": "IN",
                "app_direction": "IN",
                "length": 8,
            }
        ],
        "counts": {"packets": 1},
    }
    sr = correlate_static_runtime(static, runtime)
    rw = correlate_runtime_wire(runtime, wire)
    # length+time without bytes → rejected on RW
    assert rw
    assert rw[0]["classification"] == CLASS_REJECTED
    e2e = correlate_end_to_end(sr, rw)
    assert not any(x["classification"] == CLASS_CORRELATION for x in e2e)
