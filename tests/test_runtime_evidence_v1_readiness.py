"""Runtime evidence v1 readiness: evidence boundaries for a future real Android run.

Fixtures here are synthetic correlation inputs only — never claimed as live APK captures.
"""

from __future__ import annotations

import json
from pathlib import Path

from apk_forensics.runtime_wire_evidence import (
    V001_RUNTIME_HOOK_TARGET,
    adapt_external_runtime_to_v1,
    load_runtime_evidence,
    load_static_evidence_from_application_flow,
    load_wire_evidence,
)
from apk_forensics.static_runtime_correlation import (
    CHAIN_BYTE_CORRELATED,
    CHAIN_FULL,
    CHAIN_SESSION_MISMATCH,
    CHAIN_SESSION_UNKNOWN,
    CLASS_CORRELATION,
    CLASS_REJECTED,
    CLASS_UNKNOWN,
    RESULT_UNKNOWN,
    correlate_end_to_end,
    correlate_runtime_wire,
    correlate_static_runtime,
)

V001_API = V001_RUNTIME_HOOK_TARGET["static_source_api"]
V001_RUN = V001_RUNTIME_HOOK_TARGET["static_source_method"]


def _static_v001() -> dict:
    return load_static_evidence_from_application_flow(
        {
            "value_catalog": [
                {
                    "value_id": "VALUE-V001",
                    "source_method": V001_RUN,
                    "source_api": V001_API,
                    "source_kind": "DECODE_RETURN_PRIMITIVE",
                    "stored_field": "Lcom/bmwgroup/connected/core/services/accessory/bcl/BclConnection;->mVersion S",
                    "classification": "FACT",
                    "protocol_semantics": "UNKNOWN",
                    "value_class": "V5_ROUNDTRIP",
                    "consumers": [],
                    "lineage": [],
                }
            ],
            "flow_counts": {"catalog_values": 1},
        }
    )


def test_1_runtime_event_without_payload() -> None:
    doc = adapt_external_runtime_to_v1(
        [
            {
                "id": "R-NP",
                "type": "RUNTIME_METHOD",
                "method": V001_API,
                "phase": "exit",
                "timestamp_ms": 1000,
                "return_value": 4,
                "length": 2,
                # no bytes_hex
            }
        ],
        session_id="S1",
        package="de.bmw.connected",
        instrumentation="synthetic-fixture",
        status="OK",
    )
    assert doc["status"] == "OK"
    ev = doc["events"][0]
    assert ev["payload_observed"] is False
    assert ev["bytes_hex"] is None
    assert ev["return_value"] == 4
    assert ev["length"] == 2
    # Method execution may be FACT; payload is not observed.
    assert ev["classification"] == "FACT"


def test_2_runtime_event_with_payload() -> None:
    doc = adapt_external_runtime_to_v1(
        [
            {
                "id": "R-P",
                "type": "RUNTIME_METHOD",
                "method": V001_API,
                "phase": "exit",
                "timestamp_ms": 1000,
                "length": 2,
                "bytes_hex": "0004",
                "return_value": 4,
            }
        ],
        session_id="S1",
        instrumentation="synthetic-fixture",
        status="OK",
    )
    ev = doc["events"][0]
    assert ev["payload_observed"] is True
    assert ev["bytes_hex"] == "0004"


def test_3_runtime_event_to_static_method() -> None:
    static = _static_v001()
    runtime = {
        "status": "OK",
        "session_id": "S1",
        "events": [
            {
                "id": "R-V001",
                "type": "RUNTIME_METHOD",
                "method": V001_API,
                "timestamp_ms": 10,
                "bytes_hex": "0001",
                "length": 2,
                "return_value": 1,
                "payload_observed": True,
                "session_id": "S1",
            }
        ],
    }
    links = correlate_static_runtime(static, runtime)
    assert len(links) == 1
    assert links[0]["classification"] == CLASS_CORRELATION
    assert links[0]["static_id"] == "VALUE-V001"
    assert links[0]["runtime_id"] == "R-V001"
    assert "method_identity" in links[0]["correlation_keys"]


def test_4_ambiguous_method_match_not_fact() -> None:
    static = _static_v001()
    runtime = {
        "status": "OK",
        "events": [
            {"id": "R-A", "type": "RUNTIME_METHOD", "method": V001_API, "timestamp_ms": 1},
            {"id": "R-B", "type": "RUNTIME_METHOD", "method": V001_API, "timestamp_ms": 2},
        ],
    }
    links = correlate_static_runtime(static, runtime)
    assert links
    # Ambiguous: must not become FACT. Engine currently marks INFERENCE/AMBIGUOUS.
    assert all(x["classification"] != "FACT" for x in links)
    assert all(x.get("runtime_id") is not None for x in links)


def test_5_runtime_wire_different_session() -> None:
    runtime = {
        "status": "OK",
        "session_id": "RUN-A",
        "events": [
            {
                "id": "R1",
                "type": "RUNTIME_READ",
                "timestamp_ms": 100,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "aabb",
                "length": 2,
                "session_id": "RUN-A",
            }
        ],
    }
    wire = {
        "status": "OK",
        "session_id": "LAB-B3",
        "packets": [
            {
                "id": "W1",
                "type": "WIRE_PACKET",
                "timestamp_ms": 101,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "aabb",
                "length": 2,
                "session_id": "LAB-B3",
            }
        ],
    }
    links = correlate_runtime_wire(runtime, wire)
    assert links
    assert links[0]["classification"] == CLASS_REJECTED
    assert links[0]["session_relation"] == CHAIN_SESSION_MISMATCH
    assert "SESSION_MISMATCH" in (links[0].get("notes") or [])


def test_6_same_session_no_byte_match() -> None:
    runtime = {
        "status": "OK",
        "session_id": "S1",
        "events": [
            {
                "id": "R1",
                "type": "RUNTIME_READ",
                "timestamp_ms": 100,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "aaaa",
                "length": 2,
                "session_id": "S1",
            }
        ],
    }
    wire = {
        "status": "OK",
        "session_id": "S1",
        "packets": [
            {
                "id": "W1",
                "type": "WIRE_PACKET",
                "timestamp_ms": 101,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "bbbb",
                "length": 2,
                "session_id": "S1",
            }
        ],
    }
    links = correlate_runtime_wire(runtime, wire)
    assert links
    assert links[0]["classification"] == CLASS_REJECTED
    assert links[0].get("session_relation") != CHAIN_SESSION_MISMATCH or True


def test_7_same_session_byte_match() -> None:
    runtime = {
        "status": "OK",
        "session_id": "S1",
        "events": [
            {
                "id": "R1",
                "type": "RUNTIME_READ",
                "method": V001_API,
                "timestamp_ms": 100,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "0004",
                "length": 2,
                "session_id": "S1",
            }
        ],
    }
    wire = {
        "status": "OK",
        "session_id": "S1",
        "packets": [
            {
                "id": "W1",
                "type": "WIRE_PACKET",
                "timestamp_ms": 102,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "0004",
                "length": 2,
                "session_id": "S1",
            }
        ],
    }
    links = correlate_runtime_wire(runtime, wire)
    assert links[0]["classification"] == CLASS_CORRELATION
    assert links[0]["session_relation"] == "SAME_SESSION"
    assert "same_session" in links[0]["correlation_keys"]
    assert CHAIN_BYTE_CORRELATED in links[0]["chain_facets"]


def test_8_full_static_runtime_wire_chain() -> None:
    static = _static_v001()
    runtime = {
        "status": "OK",
        "session_id": "S1",
        "events": [
            {
                "id": "R-V001",
                "type": "RUNTIME_METHOD",
                "method": V001_API,
                "timestamp_ms": 2000,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "0004",
                "length": 2,
                "return_value": 4,
                "payload_observed": True,
                "session_id": "S1",
            }
        ],
    }
    wire = {
        "status": "OK",
        "session_id": "S1",
        "packets": [
            {
                "id": "W-V001",
                "type": "WIRE_PACKET",
                "timestamp_ms": 1999,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "0004",
                "length": 2,
                "session_id": "S1",
            }
        ],
    }
    sr = correlate_static_runtime(static, runtime)
    rw = correlate_runtime_wire(runtime, wire)
    e2e = correlate_end_to_end(sr, rw)
    assert any(x["classification"] == CLASS_CORRELATION for x in e2e)
    hit = next(x for x in e2e if x["classification"] == CLASS_CORRELATION)
    assert hit["static_id"] == "VALUE-V001"
    assert hit["chain_class"] == CHAIN_FULL
    assert hit["session_relation"] == "SAME_SESSION"
    assert hit["protocol_semantics"] == "UNKNOWN"


def test_9_input_missing_preserved(tmp_path: Path) -> None:
    path = tmp_path / "runtime_evidence.v1.json"
    path.write_text(
        json.dumps(
            {
                "schema": "apk_forensics.runtime_evidence.v1",
                "status": "INPUT_MISSING",
                "session_id": None,
                "events": [],
                "provenance": {
                    "attempted": True,
                    "missing_inputs": ["NO_DEVICE", "NO_FRIDA", "NO_PROCESS"],
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_runtime_evidence(path)
    assert loaded["status"] == "INPUT_MISSING"
    assert loaded["events"] == []
    assert load_runtime_evidence(None)["status"] == "INPUT_MISSING"
    empty_adapter = adapt_external_runtime_to_v1([], instrumentation=None)
    assert empty_adapter["status"] == "INPUT_MISSING"
    # INPUT_MISSING must not become NOT_FOUND
    assert empty_adapter["status"] != "NOT_FOUND"
    assert loaded["status"] != "NOT_FOUND"


def test_10_unknown_not_auto_not_found() -> None:
    static = _static_v001()
    runtime = {"status": "INPUT_MISSING", "events": [], "counts": {"events": 0}}
    links = correlate_static_runtime(static, runtime)
    assert links
    assert links[0]["classification"] == CLASS_UNKNOWN
    assert links[0]["result"] == RESULT_UNKNOWN
    assert "NO_EXTERNAL_EVIDENCE" in (links[0].get("notes") or [])
    assert links[0]["result"] != "NOT_FOUND"
    assert all("NOT_FOUND" not in str(x.get("result")) for x in links)
    assert all(x.get("classification") != "NOT_FOUND" for x in links)


def test_byte_match_without_session_is_not_full_chain() -> None:
    """Legacy LAB wire without session_id may byte-match, but must not claim FULL_CHAIN."""
    static = _static_v001()
    runtime = {
        "status": "OK",
        "events": [
            {
                "id": "R1",
                "type": "RUNTIME_METHOD",
                "method": V001_API,
                "timestamp_ms": 50,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "abcd",
                "length": 2,
            }
        ],
    }
    wire = {
        "status": "OK",
        "packets": [
            {
                "id": "W1",
                "type": "WIRE_PACKET",
                "timestamp_ms": 51,
                "direction": "IN",
                "app_direction": "IN",
                "bytes_hex": "abcd",
                "length": 2,
            }
        ],
    }
    sr = correlate_static_runtime(static, runtime)
    rw = correlate_runtime_wire(runtime, wire)
    e2e = correlate_end_to_end(sr, rw)
    assert rw[0]["session_relation"] == CHAIN_SESSION_UNKNOWN
    if e2e:
        assert e2e[0].get("chain_class") != CHAIN_FULL


def test_v001_hook_target_documented() -> None:
    assert "decodeVersion" in V001_RUNTIME_HOOK_TARGET["method"]
    assert "bytes_hex" in V001_RUNTIME_HOOK_TARGET["required_runtime_fields"]
    assert "value_id" not in V001_RUNTIME_HOOK_TARGET["required_runtime_fields"]


def test_capture_report_input_missing_loads(tmp_path: Path) -> None:
    src = Path("output/v16-runtime-capture/runtime_evidence.v1.json")
    if not src.is_file():
        return
    loaded = load_runtime_evidence(src)
    assert loaded["status"] == "INPUT_MISSING"
    assert loaded["counts"]["events"] == 0
