"""CASE-B B3 capture normalizer → wire_evidence.v1 (no correlation invention)."""

from __future__ import annotations

import json
from pathlib import Path

from apk_forensics.runtime_wire_evidence import normalize_b3_capture_to_wire_evidence
from apk_forensics.static_runtime_correlation import run_correlation


def test_normalize_b3_slices_match_bins(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    phone = bytes.fromhex("aabb") + bytes.fromhex("ccdd")
    hu = bytes.fromhex("11223344")
    (raw / "phone_to_hu.bin").write_bytes(phone)
    (raw / "hu_to_phone.bin").write_bytes(hu)
    (tmp_path / "b3.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"event": "relay_start", "ts": 1000.5}),
                json.dumps({"event": "bytes", "direction": "phone->hu", "n": 2, "hex_head": "aabb"}),
                json.dumps({"event": "bytes", "direction": "hu->phone", "n": 4, "hex_head": "11223344"}),
                json.dumps({"event": "bytes", "direction": "phone->hu", "n": 2, "hex_head": "ccdd"}),
            ]
        )
        + "\n"
    )
    out = normalize_b3_capture_to_wire_evidence(tmp_path)
    assert out["status"] == "OK"
    assert out["counts"]["stream_slice_complete"] is True
    pkts = [p for p in out["packets"] if p["type"] == "WIRE_PACKET"]
    assert len(pkts) == 3
    assert pkts[0]["bytes_hex"] == "aabb"
    assert pkts[0]["direction"] == "PHONE_TO_HU"
    assert pkts[0]["timestamp_ms"] == 1000500
    # reassemble
    phone_re = b"".join(bytes.fromhex(p["bytes_hex"]) for p in pkts if p["direction"] == "PHONE_TO_HU")
    hu_re = b"".join(bytes.fromhex(p["bytes_hex"]) for p in pkts if p["direction"] == "HU_TO_PHONE")
    assert phone_re == phone
    assert hu_re == hu


def test_wire_without_runtime_no_e2e(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "phone_to_hu.bin").write_bytes(b"\x01\x02")
    (raw / "hu_to_phone.bin").write_bytes(b"\x03\x04")
    (tmp_path / "b3.jsonl").write_text(
        json.dumps({"event": "bytes", "direction": "phone->hu", "n": 2}) + "\n"
        + json.dumps({"event": "bytes", "direction": "hu->phone", "n": 2}) + "\n"
    )
    wire = normalize_b3_capture_to_wire_evidence(tmp_path)
    wire_path = tmp_path / "wire.json"
    wire_path.write_text(json.dumps(wire))
    flow = {
        "value_catalog": [
            {
                "value_id": "VALUE-V001",
                "source_method": "Lcom/ex/P;->decode([B)V",
                "source_api": "Lcom/ex/P;->decode([B)V",
                "classification": "FACT",
                "protocol_semantics": "UNKNOWN",
                "consumers": [],
            }
        ],
        "flow_counts": {"catalog_values": 1},
    }
    run = run_correlation(static_flow=flow, runtime_path=None, wire_path=wire_path)
    assert run["executed"] is True
    assert run["wire"]["status"] == "OK"
    assert run["runtime"]["status"] == "INPUT_MISSING"
    assert run["counts"]["wire_packets"] == 2
    assert run["counts"]["runtime_wire"] == 0
    assert run["counts"]["end_to_end"] == 0
    assert run["answers"]["protocol_semantics"] == "UNKNOWN"
