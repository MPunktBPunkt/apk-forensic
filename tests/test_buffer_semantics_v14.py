"""v1.4 buffer-to-semantics: fixtures M–W, T5 audit, READ_LENGTH correction."""

from __future__ import annotations

import json
import re
from pathlib import Path

from apk_forensics.buffer_semantic_closure import (
    CASE_F_PATHS,
    build_semantic_closure_report,
    build_t5_audit,
)
from apk_forensics.communication_dataflow import (
    T5_BYTE_PROCESSING_DEFINITION,
    analyze_method_communication,
)
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref


def _ins(index: int, opcode: str, text: str, **kwargs) -> InstructionInfo:
    regs = kwargs.pop("registers", None)
    if regs is None:
        regs = re.findall(r"\bv\d+\b", text)
    ref_m = kwargs.get("referenced_method")
    if ref_m is None and "->" in text and opcode.startswith("invoke"):
        m = re.search(r"(L[^;]+;->[^(]+\([^)]*\)[^ ]*)", text)
        if m:
            ref_m = parse_method_ref(m.group(1))
    return InstructionInfo(
        index=index,
        offset=None,
        opcode=opcode,
        text=text,
        registers=regs,
        referenced_method=ref_m,
        referenced_field=kwargs.get("referenced_field"),
    )


def _method(cls: str, name: str, desc: str, instructions: list[InstructionInfo]) -> MethodInfo:
    return MethodInfo(
        dex_entry="classes.dex",
        class_name=cls,
        class_name_normalized=cls[1:-1].replace("/", "."),
        method_name=name,
        method_descriptor=desc,
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=len(instructions),
        code_offset=None,
        instructions=instructions,
    )


def _types(r: dict) -> set[str]:
    return {n.get("node_type") for n in r.get("nodes") or []}


def test_t5_definition_documented() -> None:
    assert "aget-byte" in T5_BYTE_PROCESSING_DEFINITION["requires"]
    assert "READ_LENGTH" in T5_BYTE_PROCESSING_DEFINITION["excludes"]


def test_read_length_not_primitive_decode() -> None:
    """v1.4: move-result of read([B) is READ_LENGTH, not PRIMITIVE_DECODE."""
    m = _method(
        "Lcom/ex/M;",
        "readWrap",
        "([B)I",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v0", "v1"],
            ),
            _ins(1, "move-result", "move-result v2", registers=["v2"]),
            _ins(2, "return", "return v2", registers=["v2"]),
        ],
    )
    r = analyze_method_communication(m)
    assert "READ_LENGTH" in _types(r)
    assert "PRIMITIVE_DECODE" not in _types(r)
    assert r["read_lengths"]
    assert not any("INBOUND_PRIMITIVE" == p.get("kind") for p in r["paths"])


def test_fixture_m_aget_byte() -> None:
    m = _method(
        "Lcom/ex/M;",
        "load",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(2, "aget-byte", "aget-byte v3, v1, v4", registers=["v3", "v1", "v4"]),
        ],
    )
    r = analyze_method_communication(m)
    assert "BYTE_PROCESSING" in _types(r)
    assert r["byte_processing"]
    assert r["byte_processing"][0]["kind"] == "ARRAY_LOAD"


def test_fixture_n_shift_or() -> None:
    m = _method(
        "Lcom/ex/N;",
        "compose",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(2, "aget-byte", "aget-byte v3, v1, v4", registers=["v3", "v1", "v4"]),
            _ins(3, "shl-int/lit8", "shl-int/lit8 v3, v3, 8", registers=["v3", "v3"]),
            _ins(4, "or-int", "or-int v5, v3, v6", registers=["v5", "v3", "v6"]),
        ],
    )
    r = analyze_method_communication(m)
    kinds = {e.get("kind") for e in r["byte_processing"]}
    assert "ARRAY_LOAD" in kinds
    assert "BITWISE" in kinds


def test_fixture_o_bytebuffer_getint() -> None:
    m = _method(
        "Lcom/ex/O;",
        "hdr",
        "()I",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(
                2,
                "invoke-static",
                "invoke-static v1, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;",
                registers=["v1"],
            ),
            _ins(3, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(
                4,
                "invoke-virtual",
                "invoke-virtual v3, Ljava/nio/ByteBuffer;->getInt()I",
                registers=["v3"],
            ),
            _ins(5, "move-result", "move-result v4", registers=["v4"]),
        ],
    )
    r = analyze_method_communication(m)
    assert "PRIMITIVE_DECODE" in _types(r)
    assert "BYTE_PROCESSING" in _types(r)
    assert r["protocol_semantics"] == "UNKNOWN"


def test_fixture_p_string_byte_array() -> None:
    m = _method(
        "Lcom/ex/P;",
        "toStr",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(2, "new-instance", "new-instance v3, Ljava/lang/String;", registers=["v3"]),
            _ins(
                3,
                "invoke-direct",
                "invoke-direct v3, v1, Ljava/lang/String;-><init>([B)V",
                registers=["v3", "v1"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert "STRING_DECODE" in _types(r)
    assert r["string_decoding"]


def test_fixture_q_constructor_from_buffer() -> None:
    m = _method(
        "Lcom/ex/Q;",
        "build",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-static",
                "invoke-static v1, Lcom/ex/Message;->decode([B)Lcom/ex/Message;",
                registers=["v1"],
            ),
            _ins(2, "move-result-object", "move-result-object v2", registers=["v2"]),
        ],
    )
    r = analyze_method_communication(m)
    assert r["decoder_candidates"]
    assert r["decoder_candidates"][0]["protocol_semantics"] == "UNKNOWN"


def test_fixture_r_field_store() -> None:
    m = _method(
        "Lcom/ex/R;",
        "store",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(2, "aget-byte", "aget-byte v3, v1, v4", registers=["v3", "v1", "v4"]),
            _ins(
                3,
                "iput",
                "iput v3, v0, Lcom/ex/R;->mVal I",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/R;->mVal I",
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert "STATE_MUTATION" in _types(r)
    assert r["state_mutations"]
    assert r["state_mutations"][0]["protocol_semantics"] == "UNKNOWN"


def test_fixture_s_static_factory() -> None:
    m = _method(
        "Lcom/ex/S;",
        "make",
        "([B)Lcom/ex/Obj;",
        [
            _ins(
                0,
                "invoke-static",
                "invoke-static v1, Lcom/ex/Obj;->fromBytes([B)Lcom/ex/Obj;",
                registers=["v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v0", registers=["v0"]),
            _ins(2, "return-object", "return-object v0", registers=["v0"]),
        ],
    )
    # without tracking v1 as buffer first — factory name alone is not enough for DECODER with CORRELATION
    r = analyze_method_communication(m)
    # fromBytes matches parse-like? "fromBytes" is in PARSER_NAME_RE
    assert r["decoder_candidates"]
    assert r["decoder_candidates"][0]["dataflow_role"] in {"UNKNOWN", "INFERENCE"}


def test_fixture_t_wrapper_consumer() -> None:
    m = _method(
        "Lcom/ex/T;",
        "viaIface",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-interface",
                "invoke-interface v2, v1, Lcom/ex/AccessorySocket;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(2, "aget-byte", "aget-byte v3, v1, v4", registers=["v3", "v1", "v4"]),
        ],
    )
    r = analyze_method_communication(m)
    assert "INPUT_READ" in _types(r)
    assert "BYTE_PROCESSING" in _types(r)


def test_fixture_u_copy_only_not_decode() -> None:
    m = _method(
        "Lcom/ex/U;",
        "copyOnly",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(1, "new-array", "new-array v2, v0, [B", registers=["v2", "v0"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v3, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v3", "v1"],
            ),
            _ins(
                3,
                "invoke-static",
                "invoke-static v1, v4, v2, v4, v0, Ljava/lang/System;->arraycopy(Ljava/lang/Object; I Ljava/lang/Object; I I)V",
                registers=["v1", "v4", "v2", "v4", "v0"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert any(op.get("op") == "COPY" for op in r["buffer_operations"])
    assert not r["decoder_candidates"]
    # copy alone is not BYTE_PROCESSING (aget/getInt)
    assert not r["byte_processing"]


def test_fixture_v_name_without_byte_flow() -> None:
    m = _method(
        "Lcom/ex/V;",
        "decodeSomething",
        "()V",
        [
            _ins(0, "const/4", "const/4 v0, 1", registers=["v0"]),
            _ins(1, "return-void", "return-void", registers=[]),
        ],
    )
    r = analyze_method_communication(m)
    assert not r["decoder_candidates"]
    assert not r["byte_processing"]


def test_fixture_w_identity_ambiguity_no_type_merge() -> None:
    m = _method(
        "Lcom/ex/W;",
        "twoBufs",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(1, "new-array", "new-array v2, v0, [B", registers=["v2", "v0"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v3, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v3", "v1"],
            ),
            _ins(3, "aget-byte", "aget-byte v4, v2, v0", registers=["v4", "v2", "v0"]),
        ],
    )
    r = analyze_method_communication(m)
    # aget on v2 which was never filled by read — should NOT create BYTE_PROCESSING from v1's buffer
    # v2 is tracked as new-array BYTE_ARRAY though — aget from v2 is processing of empty buffer identity
    # That's FACT for v2 identity, not a false merge with v1
    assert "BYTE_PROCESSING" in _types(r)
    bp = r["byte_processing"][0]
    assert bp["array_register"] == "v2"


def test_negative_case_f_not_upgraded() -> None:
    report = {
        "bluetooth_path": {
            "evidence_graph": {
                "evidence_paths": [
                    {
                        "display_id": "PATH-000009",
                        "kind": "SOCKET_PATH",
                        "classification": "INFERENCE",
                        "objects": {"socket": "socket:S1"},
                        "steps": [
                            {"node_type": "SOCKET", "label": "createRfcomm", "classification": "FACT"},
                            {"node_type": "CONNECT", "label": "connect", "classification": "FACT"},
                        ],
                        "boundaries": [],
                    }
                ]
            },
            "dataflow_paths": [],
        },
        "communication_evidence": {"counts": {}, "paths": [], "per_method": []},
    }
    expanded = {
        "counts": {"byte_processing": 5, "decoder_candidates": 2, "state_mutations": 2},
        "paths": [],
        "per_method": [
            {
                "method": "Lcom/ex/Bcl;->readPacket()V",
                "byte_processing": [{"kind": "BYTEBUFFER_GET", "operation": "getInt"}],
                "state_mutations": [{"field": "mX"}],
                "decoder_candidates": [{"method": "decode"}],
                "nodes": [],
            }
        ],
    }
    closure = build_semantic_closure_report(
        transport_report=report,
        expanded_comm=expanded,
        baseline_meta={"path_comm": 6},
    )
    row = next(p for p in closure["paths"] if p["path_id"] == "PATH-000009")
    assert row["false_positive_guard"] == "PASS"
    assert row["T5_byte_processing"] is False


def test_bmw_offline_audit_without_apk() -> None:
    report_path = Path("output/bmw-connected-600-v10/report.json")
    if not report_path.exists():
        return
    report = json.loads(report_path.read_text(encoding="utf-8"))
    v13_path = Path("output/v13-closure/TRANSPORT_EVIDENCE_CLOSURE_REPORT.json")
    v13 = json.loads(v13_path.read_text(encoding="utf-8")) if v13_path.exists() else None
    audit = build_t5_audit(
        v13_closure=v13,
        v13_comm_counts=(report.get("communication_evidence") or {}).get("counts"),
        expanded_comm=None,
    )
    assert audit["root_cause_v13_t5_zero"]["primary"] == "B_ANALYZER_MODELING_GAP"
    assert "AccessorySocket" in audit["t5_candidate_currently_cannot_see_v13"]
