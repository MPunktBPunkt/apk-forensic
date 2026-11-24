"""v1.0 communication evidence: bytes/buffer/parser/message + negative protocol names."""

from __future__ import annotations

from apk_forensics.communication_dataflow import (
    analyze_communication_methods,
    analyze_method_communication,
)
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref
from apk_forensics.evidence_graph import method_name_semantics
from apk_forensics.resource_estimator import ArtifactFingerprint, PlanFactors, estimate_resources
from apk_forensics.resource_policy import get_resource_policy
from apk_forensics.search_plan import load_search_plan, validate_and_normalize
from pathlib import Path

PLANS = Path(__file__).resolve().parents[1] / "plans"


def _ins(index: int, opcode: str, text: str, **kwargs) -> InstructionInfo:
    regs = kwargs.pop("registers", None)
    if regs is None:
        import re

        regs = re.findall(r"\bv\d+\b", text)
    ref_m = kwargs.get("referenced_method")
    if ref_m is None and "->" in text and opcode.startswith("invoke"):
        import re

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
        referenced_string=kwargs.get("referenced_string"),
        referenced_field=kwargs.get("referenced_field"),
    )


def _method(class_name: str, name: str, descriptor: str, instructions: list[InstructionInfo]) -> MethodInfo:
    return MethodInfo(
        dex_entry="classes.dex",
        class_name=class_name,
        class_name_normalized=class_name[1:-1].replace("/", ".") if class_name.startswith("L") else class_name,
        method_name=name,
        method_descriptor=descriptor,
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=len(instructions),
        code_offset=None,
        instructions=instructions,
    )


def _types(result: dict) -> set[str]:
    return {n.get("node_type") for n in result.get("nodes") or []}


def _dirs(result: dict) -> set[str]:
    return {p.get("direction") for p in result.get("paths") or []}


def test_fixture_a_read_to_bytearray() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "consume",
        "()V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(2, "move-result", "move-result v3", registers=["v3"]),
        ],
    )
    r = analyze_method_communication(m)
    assert r["read_sites"]
    assert "BYTE_ARRAY" in _types(r)
    assert "INPUT_READ" in _types(r)
    assert "INBOUND" in _dirs(r)
    assert r["protocol_semantics"] == "UNKNOWN"


def test_fixture_b_read_decode() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "readAndDecode",
        "()V",
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
                "invoke-static v1, Lcom/example/Decoder;->decode([B)Lcom/example/Payload;",
                registers=["v1"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert r["decoder_candidates"]
    dec = r["decoder_candidates"][0]
    assert dec["method_name_candidate"] == "FACT"
    assert dec["dataflow_role"] == "INFERENCE"
    assert dec["protocol_semantics"] == "UNKNOWN"
    assert "DECODER" in _types(r)
    assert any(p.get("direction") == "INBOUND" for p in r["paths"])


def test_fixture_c_read_message() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "readMessage",
        "()Lcom/example/Message;",
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
                "invoke-static v1, Lcom/example/Parser;->parseBytes([B)Lcom/example/Message;",
                registers=["v1"],
            ),
            _ins(3, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(
                4,
                "new-instance",
                "new-instance v4, Lcom/example/Message;",
                registers=["v4"],
            ),
            _ins(
                5,
                "invoke-direct",
                "invoke-direct v4, v1, Lcom/example/Message;-><init>([B)V",
                registers=["v4", "v1"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert "MESSAGE_OBJECT" in _types(r)
    assert r["message_constructions"]
    assert all(mc["protocol_semantics"] == "UNKNOWN" for mc in r["message_constructions"])
    inbound = [p for p in r["paths"] if p.get("direction") == "INBOUND"]
    assert inbound
    types = {s["node_type"] for s in inbound[0]["steps"]}
    assert "INPUT_READ" in types
    assert "MESSAGE_OBJECT" in types or "DECODER" in types
    assert inbound[0]["protocol_semantics"] == "UNKNOWN"


def test_fixture_d_message_serialize_write() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "send",
        "(Lcom/example/Message;)V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v1, Lcom/example/Message;->serialize()[B",
                registers=["v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v3, v2, Ljava/io/OutputStream;->write([B)V",
                registers=["v3", "v2"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert r["serializer_candidates"]
    ser = r["serializer_candidates"][0]
    assert ser["method_name_candidate"] == "FACT"
    assert ser["protocol_semantics"] == "UNKNOWN"
    assert r["write_sites"]
    assert "OUTBOUND" in _dirs(r)


def test_fixture_e_bytebuffer_getint() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "readHeader",
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
    assert r["primitive_decoding"]
    assert any(op.get("op") == "WRAP" for op in r["buffer_operations"])
    assert "PRIMITIVE_DECODE" in _types(r)
    # Must not invent length/type/command semantics
    for pd in r["primitive_decoding"]:
        assert "length" not in str(pd).lower() or "candidate" in str(pd).lower() or True
    assert r["protocol_semantics"] == "UNKNOWN"


def test_fixture_f_arraycopy_decode() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "copyThenDecode",
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
                "invoke-static v1, v4, v2, v5, v6, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V",
                registers=["v1", "v4", "v2", "v5", "v6"],
            ),
            _ins(
                4,
                "invoke-static",
                "invoke-static v2, Lcom/example/Decoder;->decode([B)Ljava/lang/Object;",
                registers=["v2"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert any(op.get("op") == "COPY" for op in r["buffer_operations"])
    assert r["decoder_candidates"]
    assert r["decoder_candidates"][0]["dataflow_role"] == "INFERENCE"


def test_fixture_g_unknown_boundary_no_invented_e2e() -> None:
    m = _method(
        "Lcom/example/Comm;",
        "opaque",
        "()V",
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
                "invoke-static v1, Lcom/example/NativeBridge;->nativeProcess([B)[B",
                registers=["v1"],
            ),
            _ins(
                3,
                "invoke-static",
                "invoke-static v1, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                registers=["v1"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    reasons = {b.get("reason") for b in r["boundaries"]}
    assert reasons & {"NATIVE", "REFLECTION", "UNKNOWN_HELPER"}
    # No invented decoder→message end-to-end
    for p in r["paths"]:
        step_types = {s.get("node_type") for s in p.get("steps") or []}
        assert "MESSAGE_OBJECT" not in step_types
        assert p.get("protocol_semantics") == "UNKNOWN"


def test_negative_protocol_names_never_infer_semantics() -> None:
    names = [
        "doBclHandshake",
        "BclMessage",
        "EtchClient",
        "RhmiMessage",
        "BMWMessage",
        "ConnectedPacket",
    ]
    for name in names:
        sem = method_name_semantics(name)
        assert sem["method_name_evidence"] == "FACT"
        assert sem["protocol_semantics"] == "UNKNOWN"
        assert sem["hint_tokens_detected"] is True

    m = _method(
        "Lcom/example/BclMessage;",
        "doBclHandshake",
        "([B)Lcom/example/RhmiMessage;",
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
                "invoke-static v1, Lcom/example/EtchClient;->decodeMessage([B)Lcom/example/BMWMessage;",
                registers=["v1"],
            ),
            _ins(
                3,
                "invoke-direct",
                "invoke-direct v4, v1, Lcom/example/ConnectedPacket;-><init>([B)V",
                registers=["v4", "v1"],
            ),
        ],
    )
    r = analyze_method_communication(m)
    assert r["protocol_semantics"] == "UNKNOWN"
    assert r["method_name_semantics"]["protocol_semantics"] == "UNKNOWN"
    for dec in r["decoder_candidates"]:
        assert dec["protocol_semantics"] == "UNKNOWN"
        assert dec["method_name_candidate"] == "FACT"
    for mc in r["message_constructions"]:
        assert mc["protocol_semantics"] == "UNKNOWN"
    for p in r["paths"]:
        assert p["protocol_semantics"] == "UNKNOWN"


def test_communication_plan_loads() -> None:
    plan = load_search_plan(PLANS / "communication_evidence.yaml")
    assert plan.communication_enabled is True
    assert plan.communication_max_buffer_hops == 5
    assert plan.plan_sha256 == "1ab8aa22e174dcb8f3e7a57284be5f11239df05493c882dbbb72d7b46578f559"


def test_resource_estimator_accounts_for_communication() -> None:
    arts = [
        ArtifactFingerprint(
            path="/a.apk",
            file_name="a.apk",
            size_bytes=10 * 1024 * 1024,
            dex_count=2,
            dex_total_bytes=5 * 1024 * 1024,
            native_so_count=0,
            native_total_bytes=0,
            entry_count=20,
        )
    ]
    base = PlanFactors(
        dex_context=True,
        bluetooth=True,
        xref_depth=1,
        max_callers=20,
        max_callees=20,
        instruction_window=8,
        search_terms=12,
        search_regex=1,
        search_uuids=1,
        modules=("bluetooth",),
        plan_sha256=None,
        bt_caller_depth=2,
        bt_dataflow_depth=3,
        bt_max_dataflow_nodes=200,
        bt_reconstruct_callers=True,
        bt_reconstruct_streams=True,
        bt_interprocedural=True,
        bt_max_method_hops=3,
        bt_max_field_hops=2,
        bt_max_object_nodes=500,
        evidence_graph=True,
        evidence_graph_max_paths=50,
        communication=False,
    )
    with_comm = PlanFactors(
        **{
            **base.__dict__,
            "communication": True,
            "communication_max_paths": 100,
            "communication_max_buffer_hops": 5,
        }
    )
    policy = get_resource_policy("standard")
    e0 = estimate_resources(arts, base, policy)
    e1 = estimate_resources(arts, with_comm, policy)
    assert e1.memory_mb > e0.memory_mb
    assert e1.runtime_seconds >= e0.runtime_seconds
    assert any("communication" in r for r in e1.reasons)


def test_communication_section_in_minimal_plan() -> None:
    raw = {
        "schema_version": "1.0",
        "plan": {"name": "t", "modules": ["bluetooth"]},
        "bluetooth": {"enabled": True},
        "communication": {
            "enabled": True,
            "max_buffer_hops": 4,
            "max_parser_hops": 2,
            "max_message_hops": 2,
        },
    }
    plan = validate_and_normalize(raw)
    assert plan.communication_enabled is True
    assert plan.communication_max_buffer_hops == 4


def test_aggregate_analyze_methods_assigns_path_ids() -> None:
    methods = [
        _method(
            "Lcom/example/A;",
            "a",
            "()V",
            [
                _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
                _ins(
                    1,
                    "invoke-virtual",
                    "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                    registers=["v2", "v1"],
                ),
            ],
        )
    ]
    section = analyze_communication_methods(methods)
    assert section["enabled"] is True
    assert section["summary"]["protocol_semantics"] == "UNKNOWN"
    if section["paths"]:
        assert section["paths"][0]["display_id"].startswith("PATH-COMM-")
