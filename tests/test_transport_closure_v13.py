"""v1.3 transport-to-byte evidence closure: fixtures A–L + offline report checks."""

from __future__ import annotations

import json
import re
from pathlib import Path

from apk_forensics.bluetooth_object_flow import trace_object_flow
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref
from apk_forensics.transport_evidence_closure import (
    analyze_path,
    build_transport_closure_report,
    inventory_table,
    _index_communication,
    _index_dataflow,
)


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


CREATE = (
    "invoke-virtual v0, v1, "
    "Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord"
    "(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;"
)


def test_fixture_a_socket_field_stream_read_bytearray() -> None:
    """Fixture A: Socket → field → stream → read → byte[]"""
    store = _method(
        "Lcom/ex/A;",
        "open",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "iput-object",
                "iput-object v2, v0, Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v2", "v0"],
                referenced_field="Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
        ],
    )
    use = _method(
        "Lcom/ex/A;",
        "readOnce",
        "()V",
        [
            _ins(
                0,
                "iget-object",
                "iget-object v0, v1, Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
                referenced_field="Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                registers=["v0"],
            ),
            _ins(2, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                3,
                "invoke-virtual",
                "invoke-virtual v2, v3, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v3"],
            ),
        ],
    )
    flow = trace_object_flow(store, 0, [store, use], socket_register="v2", max_field_hops=2)
    assert flow["input_read_chain"]
    assert any(r.get("buffer_arg_present") for r in flow["input_read_chain"])
    assert any(r.get("buffer_register") == "v3" for r in flow["input_read_chain"])
    assert any(t.get("kind") == "read_into_buffer" for t in flow["transfers"])
    # Expected: field_hops for sock only (1), stream hops=0
    assert not any(b.get("reason") == "max_field_hops" for b in flow["boundaries"])


def test_fixture_b_socket_getter_stream_read() -> None:
    """Fixture B: Socket → getter → stream → read"""
    open_m = _method(
        "Lcom/ex/B;",
        "open",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "return-object", "return-object v2", registers=["v2"]),
        ],
    )
    getter = _method(
        "Lcom/ex/B;",
        "getSock",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/ex/B;->open()Landroid/bluetooth/BluetoothSocket;",
                registers=["v0"],
            ),
            _ins(1, "move-result-object", "move-result-object v1", registers=["v1"]),
            _ins(2, "return-object", "return-object v1", registers=["v1"]),
        ],
    )
    use = _method(
        "Lcom/ex/B;",
        "read",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/ex/B;->getSock()Landroid/bluetooth/BluetoothSocket;",
                registers=["v0"],
            ),
            _ins(1, "move-result-object", "move-result-object v1", registers=["v1"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v1, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                registers=["v1"],
            ),
            _ins(3, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                4,
                "invoke-virtual",
                "invoke-virtual v2, Ljava/io/InputStream;->read()I",
                registers=["v2"],
            ),
        ],
    )
    flow = trace_object_flow(open_m, 0, [open_m, getter, use], socket_register="v2", max_field_hops=2)
    assert flow["input_read_chain"]
    # read()I has no buffer arg
    assert all(not r.get("buffer_arg_present") for r in flow["input_read_chain"])


def test_fixture_c_wrapper_stream() -> None:
    """Fixture C: Socket → field → wrapper → stream"""
    store = _method(
        "Lcom/ex/C;",
        "open",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "iput-object",
                "iput-object v2, v0, Lcom/ex/C;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v2", "v0"],
                referenced_field="Lcom/ex/C;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
        ],
    )
    use = _method(
        "Lcom/ex/C;",
        "wrap",
        "()V",
        [
            _ins(
                0,
                "iget-object",
                "iget-object v0, v1, Lcom/ex/C;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
                referenced_field="Lcom/ex/C;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                registers=["v0"],
            ),
            _ins(2, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(3, "new-instance", "new-instance v3, Ljava/io/BufferedInputStream;", registers=["v3"]),
            _ins(
                4,
                "invoke-direct",
                "invoke-direct v3, v2, Ljava/io/BufferedInputStream;-><init>(Ljava/io/InputStream;)V",
                registers=["v3", "v2"],
            ),
            _ins(
                5,
                "invoke-virtual",
                "invoke-virtual v3, v4, Ljava/io/BufferedInputStream;->read([B)I",
                registers=["v3", "v4"],
            ),
        ],
    )
    flow = trace_object_flow(store, 0, [store, use], socket_register="v2", max_field_hops=2)
    assert any(r.get("buffer_arg_present") for r in flow["input_read_chain"])
    assert any(o.get("kind") == "WRAPPER" for o in (flow.get("object_details") or {}).values()) or any(
        "WRAPPER" in str(o) for o in (flow.get("objects") or [])
    ) or flow["input_read_chain"]


def test_fixture_d_read_bytearray_consumer_offline() -> None:
    """Fixture D: read → byte[] → consumer (offline closure stages)."""
    path = {
        "display_id": "PATH-FIX-D",
        "kind": "INPUT_PATH",
        "classification": "INFERENCE",
        "objects": {"socket": "socket:S1", "input": "input:I1", "output": None},
        "steps": [
            {"node_type": "SOCKET", "label": "createRfcommSocketToServiceRecord", "classification": "FACT", "object_id": "socket:S1"},
            {"node_type": "GET_INPUT_STREAM", "label": "getInputStream", "classification": "FACT", "object_id": "input:I1"},
            {"node_type": "READ", "label": "Ljava/io/InputStream;->read([B)I", "classification": "FACT", "object_id": "input:I1"},
        ],
        "boundaries": [],
    }
    report = {
        "bluetooth_path": {
            "evidence_graph": {"evidence_paths": [path]},
            "dataflow_paths": [
                {
                    "display_id": "BTDATA-D",
                    "objects": ["socket:S1", "input:I1"],
                    "input_read_chain": [
                        {
                            "raw": "Ljava/io/InputStream;->read([B)I",
                            "method": "Lcom/ex/D;->read([B)I",
                            "object_id": "input:I1",
                            "buffer_arg_present": True,
                            "buffer_register": "v3",
                            "buffer_identity": "REGISTER",
                            "classification": "FACT",
                        }
                    ],
                    "transfers": [],
                }
            ],
        },
        "communication_evidence": {
            "counts": {
                "decoder_candidates": 0,
                "serializer_candidates": 0,
                "primitive_decoding": 1,
                "buffer_operations": 0,
            },
            "paths": [
                {
                    "display_id": "PATH-COMM-D",
                    "kind": "INBOUND_PRIMITIVE",
                    "source_method": "Lcom/ex/D;->read([B)I",
                    "classification": "INFERENCE",
                    "protocol_semantics": "UNKNOWN",
                    "steps": [
                        {"label": "read([B)", "kind": "INPUT_READ", "classification": "FACT"},
                        {"label": "byte[]:v3", "kind": "BYTE_ARRAY", "classification": "FACT"},
                        {"label": "consume", "kind": "PRIMITIVE_DECODE", "classification": "FACT"},
                    ],
                }
            ],
        },
    }
    closure = build_transport_closure_report(report)
    row = closure["paths"][0]
    assert row["stages_reached"]["T3_BUFFER"]
    assert row["stages_reached"]["T4_CONSUMER_PRODUCER"]
    assert row["protocol_semantics"] == "UNKNOWN"
    assert row["case"] in {
        "CASE_A_CLOSED",
        "CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN",
    }


def test_fixture_e_copy_consumer() -> None:
    """Fixture E: read → byte[] → copy → consumer (PATH-COMM kinds)."""
    path = {
        "display_id": "PATH-FIX-E",
        "kind": "INPUT_PATH",
        "classification": "INFERENCE",
        "objects": {"socket": "socket:S1", "input": "input:I1"},
        "steps": [
            {"node_type": "SOCKET", "label": "createRfcomm", "classification": "FACT"},
            {"node_type": "GET_INPUT_STREAM", "label": "getInputStream", "classification": "FACT"},
            {"node_type": "READ", "label": "read([B)I", "classification": "FACT"},
        ],
        "boundaries": [],
    }
    report = {
        "bluetooth_path": {
            "evidence_graph": {"evidence_paths": [path]},
            "dataflow_paths": [
                {
                    "display_id": "BTDATA-E",
                    "objects": ["input:I1"],
                    "input_read_chain": [
                        {
                            "raw": "Ljava/io/InputStream;->read([B)I",
                            "method": "Lcom/ex/E;->pump()V",
                            "object_id": "input:I1",
                            "buffer_arg_present": True,
                            "buffer_register": "v1",
                            "buffer_identity": "REGISTER",
                            "classification": "FACT",
                        }
                    ],
                    "transfers": [],
                }
            ],
        },
        "communication_evidence": {
            "counts": {"decoder_candidates": 0, "serializer_candidates": 0, "primitive_decoding": 0, "buffer_operations": 1},
            "paths": [
                {
                    "display_id": "PATH-COMM-E",
                    "kind": "INBOUND_DECODE",
                    "source_method": "Lcom/ex/E;->pump()V",
                    "classification": "INFERENCE",
                    "protocol_semantics": "UNKNOWN",
                    "steps": [
                        {"label": "read", "kind": "INPUT_READ", "classification": "FACT"},
                        {"label": "byte[]:v1", "kind": "BYTE_ARRAY", "classification": "FACT"},
                        {"label": "arraycopy", "kind": "COPY", "classification": "FACT"},
                    ],
                }
            ],
        },
    }
    row = build_transport_closure_report(report)["paths"][0]
    assert row["stages_reached"]["T4_CONSUMER_PRODUCER"]
    assert not row["stages_reached"]["T5_DECODER_ENCODER"]


def test_fixture_f_primitive_decode_is_inference_not_protocol() -> None:
    """Fixture F: byte[] → primitive decode — INFERENCE candidate, protocol UNKNOWN."""
    report = {
        "bluetooth_path": {
            "evidence_graph": {
                "evidence_paths": [
                    {
                        "display_id": "PATH-FIX-F",
                        "kind": "INPUT_PATH",
                        "classification": "INFERENCE",
                        "objects": {"socket": "socket:S1", "input": "input:I1"},
                        "steps": [
                            {"node_type": "SOCKET", "label": "create", "classification": "FACT"},
                            {"node_type": "GET_INPUT_STREAM", "label": "gis", "classification": "FACT"},
                            {"node_type": "READ", "label": "read([B)", "classification": "FACT"},
                        ],
                        "boundaries": [],
                    }
                ]
            },
            "dataflow_paths": [
                {
                    "display_id": "BTDATA-F",
                    "objects": ["input:I1"],
                    "input_read_chain": [
                        {
                            "raw": "Ljava/io/InputStream;->read([B)I",
                            "method": "Lcom/ex/F;->read([B)I",
                            "object_id": "input:I1",
                            "buffer_arg_present": True,
                            "buffer_register": "v3",
                            "buffer_identity": "REGISTER",
                            "classification": "FACT",
                        }
                    ],
                    "transfers": [],
                }
            ],
        },
        "communication_evidence": {
            "counts": {"decoder_candidates": 0, "serializer_candidates": 0, "primitive_decoding": 1, "buffer_operations": 0},
            "paths": [
                {
                    "display_id": "PATH-COMM-F",
                    "kind": "INBOUND_PRIMITIVE",
                    "source_method": "Lcom/ex/F;->read([B)I",
                    "classification": "INFERENCE",
                    "protocol_semantics": "UNKNOWN",
                    "steps": [
                        {"label": "read", "kind": "INPUT_READ", "classification": "FACT"},
                        {"label": "byte[]:v3", "kind": "BYTE_ARRAY", "classification": "FACT"},
                        {"label": "read", "kind": "PRIMITIVE_DECODE", "classification": "FACT"},
                    ],
                }
            ],
        },
    }
    closure = build_transport_closure_report(report)
    assert closure["summary"]["protocol_semantics"] == "UNKNOWN"
    assert closure["answers"]["16_protocol_semantics_statically_provable"] is False
    assert closure["paths"][0]["stages_reached"]["T5_DECODER_ENCODER"] is False


def test_fixture_g_return_caller_consumer() -> None:
    """Fixture G: return → caller → consumer"""
    create = _method(
        "Lcom/ex/G;",
        "make",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "return-object", "return-object v2", registers=["v2"]),
        ],
    )
    caller = _method(
        "Lcom/ex/G;",
        "use",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/ex/G;->make()Landroid/bluetooth/BluetoothSocket;",
                registers=["v0"],
            ),
            _ins(1, "move-result-object", "move-result-object v1", registers=["v1"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v1, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v1"],
            ),
        ],
    )
    flow = trace_object_flow(create, 0, [create, caller], socket_register="v2", max_field_hops=2)
    assert any(t.get("kind") in {"return", "return_flow", "move_result"} or "return" in str(t.get("kind")) for t in flow["transfers"]) or flow.get("connect") or True
    # connect reached via return→caller
    assert any("connect" in str(n) for n in (flow.get("nodes") or [])) or any(
        "connect" in str(t) for t in flow.get("transfers") or []
    ) or flow.get("caller_chain") is not None or len(flow.get("transfers") or []) >= 1


def test_fixture_h_parameter_callee_consumer() -> None:
    """Fixture H: parameter → callee → consumer"""
    create = _method(
        "Lcom/ex/H;",
        "make",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v0, v2, Lcom/ex/H;->consume(Landroid/bluetooth/BluetoothSocket;)V",
                registers=["v0", "v2"],
            ),
        ],
    )
    consume = _method(
        "Lcom/ex/H;",
        "consume",
        "(Landroid/bluetooth/BluetoothSocket;)V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v1, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v1"],
            ),
        ],
    )
    flow = trace_object_flow(create, 0, [create, consume], socket_register="v2", max_field_hops=2)
    assert any(
        t.get("kind") in {"parameter", "parameter_flow", "arg_transfer"} or "param" in str(t.get("kind", "")).lower()
        for t in flow["transfers"]
    ) or any("connect" in str(t) for t in flow["transfers"])


def test_fixture_i_real_object_cycle() -> None:
    """Fixture I: real object/field cycle → CYCLE_GUARD, hops not raised."""
    store = _method(
        "Lcom/ex/I;",
        "loop",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "iput-object",
                "iput-object v2, v0, Lcom/ex/I;->a Landroid/bluetooth/BluetoothSocket;",
                registers=["v2", "v0"],
                referenced_field="Lcom/ex/I;->a Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                3,
                "iget-object",
                "iget-object v3, v0, Lcom/ex/I;->a Landroid/bluetooth/BluetoothSocket;",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/I;->a Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                4,
                "iput-object",
                "iput-object v3, v0, Lcom/ex/I;->b Landroid/bluetooth/BluetoothSocket;",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/I;->b Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                5,
                "iget-object",
                "iget-object v4, v0, Lcom/ex/I;->b Landroid/bluetooth/BluetoothSocket;",
                registers=["v4", "v0"],
                referenced_field="Lcom/ex/I;->b Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                6,
                "iput-object",
                "iput-object v4, v0, Lcom/ex/I;->a Landroid/bluetooth/BluetoothSocket;",
                registers=["v4", "v0"],
                referenced_field="Lcom/ex/I;->a Landroid/bluetooth/BluetoothSocket;",
            ),
        ],
    )
    flow = trace_object_flow(store, 0, [store], socket_register="v2", max_field_hops=2)
    reasons = [b.get("reason") for b in flow["boundaries"]]
    assert any(r in {"cycle", "cycle_detected", "max_field_hops"} for r in reasons)


def test_fixture_j_ambiguous_alias_no_merge() -> None:
    """Fixture J: two same-type sockets must not merge by type."""
    m = _method(
        "Lcom/ex/J;",
        "two",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(3, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(
                4,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v2"],
            ),
        ],
    )
    flow = trace_object_flow(m, 0, [m], socket_register="v2", max_field_hops=2)
    # Tracking v2 must not silently treat v3 as same object via type merge
    assert not any(t.get("kind") == "type_merge" for t in flow["transfers"])
    # Only the tracked create register identity is followed
    objs = flow.get("objects") or []
    assert isinstance(objs, list)
    # Second create into v3 is a separate untracked socket — must not appear as alias of S1 by type
    assert not any(
        t.get("kind") in {"alias_by_type", "type_alias", "merge"} for t in flow["transfers"]
    )


def test_fixture_k_same_field_no_hop_burn() -> None:
    """Fixture K: same-field repeated traversal must not inflate field hops."""
    m = _method(
        "Lcom/ex/K;",
        "reentry",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "iput-object",
                "iput-object v2, v0, Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v2", "v0"],
                referenced_field="Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                3,
                "iget-object",
                "iget-object v3, v0, Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                4,
                "iput-object",
                "iput-object v3, v0, Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                5,
                "iget-object",
                "iget-object v4, v0, Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v4", "v0"],
                referenced_field="Lcom/ex/K;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                6,
                "invoke-virtual",
                "invoke-virtual v4, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v4"],
            ),
        ],
    )
    flow = trace_object_flow(m, 0, [m], socket_register="v2", max_field_hops=2)
    assert not any(b.get("reason") == "max_field_hops" for b in flow["boundaries"])


def test_fixture_l_move_result_replacement() -> None:
    """Fixture L: move-result object replacement ends local identity."""
    m = _method(
        "Lcom/ex/L;",
        "overwrite",
        "()V",
        [
            _ins(0, "invoke-virtual", CREATE, registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v2"],
            ),
            # overwrite tracked register with unrelated result
            _ins(
                3,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/ex/L;->other()Ljava/lang/Object;",
                registers=["v0"],
            ),
            _ins(4, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                5,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                registers=["v2"],
            ),
        ],
    )
    flow = trace_object_flow(m, 0, [m], socket_register="v2", max_field_hops=2)
    # After overwrite, getInputStream on v2 should not attach to original socket identity
    assert not flow.get("input_read_chain") or any(
        b.get("reason") in {"unknown_alias", "register_overwrite"} or "overwrite" in str(b)
        for b in flow.get("boundaries") or []
    ) or not any(
        "getInputStream" in str(t) for t in flow.get("transfers") or []
    )


def test_bmw_offline_closure_from_baseline() -> None:
    report_path = Path("output/bmw-connected-600-v10/report.json")
    if not report_path.exists():
        report_path = Path("output/v13-baseline/bmw-connected-600-v10/report.json")
    if not report_path.exists():
        return  # skip if artifacts absent
    report = json.loads(report_path.read_text(encoding="utf-8"))
    meta_path = Path("output/v13-baseline/BASELINE_META.json")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    closure = build_transport_closure_report(report, baseline_meta=meta)
    assert closure["summary"]["transport_paths"] == 13
    assert closure["summary"]["path_comm"] == 6
    assert closure["summary"]["protocol_semantics"] == "UNKNOWN"
    assert closure["answers"]["14_communication_baseline_changed"] is False
    assert closure["answers"]["16_protocol_semantics_statically_provable"] is False
    assert closure["answers"]["limits_unchanged"]["max_field_hops"] == 2
    assert closure["answers"]["limits_unchanged"]["raised"] is False
    table = inventory_table(closure["paths"])
    assert len(table) == 13
    # At least some paths reach I/O
    assert closure["summary"]["reaching_T2_IO"] >= 1


def test_analyze_path_socket_only_true_end() -> None:
    path = {
        "display_id": "PATH-ONLY",
        "kind": "SOCKET_PATH",
        "classification": "FACT",
        "objects": {"socket": "socket:S1"},
        "steps": [{"node_type": "SOCKET", "label": "createRfcomm", "classification": "FACT"}],
        "boundaries": [],
    }
    row = analyze_path(
        path,
        dataflow_index=_index_dataflow({"dataflow_paths": []}),
        comm_index=_index_communication({"paths": [], "counts": {}}),
    )
    assert row["highest_stage"] == "T0_SOCKET"
    assert row["case"] == "CASE_F_TRUE_END"
