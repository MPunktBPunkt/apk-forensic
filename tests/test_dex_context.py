from __future__ import annotations

from apk_forensics.dex_context import build_context_record
from apk_forensics.dex_matcher import DexMatch, MatchQuery
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, method_window


def _sample_method() -> MethodInfo:
    instructions = [
        InstructionInfo(index=i, offset=None, opcode="nop", text=f"nop #{i}")
        for i in range(20)
    ]
    instructions[10] = InstructionInfo(
        index=10,
        offset=None,
        opcode="invoke-virtual",
        text="invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
        referenced_method={
            "class_name": "android.bluetooth.BluetoothDevice",
            "method_name": "createRfcommSocketToServiceRecord",
            "descriptor": "(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
            "raw": "Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
        },
    )
    return MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/BluetoothTransport;",
        class_name_normalized="com.example.BluetoothTransport",
        method_name="connect",
        method_descriptor="()V",
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=len(instructions),
        code_offset=None,
        instructions=instructions,
    )


def test_instruction_window_bounds() -> None:
    method = _sample_method()
    window = method_window(method, 10, window=8)
    assert len(window["before"]) == 8
    assert len(window["match"]) == 1
    assert len(window["after"]) == 8
    zero = method_window(method, 10, window=0)
    assert zero["before"] == []
    assert zero["after"] == []
    capped = method_window(method, 10, window=1000)
    assert len(capped["before"]) <= 10
    assert all(ins["offset"] is None for ins in window["match"])


def test_context_record_null_offset() -> None:
    method = _sample_method()
    match = DexMatch(
        method=method,
        instruction_index=10,
        match_type="method_reference",
        matched_value="createRfcommSocketToServiceRecord",
        query=MatchQuery(value="createRfcommSocketToServiceRecord", kind="api", finding_ids=["finding-1"]),
        priority="high",
        priority_score=95,
        priority_reasons=["exact method reference"],
    )
    ctx = build_context_record(match, instruction_window=8, artifact_sha256="abc")
    assert ctx["instruction"]["offset"] is None
    assert any("offset not available" in lim.lower() for lim in ctx["limitations"])
    assert ctx["classification"] == "FACT"
    assert ctx["evidence_level"] == "dex_reference"
    assert ctx["context_id"].startswith("dexctx-")
