from __future__ import annotations

from apk_forensics.dex_model_adapter import DexSession, InstructionInfo, MethodInfo
from apk_forensics.dex_xrefs import build_xref_candidates, collect_callees, collect_callers


def _ins(index: int, opcode: str, text: str, raw_method: str | None = None) -> InstructionInfo:
    ref = None
    if raw_method:
        from apk_forensics.dex_model_adapter import parse_method_ref

        ref = parse_method_ref(raw_method)
    return InstructionInfo(
        index=index,
        offset=None,
        opcode=opcode,
        text=text,
        referenced_method=ref,
    )


def test_callee_and_caller_bounds() -> None:
    target_raw = (
        "Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord"
        "(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;"
    )
    connect = MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/BluetoothTransport;",
        class_name_normalized="com.example.BluetoothTransport",
        method_name="connect",
        method_descriptor="()V",
        access_flags=[],
        is_external=False,
        code_present=True,
        instruction_count=2,
        code_offset=None,
        instructions=[
            _ins(
                0,
                "invoke-virtual",
                f"invoke-virtual v0, v1, {target_raw}",
                target_raw,
            ),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V",
                "Landroid/bluetooth/BluetoothSocket;->connect()V",
            ),
        ],
    )
    caller = MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/Manager;",
        class_name_normalized="com.example.Manager",
        method_name="start",
        method_descriptor="()V",
        access_flags=[],
        is_external=False,
        code_present=True,
        instruction_count=1,
        code_offset=None,
        instructions=[
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/BluetoothTransport;->connect()V",
                "Lcom/example/BluetoothTransport;->connect()V",
            )
        ],
    )
    external = MethodInfo(
        dex_entry="(external)",
        class_name="Landroid/bluetooth/BluetoothSocket;",
        class_name_normalized="android.bluetooth.BluetoothSocket",
        method_name="connect",
        method_descriptor="()V",
        access_flags=[],
        is_external=True,
        code_present=False,
        instruction_count=0,
        code_offset=None,
        instructions=[],
    )
    session = DexSession(units=[], methods=[connect, caller, external])

    callees = collect_callees(connect, session, max_callees=1)
    assert len(callees) == 1
    assert callees[0]["relationship"] == "callee"
    assert "runtime" in " ".join(callees[0]["limitations"]).lower()
    assert callees[0].get("is_external") is True

    callers = collect_callers(connect, session, max_callers=5)
    assert any(c["caller_method"] == "start" for c in callers)

    contexts = [
        {
            "class_name": connect.class_name,
            "method_name": connect.method_name,
            "method_descriptor": connect.method_descriptor,
        }
    ]
    depth0 = build_xref_candidates(session, contexts, xref_depth=0, max_callers=20, max_callees=20)
    assert all(x["relationship"] == "callee" for x in depth0)

    depth1 = build_xref_candidates(session, contexts, xref_depth=1, max_callers=20, max_callees=20)
    assert any(x["relationship"] == "caller" for x in depth1)
    assert all(x.get("evidence_level") == "xref_candidate" for x in depth1)
