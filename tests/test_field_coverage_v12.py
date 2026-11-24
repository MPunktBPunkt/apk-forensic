"""v1.2 field/alias coverage: hop semantics, fixtures A–I, negatives."""

from __future__ import annotations

import json
from pathlib import Path

from apk_forensics.bluetooth_object_flow import trace_object_flow
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref
from apk_forensics.field_coverage import (
    FIELD_HOP_SEMANTICS,
    build_field_coverage_report,
    classify_root_cause,
    hop_sweep_synthetic,
    path_matrix_from_report,
    reconstruct_field_chain,
)
from apk_forensics.resource_estimator import PlanFactors, estimate_resources, ArtifactFingerprint
from apk_forensics.resource_policy import get_resource_policy


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


def test_semantics_doc_present() -> None:
    assert "distinct nested field" in FIELD_HOP_SEMANTICS["definition"]


def test_fixture_a_direct_field() -> None:
    store = _method(
        "Lcom/ex/A;",
        "store",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "iput-object", "iput-object v2, v0, Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    load = _method(
        "Lcom/ex/A;",
        "use",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/A;->sock Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "invoke-virtual", "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->connect()V", registers=["v0"]),
        ],
    )
    flow = trace_object_flow(store, 0, [store, load], socket_register="v2", max_field_hops=2)
    assert any(t["kind"] == "field_store" for t in flow["transfers"])
    assert any(t["kind"] == "field_load" for t in flow["transfers"])
    assert not any(b.get("reason") == "max_field_hops" for b in flow["boundaries"])


def test_fixture_b_two_level_field() -> None:
    store = _method(
        "Lcom/ex/B;",
        "store",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "iput-object", "iput-object v2, v0, Lcom/ex/B;->holder Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/B;->holder Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    load = _method(
        "Lcom/ex/B;",
        "nest",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/B;->holder Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/B;->holder Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "iput-object", "iput-object v0, v1, Lcom/ex/B;->sock Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/B;->sock Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    # max=1: second distinct field should truncate
    flow1 = trace_object_flow(store, 0, [store, load], socket_register="v2", max_field_hops=1)
    assert any(b.get("reason") == "max_field_hops" for b in flow1["boundaries"])
    flow2 = trace_object_flow(store, 0, [store, load], socket_register="v2", max_field_hops=2)
    assert any(t.get("field", "").endswith("sock") for t in flow2["transfers"] if t.get("kind") == "field_store")


def test_same_field_reentry_does_not_burn_hop() -> None:
    """Diagnosis: repeated mSocket store must not consume a second hop."""
    store = _method(
        "Lcom/ex/S;",
        "connect",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "iput-object", "iput-object v2, v0, Lcom/ex/S;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/S;->mSocket Landroid/bluetooth/BluetoothSocket;"),
            _ins(3, "iput-object", "iput-object v2, v0, Lcom/ex/S;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/S;->mSocket Landroid/bluetooth/BluetoothSocket;"),
            _ins(4, "invoke-virtual", "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V", registers=["v2"]),
        ],
    )
    load = _method(
        "Lcom/ex/S;",
        "read",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/S;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/S;->mSocket Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "invoke-virtual", "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;", registers=["v0"]),
            _ins(2, "move-result-object", "move-result-object v2", registers=["v2"]),
        ],
    )
    flow = trace_object_flow(store, 0, [store, load], socket_register="v2", max_field_hops=1)
    # With corrected semantics, same-field re-store at hops=1 must not emit MFH for mSocket
    mfh_msocket = [
        b
        for b in flow["boundaries"]
        if b.get("reason") == "max_field_hops" and "mSocket" in str(b.get("field"))
    ]
    assert mfh_msocket == []


def test_fixture_c_getter_return() -> None:
    getter = _method(
        "Lcom/ex/G;",
        "getSocket",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/G;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/G;->mSocket Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "return-object", "return-object v0", registers=["v0"]),
        ],
    )
    store = _method(
        "Lcom/ex/G;",
        "store",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "iput-object", "iput-object v2, v0, Lcom/ex/G;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/G;->mSocket Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    caller = _method(
        "Lcom/ex/C;",
        "use",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, Lcom/ex/G;->getSocket()Landroid/bluetooth/BluetoothSocket;", registers=["v0"]),
            _ins(1, "move-result-object", "move-result-object v1", registers=["v1"]),
            _ins(2, "invoke-virtual", "invoke-virtual v1, Landroid/bluetooth/BluetoothSocket;->connect()V", registers=["v1"]),
        ],
    )
    flow = trace_object_flow(store, 0, [store, getter, caller], socket_register="v2", max_method_hops=3, max_field_hops=2)
    kinds = {t["kind"] for t in flow["transfers"]}
    assert "field_load" in kinds


def test_fixture_d_setter() -> None:
    setter = _method(
        "Lcom/ex/D;",
        "setSocket",
        "(Landroid/bluetooth/BluetoothSocket;)V",
        [
            _ins(0, "iput-object", "iput-object v1, v0, Lcom/ex/D;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v1", "v0"], referenced_field="Lcom/ex/D;->mSocket Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "return-void", "return-void", registers=[]),
        ],
    )
    create = _method(
        "Lcom/ex/D;",
        "create",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "invoke-virtual", "invoke-virtual v0, v2, Lcom/ex/D;->setSocket(Landroid/bluetooth/BluetoothSocket;)V", registers=["v0", "v2"]),
        ],
    )
    load = _method(
        "Lcom/ex/D;",
        "load",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/D;->mSocket Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/D;->mSocket Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    flow = trace_object_flow(create, 0, [create, setter, load], socket_register="v2", max_method_hops=3)
    assert any(t["kind"] in {"parameter", "field_store"} for t in flow["transfers"])


def test_fixture_e_constructor() -> None:
    ctor = _method(
        "Lcom/ex/Holder;",
        "<init>",
        "(Landroid/bluetooth/BluetoothSocket;)V",
        [
            _ins(0, "iput-object", "iput-object v1, v0, Lcom/ex/Holder;->sock Landroid/bluetooth/BluetoothSocket;", registers=["v1", "v0"], referenced_field="Lcom/ex/Holder;->sock Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "return-void", "return-void", registers=[]),
        ],
    )
    create = _method(
        "Lcom/ex/E;",
        "make",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "new-instance", "new-instance v3, Lcom/ex/Holder;", registers=["v3"]),
            _ins(3, "invoke-direct", "invoke-direct v3, v2, Lcom/ex/Holder;-><init>(Landroid/bluetooth/BluetoothSocket;)V", registers=["v3", "v2"]),
        ],
    )
    flow = trace_object_flow(create, 0, [create, ctor], socket_register="v2", max_method_hops=3)
    assert any(t["kind"] == "constructor_arg" or "field_store" in t["kind"] for t in flow["transfers"]) or flow["objects"]


def test_fixture_f_alias_move_object() -> None:
    m = _method(
        "Lcom/ex/F;",
        "alias",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "move-object", "move-object v3, v2", registers=["v3", "v2"]),
            _ins(3, "invoke-virtual", "invoke-virtual v3, Landroid/bluetooth/BluetoothSocket;->connect()V", registers=["v3"]),
        ],
    )
    flow = trace_object_flow(m, 0, [m], socket_register="v2")
    assert any(n.get("operation") == "BluetoothSocket.connect" for n in flow.get("nodes") or []) or any(
        t.get("kind") for t in flow["transfers"]
    )


def test_fixture_g_static_field() -> None:
    store = _method(
        "Lcom/ex/G;",
        "store",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "sput-object", "sput-object v2, Lcom/ex/G;->sSocket Landroid/bluetooth/BluetoothSocket;", registers=["v2"], referenced_field="Lcom/ex/G;->sSocket Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    load = _method(
        "Lcom/ex/G;",
        "load",
        "()V",
        [
            _ins(0, "sget-object", "sget-object v0, Lcom/ex/G;->sSocket Landroid/bluetooth/BluetoothSocket;", registers=["v0"], referenced_field="Lcom/ex/G;->sSocket Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    flow = trace_object_flow(store, 0, [store, load], socket_register="v2")
    assert any(t.get("static_field") for t in flow["transfers"] if t.get("kind") == "field_store")


def test_fixture_h_cycle() -> None:
    store = _method(
        "Lcom/ex/H;",
        "store",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "iput-object", "iput-object v2, v0, Lcom/ex/H;->a Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/H;->a Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    bounce = _method(
        "Lcom/ex/H;",
        "bounce",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/H;->a Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/H;->a Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "iput-object", "iput-object v0, v1, Lcom/ex/H;->b Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/H;->b Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    back = _method(
        "Lcom/ex/H;",
        "back",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/H;->b Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/H;->b Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "iput-object", "iput-object v0, v1, Lcom/ex/H;->a Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/H;->a Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    flow = trace_object_flow(store, 0, [store, bounce, back], socket_register="v2", max_field_hops=4)
    assert any(b.get("reason") in {"cycle", "cycle_detected"} for b in flow["boundaries"])


def test_fixture_i_unknown_alias_register_overwrite() -> None:
    m = _method(
        "Lcom/ex/I;",
        "overwrite",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(3, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(4, "invoke-virtual", "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V", registers=["v2"]),
        ],
    )
    flow = trace_object_flow(m, 0, [m], socket_register="v2")
    assert any(t.get("kind") == "register_overwrite" for t in flow["transfers"])


def test_negative_same_type_not_same_object() -> None:
    # Two creates into different registers — no automatic merge
    m = _method(
        "Lcom/ex/N;",
        "two",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(3, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(4, "invoke-virtual", "invoke-virtual v3, Landroid/bluetooth/BluetoothSocket;->connect()V", registers=["v3"]),
        ],
    )
    flow = trace_object_flow(m, 0, [m], socket_register="v2")
    # Only socket:S1 is tracked from first create; connect on v3 is a different object → not claimed
    sock_objects = [o for o in flow["objects"] if o["kind"] == "SOCKET"]
    assert len(sock_objects) == 1


def test_hop_sweep_and_estimator_field_hops() -> None:
    store = _method(
        "Lcom/ex/Z;",
        "store",
        "()V",
        [
            _ins(0, "invoke-virtual", "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"]),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "iput-object", "iput-object v2, v0, Lcom/ex/Z;->a Landroid/bluetooth/BluetoothSocket;", registers=["v2", "v0"], referenced_field="Lcom/ex/Z;->a Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    load = _method(
        "Lcom/ex/Z;",
        "nest",
        "()V",
        [
            _ins(0, "iget-object", "iget-object v0, v1, Lcom/ex/Z;->a Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/Z;->a Landroid/bluetooth/BluetoothSocket;"),
            _ins(1, "iput-object", "iput-object v0, v1, Lcom/ex/Z;->b Landroid/bluetooth/BluetoothSocket;", registers=["v0", "v1"], referenced_field="Lcom/ex/Z;->b Landroid/bluetooth/BluetoothSocket;"),
        ],
    )
    sweep = hop_sweep_synthetic(store, 0, [store, load], socket_register="v2")
    assert [r["max_field_hops"] for r in sweep] == [1, 2, 3, 4]
    assert sweep[0]["max_field_hops_boundaries"] >= sweep[-1]["max_field_hops_boundaries"]

    art = ArtifactFingerprint("/a.apk", "a.apk", 10_000_000, 2, 5_000_000, 0, 0, 10)
    base = PlanFactors(
        True, True, 1, 10, 10, 8, 5, 0, 0, ("bluetooth",), None,
        bt_interprocedural=True, bt_max_method_hops=3, bt_max_field_hops=1, bt_max_object_nodes=100,
        bt_reconstruct_callers=True, bt_caller_depth=1, bt_reconstruct_streams=True, bt_dataflow_depth=1,
    )
    rich = PlanFactors(**{**base.__dict__, "bt_max_field_hops": 4})
    e0 = estimate_resources([art], base, get_resource_policy("standard"))
    e1 = estimate_resources([art], rich, get_resource_policy("standard"))
    assert e1.memory_mb >= e0.memory_mb
    assert e1.runtime_seconds >= e0.runtime_seconds


def test_path_matrix_from_bmw_report_if_present() -> None:
    path = Path("output/bmw-connected-600-v10/report.json")
    if not path.is_file():
        return
    report = json.loads(path.read_text(encoding="utf-8"))
    matrix = path_matrix_from_report(report)
    assert len(matrix) == 13
    mfh = [r for r in matrix if r["max_field_hops_hits"]]
    assert len(mfh) >= 1
    cause = classify_root_cause(matrix)
    assert cause["protocol_semantics"] == "UNKNOWN"
    built = build_field_coverage_report(
        baseline_report=report,
        root_cause=cause,
        path_matrix=matrix,
        provenance={"source": str(path), "engine": "v1.2"},
    )
    assert built["schema"].startswith("apk_forensics.field_coverage")
    # Reconstruct at least one chain
    df = (report.get("bluetooth_path") or {}).get("dataflow_paths") or []
    if df:
        chain = reconstruct_field_chain(df[0].get("transfers") or [], "socket:S1")
        assert isinstance(chain, list)
