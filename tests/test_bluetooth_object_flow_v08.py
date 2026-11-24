"""v0.8 cross-method Bluetooth socket/stream object-flow tests."""

from __future__ import annotations

from apk_forensics.bluetooth_callers import reconstruct_caller_paths, summarize_caller_reconstruction
from apk_forensics.bluetooth_object_flow import trace_object_flow
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref
from apk_forensics.search_plan import validate_and_normalize


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


def _synthetic_pipeline() -> list[MethodInfo]:
    """A → B → connectAccessory → return socket → C(socket) → field → D → stream → wrapper → read/write."""
    connect = _method(
        "Lcom/example/BtAccessorySocket;",
        "connectAccessory",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v2"],
            ),
            _ins(3, "return-object", "return-object v2", registers=["v2"]),
        ],
    )
    open_sock = _method(
        "Lcom/example/LegacyBtHandler;",
        "openAccessorySocket",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/BtAccessorySocket;->connectAccessory()Landroid/bluetooth/BluetoothSocket;",
                registers=["v0"],
            ),
            _ins(1, "move-result-object", "move-result-object v1", registers=["v1"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v0, v1, Lcom/example/LegacyBtHandler;->consumeSocket(Landroid/bluetooth/BluetoothSocket;)V",
                registers=["v0", "v1"],
            ),
            _ins(3, "return-object", "return-object v1", registers=["v1"]),
        ],
    )
    consume = _method(
        "Lcom/example/LegacyBtHandler;",
        "consumeSocket",
        "(Landroid/bluetooth/BluetoothSocket;)V",
        [
            _ins(
                0,
                "iput-object",
                "iput-object v1, v0, Lcom/example/LegacyBtHandler;->socket Landroid/bluetooth/BluetoothSocket;",
                registers=["v1", "v0"],
                referenced_field="Lcom/example/LegacyBtHandler;->socket Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(1, "return-void", "return-void", registers=[]),
        ],
    )
    read_loop = _method(
        "Lcom/example/LegacyBtHandler;",
        "readLoop",
        "()V",
        [
            _ins(
                0,
                "iget-object",
                "iget-object v0, v1, Lcom/example/LegacyBtHandler;->socket Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
                referenced_field="Lcom/example/LegacyBtHandler;->socket Landroid/bluetooth/BluetoothSocket;",
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
                "new-instance",
                "new-instance v3, Ljava/io/BufferedInputStream;",
                registers=["v3"],
            ),
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
            _ins(
                6,
                "invoke-virtual",
                "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->getOutputStream()Ljava/io/OutputStream;",
                registers=["v0"],
            ),
            _ins(7, "move-result-object", "move-result-object v5", registers=["v5"]),
            _ins(
                8,
                "new-instance",
                "new-instance v6, Ljava/io/BufferedOutputStream;",
                registers=["v6"],
            ),
            _ins(
                9,
                "invoke-direct",
                "invoke-direct v6, v5, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;)V",
                registers=["v6", "v5"],
            ),
            _ins(
                10,
                "invoke-virtual",
                "invoke-virtual v6, v4, Ljava/io/BufferedOutputStream;->write([B)V",
                registers=["v6", "v4"],
            ),
            _ins(11, "return-void", "return-void", registers=[]),
        ],
    )
    handshake = _method(
        "Lcom/example/LegacyBtHandler;",
        "doBclHandshake",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/LegacyBtHandler;->openAccessorySocket()Landroid/bluetooth/BluetoothSocket;",
                registers=["v0"],
            ),
            _ins(1, "move-result-object", "move-result-object v1", registers=["v1"]),
            _ins(2, "return-void", "return-void", registers=[]),
        ],
    )
    return [handshake, open_sock, connect, consume, read_loop]


def test_cross_method_return_parameter_field_wrapper_read_write() -> None:
    methods = _synthetic_pipeline()
    connect = methods[2]
    flow = trace_object_flow(
        connect,
        0,
        methods,
        socket_register="v2",
        max_method_hops=3,
        max_field_hops=2,
        max_object_nodes=200,
        window=20,
    )
    kinds = {t["kind"] for t in flow["transfers"]}
    assert "return" in kinds
    assert "parameter" in kinds or "field_store" in kinds
    assert "field_store" in kinds
    assert "field_load" in kinds
    assert "get_input_stream" in kinds
    assert "get_output_stream" in kinds
    assert flow["input_read_chain"], "expected cross-method read"
    assert flow["output_write_chain"], "expected cross-method write"
    assert flow["classification"] == "INFERENCE"
    assert flow["runtime_execution_proven"] is False
    assert any(o["kind"] == "WRAPPER" for o in flow["objects"])


def test_method_hop_limit_boundary() -> None:
    methods = _synthetic_pipeline()
    connect = methods[2]
    flow = trace_object_flow(
        connect,
        0,
        methods,
        socket_register="v2",
        max_method_hops=0,
        max_field_hops=2,
        max_object_nodes=200,
        window=20,
    )
    assert any(b.get("reason") == "max_method_hops" for b in flow["boundaries"])


def test_field_hop_limit() -> None:
    store = _method(
        "Lcom/example/A;",
        "store",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "iput-object",
                "iput-object v2, v0, Lcom/example/A;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v2", "v0"],
                referenced_field="Lcom/example/A;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
        ],
    )
    load = _method(
        "Lcom/example/A;",
        "load",
        "()V",
        [
            _ins(
                0,
                "iget-object",
                "iget-object v0, v1, Lcom/example/A;->sock Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
                referenced_field="Lcom/example/A;->sock Landroid/bluetooth/BluetoothSocket;",
            ),
            _ins(
                1,
                "iput-object",
                "iput-object v0, v1, Lcom/example/A;->sock2 Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
                referenced_field="Lcom/example/A;->sock2 Landroid/bluetooth/BluetoothSocket;",
            ),
        ],
    )
    flow = trace_object_flow(
        store,
        0,
        [store, load],
        socket_register="v2",
        max_method_hops=2,
        max_field_hops=1,
        max_object_nodes=50,
        window=12,
    )
    assert any(b.get("reason") == "max_field_hops" for b in flow["boundaries"]) or flow["transfers"]


def test_cycle_detection_does_not_explode() -> None:
    a = _method(
        "Lcom/example/Cyc;",
        "a",
        "()Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v0, v2, Lcom/example/Cyc;->b(Landroid/bluetooth/BluetoothSocket;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v2"],
            ),
            _ins(3, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(4, "return-object", "return-object v3", registers=["v3"]),
        ],
    )
    b = _method(
        "Lcom/example/Cyc;",
        "b",
        "(Landroid/bluetooth/BluetoothSocket;)Landroid/bluetooth/BluetoothSocket;",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, v1, Lcom/example/Cyc;->a()Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(2, "return-object", "return-object v1", registers=["v1"]),
        ],
    )
    flow = trace_object_flow(
        a, 0, [a, b], socket_register="v2", max_method_hops=3, max_field_hops=2, max_object_nodes=100, window=12
    )
    assert flow["counts"]["nodes"] <= 100


def test_caller_reduction_groups_and_dedupes() -> None:
    methods = _synthetic_pipeline()
    connect = methods[2]
    rec = reconstruct_caller_paths(connect, methods, caller_depth=2, max_callers=20)
    summary = summarize_caller_reconstruction(rec, max_callers_cap=20)
    assert summary["direct_callers"] >= 1
    assert summary["unique_chains"] >= 1
    assert summary["primary_chain"] is not None
    assert "connectAccessory" in " ".join(summary["primary_chain"]["chain"])


def test_no_false_fact_from_method_name() -> None:
    methods = _synthetic_pipeline()
    # doBclHandshake name must not create protocol FACT in object flow
    flow = trace_object_flow(
        methods[2], 0, methods, socket_register="v2", max_method_hops=3, max_field_hops=2, max_object_nodes=100, window=20
    )
    assert flow["classification"] == "INFERENCE"
    for t in flow["transfers"]:
        assert t["classification"] in {"FACT", "INFERENCE", "UNKNOWN"}
        assert "BCL" not in (t.get("kind") or "")


def test_search_plan_interprocedural_default_false() -> None:
    plan = validate_and_normalize(
        {"schema_version": "1.0", "plan": {"name": "t", "modules": ["bluetooth"]}, "bluetooth": {"enabled": True}}
    )
    assert plan.bluetooth_interprocedural is False


def test_search_plan_interprocedural_enabled() -> None:
    plan = validate_and_normalize(
        {
            "schema_version": "1.0",
            "plan": {"name": "t", "modules": ["bluetooth"]},
            "bluetooth": {
                "enabled": True,
                "interprocedural": True,
                "max_method_hops": 3,
                "max_field_hops": 2,
                "max_object_nodes": 100,
            },
        }
    )
    assert plan.bluetooth_interprocedural is True
    assert plan.bluetooth_max_method_hops == 3
