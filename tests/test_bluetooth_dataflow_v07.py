"""v0.7 caller / socket / stream / dataflow reconstruction tests."""

from __future__ import annotations

from apk_forensics.bluetooth_callers import find_direct_callers, reconstruct_caller_paths
from apk_forensics.bluetooth_dataflow import build_candidate_path, build_dataflow_path
from apk_forensics.bluetooth_socket import (
    analyze_io_path,
    analyze_socket_path,
    analyze_stream_consumers,
    analyze_stream_producers,
    track_socket_object,
)
from apk_forensics.bluetooth_uuid import resolve_rfcomm_uuid_argument
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref
from apk_forensics.resource_estimator import PlanFactors, estimate_resources, fingerprint_apk
from apk_forensics.resource_policy import get_resource_policy
from apk_forensics.search_plan import validate_and_normalize
from tests.test_bluetooth_uuid import _ins, _transport_methods


def _method(
    class_name: str,
    name: str,
    descriptor: str,
    instructions: list[InstructionInfo],
    *,
    dex: str = "classes.dex",
) -> MethodInfo:
    return MethodInfo(
        dex_entry=dex,
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


def _rfcomm_target_with_io() -> MethodInfo:
    return _method(
        "Lcom/example/BtAccessorySocket;",
        "connectAccessory",
        "()Z",
        [
            _ins(
                0,
                "iget-object",
                "iget-object v0, v8, Lcom/example/BtAccessorySocket;->mBluetoothDevice Landroid/bluetooth/BluetoothDevice;",
                registers=["v0", "v8"],
                referenced_field="Lcom/example/BtAccessorySocket;->mBluetoothDevice Landroid/bluetooth/BluetoothDevice;",
            ),
            _ins(
                1,
                "sget-object",
                "sget-object v5, Lcom/example/BtAccessorySocket;->sSppUuid Ljava/util/UUID;",
                registers=["v5"],
                referenced_field="Lcom/example/BtAccessorySocket;->sSppUuid Ljava/util/UUID;",
            ),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v0, v5, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v5"],
            ),
            _ins(3, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                4,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v2"],
            ),
            _ins(
                5,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                registers=["v2"],
            ),
            _ins(6, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(
                7,
                "invoke-virtual",
                "invoke-virtual v2, Landroid/bluetooth/BluetoothSocket;->getOutputStream()Ljava/io/OutputStream;",
                registers=["v2"],
            ),
            _ins(8, "move-result-object", "move-result-object v4", registers=["v4"]),
            _ins(
                9,
                "invoke-virtual",
                "invoke-virtual v3, v6, Ljava/io/InputStream;->read([B)I",
                registers=["v3", "v6"],
            ),
            _ins(
                10,
                "invoke-virtual",
                "invoke-virtual v4, v6, Ljava/io/OutputStream;->write([B)V",
                registers=["v4", "v6"],
            ),
            _ins(
                11,
                "invoke-virtual",
                "invoke-virtual v3, Lcom/example/BluetoothMessageReader;->readFrame([B)V",
                registers=["v3"],
            ),
        ],
    )


def test_unique_caller_fact() -> None:
    target = _rfcomm_target_with_io()
    caller = _method(
        "Lcom/example/Controller;",
        "start",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                registers=["v0"],
            )
        ],
    )
    callers = find_direct_callers(target, [caller, target], max_callers=10)
    assert len(callers) == 1
    assert callers[0]["classification"] == "FACT"
    assert callers[0]["method_name"] == "start"


def test_multiple_callers_preserved() -> None:
    target = _rfcomm_target_with_io()
    c1 = _method(
        "Lcom/example/A;",
        "a",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                registers=["v0"],
            )
        ],
    )
    c2 = _method(
        "Lcom/example/B;",
        "b",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                registers=["v0"],
            )
        ],
    )
    callers = find_direct_callers(target, [c1, c2, target], max_callers=10)
    assert len(callers) == 2
    assert {c["method_name"] for c in callers} == {"a", "b"}


def test_no_caller_unknown() -> None:
    target = _rfcomm_target_with_io()
    other = _method(
        "Lcom/example/Other;",
        "noop",
        "()V",
        [_ins(0, "return-void", "return-void", registers=[])],
    )
    rec = reconstruct_caller_paths(target, [target, other], caller_depth=2, max_callers=10)
    assert rec["caller_count"] == 0
    assert rec["classification"] == "UNKNOWN"


def test_caller_depth_and_limit() -> None:
    target = _rfcomm_target_with_io()
    mid = _method(
        "Lcom/example/Mid;",
        "mid",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                registers=["v0"],
            )
        ],
    )
    top = _method(
        "Lcom/example/Top;",
        "top",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, Lcom/example/Mid;->mid()V",
                registers=["v0"],
            )
        ],
    )
    depth1 = reconstruct_caller_paths(target, [top, mid, target], caller_depth=1, max_callers=10)
    assert depth1["caller_count"] == 1
    depth2 = reconstruct_caller_paths(target, [top, mid, target], caller_depth=2, max_callers=10)
    assert depth2["caller_count"] >= 2
    limited = reconstruct_caller_paths(target, [top, mid, target], caller_depth=2, max_callers=1)
    assert limited["caller_count"] == 1


def test_socket_register_link_fact() -> None:
    method = _rfcomm_target_with_io()
    socket = track_socket_object(method, 2, window=12)
    assert socket["register_linked"] is True
    assert socket["has_connect"] is True
    assert socket["has_input_stream"] is True
    assert socket["has_output_stream"] is True
    assert socket["classification"] == "FACT"


def test_socket_window_without_register_is_inference() -> None:
    # create without move-result; connect appears later in window on a different reg → INFERENCE
    method = _method(
        "Lcom/example/X;",
        "m",
        "()V",
        [
            _ins(
                0,
                "invoke-virtual",
                "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v1"],
            ),
            _ins(1, "nop", "nop", registers=[]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v9, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v9"],
            ),
        ],
    )
    socket = analyze_socket_path(method, 0, window=8)
    assert socket["has_connect"] is True
    assert socket["register_linked"] is False
    assert socket["classification"] == "INFERENCE"


def test_input_read_linked_fact() -> None:
    method = _rfcomm_target_with_io()
    consumers = analyze_stream_consumers(method, 2, window=12)
    assert consumers["classification"] == "FACT"
    assert consumers["read_calls"]
    assert consumers["read_calls"][0]["register_linked"] is True
    assert any(c.get("kind") == "METHOD_NAME_CANDIDATE" for c in consumers["parser_candidates"])


def test_output_write_linked_fact() -> None:
    method = _rfcomm_target_with_io()
    producers = analyze_stream_producers(method, 2, window=12)
    assert producers["classification"] == "FACT"
    assert producers["write_calls"]
    assert producers["write_calls"][0]["register_linked"] is True


def test_no_read_is_unknown_not_rejected() -> None:
    clinit, connect, _ = _transport_methods()
    consumers = analyze_stream_consumers(connect, 2, window=12)
    assert consumers["classification"] == "UNKNOWN"
    assert consumers["consumer_status"] == "UNKNOWN"
    assert consumers["consumer"] is None


def test_dataflow_path_partial_not_runtime() -> None:
    method = _rfcomm_target_with_io()
    socket = analyze_socket_path(method, 2, window=12)
    io_info = analyze_io_path(method, 2, window=12, socket_tracking=socket)
    df = build_dataflow_path(
        target_method="Lcom/example/BtAccessorySocket;->connectAccessory()Z",
        path_id="btpath-test",
        socket_creation={"method": "createRfcommSocketToServiceRecord", "classification": "FACT"},
        connect={"method": "BluetoothSocket.connect", "classification": "FACT", "confidence": "high"},
        input_info={"method": "BluetoothSocket.getInputStream", "classification": "FACT", "confidence": "high"},
        output_info={"method": "BluetoothSocket.getOutputStream", "classification": "FACT", "confidence": "high"},
        read_chain=list(io_info.get("read_calls") or []),
        write_chain=list(io_info.get("write_calls") or []),
        caller_reconstruction={"caller_count": 0, "callers": []},
        max_nodes=50,
    )
    assert df["id"].startswith("btdata-")
    assert df["classification"] == "INFERENCE"
    assert df["structure"] == "PARTIAL"
    assert df["runtime_execution_proven"] is False
    assert df["wire_correlation_available"] is False


def test_candidate_path_still_inference() -> None:
    clinit, connect, _ = _transport_methods()
    uuid_res = resolve_rfcomm_uuid_argument(
        connect, 2, class_methods=[clinit, connect], dataflow_depth=2
    )
    socket = analyze_socket_path(connect, 2, window=12)
    path = build_candidate_path(
        method_class=connect.class_name,
        method_class_normalized=connect.class_name_normalized,
        method_name=connect.method_name,
        method_descriptor=connect.method_descriptor,
        dex_entry=connect.dex_entry,
        rfcomm_api="createRfcommSocketToServiceRecord",
        create_index=2,
        uuid_resolution=uuid_res,
        device_source={"source_type": "instance_field", "notes": []},
        socket_path=socket,
        io_path={"read_calls": [], "write_calls": [], "buffer_refs": []},
        profile_correlations=[],
    )
    assert path["classification"] == "INFERENCE"
    assert path["runtime_execution_proven"] is False


def test_search_plan_v07_fields() -> None:
    plan = validate_and_normalize(
        {
            "schema_version": "1.0",
            "plan": {"name": "t", "modules": ["bluetooth"]},
            "bluetooth": {
                "enabled": True,
                "caller_depth": 2,
                "dataflow_depth": 2,
                "reconstruct_callers": True,
                "reconstruct_streams": True,
                "reconstruct_read_write": True,
                "max_callers": 40,
                "max_dataflow_nodes": 100,
            },
        }
    )
    assert plan.bluetooth_caller_depth == 2
    assert plan.bluetooth_max_callers == 40
    assert plan.bluetooth_max_dataflow_nodes == 100


def test_resource_estimator_accounts_for_dataflow(tmp_path) -> None:
    import zipfile

    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x00")
        for i in range(4):
            name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            zf.writestr(name, b"dex" + b"X" * 1000)
    fp = fingerprint_apk(apk)
    policy = get_resource_policy("standard")
    base = PlanFactors(
        dex_context=True,
        bluetooth=True,
        xref_depth=2,
        max_callers=20,
        max_callees=20,
        instruction_window=8,
        search_terms=12,
        search_regex=1,
        search_uuids=1,
        modules=("bluetooth",),
        plan_sha256=None,
    )
    rich = PlanFactors(
        dex_context=True,
        bluetooth=True,
        xref_depth=2,
        max_callers=20,
        max_callees=20,
        instruction_window=8,
        search_terms=12,
        search_regex=1,
        search_uuids=1,
        modules=("bluetooth",),
        plan_sha256=None,
        bt_caller_depth=2,
        bt_dataflow_depth=2,
        bt_max_dataflow_nodes=200,
        bt_reconstruct_callers=True,
        bt_reconstruct_streams=True,
    )
    est_base = estimate_resources([fp], base, policy)
    est_rich = estimate_resources([fp], rich, policy)
    assert est_rich.memory_mb > est_base.memory_mb
    assert est_rich.runtime_seconds > est_base.runtime_seconds
    assert "bt_caller_depth=2" in est_rich.reasons
