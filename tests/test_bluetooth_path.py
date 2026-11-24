from __future__ import annotations

from apk_forensics.bluetooth_dataflow import build_candidate_path
from apk_forensics.bluetooth_device import analyze_device_source
from apk_forensics.bluetooth_matcher import find_bluetooth_hits
from apk_forensics.bluetooth_socket import analyze_socket_path
from apk_forensics.bluetooth_uuid import resolve_rfcomm_uuid_argument
from tests.test_bluetooth_uuid import _transport_methods


def test_rfcomm_and_socket_detection() -> None:
    clinit, connect, unrelated = _transport_methods()
    hits = find_bluetooth_hits([clinit, connect, unrelated], max_results=50)
    apis = {h.api for h in hits}
    assert "createRfcommSocketToServiceRecord" in apis
    assert "BluetoothSocket.connect" in apis
    assert "getInputStream" in apis
    assert "getOutputStream" in apis


def test_device_source_instance_field() -> None:
    _, connect, _ = _transport_methods()
    device = analyze_device_source(connect, 2, window=12)
    assert device["source_type"] == "instance_field"
    assert device["classification"] == "FACT"


def test_candidate_path_inference_not_runtime_fact() -> None:
    clinit, connect, _ = _transport_methods()
    uuid_res = resolve_rfcomm_uuid_argument(
        connect, 2, class_methods=[clinit, connect], dataflow_depth=2
    )
    device = analyze_device_source(connect, 2, window=12)
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
        device_source=device,
        socket_path=socket,
        io_path={"read_calls": [], "write_calls": [], "buffer_refs": []},
        profile_correlations=[],
    )
    assert path["classification"] == "INFERENCE"
    assert path["runtime_execution_proven"] is False
    assert path["wire_correlation_available"] is False
    assert "00001101-0000-1000-8000-00805f9b34fb" in path["summary"]
    assert path["path_id"].startswith("btpath-")


def test_unconnected_uuid_does_not_create_fake_path_link() -> None:
    # Unrelated method has UUID string only; no RFCOMM create there.
    _, _, unrelated = _transport_methods()
    hits = find_bluetooth_hits([unrelated], max_results=20)
    assert all(h.category != "rfcomm_create" for h in hits)
