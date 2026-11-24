"""v0.9 evidence graph: canonicalize, provenance, boundaries, ranking."""

from __future__ import annotations

import copy

from apk_forensics.evidence_graph import (
    build_evidence_graph,
    build_evidence_graph_for_path,
    compare_cross_version,
    method_name_semantics,
)
from apk_forensics.resource_estimator import ArtifactFingerprint, PlanFactors, estimate_resources
from apk_forensics.resource_policy import get_resource_policy
from apk_forensics.search_plan import validate_and_normalize


def _sample_dataflow_path(**overrides):
    base = {
        "id": "btdata-sample",
        "display_id": "BTDATA-000001",
        "target": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
        "caller_chain": [
            "Lcom/example/LegacyBtHandler;->doBclHandshake(Ljava/lang/String;)Z",
            "Lcom/example/LegacyBtHandler;->openAccessorySocket(Landroid/bluetooth/BluetoothDevice;)Lcom/example/BtAccessorySocket;",
            "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
        ],
        "caller_summary": {
            "direct_callers": 1,
            "depth_1": 1,
            "depth_2": 1,
            "duplicate": 0,
            "truncated": 0,
            "unique_chains": 2,
        },
        "objects": ["socket:S1", "input:I1", "output:O1"],
        "object_details": [
            {"object_id": "socket:S1", "kind": "socket", "classification": "FACT"},
            {"object_id": "input:I1", "kind": "input", "classification": "FACT"},
            {"object_id": "output:O1", "kind": "output", "classification": "FACT"},
        ],
        "socket_creation": {
            "method": "createRfcommSocketToServiceRecord",
            "classification": "FACT",
            "confidence": "high",
        },
        "connect": {
            "method": "BluetoothSocket.connect",
            "classification": "FACT",
            "confidence": "high",
        },
        "input": {
            "method": "BluetoothSocket.getInputStream",
            "classification": "FACT",
            "confidence": "high",
        },
        "output": {
            "method": "BluetoothSocket.getOutputStream",
            "classification": "FACT",
            "confidence": "high",
        },
        "nodes": [
            {"node_id": "n1", "node_type": "SOCKET", "value": "socket", "classification": "FACT"},
            {"node_id": "n2", "node_type": "FIELD_WRITE", "value": "mBtSocket", "classification": "FACT"},
            {"node_id": "n2b", "node_type": "FIELD_WRITE", "value": "mBtSocket", "classification": "FACT"},
        ],
        "edges": [
            {"from": "n1", "to": "n2", "relationship": "FIELD_STORE", "classification": "FACT"},
            {"from": "n1", "to": "n2b", "relationship": "FIELD_STORE", "classification": "FACT"},
        ],
        "transfers": [
            {
                "kind": "field_store",
                "object_id": "socket:S1",
                "field": "Lcom/example/BtAccessorySocket;->mBtSocket",
                "from_method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "field_store",
                "object_id": "socket:S1",
                "field": "Lcom/example/BtAccessorySocket;->mBtSocket",
                "from_method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "field_load",
                "object_id": "socket:S1",
                "field": "Lcom/example/BtAccessorySocket;->mBtSocket",
                "to_method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "get_input_stream",
                "method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "field_store",
                "object_id": "input:I1",
                "field": "Lcom/example/BtAccessorySocket;->mInputStream",
                "from_method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "field_load",
                "object_id": "input:I1",
                "field": "Lcom/example/BtAccessorySocket;->mInputStream",
                "to_method": "Lcom/example/BtAccessorySocket;->read()I",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "get_output_stream",
                "method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "field_store",
                "object_id": "output:O1",
                "field": "Lcom/example/BtAccessorySocket;->mOutputStream",
                "from_method": "Lcom/example/BtAccessorySocket;->connectAccessory()Z",
                "classification": "FACT",
                "confidence": "high",
            },
            {
                "kind": "field_load",
                "object_id": "output:O1",
                "field": "Lcom/example/BtAccessorySocket;->mOutputStream",
                "to_method": "Lcom/example/BtAccessorySocket;->write([B)V",
                "classification": "FACT",
                "confidence": "high",
            },
        ],
        "input_read_chain": [
            {
                "method": "Lcom/example/BtAccessorySocket;->read()I",
                "text": "invoke-virtual v0, Ljava/io/InputStream;->read()I",
                "raw": "Ljava/io/InputStream;->read()I",
                "object_id": "input:I1",
                "classification": "FACT",
                "confidence": "high",
                "offset": None,
            },
            {
                "method": "Lcom/example/BtAccessorySocket;->read()I",
                "text": "invoke-virtual v0, Ljava/io/InputStream;->read()I",
                "raw": "Ljava/io/InputStream;->read()I",
                "object_id": "input:I1",
                "classification": "FACT",
                "confidence": "high",
                "offset": None,
            },
        ],
        "output_write_chain": [
            {
                "method": "Lcom/example/BtAccessorySocket;->write([B)V",
                "text": "invoke-virtual v0, v2, Ljava/io/OutputStream;->write([B)V",
                "raw": "Ljava/io/OutputStream;->write([B)V",
                "object_id": "output:O1",
                "classification": "FACT",
                "confidence": "high",
                "offset": None,
            }
        ],
        "boundaries": [
            {
                "reason": "return_no_move_result",
                "object_id": "input:I1",
                "method": "Lcom/example/BtAccessorySocket;->read()I",
                "classification": "UNKNOWN",
                "notes": ["Cross-method object-flow boundary; static evidence ends here."],
            },
            {
                "reason": "max_field_hops",
                "object_id": "socket:S1",
                "method": "Lcom/example/BtAccessorySocket;->closeAccessory()V",
                "field": "Lcom/example/BtAccessorySocket;->mBtSocket",
                "classification": "UNKNOWN",
            },
            {
                "reason": "cycle_detected",
                "object_id": "socket:S1",
                "cycle_length": 3,
                "classification": "UNKNOWN",
            },
        ],
        "classification": "INFERENCE",
        "confidence": "medium",
    }
    base.update(overrides)
    return base


def test_canonical_ids_deterministic():
    p = _sample_dataflow_path()
    a = build_evidence_graph_for_path(p, apk_sha256="abc")
    b = build_evidence_graph_for_path(copy.deepcopy(p), apk_sha256="abc")
    assert [o["object_id"] for o in a["canonical"]["objects"]] == [
        o["object_id"] for o in b["canonical"]["objects"]
    ]
    assert [n["node_id"] for n in a["canonical"]["nodes"]] == [
        n["node_id"] for n in b["canonical"]["nodes"]
    ]
    assert [e["edge_id"] for e in a["canonical"]["edges"]] == [
        e["edge_id"] for e in b["canonical"]["edges"]
    ]


def test_different_objects_different_ids():
    p = _sample_dataflow_path()
    eg = build_evidence_graph_for_path(p)
    ids = [o["object_id"] for o in eg["canonical"]["objects"]]
    assert len(ids) == len(set(ids))
    assert "socket:S1" in ids
    assert "input:I1" in ids
    assert "output:O1" in ids


def test_duplicate_transfers_deduped_with_provenance():
    p = _sample_dataflow_path()
    eg = build_evidence_graph_for_path(p)
    # Raw had duplicate field_store; canonical FIELD_STORE edges fewer than raw transfers
    assert eg["raw"]["transfers"] == len(p["transfers"])
    store_edges = [e for e in eg["canonical"]["edges"] if e["edge_type"] == "FIELD_STORE"]
    assert len(store_edges) >= 1
    # Provenance lists exist
    assert all("provenance" in e for e in eg["canonical"]["edges"])
    assert all("source_edge_ids" in e["provenance"] for e in eg["canonical"]["edges"])


def test_evidence_paths_socket_input_output_combined():
    eg = build_evidence_graph(dataflow_paths=[_sample_dataflow_path()], apk_sha256="x")
    kinds = {p["kind"] for p in eg["evidence_paths"]}
    assert "SOCKET_PATH" in kinds
    assert "INPUT_PATH" in kinds
    assert "OUTPUT_PATH" in kinds
    assert "COMBINED_COMMUNICATION_PATH" in kinds
    assert eg["evidence_paths"][0]["display_id"].startswith("PATH-")


def test_steps_fact_end_to_end_inference():
    eg = build_evidence_graph(dataflow_paths=[_sample_dataflow_path()])
    path = next(p for p in eg["evidence_paths"] if p["kind"] == "INPUT_PATH")
    assert all(c == "FACT" for c in path["step_classifications"])
    assert path["classification"] == "INFERENCE"
    assert path["protocol_semantics"] == "UNKNOWN"
    assert path["runtime_execution_proven"] is False


def test_boundary_exact_reason():
    eg = build_evidence_graph_for_path(_sample_dataflow_path())
    reasons = {b["reason"] for b in eg["boundaries"]}
    assert "return_no_move_result" in reasons
    assert "max_field_hops" in reasons
    b = next(x for x in eg["boundaries"] if x["reason"] == "return_no_move_result")
    assert b["classification"] == "UNKNOWN"
    assert b["next_required_evidence"]
    assert b["object"] == "input:I1"


def test_cycle_detected_flag():
    eg = build_evidence_graph_for_path(_sample_dataflow_path())
    assert eg["cycle_detected"] is True
    assert eg["cycle_length"] == 3


def test_method_name_not_protocol():
    sem = method_name_semantics("doBclHandshake")
    assert sem["method_name_evidence"] == "FACT"
    assert sem["protocol_semantics"] == "UNKNOWN"
    assert sem["hint_tokens_detected"] is True
    for name in ("EtchConnection", "RhmiHandler", "BMWService", "AAIdrive"):
        assert method_name_semantics(name)["protocol_semantics"] == "UNKNOWN"


def test_ranking_deterministic_and_preserves_classification():
    paths = [_sample_dataflow_path(), _sample_dataflow_path(id="btdata-other", target="LOther;->x()V")]
    a = build_evidence_graph(dataflow_paths=paths, max_evidence_paths=20)
    b = build_evidence_graph(dataflow_paths=copy.deepcopy(paths), max_evidence_paths=20)
    assert [p["path_id"] for p in a["evidence_paths"]] == [p["path_id"] for p in b["evidence_paths"]]
    for p in a["evidence_paths"]:
        assert p["classification"] in {"FACT", "INFERENCE", "UNKNOWN", "CORRELATION", "REJECTED"}
        # ranking must not invent FACT end-to-end for multi-step paths
        if len(p["steps"]) > 1:
            assert p["classification"] == "INFERENCE"


def test_instruction_offset_null_documented():
    eg = build_evidence_graph_for_path(_sample_dataflow_path())
    read_nodes = [n for n in eg["canonical"]["nodes"] if n["node_type"] == "READ"]
    assert read_nodes
    prov = read_nodes[0]["provenance"]
    assert prov["instruction_offset"] is None
    assert prov["instruction_offset_unavailable_reason"]


def test_search_plan_evidence_graph_default_false():
    plan = validate_and_normalize(
        {
            "schema_version": "1.0",
            "plan": {"name": "t", "modules": ["bluetooth"]},
            "bluetooth": {"enabled": True},
        }
    )
    assert plan.evidence_graph_enabled is False


def test_search_plan_evidence_graph_enabled():
    plan = validate_and_normalize(
        {
            "schema_version": "1.0",
            "plan": {"name": "t", "modules": ["bluetooth"]},
            "bluetooth": {"enabled": True},
            "evidence_graph": {"enabled": True, "max_evidence_paths": 25},
        }
    )
    assert plan.evidence_graph_enabled is True
    assert plan.evidence_graph_max_paths == 25


def test_resource_estimator_accounts_for_evidence_graph():
    policy = get_resource_policy("standard")
    art = ArtifactFingerprint(
        path="/tmp/x.apk",
        file_name="x.apk",
        size_bytes=50_000_000,
        dex_count=2,
        dex_total_bytes=20_000_000,
        native_so_count=0,
        native_total_bytes=0,
        entry_count=10,
    )
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
        bt_caller_depth=2,
        bt_dataflow_depth=3,
        bt_max_dataflow_nodes=200,
        bt_reconstruct_callers=True,
        bt_reconstruct_streams=True,
        bt_interprocedural=True,
        bt_max_method_hops=3,
        bt_max_field_hops=2,
        bt_max_object_nodes=500,
        evidence_graph=False,
    )
    with_eg = PlanFactors(**{**base.__dict__, "evidence_graph": True, "evidence_graph_max_paths": 50})
    e0 = estimate_resources([art], base, policy)
    e1 = estimate_resources([art], with_eg, policy)
    assert e1.memory_mb >= e0.memory_mb
    assert e1.runtime_seconds >= e0.runtime_seconds
    assert any("evidence_graph" in r for r in e1.reasons)


def test_cross_version_diff_scaffold():
    left = build_evidence_graph(dataflow_paths=[_sample_dataflow_path()], apk_sha256="a")
    right = build_evidence_graph(
        dataflow_paths=[_sample_dataflow_path(id="other")],
        apk_sha256="b",
    )
    left["cross_version_evidence"]["comparable"]["rfcomm_targets"] = 5
    right["cross_version_evidence"]["comparable"]["rfcomm_targets"] = 4
    diff = compare_cross_version(left, right)
    assert diff["metrics"]["rfcomm_targets"] == "CHANGED"
    assert "ADDED" in diff["path_fingerprints"]
    assert "REMOVED" in diff["path_fingerprints"]
    assert "UNCHANGED" in diff["path_fingerprints"]


def test_disabled_evidence_graph_empty():
    eg = build_evidence_graph(dataflow_paths=[_sample_dataflow_path()], enabled=False)
    assert eg["enabled"] is False
    assert eg["evidence_paths"] == []
