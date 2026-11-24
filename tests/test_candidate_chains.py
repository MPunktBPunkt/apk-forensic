from __future__ import annotations

from apk_forensics.candidate_chains import build_candidate_chains


def test_chain_requires_multiple_nodes_same_method() -> None:
    contexts = [
        {
            "context_id": "dexctx-1",
            "dex_entry": "classes.dex",
            "class_name": "Lcom/example/BluetoothTransport;",
            "class_name_normalized": "com.example.BluetoothTransport",
            "method_name": "connect",
            "method_descriptor": "()V",
            "match": {
                "value": "createRfcommSocketToServiceRecord",
                "match_type": "method_reference",
            },
            "referenced_symbols": {
                "methods": [
                    "Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                    "Landroid/bluetooth/BluetoothSocket;->connect()V",
                    "Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                ],
                "classes": [],
                "fields": [],
                "strings": ["00001101-0000-1000-8000-00805F9B34FB"],
            },
        }
    ]
    chains = build_candidate_chains(contexts)
    assert len(chains) == 1
    chain = chains[0]
    assert chain["classification"] == "INFERENCE"
    assert chain["runtime_execution_proven"] is False
    assert chain["wire_correlation_available"] is False
    assert chain["chain_id"].startswith("chain-")
    assert any(e["relationship"] == "same_method" for e in chain["edges"])
    assert "createRfcommSocketToServiceRecord" in chain["summary"]


def test_no_chain_for_single_isolated_string() -> None:
    contexts = [
        {
            "context_id": "dexctx-2",
            "dex_entry": "classes.dex",
            "class_name": "Lcom/example/Other;",
            "class_name_normalized": "com.example.Other",
            "method_name": "unrelatedMethod",
            "method_descriptor": "()V",
            "match": {"value": "BCL", "match_type": "string"},
            "referenced_symbols": {
                "methods": [],
                "classes": [],
                "fields": [],
                "strings": ["BCL"],
            },
        }
    ]
    assert build_candidate_chains(contexts) == []
