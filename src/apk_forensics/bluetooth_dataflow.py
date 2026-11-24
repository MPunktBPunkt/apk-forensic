"""Build bounded Bluetooth RFCOMM candidate paths from static evidence."""

from __future__ import annotations

import hashlib
from typing import Any


PROFILE_TOKENS = ["BCL", "RHMI", "Etch", "SAS", "CDS", "AV", "4004", "5001"]


def _path_id(*parts: str) -> str:
    key = "|".join(parts)
    return "btpath-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def _node_id(path_key: str, label: str) -> str:
    return "node-" + hashlib.sha256(f"{path_key}|{label}".encode()).hexdigest()[:12]


def collect_profile_correlations(method_instructions_text: str, *, scope: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    lower = method_instructions_text
    for token in PROFILE_TOKENS:
        if token in lower or token.lower() in lower.lower():
            hits.append(
                {
                    "profile": "bmw_connected",
                    "profile_match": token,
                    "scope": scope,
                    "classification": "CORRELATION",
                    "profile_confidence": "medium" if token in {"BCL", "RHMI", "Etch"} else "low",
                    "notes": ["Profile match is a correlation, not protocol proof."],
                }
            )
    return hits


def build_candidate_path(
    *,
    method_class: str,
    method_class_normalized: str | None,
    method_name: str,
    method_descriptor: str,
    dex_entry: str,
    rfcomm_api: str,
    create_index: int,
    uuid_resolution: dict[str, Any],
    device_source: dict[str, Any],
    socket_path: dict[str, Any],
    io_path: dict[str, Any],
    profile_correlations: list[dict[str, Any]],
) -> dict[str, Any]:
    path_key = f"{dex_entry}|{method_class}|{method_name}|{method_descriptor}|{create_index}|{rfcomm_api}"
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def add_node(label: str, ntype: str, value: str, evidence_level: str, classification: str = "FACT") -> str:
        nid = _node_id(path_key, label)
        nodes.append(
            {
                "id": nid,
                "type": ntype,
                "value": value,
                "evidence_level": evidence_level,
                "classification": classification,
            }
        )
        return nid

    n_device = add_node("device", "class", "android.bluetooth.BluetoothDevice", "dex_reference")
    n_rfcomm = add_node("rfcomm", "method", rfcomm_api, "dex_reference")
    edges.append(
        {
            "from": n_device,
            "to": n_rfcomm,
            "relationship": "method_call",
            "classification": "FACT",
            "confidence": "high",
        }
    )

    uuid_val = uuid_resolution.get("uuid")
    if uuid_val:
        n_uuid = add_node("uuid", "uuid", uuid_val, "instruction_context", "FACT")
        rel = "field_reference" if uuid_resolution.get("source_type") == "uuid_static_field" else "register_flow"
        edges.append(
            {
                "from": n_rfcomm,
                "to": n_uuid,
                "relationship": rel,
                "classification": "FACT",
                "confidence": uuid_resolution.get("confidence") or "medium",
            }
        )
    else:
        n_uuid = add_node("uuid", "uuid", "UNRESOLVED", "unknown", "UNKNOWN")
        edges.append(
            {
                "from": n_rfcomm,
                "to": n_uuid,
                "relationship": "register_flow",
                "classification": "UNKNOWN",
                "confidence": "unknown",
            }
        )

    n_socket = add_node("socket", "class", "android.bluetooth.BluetoothSocket", "dex_reference")
    edges.append(
        {
            "from": n_rfcomm,
            "to": n_socket,
            "relationship": "return_flow",
            "classification": "FACT",
            "confidence": "high",
        }
    )

    summary_parts = ["BluetoothDevice", rfcomm_api]
    if uuid_val:
        summary_parts.append(f"UUID={uuid_val}")
    else:
        summary_parts.append("UUID=UNKNOWN")
    summary_parts.append("BluetoothSocket")

    if socket_path.get("has_connect"):
        n_connect = add_node("connect", "method", "BluetoothSocket.connect", "dex_reference")
        edges.append(
            {
                "from": n_socket,
                "to": n_connect,
                "relationship": "same_method",
                "classification": "FACT",
                "confidence": "high",
            }
        )
        summary_parts.append("connect")
    if socket_path.get("has_input_stream"):
        n_in = add_node("input", "method", "getInputStream", "dex_reference")
        edges.append(
            {
                "from": n_socket,
                "to": n_in,
                "relationship": "same_method",
                "classification": "FACT",
                "confidence": "high",
            }
        )
        summary_parts.append("getInputStream")
    if socket_path.get("has_output_stream"):
        n_out = add_node("output", "method", "getOutputStream", "dex_reference")
        edges.append(
            {
                "from": n_socket,
                "to": n_out,
                "relationship": "same_method",
                "classification": "FACT",
                "confidence": "high",
            }
        )
        summary_parts.append("getOutputStream")

    # Path-level classification
    if uuid_val and socket_path.get("has_connect") and (
        socket_path.get("has_input_stream") or socket_path.get("has_output_stream")
    ):
        confidence = "medium"
    elif uuid_val or socket_path.get("has_connect"):
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "path_id": _path_id(path_key),
        "display_id": "",
        "dex_entry": dex_entry,
        "class_name": method_class,
        "class_name_normalized": method_class_normalized,
        "method_name": method_name,
        "method_descriptor": method_descriptor,
        "rfcomm_api": rfcomm_api,
        "create_index": create_index,
        "uuid_resolution": uuid_resolution,
        "device_source": device_source,
        "socket_path": {
            "has_connect": socket_path.get("has_connect"),
            "has_input_stream": socket_path.get("has_input_stream"),
            "has_output_stream": socket_path.get("has_output_stream"),
            "connect": socket_path.get("connect"),
            "getInputStream": socket_path.get("getInputStream"),
            "getOutputStream": socket_path.get("getOutputStream"),
        },
        "io_path": {
            "read_calls": io_path.get("read_calls"),
            "write_calls": io_path.get("write_calls"),
            "buffer_refs": io_path.get("buffer_refs"),
        },
        "profile_correlations": profile_correlations,
        "nodes": nodes,
        "edges": edges,
        "summary": " -> ".join(summary_parts),
        "classification": "INFERENCE",
        "confidence": confidence,
        "evidence_level": "candidate_chain",
        "runtime_execution_proven": False,
        "wire_correlation_available": False,
        "shared_uuid": False,
        "notes": [
            "Static candidate path only; runtime execution not established.",
            "Analyzer does not infer RFCOMM channel numbers such as SCN6.",
            "Profile matches are correlations and do not constitute protocol proof.",
        ],
        "limitations": list(uuid_resolution.get("limitations") or [])
        + list(device_source.get("notes") or []),
    }
