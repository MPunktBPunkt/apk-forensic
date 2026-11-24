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

    link_cls = "FACT" if socket_path.get("register_linked") else "INFERENCE"
    link_conf = "high" if socket_path.get("register_linked") else "medium"
    n_in = None
    n_out = None
    if socket_path.get("has_connect"):
        n_connect = add_node("connect", "method", "BluetoothSocket.connect", "dex_reference")
        edges.append(
            {
                "from": n_socket,
                "to": n_connect,
                "relationship": "same_method",
                "classification": link_cls,
                "confidence": link_conf,
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
                "classification": link_cls,
                "confidence": link_conf,
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
                "classification": link_cls,
                "confidence": link_conf,
            }
        )
        summary_parts.append("getOutputStream")

    read_calls = list(io_path.get("read_calls") or [])
    write_calls = list(io_path.get("write_calls") or [])
    if read_calls:
        n_read = add_node("read", "method", "InputStream.read", "instruction_context", "INFERENCE")
        edges.append(
            {
                "from": n_in or n_socket,
                "to": n_read,
                "relationship": "same_method",
                "classification": read_calls[0].get("classification") or "INFERENCE",
                "confidence": read_calls[0].get("confidence") or "medium",
            }
        )
        summary_parts.append("read")
    if write_calls:
        n_write = add_node("write", "method", "OutputStream.write", "instruction_context", "INFERENCE")
        edges.append(
            {
                "from": n_out or n_socket,
                "to": n_write,
                "relationship": "same_method",
                "classification": write_calls[0].get("classification") or "INFERENCE",
                "confidence": write_calls[0].get("confidence") or "medium",
            }
        )
        summary_parts.append("write")

    # Path-level classification — end-to-end remains INFERENCE (no runtime/wire proof).
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
            "register_linked": socket_path.get("register_linked"),
            "classification": socket_path.get("classification"),
            "confidence": socket_path.get("confidence"),
        },
        "io_path": {
            "read_calls": io_path.get("read_calls"),
            "write_calls": io_path.get("write_calls"),
            "buffer_refs": io_path.get("buffer_refs"),
            "input_consumers": io_path.get("input_consumers"),
            "output_producers": io_path.get("output_producers"),
        },
        "caller_reconstruction": None,
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


def _dataflow_id(*parts: str) -> str:
    return "btdata-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


def build_dataflow_path(
    *,
    target_method: str,
    path_id: str | None,
    socket_creation: dict[str, Any],
    connect: dict[str, Any] | None,
    input_info: dict[str, Any] | None,
    output_info: dict[str, Any] | None,
    read_chain: list[dict[str, Any]],
    write_chain: list[dict[str, Any]],
    caller_reconstruction: dict[str, Any] | None,
    max_nodes: int,
) -> dict[str, Any]:
    """Build a BluetoothDataflowPath evidence object (BTDATA-*)."""
    nodes: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    def add(node: dict[str, Any]) -> None:
        key = f"{node.get('type')}|{node.get('value')}|{node.get('classification')}"
        if key in seen_keys or len(nodes) >= max_nodes:
            return
        seen_keys.add(key)
        nodes.append(node)

    add(
        {
            "type": "method",
            "value": target_method,
            "role": "target",
            "classification": "FACT",
            "confidence": "high",
        }
    )
    add(
        {
            "type": "api",
            "value": socket_creation.get("method") or "createRfcommSocketToServiceRecord",
            "role": "socket_creation",
            "classification": socket_creation.get("classification") or "FACT",
            "confidence": socket_creation.get("confidence") or "high",
        }
    )
    if connect:
        add(
            {
                "type": "api",
                "value": connect.get("method") or "BluetoothSocket.connect",
                "role": "connect",
                "classification": connect.get("classification") or "FACT",
                "confidence": connect.get("confidence") or "high",
            }
        )
    if input_info:
        add(
            {
                "type": "api",
                "value": input_info.get("method") or "BluetoothSocket.getInputStream",
                "role": "input",
                "classification": input_info.get("classification") or "FACT",
                "confidence": input_info.get("confidence") or "high",
            }
        )
    if output_info:
        add(
            {
                "type": "api",
                "value": output_info.get("method") or "BluetoothSocket.getOutputStream",
                "role": "output",
                "classification": output_info.get("classification") or "FACT",
                "confidence": output_info.get("confidence") or "high",
            }
        )
    for step in read_chain:
        add(
            {
                "type": "io",
                "value": step.get("text") or "InputStream.read",
                "role": "read",
                "classification": step.get("classification") or "UNKNOWN",
                "confidence": step.get("confidence") or "low",
            }
        )
    for step in write_chain:
        add(
            {
                "type": "io",
                "value": step.get("text") or "OutputStream.write",
                "role": "write",
                "classification": step.get("classification") or "UNKNOWN",
                "confidence": step.get("confidence") or "low",
            }
        )

    stages_present = sum(
        1
        for x in (True, bool(connect), bool(input_info), bool(output_info), bool(read_chain), bool(write_chain))
        if x
    )
    if stages_present >= 4 and (read_chain or write_chain):
        structure = "PARTIAL"
        confidence = "medium"
    elif stages_present >= 3:
        structure = "PARTIAL"
        confidence = "medium"
    else:
        structure = "PARTIAL"
        confidence = "low"

    return {
        "id": _dataflow_id(target_method, path_id or "", str(len(nodes))),
        "display_id": "",
        "target": target_method,
        "path_id": path_id,
        "socket_creation": {
            "method": socket_creation.get("method") or "createRfcommSocketToServiceRecord",
            "classification": socket_creation.get("classification") or "FACT",
            "confidence": socket_creation.get("confidence") or "high",
            "evidence_level": socket_creation.get("evidence_level") or "dex_reference",
        },
        "connect": connect,
        "input": input_info,
        "output": output_info,
        "read_chain": read_chain,
        "write_chain": write_chain,
        "caller_reconstruction": caller_reconstruction,
        "nodes": nodes,
        "node_count": len(nodes),
        "classification": "INFERENCE",
        "structure": structure,
        "confidence": confidence,
        "runtime_execution_proven": False,
        "wire_correlation_available": False,
        "notes": [
            "BluetoothDataflowPath is a bounded static reconstruction, not runtime proof.",
            "PARTIAL describes structural completeness; evidence classes remain FACT/INFERENCE/UNKNOWN.",
            "Protocol names (BCL/Etch/SCN6) are never inferred from stream I/O alone.",
        ],
        "limitations": [
            "Bounded dataflow only; no full SSA or global data-flow graph.",
            "Missing read/write consumers are UNKNOWN, not REJECTED.",
        ],
    }
