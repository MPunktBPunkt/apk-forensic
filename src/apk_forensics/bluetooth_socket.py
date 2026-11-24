"""Socket connect and stream I/O context around RFCOMM creates."""

from __future__ import annotations

from typing import Any

from apk_forensics.dex_model_adapter import MethodInfo


def find_same_method_apis(
    method: MethodInfo,
    *,
    around_index: int,
    window: int,
) -> dict[str, list[dict[str, Any]]]:
    start = max(0, around_index - window)
    end = min(len(method.instructions), around_index + window + 1)
    result: dict[str, list[dict[str, Any]]] = {
        "connect": [],
        "getInputStream": [],
        "getOutputStream": [],
        "read": [],
        "write": [],
        "buffers": [],
    }
    for idx in range(start, end):
        ins = method.instructions[idx]
        ref = ins.referenced_method or {}
        name = ref.get("method_name") or ""
        raw = ref.get("raw") or ""
        text = ins.text
        item = {"index": idx, "text": text, "raw": raw or None}
        if name == "connect" and "BluetoothSocket" in (raw + text):
            result["connect"].append(item)
        elif name == "getInputStream" and "BluetoothSocket" in (raw + text):
            result["getInputStream"].append(item)
        elif name == "getOutputStream" and "BluetoothSocket" in (raw + text):
            result["getOutputStream"].append(item)
        elif name == "read" and any(x in (raw + text) for x in ("InputStream", "BufferedInput", "DataInput")):
            result["read"].append(item)
        elif name == "write" and any(x in (raw + text) for x in ("OutputStream", "BufferedOutput", "DataOutput")):
            result["write"].append(item)
        elif any(
            x in text
            for x in (
                "ByteBuffer",
                "ByteArrayInputStream",
                "ByteArrayOutputStream",
                "BufferedInputStream",
                "BufferedOutputStream",
                "DataInputStream",
                "DataOutputStream",
            )
        ):
            result["buffers"].append(item)
    return result


def analyze_socket_path(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
) -> dict[str, Any]:
    apis = find_same_method_apis(method, around_index=create_index, window=window)
    has_connect = bool(apis["connect"])
    has_in = bool(apis["getInputStream"])
    has_out = bool(apis["getOutputStream"])
    return {
        "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
        "create_index": create_index,
        "has_connect": has_connect,
        "has_input_stream": has_in,
        "has_output_stream": has_out,
        "connect": apis["connect"],
        "getInputStream": apis["getInputStream"],
        "getOutputStream": apis["getOutputStream"],
        "classification": "FACT" if (has_connect or has_in or has_out) else "UNKNOWN",
        "confidence": "high" if has_connect and has_in and has_out else ("medium" if has_connect else "low"),
        "evidence_level": "instruction_context",
        "relationship": "same_method",
        "notes": [
            "Socket connect/stream APIs listed only when present in the same method window.",
            "Presence does not prove runtime execution.",
        ],
    }


def analyze_io_path(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
) -> dict[str, Any]:
    apis = find_same_method_apis(method, around_index=create_index, window=window)
    return {
        "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
        "create_index": create_index,
        "getInputStream": apis["getInputStream"],
        "getOutputStream": apis["getOutputStream"],
        "read_calls": apis["read"],
        "write_calls": apis["write"],
        "buffer_refs": apis["buffers"],
        "classification": "FACT" if (apis["getInputStream"] or apis["getOutputStream"]) else "UNKNOWN",
        "confidence": "medium",
        "evidence_level": "instruction_context",
        "notes": [
            "I/O helpers are contextual only; no protocol payload reconstruction is performed.",
        ],
    }
