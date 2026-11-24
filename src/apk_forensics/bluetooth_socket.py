"""Socket connect/stream tracking and bounded InputStream/OutputStream I/O analysis."""

from __future__ import annotations

import re
from typing import Any

from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo


PARSER_NAME_RE = re.compile(
    r"(?i)\b(parse|decode|deserialize|readFrame|readMessage|decodeMessage|"
    r"handleMessage|onMessage|dispatch|process|consume)\w*\b"
)
ENCODER_NAME_RE = re.compile(
    r"(?i)\b(encode|serialize|writeFrame|writeMessage|encodeMessage|"
    r"buildMessage|produce|send)\w*\b"
)


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
        item = {"index": idx, "text": text, "raw": raw or None, "offset": ins.offset}
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


def _result_reg_after(method: MethodInfo, invoke_index: int) -> str | None:
    """Return destination register of move-result* immediately after an invoke, if any."""
    nxt = invoke_index + 1
    if nxt >= len(method.instructions):
        return None
    ins = method.instructions[nxt]
    if not ins.opcode.startswith("move-result"):
        return None
    if ins.registers:
        return ins.registers[0]
    m = re.search(r"\bv\d+\b", ins.text)
    return m.group(0) if m else None


def _invoke_receiver(ins: InstructionInfo) -> str | None:
    if ins.registers:
        return ins.registers[0]
    m = re.search(r"\bv\d+\b", ins.text)
    return m.group(0) if m else None


def track_socket_object(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
) -> dict[str, Any]:
    """Register-aware create → connect / getInputStream / getOutputStream tracking."""
    end = min(len(method.instructions), create_index + window + 1)
    socket_reg = _result_reg_after(method, create_index)
    linked_connect: list[dict[str, Any]] = []
    linked_in: list[dict[str, Any]] = []
    linked_out: list[dict[str, Any]] = []
    input_reg: str | None = None
    output_reg: str | None = None
    window_apis = find_same_method_apis(method, around_index=create_index, window=window)

    if socket_reg:
        for idx in range(create_index + 1, end):
            ins = method.instructions[idx]
            if not ins.opcode.startswith("invoke"):
                # Track simple moves of the socket register.
                if ins.opcode.startswith("move-object") and len(ins.registers) >= 2:
                    if ins.registers[1] == socket_reg:
                        socket_reg = ins.registers[0]
                continue
            ref = ins.referenced_method or {}
            name = ref.get("method_name") or ""
            raw = (ref.get("raw") or "") + ins.text
            recv = _invoke_receiver(ins)
            item = {
                "index": idx,
                "text": ins.text,
                "raw": ref.get("raw"),
                "offset": ins.offset,
                "receiver_register": recv,
                "socket_register": socket_reg,
            }
            if recv != socket_reg:
                continue
            if name == "connect" and "BluetoothSocket" in raw:
                linked_connect.append(item)
            elif name == "getInputStream" and "BluetoothSocket" in raw:
                linked_in.append(item)
                input_reg = _result_reg_after(method, idx) or input_reg
            elif name == "getOutputStream" and "BluetoothSocket" in raw:
                linked_out.append(item)
                output_reg = _result_reg_after(method, idx) or output_reg

    register_linked = bool(socket_reg and (linked_connect or linked_in or linked_out))
    # Fall back to window co-occurrence for presence flags (never upgrade classification).
    has_connect = bool(linked_connect) or bool(window_apis["connect"])
    has_in = bool(linked_in) or bool(window_apis["getInputStream"])
    has_out = bool(linked_out) or bool(window_apis["getOutputStream"])

    if register_linked:
        classification = "FACT"
        confidence = "high" if linked_connect and (linked_in or linked_out) else "medium"
        relationship = "register_flow"
    elif has_connect or has_in or has_out:
        classification = "INFERENCE"
        confidence = "medium" if has_connect else "low"
        relationship = "same_method_window"
    else:
        classification = "UNKNOWN"
        confidence = "low"
        relationship = "none"

    return {
        "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
        "create_index": create_index,
        "socket_register": socket_reg,
        "input_register": input_reg,
        "output_register": output_reg,
        "has_connect": has_connect,
        "has_input_stream": has_in,
        "has_output_stream": has_out,
        "connect": linked_connect or window_apis["connect"],
        "getInputStream": linked_in or window_apis["getInputStream"],
        "getOutputStream": linked_out or window_apis["getOutputStream"],
        "register_linked": register_linked,
        "classification": classification,
        "confidence": confidence,
        "evidence_level": "instruction_context",
        "relationship": relationship,
        "notes": [
            "Socket connect/stream APIs listed only when present in the same method window.",
            "Presence does not prove runtime execution.",
            "FACT requires register-linked socket object tracking; window co-occurrence alone is INFERENCE.",
        ],
    }


def analyze_socket_path(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
) -> dict[str, Any]:
    return track_socket_object(method, create_index, window=window)


def _stream_io_calls(
    method: MethodInfo,
    *,
    start_index: int,
    window: int,
    stream_reg: str | None,
    op_names: set[str],
    type_tokens: tuple[str, ...],
) -> list[dict[str, Any]]:
    end = min(len(method.instructions), start_index + window + 1)
    out: list[dict[str, Any]] = []
    active_reg = stream_reg
    for idx in range(start_index, end):
        ins = method.instructions[idx]
        if active_reg and ins.opcode.startswith("move-object") and len(ins.registers) >= 2:
            if ins.registers[1] == active_reg:
                active_reg = ins.registers[0]
            continue
        if not ins.opcode.startswith("invoke"):
            continue
        ref = ins.referenced_method or {}
        name = ref.get("method_name") or ""
        raw = (ref.get("raw") or "") + ins.text
        if name not in op_names:
            continue
        if not any(tok in raw for tok in type_tokens):
            continue
        recv = _invoke_receiver(ins)
        linked = bool(active_reg and recv == active_reg)
        # Without a stream register, same-method window hits are INFERENCE only.
        classification = "FACT" if linked else "INFERENCE"
        out.append(
            {
                "index": idx,
                "text": ins.text,
                "raw": ref.get("raw"),
                "offset": ins.offset,
                "receiver_register": recv,
                "stream_register": active_reg,
                "register_linked": linked,
                "classification": classification,
                "confidence": "high" if linked else "medium",
                "evidence_level": "instruction_context",
                "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
                "dex_entry": method.dex_entry,
                "class_name": method.class_name,
                "method_name": method.method_name,
                "method_descriptor": method.method_descriptor,
            }
        )
    return out


def _name_candidates_after(
    method: MethodInfo,
    *,
    after_index: int,
    window: int,
    pattern: re.Pattern[str],
    role: str,
) -> list[dict[str, Any]]:
    end = min(len(method.instructions), after_index + window + 1)
    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx in range(after_index, end):
        ins = method.instructions[idx]
        ref = ins.referenced_method or {}
        raw = ref.get("raw") or ""
        name = ref.get("method_name") or ""
        blob = f"{name} {raw} {ins.text}"
        m = pattern.search(blob)
        if not m:
            continue
        key = raw or f"{name}@{idx}"
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            {
                "kind": "METHOD_NAME_CANDIDATE",
                "role": role,
                "matched_name": m.group(0),
                "method_ref": raw or None,
                "method_name": name or None,
                "index": idx,
                "offset": ins.offset,
                "text": ins.text,
                "classification": "INFERENCE",
                "confidence": "low",
                "evidence_level": "name_heuristic",
                "notes": [
                    "Name similarity alone is not protocol proof.",
                    "METHOD_NAME_CANDIDATE must not be treated as FACT.",
                ],
            }
        )
    return hits


def analyze_stream_consumers(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
    socket_tracking: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bounded InputStream consumer reconstruction after getInputStream()."""
    tracking = socket_tracking or track_socket_object(method, create_index, window=window)
    get_in = tracking.get("getInputStream") or []
    start = get_in[0]["index"] if get_in else create_index
    input_reg = tracking.get("input_register")
    reads = _stream_io_calls(
        method,
        start_index=start,
        window=window,
        stream_reg=input_reg,
        op_names={"read", "available"},
        type_tokens=("InputStream", "BufferedInput", "DataInput", "Reader"),
    )
    wrappers = []
    apis = find_same_method_apis(method, around_index=create_index, window=window)
    for buf in apis["buffers"]:
        if any(x in (buf.get("text") or "") for x in ("BufferedInput", "DataInput", "InputStreamReader", "ByteArrayInput")):
            wrappers.append({**buf, "classification": "INFERENCE", "confidence": "low"})

    parsers = _name_candidates_after(
        method, after_index=start, window=window, pattern=PARSER_NAME_RE, role="input_consumer"
    )

    if any(r.get("register_linked") for r in reads):
        classification = "FACT"
        confidence = "high"
        consumer: str | dict[str, Any] = reads[0]
    elif reads:
        classification = "INFERENCE"
        confidence = "medium"
        consumer = reads[0]
    else:
        classification = "UNKNOWN"
        confidence = "low"
        consumer = "UNKNOWN"

    return {
        "method": tracking.get("method"),
        "getInputStream": get_in,
        "input_register": input_reg,
        "read_calls": reads,
        "wrappers": wrappers,
        "parser_candidates": parsers,
        "consumer": consumer if consumer != "UNKNOWN" else None,
        "consumer_status": "UNKNOWN" if consumer == "UNKNOWN" else classification,
        "classification": classification,
        "confidence": confidence,
        "notes": [
            "I/O helpers are contextual only; no protocol payload reconstruction is performed.",
            "Missing read consumer is UNKNOWN, not REJECTED.",
        ],
    }


def analyze_stream_producers(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
    socket_tracking: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bounded OutputStream producer reconstruction after getOutputStream()."""
    tracking = socket_tracking or track_socket_object(method, create_index, window=window)
    get_out = tracking.get("getOutputStream") or []
    start = get_out[0]["index"] if get_out else create_index
    output_reg = tracking.get("output_register")
    writes = _stream_io_calls(
        method,
        start_index=start,
        window=window,
        stream_reg=output_reg,
        op_names={"write", "flush", "print", "println"},
        type_tokens=("OutputStream", "BufferedOutput", "DataOutput", "PrintWriter", "Writer"),
    )
    wrappers = []
    apis = find_same_method_apis(method, around_index=create_index, window=window)
    for buf in apis["buffers"]:
        if any(x in (buf.get("text") or "") for x in ("BufferedOutput", "DataOutput", "PrintWriter", "ByteArrayOutput")):
            wrappers.append({**buf, "classification": "INFERENCE", "confidence": "low"})

    encoders = _name_candidates_after(
        method, after_index=start, window=window, pattern=ENCODER_NAME_RE, role="output_producer"
    )

    if any(w.get("register_linked") for w in writes):
        classification = "FACT"
        confidence = "high"
        producer: str | dict[str, Any] = writes[0]
    elif writes:
        classification = "INFERENCE"
        confidence = "medium"
        producer = writes[0]
    else:
        classification = "UNKNOWN"
        confidence = "low"
        producer = "UNKNOWN"

    return {
        "method": tracking.get("method"),
        "getOutputStream": get_out,
        "output_register": output_reg,
        "write_calls": writes,
        "wrappers": wrappers,
        "encoder_candidates": encoders,
        "producer": producer if producer != "UNKNOWN" else None,
        "producer_status": "UNKNOWN" if producer == "UNKNOWN" else classification,
        "classification": classification,
        "confidence": confidence,
        "notes": [
            "I/O helpers are contextual only; no protocol payload reconstruction is performed.",
            "Missing write producer is UNKNOWN, not REJECTED.",
            "byte[]/Buffer presence is not proof of a vehicle application protocol.",
        ],
    }


def analyze_io_path(
    method: MethodInfo,
    create_index: int,
    *,
    window: int,
    socket_tracking: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tracking = socket_tracking or track_socket_object(method, create_index, window=window)
    consumers = analyze_stream_consumers(
        method, create_index, window=window, socket_tracking=tracking
    )
    producers = analyze_stream_producers(
        method, create_index, window=window, socket_tracking=tracking
    )
    apis = find_same_method_apis(method, around_index=create_index, window=window)
    has_streams = bool(tracking.get("has_input_stream") or tracking.get("has_output_stream"))
    return {
        "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
        "create_index": create_index,
        "getInputStream": tracking.get("getInputStream") or [],
        "getOutputStream": tracking.get("getOutputStream") or [],
        "read_calls": consumers.get("read_calls") or apis["read"],
        "write_calls": producers.get("write_calls") or apis["write"],
        "buffer_refs": apis["buffers"],
        "input_consumers": consumers,
        "output_producers": producers,
        "classification": "FACT"
        if tracking.get("register_linked") and has_streams
        else ("INFERENCE" if has_streams else "UNKNOWN"),
        "confidence": tracking.get("confidence") or "medium",
        "evidence_level": "instruction_context",
        "notes": [
            "I/O helpers are contextual only; no protocol payload reconstruction is performed.",
        ],
    }
