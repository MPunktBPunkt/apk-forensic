"""v1.3 Transport-to-Byte Evidence Closure.

Offline analysis of persisted transport + communication reports.
Classifies each PATH-* through stages T0–T6 with FACT/CORRELATION/INFERENCE/UNKNOWN
edges. Does not raise analysis limits or invent protocol semantics.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CLOSURE_STAGES = (
    "T0_SOCKET",
    "T1_STREAM",
    "T2_IO",
    "T3_BUFFER",
    "T4_CONSUMER_PRODUCER",
    "T5_DECODER_ENCODER",
    "T6_COMMUNICATION",
)

TERMINATION_TAXONOMY = {
    "A_TRUE_GRAPH_END": "Dataflow ends in analyzed code with no further static continuation.",
    "B_RETURN_BOUNDARY": "Relevant value leaves via return.",
    "C_PARAMETER_BOUNDARY": "Value passed as parameter; next consumer outside this path.",
    "D_WRAPPER_BOUNDARY": "Wrapper abstracts further transport/buffer access.",
    "E_OBJECT_IDENTITY_BOUNDARY": "Object identity cannot be followed safely.",
    "F_BUFFER_IDENTITY_BOUNDARY": "Socket/stream known; concrete buffer/array identity lost.",
    "G_METHOD_CALL_GRAPH_BOUNDARY": "Call/method outside allowed analysis bounds.",
    "H_CYCLE_GUARD": "Stopped on a real object/field cycle.",
    "I_AMBIGUOUS_ALIAS": "Multiple objects cannot be distinguished statically.",
    "J_UNKNOWN_UNRESOLVED": "Evidence insufficient for a reliable assignment.",
}

CASE_CLASSES = {
    "CASE_A_CLOSED": "Socket→Stream→I/O→Buffer→Consumer/Producer statically closed.",
    "CASE_B_TRANSPORT_CLOSED_BUFFER_OPEN": "Socket/Stream/I/O closed; buffer identity open.",
    "CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN": "Byte/buffer flow closed; meaning/decoder semantics UNKNOWN.",
    "CASE_D_IDENTITY_BOUND": "Flow exists but object/buffer identity cannot continue safely.",
    "CASE_E_GRAPH_BOUND": "Analysis bound prevents further tracking.",
    "CASE_F_TRUE_END": "Dataflow truly ends in statically analyzed code.",
    "CASE_G_UNKNOWN": "Evidence insufficient for a reliable classification.",
}

# Map persisted boundary reasons → termination taxonomy (evidence-based, not limit inflation).
_REASON_MAP = {
    "return_no_move_result": "B_RETURN_BOUNDARY",
    "return_boundary": "B_RETURN_BOUNDARY",
    "unresolved_parameter": "C_PARAMETER_BOUNDARY",
    "parameter_boundary": "C_PARAMETER_BOUNDARY",
    "wrapper": "D_WRAPPER_BOUNDARY",
    "wrapper_boundary": "D_WRAPPER_BOUNDARY",
    "unknown_alias": "E_OBJECT_IDENTITY_BOUNDARY",
    "register_overwrite": "E_OBJECT_IDENTITY_BOUNDARY",
    "object_identity": "E_OBJECT_IDENTITY_BOUNDARY",
    "buffer_identity": "F_BUFFER_IDENTITY_BOUNDARY",
    "max_method_hops": "G_METHOD_CALL_GRAPH_BOUNDARY",
    "max_callers": "G_METHOD_CALL_GRAPH_BOUNDARY",
    "max_callees": "G_METHOD_CALL_GRAPH_BOUNDARY",
    "method_retention_cap": "G_METHOD_CALL_GRAPH_BOUNDARY",
    "cycle": "H_CYCLE_GUARD",
    "cycle_detected": "H_CYCLE_GUARD",
    "cycle_guard": "H_CYCLE_GUARD",
    "ambiguous_alias": "I_AMBIGUOUS_ALIAS",
    "unsupported_pattern": "J_UNKNOWN_UNRESOLVED",
    "field_no_loaders": "J_UNKNOWN_UNRESOLVED",
    "unresolved": "J_UNKNOWN_UNRESOLVED",
    # After v1.2, max_field_hops on a frozen baseline may be legacy hop-accounting noise.
    # Prefer classifying from path content; keep as graph bound only when it is the sole stop.
    "max_field_hops": "E_OBJECT_IDENTITY_BOUNDARY",
    "max_object_nodes": "G_METHOD_CALL_GRAPH_BOUNDARY",
}


def _step_types(path: dict[str, Any]) -> list[str]:
    return [str(s.get("node_type") or "") for s in (path.get("steps") or [])]


def _step_labels(path: dict[str, Any]) -> list[str]:
    return [str(s.get("label") or "") for s in (path.get("steps") or [])]


def _has_io(types: list[str], labels: list[str]) -> dict[str, bool]:
    joined = " ".join(labels)
    return {
        "read": "READ" in types or "->read(" in joined or ";->read(" in joined,
        "write": "WRITE" in types or "->write(" in joined or ";->write(" in joined,
        "flush": "FLUSH" in types or "->flush(" in joined or ";->flush(" in joined,
    }


def _buffer_arg_in_raw(raw: str | None) -> bool:
    if not raw:
        return False
    return "[B" in raw or "ByteBuffer" in raw


def _index_dataflow(bt: dict[str, Any]) -> dict[str, Any]:
    """Index read/write buffer evidence from dataflow paths."""
    by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    buffer_ops: list[dict[str, Any]] = []
    for df in bt.get("dataflow_paths") or []:
        for chain_name in ("input_read_chain", "read_chain", "output_write_chain", "write_chain"):
            for item in df.get(chain_name) or []:
                raw = str(item.get("raw") or "")
                entry = {
                    "display_id": df.get("display_id") or df.get("id"),
                    "chain": chain_name,
                    "method": item.get("method"),
                    "object_id": item.get("object_id"),
                    "raw": raw,
                    "text": item.get("text"),
                    "buffer_arg_present": item.get("buffer_arg_present")
                    if "buffer_arg_present" in item
                    else _buffer_arg_in_raw(raw),
                    "buffer_register": item.get("buffer_register"),
                    "buffer_identity": item.get("buffer_identity"),
                    "classification": item.get("classification") or "FACT",
                }
                if entry["buffer_arg_present"] and not entry.get("buffer_identity"):
                    entry["buffer_identity"] = (
                        "REGISTER" if entry.get("buffer_register") else "SIGNATURE_ONLY"
                    )
                if item.get("object_id"):
                    by_object[str(item["object_id"])].append(entry)
                if item.get("method"):
                    by_method[str(item["method"])].append(entry)
                if entry["buffer_arg_present"]:
                    buffer_ops.append(entry)
        for t in df.get("transfers") or []:
            if t.get("kind") in {"read_into_buffer", "write_from_buffer"}:
                buffer_ops.append(
                    {
                        "display_id": df.get("display_id") or df.get("id"),
                        "chain": "transfer",
                        "method": t.get("method"),
                        "object_id": t.get("object_id"),
                        "raw": t.get("raw"),
                        "buffer_arg_present": True,
                        "buffer_register": t.get("buffer_register"),
                        "buffer_identity": t.get("buffer_identity") or "REGISTER",
                        "classification": t.get("classification") or "FACT",
                    }
                )
    return {"by_object": by_object, "by_method": by_method, "buffer_ops": buffer_ops}


def _index_communication(ce: dict[str, Any]) -> dict[str, Any]:
    paths = list(ce.get("paths") or [])
    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for p in paths:
        sm = p.get("source_method")
        if sm:
            by_method[str(sm)].append(p)
    counts = ce.get("counts") or {}
    return {
        "paths": paths,
        "by_method": by_method,
        "counts": counts,
        "decoder_candidates": int(counts.get("decoder_candidates") or 0),
        "serializer_candidates": int(counts.get("serializer_candidates") or 0),
        "primitive_decoding": int(counts.get("primitive_decoding") or 0),
        "buffer_operations": int(counts.get("buffer_operations") or 0),
        "byte_processing": int(counts.get("byte_processing") or 0),
        "state_mutations": int(counts.get("state_mutations") or 0),
        "protocol": "UNKNOWN",  # hard rule unless explicitly proven elsewhere
    }


def _map_termination(bounds: list[Any], *, reached: dict[str, bool], stages_open: list[str]) -> dict[str, Any]:
    reasons = []
    for b in bounds:
        if isinstance(b, dict):
            reasons.append(b.get("raw_reason") or b.get("reason"))
        else:
            reasons.append(str(b))
    mapped = []
    for r in reasons:
        if not r:
            continue
        key = str(r).lower()
        mapped.append(_REASON_MAP.get(key, "J_UNKNOWN_UNRESOLVED"))

    # Prefer content-based classification when stages stop short of buffer/consumer.
    primary: str
    if not bounds and reached.get("T2_IO") and not reached.get("T3_BUFFER"):
        primary = "F_BUFFER_IDENTITY_BOUNDARY"
    elif not bounds and reached.get("T0_SOCKET") and not reached.get("T1_STREAM"):
        primary = "A_TRUE_GRAPH_END"
    elif not bounds and reached.get("T1_STREAM") and not reached.get("T2_IO"):
        primary = "A_TRUE_GRAPH_END"
    elif "H_CYCLE_GUARD" in mapped:
        primary = "H_CYCLE_GUARD"
    elif "E_OBJECT_IDENTITY_BOUNDARY" in mapped and not reached.get("T2_IO"):
        primary = "E_OBJECT_IDENTITY_BOUNDARY"
    elif reached.get("T3_BUFFER") and not reached.get("T5_DECODER_ENCODER"):
        # Buffer closed; remaining gap is semantics / decoder — not a limit.
        primary = "A_TRUE_GRAPH_END" if not stages_open else "F_BUFFER_IDENTITY_BOUNDARY"
        if reached.get("T3_BUFFER") and not reached.get("T4_CONSUMER_PRODUCER"):
            primary = "F_BUFFER_IDENTITY_BOUNDARY"
        elif reached.get("T4_CONSUMER_PRODUCER"):
            primary = "A_TRUE_GRAPH_END"
    elif "G_METHOD_CALL_GRAPH_BOUNDARY" in mapped and not any(
        m in mapped for m in ("E_OBJECT_IDENTITY_BOUNDARY", "H_CYCLE_GUARD")
    ):
        primary = "G_METHOD_CALL_GRAPH_BOUNDARY"
    elif mapped:
        # If only legacy max_field_hops but path already reached I/O, treat as true-end /
        # buffer-open rather than claiming hop limit blocked bytes.
        if set(mapped) <= {"E_OBJECT_IDENTITY_BOUNDARY"} and reached.get("T2_IO"):
            primary = (
                "F_BUFFER_IDENTITY_BOUNDARY"
                if not reached.get("T3_BUFFER")
                else "A_TRUE_GRAPH_END"
            )
        else:
            primary = mapped[0]
    else:
        primary = "A_TRUE_GRAPH_END" if reached.get("T0_SOCKET") else "J_UNKNOWN_UNRESOLVED"

    return {
        "primary": primary,
        "all": sorted(set(mapped)),
        "raw_reasons": sorted({str(r) for r in reasons if r}),
        "description": TERMINATION_TAXONOMY.get(primary, ""),
    }


def _case_class(reached: dict[str, bool], termination: str, edge_classes: dict[str, str]) -> str:
    t0 = reached.get("T0_SOCKET")
    t1 = reached.get("T1_STREAM")
    t2 = reached.get("T2_IO")
    t3 = reached.get("T3_BUFFER")
    t4 = reached.get("T4_CONSUMER_PRODUCER")
    t5 = reached.get("T5_DECODER_ENCODER")

    # Structural close requires FACT buffer + FACT/CORRELATION consumer.
    # Decoder candidate or PATH-COMM composition never upgrades protocol semantics.
    if t0 and t1 and t2 and t3 and t4 and edge_classes.get("T3_BUFFER") == "FACT" and not t5:
        if edge_classes.get("T4_CONSUMER_PRODUCER") == "FACT":
            return "CASE_A_CLOSED"
        # Consumer only via PATH-COMM composition → buffer closed, semantics still open
        return "CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN"

    if t0 and t1 and t2 and t3:
        return "CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN"

    if t0 and t1 and t2 and not t3:
        return "CASE_B_TRANSPORT_CLOSED_BUFFER_OPEN"

    if termination in {"E_OBJECT_IDENTITY_BOUNDARY", "I_AMBIGUOUS_ALIAS"}:
        return "CASE_D_IDENTITY_BOUND"

    if termination in {"G_METHOD_CALL_GRAPH_BOUNDARY"}:
        return "CASE_E_GRAPH_BOUND"

    if termination == "H_CYCLE_GUARD":
        return "CASE_D_IDENTITY_BOUND"

    if termination == "A_TRUE_GRAPH_END" and t0 and not t2:
        return "CASE_F_TRUE_END"

    if t0 and not t1:
        return "CASE_F_TRUE_END"

    return "CASE_G_UNKNOWN"


def analyze_path(
    path: dict[str, Any],
    *,
    dataflow_index: dict[str, Any],
    comm_index: dict[str, Any],
) -> dict[str, Any]:
    types = _step_types(path)
    labels = _step_labels(path)
    io = _has_io(types, labels)
    objects = path.get("objects") or {}
    # Only object IDs that appear on *this path's steps* are safe for identity linking.
    # The path-level `objects` bag is often shared across sibling PATH-* and must not
    # invent buffer closure for SOCKET-only paths.
    step_obj_ids = [
        str(s.get("object_id"))
        for s in (path.get("steps") or [])
        if s.get("object_id")
    ]
    link_obj_ids = sorted(set(step_obj_ids)) or []

    # --- Stage reachability ---
    edges: list[dict[str, Any]] = []
    reached: dict[str, bool] = {s: False for s in CLOSURE_STAGES}
    edge_class: dict[str, str] = {}

    # T0
    if "SOCKET" in types or any("createRfcomm" in lb for lb in labels):
        reached["T0_SOCKET"] = True
        edge_class["T0_SOCKET"] = "FACT"
        edges.append(
            {
                "from": None,
                "to": "T0_SOCKET",
                "classification": "FACT",
                "evidence": "SOCKET node / createRfcomm* in path steps",
            }
        )

    # T1
    stream_types = {"GET_INPUT_STREAM", "GET_OUTPUT_STREAM", "INPUT_STREAM", "OUTPUT_STREAM"}
    stream_fields = any(
        lb in {"mInputStream", "mOutputStream"} or "Stream" in lb for lb in labels
    )
    if stream_types & set(types) or stream_fields:
        reached["T1_STREAM"] = True
        edge_class["T1_STREAM"] = "FACT"
        edges.append(
            {
                "from": "T0_SOCKET",
                "to": "T1_STREAM",
                "classification": "FACT",
                "evidence": "getInputStream/getOutputStream or stream field on path",
            }
        )

    # T2
    if io["read"] or io["write"] or io["flush"]:
        reached["T2_IO"] = True
        edge_class["T2_IO"] = "FACT"
        edges.append(
            {
                "from": "T1_STREAM",
                "to": "T2_IO",
                "classification": "FACT",
                "evidence": f"I/O on path: read={io['read']} write={io['write']} flush={io['flush']}",
            }
        )

    # Buffer / PATH-COMM linkage only when this path reached stream or I/O.
    linked_buf: list[dict[str, Any]] = []
    linked_comm: list[dict[str, Any]] = []
    path_has_buf_sig = any(_buffer_arg_in_raw(lb) for lb in labels)

    if reached["T1_STREAM"] or reached["T2_IO"]:
        path_kind = str(path.get("kind") or "")
        allow_read_buf = io["read"] or "INPUT" in path_kind or "COMBINED" in path_kind
        allow_write_buf = io["write"] or "OUTPUT" in path_kind or "COMBINED" in path_kind
        # Flush-only OUTPUT paths do not inherit inbound read([B) evidence.
        if io["flush"] and not io["read"] and not io["write"] and "OUTPUT" in path_kind:
            allow_read_buf = False
            allow_write_buf = True

        def _dir_ok(entry: dict[str, Any]) -> bool:
            chain = str(entry.get("chain") or "")
            raw = str(entry.get("raw") or "")
            is_read = "read" in chain.lower() or "->read(" in raw or ";->read(" in raw
            is_write = "write" in chain.lower() or "->write(" in raw or ";->write(" in raw
            if is_read and not allow_read_buf:
                return False
            if is_write and not allow_write_buf:
                return False
            # Undirected transfer: keep if any direction allowed
            if not is_read and not is_write:
                return allow_read_buf or allow_write_buf
            return True

        cand: list[dict[str, Any]] = []
        for oid in link_obj_ids:
            cand.extend(dataflow_index["by_object"].get(oid, []))
        if not cand and isinstance(objects, dict):
            keys = []
            if allow_read_buf:
                keys.append("input")
            if allow_write_buf:
                keys.append("output")
            for key in keys:
                oid = objects.get(key)
                if oid:
                    cand.extend(dataflow_index["by_object"].get(str(oid), []))
        linked_buf = [e for e in cand if _dir_ok(e)]

        if path_has_buf_sig and reached["T2_IO"]:
            reached["T3_BUFFER"] = True
            edge_class["T3_BUFFER"] = "FACT"
            edges.append(
                {
                    "from": "T2_IO",
                    "to": "T3_BUFFER",
                    "classification": "FACT",
                    "evidence": "read/write signature with [B or ByteBuffer on path step",
                }
            )
        elif reached["T2_IO"] and any(e.get("buffer_arg_present") for e in linked_buf):
            reached["T3_BUFFER"] = True
            identities = {e.get("buffer_identity") for e in linked_buf if e.get("buffer_arg_present")}
            cls = "FACT" if ("REGISTER" in identities or "SIGNATURE_ONLY" in identities) else "CORRELATION"
            edge_class["T3_BUFFER"] = cls
            sample = next(e for e in linked_buf if e.get("buffer_arg_present"))
            edges.append(
                {
                    "from": "T2_IO",
                    "to": "T3_BUFFER",
                    "classification": cls,
                    "evidence": (
                        f"Object {sample.get('object_id')} used in {sample.get('raw')} "
                        f"(buffer_identity={sample.get('buffer_identity')})"
                    ),
                }
            )

        methods_from_buf = {e.get("method") for e in linked_buf if e.get("method")}
        for m in methods_from_buf:
            linked_comm.extend(comm_index["by_method"].get(str(m), []))
        # Direction filter on PATH-COMM
        filtered_comm = []
        for c in linked_comm:
            direction = str(c.get("direction") or "")
            kind_c = str(c.get("kind") or "")
            if direction == "INBOUND" or "INBOUND" in kind_c:
                if not allow_read_buf:
                    continue
            if direction == "OUTBOUND" or "OUTBOUND" in kind_c:
                if not allow_write_buf:
                    continue
            filtered_comm.append(c)
        seen_c: set[str] = set()
        uniq_comm = []
        for c in filtered_comm:
            cid = str(c.get("display_id") or c.get("path_id"))
            if cid in seen_c:
                continue
            seen_c.add(cid)
            uniq_comm.append(c)
        linked_comm = uniq_comm

        consumer_hit = False
        for cp in linked_comm:
            step_kinds = [s.get("kind") or s.get("node_type") for s in (cp.get("steps") or [])]
            if ("BYTE_ARRAY" in step_kinds or "BYTE_BUFFER" in step_kinds) and reached["T2_IO"]:
                if not reached["T3_BUFFER"]:
                    reached["T3_BUFFER"] = True
                    edge_class["T3_BUFFER"] = "CORRELATION"
                    edges.append(
                        {
                            "from": "T2_IO",
                            "to": "T3_BUFFER",
                            "classification": "CORRELATION",
                            "evidence": (
                                f"PATH-COMM {cp.get('display_id')} BYTE_ARRAY via {cp.get('source_method')}"
                            ),
                        }
                    )
            if cp.get("kind") in {"OUTBOUND_BUFFER_WRITE", "INBOUND_PRIMITIVE", "INBOUND_DECODE"}:
                consumer_hit = True
            if any(
                k in {"PRIMITIVE_DECODE", "OUTPUT_WRITE", "COPY", "WRAP", "DECODER", "ENCODER"}
                for k in step_kinds
            ):
                consumer_hit = True

        if consumer_hit and reached["T3_BUFFER"]:
            reached["T4_CONSUMER_PRODUCER"] = True
            edge_class["T4_CONSUMER_PRODUCER"] = "CORRELATION"
            edges.append(
                {
                    "from": "T3_BUFFER",
                    "to": "T4_CONSUMER_PRODUCER",
                    "classification": "CORRELATION",
                    "evidence": "PATH-COMM links buffer to write/primitive/copy consumer-producer",
                }
            )

    # T5 (v1.4): BYTE_PROCESSING on tracked buffer — not READ_LENGTH, not names alone.
    # Includes: aget-byte, ByteBuffer.get*, STRING_DECODE, DECODER with buffer dataflow.
    decoder_n = comm_index.get("decoder_candidates") or 0
    byte_proc_n = int(comm_index.get("counts", {}).get("byte_processing") or 0) if isinstance(comm_index.get("counts"), dict) else 0
    # also allow flat key from index
    if not byte_proc_n:
        byte_proc_n = int(comm_index.get("byte_processing") or 0)
    has_named_decoder_step = any(
        (s.get("kind") or s.get("node_type")) in {"DECODER", "ENCODER", "MESSAGE", "BYTE_PROCESSING"}
        for cp in linked_comm
        for s in (cp.get("steps") or [])
    )
    has_real_primitive = any(
        (s.get("kind") or s.get("node_type")) == "PRIMITIVE_DECODE"
        and "ByteBuffer" in str(s.get("label") or "")
        for cp in linked_comm
        for s in (cp.get("steps") or [])
    )
    has_byte_proc_step = any(
        (s.get("kind") or s.get("node_type")) in {"BYTE_PROCESSING", "STRING_DECODE"}
        for cp in linked_comm
        for s in (cp.get("steps") or [])
    )
    if reached.get("T3_BUFFER") and (
        has_named_decoder_step or has_byte_proc_step or has_real_primitive or (decoder_n > 0 and linked_comm) or (byte_proc_n > 0 and linked_comm)
    ):
        reached["T5_DECODER_ENCODER"] = True
        edge_class["T5_DECODER_ENCODER"] = "FACT" if (has_byte_proc_step or has_real_primitive) else "INFERENCE"
        edges.append(
            {
                "from": "T4_CONSUMER_PRODUCER",
                "to": "T5_DECODER_ENCODER",
                "classification": edge_class["T5_DECODER_ENCODER"],
                "evidence": (
                    "Byte/buffer processing (BYTE_PROCESSING / ByteBuffer.get* / decoder+buffer) — "
                    "not protocol proof"
                ),
            }
        )
    elif reached.get("T3_BUFFER"):
        edges.append(
            {
                "from": "T4_CONSUMER_PRODUCER",
                "to": "T5_DECODER_ENCODER",
                "classification": "UNKNOWN",
                "evidence": "No FACT byte-processing edge from tracked buffer on this path linkage",
                "reached": False,
            }
        )

    # T6: communication evidence path linked (only if this path reached I/O)
    if linked_comm and reached.get("T2_IO"):
        reached["T6_COMMUNICATION"] = True
        edge_class["T6_COMMUNICATION"] = "CORRELATION"
        edges.append(
            {
                "from": "T3_BUFFER" if reached.get("T3_BUFFER") else "T2_IO",
                "to": "T6_COMMUNICATION",
                "classification": "CORRELATION",
                "evidence": f"Linked PATH-COMM: {[c.get('display_id') for c in linked_comm]}",
            }
        )
        # Protocol remains UNKNOWN
        edges.append(
            {
                "from": "T6_COMMUNICATION",
                "to": "protocol_semantics",
                "classification": "UNKNOWN",
                "evidence": "Static APK evidence does not prove wire/protocol meaning",
            }
        )

    stages_open = [s for s, ok in reached.items() if not ok]
    termination = _map_termination(
        list(path.get("boundaries") or []),
        reached=reached,
        stages_open=stages_open,
    )
    # Refine: if we closed buffer via correlation but no further consumer identity
    if reached.get("T3_BUFFER") and not reached.get("T4_CONSUMER_PRODUCER"):
        if termination["primary"] == "A_TRUE_GRAPH_END":
            termination = {
                **termination,
                "primary": "F_BUFFER_IDENTITY_BOUNDARY",
                "description": TERMINATION_TAXONOMY["F_BUFFER_IDENTITY_BOUNDARY"],
            }

    case = _case_class(reached, termination["primary"], edge_class)

    # Inventory fields for Phase B table
    field_transfers = [
        s for s in (path.get("steps") or []) if s.get("node_type") in {"FIELD_WRITE", "FIELD_READ"}
    ]

    return {
        "path_id": path.get("display_id") or path.get("path_id"),
        "kind": path.get("kind"),
        "evidence_class": path.get("classification"),
        "start": labels[0] if labels else None,
        "end": labels[-1] if labels else None,
        "objects": objects if isinstance(objects, dict) else {"list": obj_ids},
        "steps": [
            {
                "node_type": s.get("node_type"),
                "label": s.get("label"),
                "object_id": s.get("object_id"),
                "classification": s.get("classification"),
            }
            for s in (path.get("steps") or [])
        ],
        "field_transfers": [
            {"type": s.get("node_type"), "label": s.get("label"), "object_id": s.get("object_id")}
            for s in field_transfers
        ],
        "io": io,
        "stages_reached": {k: bool(v) for k, v in reached.items()},
        "highest_stage": next(
            (s for s in reversed(CLOSURE_STAGES) if reached.get(s)),
            None,
        ),
        "edge_chain": edges,
        "edge_class_by_stage": edge_class,
        "linked_buffer_ops": [
            {
                "method": e.get("method"),
                "raw": e.get("raw"),
                "object_id": e.get("object_id"),
                "buffer_identity": e.get("buffer_identity"),
                "classification": e.get("classification"),
            }
            for e in linked_buf
            if e.get("buffer_arg_present")
        ][:12],
        "linked_path_comm": [
            {
                "path_id": c.get("display_id") or c.get("path_id"),
                "kind": c.get("kind"),
                "source_method": c.get("source_method"),
                "classification": c.get("classification"),
                "protocol_semantics": c.get("protocol_semantics") or "UNKNOWN",
            }
            for c in linked_comm
        ],
        "termination": termination,
        "case": case,
        "case_description": CASE_CLASSES.get(case, ""),
        "coverage_note": (
            "Coverage = how far the analyzer followed the graph; "
            "Evidence = what the found data proves. Not interchangeable."
        ),
        "protocol_semantics": "UNKNOWN",
    }


def analyze_path_comm(cp: dict[str, Any], transport_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Answer Phase H questions for one PATH-COMM."""
    src = cp.get("source_method")
    linked = [
        r["path_id"]
        for r in transport_rows
        if any(c.get("path_id") == (cp.get("display_id") or cp.get("path_id")) for c in r.get("linked_path_comm") or [])
        or any(
            (e.get("method") == src)
            for e in r.get("linked_buffer_ops") or []
        )
    ]
    # fallback: match via shared source method on linked_buffer_ops
    if not linked:
        linked = [
            r["path_id"]
            for r in transport_rows
            if any(e.get("method") == src for e in r.get("linked_buffer_ops") or [])
        ]
    steps = cp.get("steps") or []
    facts = [s for s in steps if s.get("classification") == "FACT"]
    corrs = [s for s in steps if s.get("classification") == "CORRELATION"]
    buf = next((s for s in steps if (s.get("kind") or s.get("node_type")) in {"BYTE_ARRAY", "BYTE_BUFFER"}), None)
    io_step = next(
        (
            s
            for s in steps
            if (s.get("kind") or s.get("node_type")) in {"INPUT_READ", "OUTPUT_WRITE"}
        ),
        None,
    )
    return {
        "path_id": cp.get("display_id") or cp.get("path_id"),
        "kind": cp.get("kind"),
        "direction": cp.get("direction"),
        "source_method": src,
        "transport_path_sources": linked,
        "socket_stream_object": "CORRELATION via transport objects when linked; not re-derived here",
        "io_operation": (io_step or {}).get("label"),
        "buffer": (buf or {}).get("label"),
        "byte_primitive_ops": [
            s.get("label")
            for s in steps
            if (s.get("kind") or s.get("node_type")) in {"PRIMITIVE_DECODE", "COPY", "WRAP"}
        ],
        "consumer_producer": cp.get("end"),
        "method_chain": [s.get("label") for s in steps],
        "fact_edges": len(facts),
        "correlation_edges": len(corrs),
        "inference_begins": (
            "End-to-end PATH-COMM composition is INFERENCE; individual steps may be FACT"
        ),
        "unknown": [
            "protocol_semantics",
            "wire format",
            "peer/HU identity",
            "runtime session state",
            "message meaning",
        ],
        "classification": cp.get("classification"),
        "protocol_semantics": cp.get("protocol_semantics") or "UNKNOWN",
    }


def build_object_identity_report(transport_rows: list[dict[str, Any]], bt: dict[str, Any]) -> dict[str, Any]:
    """Phase E: object-identity coverage notes from paths + dataflow transfers."""
    false_alias_candidates: list[dict[str, Any]] = []
    identity_breaks: list[dict[str, Any]] = []
    same_field_notes: list[dict[str, Any]] = []

    for df in bt.get("dataflow_paths") or []:
        for t in df.get("transfers") or []:
            kind = t.get("kind")
            if kind == "register_overwrite" or t.get("hop_kind") == "register_overwrite":
                identity_breaks.append(
                    {
                        "path": df.get("display_id"),
                        "kind": "move_result_overwrite",
                        "object_id": t.get("object_id"),
                        "method": t.get("from_method") or t.get("method"),
                        "classification": "FACT",
                        "note": "Local identity ends; same type must not merge",
                    }
                )
            if t.get("hop_kind") == "same_field_alias" or t.get("same_field"):
                same_field_notes.append(
                    {
                        "path": df.get("display_id"),
                        "field": t.get("field"),
                        "object_id": t.get("object_id"),
                        "note": "Same field → alias continuation, not +hop",
                    }
                )
            if kind in {"cycle", "cycle_detected"} or t.get("hop_kind") == "cycle":
                identity_breaks.append(
                    {
                        "path": df.get("display_id"),
                        "kind": "cycle_guard",
                        "object_id": t.get("object_id"),
                        "field": t.get("field"),
                        "classification": "FACT",
                    }
                )

    # SOCKET_PATH rows that never reach stream: possible identity / graph end
    for r in transport_rows:
        if r.get("case") == "CASE_D_IDENTITY_BOUND":
            identity_breaks.append(
                {
                    "path": r.get("path_id"),
                    "kind": "path_identity_bound",
                    "termination": (r.get("termination") or {}).get("primary"),
                }
            )
        # Two SOCKET objects of same type on different paths are never auto-merged
        objs = r.get("objects") or {}
        if isinstance(objs, dict) and objs.get("socket"):
            false_alias_candidates.append(
                {
                    "path": r.get("path_id"),
                    "socket_object": objs.get("socket"),
                    "rule": "REJECTED: merge-by-type",
                    "note": "Equal type BluetoothSocket ≠ same object identity across paths",
                }
            )

    return {
        "schema": "apk_forensics.object_identity_coverage_report.v1",
        "rules": {
            "same_type_not_alias": "FACT/REJECTED merge-by-type",
            "same_field": "Same static field position in object context; not automatic same instance across contexts",
            "move_result_overwrite": "Ends local register identity",
            "cycle_guard": "Real field/object cycle stops tracking",
            "stream_wrapper_new_identity": "New stream/wrapper object starts hops=0",
        },
        "identity_breaks": identity_breaks[:50],
        "same_field_continuations": same_field_notes[:50],
        "false_alias_candidates": false_alias_candidates[:30],
        "summary": {
            "identity_break_records": len(identity_breaks),
            "same_field_notes": len(same_field_notes),
            "false_alias_candidate_rows": len(false_alias_candidates),
        },
    }


def build_buffer_dataflow_report(
    transport_rows: list[dict[str, Any]],
    dataflow_index: dict[str, Any],
    comm_index: dict[str, Any],
) -> dict[str, Any]:
    """Phase F/G: buffer/byte evidence without protocol interpretation."""
    connections: list[dict[str, Any]] = []
    for op in dataflow_index.get("buffer_ops") or []:
        connections.append(
            {
                "source": op.get("object_id"),
                "operation": op.get("raw"),
                "target": op.get("buffer_register") or "signature_[B]",
                "buffer_identity": op.get("buffer_identity"),
                "method": op.get("method"),
                "classification": op.get("classification") or "FACT",
                "next_consumer": "see PATH-COMM / unresolved",
            }
        )
    # Enrich next_consumer from PATH-COMM
    for conn in connections:
        m = conn.get("method")
        comms = comm_index["by_method"].get(str(m), []) if m else []
        if comms:
            conn["next_consumer"] = [c.get("display_id") or c.get("path_id") for c in comms]
            conn["next_consumer_classification"] = "CORRELATION"

    decoder_note = {
        "decoder_candidates": comm_index.get("decoder_candidates"),
        "serializer_candidates": comm_index.get("serializer_candidates"),
        "primitive_decoding_sites": comm_index.get("primitive_decoding"),
        "interpretation": (
            "Primitive int/short results after read are INFERENCE candidates for "
            "byte-level handling only. Method names (decode/parse/Bcl/Etch/BMW) are "
            "search indicators, never protocol proof."
        ),
        "protocol_semantics": "UNKNOWN",
    }

    paths_to_buffer = sum(1 for r in transport_rows if r.get("stages_reached", {}).get("T3_BUFFER"))
    paths_to_consumer = sum(
        1 for r in transport_rows if r.get("stages_reached", {}).get("T4_CONSUMER_PRODUCER")
    )
    paths_to_decoder = sum(
        1 for r in transport_rows if r.get("stages_reached", {}).get("T5_DECODER_ENCODER")
    )

    return {
        "schema": "apk_forensics.buffer_dataflow_report.v1",
        "connections": connections[:200],
        "counts": {
            "buffer_ops": len(dataflow_index.get("buffer_ops") or []),
            "transport_paths_reaching_buffer": paths_to_buffer,
            "transport_paths_reaching_consumer_producer": paths_to_consumer,
            "transport_paths_reaching_decoder_encoder": paths_to_decoder,
        },
        "decoder_encoder": decoder_note,
        "hard_rule": "No semantic interpretation of bytes; no BMW/RFCOMM payload claims from names.",
    }


def build_closure_answers(transport_rows: list[dict[str, Any]], baseline: dict[str, Any], comm_index: dict[str, Any]) -> dict[str, Any]:
    n = len(transport_rows)
    reach_io = sum(1 for r in transport_rows if r.get("stages_reached", {}).get("T2_IO"))
    reach_buf = sum(1 for r in transport_rows if r.get("stages_reached", {}).get("T3_BUFFER"))
    reach_cp = sum(1 for r in transport_rows if r.get("stages_reached", {}).get("T4_CONSUMER_PRODUCER"))
    reach_dec = sum(1 for r in transport_rows if r.get("stages_reached", {}).get("T5_DECODER_ENCODER"))

    by_term = Counter((r.get("termination") or {}).get("primary") for r in transport_rows)
    by_case = Counter(r.get("case") for r in transport_rows)

    identity = [
        r["path_id"]
        for r in transport_rows
        if (r.get("termination") or {}).get("primary")
        in {"E_OBJECT_IDENTITY_BOUNDARY", "I_AMBIGUOUS_ALIAS"}
        or r.get("case") == "CASE_D_IDENTITY_BOUND"
    ]
    buffer_id = [
        r["path_id"]
        for r in transport_rows
        if (r.get("termination") or {}).get("primary") == "F_BUFFER_IDENTITY_BOUNDARY"
    ]
    ret_param_wrap = [
        r["path_id"]
        for r in transport_rows
        if (r.get("termination") or {}).get("primary")
        in {"B_RETURN_BOUNDARY", "C_PARAMETER_BOUNDARY", "D_WRAPPER_BOUNDARY"}
    ]
    true_end = [
        r["path_id"]
        for r in transport_rows
        if (r.get("termination") or {}).get("primary") == "A_TRUE_GRAPH_END"
        or r.get("case") == "CASE_F_TRUE_END"
    ]
    analyzer_limits = [
        r["path_id"]
        for r in transport_rows
        if (r.get("termination") or {}).get("primary") == "G_METHOD_CALL_GRAPH_BOUNDARY"
    ]

    baseline_comm = (baseline.get("path_comm") if baseline else None) or comm_index.get("paths")
    n_comm = len(baseline_comm) if isinstance(baseline_comm, list) else int(baseline.get("path_comm") or 0)

    return {
        "1_paths_reaching_read_write": {"count": reach_io, "of": n},
        "2_paths_reaching_buffer": {"count": reach_buf, "of": n},
        "3_paths_reaching_buffer_consumer_producer": {"count": reach_cp, "of": n},
        "4_paths_reaching_decoder_encoder_candidate": {"count": reach_dec, "of": n},
        "5_break_object_identity": identity,
        "6_break_buffer_identity": buffer_id,
        "7_break_return_parameter_wrapper": ret_param_wrap,
        "8_true_graph_ends": true_end,
        "9_remaining_analyzer_limits": analyzer_limits,
        "10_new_facts_vs_v12": [
            "Explicit T0–T6 stage closure per PATH-*",
            "read([B)/write([B) buffer_arg_present / buffer_register FACT on object-flow (when re-scanned)",
            "BUFFER_ARG nodes + read_into_buffer / write_from_buffer transfers",
            "Offline CORRELATION of transport object identity to dataflow buffer ops and PATH-COMM",
        ],
        "11_new_correlations": [
            "Transport stream object ↔ dataflow read([B) buffer argument",
            "Transport PATH-* ↔ PATH-COMM via source_method / object identity",
        ],
        "12_inferences_remaining": [
            "End-to-end PATH / PATH-COMM composition remains INFERENCE",
            "PRIMITIVE_DECODE as byte-handling candidate (not protocol)",
        ],
        "13_unknowns_unchanged": [
            "protocol_semantics",
            "wire format / message meaning",
            "peer/HU identity",
            "runtime session behavior",
        ],
        "14_communication_baseline_changed": False,
        "15_justification_if_changed": None,
        "16_protocol_semantics_statically_provable": False,
        "17_why_protocol_remains_unknown": (
            "Static DEX shows transport I/O and some byte[] arguments / PATH-COMM FACT steps, "
            "but no statically proven decoder that assigns wire/message meaning. "
            "Method/class names are not protocol evidence."
        ),
        "case_counts": dict(by_case),
        "termination_counts": dict(by_term),
        "path_comm_count": n_comm,
        "protocol_semantics": "UNKNOWN",
        "limits_unchanged": {
            "max_field_hops": 2,
            "max_method_hops": 3,
            "max_object_nodes": 500,
            "dataflow_depth": 3,
            "raised": False,
        },
    }


def inventory_table(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    table = []
    for r in rows:
        sr = r.get("stages_reached") or {}
        table.append(
            {
                "PATH": r.get("path_id"),
                "Transport": r.get("kind"),
                "ObjectFlow": ",".join(
                    filter(
                        None,
                        [
                            (r.get("objects") or {}).get("socket")
                            if isinstance(r.get("objects"), dict)
                            else None,
                            (r.get("objects") or {}).get("input")
                            if isinstance(r.get("objects"), dict)
                            else None,
                            (r.get("objects") or {}).get("output")
                            if isinstance(r.get("objects"), dict)
                            else None,
                        ],
                    )
                ),
                "Stream": "Y" if sr.get("T1_STREAM") else "N",
                "IO": "Y" if sr.get("T2_IO") else "N",
                "Buffer": "Y" if sr.get("T3_BUFFER") else "N",
                "ConsumerProducer": "Y" if sr.get("T4_CONSUMER_PRODUCER") else "N",
                "Ende": r.get("end"),
                "Reason": (r.get("termination") or {}).get("primary"),
                "Evidence": r.get("case"),
            }
        )
    return table


def build_transport_closure_report(
    report: dict[str, Any],
    *,
    baseline_meta: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bt = report.get("bluetooth_path") or {}
    eg = bt.get("evidence_graph") or {}
    paths = list(eg.get("evidence_paths") or [])
    ce = report.get("communication_evidence") or {}

    df_index = _index_dataflow(bt)
    comm_index = _index_communication(ce)

    transport_rows = [
        analyze_path(p, dataflow_index=df_index, comm_index=comm_index) for p in paths
    ]
    comm_rows = [analyze_path_comm(c, transport_rows) for c in comm_index["paths"]]
    answers = build_closure_answers(transport_rows, baseline_meta or {}, comm_index)
    table = inventory_table(transport_rows)

    return {
        "schema": "apk_forensics.transport_evidence_closure_report.v1",
        "provenance": provenance or {},
        "baseline": baseline_meta or {},
        "stage_definitions": {
            "T0": "Socket",
            "T1": "Stream",
            "T2": "read/write/flush",
            "T3": "Buffer/byte[]/ByteBuffer argument identity",
            "T4": "Buffer consumer/producer",
            "T5": "Decoder/encoder candidate (not protocol)",
            "T6": "Communication Evidence (PATH-COMM); protocol still UNKNOWN",
        },
        "termination_taxonomy": TERMINATION_TAXONOMY,
        "case_classes": CASE_CLASSES,
        "inventory_table": table,
        "paths": transport_rows,
        "path_comm": comm_rows,
        "answers": answers,
        "summary": {
            "transport_paths": len(transport_rows),
            "path_comm": len(comm_rows),
            "reaching_T2_IO": answers["1_paths_reaching_read_write"]["count"],
            "reaching_T3_BUFFER": answers["2_paths_reaching_buffer"]["count"],
            "reaching_T4": answers["3_paths_reaching_buffer_consumer_producer"]["count"],
            "reaching_T5": answers["4_paths_reaching_decoder_encoder_candidate"]["count"],
            "protocol_semantics": "UNKNOWN",
            "limits_raised": False,
        },
        "interpretation": (
            "v1.3 answers how far static evidence closes Bluetooth transport to bytes. "
            "It does not claim protocol discovery. Coverage ≠ evidence."
        ),
    }


def build_termination_report(closure: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for p in closure.get("paths") or []:
        rows.append(
            {
                "path_id": p.get("path_id"),
                "highest_stage": p.get("highest_stage"),
                "termination": (p.get("termination") or {}).get("primary"),
                "raw_reasons": (p.get("termination") or {}).get("raw_reasons"),
                "case": p.get("case"),
            }
        )
    return {
        "schema": "apk_forensics.path_termination_analysis.v1",
        "taxonomy": TERMINATION_TAXONOMY,
        "rows": rows,
        "counts": dict(Counter(r.get("termination") for r in rows)),
    }


def render_closure_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Transport Evidence Closure Report (v1.3)",
        "",
        "> Evidence closure from Bluetooth transport to bytes — not protocol reconstruction.",
        "",
        "## Summary",
        "",
    ]
    s = report.get("summary") or {}
    for k, v in s.items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")
    lines.append("## Inventory")
    lines.append("")
    lines.append(
        "| PATH | Transport | Object Flow | Stream | I/O | Buffer | Consumer/Producer | Ende | Reason | Evidence |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for row in report.get("inventory_table") or []:
        lines.append(
            f"| {row.get('PATH')} | {row.get('Transport')} | {row.get('ObjectFlow')} | "
            f"{row.get('Stream')} | {row.get('IO')} | {row.get('Buffer')} | "
            f"{row.get('ConsumerProducer')} | {row.get('Ende')} | {row.get('Reason')} | "
            f"{row.get('Evidence')} |"
        )
    lines.append("")
    lines.append("## Per-Path Closure Chains")
    lines.append("")
    for p in report.get("paths") or []:
        lines.append(f"### {p.get('path_id')} — `{p.get('case')}`")
        lines.append("")
        lines.append(f"- Kind: `{p.get('kind')}`")
        lines.append(f"- Highest stage: `{p.get('highest_stage')}`")
        lines.append(f"- Termination: `{(p.get('termination') or {}).get('primary')}`")
        lines.append(f"- Protocol semantics: `{p.get('protocol_semantics')}`")
        lines.append("- Stages:")
        for st, ok in (p.get("stages_reached") or {}).items():
            cls = (p.get("edge_class_by_stage") or {}).get(st, "")
            lines.append(f"  - `{st}`: {'REACHED' if ok else 'open'}" + (f" ({cls})" if cls else ""))
        lines.append("- Edge chain:")
        for e in p.get("edge_chain") or []:
            reached = e.get("reached", True)
            mark = "" if reached else " [not closed]"
            lines.append(
                f"  - `{e.get('from')} → {e.get('to')}` [{e.get('classification')}] "
                f"{e.get('evidence')}{mark}"
            )
        if p.get("linked_path_comm"):
            lines.append(
                f"- Linked PATH-COMM: "
                f"{[c.get('path_id') for c in p.get('linked_path_comm') or []]}"
            )
        lines.append("")
    lines.append("## PATH-COMM Linkage")
    lines.append("")
    for c in report.get("path_comm") or []:
        lines.append(
            f"- `{c.get('path_id')}` ← transport `{c.get('transport_path_sources')}` "
            f"| I/O `{c.get('io_operation')}` | buffer `{c.get('buffer')}` | "
            f"protocol `{c.get('protocol_semantics')}`"
        )
    lines.append("")
    lines.append("## Closure Answers (1–17)")
    lines.append("")
    for k, v in (report.get("answers") or {}).items():
        lines.append(f"- **{k}**: `{json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v}`")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(report.get("interpretation") or "")
    lines.append("")
    return "\n".join(lines)


def render_object_identity_markdown(report: dict[str, Any]) -> str:
    lines = ["# Object Identity Coverage Report (v1.3)", ""]
    lines.append("## Rules")
    lines.append("")
    for k, v in (report.get("rules") or {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for k, v in (report.get("summary") or {}).items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")
    lines.append("## Identity Breaks (sample)")
    lines.append("")
    for b in (report.get("identity_breaks") or [])[:20]:
        lines.append(f"- `{b}`")
    lines.append("")
    lines.append("## False-Alias Candidates")
    lines.append("")
    for b in (report.get("false_alias_candidates") or [])[:15]:
        lines.append(f"- `{b}`")
    lines.append("")
    return "\n".join(lines)


def render_buffer_markdown(report: dict[str, Any]) -> str:
    lines = ["# Buffer Dataflow Report (v1.3)", ""]
    lines.append(f"> {report.get('hard_rule')}")
    lines.append("")
    lines.append("## Counts")
    lines.append("")
    for k, v in (report.get("counts") or {}).items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")
    lines.append("## Decoder / Encoder")
    lines.append("")
    for k, v in (report.get("decoder_encoder") or {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("## Connections (sample)")
    lines.append("")
    lines.append("| Source | Operation | Target | Identity | Method | Class |")
    lines.append("|---|---|---|---|---|---|")
    for c in (report.get("connections") or [])[:40]:
        lines.append(
            f"| {c.get('source')} | {c.get('operation')} | {c.get('target')} | "
            f"{c.get('buffer_identity')} | {c.get('method')} | {c.get('classification')} |"
        )
    lines.append("")
    return "\n".join(lines)


def write_closure_reports(out_dir: Path, closure: dict[str, Any], identity: dict[str, Any], buffer: dict[str, Any], termination: dict[str, Any] | None = None) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name, payload, renderer in [
        ("TRANSPORT_EVIDENCE_CLOSURE_REPORT", closure, render_closure_markdown),
        ("OBJECT_IDENTITY_COVERAGE_REPORT", identity, render_object_identity_markdown),
        ("BUFFER_DATAFLOW_REPORT", buffer, render_buffer_markdown),
    ]:
        jp = out_dir / f"{name}.json"
        mp = out_dir / f"{name}.md"
        jp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        mp.write_text(renderer(payload), encoding="utf-8")
        paths[name] = jp
        paths[f"{name}_md"] = mp
    if termination is not None:
        jp = out_dir / "PATH_TERMINATION_ANALYSIS.json"
        mp = out_dir / "PATH_TERMINATION_ANALYSIS.md"
        jp.write_text(json.dumps(termination, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        lines = ["# Path Termination Analysis (v1.3)", ""]
        lines.append("| Path | Highest | Termination | Case |")
        lines.append("|---|---|---|---|")
        for r in termination.get("rows") or []:
            lines.append(
                f"| {r.get('path_id')} | {r.get('highest_stage')} | {r.get('termination')} | {r.get('case')} |"
            )
        lines.append("")
        mp.write_text("\n".join(lines), encoding="utf-8")
        paths["PATH_TERMINATION_ANALYSIS"] = jp
        paths["PATH_TERMINATION_ANALYSIS_md"] = mp
    return paths
