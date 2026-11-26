"""Minimal Runtime / Wire evidence interface (v1.6).

External artefacts are optional. Missing input → UNKNOWN / INPUT-MISSING.
Never invent traces or captures. Neutral evidence types only — no protocol names.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

RUNTIME_SCHEMA = "apk_forensics.runtime_evidence.v1"
WIRE_SCHEMA = "apk_forensics.wire_evidence.v1"

RUNTIME_TYPES = frozenset(
    {
        "RUNTIME_METHOD",
        "RUNTIME_READ",
        "RUNTIME_WRITE",
        "RUNTIME_BUFFER",
        "RUNTIME_VALUE",
        "RUNTIME_EVENT",
    }
)
WIRE_TYPES = frozenset(
    {
        "WIRE_PACKET",
        "WIRE_BYTES",
        "WIRE_READ",
        "WIRE_WRITE",
        "WIRE_DIRECTION",
        "WIRE_TIMESTAMP",
    }
)

# App-relative I/O direction only. Peer labels require explicit peer evidence.
DIRECTION_IN = "IN"  # bytes enter the application (read)
DIRECTION_OUT = "OUT"  # bytes leave the application (write)
DIRECTION_UNKNOWN = "UNKNOWN"

# Optional peer-facing labels — only when source artefact provides them.
PEER_PHONE_TO_HU = "PHONE_TO_HU"
PEER_HU_TO_PHONE = "HU_TO_PHONE"

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def normalize_hex(value: str | None) -> str | None:
    if value is None:
        return None
    s = re.sub(r"[\s:_-]", "", str(value).strip())
    if not s:
        return None
    if not _HEX_RE.match(s) or len(s) % 2 != 0:
        return None
    return s.lower()


def normalize_direction(value: Any) -> str:
    if value is None:
        return DIRECTION_UNKNOWN
    s = str(value).strip().upper().replace("-", "_")
    aliases = {
        "IN": DIRECTION_IN,
        "INBOUND": DIRECTION_IN,
        "READ": DIRECTION_IN,
        "RX": DIRECTION_IN,
        "OUT": DIRECTION_OUT,
        "OUTBOUND": DIRECTION_OUT,
        "WRITE": DIRECTION_OUT,
        "TX": DIRECTION_OUT,
        "PHONE_TO_HU": PEER_PHONE_TO_HU,
        "HU_TO_PHONE": PEER_HU_TO_PHONE,
        "UNKNOWN": DIRECTION_UNKNOWN,
    }
    return aliases.get(s, DIRECTION_UNKNOWN)


def app_direction(value: Any) -> str:
    """Collapse peer labels to app-relative IN/OUT when possible."""
    d = normalize_direction(value)
    if d in {DIRECTION_IN, DIRECTION_OUT, DIRECTION_UNKNOWN}:
        return d
    if d == PEER_HU_TO_PHONE:
        return DIRECTION_IN
    if d == PEER_PHONE_TO_HU:
        return DIRECTION_OUT
    return DIRECTION_UNKNOWN


def _norm_event(raw: dict[str, Any], *, default_prefix: str, index: int) -> dict[str, Any]:
    eid = str(raw.get("id") or f"{default_prefix}-{index:04d}")
    etype = str(raw.get("type") or raw.get("evidence_type") or "RUNTIME_EVENT")
    bytes_hex = normalize_hex(raw.get("bytes_hex") or raw.get("bytes") or raw.get("hex"))
    length = raw.get("length")
    if length is None and bytes_hex is not None:
        length = len(bytes_hex) // 2
    # Explicit length without bytes must never invent a payload.
    if length is None and raw.get("input_length") is not None:
        length = raw.get("input_length")
    ts = raw.get("timestamp_ms")
    if ts is None:
        ts = raw.get("t_ms")
    if ts is None:
        ts = raw.get("timestamp")
    try:
        timestamp_ms = int(ts) if ts is not None else None
    except (TypeError, ValueError):
        timestamp_ms = None
    mono = raw.get("monotonic_ns")
    if mono is None:
        mono = raw.get("monotonic_timestamp_ns")
    try:
        monotonic_ns = int(mono) if mono is not None else None
    except (TypeError, ValueError):
        monotonic_ns = None
    try:
        length_i = int(length) if length is not None else None
    except (TypeError, ValueError):
        length_i = None
    method = raw.get("method") or raw.get("method_identity")
    if method is not None:
        method = str(method).strip() or None
    phase = raw.get("phase") or raw.get("call_phase")
    if phase is not None:
        phase = str(phase).strip().lower() or None
        if phase in {"enter", "entry", "method_entry"}:
            phase = "entry"
        elif phase in {"exit", "return", "method_exit"}:
            phase = "exit"
    args = raw.get("arguments")
    if args is None:
        args = raw.get("args")
    return_value = raw.get("return_value")
    if return_value is None:
        return_value = raw.get("retval")
    payload_observed = bool(bytes_hex)
    # Method execution FACT ≠ payload FACT. Keep both flags explicit.
    return {
        "id": eid,
        "type": etype,
        "method": method,
        "method_name": (raw.get("method_name") or None),
        "phase": phase,
        "timestamp_ms": timestamp_ms,
        "monotonic_ns": monotonic_ns,
        "direction": normalize_direction(raw.get("direction")),
        "app_direction": app_direction(raw.get("direction")),
        "length": length_i,
        "bytes_hex": bytes_hex,
        "payload_observed": payload_observed,
        "arguments": args,
        "return_value": return_value,
        "thread_id": raw.get("thread_id") or raw.get("tid"),
        "package": raw.get("package") or raw.get("package_name"),
        "process": raw.get("process") or raw.get("process_name"),
        "process_id": raw.get("process_id") or raw.get("pid"),
        "session_id": raw.get("session_id"),
        "socket_id": raw.get("socket_id"),
        "stream_id": raw.get("stream_id"),
        "transport_id": raw.get("transport_id"),
        "buffer_ref": raw.get("buffer_ref") or raw.get("object_ref"),
        "sequence": raw.get("sequence"),
        "offset": raw.get("offset"),
        "value_id": raw.get("value_id"),
        "field": raw.get("field"),
        "branch": raw.get("branch"),
        "peer": raw.get("peer"),
        "fragment_of": raw.get("fragment_of"),
        "aggregate_of": raw.get("aggregate_of"),
        "source_artifact": raw.get("source_artifact"),
        "instrumentation": raw.get("instrumentation"),
        "classification": raw.get("classification") or "FACT",
        "protocol_semantics": "UNKNOWN",
        "raw_keys": sorted(raw.keys()),
    }


def _resolve_runtime_status(raw: dict[str, Any], events: list[dict[str, Any]]) -> str:
    """Preserve INPUT_MISSING; never upgrade empty capture attempts to NOT_FOUND."""
    declared = str(raw.get("status") or "").strip().upper()
    if declared == "INPUT_MISSING":
        return "INPUT_MISSING"
    if events:
        return "OK"
    prov = raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}
    missing = prov.get("missing_inputs") or []
    if missing or prov.get("attempted") is True and not events:
        # Attempted capture with zero events remains INPUT_MISSING (device/process absent).
        return "INPUT_MISSING"
    if declared == "EMPTY":
        return "EMPTY"
    return "EMPTY"


def load_runtime_evidence(path: Path | None) -> dict[str, Any]:
    if path is None or not Path(path).is_file():
        return {
            "schema": RUNTIME_SCHEMA,
            "status": "INPUT_MISSING",
            "events": [],
            "counts": {"events": 0},
            "session_id": None,
            "package": None,
            "process": None,
            "instrumentation": None,
            "source": None,
            "note": "No runtime evidence artefact provided.",
        }
    path = Path(path).resolve()
    raw = json.loads(path.read_text(encoding="utf-8"))
    events_in = raw.get("events") or raw.get("runtime_events") or []
    doc_session = raw.get("session_id")
    events = []
    for i, e in enumerate(events_in):
        if not isinstance(e, dict):
            continue
        ev = _norm_event(e, default_prefix="R", index=i + 1)
        if ev.get("session_id") is None and doc_session is not None:
            ev["session_id"] = doc_session
        events.append(ev)
    unknown_types = sorted({e["type"] for e in events if e["type"] not in RUNTIME_TYPES})
    status = _resolve_runtime_status(raw, events)
    return {
        "schema": raw.get("schema") or RUNTIME_SCHEMA,
        "status": status,
        "events": events,
        "counts": {
            "events": len(events),
            "by_type": _count_by(events, "type"),
            "with_payload": sum(1 for e in events if e.get("payload_observed")),
            "without_payload": sum(1 for e in events if not e.get("payload_observed")),
            "unknown_types": unknown_types,
        },
        "session_id": doc_session,
        "package": raw.get("package") or raw.get("package_name"),
        "process": raw.get("process"),
        "instrumentation": raw.get("instrumentation")
        or ((raw.get("provenance") or {}).get("instrumentation") if isinstance(raw.get("provenance"), dict) else None),
        "source": str(path),
        "provenance": raw.get("provenance") or {},
        "note": raw.get("note"),
    }


def load_wire_evidence(path: Path | None) -> dict[str, Any]:
    if path is None or not Path(path).is_file():
        return {
            "schema": WIRE_SCHEMA,
            "status": "INPUT_MISSING",
            "packets": [],
            "counts": {"packets": 0},
            "session_id": None,
            "source": None,
            "note": "No wire/capture evidence artefact provided.",
        }
    path = Path(path).resolve()
    raw = json.loads(path.read_text(encoding="utf-8"))
    packets_in = raw.get("packets") or raw.get("wire_packets") or raw.get("events") or []
    doc_session = raw.get("session_id")
    packets = []
    for i, e in enumerate(packets_in):
        if not isinstance(e, dict):
            continue
        p = _norm_event(e, default_prefix="W", index=i + 1)
        if p.get("session_id") is None and doc_session is not None:
            p["session_id"] = doc_session
        if p["type"] not in WIRE_TYPES:
            # allow generic packet label
            if p["type"] in RUNTIME_TYPES:
                p["type"] = "WIRE_PACKET"
        packets.append(p)
    unknown_types = sorted({p["type"] for p in packets if p["type"] not in WIRE_TYPES})
    declared = str(raw.get("status") or "").strip().upper()
    if declared == "INPUT_MISSING":
        status = "INPUT_MISSING"
    else:
        status = "OK" if packets else "EMPTY"
    return {
        "schema": raw.get("schema") or WIRE_SCHEMA,
        "status": status,
        "packets": packets,
        "counts": {
            "packets": len(packets),
            "by_type": _count_by(packets, "type"),
            "unknown_types": unknown_types,
        },
        "session_id": doc_session,
        "source": str(path),
        "provenance": raw.get("provenance") or {},
        "note": raw.get("note"),
    }


def adapt_external_runtime_to_v1(
    records: list[dict[str, Any]] | None,
    *,
    session_id: str | None = None,
    package: str | None = None,
    process: str | None = None,
    instrumentation: str | None = None,
    source: str | None = None,
    status: str | None = None,
    provenance: dict[str, Any] | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Minimal adapter: external hook/log records → runtime_evidence.v1.

    Does not install Frida/JVMTI. Does not invent events. Empty/absent records with
    explicit missing instrumentation → INPUT_MISSING (never NOT_FOUND).
    Static VALUE ids must not be injected here as runtime facts.
    """
    records = list(records or [])
    events = [_norm_event(r, default_prefix="R", index=i + 1) for i, r in enumerate(records) if isinstance(r, dict)]
    for ev in events:
        if ev.get("session_id") is None and session_id is not None:
            ev["session_id"] = session_id
        # Refuse silent promotion of static catalog IDs unless the external source set them.
        # (Adapter itself never invents value_id.)
    declared = (status or "").strip().upper() or None
    if provenance is None:
        missing: list[str] = []
        if not events:
            missing.append("NO_RUNTIME_RECORDS")
            if not instrumentation:
                missing.append("NO_INSTRUMENTATION")
        provenance = {
            "instrumentation": instrumentation,
            "adapter": "adapt_external_runtime_to_v1",
            "missing_inputs": missing,
        }
    raw_stub = {"status": declared, "provenance": provenance}
    if declared:
        resolved = declared
        if declared == "OK" and not events:
            resolved = "EMPTY"
    elif not events:
        resolved = "INPUT_MISSING"
    else:
        resolved = _resolve_runtime_status(raw_stub, events)
    return {
        "schema": RUNTIME_SCHEMA,
        "status": resolved,
        "session_id": session_id,
        "package": package,
        "process": process,
        "instrumentation": instrumentation,
        "events": events,
        "counts": {
            "events": len(events),
            "by_type": _count_by(events, "type"),
            "with_payload": sum(1 for e in events if e.get("payload_observed")),
            "without_payload": sum(1 for e in events if not e.get("payload_observed")),
        },
        "source": source,
        "provenance": raw_stub["provenance"],
        "note": note
        or (
            "Adapter output only. Method execution without bytes_hex is not payload evidence."
        ),
    }


# Canonical V001 hook target (static identity). Not a runtime fact.
V001_RUNTIME_HOOK_TARGET = {
    "value_id": "VALUE-V001",
    "static_source_api": "Lcom/bmwgroup/connected/core/services/accessory/bcl/packet/Info;->decodeVersion([B)S",
    "static_source_method": "Lcom/bmwgroup/connected/core/services/accessory/bcl/BclConnection$2;->run()V",
    "class": "com.bmwgroup.connected.core.services.accessory.bcl.packet.Info",
    "method": "decodeVersion",
    "descriptor": "([B)S",
    "required_runtime_fields": [
        "method",
        "timestamp_ms",
        "session_id",
        "package",
        "process",
        "phase",
        "length",
        "bytes_hex",
        "return_value",
    ],
    "optional_runtime_fields": [
        "thread_id",
        "monotonic_ns",
        "arguments",
        "socket_id",
        "transport_id",
        "buffer_ref",
    ],
    "note": (
        "Hook Info.decodeVersion only. Do not write STATIC FACT (BIG_ENDIAN slice) into the "
        "runtime event. Do not pre-fill value_id from the catalog unless the instrumentation "
        "layer explicitly tagged it after an independent join."
    ),
}


def load_static_evidence_from_application_flow(
    flow_report: dict[str, Any] | None,
    *,
    source: str | None = None,
) -> dict[str, Any]:
    """Project v1.5 application-flow / structured-value artefacts into neutral static evidence."""
    flow_report = flow_report or {}
    catalog = list(flow_report.get("value_catalog") or [])
    stored = list(flow_report.get("stored_fields") or [])
    counts = dict(flow_report.get("flow_counts") or {})
    answers = flow_report.get("answers") or {}

    static_values = []
    for v in catalog:
        static_values.append(
            {
                "id": v.get("value_id"),
                "type": "STATIC_VALUE",
                "method": v.get("source_method"),
                "source_api": v.get("source_api"),
                "source_kind": v.get("source_kind"),
                "field": v.get("stored_field"),
                "value_class": v.get("value_class"),
                "classification": v.get("classification") or "FACT",
                "protocol_semantics": "UNKNOWN",
                "consumers": v.get("consumers") or [],
                "lineage": v.get("lineage") or [],
            }
        )

    methods = sorted(
        {
            m
            for m in (
                [v.get("source_method") for v in catalog]
                + [v.get("source_api") for v in catalog]
                + [c.get("method") for v in catalog for c in (v.get("consumers") or [])]
            )
            if m
        }
    )
    fields = sorted({f for f in ([v.get("stored_field") for v in catalog] + [s.get("field") for s in stored if isinstance(s, dict)]) if f})

    return {
        "schema": "apk_forensics.static_correlation_evidence.v1",
        "status": "OK" if catalog else "EMPTY",
        "values": static_values,
        "methods": [{"id": f"SM-{i:04d}", "type": "STATIC_METHOD", "method": m} for i, m in enumerate(methods, 1)],
        "fields": [{"id": f"SF-{i:04d}", "type": "STATIC_FIELD", "field": f} for i, f in enumerate(fields, 1)],
        "counts": {
            "values": len(static_values),
            "methods": len(methods),
            "fields": len(fields),
            "field_stores": int(counts.get("field_stores") or answers.get("2_written_to_fields") or 0),
            "field_loads": int(counts.get("field_loads") or answers.get("3_later_loaded") or 0),
            "branches": int(counts.get("branches") or answers.get("6_influence_branches") or 0),
            "state_mutations": int(counts.get("state_mutations") or answers.get("7_application_state_mutations") or 0),
            "roundtrip_candidates": int(counts.get("roundtrip_candidates") or answers.get("10_output_dataflow") or 0),
            "catalog_values": int(counts.get("catalog_values") or len(catalog)),
        },
        "source": source,
        "baseline_frozen": True,
        "protocol_semantics": "UNKNOWN",
    }


def inventory_external_artefacts(roots: list[Path] | None = None) -> dict[str, Any]:
    """Repo audit helper: look for runtime/wire-like files (no parsing)."""
    roots = roots or [Path("artifacts"), Path("output"), Path("tests/fixtures")]
    patterns = ("*trace*", "*capture*", "*pcap*", "*wire*", "*runtime*", "*hci*")
    found: list[str] = []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for pat in patterns:
            for p in root.rglob(pat):
                if any(x in p.parts for x in (".git", "__pycache__", ".venv", "node_modules")):
                    continue
                if p.is_file():
                    found.append(str(p))
    found = sorted(set(found))[:200]
    return {
        "status": "NONE_IN_REPO" if not found else "CANDIDATES_FOUND",
        "candidates": found,
        "note": (
            "Filename inventory only — not evidence. Structured runtime/wire JSON must be supplied "
            "explicitly to diagnose-runtime-correlation."
        ),
    }


def normalize_b3_capture_to_wire_evidence(
    capture_dir: Path,
    *,
    include_stream_aggregates: bool = True,
) -> dict[str, Any]:
    """Deterministic CASE-B normalizer: bt-analyzer B3 capture dir → wire_evidence.v1.

    Reads:
      raw/phone_to_hu.bin, raw/hu_to_phone.bin
      optional b3.jsonl ``bytes`` events (for directional slicing + offsets)

    Does **not** invent protocol semantics. External labels (cmd_name/method) are
    omitted from evidence types; only direction/bytes/length/offset/time/peer.
    """
    capture_dir = Path(capture_dir).resolve()
    phone_bin = capture_dir / "raw" / "phone_to_hu.bin"
    hu_bin = capture_dir / "raw" / "hu_to_phone.bin"
    jsonl = capture_dir / "b3.jsonl"
    if not phone_bin.is_file() and not hu_bin.is_file():
        return {
            "schema": WIRE_SCHEMA,
            "status": "INPUT_MISSING",
            "packets": [],
            "counts": {"packets": 0},
            "source": str(capture_dir),
            "note": "No raw/phone_to_hu.bin or raw/hu_to_phone.bin in capture dir.",
            "normalization": "b3_capture_v1",
        }

    streams: dict[str, bytes] = {}
    if phone_bin.is_file():
        streams["PHONE_TO_HU"] = phone_bin.read_bytes()
    if hu_bin.is_file():
        streams["HU_TO_PHONE"] = hu_bin.read_bytes()

    # Optional absolute epoch from first relay_start ts
    t0_ms: int | None = None
    byte_events: list[dict[str, Any]] = []
    peer = None
    if jsonl.is_file():
        for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event") == "relay_start" and ev.get("ts") is not None and t0_ms is None:
                try:
                    t0_ms = int(float(ev["ts"]) * 1000)
                except (TypeError, ValueError):
                    t0_ms = None
            if ev.get("event") == "accepted" and ev.get("peer") is not None:
                peer = str(ev.get("peer"))
            if ev.get("event") == "bytes" and ev.get("direction") and ev.get("n") is not None:
                byte_events.append(ev)

    dir_map = {
        "phone->hu": "PHONE_TO_HU",
        "phone_to_hu": "PHONE_TO_HU",
        "hu->phone": "HU_TO_PHONE",
        "hu_to_phone": "HU_TO_PHONE",
    }
    packets: list[dict[str, Any]] = []
    cursors = {k: 0 for k in streams}
    seq = 0
    for ev in byte_events:
        dlabel = dir_map.get(str(ev.get("direction")).strip().lower())
        if not dlabel or dlabel not in streams:
            continue
        n = int(ev["n"])
        buf = streams[dlabel]
        off = cursors[dlabel]
        if off + n > len(buf):
            # cannot slice — skip rather than invent
            continue
        chunk = buf[off : off + n]
        cursors[dlabel] = off + n
        seq += 1
        packets.append(
            {
                "id": f"W-{seq:04d}",
                "type": "WIRE_PACKET",
                "direction": dlabel,
                "length": n,
                "bytes_hex": chunk.hex(),
                "offset": off,
                "sequence": seq,
                "timestamp_ms": t0_ms,
                "peer": peer,
                "source_artifact": str(capture_dir / "raw" / ("phone_to_hu.bin" if dlabel == "PHONE_TO_HU" else "hu_to_phone.bin")),
            }
        )

    # If jsonl missing/incomplete, emit whole-stream aggregates (still real bytes).
    if include_stream_aggregates:
        for dlabel, buf in streams.items():
            if not buf:
                continue
            # skip aggregate if we already sliced the full stream exactly
            if cursors.get(dlabel, 0) == len(buf) and any(p["direction"] == dlabel for p in packets):
                continue
            seq += 1
            packets.append(
                {
                    "id": f"W-STREAM-{dlabel}",
                    "type": "WIRE_BYTES",
                    "direction": dlabel,
                    "length": len(buf),
                    "bytes_hex": buf.hex(),
                    "offset": 0,
                    "sequence": seq,
                    "timestamp_ms": t0_ms,
                    "peer": peer,
                    "source_artifact": str(
                        capture_dir / "raw" / ("phone_to_hu.bin" if dlabel == "PHONE_TO_HU" else "hu_to_phone.bin")
                    ),
                    "note": "full_stream_aggregate",
                }
            )

    sliced_ok = all(cursors.get(k, 0) == len(v) for k, v in streams.items() if v)
    return {
        "schema": WIRE_SCHEMA,
        "status": "OK" if packets else "EMPTY",
        "packets": packets,
        "counts": {
            "packets": len(packets),
            "by_direction": _count_by(
                [{"type": p.get("direction")} for p in packets],
                "type",
            ),
            "phone_to_hu_bytes": len(streams.get("PHONE_TO_HU") or b""),
            "hu_to_phone_bytes": len(streams.get("HU_TO_PHONE") or b""),
            "jsonl_byte_events": len(byte_events),
            "stream_slice_complete": sliced_ok,
        },
        "source": str(capture_dir),
        "provenance": {
            "claim": "LAB",
            "normalization": "b3_capture_v1",
            "inputs": [str(p) for p in (phone_bin, hu_bin, jsonl) if p.is_file()],
            "protocol_semantics": "UNKNOWN",
            "note": (
                "Normalized from bt-analyzer B3 capture. External method/cmd labels are not "
                "copied into evidence types. This is Wire evidence — not APK FACT."
            ),
        },
        "normalization": "b3_capture_v1",
    }


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        k = str(it.get(key) or "UNKNOWN")
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))
