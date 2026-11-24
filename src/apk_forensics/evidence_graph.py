"""v0.9 Evidence Graph: canonicalize raw object/dataflow into provenance-backed paths.

Three strict layers:
  A. Raw Graph        — unbounded redundancy from bounded analysis
  B. Canonical Graph  — deduplicated logical objects / edges
  C. Evidence Paths   — compact forensic chains for the report

Ranking never changes classification.
Method names never imply protocol semantics.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any

BOUNDARY_REASONS = frozenset(
    {
        "max_method_hops",
        "max_field_hops",
        "max_object_nodes",
        "max_dataflow_nodes",
        "return_no_move_result",
        "parameter_unresolved",
        "parameter_callee_unresolved",
        "field_alias_unresolved",
        "constructor_unresolved",
        "wrapper_unresolved",
        "cycle_detected",
        "cycle",
        "field_no_loaders",
        "instruction_context_unavailable",
        "unsupported_pattern",
        "return_no_callers",
    }
)

# Normalize legacy / alternate reason strings onto the v0.9 vocabulary.
_REASON_ALIASES = {
    "parameter_callee_unresolved": "parameter_unresolved",
    "return_no_callers": "return_no_move_result",
    "max_nodes": "max_object_nodes",
    "cycle": "cycle_detected",
}

NODE_TYPES = frozenset(
    {
        "SOCKET",
        "INPUT_STREAM",
        "OUTPUT_STREAM",
        "FIELD",
        "FIELD_WRITE",
        "FIELD_READ",
        "RETURN",
        "PARAMETER",
        "CONSTRUCTOR",
        "WRAPPER",
        "CONNECT",
        "GET_INPUT_STREAM",
        "GET_OUTPUT_STREAM",
        "READ",
        "WRITE",
        "FLUSH",
        "CALL",
        "BOUNDARY",
        "METHOD_CALL",
        "OBJECT",
        "UNKNOWN",
    }
)

EDGE_TYPES = frozenset(
    {
        "CALL",
        "RETURN",
        "PARAMETER",
        "ARGUMENT",
        "FIELD_STORE",
        "FIELD_LOAD",
        "CONSTRUCTOR",
        "CONSTRUCTOR_ARG",
        "GET_INPUT_STREAM",
        "GET_OUTPUT_STREAM",
        "READS_FROM",
        "WRITES_TO",
        "WRAPS",
        "ALIAS",
        "BOUNDARY",
    }
)

_PROTOCOL_NAME_HINTS = re.compile(
    r"(?i)(?:^|[^a-z0-9])(bcl|etch|rhmi|aaidrive|scn\d*|nbt|bmw|connected)(?:[^a-z0-9]|$)"
    r"|(?:Bcl|Etch|Rhmi|AAIdrive|SCN\d*|Nbt|Bmw|Connected)"
)


def method_name_semantics(method_name: str | None) -> dict[str, Any]:
    """DEX method names are FACT as strings; protocol meaning stays UNKNOWN."""
    name = method_name or ""
    return {
        "method_name": name,
        "method_name_evidence": "FACT" if name else "UNKNOWN",
        "protocol_semantics": "UNKNOWN",
        "notes": [
            "Method names are DEX identifiers only.",
            "Names such as doBclHandshake / Etch / RHMI do not prove protocol semantics.",
        ],
        "hint_tokens_detected": bool(_PROTOCOL_NAME_HINTS.search(name)),
    }


def _stable_hash(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _short_id(prefix: str, *parts: str, n: int = 12) -> str:
    return f"{prefix}-{_stable_hash(*parts)[:n]}"


def _norm_reason(reason: str | None) -> str:
    r = (reason or "unsupported_pattern").strip()
    r = _REASON_ALIASES.get(r, r)
    if r not in BOUNDARY_REASONS:
        return "unsupported_pattern"
    # Map aliases that remain in BOUNDARY_REASONS for provenance fidelity
    return _REASON_ALIASES.get(r, r)


def _field_short(field: str | None) -> str | None:
    if not field:
        return None
    if ";->" in field:
        return field.split(";->")[-1]
    return field


def _method_short(method: str | None) -> str | None:
    if not method:
        return None
    if "->" in method:
        return method.split("->")[-1]
    return method


def _provenance(
    *,
    apk: str | None = None,
    dex_file: str | None = None,
    class_name: str | None = None,
    method: str | None = None,
    instruction_offset: int | None = None,
    instruction: str | None = None,
    source_node_ids: list[str] | None = None,
    source_edge_ids: list[str] | None = None,
    evidence_kind: str | None = None,
    instruction_offset_unavailable_reason: str | None = None,
) -> dict[str, Any]:
    offset = instruction_offset
    reason = instruction_offset_unavailable_reason
    if offset is None and reason is None:
        reason = "instruction_offset not provided by DEX adapter"
    return {
        "apk": apk,
        "dex_file": dex_file,
        "class": class_name,
        "method": method,
        "instruction_offset": offset,
        "instruction": instruction,
        "source_node_ids": list(source_node_ids or []),
        "source_edge_ids": list(source_edge_ids or []),
        "evidence_kind": evidence_kind,
        "instruction_offset_unavailable_reason": reason if offset is None else None,
    }


def _canon_node_type(raw_type: str | None, role: str | None = None, value: str | None = None) -> str:
    t = (raw_type or "").upper()
    role_l = (role or "").lower()
    val = (value or "").lower()
    if t in NODE_TYPES:
        if t == "METHOD_CALL":
            if "connect" in role_l or val.endswith(".connect") or "->connect(" in val:
                return "CONNECT"
            if "getinputstream" in val.replace("_", "").lower() or role_l == "input":
                return "GET_INPUT_STREAM"
            if "getoutputstream" in val.replace("_", "").lower() or role_l == "output":
                return "GET_OUTPUT_STREAM"
        return t
    if "flush" in val:
        return "FLUSH"
    if "read" in role_l or "read" in val:
        return "READ"
    if "write" in role_l or "write" in val:
        return "WRITE"
    if "socket" in role_l or "socket" in val:
        return "SOCKET"
    if "input" in role_l:
        return "INPUT_STREAM"
    if "output" in role_l:
        return "OUTPUT_STREAM"
    if "field" in t.lower() or "field" in role_l:
        return "FIELD"
    return "UNKNOWN"


def _edge_type_from_kind(kind: str | None, relationship: str | None = None) -> str:
    k = (relationship or kind or "").upper()
    mapping = {
        "FIELD_STORE": "FIELD_STORE",
        "FIELD_LOAD": "FIELD_LOAD",
        "FIELD_STORE".lower(): "FIELD_STORE",
        "CALL": "CALL",
        "RETURN": "RETURN",
        "ARGUMENT": "ARGUMENT",
        "PARAMETER": "PARAMETER",
        "CONSTRUCTOR": "CONSTRUCTOR",
        "CONSTRUCTOR_ARG": "CONSTRUCTOR_ARG",
        "GET_INPUT_STREAM": "GET_INPUT_STREAM",
        "GET_OUTPUT_STREAM": "GET_OUTPUT_STREAM",
        "READS_FROM": "READS_FROM",
        "WRITES_TO": "WRITES_TO",
        "WRAPS": "WRAPS",
        "ALIAS": "ALIAS",
        "BOUNDARY": "BOUNDARY",
        "FIELD_STORE_KIND": "FIELD_STORE",
    }
    if k in EDGE_TYPES:
        return k
    low = (kind or "").lower()
    if low == "field_store":
        return "FIELD_STORE"
    if low == "field_load":
        return "FIELD_LOAD"
    if low == "get_input_stream":
        return "GET_INPUT_STREAM"
    if low == "get_output_stream":
        return "GET_OUTPUT_STREAM"
    if low == "return":
        return "RETURN"
    if low in {"constructor_arg", "constructor"}:
        return "CONSTRUCTOR_ARG"
    if low == "parameter":
        return "PARAMETER"
    return mapping.get(k, "ALIAS")


class _ObjectIdFactory:
    """Deterministic object IDs independent of dict/set iteration order."""

    def __init__(self) -> None:
        self._assigned: dict[str, str] = {}
        self._counters: dict[str, int] = {"socket": 0, "input": 0, "output": 0, "wrapper": 0}

    def get(self, kind: str, identity_key: str) -> str:
        kind = kind if kind in self._counters else "wrapper"
        if identity_key in self._assigned:
            return self._assigned[identity_key]
        self._counters[kind] += 1
        oid = f"{kind}:{kind[0].upper()}{self._counters[kind]}"
        # Prefer analysis-provided IDs when they already match the scheme and are unused.
        self._assigned[identity_key] = oid
        return oid

    def adopt(self, existing: str, identity_key: str) -> str:
        if identity_key in self._assigned:
            return self._assigned[identity_key]
        if existing and existing not in self._assigned.values():
            self._assigned[identity_key] = existing
            # bump counters so later generated IDs don't collide
            prefix = existing.split(":", 1)[0]
            if prefix in self._counters:
                try:
                    num = int(existing.split(":")[-1][1:])
                    self._counters[prefix] = max(self._counters[prefix], num)
                except ValueError:
                    pass
            return existing
        kind = existing.split(":")[0] if existing and ":" in existing else "wrapper"
        return self.get(kind, identity_key)


def _transfer_identity(transfer: dict[str, Any]) -> str:
    return "|".join(
        [
            str(transfer.get("kind") or ""),
            str(transfer.get("object_id") or ""),
            str(transfer.get("field") or ""),
            str(transfer.get("from_method") or ""),
            str(transfer.get("to_method") or ""),
            str(transfer.get("method") or ""),
            str(transfer.get("classification") or ""),
        ]
    )


def _step_identity(step: dict[str, Any], kind: str) -> str:
    return "|".join(
        [
            kind,
            str(step.get("method") or ""),
            str(step.get("raw") or step.get("text") or ""),
            str(step.get("index") if step.get("index") is not None else ""),
            str(step.get("object_id") or ""),
            str(step.get("classification") or ""),
        ]
    )


def build_evidence_graph_for_path(
    dataflow_path: dict[str, Any],
    *,
    apk_sha256: str | None = None,
    include_boundaries: bool = True,
) -> dict[str, Any]:
    """Build canonical graph + evidence paths for one BluetoothDataflowPath."""
    factory = _ObjectIdFactory()
    raw_nodes = list(dataflow_path.get("nodes") or [])
    raw_edges = list(dataflow_path.get("edges") or [])
    transfers = list(dataflow_path.get("transfers") or [])
    raw_boundaries = list(dataflow_path.get("boundaries") or [])
    objects = list(dataflow_path.get("object_details") or dataflow_path.get("objects") or [])

    # --- Canonical objects (deterministic order) ---
    object_records: list[dict[str, Any]] = []
    if objects and isinstance(objects[0], dict):
        sorted_objs = sorted(
            objects,
            key=lambda o: (
                str(o.get("kind") or o.get("type") or ""),
                str(o.get("object_id") or ""),
                str(o.get("created_in") or o.get("method") or ""),
            ),
        )
        for o in sorted_objs:
            existing = str(o.get("object_id") or "")
            kind = "socket"
            if existing.startswith("input:") or "input" in str(o.get("kind") or "").lower():
                kind = "input"
            elif existing.startswith("output:") or "output" in str(o.get("kind") or "").lower():
                kind = "output"
            elif existing.startswith("wrapper:") or "wrapper" in str(o.get("kind") or "").lower():
                kind = "wrapper"
            elif existing.startswith("socket:"):
                kind = "socket"
            key = f"{kind}|{existing}|{o.get('created_in') or o.get('method') or ''}"
            oid = factory.adopt(existing, key) if existing else factory.get(kind, key)
            object_records.append(
                {
                    "object_id": oid,
                    "kind": kind,
                    "raw_object_id": existing or None,
                    "classification": o.get("classification") or "FACT",
                    "provenance": _provenance(
                        apk=apk_sha256,
                        method=o.get("created_in") or o.get("method"),
                        evidence_kind="object_identity",
                        source_node_ids=[existing] if existing else [],
                    ),
                }
            )
    else:
        for oid in sorted(str(x) for x in (dataflow_path.get("objects") or []) if x):
            kind = oid.split(":")[0] if ":" in oid else "wrapper"
            factory.adopt(oid, f"{kind}|{oid}")
            object_records.append(
                {
                    "object_id": oid,
                    "kind": kind,
                    "raw_object_id": oid,
                    "classification": "FACT",
                    "provenance": _provenance(
                        apk=apk_sha256,
                        evidence_kind="object_identity",
                        source_node_ids=[oid],
                    ),
                }
            )

    # Ensure primary S/I/O exist when streams are known
    if dataflow_path.get("connect") and not any(o["kind"] == "socket" for o in object_records):
        oid = factory.get("socket", "socket|implicit|connect")
        object_records.append(
            {
                "object_id": oid,
                "kind": "socket",
                "raw_object_id": None,
                "classification": "FACT",
                "provenance": _provenance(apk=apk_sha256, evidence_kind="implicit_socket"),
            }
        )

    object_records.sort(key=lambda o: o["object_id"])
    primary_socket = next((o["object_id"] for o in object_records if o["kind"] == "socket"), None)
    primary_input = next((o["object_id"] for o in object_records if o["kind"] == "input"), None)
    primary_output = next((o["object_id"] for o in object_records if o["kind"] == "output"), None)

    # --- Canonical nodes from stages + transfers ---
    canon_nodes: dict[str, dict[str, Any]] = {}
    canon_edges: dict[str, dict[str, Any]] = {}

    def add_node(
        *,
        node_type: str,
        label: str,
        object_id: str | None = None,
        field: str | None = None,
        method: str | None = None,
        classification: str = "FACT",
        confidence: str = "high",
        raw_ids: list[str] | None = None,
        instruction: str | None = None,
        dex_file: str | None = None,
        class_name: str | None = None,
        instruction_offset: int | None = None,
    ) -> str:
        key = "|".join(
            [
                node_type,
                label,
                object_id or "",
                field or "",
                method or "",
                classification,
            ]
        )
        nid = _short_id("cnode", key)
        if nid in canon_nodes:
            existing = canon_nodes[nid]
            for rid in raw_ids or []:
                if rid not in existing["provenance"]["source_node_ids"]:
                    existing["provenance"]["source_node_ids"].append(rid)
            return nid
        canon_nodes[nid] = {
            "node_id": nid,
            "node_type": node_type if node_type in NODE_TYPES else "UNKNOWN",
            "label": label,
            "object_id": object_id,
            "field": field,
            "method": method,
            "classification": classification,
            "confidence": confidence,
            "provenance": _provenance(
                apk=apk_sha256,
                dex_file=dex_file,
                class_name=class_name,
                method=method,
                instruction_offset=instruction_offset,
                instruction=instruction,
                source_node_ids=list(raw_ids or []),
                evidence_kind="canonical_node",
            ),
        }
        return nid

    def add_edge(
        *,
        edge_type: str,
        frm: str,
        to: str,
        classification: str = "FACT",
        confidence: str = "high",
        raw_ids: list[str] | None = None,
        field: str | None = None,
        method: str | None = None,
    ) -> str:
        et = edge_type if edge_type in EDGE_TYPES else "ALIAS"
        key = "|".join([et, frm, to, field or "", method or "", classification])
        eid = _short_id("cedge", key)
        if eid in canon_edges:
            existing = canon_edges[eid]
            for rid in raw_ids or []:
                if rid not in existing["provenance"]["source_edge_ids"]:
                    existing["provenance"]["source_edge_ids"].append(rid)
            return eid
        canon_edges[eid] = {
            "edge_id": eid,
            "edge_type": et,
            "from": frm,
            "to": to,
            "field": field,
            "method": method,
            "classification": classification,
            "confidence": confidence,
            "provenance": _provenance(
                apk=apk_sha256,
                method=method,
                source_edge_ids=list(raw_ids or []),
                evidence_kind="canonical_edge",
            ),
        }
        return eid

    target = dataflow_path.get("target") or ""
    target_node = add_node(
        node_type="CALL",
        label=_method_short(target) or target,
        method=target,
        classification="FACT",
        raw_ids=[dataflow_path.get("id") or ""],
    )

    socket_creation = dataflow_path.get("socket_creation") or {}
    socket_node = add_node(
        node_type="SOCKET",
        label=socket_creation.get("method") or "createRfcommSocketToServiceRecord",
        object_id=primary_socket,
        classification=socket_creation.get("classification") or "FACT",
        confidence=socket_creation.get("confidence") or "high",
    )
    add_edge(edge_type="CALL", frm=target_node, to=socket_node, classification="FACT")

    connect = dataflow_path.get("connect")
    connect_node = None
    if connect:
        connect_node = add_node(
            node_type="CONNECT",
            label=connect.get("method") or "BluetoothSocket.connect",
            object_id=primary_socket,
            classification=connect.get("classification") or "FACT",
            confidence=connect.get("confidence") or "high",
        )
        add_edge(
            edge_type="CALL",
            frm=socket_node,
            to=connect_node,
            classification=connect.get("classification") or "FACT",
        )

    # Deduplicated transfers → field / stream nodes.
    # Prefer socket/stream field transfers; hard-cap unique transfers for RAM.
    _PRIORITY_FIELDS = ("mBtSocket", "mSocket", "mInputStream", "mOutputStream")
    seen_transfer_keys: set[str] = set()
    field_nodes: dict[str, str] = {}
    stream_get_nodes: dict[str, str] = {}
    unique_transfers: list[dict[str, Any]] = []
    for tr in sorted(transfers, key=_transfer_identity):
        tid = _transfer_identity(tr)
        if tid in seen_transfer_keys:
            continue
        seen_transfer_keys.add(tid)
        unique_transfers.append(tr)

    def _transfer_priority(tr: dict[str, Any]) -> tuple[int, str]:
        kind = (tr.get("kind") or "").lower()
        field = str(tr.get("field") or "")
        pri = 50
        if kind in {"get_input_stream", "get_output_stream"}:
            pri = 0
        elif any(f in field for f in _PRIORITY_FIELDS):
            pri = 1
        elif kind in {"field_store", "field_load"}:
            pri = 10
        elif kind in {"return", "parameter", "constructor_arg"}:
            pri = 20
        return (pri, _transfer_identity(tr))

    unique_transfers.sort(key=_transfer_priority)
    max_unique_transfers = 120
    for tr in unique_transfers[:max_unique_transfers]:
        tid = _transfer_identity(tr)
        kind = (tr.get("kind") or "").lower()
        oid = tr.get("object_id") or primary_socket
        field = tr.get("field")
        fshort = _field_short(field)
        cls = tr.get("classification") or "FACT"
        conf = tr.get("confidence") or "high"
        raw_eid = _short_id("rawtr", tid)

        if kind == "field_store" and field:
            fn = add_node(
                node_type="FIELD_WRITE",
                label=fshort or field,
                object_id=oid,
                field=field,
                method=tr.get("from_method"),
                classification=cls,
                confidence=conf,
            )
            field_nodes[f"store|{field}|{oid}"] = fn
            add_edge(
                edge_type="FIELD_STORE",
                frm=socket_node if (oid == primary_socket or not oid) else add_node(
                    node_type="OBJECT",
                    label=str(oid),
                    object_id=str(oid),
                    classification="FACT",
                ),
                to=fn,
                classification=cls,
                confidence=conf,
                field=field,
                method=tr.get("from_method"),
                raw_ids=[raw_eid],
            )
        elif kind == "field_load" and field:
            fn = add_node(
                node_type="FIELD_READ",
                label=fshort or field,
                object_id=oid,
                field=field,
                method=tr.get("to_method"),
                classification=cls,
                confidence=conf,
            )
            field_nodes[f"load|{field}|{oid}|{tr.get('to_method')}"] = fn
            store_key = f"store|{field}|{oid}"
            frm = field_nodes.get(store_key) or socket_node
            add_edge(
                edge_type="FIELD_LOAD",
                frm=frm,
                to=fn,
                classification=cls,
                confidence=conf,
                field=field,
                method=tr.get("to_method"),
                raw_ids=[raw_eid],
            )
        elif kind == "get_input_stream":
            gn = add_node(
                node_type="GET_INPUT_STREAM",
                label="BluetoothSocket.getInputStream",
                object_id=primary_input or oid,
                method=tr.get("method"),
                classification=cls,
                confidence=conf,
            )
            stream_get_nodes["input"] = gn
            src = connect_node or socket_node
            # Prefer field-load of socket field when present
            for k, nid in field_nodes.items():
                if "mBtSocket" in k or "mSocket" in k:
                    if k.startswith("load|"):
                        src = nid
                        break
            add_edge(
                edge_type="GET_INPUT_STREAM",
                frm=src,
                to=gn,
                classification=cls,
                confidence=conf,
                method=tr.get("method"),
                raw_ids=[raw_eid],
            )
        elif kind == "get_output_stream":
            gn = add_node(
                node_type="GET_OUTPUT_STREAM",
                label="BluetoothSocket.getOutputStream",
                object_id=primary_output or oid,
                method=tr.get("method"),
                classification=cls,
                confidence=conf,
            )
            stream_get_nodes["output"] = gn
            src = connect_node or socket_node
            for k, nid in field_nodes.items():
                if ("mBtSocket" in k or "mSocket" in k) and k.startswith("load|"):
                    src = nid
                    break
            add_edge(
                edge_type="GET_OUTPUT_STREAM",
                frm=src,
                to=gn,
                classification=cls,
                confidence=conf,
                method=tr.get("method"),
                raw_ids=[raw_eid],
            )

    # Explicit stream API nodes when transfers omitted them
    input_info = dataflow_path.get("input")
    if input_info and "input" not in stream_get_nodes:
        stream_get_nodes["input"] = add_node(
            node_type="GET_INPUT_STREAM",
            label=input_info.get("method") or "BluetoothSocket.getInputStream",
            object_id=primary_input,
            classification=input_info.get("classification") or "FACT",
            confidence=input_info.get("confidence") or "high",
        )
        add_edge(
            edge_type="GET_INPUT_STREAM",
            frm=connect_node or socket_node,
            to=stream_get_nodes["input"],
            classification=input_info.get("classification") or "FACT",
        )
    output_info = dataflow_path.get("output")
    if output_info and "output" not in stream_get_nodes:
        stream_get_nodes["output"] = add_node(
            node_type="GET_OUTPUT_STREAM",
            label=output_info.get("method") or "BluetoothSocket.getOutputStream",
            object_id=primary_output,
            classification=output_info.get("classification") or "FACT",
            confidence=output_info.get("confidence") or "high",
        )
        add_edge(
            edge_type="GET_OUTPUT_STREAM",
            frm=connect_node or socket_node,
            to=stream_get_nodes["output"],
            classification=output_info.get("classification") or "FACT",
        )

    # Read / write steps (deduped)
    read_nodes: list[str] = []
    write_nodes: list[str] = []
    seen_rw: set[str] = set()
    for step in dataflow_path.get("input_read_chain") or dataflow_path.get("read_chain") or []:
        sid = _step_identity(step, "read")
        if sid in seen_rw:
            continue
        seen_rw.add(sid)
        is_flush = "flush" in str(step.get("raw") or step.get("text") or "").lower()
        ntype = "FLUSH" if is_flush else "READ"
        rn = add_node(
            node_type=ntype,
            label=step.get("raw") or step.get("text") or "InputStream.read",
            object_id=step.get("object_id") or primary_input,
            method=step.get("method"),
            classification=step.get("classification") or "FACT",
            confidence=step.get("confidence") or "high",
            instruction=step.get("text"),
            instruction_offset=step.get("offset") if isinstance(step.get("offset"), int) else None,
        )
        read_nodes.append(rn)
        src = stream_get_nodes.get("input") or socket_node
        # Prefer mInputStream field load into this method
        for k, nid in field_nodes.items():
            if "mInputStream" in k and k.startswith("load|") and (
                not step.get("method") or _method_short(step.get("method")) in (k or "")
                or step.get("method") and step.get("method") in k
            ):
                src = nid
                break
        else:
            for k, nid in field_nodes.items():
                if "mInputStream" in k and k.startswith("load|"):
                    src = nid
                    break
        add_edge(
            edge_type="READS_FROM",
            frm=src,
            to=rn,
            classification=step.get("classification") or "FACT",
            confidence=step.get("confidence") or "high",
            method=step.get("method"),
            raw_ids=[_short_id("rawrw", sid)],
        )

    for step in dataflow_path.get("output_write_chain") or dataflow_path.get("write_chain") or []:
        sid = _step_identity(step, "write")
        if sid in seen_rw:
            continue
        seen_rw.add(sid)
        raw = str(step.get("raw") or step.get("text") or "")
        ntype = "FLUSH" if "flush" in raw.lower() else "WRITE"
        wn = add_node(
            node_type=ntype,
            label=raw or "OutputStream.write",
            object_id=step.get("object_id") or primary_output,
            method=step.get("method"),
            classification=step.get("classification") or "FACT",
            confidence=step.get("confidence") or "high",
            instruction=step.get("text"),
            instruction_offset=step.get("offset") if isinstance(step.get("offset"), int) else None,
        )
        write_nodes.append(wn)
        src = stream_get_nodes.get("output") or socket_node
        for k, nid in field_nodes.items():
            if "mOutputStream" in k and k.startswith("load|"):
                src = nid
                break
        add_edge(
            edge_type="WRITES_TO",
            frm=src,
            to=wn,
            classification=step.get("classification") or "FACT",
            confidence=step.get("confidence") or "high",
            method=step.get("method"),
            raw_ids=[_short_id("rawrw", sid)],
        )

    # --- Boundaries ---
    boundaries: list[dict[str, Any]] = []
    cycle_detected = False
    cycle_length = None
    if include_boundaries:
        # Deduplicate boundaries by reason+object+method
        seen_b: set[str] = set()
        for b in sorted(
            raw_boundaries,
            key=lambda x: (
                str(x.get("reason") or ""),
                str(x.get("object_id") or ""),
                str(x.get("method") or ""),
                str(x.get("field") or ""),
            ),
        ):
            reason = _norm_reason(b.get("reason"))
            if reason == "cycle_detected" or (b.get("reason") or "") == "cycle_detected":
                cycle_detected = True
                cycle_length = b.get("cycle_length") or cycle_length
            key = f"{reason}|{b.get('object_id')}|{b.get('method')}|{b.get('field')}"
            if key in seen_b:
                continue
            seen_b.add(key)
            last_proven = None
            if read_nodes:
                last_proven = canon_nodes[read_nodes[0]]["label"]
            elif write_nodes:
                last_proven = canon_nodes[write_nodes[0]]["label"]
            elif connect_node:
                last_proven = canon_nodes[connect_node]["label"]
            boundaries.append(
                {
                    "boundary_id": _short_id("bnd", key),
                    "object": b.get("object_id"),
                    "method": b.get("method"),
                    "field": b.get("field"),
                    "reason": reason,
                    "raw_reason": b.get("reason"),
                    "last_proven_node": last_proven,
                    "next_required_evidence": _next_required(reason),
                    "classification": b.get("classification") or "UNKNOWN",
                    "notes": list(b.get("notes") or [])
                    + ["Boundary reason is separate from evidence classification."],
                    "provenance": _provenance(
                        apk=apk_sha256,
                        method=b.get("method"),
                        evidence_kind="boundary",
                    ),
                }
            )

    # Cycle scan on canonical edges (simple DFS)
    if not cycle_detected:
        adj: dict[str, list[str]] = defaultdict(list)
        for e in canon_edges.values():
            adj[e["from"]].append(e["to"])
        visited: set[str] = set()
        stack: set[str] = set()

        def dfs(n: str, path: list[str]) -> bool:
            nonlocal cycle_detected, cycle_length
            visited.add(n)
            stack.add(n)
            for nxt in adj.get(n, []):
                if nxt not in visited:
                    if dfs(nxt, path + [nxt]):
                        return True
                elif nxt in stack:
                    cycle_detected = True
                    try:
                        cycle_length = len(path) - path.index(nxt) + 1
                    except ValueError:
                        cycle_length = len(path)
                    return True
            stack.remove(n)
            return False

        for n in list(canon_nodes):
            if n not in visited and dfs(n, [n]):
                break

    # --- Evidence paths ---
    evidence_paths: list[dict[str, Any]] = []

    def _path_record(
        *,
        kind: str,
        steps: list[dict[str, Any]],
        edge_ids: list[str],
        end_to_end_class: str,
        confidence: str,
        path_boundaries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        step_labels = [s["label"] for s in steps]
        pid = _short_id("epath", kind, target, *step_labels)
        ranking = _rank_path(kind, steps, path_boundaries, dataflow_path)
        # Preserve step classifications; never upgrade end-to-end from ranking
        return {
            "path_id": pid,
            "display_id": "",
            "kind": kind,
            "target": target,
            "caller_chain": list(dataflow_path.get("caller_chain") or []),
            "caller_summary": dataflow_path.get("caller_summary"),
            "steps": steps,
            "edge_ids": edge_ids,
            "objects": {
                "socket": primary_socket,
                "input": primary_input,
                "output": primary_output,
            },
            "classification": end_to_end_class,
            "confidence": confidence,
            "step_classifications": [s["classification"] for s in steps],
            "boundary": path_boundaries[0] if path_boundaries else None,
            "boundaries": path_boundaries,
            "ranking_score": ranking,
            "runtime_execution_proven": False,
            "wire_correlation_available": False,
            "protocol_semantics": "UNKNOWN",
            "method_name_semantics": method_name_semantics(
                (dataflow_path.get("caller_chain") or [None])[0]
                if dataflow_path.get("caller_chain")
                else _method_short(target)
            ),
            "cross_version_fingerprint": _stable_hash(
                kind,
                *step_labels,
                *(dataflow_path.get("caller_chain") or []),
            )[:24],
            "notes": [
                "Individual steps keep their own classifications.",
                "End-to-end path classification is INFERENCE when composed of multiple FACT steps.",
                "Ranking does not change classification.",
                "Protocol semantics remain UNKNOWN without external evidence.",
            ],
            "provenance": _provenance(
                apk=apk_sha256,
                method=target,
                source_node_ids=[s["node_id"] for s in steps],
                source_edge_ids=list(edge_ids),
                evidence_kind="evidence_path",
            ),
        }

    def _step_from_node(nid: str) -> dict[str, Any]:
        n = canon_nodes[nid]
        return {
            "node_id": nid,
            "node_type": n["node_type"],
            "label": n["label"],
            "object_id": n.get("object_id"),
            "field": n.get("field"),
            "method": n.get("method"),
            "classification": n["classification"],
            "confidence": n["confidence"],
        }

    # Socket path
    socket_steps = [_step_from_node(socket_node)]
    socket_edges: list[str] = []
    # field store mBtSocket / mSocket
    for k, nid in sorted(field_nodes.items()):
        if k.startswith("store|") and ("mBtSocket" in k or "mSocket" in k):
            socket_steps.append(_step_from_node(nid))
            break
    if connect_node:
        socket_steps.append(_step_from_node(connect_node))
    evidence_paths.append(
        _path_record(
            kind="SOCKET_PATH",
            steps=socket_steps,
            edge_ids=socket_edges,
            end_to_end_class="INFERENCE" if len(socket_steps) > 1 else (socket_steps[0]["classification"]),
            confidence="medium" if len(socket_steps) > 1 else "high",
            path_boundaries=[],
        )
    )

    # Input path
    if stream_get_nodes.get("input") or read_nodes:
        steps = [_step_from_node(socket_node)]
        if connect_node:
            steps.append(_step_from_node(connect_node))
        if stream_get_nodes.get("input"):
            steps.append(_step_from_node(stream_get_nodes["input"]))
        for k, nid in sorted(field_nodes.items()):
            if "mInputStream" in k and k.startswith("store|"):
                steps.append(_step_from_node(nid))
                break
        for k, nid in sorted(field_nodes.items()):
            if "mInputStream" in k and k.startswith("load|"):
                steps.append(_step_from_node(nid))
                break
        if read_nodes:
            # one representative read
            steps.append(_step_from_node(read_nodes[0]))
        in_bounds = [b for b in boundaries if (b.get("object") or "").startswith("input:")]
        evidence_paths.append(
            _path_record(
                kind="INPUT_PATH",
                steps=steps,
                edge_ids=[],
                end_to_end_class="INFERENCE",
                confidence="medium" if read_nodes else "low",
                path_boundaries=in_bounds[:3],
            )
        )

    # Output path
    if stream_get_nodes.get("output") or write_nodes:
        steps = [_step_from_node(socket_node)]
        if connect_node:
            steps.append(_step_from_node(connect_node))
        if stream_get_nodes.get("output"):
            steps.append(_step_from_node(stream_get_nodes["output"]))
        for k, nid in sorted(field_nodes.items()):
            if "mOutputStream" in k and k.startswith("store|"):
                steps.append(_step_from_node(nid))
                break
        for k, nid in sorted(field_nodes.items()):
            if "mOutputStream" in k and k.startswith("load|"):
                steps.append(_step_from_node(nid))
                break
        if write_nodes:
            steps.append(_step_from_node(write_nodes[0]))
        out_bounds = [b for b in boundaries if (b.get("object") or "").startswith("output:")]
        evidence_paths.append(
            _path_record(
                kind="OUTPUT_PATH",
                steps=steps,
                edge_ids=[],
                end_to_end_class="INFERENCE",
                confidence="medium" if write_nodes else "low",
                path_boundaries=out_bounds[:3],
            )
        )

    # Combined communication path
    if (stream_get_nodes.get("input") or read_nodes) and (stream_get_nodes.get("output") or write_nodes):
        steps = [_step_from_node(socket_node)]
        if connect_node:
            steps.append(_step_from_node(connect_node))
        if stream_get_nodes.get("input"):
            steps.append(_step_from_node(stream_get_nodes["input"]))
        if read_nodes:
            steps.append(_step_from_node(read_nodes[0]))
        if stream_get_nodes.get("output"):
            steps.append(_step_from_node(stream_get_nodes["output"]))
        if write_nodes:
            steps.append(_step_from_node(write_nodes[0]))
        evidence_paths.append(
            _path_record(
                kind="COMBINED_COMMUNICATION_PATH",
                steps=steps,
                edge_ids=[],
                end_to_end_class="INFERENCE",
                confidence="medium",
                path_boundaries=boundaries[:5],
            )
        )

    # Deterministic ranking order
    evidence_paths.sort(
        key=lambda p: (-int(p["ranking_score"]), p["kind"], p["path_id"])
    )

    raw_counts = {
        "nodes": len(raw_nodes),
        "edges": len(raw_edges),
        "transfers": len(transfers),
        "boundaries": len(raw_boundaries),
    }
    canonical_nodes = [canon_nodes[k] for k in sorted(canon_nodes)]
    canonical_edges = [canon_edges[k] for k in sorted(canon_edges)]

    return {
        "source_dataflow_id": dataflow_path.get("id"),
        "source_display_id": dataflow_path.get("display_id"),
        "target": target,
        "raw": raw_counts,
        "canonical": {
            "objects": object_records,
            "nodes": canonical_nodes,
            "edges": canonical_edges,
            "object_count": len(object_records),
            "node_count": len(canonical_nodes),
            "edge_count": len(canonical_edges),
        },
        "evidence_paths": evidence_paths,
        "boundaries": boundaries,
        "cycle_detected": cycle_detected,
        "cycle_length": cycle_length,
        "caller_summary": dataflow_path.get("caller_summary"),
        "classification": dataflow_path.get("classification") or "INFERENCE",
        "confidence": dataflow_path.get("confidence") or "medium",
        "runtime_execution_proven": False,
        "wire_correlation_available": False,
        "protocol_semantics": "UNKNOWN",
    }


def _next_required(reason: str) -> str:
    return {
        "max_method_hops": "increase max_method_hops or stop at boundary",
        "max_field_hops": "increase max_field_hops or stop at boundary",
        "max_object_nodes": "increase max_object_nodes or stop at boundary",
        "max_dataflow_nodes": "increase max_dataflow_nodes or stop at boundary",
        "return_no_move_result": "returned object / move-result / parameter / field alias",
        "parameter_unresolved": "callee parameter binding evidence",
        "field_alias_unresolved": "field alias / store-load identity evidence",
        "constructor_unresolved": "constructor argument retention evidence",
        "wrapper_unresolved": "wrapper construction / wrappee identity",
        "cycle_detected": "acyclic continuation (cycle already recorded)",
        "instruction_context_unavailable": "DEX instruction context",
        "unsupported_pattern": "supported transfer pattern",
    }.get(reason, "additional static evidence")


def _rank_path(
    kind: str,
    steps: list[dict[str, Any]],
    boundaries: list[dict[str, Any]],
    dataflow_path: dict[str, Any],
) -> int:
    score = 0
    types = {s["node_type"] for s in steps}
    if "CONNECT" in types:
        score += 20
    if "GET_INPUT_STREAM" in types:
        score += 15
    if "GET_OUTPUT_STREAM" in types:
        score += 15
    if "READ" in types:
        score += 25
    if "WRITE" in types or "FLUSH" in types:
        score += 25
    if "FIELD_WRITE" in types:
        score += 10
    if "FIELD_READ" in types:
        score += 10
    if kind == "COMBINED_COMMUNICATION_PATH":
        score += 30
    if kind == "INPUT_PATH":
        score += 8
    if kind == "OUTPUT_PATH":
        score += 8
    # Prefer FACT steps
    score += sum(5 for s in steps if s.get("classification") == "FACT")
    # Penalize many boundaries / truncations
    score -= 3 * len(boundaries)
    cs = dataflow_path.get("caller_summary") or {}
    if isinstance(cs, dict):
        score -= 2 * int(cs.get("truncated") or 0)
        if int(cs.get("direct_callers") or 0) == 1:
            score += 5
        chain = dataflow_path.get("caller_chain") or []
        if 0 < len(chain) <= 3:
            score += 4
    return score


def build_evidence_graph(
    *,
    dataflow_paths: list[dict[str, Any]],
    apk_sha256: str | None = None,
    package_name: str | None = None,
    enabled: bool = True,
    canonicalize: bool = True,
    deduplicate: bool = True,
    extract_paths: bool = True,
    include_boundaries: bool = True,
    max_evidence_paths: int = 50,
) -> dict[str, Any]:
    """Aggregate evidence graphs across all BluetoothDataflowPaths."""
    if not enabled:
        return empty_evidence_graph(enabled=False)

    per_target: list[dict[str, Any]] = []
    all_paths: list[dict[str, Any]] = []
    raw_nodes = raw_edges = raw_transfers = 0
    canon_nodes = canon_edges = canon_objects = 0
    all_boundaries: list[dict[str, Any]] = []

    for df in dataflow_paths:
        if not canonicalize:
            continue
        eg = build_evidence_graph_for_path(
            df,
            apk_sha256=apk_sha256,
            include_boundaries=include_boundaries,
        )
        # deduplicate flag currently applied inside path builder via transfer keys
        if not deduplicate:
            pass
        per_target.append(eg)
        raw_nodes += eg["raw"]["nodes"]
        raw_edges += eg["raw"]["edges"]
        raw_transfers += eg["raw"]["transfers"]
        canon_nodes += eg["canonical"]["node_count"]
        canon_edges += eg["canonical"]["edge_count"]
        canon_objects += eg["canonical"]["object_count"]
        all_boundaries.extend(eg.get("boundaries") or [])
        if extract_paths:
            all_paths.extend(eg.get("evidence_paths") or [])

    # Global deterministic ranking + display IDs
    all_paths.sort(key=lambda p: (-int(p.get("ranking_score") or 0), p.get("kind") or "", p.get("path_id") or ""))
    # Deduplicate identical evidence paths by fingerprint
    if deduplicate:
        seen_fp: set[str] = set()
        unique: list[dict[str, Any]] = []
        for p in all_paths:
            fp = p.get("cross_version_fingerprint") or p.get("path_id")
            if fp in seen_fp:
                # keep provenance by merging source ids into first
                continue
            seen_fp.add(fp)
            unique.append(p)
        all_paths = unique

    all_paths = all_paths[: max(0, max_evidence_paths)]
    for idx, p in enumerate(all_paths, start=1):
        p["display_id"] = f"PATH-{idx:06d}"

    from apk_forensics.coverage_analysis import annotate_paths as _annotate_coverage_paths

    all_paths, transport_coverage = _annotate_coverage_paths(all_paths)

    strongest = all_paths[0] if all_paths else None
    input_paths = [p for p in all_paths if p["kind"] == "INPUT_PATH"]
    output_paths = [p for p in all_paths if p["kind"] == "OUTPUT_PATH"]
    combined = [p for p in all_paths if p["kind"] == "COMBINED_COMMUNICATION_PATH"]

    # Cross-version comparison scaffold (no semantic equality from names)
    cross_version = {
        "schema": "apk_forensics.cross_version_evidence.v0",
        "package_name": package_name,
        "apk_sha256": apk_sha256,
        "comparable": {
            "rfcomm_targets": None,  # filled by caller
            "uuid_resolutions": None,
            "bluetooth_paths": None,
            "caller_paths": None,
            "canonical_socket_objects": sum(
                1
                for eg in per_target
                for o in eg["canonical"]["objects"]
                if o.get("kind") == "socket"
            ),
            "input_consumers": len(input_paths),
            "output_producers": len(output_paths),
            "communication_paths": len(combined) + len(input_paths) + len(output_paths),
            "boundaries": len(all_boundaries),
            "path_fingerprints": [p.get("cross_version_fingerprint") for p in all_paths],
        },
        "diff_status_vocabulary": ["ADDED", "REMOVED", "UNCHANGED", "CHANGED"],
        "notes": [
            "Fingerprints compare canonical path structure, not method-name semantics.",
            "Use class+method+descriptor+path structure for cross-APK comparison.",
        ],
    }

    # Slim per-target payloads for report size / RAM (full graphs stay reconstructible).
    slim_targets: list[dict[str, Any]] = []
    for eg in per_target:
        slim_targets.append(
            {
                "source_dataflow_id": eg.get("source_dataflow_id"),
                "source_display_id": eg.get("source_display_id"),
                "target": eg.get("target"),
                "raw": eg.get("raw"),
                "canonical": {
                    "object_count": eg.get("canonical", {}).get("object_count"),
                    "node_count": eg.get("canonical", {}).get("node_count"),
                    "edge_count": eg.get("canonical", {}).get("edge_count"),
                    "objects": eg.get("canonical", {}).get("objects"),
                },
                "evidence_path_ids": [p.get("path_id") for p in eg.get("evidence_paths") or []],
                "boundaries": eg.get("boundaries"),
                "cycle_detected": eg.get("cycle_detected"),
                "cycle_length": eg.get("cycle_length"),
                "classification": eg.get("classification"),
                "confidence": eg.get("confidence"),
                "protocol_semantics": eg.get("protocol_semantics"),
            }
        )

    return {
        "enabled": True,
        "schema": "apk_forensics.evidence_graph.v0",
        "configuration": {
            "canonicalize": canonicalize,
            "deduplicate": deduplicate,
            "extract_paths": extract_paths,
            "include_boundaries": include_boundaries,
            "max_evidence_paths": max_evidence_paths,
        },
        "raw": {
            "nodes": raw_nodes,
            "edges": raw_edges,
            "transfers": raw_transfers,
        },
        "canonical": {
            "objects": canon_objects,
            "nodes": canon_nodes,
            "edges": canon_edges,
            "paths": len(all_paths),
        },
        "evidence_paths": all_paths,
        "boundaries": _dedupe_boundaries(all_boundaries)[:200],
        "per_target": slim_targets,
        "summary": {
            "evidence_paths": len(all_paths),
            "socket_paths": sum(1 for p in all_paths if p["kind"] == "SOCKET_PATH"),
            "input_paths": len(input_paths),
            "output_paths": len(output_paths),
            "combined_communication_paths": len(combined),
            "boundaries": len(_dedupe_boundaries(all_boundaries)),
            "strongest_path_id": (strongest or {}).get("display_id"),
            "strongest_path_kind": (strongest or {}).get("kind"),
            "strongest_classification": (strongest or {}).get("classification"),
            "strongest_confidence": (strongest or {}).get("confidence"),
            "runtime_execution": "UNKNOWN",
            "wire_correlation": "UNKNOWN",
            "protocol_semantics": "UNKNOWN",
            "coverage": {
                "complete": transport_coverage.get("complete"),
                "truncated": transport_coverage.get("truncated"),
                "boundary": transport_coverage.get("boundary"),
                "unresolved": transport_coverage.get("unresolved"),
                "no_continuation": transport_coverage.get("no_continuation"),
                "primary_truncation": transport_coverage.get("primary_truncation"),
                "primary_boundary": transport_coverage.get("primary_boundary"),
            },
        },
        "coverage": transport_coverage,
        "cross_version_evidence": cross_version,
        "limitations": [
            "Raw graph counts are not communication-operation counts.",
            "Canonical graph is a bounded deduplication of static evidence only.",
            "End-to-end paths are INFERENCE even when every step is FACT.",
            "No protocol semantics from method names.",
            "No runtime or wire proof.",
            "Coverage status does not reclassify FACT/INFERENCE/UNKNOWN.",
        ],
    }


def _dedupe_boundaries(boundaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for b in sorted(
        boundaries,
        key=lambda x: (
            str(x.get("reason") or ""),
            str(x.get("object") or ""),
            str(x.get("method") or ""),
            str(x.get("boundary_id") or ""),
        ),
    ):
        key = f"{b.get('reason')}|{b.get('object')}|{b.get('method')}|{b.get('field')}"
        if key in seen:
            continue
        seen.add(key)
        out.append(b)
    return out


def empty_evidence_graph(*, enabled: bool = False) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "schema": "apk_forensics.evidence_graph.v0",
        "configuration": {},
        "raw": {"nodes": 0, "edges": 0, "transfers": 0},
        "canonical": {"objects": 0, "nodes": 0, "edges": 0, "paths": 0},
        "evidence_paths": [],
        "boundaries": [],
        "per_target": [],
        "summary": {
            "evidence_paths": 0,
            "socket_paths": 0,
            "input_paths": 0,
            "output_paths": 0,
            "combined_communication_paths": 0,
            "boundaries": 0,
            "strongest_path_id": None,
            "strongest_path_kind": None,
            "strongest_classification": None,
            "strongest_confidence": None,
            "runtime_execution": "UNKNOWN",
            "wire_correlation": "UNKNOWN",
            "protocol_semantics": "UNKNOWN",
        },
        "cross_version_evidence": {
            "schema": "apk_forensics.cross_version_evidence.v0",
            "diff_status_vocabulary": ["ADDED", "REMOVED", "UNCHANGED", "CHANGED"],
        },
        "limitations": [],
    }


def compare_cross_version(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    """Prepare ADDED/REMOVED/UNCHANGED/CHANGED over comparable fingerprints."""
    lc = (left.get("cross_version_evidence") or {}).get("comparable") or {}
    rc = (right.get("cross_version_evidence") or {}).get("comparable") or {}
    lf = set(lc.get("path_fingerprints") or [])
    rf = set(rc.get("path_fingerprints") or [])
    metrics = [
        "rfcomm_targets",
        "uuid_resolutions",
        "bluetooth_paths",
        "caller_paths",
        "canonical_socket_objects",
        "input_consumers",
        "output_producers",
        "communication_paths",
        "boundaries",
    ]
    metric_diff = {}
    for m in metrics:
        a, b = lc.get(m), rc.get(m)
        if a is None and b is None:
            metric_diff[m] = "UNCHANGED"
        elif a == b:
            metric_diff[m] = "UNCHANGED"
        elif a is None:
            metric_diff[m] = "ADDED"
        elif b is None:
            metric_diff[m] = "REMOVED"
        else:
            metric_diff[m] = "CHANGED"
    return {
        "schema": "apk_forensics.cross_version_diff.v0",
        "metrics": metric_diff,
        "path_fingerprints": {
            "ADDED": sorted(rf - lf),
            "REMOVED": sorted(lf - rf),
            "UNCHANGED": sorted(lf & rf),
        },
        "notes": [
            "Comparison is structural only; method names do not imply protocol equality.",
        ],
    }
