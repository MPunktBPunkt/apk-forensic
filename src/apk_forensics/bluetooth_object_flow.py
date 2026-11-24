"""Bounded interprocedural BluetoothSocket / stream object-flow tracking (v0.8)."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from apk_forensics.bluetooth_callers import find_direct_callers
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo


WRAPPER_TYPES = (
    "BufferedInputStream",
    "BufferedOutputStream",
    "DataInputStream",
    "DataOutputStream",
    "InputStreamReader",
    "OutputStreamWriter",
)
INPUT_TYPES = ("InputStream", "BufferedInput", "DataInput", "Reader") + WRAPPER_TYPES
OUTPUT_TYPES = ("OutputStream", "BufferedOutput", "DataOutput", "Writer", "PrintWriter") + WRAPPER_TYPES

BOUNDARY_NOTE = "Cross-method object-flow boundary; static evidence ends here."


def _method_key(method: MethodInfo) -> str:
    return f"{method.class_name}->{method.method_name}{method.method_descriptor}"


def _node_id(*parts: str) -> str:
    return "btnode-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _field_key(raw: str | None) -> str | None:
    if not raw:
        return None
    m = re.match(r"(L[^;]+;->[^\s:]+)", raw.strip())
    return m.group(1) if m else raw.strip()


def _regs(ins: InstructionInfo) -> list[str]:
    if ins.registers:
        return list(ins.registers)
    return re.findall(r"\bv\d+\b", ins.text)


def _result_reg_after(method: MethodInfo, invoke_index: int) -> str | None:
    nxt = invoke_index + 1
    if nxt >= len(method.instructions):
        return None
    ins = method.instructions[nxt]
    if not ins.opcode.startswith("move-result"):
        return None
    regs = _regs(ins)
    return regs[0] if regs else None


def _make_node(
    *,
    node_type: str,
    method: MethodInfo | None,
    operation: str | None,
    classification: str,
    confidence: str,
    register: str | None = None,
    field_name: str | None = None,
    instruction_index: int | None = None,
    instruction_offset: int | None = None,
    object_id: str | None = None,
    value: str | None = None,
) -> dict[str, Any]:
    mid = _method_key(method) if method else None
    nid = _node_id(
        node_type,
        mid or "",
        operation or "",
        register or "",
        field_name or "",
        str(instruction_index),
        object_id or "",
    )
    return {
        "node_id": nid,
        "node_type": node_type,
        "artifact": None,
        "dex_entry": method.dex_entry if method else None,
        "class_name": method.class_name if method else None,
        "method_name": method.method_name if method else None,
        "method_descriptor": method.method_descriptor if method else None,
        "method": mid,
        "register": register,
        "field": field_name,
        "instruction_index": instruction_index,
        "instruction_offset": instruction_offset,
        "operation": operation,
        "object_id": object_id,
        "value": value or operation,
        "classification": classification,
        "confidence": confidence,
    }


def _edge(from_id: str, to_id: str, relationship: str, classification: str = "FACT", confidence: str = "high") -> dict[str, Any]:
    return {
        "from": from_id,
        "to": to_id,
        "relationship": relationship,
        "classification": classification,
        "confidence": confidence,
    }


@dataclass
class _ObjectRec:
    object_id: str
    kind: str  # SOCKET | INPUT_STREAM | OUTPUT_STREAM | WRAPPER
    wrapper_type: str | None = None
    origin_method: str | None = None


@dataclass
class _State:
    object_id: str
    method: MethodInfo
    register: str | None
    field_name: str | None
    start_index: int
    method_hops: int
    field_hops: int
    via: str  # local | return | parameter | field | constructor
    # Distinct fields already traversed for this object identity (order preserved).
    # Same-field re-store/load is alias continuation and does NOT consume a hop.
    field_chain: tuple[str, ...] = ()


@dataclass
class _Engine:
    by_key: dict[str, MethodInfo]
    by_class: dict[str, list[MethodInfo]]
    max_method_hops: int
    max_field_hops: int
    max_object_nodes: int
    window: int
    objects: dict[str, _ObjectRec] = field(default_factory=dict)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    transfers: list[dict[str, Any]] = field(default_factory=list)
    read_chain: list[dict[str, Any]] = field(default_factory=list)
    write_chain: list[dict[str, Any]] = field(default_factory=list)
    boundaries: list[dict[str, Any]] = field(default_factory=list)
    seen_states: set[tuple] = field(default_factory=set)
    object_counter: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    node_index: dict[str, dict[str, Any]] = field(default_factory=dict)
    object_nodes: dict[str, str] = field(default_factory=dict)  # object_id -> node_id
    queue: deque = field(default_factory=deque)

    def new_object(self, kind: str, *, origin_method: str | None = None, wrapper_type: str | None = None) -> str:
        prefix = {"SOCKET": "S", "INPUT_STREAM": "I", "OUTPUT_STREAM": "O", "WRAPPER": "W"}.get(kind, "X")
        self.object_counter[prefix] += 1
        oid = f"{kind.lower().split('_')[0] if kind != 'WRAPPER' else 'wrapper'}:{prefix}{self.object_counter[prefix]}"
        if kind == "SOCKET":
            oid = f"socket:S{self.object_counter[prefix]}"
        elif kind == "INPUT_STREAM":
            oid = f"input:I{self.object_counter[prefix]}"
        elif kind == "OUTPUT_STREAM":
            oid = f"output:O{self.object_counter[prefix]}"
        elif kind == "WRAPPER":
            oid = f"wrapper:W{self.object_counter[prefix]}"
        self.objects[oid] = _ObjectRec(oid, kind, wrapper_type=wrapper_type, origin_method=origin_method)
        return oid

    def add_node(self, node: dict[str, Any]) -> str:
        if len(self.nodes) >= self.max_object_nodes:
            return node["node_id"]
        nid = node["node_id"]
        if nid not in self.node_index:
            self.nodes.append(node)
            self.node_index[nid] = node
        return nid

    def add_edge(self, edge: dict[str, Any]) -> None:
        key = (edge["from"], edge["to"], edge["relationship"])
        if any((e["from"], e["to"], e["relationship"]) == key for e in self.edges):
            return
        self.edges.append(edge)

    def state_key(self, st: _State) -> tuple:
        # Include start_index so reloads of the same field mid-method (e.g. mBtSocket
        # reloaded after getInputStream register reuse) are not collapsed.
        return (
            st.object_id,
            _method_key(st.method),
            st.register or "",
            st.field_name or "",
            st.start_index,
            st.method_hops,
            st.field_hops,
            st.via,
            st.field_chain,
        )


def _is_stream_read(name: str, raw: str) -> bool:
    if name not in {"read", "available"}:
        return False
    return any(t in raw for t in INPUT_TYPES)


def _is_stream_write(name: str, raw: str) -> bool:
    if name not in {"write", "flush", "print", "println"}:
        return False
    return any(t in raw for t in OUTPUT_TYPES)


def _wrapper_from_raw(raw: str) -> str | None:
    for w in WRAPPER_TYPES:
        if w in raw:
            return w
    return None


def _find_field_loaders(methods: list[MethodInfo], field_key: str) -> list[tuple[MethodInfo, int]]:
    hits: list[tuple[MethodInfo, int]] = []
    for method in methods:
        for ins in method.instructions:
            if not (ins.opcode.startswith("iget") or ins.opcode.startswith("sget")):
                continue
            if _field_key(ins.referenced_field) == field_key:
                hits.append((method, ins.index))
    return hits


def _callee_lookup(by_key: dict[str, MethodInfo], by_class: dict[str, list[MethodInfo]], raw: str | None) -> MethodInfo | None:
    if not raw or "->" not in raw:
        return None
    # Exact key match first
    compact = re.sub(r"\s+", "", raw)
    if compact in by_key:
        return by_key[compact]
    m = re.match(r"(L[^;]+;)->([^(]+)\(([^)]*)\)(.+)", compact)
    if not m:
        return None
    class_name, name, params, ret = m.groups()
    descriptor = f"({params}){ret}"
    key = f"{class_name}->{name}{descriptor}"
    if key in by_key:
        return by_key[key]
    # Fallback: unique name match in class
    candidates = [
        meth
        for meth in by_class.get(class_name, [])
        if meth.method_name == name and meth.method_descriptor == descriptor
    ]
    return candidates[0] if len(candidates) == 1 else None


def _param_register_for_arg(callee: MethodInfo, arg_position: int) -> str | None:
    """Map invoke argument position to likely callee register (simple instance heuristic)."""
    # Instance methods: v0=this, v1=first arg, ...
    # Static: v0=first arg. We cannot know access flags reliably always; prefer instance.
    is_static = "static" in (callee.access_flags or [])
    base = 0 if is_static else 1
    return f"v{base + arg_position}"


def _scan_method(engine: _Engine, st: _State) -> None:
    method = st.method
    obj = engine.objects.get(st.object_id)
    if not obj:
        return
    active_reg = st.register
    end = len(method.instructions)
    # Bound local scan window when entering mid-method via create/getStream
    if st.via == "local" and st.start_index >= 0:
        end = min(len(method.instructions), st.start_index + max(engine.window * 3, 24))

    for idx in range(st.start_index, end):
        if len(engine.nodes) >= engine.max_object_nodes:
            engine.boundaries.append(
                {
                    "reason": "max_object_nodes",
                    "method": _method_key(method),
                    "object_id": st.object_id,
                    "classification": "UNKNOWN",
                }
            )
            return
        ins = method.instructions[idx]
        regs = _regs(ins)
        opcode = ins.opcode

        # Register aliases (proven move-object only — same type ≠ alias)
        if active_reg and opcode.startswith("move-object") and len(regs) >= 2:
            if regs[1] == active_reg:
                active_reg = regs[0]
            continue

        # Register overwrite by later move-result → local identity ends.
        # Skip the entry move-result that defines this state's register (idx == start_index).
        if (
            active_reg
            and opcode.startswith("move-result")
            and regs
            and regs[0] == active_reg
            and idx > st.start_index
        ):
            engine.transfers.append(
                {
                    "kind": "register_overwrite",
                    "object_id": st.object_id,
                    "register": active_reg,
                    "method": _method_key(method),
                    "classification": "FACT",
                    "confidence": "high",
                    "instruction_index": idx,
                    "notes": [
                        "Tracked register overwritten; local alias ends "
                        "(UNKNOWN_ALIAS for later same-typed values in this register)."
                    ],
                }
            )
            active_reg = None
            continue

        # Return flow
        if active_reg and opcode.startswith("return") and regs and regs[0] == active_reg:
            n_ret = engine.add_node(
                _make_node(
                    node_type="RETURN",
                    method=method,
                    operation="return-object",
                    classification="FACT",
                    confidence="high",
                    register=active_reg,
                    instruction_index=idx,
                    instruction_offset=ins.offset,
                    object_id=st.object_id,
                )
            )
            engine.transfers.append(
                {
                    "kind": "return",
                    "object_id": st.object_id,
                    "from_method": _method_key(method),
                    "classification": "FACT",
                    "confidence": "high",
                    "instruction_index": idx,
                }
            )
            if st.method_hops >= engine.max_method_hops:
                engine.boundaries.append(
                    {
                        "reason": "max_method_hops",
                        "at": "return",
                        "method": _method_key(method),
                        "object_id": st.object_id,
                        "classification": "UNKNOWN",
                        "notes": [BOUNDARY_NOTE],
                    }
                )
                continue
            callers = find_direct_callers(method, list(engine.by_key.values()), max_callers=20)
            if not callers:
                engine.boundaries.append(
                    {
                        "reason": "return_no_callers",
                        "method": _method_key(method),
                        "object_id": st.object_id,
                        "classification": "UNKNOWN",
                        "notes": [BOUNDARY_NOTE, "return-object found but no static callers in retained set."],
                    }
                )
                continue
            for caller in callers:
                caller_m = engine.by_key.get(caller["method"])
                if caller_m is None:
                    continue
                # Find invoke index + move-result register
                for cins in caller_m.instructions:
                    if not cins.opcode.startswith("invoke"):
                        continue
                    raw = (cins.referenced_method or {}).get("raw") or ""
                    if method.method_name not in (cins.text + raw):
                        continue
                    if f"->{method.method_name}(" not in cins.text and f"->{method.method_name}(" not in raw:
                        continue
                    result_reg = _result_reg_after(caller_m, cins.index)
                    if not result_reg:
                        engine.boundaries.append(
                            {
                                "reason": "return_no_move_result",
                                "method": _method_key(caller_m),
                                "object_id": st.object_id,
                                "classification": "UNKNOWN",
                                "notes": [BOUNDARY_NOTE],
                            }
                        )
                        continue
                    n_caller = engine.add_node(
                        _make_node(
                            node_type="METHOD_CALL",
                            method=caller_m,
                            operation="move-result-object",
                            classification="FACT",
                            confidence="high",
                            register=result_reg,
                            instruction_index=cins.index + 1,
                            instruction_offset=None,
                            object_id=st.object_id,
                        )
                    )
                    engine.add_edge(_edge(n_ret, n_caller, "RETURN"))
                    yield_state = _State(
                        object_id=st.object_id,
                        method=caller_m,
                        register=result_reg,
                        field_name=None,
                        start_index=cins.index + 1,
                        method_hops=st.method_hops + 1,
                        field_hops=st.field_hops,
                        via="return",
                        field_chain=st.field_chain,
                    )
                    _enqueue(engine, yield_state)
            continue

        # Field store (iput/sput). field_hops counts distinct nested field edges for this
        # object identity — NOT every re-store of the same field (alias continuation).
        if active_reg and (opcode.startswith("iput") or opcode.startswith("sput")) and regs and regs[0] == active_reg:
            fkey = _field_key(ins.referenced_field)
            is_static = opcode.startswith("sput")
            n_store = engine.add_node(
                _make_node(
                    node_type="FIELD_WRITE",
                    method=method,
                    operation=opcode,
                    classification="FACT",
                    confidence="high",
                    register=active_reg,
                    field_name=fkey,
                    instruction_index=idx,
                    instruction_offset=ins.offset,
                    object_id=st.object_id,
                )
            )
            engine.transfers.append(
                {
                    "kind": "field_store",
                    "object_id": st.object_id,
                    "field": fkey,
                    "static_field": is_static,
                    "from_method": _method_key(method),
                    "classification": "FACT",
                    "confidence": "high",
                    "instruction_index": idx,
                    "field_hops_before": st.field_hops,
                    "field_chain_before": list(st.field_chain),
                }
            )
            if not fkey:
                continue

            last_field = st.field_chain[-1] if st.field_chain else st.field_name
            same_field_continuation = fkey == last_field or fkey == st.field_name
            cycle = bool(st.field_chain) and fkey in st.field_chain and not same_field_continuation
            if cycle:
                engine.boundaries.append(
                    {
                        "reason": "cycle",
                        "field": fkey,
                        "method": _method_key(method),
                        "object_id": st.object_id,
                        "classification": "UNKNOWN",
                        "notes": [
                            BOUNDARY_NOTE,
                            "Field re-entered earlier in the distinct-field chain (CYCLE_GUARD).",
                        ],
                        "field_chain": list(st.field_chain),
                    }
                )
                continue

            if same_field_continuation:
                next_hops = st.field_hops
                next_chain = st.field_chain if st.field_chain else ((fkey,) if fkey else ())
                hop_kind = "same_field_alias"
            else:
                next_hops = st.field_hops + 1
                next_chain = st.field_chain + (fkey,)
                hop_kind = "new_field"

            if next_hops > engine.max_field_hops:
                engine.boundaries.append(
                    {
                        "reason": "max_field_hops",
                        "field": fkey,
                        "method": _method_key(method),
                        "object_id": st.object_id,
                        "classification": "UNKNOWN",
                        "notes": [BOUNDARY_NOTE],
                        "field_hops": st.field_hops,
                        "next_field_hops": next_hops,
                        "field_chain": list(st.field_chain),
                        "hop_kind": hop_kind,
                    }
                )
                continue
            # Prefer same-class loaders (esp. read/write), then bounded external loaders.
            class_methods = engine.by_class.get(method.class_name, [])
            loaders = _find_field_loaders(class_methods, fkey)

            def _loader_priority(item: tuple[MethodInfo, int]) -> tuple[int, str]:
                meth, _idx = item
                name = meth.method_name.lower()
                if name in {"read", "write", "available", "flush", "close"}:
                    return (0, name)
                if name.startswith("get") or name.startswith("set"):
                    return (1, name)
                return (2, name)

            loaders = sorted(loaders, key=_loader_priority)
            if len(loaders) < 8:
                extra = _find_field_loaders(list(engine.by_key.values()), fkey)
                seen_loader = {(_method_key(m), i) for m, i in loaders}
                for item in sorted(extra, key=_loader_priority):
                    key = (_method_key(item[0]), item[1])
                    if key in seen_loader:
                        continue
                    loaders.append(item)
                    seen_loader.add(key)
                    if len(loaders) >= 12:
                        break
            if not loaders:
                engine.boundaries.append(
                    {
                        "reason": "field_no_loaders",
                        "field": fkey,
                        "method": _method_key(method),
                        "object_id": st.object_id,
                        "classification": "UNKNOWN",
                        "notes": [BOUNDARY_NOTE, "Field store found; no iget/sget in retained methods."],
                    }
                )
                continue
            for loader_m, load_idx in loaders[:12]:
                dest = _regs(loader_m.instructions[load_idx])
                dest_reg = dest[0] if dest else None
                n_load = engine.add_node(
                    _make_node(
                        node_type="FIELD_READ",
                        method=loader_m,
                        operation="iget/sget",
                        classification="FACT",
                        confidence="high",
                        register=dest_reg,
                        field_name=fkey,
                        instruction_index=load_idx,
                        instruction_offset=loader_m.instructions[load_idx].offset,
                        object_id=st.object_id,
                    )
                )
                engine.add_edge(_edge(n_store, n_load, "FIELD_LOAD"))
                engine.transfers.append(
                    {
                        "kind": "field_load",
                        "object_id": st.object_id,
                        "field": fkey,
                        "static_field": is_static or loader_m.instructions[load_idx].opcode.startswith("sget"),
                        "to_method": _method_key(loader_m),
                        "classification": "FACT",
                        "confidence": "high",
                        "instruction_index": load_idx,
                        "field_hops_after": next_hops,
                        "hop_kind": hop_kind,
                        "field_chain": list(next_chain),
                    }
                )
                if dest_reg:
                    _enqueue(
                        engine,
                        _State(
                            object_id=st.object_id,
                            method=loader_m,
                            register=dest_reg,
                            field_name=fkey,
                            start_index=load_idx + 1,
                            method_hops=st.method_hops,
                            field_hops=next_hops,
                            via="field",
                            field_chain=next_chain,
                        ),
                    )
            continue

        if not opcode.startswith("invoke"):
            continue

        ref = ins.referenced_method or {}
        name = ref.get("method_name") or ""
        raw = (ref.get("raw") or "") + ins.text
        recv = regs[0] if regs else None

        # API on tracked receiver
        if active_reg and recv == active_reg:
            if name == "connect" and "BluetoothSocket" in raw and obj.kind == "SOCKET":
                n = engine.add_node(
                    _make_node(
                        node_type="METHOD_CALL",
                        method=method,
                        operation="BluetoothSocket.connect",
                        classification="FACT",
                        confidence="high",
                        register=active_reg,
                        instruction_index=idx,
                        instruction_offset=ins.offset,
                        object_id=st.object_id,
                    )
                )
                sock_node = engine.object_nodes.get(st.object_id)
                if sock_node:
                    engine.add_edge(_edge(sock_node, n, "CALL", "FACT"))
                continue
            elif name == "getInputStream" and "BluetoothSocket" in raw and obj.kind == "SOCKET":
                result = _result_reg_after(method, idx)
                in_id = engine.new_object("INPUT_STREAM", origin_method=_method_key(method))
                n_get = engine.add_node(
                    _make_node(
                        node_type="INPUT_STREAM",
                        method=method,
                        operation="getInputStream",
                        classification="FACT",
                        confidence="high",
                        register=result,
                        instruction_index=idx,
                        instruction_offset=ins.offset,
                        object_id=in_id,
                    )
                )
                engine.transfers.append(
                    {
                        "kind": "get_input_stream",
                        "from_object": st.object_id,
                        "to_object": in_id,
                        "method": _method_key(method),
                        "classification": "FACT",
                        "confidence": "high",
                        "instruction_index": idx,
                    }
                )
                engine.object_nodes[in_id] = n_get
                sock_node = engine.object_nodes.get(st.object_id)
                if sock_node:
                    engine.add_edge(_edge(sock_node, n_get, "GET_INPUT_STREAM"))
                if result:
                    _enqueue(
                        engine,
                        _State(
                            object_id=in_id,
                            method=method,
                            register=result,
                            field_name=None,
                            start_index=idx + 1,
                            method_hops=st.method_hops,
                            # New object identity: field depth starts at 0 (not inherited).
                            field_hops=0,
                            via="local",
                            field_chain=(),
                        ),
                    )
                    # Dalvik may reuse the socket register for the stream result.
                    if result == active_reg:
                        active_reg = None
                continue
            elif name == "getOutputStream" and "BluetoothSocket" in raw and obj.kind == "SOCKET":
                result = _result_reg_after(method, idx)
                out_id = engine.new_object("OUTPUT_STREAM", origin_method=_method_key(method))
                n_out = engine.add_node(
                    _make_node(
                        node_type="OUTPUT_STREAM",
                        method=method,
                        operation="getOutputStream",
                        classification="FACT",
                        confidence="high",
                        register=result,
                        instruction_index=idx,
                        instruction_offset=ins.offset,
                        object_id=out_id,
                    )
                )
                engine.object_nodes[out_id] = n_out
                sock_node = engine.object_nodes.get(st.object_id)
                if sock_node:
                    engine.add_edge(_edge(sock_node, n_out, "GET_OUTPUT_STREAM"))
                engine.transfers.append(
                    {
                        "kind": "get_output_stream",
                        "from_object": st.object_id,
                        "to_object": out_id,
                        "method": _method_key(method),
                        "classification": "FACT",
                        "confidence": "high",
                        "instruction_index": idx,
                    }
                )
                if result:
                    _enqueue(
                        engine,
                        _State(
                            object_id=out_id,
                            method=method,
                            register=result,
                            field_name=None,
                            start_index=idx + 1,
                            method_hops=st.method_hops,
                            field_hops=0,
                            via="local",
                            field_chain=(),
                        ),
                    )
                    if result == active_reg:
                        active_reg = None
                continue
            elif _is_stream_read(name, raw) and obj.kind in {"INPUT_STREAM", "WRAPPER"}:
                item = {
                    "index": idx,
                    "text": ins.text,
                    "raw": ref.get("raw"),
                    "offset": ins.offset,
                    "method": _method_key(method),
                    "object_id": st.object_id,
                    "classification": "FACT",
                    "confidence": "high",
                    "evidence_level": "dex_reference",
                    "register_linked": True,
                }
                engine.read_chain.append(item)
                n_read = engine.add_node(
                    _make_node(
                        node_type="READ",
                        method=method,
                        operation=name,
                        classification="FACT",
                        confidence="high",
                        register=active_reg,
                        instruction_index=idx,
                        instruction_offset=ins.offset,
                        object_id=st.object_id,
                        value=ins.text,
                    )
                )
                src = engine.object_nodes.get(st.object_id)
                if src:
                    engine.add_edge(_edge(src, n_read, "READS_FROM"))
                continue
            elif _is_stream_write(name, raw) and obj.kind in {"OUTPUT_STREAM", "WRAPPER"}:
                item = {
                    "index": idx,
                    "text": ins.text,
                    "raw": ref.get("raw"),
                    "offset": ins.offset,
                    "method": _method_key(method),
                    "object_id": st.object_id,
                    "classification": "FACT",
                    "confidence": "high",
                    "evidence_level": "dex_reference",
                    "register_linked": True,
                }
                engine.write_chain.append(item)
                n_write = engine.add_node(
                    _make_node(
                        node_type="WRITE",
                        method=method,
                        operation=name,
                        classification="FACT",
                        confidence="high",
                        register=active_reg,
                        instruction_index=idx,
                        instruction_offset=ins.offset,
                        object_id=st.object_id,
                        value=ins.text,
                    )
                )
                src = engine.object_nodes.get(st.object_id)
                if src:
                    engine.add_edge(_edge(src, n_write, "WRITES_TO"))
                continue

        # Argument / constructor transfer (object passed, not necessarily receiver)
        if active_reg and active_reg in regs:
            arg_pos = regs.index(active_reg)
            # receiver-only already handled; still allow constructor/wrapper when name=<init>
            is_init = name == "<init>"
            is_arg = arg_pos > 0 or (arg_pos == 0 and "static" in raw)  # rough
            if is_init and active_reg in regs:
                wtype = _wrapper_from_raw(raw)
                n_ctor = engine.add_node(
                    _make_node(
                        node_type="CONSTRUCTOR",
                        method=method,
                        operation=raw.split("->")[-1] if "->" in raw else "<init>",
                        classification="FACT",
                        confidence="high",
                        register=active_reg,
                        instruction_index=idx,
                        instruction_offset=ins.offset,
                        object_id=st.object_id,
                    )
                )
                engine.transfers.append(
                    {
                        "kind": "constructor_arg",
                        "object_id": st.object_id,
                        "method": _method_key(method),
                        "classification": "FACT",
                        "confidence": "high",
                        "instruction_index": idx,
                        "wrapper_type": wtype,
                    }
                )
                if wtype:
                    wrap_id = engine.new_object("WRAPPER", origin_method=_method_key(method), wrapper_type=wtype)
                    # Wrapper instance is typically in regs[0] for invoke-direct
                    wrap_reg = regs[0] if regs else None
                    n_wrap = engine.add_node(
                        _make_node(
                            node_type="WRAPPER",
                            method=method,
                            operation=wtype,
                            classification="FACT",
                            confidence="high",
                            register=wrap_reg,
                            instruction_index=idx,
                            instruction_offset=ins.offset,
                            object_id=wrap_id,
                            value=wtype,
                        )
                    )
                    engine.add_edge(_edge(n_ctor, n_wrap, "WRAPS"))
                    src_node = engine.object_nodes.get(st.object_id)
                    if src_node:
                        engine.add_edge(_edge(src_node, n_wrap, "WRAPS", "FACT"))
                    engine.object_nodes[wrap_id] = n_wrap
                    if wrap_reg:
                        _enqueue(
                            engine,
                            _State(
                                object_id=wrap_id,
                                method=method,
                                register=wrap_reg,
                                field_name=None,
                                start_index=idx + 1,
                                method_hops=st.method_hops,
                                field_hops=0,
                                via="constructor",
                                field_chain=(),
                            ),
                        )
                continue

            # Parameter transfer into callee — only when signature suggests stream/socket types.
            if is_arg and name != "<init>" and st.method_hops < engine.max_method_hops:
                raw_sig = ref.get("raw") or raw
                type_hint = any(
                    t in raw_sig
                    for t in (
                        "BluetoothSocket",
                        "InputStream",
                        "OutputStream",
                        "BufferedInput",
                        "BufferedOutput",
                        "DataInput",
                        "DataOutput",
                    )
                )
                if not type_hint:
                    continue
                callee = _callee_lookup(engine.by_key, engine.by_class, ref.get("raw"))
                if callee is None:
                    if arg_pos > 0:
                        engine.boundaries.append(
                            {
                                "reason": "parameter_callee_unresolved",
                                "method": _method_key(method),
                                "target": ref.get("raw"),
                                "object_id": st.object_id,
                                "classification": "UNKNOWN",
                                "notes": [BOUNDARY_NOTE],
                            }
                        )
                    continue
                # Map argument index among invoke regs excluding receiver for instance
                args = regs[1:] if regs else []
                if active_reg not in args and active_reg != regs[0]:
                    continue
                if active_reg in args:
                    pos = args.index(active_reg)
                else:
                    continue
                param_reg = _param_register_for_arg(callee, pos)
                engine.transfers.append(
                    {
                        "kind": "parameter",
                        "object_id": st.object_id,
                        "from_method": _method_key(method),
                        "to_method": _method_key(callee),
                        "arg_position": pos,
                        "classification": "FACT",
                        "confidence": "high",
                        "instruction_index": idx,
                    }
                )
                n_param = engine.add_node(
                    _make_node(
                        node_type="PARAMETER",
                        method=callee,
                        operation=f"param[{pos}]",
                        classification="FACT",
                        confidence="high",
                        register=param_reg,
                        instruction_index=0,
                        instruction_offset=None,
                        object_id=st.object_id,
                    )
                )
                engine.add_edge(
                    _edge(
                        _node_id("METHOD_CALL", _method_key(method), str(idx), st.object_id),
                        n_param,
                        "ARGUMENT",
                    )
                )
                if param_reg:
                    _enqueue(
                        engine,
                        _State(
                            object_id=st.object_id,
                            method=callee,
                            register=param_reg,
                            field_name=None,
                            start_index=0,
                            method_hops=st.method_hops + 1,
                            field_hops=st.field_hops,
                            via="parameter",
                            field_chain=st.field_chain,
                        ),
                    )


def _enqueue(engine: _Engine, st: _State) -> None:
    key = engine.state_key(st)
    if key in engine.seen_states:
        return
    engine.seen_states.add(key)
    engine.queue.append(st)


def trace_object_flow(
    origin_method: MethodInfo,
    create_index: int,
    methods: list[MethodInfo],
    *,
    socket_register: str | None,
    max_method_hops: int = 3,
    max_field_hops: int = 2,
    max_object_nodes: int = 500,
    window: int = 12,
) -> dict[str, Any]:
    """Trace BluetoothSocket (and derived streams) across bounded method/field hops."""
    by_key = {_method_key(m): m for m in methods if not m.is_external}
    by_class: dict[str, list[MethodInfo]] = defaultdict(list)
    for m in methods:
        if not m.is_external:
            by_class[m.class_name].append(m)

    engine = _Engine(
        by_key=by_key,
        by_class=by_class,
        max_method_hops=max(0, min(int(max_method_hops), 5)),
        max_field_hops=max(0, min(int(max_field_hops), 4)),
        max_object_nodes=max(1, min(int(max_object_nodes), 500)),
        window=window,
    )

    sock_reg = socket_register or _result_reg_after(origin_method, create_index)
    socket_id = engine.new_object("SOCKET", origin_method=_method_key(origin_method))
    sock_node = engine.add_node(
        _make_node(
            node_type="SOCKET",
            method=origin_method,
            operation="createRfcommSocketToServiceRecord",
            classification="FACT",
            confidence="high",
            register=sock_reg,
            instruction_index=create_index,
            instruction_offset=None,
            object_id=socket_id,
            value=socket_id,
        )
    )
    engine.object_nodes[socket_id] = sock_node

    if not sock_reg:
        engine.boundaries.append(
            {
                "reason": "no_socket_register",
                "method": _method_key(origin_method),
                "classification": "UNKNOWN",
                "notes": [BOUNDARY_NOTE, "createRfcomm invoke had no move-result-object register."],
            }
        )
        return _finalize(engine, socket_id)

    seed = _State(
        object_id=socket_id,
        method=origin_method,
        register=sock_reg,
        field_name=None,
        start_index=create_index + 1,
        method_hops=0,
        field_hops=0,
        via="local",
        field_chain=(),
    )
    _enqueue(engine, seed)
    while engine.queue:
        st = engine.queue.popleft()
        _scan_method(engine, st)
    return _finalize(engine, socket_id)


def _finalize(engine: _Engine, socket_id: str) -> dict[str, Any]:
    ranking = 0
    ranking += 10 if any(t.get("kind") == "get_input_stream" for t in engine.transfers) else 0
    ranking += 10 if any(t.get("kind") == "get_output_stream" for t in engine.transfers) else 0
    ranking += 20 if engine.read_chain else 0
    ranking += 20 if engine.write_chain else 0
    ranking += 5 * sum(1 for t in engine.transfers if t.get("kind") in {"return", "parameter", "field_store", "field_load"})
    # End-to-end remains INFERENCE even when stages are FACT
    if engine.read_chain or engine.write_chain:
        confidence = "medium"
    elif any(t.get("kind") in {"return", "parameter", "field_store", "get_input_stream"} for t in engine.transfers):
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "socket_object_id": socket_id,
        "objects": [
            {
                "object_id": o.object_id,
                "kind": o.kind,
                "wrapper_type": o.wrapper_type,
                "origin_method": o.origin_method,
            }
            for o in engine.objects.values()
        ],
        "nodes": engine.nodes[: engine.max_object_nodes],
        "edges": engine.edges,
        "transfers": engine.transfers,
        "socket_transfers": [t for t in engine.transfers if t.get("object_id") == socket_id or t.get("from_object") == socket_id],
        "stream_transfers": [
            t
            for t in engine.transfers
            if t.get("kind") in {"get_input_stream", "get_output_stream", "constructor_arg", "parameter", "return", "field_store", "field_load"}
            and t.get("kind") != "connect"
        ],
        "input_read_chain": engine.read_chain,
        "output_write_chain": engine.write_chain,
        "boundaries": engine.boundaries,
        "ranking_score": ranking,
        "classification": "INFERENCE",
        "confidence": confidence,
        "runtime_execution_proven": False,
        "wire_correlation_available": False,
        "counts": {
            "objects": len(engine.objects),
            "nodes": len(engine.nodes),
            "edges": len(engine.edges),
            "transfers": len(engine.transfers),
            "reads": len(engine.read_chain),
            "writes": len(engine.write_chain),
            "boundaries": len(engine.boundaries),
        },
        "limitations": [
            "Bounded interprocedural object-flow only; no full alias or SSA analysis.",
            "End-to-end semantic meaning remains INFERENCE even when steps are FACT.",
            BOUNDARY_NOTE,
        ],
    }
