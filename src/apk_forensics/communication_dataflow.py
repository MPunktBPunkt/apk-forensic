"""v1.0 bounded communication dataflow: bytes/buffers → parser/serializer → message.

Builds on transport read/write sites. Method names never imply protocol identity.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Iterable

from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo
from apk_forensics.evidence_graph import method_name_semantics

READ_API_RE = re.compile(
    r"Ljava/io/(?:InputStream|DataInputStream|BufferedInputStream);"
    r"->read(?:\(|$)|"
    r"Ljava/nio/channels/Channels;->newInputStream|"
    r"Ljava/io/DataInputStream;->read(?:Boolean|Byte|Char|Double|Float|Int|Long|Short|UTF|Fully|Unsigned)"
)
WRITE_API_RE = re.compile(
    r"Ljava/io/(?:OutputStream|DataOutputStream|BufferedOutputStream);"
    r"->(?:write|flush)(?:\(|$)|"
    r"Ljava/io/DataOutputStream;->write(?:Boolean|Byte|Bytes|Char|Chars|Double|Float|Int|Long|Short|UTF)"
)

BYTEBUFFER_OPS = (
    "Ljava/nio/ByteBuffer;->wrap",
    "Ljava/nio/ByteBuffer;->allocate",
    "Ljava/nio/ByteBuffer;->get",
    "Ljava/nio/ByteBuffer;->getInt",
    "Ljava/nio/ByteBuffer;->getShort",
    "Ljava/nio/ByteBuffer;->getLong",
    "Ljava/nio/ByteBuffer;->getFloat",
    "Ljava/nio/ByteBuffer;->getDouble",
    "Ljava/nio/ByteBuffer;->put",
    "Ljava/nio/ByteBuffer;->putInt",
    "Ljava/nio/ByteBuffer;->putShort",
    "Ljava/nio/ByteBuffer;->putLong",
    "Ljava/nio/ByteBuffer;->array",
    "Ljava/nio/ByteBuffer;->slice",
    "Ljava/nio/ByteBuffer;->asReadOnlyBuffer",
    "Ljava/nio/ByteBuffer;->position",
    "Ljava/nio/ByteBuffer;->limit",
    "Ljava/nio/ByteBuffer;->duplicate",
)

COPY_OPS = (
    "Ljava/lang/System;->arraycopy",
    "Ljava/util/Arrays;->copyOf",
    "Ljava/util/Arrays;->copyOfRange",
)

STRING_DECODE_OPS = (
    "Ljava/lang/String;-><init>([B",
    "Ljava/lang/String;-><init>([BLjava/nio/charset",
    "Ljava/nio/charset/Charset;->decode",
    "Ljava/nio/charset/CharsetDecoder;->decode",
)

PARSER_NAME_RE = re.compile(
    r"(?i)(parse|decode|deserialize|frombytes|from_bytes|readmessage|readpacket|"
    r"readframe|decodemessage|parsebytes|parseresponse|unpack)"
)
SERIALIZER_NAME_RE = re.compile(
    r"(?i)(serialize|encode|tobytes|to_bytes|writemessage|writepacket|"
    r"encodeMessage|pack|marshall)"
)
MESSAGE_TYPE_RE = re.compile(
    r"(?i)(Message|Packet|Response|Request|Command|Frame|Dto|DTO|Payload)"
)
NATIVE_OR_REFLECT_RE = re.compile(
    r"Ljava/lang/reflect/|Ldalvik/system/|->native|invoke-polymorphic|"
    r"Ljava/lang/Class;->forName|Ljava/lang/Method;->invoke"
)

BOUNDARY_REASONS = frozenset(
    {
        "max_buffer_hops",
        "max_parser_hops",
        "max_message_hops",
        "max_method_hops",
        "UNKNOWN_HELPER",
        "NATIVE",
        "REFLECTION",
        "unsupported_pattern",
        "unresolved_callee",
    }
)


def _stable(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _sid(prefix: str, *parts: str, n: int = 12) -> str:
    return f"{prefix}-{_stable(*parts)[:n]}"


def _method_key(m: MethodInfo) -> str:
    return f"{m.class_name}->{m.method_name}{m.method_descriptor}"


def _ref_raw(ins: InstructionInfo) -> str:
    rm = ins.referenced_method or {}
    if rm.get("class_name") and rm.get("name"):
        return f"{rm['class_name']}->{rm['name']}{rm.get('descriptor') or ''}"
    m = re.search(r"(L[^;]+;->[^(]+\([^)]*\)[^ ;\"]*)", ins.text or "")
    return m.group(1) if m else (ins.text or "")


def _is_new_array_byte(ins: InstructionInfo) -> bool:
    return "new-array" in (ins.opcode or "") and "[B" in (ins.text or "")


def _is_filled_or_const(ins: InstructionInfo) -> bool:
    return (ins.opcode or "").startswith(("const", "fill-array"))


def _invoke_name(raw: str) -> str:
    if "->" in raw:
        return raw.split("->")[-1].split("(")[0]
    return raw


def _classify_boundary(raw: str) -> str:
    if NATIVE_OR_REFLECT_RE.search(raw):
        if "reflect" in raw.lower() or "Method;->invoke" in raw or "forName" in raw:
            return "REFLECTION"
        return "NATIVE"
    return "UNKNOWN_HELPER"


def analyze_method_communication(
    method: MethodInfo,
    *,
    method_index: dict[str, MethodInfo] | None = None,
    max_buffer_hops: int = 5,
    max_parser_hops: int = 3,
    max_message_hops: int = 3,
    max_method_hops: int = 3,
) -> dict[str, Any]:
    """Analyze one method for inbound/outbound communication-relevant flows."""
    index = method_index or {}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    boundaries: list[dict[str, Any]] = []
    read_sites: list[dict[str, Any]] = []
    write_sites: list[dict[str, Any]] = []
    buffer_ops: list[dict[str, Any]] = []
    decoder_cands: list[dict[str, Any]] = []
    encoder_cands: list[dict[str, Any]] = []
    message_ctors: list[dict[str, Any]] = []
    primitive_decodes: list[dict[str, Any]] = []
    string_decodes: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []

    # Track registers that hold byte[] / ByteBuffer with hop counts
    buf_regs: dict[str, dict[str, Any]] = {}
    seen_states: set[str] = set()

    def add_node(**kwargs: Any) -> str:
        nid = kwargs.get("node_id") or _sid(
            "cnode",
            kwargs.get("node_type", ""),
            kwargs.get("label", ""),
            kwargs.get("method", ""),
            str(kwargs.get("instruction_index", "")),
        )
        kwargs["node_id"] = nid
        if not any(n["node_id"] == nid for n in nodes):
            nodes.append(kwargs)
        return nid

    def add_edge(frm: str, to: str, etype: str, classification: str = "FACT", **extra: Any) -> None:
        eid = _sid("cedge", etype, frm, to, classification)
        if any(e.get("edge_id") == eid for e in edges):
            return
        edges.append(
            {
                "edge_id": eid,
                "from": frm,
                "to": to,
                "edge_type": etype,
                "classification": classification,
                "confidence": extra.get("confidence", "high"),
                **{k: v for k, v in extra.items() if k != "confidence"},
            }
        )

    def mark_boundary(reason: str, *, last: str | None, detail: str | None = None) -> None:
        r = reason if reason in BOUNDARY_REASONS else "unsupported_pattern"
        boundaries.append(
            {
                "boundary_id": _sid("cbnd", r, last or "", detail or ""),
                "reason": r,
                "last_proven": last,
                "detail": detail,
                "classification": "UNKNOWN",
                "method": _method_key(method),
            }
        )

    def track_buf(reg: str, kind: str, source_nid: str, hops: int) -> None:
        if hops > max_buffer_hops:
            mark_boundary("max_buffer_hops", last=source_nid, detail=reg)
            return
        prev = buf_regs.get(reg)
        if prev and prev.get("hops", 0) <= hops and prev.get("source") == source_nid:
            return
        buf_regs[reg] = {"kind": kind, "source": source_nid, "hops": hops}

    instructions = list(method.instructions or [])
    for i, ins in enumerate(instructions):
        text = ins.text or ""
        raw = _ref_raw(ins)
        regs = list(ins.registers or [])

        # --- READ sites ---
        if (ins.opcode or "").startswith("invoke") and READ_API_RE.search(raw):
            site = {
                "index": ins.index,
                "text": text,
                "raw": raw,
                "classification": "FACT",
                "confidence": "high",
                "method": _method_key(method),
            }
            read_sites.append(site)
            rn = add_node(
                node_type="INPUT_READ",
                label=raw,
                method=_method_key(method),
                instruction_index=ins.index,
                instruction=text,
                classification="FACT",
                confidence="high",
            )
            # read([B) / read([BII) — array is typically second register after receiver
            dest = None
            if "[B" in raw and len(regs) >= 2:
                dest = regs[1]
            elif len(regs) >= 1 and "read()I" in raw:
                # scalar read — result register after move-result
                dest = None
            if dest:
                bn = add_node(
                    node_type="BYTE_ARRAY",
                    label=f"byte[]:{dest}",
                    method=_method_key(method),
                    instruction_index=ins.index,
                    register=dest,
                    classification="FACT",
                    confidence="high",
                )
                add_edge(rn, bn, "WRITES_TO", classification="FACT")
                track_buf(dest, "BYTE_ARRAY", bn, 0)
            # look ahead for move-result into register (for read()I still track as primitive)
            if i + 1 < len(instructions) and (instructions[i + 1].opcode or "").startswith("move-result"):
                mr = instructions[i + 1]
                if mr.registers:
                    # scalar result — PRIMITIVE_DECODE candidate from stream
                    pn = add_node(
                        node_type="PRIMITIVE_DECODE",
                        label=raw,
                        method=_method_key(method),
                        instruction_index=ins.index,
                        register=mr.registers[0],
                        classification="FACT",
                        confidence="high",
                    )
                    add_edge(rn, pn, "READS_FROM", classification="FACT")
                    primitive_decodes.append(
                        {"method": _method_key(method), "api": raw, "classification": "FACT"}
                    )

        # --- WRITE sites ---
        if (ins.opcode or "").startswith("invoke") and WRITE_API_RE.search(raw):
            site = {
                "index": ins.index,
                "text": text,
                "raw": raw,
                "classification": "FACT",
                "confidence": "high",
                "method": _method_key(method),
            }
            write_sites.append(site)
            wn = add_node(
                node_type="OUTPUT_WRITE",
                label=raw,
                method=_method_key(method),
                instruction_index=ins.index,
                instruction=text,
                classification="FACT",
                confidence="high",
            )
            # write([B) — buffer is typically regs[1]
            src_reg = regs[1] if "[B" in raw and len(regs) >= 2 else (regs[1] if len(regs) >= 2 else None)
            if src_reg and src_reg in buf_regs:
                add_edge(buf_regs[src_reg]["source"], wn, "WRITES_TO", classification="FACT")
            elif src_reg:
                bn = add_node(
                    node_type="BYTE_ARRAY",
                    label=f"byte[]:{src_reg}",
                    method=_method_key(method),
                    instruction_index=ins.index,
                    register=src_reg,
                    classification="FACT",
                    confidence="medium",
                )
                add_edge(bn, wn, "WRITES_TO", classification="FACT")
                track_buf(src_reg, "BYTE_ARRAY", bn, 0)

        # --- new byte[] ---
        if _is_new_array_byte(ins) and regs:
            bn = add_node(
                node_type="BYTE_ARRAY",
                label=f"new-array [B:{regs[0]}",
                method=_method_key(method),
                instruction_index=ins.index,
                register=regs[0],
                classification="FACT",
                confidence="high",
            )
            track_buf(regs[0], "BYTE_ARRAY", bn, 0)

        # --- copy / wrap / buffer ops ---
        if (ins.opcode or "").startswith("invoke"):
            if any(op in raw for op in COPY_OPS):
                # System.arraycopy(src, ..., dst, ...)
                src_r = regs[0] if regs else None
                dst_r = regs[2] if len(regs) >= 3 else (regs[1] if len(regs) >= 2 else None)
                # Arrays.copyOf(src) -> move-result
                cn = add_node(
                    node_type="COPY",
                    label=raw,
                    method=_method_key(method),
                    instruction_index=ins.index,
                    classification="FACT",
                    confidence="high",
                )
                buffer_ops.append({"op": "COPY", "raw": raw, "classification": "FACT"})
                if src_r and src_r in buf_regs:
                    add_edge(buf_regs[src_r]["source"], cn, "COPY", classification="FACT")
                    hops = buf_regs[src_r]["hops"] + 1
                else:
                    hops = 1
                if dst_r:
                    track_buf(dst_r, "BYTE_ARRAY", cn, hops)
                elif i + 1 < len(instructions) and (instructions[i + 1].opcode or "").startswith(
                    "move-result-object"
                ):
                    mr = instructions[i + 1].registers[0] if instructions[i + 1].registers else None
                    if mr:
                        track_buf(mr, "BYTE_ARRAY", cn, hops)

            if any(op in raw for op in BYTEBUFFER_OPS):
                kind = "WRAP" if "wrap" in raw or "allocate" in raw else "BYTE_BUFFER"
                if "slice" in raw or "asReadOnlyBuffer" in raw or "duplicate" in raw:
                    kind = "SLICE"
                if any(x in raw for x in ("getInt", "getShort", "getLong", "getFloat", "getDouble", "->get(")):
                    kind = "PRIMITIVE_DECODE"
                bn = add_node(
                    node_type=kind if kind != "PRIMITIVE_DECODE" else "BYTE_BUFFER",
                    label=raw,
                    method=_method_key(method),
                    instruction_index=ins.index,
                    classification="FACT",
                    confidence="high",
                )
                buffer_ops.append({"op": kind, "raw": raw, "classification": "FACT"})
                # wrap([B) — first arg after static is often the array; for invoke-static wrap, regs[0]
                src_r = regs[0] if regs else None
                if src_r and src_r in buf_regs:
                    add_edge(buf_regs[src_r]["source"], bn, kind, classification="FACT")
                    hops = buf_regs[src_r]["hops"] + 1
                else:
                    hops = 0
                if kind == "PRIMITIVE_DECODE":
                    pn = add_node(
                        node_type="PRIMITIVE_DECODE",
                        label=raw,
                        method=_method_key(method),
                        instruction_index=ins.index,
                        classification="FACT",
                        confidence="high",
                    )
                    add_edge(bn, pn, "DECODES", classification="FACT")
                    primitive_decodes.append(
                        {"method": _method_key(method), "api": raw, "classification": "FACT"}
                    )
                if i + 1 < len(instructions) and (instructions[i + 1].opcode or "").startswith(
                    "move-result"
                ):
                    mr = instructions[i + 1].registers[0] if instructions[i + 1].registers else None
                    if mr and kind in {"WRAP", "SLICE", "BYTE_BUFFER"}:
                        track_buf(mr, "BYTE_BUFFER", bn, hops + 1)
                elif src_r and kind in {"WRAP", "BYTE_BUFFER"}:
                    # instance put/get keep receiver as buffer
                    if regs:
                        track_buf(regs[0], "BYTE_BUFFER", bn, hops)

            if any(op in raw for op in STRING_DECODE_OPS) or (
                "Ljava/lang/String;-><init>" in raw and "[B" in raw
            ):
                sn = add_node(
                    node_type="STRING_DECODE",
                    label=raw,
                    method=_method_key(method),
                    instruction_index=ins.index,
                    classification="FACT",
                    confidence="high",
                )
                string_decodes.append({"method": _method_key(method), "api": raw, "classification": "FACT"})
                src_r = regs[1] if len(regs) >= 2 else (regs[0] if regs else None)
                if src_r and src_r in buf_regs:
                    add_edge(buf_regs[src_r]["source"], sn, "DECODES", classification="FACT")

            # --- parser / decoder candidates by name + dataflow ---
            name = _invoke_name(raw)
            if PARSER_NAME_RE.search(name):
                sem = method_name_semantics(name)
                has_buf_arg = any(r in buf_regs for r in regs)
                role_class = "INFERENCE" if has_buf_arg else "UNKNOWN"
                dn = add_node(
                    node_type="DECODER",
                    label=raw,
                    method=_method_key(method),
                    instruction_index=ins.index,
                    classification=role_class if has_buf_arg else "FACT",
                    confidence="medium" if has_buf_arg else "low",
                    method_name_candidate="FACT",
                    dataflow_role=role_class,
                    protocol_semantics="UNKNOWN",
                )
                decoder_cands.append(
                    {
                        "method": raw,
                        "method_name_candidate": "FACT",
                        "dataflow_role": role_class,
                        "protocol_semantics": "UNKNOWN",
                        "hint_tokens_detected": sem["hint_tokens_detected"],
                        "classification": role_class,
                    }
                )
                if has_buf_arg:
                    for r in regs:
                        if r in buf_regs:
                            add_edge(buf_regs[r]["source"], dn, "DECODED_BY", classification="CORRELATION")
                            break
                # unresolved callee body
                if raw not in index and max_parser_hops <= 0:
                    mark_boundary("unresolved_callee", last=dn, detail=raw)
                elif NATIVE_OR_REFLECT_RE.search(raw):
                    mark_boundary(_classify_boundary(raw), last=dn, detail=raw)

            if SERIALIZER_NAME_RE.search(name):
                sem = method_name_semantics(name)
                # serializer if result flows to buffer later, or args include message-like
                role_class = "INFERENCE"  # refined after path build
                en = add_node(
                    node_type="SERIALIZER",
                    label=raw,
                    method=_method_key(method),
                    instruction_index=ins.index,
                    classification="FACT",
                    confidence="medium",
                    method_name_candidate="FACT",
                    dataflow_role="INFERENCE",
                    protocol_semantics="UNKNOWN",
                )
                encoder_cands.append(
                    {
                        "method": raw,
                        "method_name_candidate": "FACT",
                        "dataflow_role": "INFERENCE",
                        "protocol_semantics": "UNKNOWN",
                        "hint_tokens_detected": sem["hint_tokens_detected"],
                        "classification": "INFERENCE",
                    }
                )
                if i + 1 < len(instructions) and (instructions[i + 1].opcode or "").startswith(
                    "move-result-object"
                ):
                    mr = instructions[i + 1].registers[0] if instructions[i + 1].registers else None
                    if mr:
                        track_buf(mr, "BYTE_ARRAY", en, 1)

            # --- constructors of message-like types ---
            if (ins.opcode or "").startswith("invoke") and "<init>" in raw:
                cls = raw.split("->")[0] if "->" in raw else ""
                short = cls.split("/")[-1].rstrip(";") if cls else ""
                if MESSAGE_TYPE_RE.search(short) or any(r in buf_regs for r in regs[1:]):
                    mn = add_node(
                        node_type="MESSAGE_OBJECT",
                        label=raw,
                        method=_method_key(method),
                        instruction_index=ins.index,
                        classification="FACT",
                        confidence="high",
                        protocol_semantics="UNKNOWN",
                    )
                    message_ctors.append(
                        {
                            "constructor": raw,
                            "classification": "FACT",
                            "protocol_semantics": "UNKNOWN",
                            "method_name_semantics": method_name_semantics(short),
                        }
                    )
                    for r in regs[1:]:
                        if r in buf_regs:
                            add_edge(buf_regs[r]["source"], mn, "CONSTRUCTS", classification="CORRELATION")
                            break
                    # also link from recent decoder
                    for n in reversed(nodes):
                        if n.get("node_type") == "DECODER":
                            add_edge(n["node_id"], mn, "PRODUCES", classification="INFERENCE")
                            break

            # unknown helper receiving buffer
            if any(r in buf_regs for r in regs) and (ins.opcode or "").startswith("invoke"):
                if not (
                    READ_API_RE.search(raw)
                    or WRITE_API_RE.search(raw)
                    or any(op in raw for op in COPY_OPS + BYTEBUFFER_OPS + STRING_DECODE_OPS)
                    or PARSER_NAME_RE.search(_invoke_name(raw))
                    or SERIALIZER_NAME_RE.search(_invoke_name(raw))
                    or "<init>" in raw
                ):
                    if NATIVE_OR_REFLECT_RE.search(raw):
                        mark_boundary(_classify_boundary(raw), last=raw, detail=_method_key(method))
                    elif raw not in index:
                        # only mark once per unique helper
                        key = f"helper|{raw}"
                        if key not in seen_states:
                            seen_states.add(key)
                            mark_boundary("UNKNOWN_HELPER", last=raw, detail=_method_key(method))

        # register moves preserve buffer identity
        if (ins.opcode or "") in {"move-object", "move-object/from16", "move-object/16"} and len(regs) >= 2:
            if regs[1] in buf_regs:
                track_buf(regs[0], buf_regs[regs[1]]["kind"], buf_regs[regs[1]]["source"], buf_regs[regs[1]]["hops"])

        # field store/load of buffers
        if (ins.opcode or "").startswith("iput-object") and len(regs) >= 1 and regs[0] in buf_regs:
            fn = add_node(
                node_type="FIELD_WRITE",
                label=ins.referenced_field or text,
                method=_method_key(method),
                instruction_index=ins.index,
                classification="FACT",
                confidence="high",
            )
            add_edge(buf_regs[regs[0]]["source"], fn, "FIELD_STORE", classification="FACT")
        if (ins.opcode or "").startswith("iget-object") and regs:
            # optimistic: if field name suggests stream/buffer
            field = ins.referenced_field or text
            if any(x in field for x in ("[B", "ByteBuffer", "Buffer", "mBuf", "buffer", "payload", "data")):
                bn = add_node(
                    node_type="BYTE_ARRAY",
                    label=field,
                    method=_method_key(method),
                    instruction_index=ins.index,
                    register=regs[0],
                    classification="FACT",
                    confidence="medium",
                )
                track_buf(regs[0], "BYTE_ARRAY", bn, 0)

    # --- Extract compact communication paths ---
    def path_from_chain(kind: str, direction: str, step_nodes: list[dict[str, Any]]) -> dict[str, Any]:
        labels = [s["label"] for s in step_nodes]
        # end-to-end
        e2e = "INFERENCE" if len(step_nodes) > 1 else step_nodes[0].get("classification", "FACT")
        return {
            "path_id": _sid("comm", kind, direction, *labels),
            "display_id": "",
            "kind": kind,
            "direction": direction,
            "start": labels[0] if labels else None,
            "end": labels[-1] if labels else None,
            "steps": [
                {
                    "node_id": s["node_id"],
                    "node_type": s.get("node_type"),
                    "label": s.get("label"),
                    "classification": s.get("classification"),
                    "confidence": s.get("confidence"),
                    "protocol_semantics": s.get("protocol_semantics", "UNKNOWN"),
                }
                for s in step_nodes
            ],
            "classification": e2e,
            "confidence": "medium" if e2e == "INFERENCE" else "high",
            "protocol_semantics": "UNKNOWN",
            "method_name_semantics": method_name_semantics(method.method_name),
            "boundaries": [b for b in boundaries if True][:5],
            "source_method": _method_key(method),
            "runtime_execution_proven": False,
            "wire_correlation_available": False,
            "notes": [
                "Individual steps keep their classifications.",
                "End-to-end communication path is INFERENCE when composed of multiple FACT/CORRELATION steps.",
                "Protocol semantics remain UNKNOWN without independent evidence.",
            ],
        }

    # Inbound: INPUT_READ → BYTE_ARRAY → (COPY|WRAP|BUFFER) → DECODER → MESSAGE
    reads = [n for n in nodes if n.get("node_type") == "INPUT_READ"]
    arrays = [n for n in nodes if n.get("node_type") in {"BYTE_ARRAY", "BYTE_BUFFER", "WRAP", "COPY", "SLICE"}]
    decoders = [n for n in nodes if n.get("node_type") == "DECODER"]
    messages = [n for n in nodes if n.get("node_type") == "MESSAGE_OBJECT"]
    primitives = [n for n in nodes if n.get("node_type") == "PRIMITIVE_DECODE"]
    strings = [n for n in nodes if n.get("node_type") == "STRING_DECODE"]
    writes = [n for n in nodes if n.get("node_type") == "OUTPUT_WRITE"]
    serializers = [n for n in nodes if n.get("node_type") == "SERIALIZER"]

    if reads and arrays:
        chain = [reads[0], arrays[0]]
        if any(n.get("node_type") in {"WRAP", "COPY", "SLICE", "BYTE_BUFFER"} for n in arrays[1:]):
            chain.append(next(n for n in arrays[1:] if n.get("node_type") in {"WRAP", "COPY", "SLICE", "BYTE_BUFFER"}))
        if decoders:
            chain.append(decoders[0])
        if messages:
            chain.append(messages[0])
        elif primitives:
            chain.append(primitives[0])
        elif strings:
            chain.append(strings[0])
        paths.append(path_from_chain("INBOUND_DECODE", "INBOUND", chain))

    if messages and serializers and writes:
        paths.append(path_from_chain("OUTBOUND_ENCODE", "OUTBOUND", [messages[0], serializers[0], arrays[0] if arrays else serializers[0], writes[0]]))
    elif serializers and writes:
        chain = [serializers[0]]
        if arrays:
            chain.append(arrays[0])
        chain.append(writes[0])
        paths.append(path_from_chain("OUTBOUND_ENCODE", "OUTBOUND", chain))
    elif arrays and writes:
        paths.append(path_from_chain("OUTBOUND_BUFFER_WRITE", "OUTBOUND", [arrays[0], writes[0]]))

    if reads and arrays and primitives and not decoders:
        paths.append(path_from_chain("INBOUND_PRIMITIVE", "INBOUND", [reads[0], arrays[0], primitives[0]]))

    # Ranking score
    for p in paths:
        score = 0
        types = {s["node_type"] for s in p["steps"]}
        if "INPUT_READ" in types:
            score += 20
        if "OUTPUT_WRITE" in types:
            score += 20
        if "DECODER" in types or "PARSER" in types:
            score += 15
        if "SERIALIZER" in types:
            score += 15
        if "MESSAGE_OBJECT" in types:
            score += 25
        if "BYTE_BUFFER" in types or "WRAP" in types:
            score += 10
        if "PRIMITIVE_DECODE" in types:
            score += 8
        score += sum(5 for s in p["steps"] if s.get("classification") == "FACT")
        score -= 3 * len(p.get("boundaries") or [])
        p["ranking_score"] = score

    paths.sort(key=lambda p: (-int(p.get("ranking_score") or 0), p.get("path_id") or ""))

    return {
        "method": _method_key(method),
        "read_sites": read_sites,
        "write_sites": write_sites,
        "buffer_operations": buffer_ops,
        "decoder_candidates": decoder_cands,
        "serializer_candidates": encoder_cands,
        "message_constructions": message_ctors,
        "primitive_decoding": primitive_decodes,
        "string_decoding": string_decodes,
        "nodes": nodes,
        "edges": edges,
        "boundaries": boundaries,
        "paths": paths,
        "protocol_semantics": "UNKNOWN",
        "method_name_semantics": method_name_semantics(method.method_name),
    }


def analyze_communication_methods(
    methods: Iterable[MethodInfo],
    *,
    max_buffer_hops: int = 5,
    max_parser_hops: int = 3,
    max_message_hops: int = 3,
    max_method_hops: int = 3,
    max_methods: int = 200,
) -> dict[str, Any]:
    methods_list = list(methods)[: max(0, max_methods)]
    index = {_method_key(m): m for m in methods_list}
    per_method: list[dict[str, Any]] = []
    all_paths: list[dict[str, Any]] = []
    all_boundaries: list[dict[str, Any]] = []
    totals = defaultdict(int)

    for m in methods_list:
        result = analyze_method_communication(
            m,
            method_index=index,
            max_buffer_hops=max_buffer_hops,
            max_parser_hops=max_parser_hops,
            max_message_hops=max_message_hops,
            max_method_hops=max_method_hops,
        )
        per_method.append(result)
        all_paths.extend(result.get("paths") or [])
        all_boundaries.extend(result.get("boundaries") or [])
        totals["read_sites"] += len(result.get("read_sites") or [])
        totals["write_sites"] += len(result.get("write_sites") or [])
        totals["buffer_operations"] += len(result.get("buffer_operations") or [])
        totals["decoder_candidates"] += len(result.get("decoder_candidates") or [])
        totals["serializer_candidates"] += len(result.get("serializer_candidates") or [])
        totals["message_constructions"] += len(result.get("message_constructions") or [])
        totals["primitive_decoding"] += len(result.get("primitive_decoding") or [])
        totals["string_decoding"] += len(result.get("string_decoding") or [])

    # Deduplicate paths by path_id
    seen: set[str] = set()
    unique_paths: list[dict[str, Any]] = []
    for p in sorted(all_paths, key=lambda x: (-int(x.get("ranking_score") or 0), x.get("path_id") or "")):
        if p["path_id"] in seen:
            continue
        seen.add(p["path_id"])
        unique_paths.append(p)
    for i, p in enumerate(unique_paths, start=1):
        p["display_id"] = f"PATH-COMM-{i:06d}"

    return {
        "enabled": True,
        "schema": "apk_forensics.communication_evidence.v1",
        "methods_analyzed": len(methods_list),
        "counts": dict(totals),
        "paths": unique_paths,
        "boundaries": all_boundaries[:500],
        "per_method": per_method,
        "summary": {
            "communication_paths": len(unique_paths),
            "inbound_paths": sum(1 for p in unique_paths if p.get("direction") == "INBOUND"),
            "outbound_paths": sum(1 for p in unique_paths if p.get("direction") == "OUTBOUND"),
            "read_sites": totals["read_sites"],
            "write_sites": totals["write_sites"],
            "decoder_candidates": totals["decoder_candidates"],
            "serializer_candidates": totals["serializer_candidates"],
            "message_constructions": totals["message_constructions"],
            "boundaries": len(all_boundaries),
            "strongest_path_id": unique_paths[0]["display_id"] if unique_paths else None,
            "strongest_classification": unique_paths[0]["classification"] if unique_paths else None,
            "protocol_semantics": "UNKNOWN",
            "runtime_execution": "UNKNOWN",
            "wire_correlation": "UNKNOWN",
        },
        "limitations": [
            "Communication analysis is bounded static dataflow only.",
            "Method names never establish protocol identity.",
            "No wire bytes, runtime execution, or peer identity is proven.",
            "Transport evidence classifications are not rewritten by this step.",
        ],
    }


def empty_communication_section(*, enabled: bool = False) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "schema": "apk_forensics.communication_evidence.v1",
        "methods_analyzed": 0,
        "counts": {},
        "paths": [],
        "boundaries": [],
        "per_method": [],
        "summary": {
            "communication_paths": 0,
            "inbound_paths": 0,
            "outbound_paths": 0,
            "read_sites": 0,
            "write_sites": 0,
            "decoder_candidates": 0,
            "serializer_candidates": 0,
            "message_constructions": 0,
            "boundaries": 0,
            "strongest_path_id": None,
            "strongest_classification": None,
            "protocol_semantics": "UNKNOWN",
            "runtime_execution": "UNKNOWN",
            "wire_correlation": "UNKNOWN",
        },
        "limitations": [],
        "provenance": {},
    }
