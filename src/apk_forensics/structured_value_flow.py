"""v1.5 Structured-value lineage and field-consumer closure.

Tracks byte-derived primitives/objects into fields, loads, branches, and
application actions. Field names never imply protocol meaning.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Iterable

from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo


STRUCTURED_VALUE_DEFINITION = {
    "definition": (
        "A STRUCTURED_VALUE is a FACT when a tracked byte[]/ByteBuffer identity "
        "is transformed by a concrete DEX instruction into a typed register value "
        "(primitive, String, or object ref) that is distinct from READ_LENGTH."
    ),
    "examples": [
        "ByteBuffer.getInt/getShort → register",
        "aget-byte → register",
        "decode*([B) → move-result / move-result-object",
        "String.<init>([B) → object register",
    ],
    "excludes": [
        "InputStream.read length move-result (READ_LENGTH)",
        "Field/method/class names as semantic labels",
        "Protocol/command/message claims",
    ],
}

BRANCH_OPS = frozenset(
    {
        "if-eq",
        "if-ne",
        "if-lt",
        "if-ge",
        "if-gt",
        "if-le",
        "if-eqz",
        "if-nez",
        "if-ltz",
        "if-gez",
        "if-gtz",
        "if-lez",
        "packed-switch",
        "sparse-switch",
    }
)

COLLECTION_PUT_RE = re.compile(
    r"Ljava/util/(?:Map|HashMap|LinkedHashMap|ConcurrentHashMap|List|ArrayList|Set|HashSet|Queue|LinkedList);"
    r"->(?:put|add|offer|set)\("
)
ENCODE_WRITE_RE = re.compile(
    r"->(?:encode|serialize|toBytes|write)\(|"
    r"Ljava/io/(?:OutputStream|DataOutputStream);"
    r"->write|"
    r"AccessorySocket;->write|"
    r"ByteBuffer;->(?:put|array)\("
)


def _stable(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _method_key(m: MethodInfo) -> str:
    return f"{m.class_name}->{m.method_name}{m.method_descriptor}"


def _ref_raw(ins: InstructionInfo) -> str:
    rm = ins.referenced_method or {}
    if rm.get("class_name") and rm.get("name"):
        return f"{rm['class_name']}->{rm['name']}{rm.get('descriptor') or ''}"
    m = re.search(r"(L[^;]+;->[^(]+\([^)]*\)[^ ;\"]*)", ins.text or "")
    return m.group(1) if m else (ins.text or "")


def _field_raw(ins: InstructionInfo) -> str:
    if ins.referenced_field:
        return str(ins.referenced_field)
    m = re.search(r"(L[^;]+;->\w+\s+[^ ]+)", ins.text or "")
    return m.group(1) if m else (ins.text or "")


def _field_short(field: str) -> str:
    if ";->" in field:
        return field.split(";->", 1)[1]
    return field


def analyze_method_value_lineage(method: MethodInfo) -> dict[str, Any]:
    """Intra-method: buffer → structured value → store/return/branch/param."""
    instructions = list(method.instructions or [])
    buf_regs: set[str] = set()
    # register → value provenance
    values: dict[str, dict[str, Any]] = {}
    structured: list[dict[str, Any]] = []
    stores: list[dict[str, Any]] = []
    branches: list[dict[str, Any]] = []
    returns: list[dict[str, Any]] = []
    params: list[dict[str, Any]] = []
    collections: list[dict[str, Any]] = []
    app_actions: list[dict[str, Any]] = []
    roundtrips: list[dict[str, Any]] = []

    mk = _method_key(method)

    def mark_value(reg: str, **meta: Any) -> dict[str, Any]:
        vid_local = f"tmp-{reg}-{meta.get('instruction_index')}"
        entry = {
            "register": reg,
            "method": mk,
            "classification": "FACT",
            "protocol_semantics": "UNKNOWN",
            **meta,
        }
        values[reg] = entry
        structured.append(entry)
        return entry

    for i, ins in enumerate(instructions):
        op = ins.opcode or ""
        text = ins.text or ""
        regs = list(ins.registers or [])
        raw = _ref_raw(ins)

        # new-array [B / wrap creates buffer identity
        if "new-array" in op and "[B" in text and regs:
            buf_regs.add(regs[0])
        if "ByteBuffer;->wrap" in raw or "ByteBuffer;->allocate" in raw:
            if i + 1 < len(instructions) and (instructions[i + 1].opcode or "").startswith(
                "move-result-object"
            ):
                mr = instructions[i + 1].registers[0] if instructions[i + 1].registers else None
                if mr:
                    buf_regs.add(mr)
            elif regs:
                # instance receive may already be buffer
                buf_regs.add(regs[0])
            # wrap([B): source array
            if regs and regs[0] in buf_regs or (regs and "[B" in raw):
                if regs:
                    buf_regs.add(regs[0])

        # read into buffer keeps buffer
        if "->read(" in raw and "[B" in raw and len(regs) >= 2:
            buf_regs.add(regs[1])

        # ByteBuffer.get* / aget → structured value
        if any(
            x in raw
            for x in (
                "ByteBuffer;->getInt",
                "ByteBuffer;->getShort",
                "ByteBuffer;->getLong",
                "ByteBuffer;->get(",
                "ByteBuffer;->getFloat",
                "ByteBuffer;->getDouble",
            )
        ):
            if i + 1 < len(instructions) and (instructions[i + 1].opcode or "").startswith("move-result"):
                mr_ins = instructions[i + 1]
                if mr_ins.registers and not (mr_ins.opcode or "").startswith("move-result-object"):
                    prim = "int"
                    if "getShort" in raw:
                        prim = "short"
                    elif "getLong" in raw:
                        prim = "long"
                    elif "getFloat" in raw:
                        prim = "float"
                    elif "getDouble" in raw:
                        prim = "double"
                    mark_value(
                        mr_ins.registers[0],
                        source_kind="BYTEBUFFER_GET",
                        source_api=raw,
                        primitive_type=prim,
                        instruction_index=ins.index,
                        instruction=text,
                        buffer_register=regs[0] if regs else None,
                        t6_stage="T6.0_STRUCTURED_VALUE",
                    )

        if op.startswith("aget") and len(regs) >= 2 and regs[1] in buf_regs:
            mark_value(
                regs[0],
                source_kind="ARRAY_LOAD",
                source_api=op,
                primitive_type="byte" if "byte" in op else "element",
                instruction_index=ins.index,
                instruction=text,
                buffer_register=regs[1],
                t6_stage="T6.0_STRUCTURED_VALUE",
            )

        # decode*/parse* returning value from [B argument
        if (op.startswith("invoke") and ("decode" in raw.lower() or "parse" in raw.lower())) and "[B" in raw:
            has_buf_arg = any(r in buf_regs for r in regs) or True  # param [B often p0/vN
            if has_buf_arg and i + 1 < len(instructions):
                nxt = instructions[i + 1]
                if (nxt.opcode or "").startswith("move-result-object") and nxt.registers:
                    mark_value(
                        nxt.registers[0],
                        source_kind="DECODE_RETURN_OBJECT",
                        source_api=raw,
                        primitive_type="object",
                        instruction_index=ins.index,
                        instruction=text,
                        classification="FACT",
                        dataflow_role="CORRELATION",
                        t6_stage="T6.0_STRUCTURED_VALUE",
                        note="Return object from decode* on byte[]; name is search indicator only",
                    )
                elif (nxt.opcode or "").startswith("move-result") and nxt.registers:
                    mark_value(
                        nxt.registers[0],
                        source_kind="DECODE_RETURN_PRIMITIVE",
                        source_api=raw,
                        primitive_type="primitive",
                        instruction_index=ins.index,
                        instruction=text,
                        classification="FACT",
                        dataflow_role="CORRELATION",
                        t6_stage="T6.0_STRUCTURED_VALUE",
                        note="Return primitive from decode* on byte[]; name is search indicator only",
                    )

        # String([B)
        if "Ljava/lang/String;-><init>" in raw and "[B" in raw:
            # receiver is string object being constructed
            if regs:
                mark_value(
                    regs[0],
                    source_kind="STRING_FROM_BYTES",
                    source_api=raw,
                    primitive_type="string",
                    instruction_index=ins.index,
                    instruction=text,
                    buffer_register=regs[1] if len(regs) > 1 else None,
                    t6_stage="T6.0_STRUCTURED_VALUE",
                )

        # move-object preserves value identity
        if op in {"move-object", "move-object/from16", "move-object/16", "move", "move/from16", "move/16"} and len(regs) >= 2:
            if regs[1] in values:
                values[regs[0]] = {**values[regs[1]], "register": regs[0], "via": "move"}
            if regs[1] in buf_regs:
                buf_regs.add(regs[0])

        # field stores of structured values
        if op.startswith(("iput", "sput")) and regs:
            src = regs[0]
            if src in values:
                field = _field_raw(ins)
                stores.append(
                    {
                        "kind": "FIELD_STORE_FROM_BYTES",
                        "field": field,
                        "field_short": _field_short(field),
                        "value_register": src,
                        "value_source": values[src].get("source_kind"),
                        "value_api": values[src].get("source_api"),
                        "primitive_type": values[src].get("primitive_type"),
                        "method": mk,
                        "instruction_index": ins.index,
                        "instruction": text,
                        "classification": "FACT",
                        "protocol_semantics": "UNKNOWN",
                        "t6_stage": "T6.1_FIELD_STATE",
                    }
                )

        # branches on structured values
        if op in BRANCH_OPS and regs:
            used = [r for r in regs if r in values]
            if used:
                branches.append(
                    {
                        "kind": "BRANCH_ON_VALUE",
                        "opcode": op,
                        "registers": used,
                        "value_sources": [values[r].get("source_kind") for r in used],
                        "method": mk,
                        "instruction_index": ins.index,
                        "instruction": text,
                        "classification": "FACT",
                        "protocol_semantics": "UNKNOWN",
                        "note": "Comparison/branch on byte-derived value; constant meaning UNKNOWN",
                        "t6_stage": "T6.3_CONTROL_FLOW",
                    }
                )

        # return of structured value
        if op.startswith("return") and regs and regs[0] in values:
            returns.append(
                {
                    "kind": "VALUE_RETURN",
                    "register": regs[0],
                    "value_source": values[regs[0]].get("source_kind"),
                    "method": mk,
                    "instruction_index": ins.index,
                    "classification": "FACT",
                    "protocol_semantics": "UNKNOWN",
                    "t6_stage": "T6.2_VALUE_CONSUMER",
                }
            )

        # invoke with structured value as arg (not receiver-only for void logging?)
        if op.startswith("invoke") and regs:
            for pos, r in enumerate(regs):
                if r in values:
                    params.append(
                        {
                            "kind": "VALUE_PARAMETER",
                            "register": r,
                            "arg_position": pos,
                            "callee": raw,
                            "value_source": values[r].get("source_kind"),
                            "method": mk,
                            "instruction_index": ins.index,
                            "classification": "FACT",
                            "protocol_semantics": "UNKNOWN",
                            "t6_stage": "T6.2_VALUE_CONSUMER",
                        }
                    )
                    if COLLECTION_PUT_RE.search(raw):
                        collections.append(
                            {
                                "kind": "COLLECTION_INSERT",
                                "callee": raw,
                                "register": r,
                                "method": mk,
                                "instruction_index": ins.index,
                                "classification": "FACT",
                                "protocol_semantics": "UNKNOWN",
                                "t6_stage": "T6.4_APPLICATION_ACTION",
                            }
                        )
                    if ENCODE_WRITE_RE.search(raw) and values[r].get("primitive_type") in {
                        "object",
                        "string",
                    } or (
                        ENCODE_WRITE_RE.search(raw) and r in buf_regs
                    ):
                        roundtrips.append(
                            {
                                "kind": "ROUNDTRIP_CANDIDATE",
                                "callee": raw,
                                "register": r,
                                "method": mk,
                                "instruction_index": ins.index,
                                "classification": "CORRELATION",
                                "protocol_semantics": "UNKNOWN",
                                "note": "Byte-derived value/buffer reaches encode/write-like API",
                                "t6_stage": "T6.5_ROUNDTRIP",
                            }
                        )
                    # application action: setState / notify / callback-ish invoke
                    name = raw.split("->")[-1].split("(")[0] if "->" in raw else raw
                    if any(
                        x in name.lower()
                        for x in ("setstate", "notify", "callback", "onread", "dispatch", "handle")
                    ):
                        app_actions.append(
                            {
                                "kind": "APPLICATION_ACTION",
                                "callee": raw,
                                "register": r,
                                "method": mk,
                                "instruction_index": ins.index,
                                "classification": "CORRELATION",
                                "protocol_semantics": "UNKNOWN",
                                "t6_stage": "T6.4_APPLICATION_ACTION",
                                "note": "Method name is search indicator only",
                            }
                        )

    return {
        "method": mk,
        "structured_values": structured,
        "field_stores": stores,
        "branches": branches,
        "returns": returns,
        "parameters": params,
        "collections": collections,
        "application_actions": app_actions,
        "roundtrip_candidates": roundtrips,
        "buffer_registers": sorted(buf_regs),
        "definition": STRUCTURED_VALUE_DEFINITION,
    }


def analyze_field_load_consumers(
    methods: Iterable[MethodInfo],
    stored_fields: set[str],
) -> list[dict[str, Any]]:
    """Cross-method: iget/sget of fields previously stored from byte-derived values.

    Same field *descriptor* is CORRELATION (static field position), not proven
    same runtime object instance.
    """
    # normalize stored field keys (strip trailing type noise mismatches)
    norms = set()
    for f in stored_fields:
        norms.add(f)
        if " " in f:
            norms.add(f.split(" ")[0])  # L...;->name without type
        short = _field_short(f)
        norms.add(short)

    consumers: list[dict[str, Any]] = []
    for method in methods:
        mk = _method_key(method)
        instructions = list(method.instructions or [])
        loaded: dict[str, dict[str, Any]] = {}  # reg → field meta

        for i, ins in enumerate(instructions):
            op = ins.opcode or ""
            text = ins.text or ""
            regs = list(ins.registers or [])
            field = _field_raw(ins)
            field_match = False
            for n in norms:
                if n and n in field:
                    field_match = True
                    break
            if not field_match and field not in stored_fields:
                # also match by short name against stored shorts
                fs = _field_short(field)
                field_match = any(fs == _field_short(s) or fs in s for s in stored_fields)

            if op.startswith(("iget", "sget")) and regs and field_match:
                meta = {
                    "kind": "FIELD_LOAD",
                    "field": field,
                    "field_short": _field_short(field),
                    "register": regs[0],
                    "method": mk,
                    "instruction_index": ins.index,
                    "instruction": text,
                    "classification": "CORRELATION",
                    "protocol_semantics": "UNKNOWN",
                    "note": "Load of field descriptor previously stored from byte-derived value; same instance not proven",
                    "t6_stage": "T6.2_VALUE_CONSUMER",
                }
                loaded[regs[0]] = meta
                consumers.append(meta)

            if op in {"move-object", "move-object/from16", "move", "move/from16"} and len(regs) >= 2:
                if regs[1] in loaded:
                    loaded[regs[0]] = {**loaded[regs[1]], "register": regs[0]}

            if op in BRANCH_OPS and regs:
                used = [r for r in regs if r in loaded]
                if used:
                    consumers.append(
                        {
                            "kind": "BRANCH_ON_FIELD_VALUE",
                            "opcode": op,
                            "registers": used,
                            "fields": [loaded[r].get("field") for r in used],
                            "method": mk,
                            "instruction_index": ins.index,
                            "instruction": text,
                            "classification": "CORRELATION",
                            "protocol_semantics": "UNKNOWN",
                            "note": "Branch on loaded field previously associated with byte-derived store",
                            "t6_stage": "T6.3_CONTROL_FLOW",
                        }
                    )

            if op.startswith("return") and regs and regs[0] in loaded:
                consumers.append(
                    {
                        "kind": "VALUE_RETURN_FROM_FIELD",
                        "field": loaded[regs[0]].get("field"),
                        "method": mk,
                        "instruction_index": ins.index,
                        "classification": "CORRELATION",
                        "protocol_semantics": "UNKNOWN",
                        "t6_stage": "T6.2_VALUE_CONSUMER",
                    }
                )

            if op.startswith("invoke") and regs:
                raw = _ref_raw(ins)
                for pos, r in enumerate(regs):
                    if r in loaded:
                        consumers.append(
                            {
                                "kind": "VALUE_PARAMETER_FROM_FIELD",
                                "field": loaded[r].get("field"),
                                "arg_position": pos,
                                "callee": raw,
                                "method": mk,
                                "instruction_index": ins.index,
                                "classification": "CORRELATION",
                                "protocol_semantics": "UNKNOWN",
                                "t6_stage": "T6.2_VALUE_CONSUMER",
                            }
                        )
                        if COLLECTION_PUT_RE.search(raw):
                            consumers.append(
                                {
                                    "kind": "COLLECTION_INSERT_FROM_FIELD",
                                    "field": loaded[r].get("field"),
                                    "callee": raw,
                                    "method": mk,
                                    "instruction_index": ins.index,
                                    "classification": "CORRELATION",
                                    "protocol_semantics": "UNKNOWN",
                                    "t6_stage": "T6.4_APPLICATION_ACTION",
                                }
                            )
                        if ENCODE_WRITE_RE.search(raw):
                            consumers.append(
                                {
                                    "kind": "ROUNDTRIP_FROM_FIELD",
                                    "field": loaded[r].get("field"),
                                    "callee": raw,
                                    "method": mk,
                                    "instruction_index": ins.index,
                                    "classification": "CORRELATION",
                                    "protocol_semantics": "UNKNOWN",
                                    "t6_stage": "T6.5_ROUNDTRIP",
                                }
                            )

            # further state mutation from loaded field
            if op.startswith(("iput", "sput")) and regs and regs[0] in loaded:
                consumers.append(
                    {
                        "kind": "STATE_MUTATION_FROM_FIELD",
                        "source_field": loaded[regs[0]].get("field"),
                        "dest_field": _field_raw(ins),
                        "method": mk,
                        "instruction_index": ins.index,
                        "instruction": text,
                        "classification": "CORRELATION",
                        "protocol_semantics": "UNKNOWN",
                        "t6_stage": "T6.4_APPLICATION_ACTION",
                    }
                )

    return consumers


def build_value_catalog(
    per_method: list[dict[str, Any]],
    field_consumers: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Assign neutral VALUE-V### IDs and classify V0–V5."""
    catalog: list[dict[str, Any]] = []
    # Index consumers by field short name
    by_field: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in field_consumers:
        fs = c.get("field_short") or _field_short(str(c.get("field") or c.get("fields") or ""))
        if isinstance(c.get("fields"), list):
            for f in c["fields"]:
                by_field[_field_short(str(f))].append(c)
        elif fs:
            by_field[fs].append(c)

    n = 0
    for pm in per_method:
        # Prefer field stores as primary catalog entries; also standalone values
        for st in pm.get("field_stores") or []:
            n += 1
            vid = f"VALUE-V{n:03d}"
            fs = st.get("field_short") or _field_short(st.get("field") or "")
            related = by_field.get(fs, [])
            kinds = {c.get("kind") for c in related}
            vclass = "V1_FIELD_STATE"
            t6 = "T6.1_FIELD_STATE"
            if any(k and "BRANCH" in k for k in kinds):
                vclass = "V3_CONTROL_FLOW"
                t6 = "T6.3_CONTROL_FLOW"
            if any(k and ("STATE_MUTATION" in k or "COLLECTION" in k or "APPLICATION" in k) for k in kinds):
                vclass = "V4_APPLICATION_ACTION"
                t6 = "T6.4_APPLICATION_ACTION"
            if any(k and "ROUNDTRIP" in k for k in kinds):
                vclass = "V5_ROUNDTRIP"
                t6 = "T6.5_ROUNDTRIP"
            elif any(k and ("PARAMETER" in k or "RETURN" in k or k == "FIELD_LOAD") for k in kinds):
                if vclass == "V1_FIELD_STATE":
                    vclass = "V2_CONSUMED"
                    t6 = "T6.2_VALUE_CONSUMER"

            catalog.append(
                {
                    "value_id": vid,
                    "source_method": pm.get("method"),
                    "source_kind": st.get("value_source"),
                    "source_api": st.get("value_api"),
                    "primitive_type": st.get("primitive_type"),
                    "stored_field": st.get("field"),
                    "store_instruction_index": st.get("instruction_index"),
                    "classification": "FACT",
                    "protocol_semantics": "UNKNOWN",
                    "semantic_label": None,  # never invent
                    "value_class": vclass,
                    "t6_stage": t6,
                    "consumers": [
                        {
                            "kind": c.get("kind"),
                            "method": c.get("method"),
                            "instruction_index": c.get("instruction_index"),
                            "classification": c.get("classification"),
                        }
                        for c in related[:20]
                    ],
                    "consumer_kinds": sorted(k for k in kinds if k),
                    "lineage": [
                        f"BYTES → {st.get('value_api') or st.get('value_source')}",
                        f"REGISTER → FIELD_STORE {fs}",
                        *[f"CONSUMER {c.get('kind')} @ {c.get('method')}" for c in related[:8]],
                    ],
                }
            )

        # values that never got stored
        stored_regs = {st.get("value_register") for st in pm.get("field_stores") or []}
        for val in pm.get("structured_values") or []:
            if val.get("register") in stored_regs:
                continue
            # skip if only intermediate
            n += 1
            vid = f"VALUE-V{n:03d}"
            vclass = "V0_SOURCE_ONLY"
            t6 = "T6.0_STRUCTURED_VALUE"
            # check intra-method consumers
            if any(b.get("registers") and val.get("register") in b.get("registers") for b in pm.get("branches") or []):
                vclass = "V3_CONTROL_FLOW"
                t6 = "T6.3_CONTROL_FLOW"
            elif any(p.get("register") == val.get("register") for p in pm.get("parameters") or []):
                vclass = "V2_CONSUMED"
                t6 = "T6.2_VALUE_CONSUMER"
            elif any(r.get("register") == val.get("register") for r in pm.get("returns") or []):
                vclass = "V2_CONSUMED"
                t6 = "T6.2_VALUE_CONSUMER"
            catalog.append(
                {
                    "value_id": vid,
                    "source_method": pm.get("method"),
                    "source_kind": val.get("source_kind"),
                    "source_api": val.get("source_api"),
                    "primitive_type": val.get("primitive_type"),
                    "register": val.get("register"),
                    "instruction_index": val.get("instruction_index"),
                    "stored_field": None,
                    "classification": val.get("classification") or "FACT",
                    "protocol_semantics": "UNKNOWN",
                    "semantic_label": None,
                    "value_class": vclass,
                    "t6_stage": t6,
                    "consumers": [],
                    "consumer_kinds": [],
                    "lineage": [
                        f"BYTES → {val.get('source_api') or val.get('source_kind')}",
                        f"REGISTER {val.get('register')}",
                        "NO_FIELD_STORE",
                    ],
                }
            )

    return catalog


def analyze_application_value_flow(methods: list[MethodInfo]) -> dict[str, Any]:
    per_method = [analyze_method_value_lineage(m) for m in methods]
    stored_fields: set[str] = set()
    for pm in per_method:
        for st in pm.get("field_stores") or []:
            if st.get("field"):
                stored_fields.add(str(st["field"]))
    consumers = analyze_field_load_consumers(methods, stored_fields)
    catalog = build_value_catalog(per_method, consumers)

    counts = {
        "methods_analyzed": len(methods),
        "structured_values": sum(len(p.get("structured_values") or []) for p in per_method),
        "field_stores": sum(len(p.get("field_stores") or []) for p in per_method),
        "field_loads": sum(1 for c in consumers if c.get("kind") == "FIELD_LOAD"),
        "branches": sum(1 for c in consumers if c.get("kind") == "BRANCH_ON_FIELD_VALUE")
        + sum(len(p.get("branches") or []) for p in per_method),
        "parameters": sum(1 for c in consumers if "PARAMETER" in str(c.get("kind")))
        + sum(len(p.get("parameters") or []) for p in per_method),
        "returns": sum(1 for c in consumers if "RETURN" in str(c.get("kind")))
        + sum(len(p.get("returns") or []) for p in per_method),
        "state_mutations": sum(1 for c in consumers if c.get("kind") == "STATE_MUTATION_FROM_FIELD"),
        "collections": sum(1 for c in consumers if "COLLECTION" in str(c.get("kind")))
        + sum(len(p.get("collections") or []) for p in per_method),
        "roundtrip_candidates": sum(1 for c in consumers if "ROUNDTRIP" in str(c.get("kind")))
        + sum(len(p.get("roundtrip_candidates") or []) for p in per_method),
        "catalog_values": len(catalog),
    }
    by_class = defaultdict(int)
    for v in catalog:
        by_class[str(v.get("value_class"))] += 1

    return {
        "schema": "apk_forensics.structured_value_flow.v1",
        "definition": STRUCTURED_VALUE_DEFINITION,
        "per_method": per_method,
        "field_consumers": consumers,
        "value_catalog": catalog,
        "stored_fields": sorted(stored_fields),
        "counts": dict(counts),
        "value_class_counts": dict(by_class),
        "protocol_semantics": "UNKNOWN",
        "limitations": [
            "Same field descriptor across methods is CORRELATION, not proven same instance.",
            "No protocol meaning from field/method/class names.",
            "Bounded method set only; not a full program value analysis.",
        ],
    }
