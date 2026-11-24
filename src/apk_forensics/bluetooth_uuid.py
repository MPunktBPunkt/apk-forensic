"""Bounded static UUID resolution for RFCOMM create calls."""

from __future__ import annotations

import re
from typing import Any

from apk_forensics.bluetooth_matcher import SPP_UUID
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo


UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)


def normalize_uuid(value: str | None) -> str | None:
    if not value:
        return None
    try:
        import uuid

        return str(uuid.UUID(value)).lower()
    except Exception:
        return None


def _reg_num(reg: str | None) -> int | None:
    if not reg:
        return None
    m = re.fullmatch(r"v(\d+)", reg)
    return int(m.group(1)) if m else None


def _dest_reg(ins: InstructionInfo) -> str | None:
    if ins.registers:
        return ins.registers[0]
    return None


def _source_regs(ins: InstructionInfo) -> list[str]:
    if len(ins.registers) > 1:
        return list(ins.registers[1:])
    if ins.opcode.startswith("move") and len(ins.registers) == 2:
        return [ins.registers[1]]
    return []


def _field_key(field: str | None) -> str | None:
    if not field:
        return None
    # Normalize "Lcls;->name Type" and "Lcls;->name:Type"
    field = field.strip()
    m = re.match(r"(L[^;]+;->[^\s:]+)", field)
    return m.group(1) if m else field


def resolve_uuid_literal_in_method(method: MethodInfo) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for ins in method.instructions:
        if ins.referenced_string and UUID_RE.fullmatch(ins.referenced_string.strip()):
            found.append(
                {
                    "uuid": normalize_uuid(ins.referenced_string),
                    "source_type": "uuid_literal_direct",
                    "source": f"{method.class_name}->{method.method_name}",
                    "instruction_index": ins.index,
                    "resolution": "static",
                    "classification": "FACT",
                    "confidence": "high",
                    "evidence_level": "instruction_context",
                }
            )
    return found


def resolve_static_field_uuid(
    field_raw: str,
    class_methods: list[MethodInfo],
    *,
    depth: int,
) -> dict[str, Any] | None:
    """Look in <clinit> (and optionally other methods) for sput of this UUID field."""
    if depth < 0:
        return None
    key = _field_key(field_raw)
    if not key:
        return None
    for method in class_methods:
        if method.method_name != "<clinit>" and depth == 0:
            continue
        for idx, ins in enumerate(method.instructions):
            if not ins.opcode.startswith("sput"):
                continue
            if _field_key(ins.referenced_field) != key:
                continue
            # Backtrack register that was stored
            dest = _dest_reg(ins)
            if not dest:
                continue
            resolved = backtrack_register(
                method,
                start_index=idx,
                register=dest,
                class_methods=class_methods,
                depth=depth,
            )
            if resolved and resolved.get("uuid"):
                resolved = dict(resolved)
                resolved["source_type"] = "uuid_static_field"
                resolved["source"] = field_raw
                resolved["field"] = key
                resolved["clinit_method"] = f"{method.class_name}->{method.method_name}"
                resolved["classification"] = "FACT"
                resolved["confidence"] = "high"
                resolved["resolution"] = "static"
                return resolved
    return {
        "uuid": None,
        "source_type": "uuid_static_field",
        "source": field_raw,
        "field": key,
        "resolution": "unknown",
        "classification": "UNKNOWN",
        "confidence": "unknown",
        "limitations": ["Static field referenced, but UUID value not resolved in <clinit>."],
    }


def backtrack_register(
    method: MethodInfo,
    *,
    start_index: int,
    register: str,
    class_methods: list[MethodInfo],
    depth: int,
) -> dict[str, Any] | None:
    """Bounded backwards register tracking for simple DEX patterns."""
    current = register
    steps: list[dict[str, Any]] = []
    idx = start_index - 1
    hops = 0
    max_hops = 32

    while idx >= 0 and hops < max_hops:
        hops += 1
        ins = method.instructions[idx]
        dest = _dest_reg(ins)

        # const-string into current register
        if ins.opcode.startswith("const-string") and dest == current and ins.referenced_string:
            steps.append({"index": idx, "op": ins.opcode, "text": ins.text})
            if UUID_RE.fullmatch(ins.referenced_string.strip()):
                return {
                    "uuid": normalize_uuid(ins.referenced_string),
                    "source_type": "uuid_literal_direct",
                    "source": ins.referenced_string,
                    "resolution": "static",
                    "classification": "FACT",
                    "confidence": "high",
                    "evidence_level": "instruction_context",
                    "steps": steps,
                    "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
                }
            # maybe later used by fromString via move-result chain — keep going? literal non-uuid
            return {
                "uuid": None,
                "source_type": "uuid_unknown",
                "source": ins.referenced_string,
                "resolution": "unknown",
                "classification": "UNKNOWN",
                "confidence": "low",
                "steps": steps,
                "limitations": ["const-string found but not a UUID literal."],
            }

        # move / move-object: dest <- src
        if ins.opcode.startswith("move") and not ins.opcode.startswith("move-result") and dest == current:
            srcs = _source_regs(ins)
            if srcs:
                steps.append({"index": idx, "op": ins.opcode, "text": ins.text})
                current = srcs[0]
                idx -= 1
                continue

        # move-result-object: result of previous invoke
        if ins.opcode.startswith("move-result") and dest == current:
            steps.append({"index": idx, "op": ins.opcode, "text": ins.text})
            # previous useful invoke
            j = idx - 1
            while j >= 0 and method.instructions[j].opcode.startswith("nop"):
                j -= 1
            if j >= 0 and method.instructions[j].opcode.startswith("invoke"):
                inv = method.instructions[j]
                steps.append({"index": j, "op": inv.opcode, "text": inv.text})
                ref = inv.referenced_method or {}
                if ref.get("method_name") == "fromString" and "UUID" in (ref.get("class_name") or ""):
                    # UUID arg is first register of invoke-static
                    arg_regs = list(inv.registers)
                    if arg_regs:
                        nested = backtrack_register(
                            method,
                            start_index=j,
                            register=arg_regs[0],
                            class_methods=class_methods,
                            depth=depth,
                        )
                        if nested and nested.get("uuid"):
                            nested = dict(nested)
                            nested["source_type"] = "uuid_from_string"
                            nested["steps"] = steps + list(nested.get("steps") or [])
                            nested["classification"] = "FACT"
                            nested["confidence"] = "high"
                            nested["resolution"] = "static"
                            return nested
                    return {
                        "uuid": None,
                        "source_type": "uuid_from_string",
                        "source": inv.text,
                        "resolution": "unknown",
                        "classification": "UNKNOWN",
                        "confidence": "low",
                        "steps": steps,
                        "limitations": ["UUID.fromString call found but string argument not resolved."],
                    }
                # generic method return
                return {
                    "uuid": None,
                    "source_type": "uuid_method_return",
                    "source": ref.get("raw") or inv.text,
                    "resolution": "unknown",
                    "classification": "UNKNOWN",
                    "confidence": "low",
                    "steps": steps,
                    "limitations": ["UUID came from method return; value not statically resolved."],
                }
            idx -= 1
            continue

        # sget-object into current register
        if ins.opcode.startswith("sget") and dest == current and ins.referenced_field:
            steps.append({"index": idx, "op": ins.opcode, "text": ins.text})
            if depth <= 0:
                return {
                    "uuid": None,
                    "source_type": "uuid_static_field",
                    "source": ins.referenced_field,
                    "resolution": "unknown",
                    "classification": "UNKNOWN",
                    "confidence": "low",
                    "steps": steps,
                    "limitations": ["Static field load found; dataflow depth insufficient to resolve value."],
                }
            return resolve_static_field_uuid(
                ins.referenced_field,
                class_methods,
                depth=depth - 1,
            )

        # iget-object into current
        if ins.opcode.startswith("iget") and dest == current:
            steps.append({"index": idx, "op": ins.opcode, "text": ins.text})
            return {
                "uuid": None,
                "source_type": "uuid_parameter" if "UUID" in (ins.referenced_field or "") else "uuid_unknown",
                "source": ins.referenced_field or ins.text,
                "resolution": "unknown",
                "classification": "UNKNOWN",
                "confidence": "low",
                "steps": steps,
                "limitations": ["Instance field / parameter UUID; value not statically resolved."],
            }

        idx -= 1

    return {
        "uuid": None,
        "source_type": "uuid_unknown",
        "source": f"{method.class_name}->{method.method_name}:{register}",
        "resolution": "unknown",
        "classification": "UNKNOWN",
        "confidence": "unknown",
        "steps": steps,
        "limitations": ["Register could not be resolved with bounded static dataflow."],
    }


def resolve_rfcomm_uuid_argument(
    method: MethodInfo,
    create_index: int,
    *,
    class_methods: list[MethodInfo],
    dataflow_depth: int,
) -> dict[str, Any]:
    """Resolve UUID argument of createRfcommSocketToServiceRecord at create_index."""
    ins = method.instructions[create_index]
    # invoke-virtual deviceReg, uuidReg, Method
    regs = list(ins.registers)
    if len(regs) < 2:
        return {
            "uuid": None,
            "source_type": "uuid_unknown",
            "source": ins.text,
            "resolution": "unknown",
            "classification": "UNKNOWN",
            "confidence": "unknown",
            "limitations": ["Could not determine UUID argument register from invoke operands."],
            "instruction_index": create_index,
            "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
        }
    uuid_reg = regs[1]
    resolved = backtrack_register(
        method,
        start_index=create_index,
        register=uuid_reg,
        class_methods=class_methods,
        depth=dataflow_depth,
    ) or {
        "uuid": None,
        "source_type": "uuid_unknown",
        "resolution": "unknown",
        "classification": "UNKNOWN",
    }
    resolved["instruction_index"] = create_index
    resolved["method"] = f"{method.class_name}->{method.method_name}{method.method_descriptor}"
    resolved["uuid_register"] = uuid_reg
    resolved["device_register"] = regs[0]
    if resolved.get("uuid"):
        resolved["is_spp_uuid"] = resolved["uuid"] == SPP_UUID
    return resolved
