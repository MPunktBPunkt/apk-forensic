"""BluetoothDevice source analysis within RFCOMM methods."""

from __future__ import annotations

import re
from typing import Any

from apk_forensics.dex_model_adapter import MethodInfo

MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")


def analyze_device_source(
    method: MethodInfo,
    create_index: int,
    *,
    window: int = 12,
) -> dict[str, Any]:
    """Inspect how the BluetoothDevice used at RFCOMM create is obtained."""
    ins = method.instructions[create_index]
    regs = list(ins.registers)
    device_reg = regs[0] if regs else None
    start = max(0, create_index - window)
    end = min(len(method.instructions), create_index + 1)

    evidence: list[dict[str, Any]] = []
    source_type = "unknown"
    source_value = None
    classification = "UNKNOWN"
    confidence = "unknown"
    notes: list[str] = []

    # Prefer exact register definition just before create
    if device_reg:
        for idx in range(create_index - 1, start - 1, -1):
            cur = method.instructions[idx]
            dest = cur.registers[0] if cur.registers else None
            if dest != device_reg:
                continue
            if cur.opcode.startswith("iget") and cur.referenced_field:
                source_type = "instance_field"
                source_value = cur.referenced_field
                classification = "FACT"
                confidence = "high"
                evidence.append({"index": idx, "text": cur.text, "relationship": "field_reference"})
                notes.append("BluetoothDevice loaded from instance field.")
                break
            if cur.opcode.startswith("sget") and cur.referenced_field:
                source_type = "static_field"
                source_value = cur.referenced_field
                classification = "FACT"
                confidence = "medium"
                evidence.append({"index": idx, "text": cur.text, "relationship": "field_reference"})
                break
            if cur.opcode.startswith("invoke") and (cur.referenced_method or {}).get("method_name") == "getRemoteDevice":
                source_type = "getRemoteDevice"
                source_value = (cur.referenced_method or {}).get("raw")
                classification = "FACT"
                confidence = "high"
                evidence.append({"index": idx, "text": cur.text, "relationship": "method_call"})
                break
            if cur.opcode.startswith("invoke") and (cur.referenced_method or {}).get("method_name") == "getBondedDevices":
                source_type = "getBondedDevices"
                source_value = (cur.referenced_method or {}).get("raw")
                classification = "FACT"
                confidence = "medium"
                evidence.append({"index": idx, "text": cur.text, "relationship": "method_call"})
                break
            if cur.opcode.startswith("move-result"):
                # look at previous invoke
                if idx > 0 and method.instructions[idx - 1].opcode.startswith("invoke"):
                    prev = method.instructions[idx - 1]
                    name = (prev.referenced_method or {}).get("method_name")
                    if name in {"getRemoteDevice", "getBondedDevices"}:
                        source_type = name
                        source_value = (prev.referenced_method or {}).get("raw")
                        classification = "FACT"
                        confidence = "high" if name == "getRemoteDevice" else "medium"
                        evidence.append({"index": idx - 1, "text": prev.text, "relationship": "method_call"})
                        break
            if cur.opcode.startswith("move") and len(cur.registers) >= 2:
                device_reg = cur.registers[1]
                evidence.append({"index": idx, "text": cur.text, "relationship": "register_flow"})
                continue
            break

    # Window scan for related APIs / strings
    mac_candidates: list[str] = []
    name_candidates: list[str] = []
    for idx in range(start, end):
        cur = method.instructions[idx]
        if cur.referenced_string:
            if MAC_RE.fullmatch(cur.referenced_string.strip()):
                mac_candidates.append(cur.referenced_string)
            if any(tok in cur.referenced_string for tok in ("BMW", "Connected", "Head")):
                name_candidates.append(cur.referenced_string)
        name = (cur.referenced_method or {}).get("method_name")
        if name in {"getRemoteDevice", "getBondedDevices", "getAddress", "getName"}:
            evidence.append({"index": idx, "text": cur.text, "relationship": "method_call"})

    if source_type == "unknown":
        notes.append("BluetoothDevice source not statically resolved within window.")

    return {
        "source_type": source_type,
        "source": source_value,
        "device_register": regs[0] if regs else None,
        "classification": classification,
        "confidence": confidence,
        "evidence_level": "instruction_context" if classification == "FACT" else "unknown",
        "evidence": evidence,
        "mac_candidates": mac_candidates,
        "name_string_candidates": name_candidates,
        "notes": notes
        + (
            ["Static Bluetooth address candidate only; not a proven target device."]
            if mac_candidates
            else []
        )
        + (
            ["Name string is profile/string correlation only; not HU proof."]
            if name_candidates
            else []
        ),
        "method": f"{method.class_name}->{method.method_name}{method.method_descriptor}",
        "instruction_index": create_index,
    }
