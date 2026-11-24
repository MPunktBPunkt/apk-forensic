"""Build DEX context records from matches."""

from __future__ import annotations

from typing import Any

from apk_forensics.dex_matcher import DexMatch, collect_method_symbols, make_context_id
from apk_forensics.dex_model_adapter import DexSession, method_window
from apk_forensics.models import Classification, Confidence


def build_context_record(
    match: DexMatch,
    *,
    instruction_window: int,
    artifact_sha256: str,
) -> dict[str, Any]:
    method = match.method
    ins = method.instructions[match.instruction_index]
    window = method_window(method, match.instruction_index, window=instruction_window)
    # Use whole-method symbols for chaining when method is reasonably small.
    if method.instruction_count and method.instruction_count <= 400:
        symbols = collect_method_symbols(method, around_index=None)
    else:
        symbols = collect_method_symbols(
            method,
            around_index=match.instruction_index,
            window=max(instruction_window, 32),
        )
    limitations: list[str] = [
        "Static DEX context does not prove runtime execution.",
    ]
    if ins.offset is None:
        limitations.append("Instruction offset not available through the parser API.")

    evidence_level = "instruction_context" if match.match_type != "unknown" else "raw_string"
    if match.match_type == "method_reference":
        evidence_level = "dex_reference"

    finding_id = match.query.finding_ids[0] if match.query.finding_ids else None
    context_id = make_context_id(match)

    return {
        "context_id": context_id,
        "finding_id": finding_id,
        "finding_ids": list(match.query.finding_ids),
        "dex_entry": method.dex_entry,
        "class_name": method.class_name,
        "class_name_normalized": method.class_name_normalized,
        "method_name": method.method_name,
        "method_descriptor": method.method_descriptor,
        "match": {
            "kind": match.query.kind,
            "value": match.matched_value,
            "normalized_value": match.matched_value.lower(),
            "match_type": match.match_type,
        },
        "instruction": ins.to_dict(),
        "instruction_window": window,
        "referenced_symbols": symbols,
        "priority": match.priority,
        "priority_score": match.priority_score,
        "priority_reasons": list(match.priority_reasons),
        "classification": Classification.FACT.value,
        "confidence": (
            Confidence.HIGH.value
            if match.match_type == "method_reference"
            else Confidence.MEDIUM.value
        ),
        "evidence_level": evidence_level,
        "limitations": limitations,
        "notes": [
            "Method reference is stronger than a raw string hit."
            if match.match_type == "method_reference"
            else "String/class presence in method context only."
        ],
        "artifact_sha256": artifact_sha256,
    }


def build_contexts(
    matches: list[DexMatch],
    *,
    instruction_window: int,
    artifact_sha256: str,
) -> list[dict[str, Any]]:
    contexts = [
        build_context_record(
            match,
            instruction_window=instruction_window,
            artifact_sha256=artifact_sha256,
        )
        for match in matches
    ]
    contexts.sort(
        key=lambda c: (
            -int(c.get("priority_score") or 0),
            c.get("dex_entry") or "",
            c.get("class_name") or "",
            c.get("method_name") or "",
            int((c.get("instruction") or {}).get("index") or 0),
            c.get("context_id") or "",
        )
    )
    # assign display ids
    for idx, ctx in enumerate(contexts, start=1):
        ctx["display_id"] = f"DEXCTX-{idx:06d}"
    return contexts


def empty_dex_context_section(
    *,
    enabled: bool,
    status: str,
    warnings: list[str] | None = None,
    limitations: list[str] | None = None,
    configuration: dict[str, Any] | None = None,
    parser: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": status,
        "parser": parser or {"name": None, "version": None},
        "configuration": configuration or {},
        "units": [],
        "contexts": [],
        "xref_candidates": [],
        "candidate_chains": [],
        "warnings": list(warnings or []),
        "limitations": list(
            limitations
            or [
                "DEX context analysis not enabled.",
            ]
        ),
    }
