"""v1.5 Application-flow closure reports over structured values."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apk_forensics.structured_value_flow import (
    STRUCTURED_VALUE_DEFINITION,
    analyze_application_value_flow,
)

CASE_C = {f"PATH-{i:06d}" for i in range(1, 9)}
CASE_F = {"PATH-000009", "PATH-000010", "PATH-000012", "PATH-000013"}
CASE_D = {"PATH-000011"}

VALUE_CLASSES = {
    "V0_SOURCE_ONLY": "Value extracted; not further followed.",
    "V1_FIELD_STATE": "Value written to object field.",
    "V2_CONSUMED": "Value/field loaded and passed/returned.",
    "V3_CONTROL_FLOW": "Value influences branch/switch/compare.",
    "V4_APPLICATION_ACTION": "Value drives further state/collection/action.",
    "V5_ROUNDTRIP": "Value reaches encode/write-like output path.",
}


def build_path_comm_provenance(
    *,
    baseline_path_comm: int,
    current_path_comm: int,
    v14_note: str,
) -> dict[str, Any]:
    return {
        "baseline_v14_path_comm": baseline_path_comm,
        "current_path_comm": current_path_comm,
        "changed": current_path_comm != baseline_path_comm,
        "provenance_note": v14_note,
        "v15_note": (
            "v1.5 does not silently rewrite PATH-COMM. Application-flow analysis is additive. "
            "Any PATH-COMM delta must cite seed expansion / READ_LENGTH / new analysis — not APK change."
        ),
        "analyzer_expansion_vs_apk": "PATH-COMM growth from v1.3→v1.4 was analyzer expansion, not new APK bytes.",
    }


def build_answers(flow: dict[str, Any], provenance: dict[str, Any]) -> dict[str, Any]:
    catalog = flow.get("value_catalog") or []
    counts = flow.get("counts") or {}
    by = flow.get("value_class_counts") or {}

    field_stores = int(counts.get("field_stores") or 0)
    field_loads = int(counts.get("field_loads") or 0)
    params = int(counts.get("parameters") or 0)
    returns = int(counts.get("returns") or 0)
    branches = int(counts.get("branches") or 0)
    state = int(counts.get("state_mutations") or 0)
    coll = int(counts.get("collections") or 0)
    roundtrip = int(counts.get("roundtrip_candidates") or 0)

    # object construction: DECODE_RETURN_OBJECT or MESSAGE-like stores
    obj_ctor = sum(
        1
        for v in catalog
        if v.get("source_kind") == "DECODE_RETURN_OBJECT" or v.get("primitive_type") == "object"
    )

    return {
        "1_structured_values_from_s4": {
            "catalog_count": len(catalog),
            "sample_ids": [v.get("value_id") for v in catalog[:12]],
            "note": "Neutral VALUE-V### IDs; no semantic naming",
        },
        "2_written_to_fields": field_stores,
        "3_later_loaded": field_loads,
        "4_passed_to_methods": params,
        "5_returned": returns,
        "6_influence_branches": branches,
        "7_application_state_mutations": state,
        "8_collections_maps": coll,
        "9_object_construction": obj_ctor,
        "10_output_dataflow": roundtrip,
        "11_true_roundtrip_correlations": roundtrip > 0,
        "12_where_lineage_ends": [
            "Intra-method: return / last use / overwrite",
            "Cross-method: field descriptor CORRELATION without proven instance",
            "Call-graph / retention boundary beyond expanded seed set",
        ],
        "13_true_apk_ends": [
            "Some values are logging-only consumers",
            "Some branches compare to constants without further static sink",
        ],
        "14_analyzer_bounds": [
            "Bounded method retention / seed expansion",
            "No full SSA; register overwrite ends local lineage",
            "Interface/instance identity across Packet args is CORRELATION",
        ],
        "15_new_facts": [
            "STRUCTURED_VALUE from ByteBuffer.get*/aget/decode return",
            "FIELD_STORE_FROM_BYTES instruction-level",
            "BRANCH_ON_VALUE / BRANCH_ON_FIELD_VALUE",
        ],
        "16_new_correlations": [
            "Field store descriptor → later iget consumers",
            "Byte-derived field → setState / further decode on mData",
            "Optional ROUNDTRIP_FROM_FIELD when encode/write reached",
        ],
        "17_allowed_inferences": [
            "End-to-end application-flow path composition is INFERENCE",
            "Method-name search indicators (decode/setState) never protocol proof",
        ],
        "18_unknowns": [
            "protocol_semantics",
            "meaning of compared constants",
            "peer/HU identity",
            "runtime session / which Packet instance",
        ],
        "19_path_comm_changed": provenance.get("changed"),
        "20_path_comm_why": provenance.get("v15_note"),
        "21_protocol_semantics_unknown": True,
        "22_application_level_evidence_chain": True,
        "value_class_counts": dict(by),
        "path_comm_provenance": provenance,
        "limits_unchanged": {"max_field_hops": 2, "raised": False},
        "negative_controls": {
            "CASE_F": sorted(CASE_F),
            "CASE_D": sorted(CASE_D),
            "must_not_gain_structured_value_from_transport": True,
        },
    }


def build_application_flow_report(
    flow: dict[str, Any],
    *,
    path_comm_provenance: dict[str, Any],
    provenance: dict[str, Any] | None = None,
    negative_control_check: dict[str, Any] | None = None,
) -> dict[str, Any]:
    answers = build_answers(flow, path_comm_provenance)
    return {
        "schema": "apk_forensics.application_flow_evidence_report.v1",
        "provenance": provenance or {},
        "structured_value_definition": STRUCTURED_VALUE_DEFINITION,
        "value_classes": VALUE_CLASSES,
        "flow_counts": flow.get("counts"),
        "value_catalog": flow.get("value_catalog"),
        "stored_fields": flow.get("stored_fields"),
        "field_consumers_sample": (flow.get("field_consumers") or [])[:80],
        "path_comm_provenance": path_comm_provenance,
        "negative_control_check": negative_control_check
        or {
            "paths": sorted(CASE_F | CASE_D),
            "status": "PASS_IF_NO_TRANSPORT_BUFFER_FLOW",
            "note": "Application-flow must not invent T3/T5/T6 for CASE-F / PATH-011",
        },
        "answers": answers,
        "protocol_semantics": "UNKNOWN",
        "interpretation": (
            "v1.5 closes Structured Value → Application Flow with FACT/CORRELATION edges. "
            "It does not close Application Flow → Protocol Semantics."
        ),
    }


def render_value_lineage_md(flow: dict[str, Any]) -> str:
    lines = [
        "# Value Lineage Report (v1.5)",
        "",
        "> Neutral VALUE-V### IDs. No protocol naming.",
        "",
        "## Definition",
        "",
        STRUCTURED_VALUE_DEFINITION["definition"],
        "",
        "## Catalog",
        "",
    ]
    for v in flow.get("value_catalog") or []:
        lines.append(f"### {v.get('value_id')} — `{v.get('value_class')}`")
        lines.append("")
        lines.append(f"- Source method: `{v.get('source_method')}`")
        lines.append(f"- Source: `{v.get('source_kind')}` / `{v.get('source_api')}`")
        lines.append(f"- Type: `{v.get('primitive_type')}`")
        lines.append(f"- Field: `{v.get('stored_field')}`")
        lines.append(f"- T6: `{v.get('t6_stage')}`")
        lines.append(f"- Protocol: `{v.get('protocol_semantics')}`")
        lines.append("- Lineage:")
        for step in v.get("lineage") or []:
            lines.append(f"  - {step}")
        lines.append("")
    return "\n".join(lines)


def render_structured_value_md(flow: dict[str, Any]) -> str:
    lines = [
        "# Structured Value Report (v1.5)",
        "",
        f"> {STRUCTURED_VALUE_DEFINITION['definition']}",
        "",
        "## Counts",
        "",
    ]
    for k, v in (flow.get("counts") or {}).items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")
    lines.append("## Value classes")
    lines.append("")
    for k, v in (flow.get("value_class_counts") or {}).items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")
    lines.append("## Stored fields (descriptors only)")
    lines.append("")
    for f in flow.get("stored_fields") or []:
        lines.append(f"- `{f}`")
    lines.append("")
    lines.append("Protocol semantics: **UNKNOWN**")
    lines.append("")
    return "\n".join(lines)


def render_field_consumer_md(flow: dict[str, Any]) -> str:
    lines = [
        "# Field Consumer Closure Report (v1.5)",
        "",
        "> Store → Load → Consumer. Same field descriptor = CORRELATION.",
        "",
        "| Kind | Method | Field | Index | Class |",
        "|---|---|---|---:|---|",
    ]
    for c in (flow.get("field_consumers") or [])[:100]:
        lines.append(
            f"| {c.get('kind')} | {c.get('method')} | "
            f"{c.get('field') or c.get('fields') or c.get('source_field')} | "
            f"{c.get('instruction_index')} | {c.get('classification')} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_application_flow_md(report: dict[str, Any]) -> str:
    lines = [
        "# Application Flow Evidence Report (v1.5)",
        "",
        "> Structured Value → Application Flow. Not protocol reconstruction.",
        "",
        "## Interpretation",
        "",
        report.get("interpretation") or "",
        "",
        "## PATH-COMM provenance",
        "",
    ]
    for k, v in (report.get("path_comm_provenance") or {}).items():
        lines.append(f"- **{k}**: `{v}`")
    lines.append("")
    lines.append("## Answers")
    lines.append("")
    for k, v in (report.get("answers") or {}).items():
        lines.append(f"- **{k}**: `{json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v}`")
    lines.append("")
    lines.append("Protocol semantics: **UNKNOWN**")
    lines.append("")
    return "\n".join(lines)


def write_application_flow_reports(
    out_dir: Path,
    flow: dict[str, Any],
    app_report: dict[str, Any],
) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    pairs = [
        ("STRUCTURED_VALUE_REPORT", flow, render_structured_value_md),
        ("VALUE_LINEAGE_REPORT", flow, render_value_lineage_md),
        ("FIELD_CONSUMER_CLOSURE_REPORT", flow, render_field_consumer_md),
        ("APPLICATION_FLOW_EVIDENCE_REPORT", app_report, render_application_flow_md),
    ]
    for name, payload, renderer in pairs:
        # For structured/value/field use flow; application uses app_report
        jp = out_dir / f"{name}.json"
        mp = out_dir / f"{name}.md"
        if name == "APPLICATION_FLOW_EVIDENCE_REPORT":
            data = payload
        elif name == "STRUCTURED_VALUE_REPORT":
            data = {
                "schema": "apk_forensics.structured_value_report.v1",
                "definition": STRUCTURED_VALUE_DEFINITION,
                "counts": flow.get("counts"),
                "value_class_counts": flow.get("value_class_counts"),
                "stored_fields": flow.get("stored_fields"),
                "value_catalog": flow.get("value_catalog"),
                "protocol_semantics": "UNKNOWN",
            }
        elif name == "VALUE_LINEAGE_REPORT":
            data = {
                "schema": "apk_forensics.value_lineage_report.v1",
                "value_catalog": flow.get("value_catalog"),
                "protocol_semantics": "UNKNOWN",
            }
        else:
            data = {
                "schema": "apk_forensics.field_consumer_closure_report.v1",
                "field_consumers": flow.get("field_consumers"),
                "stored_fields": flow.get("stored_fields"),
                "protocol_semantics": "UNKNOWN",
            }
        jp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        mp.write_text(renderer(flow if name != "APPLICATION_FLOW_EVIDENCE_REPORT" else app_report), encoding="utf-8")
        written[name] = jp
    return written
