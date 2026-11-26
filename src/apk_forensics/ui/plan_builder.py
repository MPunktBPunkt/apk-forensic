"""Search Plan Builder — investigation goal → validated SearchPlan draft.

Deterministic / local. Never produces evidence, FACT, or protocol semantics.
Uses only fields supported by search_plan.validate_and_normalize.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from apk_forensics.search_plan import (
    KNOWN_API_PATTERNS,
    SEARCH_PLAN_SCHEMA_VERSION,
    SearchPlan,
    compute_plan_sha256,
    load_plan_yaml,
    load_search_plan,
    validate_and_normalize,
)
from apk_forensics.utils import utc_now_iso

PLAN_PROVENANCE_SCHEMA = "apk_forensics.plan_provenance.v1"

# Parameter help (meaning + scope impact). No invented performance numbers.
PARAM_HELP: dict[str, dict[str, str]] = {
    "dex_context.instruction_window": {
        "meaning": "Instruction window around matched DEX sites.",
        "impact": "Larger windows expand context size in DEX context results.",
    },
    "dex_context.xref_depth": {
        "meaning": "Caller/callee XREF expansion depth (0–2).",
        "impact": "Higher depth widens call-graph exploration.",
    },
    "dex_context.max_callers": {
        "meaning": "Cap on recorded callers per site.",
        "impact": "Higher caps retain more caller edges (SearchPlan limit, not Resource Policy).",
    },
    "dex_context.max_callees": {
        "meaning": "Cap on recorded callees per site.",
        "impact": "Higher caps retain more callee edges.",
    },
    "bluetooth.dataflow_depth": {
        "meaning": "Bluetooth dataflow reconstruction depth.",
        "impact": "Deeper flow follows more hops from socket/stream sites.",
    },
    "bluetooth.caller_depth": {
        "meaning": "Caller reconstruction depth for Bluetooth paths.",
        "impact": "Higher values expand caller chains above RFCOMM/socket use.",
    },
    "bluetooth.max_method_hops": {
        "meaning": "Max interprocedural method hops (Bluetooth object flow).",
        "impact": "Higher values can yield more evidence paths and raise runtime/memory.",
    },
    "bluetooth.max_field_hops": {
        "meaning": "Max field hops in Bluetooth object flow.",
        "impact": "Higher values follow more field stores/loads.",
    },
    "bluetooth.max_object_nodes": {
        "meaning": "Cap on Bluetooth object-flow nodes.",
        "impact": "Hard SearchPlan bound on graph size.",
    },
    "evidence_graph.max_evidence_paths": {
        "meaning": "Maximum extracted evidence paths from the graph.",
        "impact": "Caps reported path count (not a resource policy).",
    },
    "communication.max_method_hops": {
        "meaning": "Max method hops above transport (buffers/parsers/messages).",
        "impact": "Higher values explore deeper communication dataflow.",
    },
    "communication.max_field_hops": {
        "meaning": "Max field hops in communication dataflow.",
        "impact": "Higher values follow more field-mediated flows.",
    },
    "communication.max_buffer_hops": {
        "meaning": "Max buffer/arraycopy-style hops.",
        "impact": "Higher values follow longer buffer chains.",
    },
    "communication.max_parser_hops": {
        "meaning": "Max hops into parser/decoder-like consumers.",
        "impact": "Higher values expand decoder-side exploration.",
    },
    "communication.max_message_hops": {
        "meaning": "Max hops into message/object assembly sites.",
        "impact": "Higher values expand message-side exploration.",
    },
    "communication.max_dataflow_paths": {
        "meaning": "Cap on communication dataflow paths.",
        "impact": "SearchPlan result bound.",
    },
}

# Deterministic topic heuristics — search intention only, never “FOUND”.
TOPIC_HEURISTICS: list[dict[str, Any]] = [
    {
        "id": "iap2",
        "match": [r"\biap2\b", r"\biap\b", r"accessory protocol", r"\biap\s*2\b"],
        "terms": ["iAP2", "iAP", "Accessory Protocol", "iPod Accessory", "EASession"],
        "api_patterns": ["bluetooth", "usb", "socket", "android"],
        "enable": {"bluetooth": True, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched investigation topic 'iAP2/accessory' → added as search terms only (not protocol FACT).",
            "Bluetooth/USB/socket api_patterns enabled as supported search scopes.",
            "Bluetooth + communication + evidence_graph enabled for static path/dataflow investigation.",
        ],
    },
    {
        "id": "aoa",
        "match": [r"\baoa\b", r"android open accessory", r"usbaccessory", r"usb accessory"],
        "terms": ["AOA", "Android Open Accessory", "UsbAccessory", "UsbManager", "accessory"],
        "api_patterns": ["usb", "android", "socket"],
        "enable": {"bluetooth": False, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched AOA/USB accessory topic → search terms/API patterns only.",
            "Communication/DEX context enabled for static accessory I/O path exploration.",
        ],
    },
    {
        "id": "rfcomm_bt",
        "match": [r"\brfcomm\b", r"bluetooth", r"bluetoothsocket", r"\bspp\b"],
        "terms": [
            "BluetoothSocket",
            "createRfcommSocketToServiceRecord",
            "getInputStream",
            "getOutputStream",
            "RFCOMM",
        ],
        "api_patterns": ["bluetooth", "rfcomm", "socket", "android"],
        "enable": {"bluetooth": True, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched Bluetooth/RFCOMM topic → transport search terms + bluetooth module.",
            "Communication enabled to follow stream/buffer consumers statically.",
        ],
    },
    {
        "id": "auth_handshake",
        "match": [r"auth", r"handshake", r"challenge", r"pairing", r"certificate"],
        "terms": ["authenticate", "handshake", "challenge", "response", "pairing", "certificate"],
        "api_patterns": ["network", "socket", "android"],
        "enable": {"bluetooth": True, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched auth/handshake language → generic search terms (no protocol identity claimed).",
            "Communication/Bluetooth enabled for static path following around candidate sites.",
        ],
    },
    {
        "id": "media_audio",
        "match": [r"\baudio\b", r"\bmedia\b", r"a2dp", r"avrcp", r"sound"],
        "terms": ["AudioTrack", "MediaPlayer", "AudioManager", "A2DP", "AVRCP", "audio"],
        "api_patterns": ["bluetooth", "android", "socket"],
        "enable": {"bluetooth": True, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched media/audio topic → search terms only; no format/protocol FACT.",
        ],
    },
    {
        "id": "bcl",
        "match": [r"\bbcl\b", r"carlink"],
        "terms": ["BCL", "BclConnection", "AccessorySocket"],
        "api_patterns": ["bluetooth", "socket", "android"],
        "enable": {"bluetooth": True, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched BCL/CarLink as search intention terms only — no vendor/protocol identity asserted.",
        ],
    },
    {
        "id": "etch_rhmi",
        "match": [r"\betch\b", r"\brhmi\b", r"\bsas\b"],
        "terms": ["Etch", "RHMI", "SAS"],
        "api_patterns": ["android", "socket", "network"],
        "enable": {"bluetooth": True, "communication": True, "evidence_graph": True, "dex_context": True},
        "rationale": [
            "Matched Etch/RHMI/SAS as literal search targets only — no semantic FACT injection.",
        ],
    },
]


def slugify_plan_name(text: str, *, fallback: str = "custom_investigation") -> str:
    s = text.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = s.strip("_")[:48]
    return s or fallback


def match_topics(goal: str) -> list[dict[str, Any]]:
    g = goal.lower()
    hits: list[dict[str, Any]] = []
    for topic in TOPIC_HEURISTICS:
        for pat in topic["match"]:
            if re.search(pat, g, flags=re.IGNORECASE):
                hits.append(topic)
                break
    return hits


def base_inventory_modules() -> list[str]:
    return ["manifest", "zip_inventory", "dex", "strings", "uuid", "candidate"]


def suggest_plan_from_goal(
    goal: str,
    *,
    plan_name: str | None = None,
    depth: str = "standard",
) -> dict[str, Any]:
    """Build a raw SearchPlan dict + provenance/rationale. Not evidence."""
    goal = (goal or "").strip()
    if not goal:
        raise ValueError("investigation goal is required")

    topics = match_topics(goal)
    terms: list[str] = []
    api_patterns: list[str] = []
    rationale: list[str] = [
        "Investigation goal is metadata / search intention — not evidence.",
        "Suggestion configures SearchPlan fields only; analyzer findings remain evidence-driven.",
    ]
    enable = {
        "dex_context": True,
        "bluetooth": False,
        "communication": False,
        "evidence_graph": False,
        "correlation": False,
    }

    if not topics:
        # Generic static investigation: take notable tokens as search terms
        tokens = re.findall(r"[A-Za-z][A-Za-z0-9_\-]{2,}", goal)
        stop = {
            "und",
            "die",
            "der",
            "das",
            "the",
            "and",
            "for",
            "with",
            "untersuche",
            "untersuchung",
            "analyze",
            "analyse",
            "search",
            "suche",
            "ob",
            "wie",
            "which",
            "what",
            "path",
            "paths",
            "daten",
            "data",
            "flow",
            "flows",
            "so",
            "weit",
            "möglich",
            "möglichst",
            "static",
            "statisch",
            "apk",
        }
        for t in tokens:
            if t.lower() in stop:
                continue
            if t not in terms:
                terms.append(t)
            if len(terms) >= 12:
                break
        enable["bluetooth"] = any(x in goal.lower() for x in ("bluetooth", "socket", "kommunik", "communic"))
        enable["communication"] = enable["bluetooth"] or "daten" in goal.lower() or "data" in goal.lower()
        enable["evidence_graph"] = enable["bluetooth"] or enable["communication"]
        rationale.append(
            "No named topic heuristic matched; extracted alphanumeric tokens as literal search terms."
        )
        if enable["bluetooth"]:
            rationale.append("Goal language suggested communication/transport → bluetooth/communication modules.")
    else:
        for topic in topics:
            for t in topic.get("terms") or []:
                if t not in terms:
                    terms.append(t)
            for a in topic.get("api_patterns") or []:
                if a in KNOWN_API_PATTERNS and a not in api_patterns:
                    api_patterns.append(a)
            for k, v in (topic.get("enable") or {}).items():
                if v:
                    enable[k] = True
            rationale.extend(topic.get("rationale") or [])

    # Depth presets (SearchPlan traversal only)
    depth = (depth or "standard").lower()
    if depth not in {"shallow", "standard", "deep"}:
        depth = "standard"
    depth_params = {
        "shallow": {
            "xref_depth": 1,
            "instruction_window": 6,
            "bt_dataflow_depth": 1,
            "bt_method_hops": 2,
            "bt_field_hops": 1,
            "comm_method_hops": 2,
            "comm_field_hops": 1,
            "comm_buffer_hops": 3,
        },
        "standard": {
            "xref_depth": 2,
            "instruction_window": 8,
            "bt_dataflow_depth": 2,
            "bt_method_hops": 3,
            "bt_field_hops": 2,
            "comm_method_hops": 3,
            "comm_field_hops": 2,
            "comm_buffer_hops": 5,
        },
        "deep": {
            "xref_depth": 2,
            "instruction_window": 12,
            "bt_dataflow_depth": 3,
            "bt_method_hops": 5,
            "bt_field_hops": 4,
            "comm_method_hops": 5,
            "comm_field_hops": 4,
            "comm_buffer_hops": 8,
        },
    }[depth]
    rationale.append(f"Traversal depth preset '{depth}' applied to supported SearchPlan fields only.")

    modules = base_inventory_modules()
    if enable["dex_context"]:
        modules.extend(["dex_context", "xref"])
    if enable["bluetooth"]:
        modules.append("bluetooth")
    # communication/evidence_graph/correlation are flags, not module enum entries

    name = plan_name or slugify_plan_name(topics[0]["id"] + "_investigation" if topics else goal)
    raw: dict[str, Any] = {
        "schema_version": SEARCH_PLAN_SCHEMA_VERSION,
        "plan": {
            "name": name,
            "description": (
                f"User investigation goal (search intention, not evidence):\n{goal}"
            ),
            "modules": modules,
        },
        "input": {
            "description": "APK path provided by CLI / Workbench (not by this plan).",
            "note": f"source_goal: {goal}",
        },
        "search": {
            "terms": terms,
            "regex": [],
            "uuids": [],
            "api_patterns": api_patterns,
        },
        "dex_context": {
            "enabled": bool(enable["dex_context"]),
            "instruction_window": depth_params["instruction_window"],
            "xref_depth": depth_params["xref_depth"],
            "max_callers": 20,
            "max_callees": 20,
        },
        "bluetooth": {
            "enabled": bool(enable["bluetooth"]),
            "dataflow_depth": depth_params["bt_dataflow_depth"],
            "window": 12,
            "max_paths": 50,
            "max_results": 100,
            "caller_depth": 2,
            "reconstruct_callers": True,
            "reconstruct_streams": True,
            "reconstruct_read_write": True,
            "max_callers": 50,
            "max_callees": 50,
            "max_dataflow_paths": 50,
            "max_dataflow_nodes": 200,
            "interprocedural": True,
            "max_method_hops": depth_params["bt_method_hops"],
            "max_field_hops": depth_params["bt_field_hops"],
            "max_object_nodes": 500,
        },
        "evidence_graph": {
            "enabled": bool(enable["evidence_graph"]),
            "canonicalize": True,
            "deduplicate": True,
            "extract_paths": True,
            "include_boundaries": True,
            "max_evidence_paths": 50,
        },
        "communication": {
            "enabled": bool(enable["communication"]),
            "interprocedural": True,
            "max_method_hops": depth_params["comm_method_hops"],
            "max_field_hops": depth_params["comm_field_hops"],
            "max_object_nodes": 500,
            "max_dataflow_paths": 100,
            "max_buffer_hops": depth_params["comm_buffer_hops"],
            "max_parser_hops": 3,
            "max_message_hops": 3,
        },
        "correlation": {
            "enabled": False,
            "timestamp_window_ms": 50,
            "max_runtime_events": 10000,
            "max_wire_packets": 10000,
            "max_correlations": 500,
            "require_direction_match": True,
            "allow_fragmentation": True,
            "allow_aggregation": True,
        },
        "evidence": {
            "classifications": ["FACT", "CORRELATION", "INFERENCE", "UNKNOWN"],
        },
        "limits": {
            "max_results": 100,
            "max_contexts": 100,
            "max_xrefs": 1000,
            "max_chains": 20,
            "max_findings": 10000,
        },
        "output": {"format": ["json", "markdown"], "include_raw": False},
    }

    plan = validate_and_normalize(raw)
    preview = plan_preview(plan, goal=goal, rationale=rationale, topics=[t["id"] for t in topics])
    return {
        "ok": True,
        "kind": "SUGGESTION",
        "note": (
            "Plan suggestion only. Does not mean any protocol/topic was FOUND. "
            "No evidence / FACT produced."
        ),
        "raw": plan.to_canonical_dict(),
        "plan": preview,
        "provenance": {
            "schema": PLAN_PROVENANCE_SCHEMA,
            "source_goal": goal,
            "topics_matched": [t["id"] for t in topics],
            "rationale": rationale,
            "depth_preset": depth,
            "created_at": utc_now_iso(),
            "created_by": "plan_builder.suggest_plan_from_goal",
            "plan_sha256": plan.plan_sha256,
        },
    }


def plan_to_yaml(plan: SearchPlan | dict[str, Any]) -> str:
    data = plan.to_canonical_dict() if isinstance(plan, SearchPlan) else dict(plan)
    # Ensure schema_version present for round-trip save
    if "schema_version" not in data:
        data = {"schema_version": SEARCH_PLAN_SCHEMA_VERSION, **data}
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def plan_to_normalized_json(plan: SearchPlan) -> str:
    payload = plan.to_canonical_dict()
    payload["plan_sha256"] = plan.plan_sha256
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def plan_capabilities(plan: SearchPlan) -> dict[str, Any]:
    can = []
    cannot = [
        "APK execution",
        "Runtime instrumentation / live device evidence",
        "Wire capture collection",
        "Same-session runtime↔wire correlation without INPUT",
        "Automatic protocol semantics (names ≠ meaning)",
        "Extended diagnose-* post-processing (application-flow / V001 deep forensic) — NOT AUTOMATIC in Workbench base scan",
    ]
    can.append("String / API / UUID search")
    if plan.dex_context_enabled:
        can.append("DEX context / XREF")
    if plan.bluetooth_enabled:
        can.append("Bluetooth transport paths")
        if plan.bluetooth_reconstruct_callers:
            can.append("Bluetooth caller reconstruction")
        if plan.bluetooth_interprocedural:
            can.append("Bluetooth object / interprocedural flow")
    if plan.evidence_graph_enabled:
        can.append("Evidence graph extraction")
    if plan.communication_enabled:
        can.append("Communication object/dataflow (static)")
    if plan.correlation_enabled:
        can.append(
            "Offline static↔runtime/wire correlation limits (requires external INPUT; does not execute APK)"
        )
    else:
        cannot.append("Correlation enabled in this plan (flag is off)")

    return {
        "can": can,
        "cannot": cannot,
        "pipeline_coverage": {
            "base_static_analysis": "AVAILABLE",
            "extended_forensic_post_processing": "NOT AUTOMATIC",
            "runtime_instrumentation": "SEPARATE WORKFLOW",
            "runtime_wire_correlation": "INPUT-DEPENDENT",
        },
    }


def plan_preview(
    plan: SearchPlan,
    *,
    goal: str | None = None,
    rationale: list[str] | None = None,
    topics: list[str] | None = None,
) -> dict[str, Any]:
    caps = plan_capabilities(plan)
    areas = {
        "search": True,
        "dex_context": plan.dex_context_enabled,
        "bluetooth": plan.bluetooth_enabled,
        "evidence_graph": plan.evidence_graph_enabled,
        "communication": plan.communication_enabled,
        "correlation": plan.correlation_enabled,
    }
    return {
        "name": plan.plan_name,
        "description": plan.plan_description,
        "plan_sha256": plan.plan_sha256,
        "modules": list(plan.modules),
        "areas": areas,
        "search_targets": {
            "terms": list(plan.search_terms),
            "regex": list(plan.search_regex),
            "uuids": list(plan.search_uuids),
            "api_patterns": list(plan.api_patterns),
        },
        "traversal": {
            "instruction_window": plan.instruction_window,
            "xref_depth": plan.xref_depth,
            "max_callers": plan.max_callers,
            "max_callees": plan.max_callees,
            "bluetooth_dataflow_depth": plan.bluetooth_dataflow_depth,
            "bluetooth_max_method_hops": plan.bluetooth_max_method_hops,
            "bluetooth_max_field_hops": plan.bluetooth_max_field_hops,
            "communication_max_method_hops": plan.communication_max_method_hops,
            "communication_max_field_hops": plan.communication_max_field_hops,
            "communication_max_buffer_hops": plan.communication_max_buffer_hops,
            "communication_max_parser_hops": plan.communication_max_parser_hops,
            "communication_max_message_hops": plan.communication_max_message_hops,
            "evidence_graph_max_paths": plan.evidence_graph_max_paths,
        },
        "param_help": PARAM_HELP,
        "investigation_goal": goal,
        "topics_matched": topics or [],
        "rationale": rationale or [],
        "what_this_plan_investigates": caps["can"],
        "what_this_plan_cannot": caps["cannot"],
        "pipeline_coverage": caps["pipeline_coverage"],
        "yaml": plan_to_yaml(plan),
        "normalized_json": plan_to_normalized_json(plan),
        "disclaimer": (
            "SearchPlan describes what/how to investigate. "
            "It does not assert that any named protocol was found."
        ),
    }


def validate_raw_plan(raw: dict[str, Any]) -> dict[str, Any]:
    try:
        plan = validate_and_normalize(raw)
    except Exception as exc:  # PlanValidationError or others
        errors = getattr(exc, "errors", None) or [str(exc)]
        return {"ok": False, "error": "INVALID_SEARCH_PLAN", "errors": list(errors)}
    return {
        "ok": True,
        "plan": plan_preview(plan, goal=(raw.get("input") or {}).get("note")),
        "plan_sha256": plan.plan_sha256,
    }


def build_raw_from_builder_form(form: dict[str, Any]) -> dict[str, Any]:
    """Map UI form fields → SearchPlan YAML-shaped dict (supported fields only)."""
    name = slugify_plan_name(str(form.get("name") or "custom_plan"))
    goal = str(form.get("investigation_goal") or form.get("goal") or "").strip()
    terms = [str(t).strip() for t in (form.get("terms") or []) if str(t).strip()]
    regex = [str(t).strip() for t in (form.get("regex") or []) if str(t).strip()]
    uuids = [str(t).strip() for t in (form.get("uuids") or []) if str(t).strip()]
    api_patterns = [str(t).strip() for t in (form.get("api_patterns") or []) if str(t).strip()]
    areas = form.get("areas") or {}
    trav = form.get("traversal") or {}

    modules = list(form.get("modules") or base_inventory_modules())
    if areas.get("dex_context") and "dex_context" not in modules:
        modules.extend(["dex_context", "xref"])
    if areas.get("bluetooth") and "bluetooth" not in modules:
        modules.append("bluetooth")

    raw: dict[str, Any] = {
        "schema_version": SEARCH_PLAN_SCHEMA_VERSION,
        "plan": {
            "name": name,
            "description": form.get("description")
            or (f"User investigation goal (search intention, not evidence):\n{goal}" if goal else name),
            "modules": modules,
        },
        "input": {
            "description": "APK path provided by CLI / Workbench (not by this plan).",
            "note": f"source_goal: {goal}" if goal else "user plan",
        },
        "search": {
            "terms": terms,
            "regex": regex,
            "uuids": uuids,
            "api_patterns": api_patterns,
        },
        "dex_context": {
            "enabled": bool(areas.get("dex_context", True)),
            "instruction_window": int(trav.get("instruction_window", 8)),
            "xref_depth": int(trav.get("xref_depth", 2)),
            "max_callers": int(trav.get("max_callers", 20)),
            "max_callees": int(trav.get("max_callees", 20)),
        },
        "bluetooth": {
            "enabled": bool(areas.get("bluetooth", False)),
            "dataflow_depth": int(trav.get("bluetooth_dataflow_depth", trav.get("dataflow_depth", 2))),
            "window": int(trav.get("bluetooth_window", 12)),
            "max_paths": int(trav.get("bluetooth_max_paths", 50)),
            "max_results": int(trav.get("bluetooth_max_results", 100)),
            "caller_depth": int(trav.get("bluetooth_caller_depth", 2)),
            "reconstruct_callers": bool(trav.get("reconstruct_callers", True)),
            "reconstruct_streams": bool(trav.get("reconstruct_streams", True)),
            "reconstruct_read_write": bool(trav.get("reconstruct_read_write", True)),
            "max_callers": int(trav.get("bluetooth_max_callers", 50)),
            "max_callees": int(trav.get("bluetooth_max_callees", 50)),
            "max_dataflow_paths": int(trav.get("bluetooth_max_dataflow_paths", 50)),
            "max_dataflow_nodes": int(trav.get("bluetooth_max_dataflow_nodes", 200)),
            "interprocedural": bool(trav.get("bluetooth_interprocedural", True)),
            "max_method_hops": int(trav.get("bluetooth_max_method_hops", trav.get("max_method_hops", 3))),
            "max_field_hops": int(trav.get("bluetooth_max_field_hops", trav.get("max_field_hops", 2))),
            "max_object_nodes": int(trav.get("bluetooth_max_object_nodes", 500)),
        },
        "evidence_graph": {
            "enabled": bool(areas.get("evidence_graph", False)),
            "canonicalize": bool(trav.get("canonicalize", True)),
            "deduplicate": bool(trav.get("deduplicate", True)),
            "extract_paths": bool(trav.get("extract_paths", True)),
            "include_boundaries": bool(trav.get("include_boundaries", True)),
            "max_evidence_paths": int(trav.get("evidence_graph_max_paths", trav.get("max_paths", 50))),
        },
        "communication": {
            "enabled": bool(areas.get("communication", False)),
            "interprocedural": bool(trav.get("communication_interprocedural", True)),
            "max_method_hops": int(trav.get("communication_max_method_hops", 3)),
            "max_field_hops": int(trav.get("communication_max_field_hops", 2)),
            "max_object_nodes": int(trav.get("communication_max_object_nodes", 500)),
            "max_dataflow_paths": int(trav.get("communication_max_dataflow_paths", 100)),
            "max_buffer_hops": int(trav.get("communication_max_buffer_hops", 5)),
            "max_parser_hops": int(trav.get("communication_max_parser_hops", 3)),
            "max_message_hops": int(trav.get("communication_max_message_hops", 3)),
        },
        "correlation": {
            "enabled": bool(areas.get("correlation", False)),
            "timestamp_window_ms": 50,
            "max_runtime_events": 10000,
            "max_wire_packets": 10000,
            "max_correlations": 500,
            "require_direction_match": True,
            "allow_fragmentation": True,
            "allow_aggregation": True,
        },
        "evidence": {
            "classifications": list(
                form.get("evidence_classifications")
                or ["FACT", "CORRELATION", "INFERENCE", "UNKNOWN"]
            ),
        },
        "limits": {
            "max_results": int(trav.get("max_results", 100)),
            "max_contexts": int(trav.get("max_contexts", 100)),
            "max_xrefs": int(trav.get("max_xrefs", 1000)),
            "max_chains": int(trav.get("max_chains", 20)),
            "max_findings": int(trav.get("max_findings", 10000)),
        },
        "output": {"format": ["json", "markdown"], "include_raw": False},
    }
    return raw


@dataclass
class SavedUserPlan:
    path: Path
    provenance_path: Path | None
    plan: SearchPlan
    kind: str = "user"


def user_plans_dir(root: Path) -> Path:
    d = (root / "work" / "user-plans").resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_user_plans(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    d = user_plans_dir(root)
    for path in sorted(d.glob("*.yaml")):
        try:
            plan = load_search_plan(path)
            prov_path = path.with_suffix(".provenance.json")
            prov = None
            if prov_path.is_file():
                prov = json.loads(prov_path.read_text(encoding="utf-8"))
            out.append(
                {
                    "id": f"user:{plan.plan_name}",
                    "name": plan.plan_name,
                    "path": str(path),
                    "rel_path": str(path.relative_to(root.resolve())) if path.is_relative_to(root.resolve()) else str(path),
                    "description": plan.plan_description,
                    "plan_sha256": plan.plan_sha256,
                    "kind": "user",
                    "valid": True,
                    "provenance": prov,
                    "modules": list(plan.modules),
                    "dex_context_enabled": plan.dex_context_enabled,
                    "bluetooth_enabled": plan.bluetooth_enabled,
                    "evidence_graph_enabled": plan.evidence_graph_enabled,
                    "communication_enabled": plan.communication_enabled,
                    "correlation_enabled": plan.correlation_enabled,
                }
            )
        except Exception as exc:  # noqa: BLE001
            out.append(
                {
                    "id": f"user:{path.stem}",
                    "name": path.stem,
                    "path": str(path),
                    "kind": "user",
                    "valid": False,
                    "error": str(exc),
                }
            )
    return out


def save_user_plan(
    root: Path,
    raw: dict[str, Any],
    *,
    provenance: dict[str, Any] | None = None,
    overwrite: bool = False,
) -> SavedUserPlan:
    plan = validate_and_normalize(raw)
    dest_dir = user_plans_dir(root)
    dest = dest_dir / f"{plan.plan_name}.yaml"
    if dest.exists() and not overwrite:
        raise FileExistsError(f"User plan already exists: {dest.name} (use overwrite or rename)")
    dest.write_text(plan_to_yaml(plan), encoding="utf-8")
    prov = {
        "schema": PLAN_PROVENANCE_SCHEMA,
        "created_at": utc_now_iso(),
        "created_by": "workbench.plan_builder",
        "source_goal": (provenance or {}).get("source_goal")
        or (raw.get("input") or {}).get("note"),
        "base_plan": (provenance or {}).get("base_plan"),
        "topics_matched": (provenance or {}).get("topics_matched") or [],
        "rationale": (provenance or {}).get("rationale") or [],
        "plan_sha256": plan.plan_sha256,
        "plan_file": dest.name,
        "note": "Provenance is not evidence. SearchPlan configures investigation only.",
    }
    if provenance:
        for k, v in provenance.items():
            if k not in {"schema"} and v is not None:
                prov[k] = v
        prov["plan_sha256"] = plan.plan_sha256
    prov_path = dest.with_suffix(".provenance.json")
    prov_path.write_text(json.dumps(prov, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return SavedUserPlan(path=dest, provenance_path=prov_path, plan=plan, kind="user")


def clone_plan(
    root: Path,
    source_path: Path,
    *,
    new_name: str,
    goal_note: str | None = None,
) -> SavedUserPlan:
    raw = load_plan_yaml(source_path)
    raw = deepcopy(raw)
    plan_sec = raw.setdefault("plan", {})
    plan_sec["name"] = slugify_plan_name(new_name)
    if goal_note:
        plan_sec["description"] = (
            (plan_sec.get("description") or "")
            + f"\n\nCloned investigation note (not evidence): {goal_note}"
        ).strip()
        raw.setdefault("input", {})["note"] = f"cloned_from={source_path.name}; {goal_note}"
    return save_user_plan(
        root,
        raw,
        provenance={
            "base_plan": str(source_path),
            "source_goal": goal_note,
            "rationale": [f"Cloned from {source_path.name} without modifying the original."],
        },
        overwrite=False,
    )
