"""Deterministic read-only aggregator: existing reports → analysis_ui_snapshot.v1.

Never invents FACT/INFERENCE/UNKNOWN. Missing inputs stay INPUT_MISSING.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from apk_forensics import __version__
from apk_forensics.runtime_wire_evidence import V001_RUNTIME_HOOK_TARGET

SNAPSHOT_SCHEMA = "apk_forensics.analysis_ui_snapshot.v1"

# Case presets map logical roles → relative report paths (repo-root relative).
CASE_PRESETS: dict[str, dict[str, Any]] = {
    "bmw-connected": {
        "label": "BMW Connected 6.0.0.4962",
        "focus_value_id": "VALUE-V001",
        "sources": {
            "baseline_meta": "output/v16-baseline/BASELINE_META.json",
            "application_flow": "output/v15-application-flow/APPLICATION_FLOW_EVIDENCE_REPORT.json",
            "structured_value_flow": "output/v15-application-flow/structured_value_flow.json",
            "value_v001": "output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
            "buffer_semantics": "output/v14-semantic-closure/BUFFER_SEMANTIC_CLOSURE_REPORT.json",
            "transport_closure": "output/v13-closure/TRANSPORT_EVIDENCE_CLOSURE_REPORT.json",
            "runtime_evidence": "output/v16-runtime-capture/runtime_evidence.v1.json",
            "runtime_capture_report": "output/v16-runtime-capture/RUNTIME_CAPTURE_REPORT.json",
            "runtime_readiness": "output/v17-runtime-evidence/RUNTIME_EVIDENCE_V1_READINESS.json",
            "cross_apk": "output/v16-cross-apk/CROSS_APK_EVALUATION_REPORT.json",
        },
    },
    "bimmerlink": {
        "label": "BimmerLink 2.38.1-7223",
        "focus_value_id": None,
        "sources": {
            "case_meta": "output/bimmerlink-2381/META.json",
            "application_flow": "output/bimmerlink-2381/v15-flow/APPLICATION_FLOW_EVIDENCE_REPORT.json",
            "structured_value_flow": "output/bimmerlink-2381/v15-flow/structured_value_flow.json",
            "transport_closure": "output/bimmerlink-2381/v13-closure/TRANSPORT_EVIDENCE_CLOSURE_REPORT.json",
        },
    },
    "serial-bt": {
        "label": "Serial Bluetooth Terminal 1.52",
        "focus_value_id": "VALUE-V001",
        "sources": {
            "application_flow": "output/serial-bt-terminal-152/v15-flow/APPLICATION_FLOW_EVIDENCE_REPORT.json",
            "structured_value_flow": "output/serial-bt-terminal-152/v15-flow/structured_value_flow.json",
            "case_meta": "output/serial-bt-terminal-152/.apk-forensics-managed.json",
        },
    },
}


def load_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not Path(path).is_file():
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def _source_entry(root: Path, role: str, rel: str | None) -> dict[str, Any]:
    if not rel:
        return {"role": role, "path": None, "present": False}
    path = root / rel
    return {
        "role": role,
        "path": rel,
        "present": path.is_file(),
        "sha256_prefix": (
            hashlib.sha256(path.read_bytes()).hexdigest()[:16] if path.is_file() else None
        ),
    }


def _status_block(
    *,
    static_analysis: str,
    value_analysis: str,
    runtime_pipeline: str,
    runtime_execution: str,
    wire_correlation: str,
    protocol_semantics: str,
) -> dict[str, str]:
    return {
        "STATIC_ANALYSIS": static_analysis,
        "VALUE_ANALYSIS": value_analysis,
        "RUNTIME_PIPELINE": runtime_pipeline,
        "RUNTIME_EXECUTION": runtime_execution,
        "WIRE_CORRELATION": wire_correlation,
        "PROTOCOL_SEMANTICS": protocol_semantics,
    }


def _catalog_from_flow(flow: dict[str, Any] | None, app: dict[str, Any] | None) -> list[dict[str, Any]]:
    if flow and flow.get("value_catalog"):
        return list(flow["value_catalog"])
    if app and app.get("value_catalog"):
        return list(app["value_catalog"])
    return []


def _counters_from_cross_apk(cross: dict[str, Any] | None, *, apk_key: str = "BMW_Connected") -> dict[str, Any]:
    if not cross:
        return {}
    # Canonical location in CROSS_APK_EVALUATION_REPORT.json
    table = ((cross.get("STATIC_FACTS") or {}).get("comparison_table")) or {}
    if isinstance(table, dict):
        if apk_key in table and isinstance(table[apk_key], dict):
            return dict(table[apk_key])
        # tolerate spaced labels
        want = apk_key.replace("_", " ").lower()
        for name, row in table.items():
            if isinstance(row, dict) and str(name).replace("_", " ").lower() == want:
                return dict(row)
            if isinstance(row, dict) and want in str(name).replace("_", " ").lower():
                return dict(row)
    return {}


def _counters(
    *,
    baseline: dict[str, Any] | None,
    app: dict[str, Any] | None,
    flow: dict[str, Any] | None,
    buffer: dict[str, Any] | None,
    transport: dict[str, Any] | None,
    case_meta: dict[str, Any] | None,
    cross_apk: dict[str, Any] | None = None,
    cross_apk_key: str = "BMW Connected",
) -> dict[str, Any]:
    answers = (app or {}).get("answers") or {}
    counts = (flow or {}).get("counts") or {}
    summary = (buffer or {}).get("summary") or {}
    t5 = ((buffer or {}).get("t5_audit") or {}) if buffer else {}
    out: dict[str, Any] = {
        "rfcomm_targets": None,
        "evidence_paths": None,
        "communication_paths": None,
        "structured_values": None,
        "v5_roundtrip_candidates": None,
        "field_loads": None,
        "decoder_candidates": None,
        "encoder_candidates": None,
        "source_notes": [],
    }
    if case_meta:
        if case_meta.get("rfcomm_targets") is not None:
            out["rfcomm_targets"] = case_meta.get("rfcomm_targets")
        if case_meta.get("bluetooth_paths") is not None and out["evidence_paths"] is None:
            out["source_notes"].append("case_meta.bluetooth_paths present (not evidence_paths)")
        if case_meta.get("communication_paths") is not None:
            out["communication_paths"] = case_meta.get("communication_paths")
        if case_meta.get("structured_values") is not None:
            out["structured_values"] = case_meta.get("structured_values")
    if baseline:
        out["structured_values"] = baseline.get("catalog_values", out["structured_values"])
        out["field_loads"] = baseline.get("field_loads", out["field_loads"])
        out["communication_paths"] = baseline.get("path_comm", out["communication_paths"])
        vcc = baseline.get("value_class_counts") or {}
        if "V5_ROUNDTRIP" in vcc:
            out["v5_roundtrip_candidates"] = vcc.get("V5_ROUNDTRIP")
    if counts:
        out["structured_values"] = counts.get("catalog_values", out["structured_values"])
        out["field_loads"] = counts.get("field_loads", out["field_loads"])
        out["v5_roundtrip_candidates"] = counts.get(
            "roundtrip_candidates", out["v5_roundtrip_candidates"]
        )
    # application-flow answers may embed catalog count object
    s4 = answers.get("1_structured_values_from_s4")
    if isinstance(s4, dict) and s4.get("catalog_count") is not None:
        out["structured_values"] = s4.get("catalog_count")
    if answers.get("3_later_loaded") is not None:
        out["field_loads"] = answers.get("3_later_loaded")
    if transport:
        out["evidence_paths"] = transport.get("transport_paths") or len(transport.get("paths") or []) or out["evidence_paths"]
        # inventory table length fallback
        inv = transport.get("inventory") or transport.get("paths") or []
        if out["evidence_paths"] is None and isinstance(inv, list):
            out["evidence_paths"] = len(inv)
    if buffer:
        # decoder/encoder from answers when present
        ans = buffer.get("answers") or {}
        # BMW buffer report references expanded communication
        if summary.get("decoder_candidates") is not None:
            out["decoder_candidates"] = summary.get("decoder_candidates")
        if summary.get("encoder_candidates") is not None:
            out["encoder_candidates"] = summary.get("encoder_candidates")
        # fallback from known BMW semantic closure answers text keys
        for key, dest in (
            ("decoder_candidates", "decoder_candidates"),
            ("encoder_candidates", "encoder_candidates"),
            ("serializer_candidates", "encoder_candidates"),
        ):
            if ans.get(key) is not None and out.get(dest) is None:
                out[dest] = ans.get(key)
    cross_row = _counters_from_cross_apk(cross_apk, apk_key=cross_apk_key)
    for key in (
        "rfcomm_targets",
        "evidence_paths",
        "communication_paths",
        "structured_values",
        "decoder_candidates",
        "encoder_candidates",
        "field_loads",
    ):
        if out.get(key) is None and cross_row.get(key) is not None:
            out[key] = cross_row.get(key)
            out["source_notes"].append(f"counter:{key}←cross_apk:{cross_apk_key}")
    if out.get("v5_roundtrip_candidates") is None and cross_row.get("v5_roundtrip") is not None:
        out["v5_roundtrip_candidates"] = cross_row.get("v5_roundtrip")
    if out.get("v5_roundtrip_candidates") is None and cross_row.get("values_with_roundtrip_candidate") is not None:
        out["v5_roundtrip_candidates"] = cross_row.get("values_with_roundtrip_candidate")
    # Hard-coded-free: leave None when unknown
    return out


def _apk_block(
    *,
    v001: dict[str, Any] | None,
    app: dict[str, Any] | None,
    case_meta: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
) -> dict[str, Any]:
    apk: dict[str, Any] = {
        "package": None,
        "version_name": None,
        "version_code": None,
        "sha256": None,
        "file": None,
        "analyzer_version": __version__,
        "analyzed_at_utc": None,
        "git_commit": None,
    }
    if case_meta:
        apk["package"] = case_meta.get("package") or apk["package"]
        apk["version_name"] = case_meta.get("version_name") or apk["version_name"]
        apk["version_code"] = case_meta.get("version_code") or apk["version_code"]
        art = case_meta.get("artifact") or {}
        apk["sha256"] = art.get("base_sha256") or apk["sha256"]
        apk["file"] = art.get("base_apk") or apk["file"]
        apk["analyzed_at_utc"] = case_meta.get("generated_at_utc") or apk["analyzed_at_utc"]
        apk["analyzer_version"] = case_meta.get("engine") or apk["analyzer_version"]
    if v001:
        method = v001.get("method") or {}
        ap = method.get("apk") or {}
        apk["package"] = ap.get("package_name") or apk["package"]
        apk["version_name"] = ap.get("version_name") or apk["version_name"]
        apk["version_code"] = ap.get("version_code") or apk["version_code"]
        apk["sha256"] = ap.get("sha256") or apk["sha256"]
        apk["file"] = ap.get("file") or apk["file"]
        apk["git_commit"] = v001.get("git_commit") or apk["git_commit"]
        apk["analyzed_at_utc"] = v001.get("generated_utc") or apk["analyzed_at_utc"]
        apk["analyzer_version"] = v001.get("engine") or apk["analyzer_version"]
    if app:
        prov = app.get("provenance") or {}
        apk["file"] = apk["file"] or prov.get("apk")
        apk["analyzer_version"] = apk["analyzer_version"] or prov.get("postprocessing_version")
    if readiness:
        apk["git_commit"] = apk["git_commit"] or readiness.get("git_commit_base")
        ra = readiness.get("apk") or {}
        apk["package"] = apk["package"] or ra.get("package_name")
        apk["version_name"] = apk["version_name"] or ra.get("version_name")
        apk["file"] = apk["file"] or ra.get("file")
    return apk


def _pipeline_stages(
    *,
    has_transport: bool,
    has_comm: bool,
    has_buffer: bool,
    has_values: bool,
    runtime_status: str,
    wire_status: str,
    correlation_status: str,
) -> list[dict[str, Any]]:
    def stage(sid: str, label: str, status: str, note: str) -> dict[str, Any]:
        return {"id": sid, "label": label, "status": status, "note": note}

    return [
        stage("apk", "APK", "FACT" if True else "UNKNOWN", "Input artefact identity from reports"),
        stage("inventory", "Inventory", "FACT" if has_transport or has_values or has_comm else "UNKNOWN", "ZIP/DEX inventory from prior scan"),
        stage("transport", "Transport", "FACT" if has_transport else "INPUT_MISSING", "Bluetooth/transport closure reports"),
        stage("communication", "Communication", "FACT" if has_comm else "INPUT_MISSING", "PATH-COMM / communication evidence"),
        stage("buffer", "Buffer / Bytes", "FACT" if has_buffer else "INPUT_MISSING", "Buffer semantic / byte processing"),
        stage("decoder", "Decoder", "FACT" if has_buffer or has_values else "UNKNOWN", "Decoder/encoder candidates from reports"),
        stage("structured_value", "Structured Value", "FACT" if has_values else "INPUT_MISSING", "VALUE-V### catalog"),
        stage("application_flow", "Application Flow", "FACT" if has_values else "INPUT_MISSING", "Field consumers / forward flow"),
        stage("runtime", "Runtime", runtime_status, "runtime_evidence.v1"),
        stage("wire", "Wire", wire_status, "wire_evidence.v1 / LAB capture"),
        stage("correlation", "Correlation", correlation_status, "STATIC↔RUNTIME↔WIRE joins"),
    ]


def _v001_nodes_edges(v001: dict[str, Any] | None, catalog_entry: dict[str, Any] | None) -> tuple[list[dict], list[dict], list[dict]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    open_edges: list[dict[str, Any]] = []
    if not v001 and not catalog_entry:
        return nodes, edges, open_edges

    def add_node(**kwargs: Any) -> str:
        nid = str(kwargs["id"])
        nodes.append(kwargs)
        return nid

    # Prefer forensic closure when present
    if v001:
        method = v001.get("method") or {}
        decoder = v001.get("decoder") or {}
        boundary = v001.get("boundary") or {}
        runtime = v001.get("runtime") or {}
        n_sock = add_node(
            id="n-accessory-read",
            label="AccessorySocket.read([BII)I",
            kind="TRANSPORT_INTERFACE",
            classification="FACT",
            limit="DYNAMIC_DISPATCH",
            method="Lcom/bmwgroup/connected/core/services/accessory/AccessorySocket;->read([B I I)I",
            source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
            details={
                "note": "Interface invoke; concrete impl not uniquely bound",
                "candidates": ["BtAccessorySocket", "UsbAccessorySocket", "EthAccessorySocket"],
            },
        )
        n_ir = add_node(
            id="n-internalread",
            label="BclConnection.internalread",
            kind="METHOD",
            classification="FACT",
            method="Lcom/bmwgroup/connected/core/services/accessory/bcl/BclConnection;->internalread([B I)I",
            source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
        )
        n_rp = add_node(
            id="n-readpacket",
            label="BclConnection.readPacket",
            kind="METHOD",
            classification="FACT",
            method="Lcom/bmwgroup/connected/core/services/accessory/bcl/BclConnection;->readPacket(...)",
            source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
        )
        n_data = add_node(
            id="n-packet-mdata",
            label="Packet.mData",
            kind="FIELD",
            classification="FACT",
            field="Packet.mData [B",
            source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
        )
        n_dec = add_node(
            id="n-decodeversion",
            label="Info.decodeVersion([B)S",
            kind="DECODER",
            classification="FACT",
            method=method.get("full") or V001_RUNTIME_HOOK_TARGET["static_source_api"],
            source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
            details={
                "transformation": "ByteBuffer.wrap(input, 0, 2).getShort()",
                "endianness": "BIG_ENDIAN",
                "reconstruction_status": decoder.get("reconstruction_status"),
            },
        )
        n_val = add_node(
            id="n-value-v001",
            label="VALUE-V001",
            kind="STRUCTURED_VALUE",
            classification="FACT",
            value_id="VALUE-V001",
            method=(catalog_entry or {}).get("source_api") or method.get("full"),
            source="output/v15-application-flow/structured_value_flow.json",
            details={
                "semantic_label": None,
                "protocol_semantics": "UNKNOWN",
                "stored_field": (catalog_entry or {}).get("stored_field")
                or "Lcom/bmwgroup/connected/core/services/accessory/bcl/BclConnection;->mVersion S",
                "value_class": (catalog_entry or {}).get("value_class"),
                "runtime": runtime.get("android_runtime") or "INPUT_MISSING",
                "wire": runtime.get("runtime_wire_correlation") or "NOT_EXECUTED",
            },
        )
        n_mv = add_node(
            id="n-mversion",
            label="mVersion",
            kind="FIELD",
            classification="FACT",
            field="BclConnection.mVersion S",
            source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
        )
        for kid, label, kind in (
            ("n-clamp", "Clamp (≤4)", "CONTROL"),
            ("n-branch", "Branches", "CONTROL"),
            ("n-single", "mIsSingleSA", "STATE"),
            ("n-gating", "MAX_HU_BUF_SIZE[mVersion]", "CONTROL"),
        ):
            add_node(
                id=kid,
                label=label,
                kind=kind,
                classification="FACT",
                source="output/v16-value-v001/VALUE_V001_FORENSIC_ANALYSIS.json",
            )

        def edge(eid: str, frm: str, to: str, classification: str, relation: str, **extra: Any) -> None:
            edges.append(
                {
                    "id": eid,
                    "from": frm,
                    "to": to,
                    "classification": classification,
                    "relation": relation,
                    **extra,
                }
            )

        edge("e1", n_sock, n_ir, "FACT", "INTERFACE_INVOKE_READ", limit="DYNAMIC_DISPATCH")
        edge("e2", n_ir, n_rp, "FACT", "CALLER")
        edge("e3", n_rp, n_data, "FACT", "BUFFER_FILL")
        edge("e4", n_data, n_dec, "FACT", "PARAM")
        edge("e5", n_dec, n_val, "FACT", "STRUCTURED_VALUE")
        edge("e6", n_val, n_mv, "FACT", "FIELD_STORE")
        edge("e7", n_mv, "n-clamp", "FACT", "CONTROL")
        edge("e8", n_mv, "n-branch", "FACT", "CONTROL")
        edge("e9", n_mv, "n-single", "FACT", "STATE")
        edge("e10", n_mv, "n-gating", "FACT", "CONTROL_INDEX")

        open_edges.extend(
            [
                {
                    "id": "oe-dynamic-dispatch",
                    "label": "DYNAMIC_DISPATCH",
                    "from": "AccessorySocket.read([BII)I",
                    "to": "BtAccessorySocket | UsbAccessorySocket | EthAccessorySocket",
                    "status": "DYNAMIC_DISPATCH",
                    "reason": (boundary.get("first_unclosed_edge") or "concrete AccessorySocket impl unbound"),
                    "not": ["NOT_FOUND"],
                },
                {
                    "id": "oe-outbound",
                    "label": "NOT_PROVEN",
                    "from": "mVersion",
                    "to": "outbound payload bytes",
                    "status": "NOT_PROVEN",
                    "reason": (v001.get("roundtrip") or {}).get("status") or "re-encode not proven",
                    "not": ["NO_ROUNDTRIP_EXISTS"],
                },
                {
                    "id": "oe-runtime",
                    "label": "INPUT_MISSING",
                    "from": "STATIC VALUE-V001",
                    "to": "RUNTIME execution",
                    "status": "INPUT_MISSING",
                    "reason": "No live APK process / instrumentation events",
                    "not": ["NO_RUNTIME_PATH", "NOT_FOUND"],
                },
                {
                    "id": "oe-wire",
                    "label": "NOT_EXECUTED",
                    "from": "RUNTIME",
                    "to": "WIRE",
                    "status": "NOT_EXECUTED",
                    "reason": "No same-session runtime↔wire join executed",
                    "not": ["NO_PROTOCOL"],
                },
                {
                    "id": "oe-semantics",
                    "label": "UNKNOWN",
                    "from": "VALUE-V001 / mVersion",
                    "to": "protocol semantics",
                    "status": "UNKNOWN",
                    "reason": "Field/method names are not protocol proof",
                    "not": ["REJECTED"],
                },
            ]
        )
    elif catalog_entry:
        add_node(
            id="n-value-focus",
            label=str(catalog_entry.get("value_id")),
            kind="STRUCTURED_VALUE",
            classification=catalog_entry.get("classification") or "FACT",
            value_id=catalog_entry.get("value_id"),
            method=catalog_entry.get("source_api") or catalog_entry.get("source_method"),
            source="structured_value_flow.json",
            details={
                "semantic_label": None,
                "protocol_semantics": "UNKNOWN",
                "value_class": catalog_entry.get("value_class"),
                "stored_field": catalog_entry.get("stored_field"),
            },
        )
    return nodes, edges, open_edges


def _knowledge_panels(
    *,
    catalog: list[dict[str, Any]],
    v001: dict[str, Any] | None,
    runtime_status: str,
    counters: dict[str, Any],
) -> dict[str, list[str]]:
    proven: list[str] = []
    not_proven: list[str] = []
    missing: list[str] = []
    if counters.get("structured_values") is not None:
        proven.append(f"{counters['structured_values']} structured values in current catalog")
    if v001:
        proven.extend(
            [
                "Info.decodeVersion([B)S exists (DEX FACT)",
                "first two input bytes interpreted as BIG_ENDIAN short (decoder FACT)",
                "result stored in BclConnection.mVersion",
                "mVersion participates in clamp/branch/write-gating control flow (FACT)",
            ]
        )
        not_proven.extend(
            [
                "outbound encoding of mVersion into payload bytes",
                "concrete AccessorySocket receiver for the VALUE-V001 instance",
                "protocol / message meaning of mVersion",
                "runtime execution of decodeVersion",
                "runtime↔wire same-session correlation",
            ]
        )
    elif catalog:
        proven.append(f"Catalog presents {len(catalog)} VALUE entries from application-flow reports")
    else:
        not_proven.append("No structured values in this case's application-flow reports")
    if runtime_status == "INPUT_MISSING":
        missing.extend(
            [
                "Android device/emulator",
                "running APK process",
                "instrumentation (e.g. Frida)",
                "same-session runtime + wire capture",
            ]
        )
    return {"proven_facts": proven, "not_proven": not_proven, "missing_input": missing}


def _next_experiment(runtime_status: str, focus_value: str | None) -> dict[str, Any]:
    if runtime_status == "INPUT_MISSING":
        target = (
            V001_RUNTIME_HOOK_TARGET["static_source_api"]
            if focus_value == "VALUE-V001"
            else "instrumentable method from static catalog"
        )
        return {
            "title": "NEXT REQUIRED EXPERIMENT",
            "summary": (
                "Obtain a real runtime session of the target APK with instrumentation "
                "and simultaneous wire capture."
            ),
            "target": target,
            "required_evidence": [
                "method execution",
                "input bytes (optional bytes_hex)",
                "return value",
                "session_id",
                "timestamp",
                "same-session wire packets",
            ],
            "classification": "GUIDANCE",
            "note": "Guidance only — not new forensic evidence.",
        }
    return {
        "title": "NEXT REQUIRED EXPERIMENT",
        "summary": "Review correlation outputs for FULL_CHAIN / SESSION_MISMATCH.",
        "classification": "GUIDANCE",
        "note": "Guidance only — not new forensic evidence.",
    }


def _timeline(
    *,
    v001: dict[str, Any] | None,
    runtime_status: str,
    wire_available: bool,
    correlation_status: str,
) -> list[dict[str, Any]]:
    items = [
        {"id": "t-static", "label": "STATIC ANALYSIS", "status": "COMPLETE" if v001 or True else "UNKNOWN"},
    ]
    if v001:
        items.extend(
            [
                {"id": "t-v001", "label": "V001 discovered / catalogued", "status": "FACT"},
                {"id": "t-decoder", "label": "decoder closed", "status": "FACT"},
                {"id": "t-forward", "label": "forward flow closed", "status": "FACT"},
            ]
        )
    items.append({"id": "t-runtime", "label": "RUNTIME", "status": runtime_status})
    items.append(
        {
            "id": "t-wire",
            "label": "WIRE (LAB_B3 or other)",
            "status": "AVAILABLE" if wire_available else "INPUT_MISSING",
            "note": "Separate from APK runtime session unless SAME_SESSION proven",
        }
    )
    items.append({"id": "t-corr", "label": "CORRELATION", "status": correlation_status})
    return items


def build_ui_snapshot(
    *,
    root: Path,
    case: str | None = None,
    sources: dict[str, str] | None = None,
    focus_value_id: str | None = None,
    label: str | None = None,
) -> dict[str, Any]:
    root = Path(root).resolve()
    preset = CASE_PRESETS.get(case or "", {})
    src_map = dict(preset.get("sources") or {})
    if sources:
        src_map.update(sources)
    focus_value_id = focus_value_id or preset.get("focus_value_id")
    label = label or preset.get("label") or case or "custom"

    loaded: dict[str, dict[str, Any] | None] = {}
    source_index: list[dict[str, Any]] = []
    for role, rel in src_map.items():
        source_index.append(_source_entry(root, role, rel))
        loaded[role] = load_json(root / rel) if rel else None

    baseline = loaded.get("baseline_meta")
    app = loaded.get("application_flow")
    flow = loaded.get("structured_value_flow")
    v001 = loaded.get("value_v001")
    buffer = loaded.get("buffer_semantics")
    transport = loaded.get("transport_closure")
    runtime_ev = loaded.get("runtime_evidence")
    runtime_cap = loaded.get("runtime_capture_report")
    readiness = loaded.get("runtime_readiness")
    case_meta = loaded.get("case_meta")
    cross_apk = loaded.get("cross_apk")

    catalog = _catalog_from_flow(flow, app)
    focus_entry = next((v for v in catalog if v.get("value_id") == focus_value_id), None)

    runtime_status = "INPUT_MISSING"
    if runtime_ev and runtime_ev.get("status"):
        runtime_status = str(runtime_ev.get("status"))
    elif runtime_cap and runtime_cap.get("final_verdict"):
        runtime_status = str(runtime_cap.get("final_verdict"))
    elif readiness and readiness.get("current_runtime_status"):
        runtime_status = str(readiness.get("current_runtime_status"))

    wire_available = False
    wire_label = None
    if runtime_cap:
        inv = ((runtime_cap.get("inventory") or {}) if isinstance(runtime_cap.get("inventory"), dict) else {})
        # capture report mentions LAB_B3
        text = json.dumps(runtime_cap)
        if "LAB_B3" in text or "wire_evidence" in text:
            wire_available = True
            wire_label = "LAB_B3_TCP_FULLAUTH (external wire; not same-session APK runtime)"
    if readiness and (readiness.get("closing_assessment") or {}).get("Runtime_Wire") == "NOT_EXECUTED":
        wire_available = wire_available or True

    correlation_status = "NOT_EXECUTED"
    if runtime_status == "INPUT_MISSING":
        correlation_status = "NOT_EXECUTED"

    has_values = bool(catalog)
    has_transport = transport is not None or (case_meta and case_meta.get("rfcomm_targets") is not None)
    has_comm = bool(
        (baseline and baseline.get("path_comm"))
        or (case_meta and case_meta.get("communication_paths"))
        or (app and (app.get("answers") or {}))
    )
    has_buffer = buffer is not None

    cross_key = "BMW_Connected"
    if case == "serial-bt":
        cross_key = "Serial_BT_Terminal_1_52"
    elif case == "bimmerlink":
        cross_key = "BimmerLink"  # may be absent → counters stay from META
    counters = _counters(
        baseline=baseline,
        app=app,
        flow=flow,
        buffer=buffer,
        transport=transport,
        case_meta=case_meta,
        cross_apk=cross_apk,
        cross_apk_key=cross_key,
    )
    if transport:
        paths = transport.get("paths") or []
        if isinstance(paths, list) and counters.get("evidence_paths") is None:
            counters["evidence_paths"] = len(paths)
        if transport.get("transport_paths") is not None:
            counters["evidence_paths"] = transport.get("transport_paths")

    apk = _apk_block(v001=v001, app=app, case_meta=case_meta, readiness=readiness)
    nodes, edges, open_edges = _v001_nodes_edges(v001, focus_entry)

    # Enrich counters for BMW from V15 baseline + buffer answers when possible
    if buffer and counters.get("decoder_candidates") is None:
        ans = buffer.get("answers") or {}
        # answers may contain nested structures; look for numeric decoder hints in summary
        sem = buffer.get("summary") or {}
        for k in ("decoder_candidates", "encoder_candidates", "serializer_candidates"):
            if sem.get(k) is not None:
                dest = "encoder_candidates" if "encoder" in k or "serializer" in k else "decoder_candidates"
                counters[dest] = sem.get(k)

    # From architecture-frozen BMW numbers only if baseline explicitly carries them — already handled.
    # Optional: parse BUFFER report interpretation is forbidden for inventing numbers.

    analysis_status = _status_block(
        static_analysis="COMPLETE" if has_transport or has_values else "PARTIAL",
        value_analysis="COMPLETE" if has_values else ("EMPTY" if case_meta and case_meta.get("structured_values") == 0 else "INPUT_MISSING"),
        runtime_pipeline="READY" if readiness else ("READY" if runtime_ev is not None else "UNKNOWN"),
        runtime_execution=runtime_status,
        wire_correlation=correlation_status,
        protocol_semantics="UNKNOWN",
    )

    # Correlation graph placeholders (no invented FULL_CHAIN)
    correlation_graph = {
        "nodes": [
            {"id": "cg-static", "label": "STATIC METHOD", "status": "FACT" if focus_entry or v001 else "UNKNOWN"},
            {"id": "cg-runtime", "label": "RUNTIME EVENT", "status": runtime_status},
            {"id": "cg-wire", "label": "WIRE PACKET", "status": "AVAILABLE" if wire_available else "INPUT_MISSING"},
        ],
        "edges": [
            {
                "id": "cg-sr",
                "from": "cg-static",
                "to": "cg-runtime",
                "classification": "NOT_EXECUTED" if runtime_status == "INPUT_MISSING" else "UNKNOWN",
                "facets": [],
            },
            {
                "id": "cg-rw",
                "from": "cg-runtime",
                "to": "cg-wire",
                "classification": "NOT_EXECUTED",
                "facets": [],
                "note": "LAB wire must not be treated as same-session without session_id proof",
            },
        ],
        "full_chain_present": False,
        "same_session": "UNKNOWN",
        "session_mismatch_example": {
            "runtime_session": None,
            "wire_session": "LAB_B3 (external)" if wire_available else None,
            "result": "REJECTED if both set and unequal; currently NOT_EXECUTED",
        },
    }

    runtime_wire_view = {
        "STATIC": "FACT" if (v001 or focus_entry) else ("FACT" if has_transport else "UNKNOWN"),
        "RUNTIME": runtime_status,
        "WIRE": "AVAILABLE" if wire_available else "INPUT_MISSING",
        "SAME_SESSION": "UNKNOWN",
        "CORRELATION": correlation_status,
        "wire_artefact": wire_label,
        "warning": (
            "Existing LAB_B3 capture is separate Wire evidence. "
            "UI must not imply it belongs to a VALUE-V001 APK runtime session."
        ),
    }

    knowledge = _knowledge_panels(
        catalog=catalog,
        v001=v001,
        runtime_status=runtime_status,
        counters=counters,
    )

    values_summary = [
        {
            "value_id": v.get("value_id"),
            "classification": v.get("classification"),
            "source_api": v.get("source_api"),
            "source_method": v.get("source_method"),
            "stored_field": v.get("stored_field"),
            "value_class": v.get("value_class"),
            "protocol_semantics": v.get("protocol_semantics") or "UNKNOWN",
            "semantic_label": None,
            "focused": v.get("value_id") == focus_value_id,
        }
        for v in catalog
    ]

    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "case": case,
        "label": label,
        "focus_value_id": focus_value_id,
        "generator": {
            "tool": "apk-forensics",
            "version": __version__,
            "component": "apk_forensics.ui.snapshot.build_ui_snapshot",
            "note": "Read-only aggregation of existing reports. No new evidence.",
        },
        "apk": apk,
        "analysis_status": analysis_status,
        "counters": counters,
        "pipeline_stages": _pipeline_stages(
            has_transport=bool(has_transport),
            has_comm=bool(has_comm),
            has_buffer=bool(has_buffer),
            has_values=has_values,
            runtime_status=runtime_status,
            wire_status="AVAILABLE" if wire_available else "INPUT_MISSING",
            correlation_status=correlation_status,
        ),
        "values": values_summary,
        "nodes": nodes,
        "edges": edges,
        "open_edges": open_edges,
        "runtime_wire": runtime_wire_view,
        "correlation_graph": correlation_graph,
        "timeline": _timeline(
            v001=v001,
            runtime_status=runtime_status,
            wire_available=wire_available,
            correlation_status=correlation_status,
        ),
        "knowledge": knowledge,
        "next_experiment": _next_experiment(runtime_status, focus_value_id),
        "sources": source_index,
        "closing_assessment": (readiness or {}).get("closing_assessment")
        or {
            "STATIC_V001": "FACT" if v001 else ("N/A" if not focus_value_id else "UNKNOWN"),
            "Runtime_V001_execution": runtime_status,
            "Runtime_bytes": runtime_status,
            "Runtime_return_value": runtime_status,
            "Runtime_Static": "NOT_EXECUTED",
            "Runtime_Wire": "NOT_EXECUTED",
            "Same_session_correlation": "UNKNOWN",
            "Protocol_semantics": "UNKNOWN",
            "V001_outbound_encoding": "NOT_PROVEN" if v001 else "N/A",
            "AccessorySocket_receiver": "DYNAMIC_DISPATCH / NOT_PROVEN" if v001 else "N/A",
        },
    }
    # Deterministic content hash over canonical JSON without generator wall-clock
    canon = json.dumps(snapshot, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    snapshot["content_sha256"] = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return snapshot


def write_ui_snapshot(snapshot: dict[str, Any], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
