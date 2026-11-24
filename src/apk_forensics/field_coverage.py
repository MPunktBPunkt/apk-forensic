"""v1.2 Field/Alias coverage diagnostics — separate from resource calibration.

Documents field-hop semantics and builds path matrices from persisted reports
and synthetic traces. Does not invent protocol semantics.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from apk_forensics.coverage_analysis import annotate_paths, normalize_reason
from apk_forensics.bluetooth_object_flow import trace_object_flow
from apk_forensics.dex_model_adapter import MethodInfo


FIELD_HOP_SEMANTICS = {
    "definition": (
        "field_hops counts distinct nested field edges for one object identity. "
        "Re-store/load of the same field is same-field alias continuation and does not "
        "consume a hop. A new field name extends the chain (+1). Re-entering an earlier "
        "distinct field is CYCLE_GUARD."
    ),
    "iput": "counts when value register holds the tracked object",
    "sput": "counts as static_field=true; still a field edge for that object",
    "iget_sget": "follow edges after a charged store; do not themselves increment",
    "wrapper_calls": "do not increment field_hops (constructor/wrapper uses separate object)",
    "return_parameter": "do not increment field_hops",
    "same_object_field_change": "new field name → +1 hop",
    "alias_transfer_move_object": "proven alias; no field hop",
    "same_type_not_alias": "BluetoothSocket a and BluetoothSocket b never merged by type alone",
    "register_overwrite": "move-result into tracked register ends local identity (UNKNOWN_ALIAS)",
}


def reconstruct_field_chain(transfers: list[dict[str, Any]], object_id: str) -> list[dict[str, Any]]:
    """Compress field_store/load events for one object into a readable chain."""
    chain: list[dict[str, Any]] = []
    for t in transfers:
        if t.get("object_id") != object_id:
            continue
        kind = t.get("kind")
        if kind not in {"field_store", "field_load"}:
            continue
        field = t.get("field") or ""
        short = field.split(";->")[-1] if ";->" in field else field
        step = {
            "kind": kind,
            "field": field,
            "field_short": short,
            "static_field": bool(t.get("static_field")),
            "method": t.get("from_method") or t.get("to_method"),
            "hop_kind": t.get("hop_kind"),
            "field_hops_after": t.get("field_hops_after"),
            "field_chain": t.get("field_chain") or t.get("field_chain_before"),
        }
        if chain and chain[-1]["kind"] == kind and chain[-1]["field"] == field:
            continue
        chain.append(step)
    return chain


def path_matrix_from_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    bt = report.get("bluetooth_path") or {}
    eg = bt.get("evidence_graph") or {}
    paths = list(eg.get("evidence_paths") or [])
    annotated, _ = annotate_paths(paths)
    # Index dataflow transfers by display
    df_by_id = {p.get("display_id") or p.get("id"): p for p in (bt.get("dataflow_paths") or [])}

    rows: list[dict[str, Any]] = []
    for p in annotated:
        bounds = p.get("boundaries") or []
        reasons = [normalize_reason(b.get("reason") if isinstance(b, dict) else b) for b in bounds]
        mfh = [b for b in bounds if isinstance(b, dict) and b.get("reason") == "max_field_hops"]
        # Attach field chains from related dataflow objects mentioned in boundaries
        field_chains: dict[str, list] = {}
        for b in mfh:
            oid = b.get("object") or b.get("object_id")
            # Find any dataflow path containing this object
            for df in df_by_id.values():
                if oid and oid in (df.get("objects") or []):
                    field_chains[str(oid)] = reconstruct_field_chain(df.get("transfers") or [], str(oid))
                    break
        steps = p.get("steps") or []
        rows.append(
            {
                "path_id": p.get("display_id") or p.get("path_id"),
                "kind": p.get("kind"),
                "start": (steps[0].get("label") if steps else None),
                "end": (steps[-1].get("label") if steps else None),
                "direction": p.get("direction") or p.get("kind"),
                "evidence_class": p.get("classification"),
                "coverage_status": p.get("coverage_status") or (p.get("coverage") or {}).get("status"),
                "termination_reason": p.get("termination_reason") or (p.get("coverage") or {}).get("reason"),
                "boundary_reasons": [r for r in reasons if r],
                "max_field_hops_hits": len(mfh),
                "field_chains": field_chains,
                "final_known_object": (steps[-1].get("object_id") if steps else None),
                "next_unresolved_step": (
                    {
                        "reason": mfh[0].get("reason"),
                        "field": mfh[0].get("field") or mfh[0].get("detail"),
                        "object": mfh[0].get("object") or mfh[0].get("object_id"),
                        "method": mfh[0].get("method"),
                    }
                    if mfh
                    else None
                ),
                "depth_reached": len(steps),
            }
        )
    return rows


def classify_root_cause(rows: list[dict[str, Any]], *, semantics_note: str | None = None) -> dict[str, Any]:
    """Map diagnostics onto cases A–G from the v1.2 brief."""
    mfh_rows = [r for r in rows if r.get("max_field_hops_hits")]
    # Heuristic: repeated same short field names in compressed chains → B/C not deep nesting
    repeated_same = 0
    deep_unique = 0
    store_freq: Counter[str] = Counter()
    reentry_pairs = 0
    for r in mfh_rows:
        for _oid, chain in (r.get("field_chains") or {}).items():
            shorts = [c.get("field_short") for c in chain if c.get("kind") == "field_store"]
            for s in shorts:
                if s:
                    store_freq[str(s)] += 1
            # consecutive duplicate stores of same field = re-entry burn signal
            for i in range(1, len(shorts)):
                if shorts[i] and shorts[i] == shorts[i - 1]:
                    reentry_pairs += 1
            if len(shorts) >= 2 and len(set(shorts)) == 1:
                repeated_same += 1
            # "Deep" only if many *unique* fields without heavy reentry
            if len(set(s for s in shorts if s)) >= 4 and reentry_pairs == 0:
                deep_unique += 1

    transport_like = sum(store_freq[k] for k in ("mBtSocket", "mSocket", "mInputStream", "mOutputStream"))
    case = "B_C_same_field_reentry_burns_hops"
    if deep_unique and not repeated_same and reentry_pairs == 0 and transport_like == 0:
        case = "A_deep_field_chain"
    elif reentry_pairs or transport_like >= 3 or repeated_same:
        case = "B_C_same_field_reentry_burns_hops"
    elif not mfh_rows:
        case = "F_apk_evidence_ends"
    recommendation = (
        "Do not raise default max_field_hops. Fix hop semantics: charge only distinct "
        "nested fields; treat same-field re-store as alias continuation; reset field "
        "depth for new object identities (streams/wrappers); detect cycles explicitly."
    )
    if case == "A_deep_field_chain":
        recommendation = (
            "Consider controlled default increase only after hop-sweep proves additional "
            "FACT edges and resource cost remains WARNING-acceptable."
        )
    return {
        "case": case,
        "mfh_path_count": len(mfh_rows),
        "repeated_same_field_objects": repeated_same,
        "deep_unique_field_objects": deep_unique,
        "same_field_reentry_pairs": reentry_pairs,
        "top_mfh_store_fields": store_freq.most_common(8),
        "recommendation": recommendation,
        "semantics": semantics_note or FIELD_HOP_SEMANTICS["definition"],
        "protocol_semantics": "UNKNOWN",
    }


def hop_sweep_synthetic(
    origin: MethodInfo,
    create_index: int,
    methods: list[MethodInfo],
    *,
    socket_register: str,
    hops: tuple[int, ...] = (1, 2, 3, 4),
) -> list[dict[str, Any]]:
    rows = []
    for h in hops:
        flow = trace_object_flow(
            origin,
            create_index,
            methods,
            socket_register=socket_register,
            max_method_hops=3,
            max_field_hops=h,
            max_object_nodes=200,
            window=20,
        )
        reasons = Counter(b.get("reason") for b in flow.get("boundaries") or [])
        rows.append(
            {
                "max_field_hops": h,
                "objects": len(flow.get("objects") or []),
                "transfers": len(flow.get("transfers") or []),
                "boundaries": len(flow.get("boundaries") or []),
                "max_field_hops_boundaries": reasons.get("max_field_hops", 0),
                "cycle_boundaries": reasons.get("cycle", 0) + reasons.get("cycle_detected", 0),
                "has_read": bool(flow.get("input_read_chain")),
                "has_write": bool(flow.get("output_write_chain")),
            }
        )
    return rows


def build_field_coverage_report(
    *,
    baseline_report: dict[str, Any] | None,
    root_cause: dict[str, Any],
    path_matrix: list[dict[str, Any]],
    hop_sweep: list[dict[str, Any]] | None = None,
    alias_summary: dict[str, Any] | None = None,
    resource_delta: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cov = Counter(r.get("coverage_status") for r in path_matrix)
    return {
        "schema": "apk_forensics.field_coverage_report.v1",
        "provenance": provenance or {},
        "field_hop_semantics": FIELD_HOP_SEMANTICS,
        "baseline": {
            "label": "v1.1",
            "transport_paths": len(path_matrix),
            "coverage_counts": dict(cov),
            "communication": (
                ((baseline_report or {}).get("communication_evidence") or {}).get("summary")
                if baseline_report
                else None
            ),
        },
        "root_cause": root_cause,
        "path_matrix": path_matrix,
        "field_hop_diagnostics": hop_sweep or [],
        "alias_analysis": alias_summary
        or {
            "proven": "move-object / same-field continuation / field_load of stored object",
            "unknown": "UNKNOWN_ALIAS after register_overwrite; same type alone",
            "rejected": "merging objects by type or variable name only",
        },
        "resource_delta": resource_delta
        or {
            "note": (
                "Default max_field_hops unchanged unless hop-sweep + resource estimate justify it. "
                "Estimator already scales with bt_max_field_hops × DEX."
            ),
            "default_max_field_hops": 2,
            "default_changed": False,
        },
        "interpretation": root_cause.get("recommendation"),
    }


def render_field_coverage_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# Field Coverage Report (v1.2)", ""]
    lines.append("> Field/alias coverage is separate from resource estimation and protocol claims.")
    lines.append("")
    lines.append("## Field-Hop Semantics")
    lines.append("")
    for k, v in (report.get("field_hop_semantics") or {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    rc = report.get("root_cause") or {}
    lines.append("## Root Cause")
    lines.append("")
    lines.append(f"- Case: `{rc.get('case')}`")
    lines.append(f"- MFH paths: `{rc.get('mfh_path_count')}`")
    lines.append(f"- Recommendation: {rc.get('recommendation')}")
    lines.append(f"- Protocol semantics: `{rc.get('protocol_semantics')}`")
    lines.append("")
    lines.append("## Path Matrix")
    lines.append("")
    lines.append("| Path | Kind | Coverage | Termination | MFH hits | Final object |")
    lines.append("|---|---|---|---|---:|---|")
    for r in report.get("path_matrix") or []:
        lines.append(
            f"| {r.get('path_id')} | {r.get('kind')} | {r.get('coverage_status')} | "
            f"{r.get('termination_reason')} | {r.get('max_field_hops_hits')} | "
            f"{r.get('final_known_object')} |"
        )
    lines.append("")
    if report.get("field_hop_diagnostics"):
        lines.append("## Field-Hop Diagnostics (synthetic / controlled)")
        lines.append("")
        lines.append("| max_field_hops | objects | transfers | MFH bounds | cycle | read | write |")
        lines.append("|---:|---:|---:|---:|---:|---|---|")
        for row in report["field_hop_diagnostics"]:
            lines.append(
                f"| {row.get('max_field_hops')} | {row.get('objects')} | {row.get('transfers')} | "
                f"{row.get('max_field_hops_boundaries')} | {row.get('cycle_boundaries')} | "
                f"{row.get('has_read')} | {row.get('has_write')} |"
            )
        lines.append("")
    lines.append("## Alias Analysis")
    lines.append("")
    for k, v in (report.get("alias_analysis") or {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("## Resource Delta")
    lines.append("")
    for k, v in (report.get("resource_delta") or {}).items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(report.get("interpretation") or "")
    lines.append("")
    return "\n".join(lines)


def write_field_coverage_reports(out_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jp = out_dir / "FIELD_COVERAGE_REPORT.json"
    mp = out_dir / "FIELD_COVERAGE_REPORT.md"
    jp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    mp.write_text(render_field_coverage_markdown(report), encoding="utf-8")
    return jp, mp
