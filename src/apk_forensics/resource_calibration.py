"""v1.1 Resource calibration utilities — separate from coverage analysis.

Does not alter Guard decisions after a run. Historical comparisons are
informational; they never rewrite a completed estimate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apk_forensics.resource_estimator import (
    ArtifactFingerprint,
    PlanFactors,
    ResourceEstimate,
    estimate_resources,
    plan_factors_from_search_plan,
)
from apk_forensics.resource_policy import get_resource_policy
from apk_forensics.search_plan import SearchPlan


@dataclass(frozen=True)
class EstimateActualPair:
    memory_estimate: int | None
    memory_actual: int | None
    runtime_estimate: int | None
    runtime_actual: float | None

    def ratios(self) -> dict[str, Any]:
        def _ratio(a: float | None, e: float | None) -> float | None:
            if a is None or e is None or e == 0:
                return None
            return round(float(a) / float(e), 4)

        def _err(a: float | None, e: float | None) -> dict[str, Any]:
            if a is None or e is None:
                return {"absolute": None, "relative": None}
            abs_err = float(a) - float(e)
            rel = abs_err / float(e) if e else None
            return {
                "absolute": round(abs_err, 3),
                "relative": round(rel, 4) if rel is not None else None,
            }

        return {
            "memory": {
                "estimate": self.memory_estimate,
                "actual": self.memory_actual,
                "actual_over_estimate": _ratio(self.memory_actual, self.memory_estimate),
                "estimate_over_actual": _ratio(self.memory_estimate, self.memory_actual),
                "error": _err(self.memory_actual, self.memory_estimate),
            },
            "runtime": {
                "estimate": self.runtime_estimate,
                "actual": self.runtime_actual,
                "actual_over_estimate": _ratio(self.runtime_actual, self.runtime_estimate),
                "estimate_over_actual": _ratio(self.runtime_estimate, self.runtime_actual),
                "error": _err(self.runtime_actual, self.runtime_estimate),
            },
        }


def compare_estimate_actual(
    estimate: dict[str, Any] | ResourceEstimate | None,
    actual: dict[str, Any] | None,
) -> dict[str, Any]:
    est = estimate.to_dict() if isinstance(estimate, ResourceEstimate) else (estimate or {})
    act = actual or {}
    pair = EstimateActualPair(
        memory_estimate=est.get("memory_mb"),
        memory_actual=act.get("peak_memory_mb"),
        runtime_estimate=est.get("runtime_seconds"),
        runtime_actual=act.get("runtime_seconds"),
    )
    return {
        "table": [
            {
                "metric": "Memory",
                "estimate": pair.memory_estimate,
                "actual": pair.memory_actual,
                "unit": "MiB",
                "actual_over_estimate": pair.ratios()["memory"]["actual_over_estimate"],
            },
            {
                "metric": "Runtime",
                "estimate": pair.runtime_estimate,
                "actual": pair.runtime_actual,
                "unit": "s",
                "actual_over_estimate": pair.ratios()["runtime"]["actual_over_estimate"],
            },
        ],
        **pair.ratios(),
        "note": (
            "Ratios are observational. They must not rewrite Guard decisions for the same run. "
            "Do not apply a single global scale factor from one APK."
        ),
    }


def extract_run_record(report: dict[str, Any], *, label: str | None = None) -> dict[str, Any]:
    """Pull known fields from a persisted report; missing → UNKNOWN."""
    tool = report.get("tool") or {}
    analysis = report.get("analysis") or {}
    inp = report.get("input") or {}
    art = report.get("artifact") or {}
    res = report.get("resource") or {}
    est = res.get("estimate") or {}
    act = res.get("actual") or {}
    aj = report.get("analysis_job") or {}
    bt = report.get("bluetooth_path") or {}
    eg = bt.get("evidence_graph") or {}
    ce = report.get("communication_evidence") or {}
    dex_inv = report.get("dex_inventory") or []
    native_inv = report.get("native_inventory") or []

    def u(v: Any) -> Any:
        return "UNKNOWN" if v is None or v == "" else v

    return {
        "label": label or art.get("file_name") or inp.get("file_name") or "UNKNOWN",
        "engine_version": u(tool.get("version") or analysis.get("engine_version")),
        "plan_sha256": u(analysis.get("plan_sha256") or aj.get("plan_sha256") or (report.get("search_plan") or {}).get("plan_sha256")),
        "artifact": u(art.get("file_name") or inp.get("file_name")),
        "package_name": u(art.get("package_name")),
        "version_name": u(art.get("version_name")),
        "artifact_sha256": u(inp.get("sha256") or art.get("sha256") or aj.get("input_artifact_sha256")),
        "artifact_size_bytes": u(inp.get("size_bytes")),
        "dex_count": u(len(dex_inv) if dex_inv else (est.get("factors") or {}).get("totals", {}).get("dex_count")),
        "dex_total_bytes": u(sum(int(x.get("size_bytes") or 0) for x in dex_inv) if dex_inv else None),
        "native_count": u(len(native_inv) if native_inv else (est.get("factors") or {}).get("totals", {}).get("native_so_count")),
        "estimate_memory_mb": u(est.get("memory_mb")),
        "estimate_runtime_s": u(est.get("runtime_seconds")),
        "actual_memory_mb": u(act.get("peak_memory_mb")),
        "actual_runtime_s": u(act.get("runtime_seconds")),
        "decision": u(res.get("decision")),
        "termination": u(res.get("termination_reason") or aj.get("termination_reason") or aj.get("status")),
        "result_counts": {
            "findings": u(act.get("findings")),
            "dex_contexts": u(act.get("dex_contexts")),
            "xrefs": u(act.get("xrefs")),
            "evidence_paths": len(eg.get("evidence_paths") or []) if eg else "UNKNOWN",
            "communication_paths": (ce.get("summary") or {}).get("communication_paths", "UNKNOWN" if not ce else 0),
            "raw_nodes": (eg.get("raw") or {}).get("nodes", "UNKNOWN" if not eg else 0),
            "raw_edges": (eg.get("raw") or {}).get("edges", "UNKNOWN" if not eg else 0),
            "canonical_nodes": (eg.get("canonical") or {}).get("nodes", "UNKNOWN" if not eg else 0),
            "canonical_objects": (eg.get("canonical") or {}).get("objects", "UNKNOWN" if not eg else 0),
        },
        "compare": compare_estimate_actual(est, act)
        if est.get("memory_mb") is not None
        else {"note": "estimate missing"},
    }


def load_historical_runs(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in paths:
        if not p.is_file():
            rows.append({"label": str(p), "error": "MISSING", "engine_version": "UNKNOWN"})
            continue
        report = json.loads(p.read_text(encoding="utf-8"))
        rows.append(extract_run_record(report, label=p.parent.name))
    return rows


def sensitivity_matrix(
    fingerprint: ArtifactFingerprint,
    base_plan: SearchPlan,
    *,
    policy_name: str = "standard",
) -> dict[str, Any]:
    """Controlled estimate-only sweeps — no deep analysis."""
    policy = get_resource_policy(policy_name)
    base = plan_factors_from_search_plan(base_plan)
    base_est = estimate_resources([fingerprint], base, policy)

    def _clone(**overrides: Any) -> PlanFactors:
        d = base.to_dict()
        d.update(overrides)
        return PlanFactors(**d)

    sweeps: dict[str, list[dict[str, Any]]] = {}

    hop_rows = []
    for hops in (1, 2, 3):
        f = _clone(bt_max_method_hops=hops, bt_interprocedural=True)
        e = estimate_resources([fingerprint], f, policy)
        hop_rows.append(
            {
                "max_method_hops": hops,
                "memory_mb": e.memory_mb,
                "runtime_seconds": e.runtime_seconds,
                "delta_memory_vs_base": e.memory_mb - base_est.memory_mb,
                "delta_runtime_vs_base": e.runtime_seconds - base_est.runtime_seconds,
            }
        )
    sweeps["max_method_hops"] = hop_rows

    obj_rows = []
    for nodes in (100, 250, 500):
        f = _clone(bt_max_object_nodes=nodes, bt_interprocedural=True)
        e = estimate_resources([fingerprint], f, policy)
        obj_rows.append(
            {
                "max_object_nodes": nodes,
                "memory_mb": e.memory_mb,
                "runtime_seconds": e.runtime_seconds,
                "delta_memory_vs_base": e.memory_mb - base_est.memory_mb,
                "delta_runtime_vs_base": e.runtime_seconds - base_est.runtime_seconds,
            }
        )
    sweeps["max_object_nodes"] = obj_rows

    comm_rows = []
    for enabled in (False, True):
        f = _clone(communication=enabled, communication_max_paths=100 if enabled else 0, communication_max_buffer_hops=5 if enabled else 0)
        e = estimate_resources([fingerprint], f, policy)
        comm_rows.append(
            {
                "communication_enabled": enabled,
                "memory_mb": e.memory_mb,
                "runtime_seconds": e.runtime_seconds,
            }
        )
    sweeps["communication"] = comm_rows

    eg_rows = []
    for enabled in (False, True):
        f = _clone(evidence_graph=enabled, evidence_graph_max_paths=50 if enabled else 0)
        e = estimate_resources([fingerprint], f, policy)
        eg_rows.append(
            {
                "evidence_graph_enabled": enabled,
                "memory_mb": e.memory_mb,
                "runtime_seconds": e.runtime_seconds,
            }
        )
    sweeps["evidence_graph"] = eg_rows

    return {
        "base": {
            "memory_mb": base_est.memory_mb,
            "runtime_seconds": base_est.runtime_seconds,
            "breakdown": base_est.breakdown,
        },
        "sweeps": sweeps,
        "interpretation": [
            "Sensitivity uses the estimator only — not measured peak RSS.",
            "Dex/input size dominate absolute cost; hop/object caps contribute linearly × DEX count.",
            "Communication and evidence_graph add small fixed bases relative to bluetooth+dex_context.",
        ],
    }


def calibration_observations(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Explainable, non-ML summary of historical estimate/actual ratios."""
    mem_ratios: list[float] = []
    rt_ratios: list[float] = []
    for r in rows:
        cmp_ = r.get("compare") or {}
        mr = (cmp_.get("memory") or {}).get("actual_over_estimate")
        tr = (cmp_.get("runtime") or {}).get("actual_over_estimate")
        if isinstance(mr, (int, float)):
            mem_ratios.append(float(mr))
        if isinstance(tr, (int, float)):
            rt_ratios.append(float(tr))

    def _median(xs: list[float]) -> float | None:
        if not xs:
            return None
        s = sorted(xs)
        mid = len(s) // 2
        return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2

    mem_med = _median(mem_ratios)
    rt_med = _median(rt_ratios)
    return {
        "n_runs_with_memory": len(mem_ratios),
        "n_runs_with_runtime": len(rt_ratios),
        "memory_actual_over_estimate": {
            "values": mem_ratios,
            "median": mem_med,
            "min": min(mem_ratios) if mem_ratios else None,
            "max": max(mem_ratios) if mem_ratios else None,
        },
        "runtime_actual_over_estimate": {
            "values": rt_ratios,
            "median": rt_med,
            "min": min(rt_ratios) if rt_ratios else None,
            "max": max(rt_ratios) if rt_ratios else None,
        },
        "recommended_action": [
            "Keep Guard thresholds tied to conservative preflight estimates.",
            "Do not multiply totals by a single BMW-v1.0 ratio.",
            "Prefer documenting component over-prediction (dex_context + bluetooth dominate).",
            "Optional future work: component-wise coefficients with multi-APK holdout — not applied here.",
        ],
        "applied_to_guard": False,
        "note": "Informational calibration only. Estimate → Guard → Run → Actual order preserved.",
    }


def build_resource_estimate_report(
    *,
    historical: list[dict[str, Any]],
    focus_estimate: ResourceEstimate | None = None,
    focus_actual: dict[str, Any] | None = None,
    sensitivity: dict[str, Any] | None = None,
    focus_label: str | None = None,
) -> dict[str, Any]:
    observations = calibration_observations(historical)
    focus_compare = (
        compare_estimate_actual(focus_estimate, focus_actual) if focus_estimate is not None else None
    )
    return {
        "schema": "apk_forensics.resource_estimate_report.v1",
        "focus_label": focus_label,
        "guard_semantics": {
            "OK": "Estimated resources within warning thresholds; analysis may start.",
            "WARNING": "Estimate exceeds warning threshold; explicit --allow-resource-warning required.",
            "REJECT": "Estimate exceeds hard limit; no override.",
            "order": ["Estimate", "Guard decision", "Run", "Actual measurement"],
            "forbidden": "Actuals must not rewrite the estimate or Guard decision for the same run.",
        },
        "focus_breakdown": focus_estimate.breakdown if focus_estimate else None,
        "focus_compare": focus_compare,
        "historical_runs": historical,
        "calibration_observations": observations,
        "sensitivity": sensitivity,
        "main_contributors": _top_contributors(focus_estimate.breakdown if focus_estimate else None),
        "interpretation": (
            "Resource WARNING is not evidence failure. "
            "Estimator remains intentionally conservative relative to measured peak RSS / wall time."
        ),
    }


def _top_contributors(breakdown: dict[str, Any] | None, n: int = 5) -> list[dict[str, Any]]:
    if not breakdown:
        return []
    comps = [c for c in (breakdown.get("components") or []) if c.get("name") != "TOTAL"]
    comps = sorted(comps, key=lambda c: (-int(c.get("memory_mb") or 0), c.get("name") or ""))
    return comps[:n]


def render_resource_estimate_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Resource Estimate Report (v1.1)")
    lines.append("")
    lines.append("> Resource estimation is separate from analysis coverage.")
    lines.append("")
    lines.append("## Guard Semantics")
    lines.append("")
    for k, v in (report.get("guard_semantics") or {}).items():
        if k in {"OK", "WARNING", "REJECT"}:
            lines.append(f"- **{k}**: {v}")
    lines.append(f"- Order: `{' → '.join((report.get('guard_semantics') or {}).get('order') or [])}`")
    lines.append("")
    if report.get("focus_breakdown"):
        lines.append("## Focus Breakdown")
        lines.append("")
        if report.get("focus_label"):
            lines.append(f"Label: `{report['focus_label']}`")
            lines.append("")
        lines.append("| Component | Memory (MiB) | Runtime (s) |")
        lines.append("|---|---:|---:|")
        for c in report["focus_breakdown"].get("components") or []:
            lines.append(
                f"| {c.get('name')} | {c.get('memory_mb')} | {c.get('runtime_seconds')} |"
            )
        lines.append("")
        lines.append("### Main contributors")
        lines.append("")
        for c in report.get("main_contributors") or []:
            lines.append(f"- `{c.get('name')}`: {c.get('memory_mb')} MiB / {c.get('runtime_seconds')} s")
        lines.append("")
    if report.get("focus_compare"):
        lines.append("## Estimate vs Actual (focus)")
        lines.append("")
        lines.append("| Metric | Estimate | Actual | Actual/Estimate |")
        lines.append("|---|---:|---:|---:|")
        for row in report["focus_compare"].get("table") or []:
            lines.append(
                f"| {row.get('metric')} | {row.get('estimate')} | {row.get('actual')} | "
                f"{row.get('actual_over_estimate')} |"
            )
        lines.append("")
    lines.append("## Historical Runs")
    lines.append("")
    lines.append("| Run | Est.Mem | Act.Mem | Est.Time | Act.Time | Decision |")
    lines.append("|---|---:|---:|---:|---:|---|")
    for r in report.get("historical_runs") or []:
        lines.append(
            f"| {r.get('label')} | {r.get('estimate_memory_mb')} | {r.get('actual_memory_mb')} | "
            f"{r.get('estimate_runtime_s')} | {r.get('actual_runtime_s')} | {r.get('decision')} |"
        )
    lines.append("")
    obs = report.get("calibration_observations") or {}
    lines.append("## Calibration Observations")
    lines.append("")
    lines.append(
        f"- Memory actual/estimate median: `{((obs.get('memory_actual_over_estimate') or {}).get('median'))}` "
        f"(n={obs.get('n_runs_with_memory')})"
    )
    lines.append(
        f"- Runtime actual/estimate median: `{((obs.get('runtime_actual_over_estimate') or {}).get('median'))}` "
        f"(n={obs.get('n_runs_with_runtime')})"
    )
    lines.append(f"- Applied to Guard: `{obs.get('applied_to_guard')}`")
    lines.append("")
    for a in obs.get("recommended_action") or []:
        lines.append(f"- {a}")
    lines.append("")
    if report.get("sensitivity"):
        lines.append("## Sensitivity (estimate-only)")
        lines.append("")
        sens = report["sensitivity"]
        for name, rows in (sens.get("sweeps") or {}).items():
            lines.append(f"### {name}")
            lines.append("")
            if not rows:
                continue
            keys = list(rows[0].keys())
            lines.append("| " + " | ".join(keys) + " |")
            lines.append("|" + "|".join(["---"] * len(keys)) + "|")
            for row in rows:
                lines.append("| " + " | ".join(str(row.get(k)) for k in keys) + " |")
            lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(report.get("interpretation") or "")
    lines.append("")
    return "\n".join(lines)


def build_coverage_report(
    *,
    transport_coverage: dict[str, Any] | None,
    communication_coverage: dict[str, Any] | None,
    retention: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "apk_forensics.coverage_report.v1",
        "provenance": provenance or {},
        "transport": transport_coverage,
        "communication": communication_coverage,
        "method_retention": retention,
        "interpretation": (
            "Coverage limits do not downgrade FACT evidence. "
            "METHOD_RETENTION_CAP is an analyzer bound, not an APK semantic proof gap."
        ),
    }


def render_coverage_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = ["# Coverage Report (v1.1)", ""]
    lines.append("> Analysis coverage is separate from resource estimation.")
    lines.append("")
    prov = report.get("provenance") or {}
    if prov:
        lines.append("## Provenance")
        lines.append("")
        for k, v in prov.items():
            lines.append(f"- {k}: `{v}`")
        lines.append("")
    for label, key in (("Transport Evidence", "transport"), ("Communication Evidence", "communication")):
        cov = report.get(key) or {}
        lines.append(f"## {label}")
        lines.append("")
        lines.append("| Status | Count |")
        lines.append("|---|---:|")
        for st in ("complete", "truncated", "boundary", "unresolved", "no_continuation"):
            lines.append(f"| {st} | {cov.get(st, 0)} |")
        lines.append("")
        lines.append("Truncation reasons:")
        lines.append("")
        for r, n in (cov.get("truncation_reasons") or {}).items():
            lines.append(f"- `{r}`: {n}")
        if not cov.get("truncation_reasons"):
            lines.append("- _(none)_")
        lines.append("")
        lines.append("Boundary reasons:")
        lines.append("")
        for r, n in (cov.get("boundary_reasons") or {}).items():
            lines.append(f"- `{r}`: {n}")
        if not cov.get("boundary_reasons"):
            lines.append("- _(none)_")
        lines.append("")
        lines.append(f"Primary truncation: `{cov.get('primary_truncation')}`")
        lines.append(f"Primary boundary: `{cov.get('primary_boundary')}`")
        lines.append("")
    ret = report.get("method_retention") or {}
    if ret:
        lines.append("## Method Retention")
        lines.append("")
        for k in (
            "candidate_methods",
            "retained_methods",
            "discarded_methods",
            "discard_reason",
            "cap",
            "capped",
        ):
            if k in ret:
                lines.append(f"- {k}: `{ret.get(k)}`")
        lines.append("")
        lines.append(
            "Interpretation: retention cap is an **analyzer limit** (METHOD_RETENTION_CAP), "
            "not a native/reflection APK boundary."
        )
        lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(report.get("interpretation") or "")
    lines.append("")
    return "\n".join(lines)


def write_report_pair(out_dir: Path, name: str, payload: dict[str, Any], markdown: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jp = out_dir / f"{name}.json"
    mp = out_dir / f"{name}.md"
    jp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    mp.write_text(markdown if markdown.endswith("\n") else markdown + "\n", encoding="utf-8")
    return jp, mp
