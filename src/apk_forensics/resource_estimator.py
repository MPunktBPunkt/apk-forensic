"""Deterministic preflight resource estimator.

Uses only ZIP/metadata + SearchPlan/config factors. Does not run deep analysis.
Same inputs → same estimate (no wall-clock, no system load).
"""

from __future__ import annotations

import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from apk_forensics.resource_policy import ResourcePolicy
from apk_forensics.search_plan import SearchPlan
from apk_forensics.utils import classify_zip_entry


@dataclass(frozen=True)
class ArtifactFingerprint:
    path: str
    file_name: str
    size_bytes: int
    dex_count: int
    dex_total_bytes: int
    native_so_count: int
    native_total_bytes: int
    entry_count: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PlanFactors:
    dex_context: bool
    bluetooth: bool
    xref_depth: int
    max_callers: int
    max_callees: int
    instruction_window: int
    search_terms: int
    search_regex: int
    search_uuids: int
    modules: tuple[str, ...]
    plan_sha256: str | None
    # v0.7 Bluetooth caller / dataflow factors (defaults keep v0.6 estimates stable)
    bt_caller_depth: int = 0
    bt_dataflow_depth: int = 0
    bt_max_dataflow_nodes: int = 0
    bt_reconstruct_callers: bool = False
    bt_reconstruct_streams: bool = False
    bt_interprocedural: bool = False
    bt_max_method_hops: int = 0
    bt_max_field_hops: int = 0
    bt_max_object_nodes: int = 0
    evidence_graph: bool = False
    evidence_graph_max_paths: int = 0
    communication: bool = False
    communication_max_paths: int = 0
    communication_max_buffer_hops: int = 0
    correlation: bool = False
    correlation_max_runtime_events: int = 0
    correlation_max_wire_packets: int = 0
    correlation_max_correlations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResourceEstimate:
    memory_mb: int
    runtime_seconds: int
    findings: int
    dex_contexts: int
    xrefs: int
    risk: str  # ok | warning | reject  (estimator-local risk label before guard)
    reasons: list[str] = field(default_factory=list)
    factors: dict[str, Any] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    breakdown: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "memory_mb": self.memory_mb,
            "runtime_seconds": self.runtime_seconds,
            "findings": self.findings,
            "dex_contexts": self.dex_contexts,
            "xrefs": self.xrefs,
            "risk": self.risk,
            "reasons": list(self.reasons),
            "factors": dict(self.factors),
            "artifacts": list(self.artifacts),
        }
        if self.breakdown:
            payload["breakdown"] = dict(self.breakdown)
        return payload


def fingerprint_apk(path: Path) -> ArtifactFingerprint:
    """Lightweight ZIP listing — no entry hashing, no DEX parse."""
    from apk_forensics.errors import InvalidApkError

    path = path.resolve()
    if not path.is_file():
        raise InvalidApkError(f"File is not a valid APK/ZIP: {path}")
    size_bytes = path.stat().st_size
    dex_count = 0
    dex_total = 0
    native_count = 0
    native_total = 0
    entry_count = 0
    if not zipfile.is_zipfile(path):
        raise InvalidApkError(f"File is not a valid APK/ZIP: {path}")
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                entry_count += 1
                kind = classify_zip_entry(info.filename)
                if kind == "dex":
                    dex_count += 1
                    dex_total += int(info.file_size)
                elif kind == "native":
                    native_count += 1
                    native_total += int(info.file_size)
    except zipfile.BadZipFile as exc:
        raise InvalidApkError(f"File is not a valid APK/ZIP: {path}") from exc
    return ArtifactFingerprint(
        path=str(path),
        file_name=path.name,
        size_bytes=size_bytes,
        dex_count=dex_count,
        dex_total_bytes=dex_total,
        native_so_count=native_count,
        native_total_bytes=native_total,
        entry_count=entry_count,
    )


def plan_factors_from_search_plan(plan: SearchPlan | None, *, cli_dex: bool = False, cli_bt: bool = False) -> PlanFactors:
    if plan is None:
        return PlanFactors(
            dex_context=bool(cli_dex),
            bluetooth=bool(cli_bt),
            xref_depth=0,
            max_callers=20,
            max_callees=20,
            instruction_window=8,
            search_terms=0,
            search_regex=0,
            search_uuids=0,
            modules=tuple(),
            plan_sha256=None,
        )
    return PlanFactors(
        dex_context=bool(plan.dex_context_enabled),
        bluetooth=bool(plan.bluetooth_enabled),
        xref_depth=int(plan.xref_depth),
        max_callers=int(plan.max_callers),
        max_callees=int(plan.max_callees),
        instruction_window=int(plan.instruction_window),
        search_terms=len(plan.search_terms),
        search_regex=len(plan.search_regex),
        search_uuids=len(plan.search_uuids),
        modules=tuple(plan.modules),
        plan_sha256=plan.plan_sha256,
        bt_caller_depth=int(plan.bluetooth_caller_depth) if plan.bluetooth_enabled else 0,
        bt_dataflow_depth=int(plan.bluetooth_dataflow_depth) if plan.bluetooth_enabled else 0,
        bt_max_dataflow_nodes=int(plan.bluetooth_max_dataflow_nodes) if plan.bluetooth_enabled else 0,
        bt_reconstruct_callers=bool(plan.bluetooth_reconstruct_callers) if plan.bluetooth_enabled else False,
        bt_reconstruct_streams=bool(plan.bluetooth_reconstruct_streams) if plan.bluetooth_enabled else False,
        bt_interprocedural=bool(plan.bluetooth_interprocedural) if plan.bluetooth_enabled else False,
        bt_max_method_hops=int(plan.bluetooth_max_method_hops) if plan.bluetooth_enabled else 0,
        bt_max_field_hops=int(plan.bluetooth_max_field_hops) if plan.bluetooth_enabled else 0,
        bt_max_object_nodes=int(plan.bluetooth_max_object_nodes) if plan.bluetooth_enabled else 0,
        evidence_graph=bool(plan.evidence_graph_enabled),
        evidence_graph_max_paths=int(plan.evidence_graph_max_paths) if plan.evidence_graph_enabled else 0,
        communication=bool(plan.communication_enabled),
        communication_max_paths=int(plan.communication_max_dataflow_paths) if plan.communication_enabled else 0,
        communication_max_buffer_hops=int(plan.communication_max_buffer_hops) if plan.communication_enabled else 0,
        correlation=bool(plan.correlation_enabled),
        correlation_max_runtime_events=int(plan.correlation_max_runtime_events)
        if plan.correlation_enabled
        else 0,
        correlation_max_wire_packets=int(plan.correlation_max_wire_packets)
        if plan.correlation_enabled
        else 0,
        correlation_max_correlations=int(plan.correlation_max_correlations)
        if plan.correlation_enabled
        else 0,
    )


def estimate_resources(
    artifacts: list[ArtifactFingerprint],
    factors: PlanFactors,
    policy: ResourcePolicy,
) -> ResourceEstimate:
    """Deterministic conservative estimate with component breakdown.

    Totals are unchanged vs prior coefficient tables; breakdown accounts for
    the same contributions so Guard decisions remain stable.
    Coefficients are heuristic/conservative (not post-hoc scaled from one run).
    """
    # --- documented coefficients (integer math where possible) ---
    BASE_MEMORY_MB = 96
    PER_INPUT_MB_FRACTION = 20  # size_mb * 20 / 100
    PER_DEX_MB = 100
    PER_DEX_MB_CONTEXT = 120
    PER_DEX_MB_XREF = 50  # * xref_depth
    PER_BT_BASE_MB = 120
    PER_BT_DEX_MB = 40
    PER_BT_CALLER_DEPTH_MB = 10  # * caller_depth * dex_count
    PER_BT_DATAFLOW_DEPTH_MB = 12  # * dataflow_depth * dex_count
    PER_BT_DATAFLOW_NODES_MB = 2  # * (nodes // 100) * dex_count
    PER_BT_INTERPROC_BASE_MB = 8
    PER_BT_METHOD_HOP_MB = 1  # * method_hops * dex
    PER_BT_FIELD_HOP_MB = 1  # * field_hops * dex
    PER_BT_OBJECT_NODES_MB = 1  # * (object_nodes // 100) * dex
    PER_EVIDENCE_GRAPH_BASE_MB = 4
    PER_EVIDENCE_PATH_MB = 0
    PER_NATIVE_MB = 3
    PER_TERM_MB = 1
    PER_DEX_MB_BYTES = 2  # dex_total_mb * 2 when context

    BASE_RUNTIME_S = 15
    PER_INPUT_RUNTIME = 1  # per 4 MiB
    PER_DEX_RUNTIME = 8
    PER_DEX_CONTEXT_RUNTIME = 35
    PER_XREF_RUNTIME = 25  # * depth * dex
    PER_BT_RUNTIME = 30  # * dex
    PER_BT_CALLER_DEPTH_RT = 5
    PER_BT_DATAFLOW_DEPTH_RT = 6
    PER_BT_DATAFLOW_NODES_RT = 2
    PER_BT_INTERPROC_BASE_RT = 8
    PER_BT_METHOD_HOP_RT = 3
    PER_BT_FIELD_HOP_RT = 2
    PER_BT_OBJECT_NODES_RT = 1
    PER_EVIDENCE_GRAPH_BASE_RT = 5
    PER_EVIDENCE_PATH_RT = 0
    PER_COMM_BASE_MB = 6
    PER_COMM_BUFFER_HOP_MB = 1
    PER_COMM_BASE_RT = 8
    PER_COMM_BUFFER_HOP_RT = 1
    PER_CORR_BASE_MB = 4
    PER_CORR_EVENT_K_MB = 1  # per 1000 runtime+wire events
    PER_CORR_BASE_RT = 3
    PER_CORR_EVENT_K_RT = 1
    PER_NATIVE_RUNTIME = 1
    PER_TERM_RUNTIME = 1  # per 10 terms

    BASE_FINDINGS = 150
    PER_DEX_FINDINGS = 250
    PER_TERM_FINDINGS = 40
    PER_BT_FINDINGS = 400
    PER_NATIVE_FINDINGS = 20

    reasons: list[str] = []
    total_size = sum(a.size_bytes for a in artifacts)
    total_size_mb = max(1, (total_size + 1024 * 1024 - 1) // (1024 * 1024))
    dex_count = sum(a.dex_count for a in artifacts)
    native_count = sum(a.native_so_count for a in artifacts)
    dex_total_mb = max(0, (sum(a.dex_total_bytes for a in artifacts) + 1024 * 1024 - 1) // (1024 * 1024))

    components: list[dict[str, Any]] = []

    def add_comp(name: str, mem: int, rt: int, *, source: str, heuristic: bool = True) -> None:
        components.append(
            {
                "name": name,
                "memory_mb": int(mem),
                "runtime_seconds": int(rt),
                "source": source,
                "kind": "heuristic" if heuristic else "empirical",
                "affects": "both" if mem and rt else ("memory" if mem else "runtime"),
            }
        )

    # Baseline + input/DEX/native/terms (shallow scan)
    base_mem = BASE_MEMORY_MB
    base_mem += (total_size_mb * PER_INPUT_MB_FRACTION) // 100
    base_mem += dex_count * PER_DEX_MB
    base_mem += native_count * PER_NATIVE_MB
    base_mem += factors.search_terms * PER_TERM_MB
    base_mem += factors.search_regex * PER_TERM_MB
    base_rt = BASE_RUNTIME_S
    base_rt += total_size_mb // 4 * PER_INPUT_RUNTIME
    base_rt += dex_count * PER_DEX_RUNTIME
    base_rt += native_count * PER_NATIVE_RUNTIME
    base_rt += (factors.search_terms // 10) * PER_TERM_RUNTIME
    add_comp("baseline_input_dex_native", base_mem, base_rt, source="artifact_fingerprint+BASE_*")

    dex_mem = 0
    dex_rt = 0
    if factors.dex_context:
        dex_mem += dex_count * PER_DEX_MB_CONTEXT
        dex_mem += dex_total_mb * PER_DEX_MB_BYTES
        dex_mem += dex_count * factors.xref_depth * PER_DEX_MB_XREF
        dex_rt += dex_count * PER_DEX_CONTEXT_RUNTIME
        dex_rt += dex_count * max(factors.xref_depth, 0) * PER_XREF_RUNTIME
        dex_rt += (factors.max_callers + factors.max_callees) // 20 * dex_count
        reasons.append("dex_context enabled")
        if factors.xref_depth:
            reasons.append(f"xref_depth={factors.xref_depth}")
        if dex_count:
            reasons.append(f"{dex_count} DEX file(s)")
        if dex_total_mb:
            reasons.append(f"DEX payload ~{dex_total_mb} MiB")
    add_comp("dex_context_xref", dex_mem, dex_rt, source="plan.dex_context/xref_depth")

    bt_path_mem = 0
    bt_path_rt = 0
    caller_mem = 0
    caller_rt = 0
    obj_mem = 0
    obj_rt = 0
    if factors.bluetooth:
        bt_path_mem += PER_BT_BASE_MB
        bt_path_mem += max(dex_count, 0) * PER_BT_DEX_MB
        reasons.append("bluetooth enabled")
        if dex_count > 0:
            bt_path_rt += dex_count * PER_BT_RUNTIME
        else:
            bt_path_rt += 10
        if factors.bt_reconstruct_callers and factors.bt_caller_depth:
            caller_mem += max(dex_count, 0) * factors.bt_caller_depth * PER_BT_CALLER_DEPTH_MB
            if dex_count > 0:
                caller_rt += dex_count * factors.bt_caller_depth * PER_BT_CALLER_DEPTH_RT
            reasons.append(f"bt_caller_depth={factors.bt_caller_depth}")
        if factors.bt_reconstruct_streams and factors.bt_dataflow_depth:
            bt_path_mem += max(dex_count, 0) * factors.bt_dataflow_depth * PER_BT_DATAFLOW_DEPTH_MB
            if dex_count > 0:
                bt_path_rt += dex_count * factors.bt_dataflow_depth * PER_BT_DATAFLOW_DEPTH_RT
            reasons.append(f"bt_dataflow_depth={factors.bt_dataflow_depth}")
        if factors.bt_max_dataflow_nodes:
            bt_path_mem += max(dex_count, 0) * (factors.bt_max_dataflow_nodes // 100) * PER_BT_DATAFLOW_NODES_MB
            if dex_count > 0:
                bt_path_rt += dex_count * (factors.bt_max_dataflow_nodes // 100) * PER_BT_DATAFLOW_NODES_RT
        if factors.bt_interprocedural:
            obj_mem += PER_BT_INTERPROC_BASE_MB
            obj_mem += max(dex_count, 0) * factors.bt_max_method_hops * PER_BT_METHOD_HOP_MB
            obj_mem += max(dex_count, 0) * factors.bt_max_field_hops * PER_BT_FIELD_HOP_MB
            obj_mem += max(dex_count, 0) * (factors.bt_max_object_nodes // 100) * PER_BT_OBJECT_NODES_MB
            if dex_count > 0:
                obj_rt += PER_BT_INTERPROC_BASE_RT
                obj_rt += dex_count * factors.bt_max_method_hops * PER_BT_METHOD_HOP_RT
                obj_rt += dex_count * factors.bt_max_field_hops * PER_BT_FIELD_HOP_RT
                obj_rt += dex_count * (factors.bt_max_object_nodes // 100) * PER_BT_OBJECT_NODES_RT
            reasons.append("bluetooth interprocedural object-flow")
            if factors.bt_max_method_hops:
                reasons.append(f"bt_max_method_hops={factors.bt_max_method_hops}")
            if factors.bt_max_field_hops:
                reasons.append(f"bt_max_field_hops={factors.bt_max_field_hops}")
    add_comp("bluetooth_path_analysis", bt_path_mem, bt_path_rt, source="plan.bluetooth")
    add_comp("caller_reconstruction", caller_mem, caller_rt, source="plan.bluetooth.caller_depth")
    add_comp("object_flow", obj_mem, obj_rt, source="plan.bluetooth.interprocedural")

    eg_mem = 0
    eg_rt = 0
    if factors.evidence_graph:
        eg_mem += PER_EVIDENCE_GRAPH_BASE_MB
        eg_mem += (max(factors.evidence_graph_max_paths, 0) // 10) * PER_EVIDENCE_PATH_MB
        eg_rt += PER_EVIDENCE_GRAPH_BASE_RT
        eg_rt += (max(factors.evidence_graph_max_paths, 0) // 10) * PER_EVIDENCE_PATH_RT
        reasons.append("evidence_graph canonicalize/paths")
        if factors.evidence_graph_max_paths:
            reasons.append(f"evidence_graph_max_paths={factors.evidence_graph_max_paths}")
    add_comp("evidence_graph", eg_mem, eg_rt, source="plan.evidence_graph")

    comm_mem = 0
    comm_rt = 0
    if factors.communication:
        # communication_max_paths is tracked for reporting; cost model uses buffer hops + base
        # (paths are post-process caps, not primary memory drivers in current model).
        _ = factors.communication_max_paths
        comm_mem += PER_COMM_BASE_MB
        comm_mem += max(factors.communication_max_buffer_hops, 0) * PER_COMM_BUFFER_HOP_MB
        comm_rt += PER_COMM_BASE_RT
        comm_rt += max(factors.communication_max_buffer_hops, 0) * PER_COMM_BUFFER_HOP_RT
        reasons.append("communication bytes/parser/message analysis")
        if factors.communication_max_paths:
            reasons.append(f"communication_max_paths={factors.communication_max_paths}")
    add_comp("communication_dataflow", comm_mem, comm_rt, source="plan.communication")

    corr_mem = 0
    corr_rt = 0
    if factors.correlation:
        events = max(factors.correlation_max_runtime_events, 0) + max(
            factors.correlation_max_wire_packets, 0
        )
        corr_mem += PER_CORR_BASE_MB
        corr_mem += (events // 1000) * PER_CORR_EVENT_K_MB
        corr_rt += PER_CORR_BASE_RT
        corr_rt += (events // 1000) * PER_CORR_EVENT_K_RT
        reasons.append("correlation static/runtime/wire (indexed, capped)")
        if factors.correlation_max_correlations:
            reasons.append(f"correlation_max_correlations={factors.correlation_max_correlations}")
    add_comp("static_runtime_correlation", corr_mem, corr_rt, source="plan.correlation")

    if total_size_mb >= 100:
        reasons.append(f"large input artifact(s) ~{total_size_mb} MiB")
    if native_count:
        reasons.append(f"{native_count} native .so")
    if len(artifacts) > 1:
        reasons.append(f"{len(artifacts)} artifacts in set")
    if factors.search_terms:
        reasons.append(f"{factors.search_terms} search terms")

    memory = sum(int(c["memory_mb"]) for c in components)
    runtime = sum(int(c["runtime_seconds"]) for c in components)
    components.append(
        {
            "name": "TOTAL",
            "memory_mb": int(memory),
            "runtime_seconds": int(runtime),
            "source": "sum(components)",
            "kind": "derived",
            "affects": "both",
        }
    )

    findings = BASE_FINDINGS
    findings += dex_count * PER_DEX_FINDINGS
    findings += factors.search_terms * PER_TERM_FINDINGS
    findings += native_count * PER_NATIVE_FINDINGS
    if factors.bluetooth:
        findings += PER_BT_FINDINGS
    if factors.dex_context:
        findings += dex_count * 50

    dex_contexts = 0
    xrefs = 0
    if factors.dex_context:
        dex_contexts = min(10_000, max(50, dex_count * 40 + factors.search_terms * 5))
        xrefs = min(50_000, dex_count * max(factors.xref_depth, 1) * 200 + factors.max_callers * dex_count)

    risk = "ok"
    if policy.warn_estimated_memory_mb is not None and memory >= policy.warn_estimated_memory_mb:
        risk = "warning"
    if policy.warn_estimated_runtime_seconds is not None and runtime >= policy.warn_estimated_runtime_seconds:
        risk = "warning"
    if policy.reject_estimated_memory_mb is not None and memory >= policy.reject_estimated_memory_mb:
        risk = "reject"
    if policy.reject_estimated_runtime_seconds is not None and runtime >= policy.reject_estimated_runtime_seconds:
        risk = "reject"
    if policy.max_input_size_mb is not None and total_size_mb > policy.max_input_size_mb:
        risk = "reject"
        reasons.append(f"input size {total_size_mb} MiB exceeds policy max_input_size_mb={policy.max_input_size_mb}")
    if policy.max_artifacts is not None and len(artifacts) > policy.max_artifacts:
        risk = "reject"
        reasons.append(f"artifact count {len(artifacts)} exceeds max_artifacts={policy.max_artifacts}")

    if not reasons:
        reasons.append("baseline shallow scan")

    breakdown = {
        "components": components,
        "notes": [
            "Breakdown sums to the Guard-facing totals; no post-hoc actual scaling.",
            "Coefficients are conservative heuristics keyed by input size + plan complexity.",
            "INPUT SIZE (APK/DEX/native) is distinct from ANALYSIS COMPLEXITY (hops/nodes/modules).",
        ],
        "component_catalog": [
            {
                "name": "baseline_input_dex_native",
                "memory_formula": "BASE + size_frac + dex*PER_DEX + native*PER_NATIVE + terms",
                "runtime_formula": "BASE + size/4 + dex*PER_DEX_RT + native + terms/10",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
            {
                "name": "dex_context_xref",
                "memory_formula": "dex*(CONTEXT + xref_depth*XREF) + dex_total_mb*BYTES",
                "runtime_formula": "dex*(CONTEXT_RT + xref_depth*XREF_RT) + callers/callees term",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
            {
                "name": "bluetooth_path_analysis",
                "memory_formula": "BT_BASE + dex*BT_DEX + dataflow_depth/nodes terms",
                "runtime_formula": "dex*BT_RT + dataflow depth/nodes terms",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
            {
                "name": "caller_reconstruction",
                "memory_formula": "dex * caller_depth * PER_BT_CALLER_DEPTH_MB",
                "runtime_formula": "dex * caller_depth * PER_BT_CALLER_DEPTH_RT",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
            {
                "name": "object_flow",
                "memory_formula": "INTERPROC_BASE + dex*(method_hops + field_hops + object_nodes/100)",
                "runtime_formula": "INTERPROC_BASE_RT + dex*(method_hops*3 + field_hops*2 + object_nodes/100)",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
            {
                "name": "evidence_graph",
                "memory_formula": "PER_EVIDENCE_GRAPH_BASE_MB (+ path term currently 0)",
                "runtime_formula": "PER_EVIDENCE_GRAPH_BASE_RT",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
            {
                "name": "communication_dataflow",
                "memory_formula": "PER_COMM_BASE_MB + buffer_hops*PER_COMM_BUFFER_HOP_MB",
                "runtime_formula": "PER_COMM_BASE_RT + buffer_hops*PER_COMM_BUFFER_HOP_RT",
                "empirical_or_heuristic": "heuristic",
                "statically_measurable": True,
                "empirically_calibratable": True,
            },
        ],
    }

    factors_doc = {
        "coefficients": {
            "BASE_MEMORY_MB": BASE_MEMORY_MB,
            "PER_DEX_MB": PER_DEX_MB,
            "PER_DEX_MB_CONTEXT": PER_DEX_MB_CONTEXT,
            "PER_DEX_MB_XREF": PER_DEX_MB_XREF,
            "PER_BT_BASE_MB": PER_BT_BASE_MB,
            "PER_BT_CALLER_DEPTH_MB": PER_BT_CALLER_DEPTH_MB,
            "PER_BT_DATAFLOW_DEPTH_MB": PER_BT_DATAFLOW_DEPTH_MB,
            "PER_BT_CALLER_DEPTH_RT": PER_BT_CALLER_DEPTH_RT,
            "PER_BT_DATAFLOW_DEPTH_RT": PER_BT_DATAFLOW_DEPTH_RT,
            "PER_BT_INTERPROC_BASE_MB": PER_BT_INTERPROC_BASE_MB,
            "PER_BT_METHOD_HOP_MB": PER_BT_METHOD_HOP_MB,
            "PER_BT_FIELD_HOP_MB": PER_BT_FIELD_HOP_MB,
            "BASE_RUNTIME_S": BASE_RUNTIME_S,
            "PER_DEX_CONTEXT_RUNTIME": PER_DEX_CONTEXT_RUNTIME,
            "PER_COMM_BASE_MB": PER_COMM_BASE_MB,
            "PER_COMM_BUFFER_HOP_MB": PER_COMM_BUFFER_HOP_MB,
        },
        "totals": {
            "size_mb": total_size_mb,
            "dex_count": dex_count,
            "dex_total_mb": dex_total_mb,
            "native_so_count": native_count,
            "artifact_count": len(artifacts),
        },
        "plan": factors.to_dict(),
        "policy": policy.name,
        "calibration": {
            "applied_to_totals": False,
            "note": "No global actual/estimate scale factor is applied to Guard inputs.",
        },
    }

    return ResourceEstimate(
        memory_mb=int(memory),
        runtime_seconds=int(runtime),
        findings=int(findings),
        dex_contexts=int(dex_contexts),
        xrefs=int(xrefs),
        risk=risk,
        reasons=reasons,
        factors=factors_doc,
        artifacts=[a.to_dict() for a in artifacts],
        breakdown=breakdown,
    )
