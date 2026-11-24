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

    def to_dict(self) -> dict[str, Any]:
        return {
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
    )


def estimate_resources(
    artifacts: list[ArtifactFingerprint],
    factors: PlanFactors,
    policy: ResourcePolicy,
) -> ResourceEstimate:
    """Deterministic conservative estimate. Documented coefficients below."""
    # --- documented coefficients (integer math where possible) ---
    # Tuned so a ~150 MiB / 4-DEX bluetooth+dex_context+xref=2 plan is WARNING
    # under standard policy, while larger synthetic cases can hit REJECT.
    BASE_MEMORY_MB = 96
    PER_INPUT_MB_FRACTION = 20  # size_mb * 20 / 100
    PER_DEX_MB = 100
    PER_DEX_MB_CONTEXT = 120
    PER_DEX_MB_XREF = 50  # * xref_depth
    PER_BT_BASE_MB = 120
    PER_BT_DEX_MB = 40
    # v0.7: bounded caller/dataflow inflate estimate without unbounded linear blow-up
    PER_BT_CALLER_DEPTH_MB = 10  # * caller_depth * dex_count
    PER_BT_DATAFLOW_DEPTH_MB = 12  # * dataflow_depth * dex_count
    PER_BT_DATAFLOW_NODES_MB = 2  # * (nodes // 100) * dex_count
    # Tuned so MyBMW-sized bluetooth+interprocedural plans stay WARNING, not REJECT.
    PER_BT_INTERPROC_BASE_MB = 8
    PER_BT_METHOD_HOP_MB = 1  # * method_hops * dex
    PER_BT_FIELD_HOP_MB = 1  # * field_hops * dex
    PER_BT_OBJECT_NODES_MB = 1  # * (object_nodes // 100) * dex
    # Keep MyBMW-sized bluetooth+interproc+evidence_graph under hard 2048 MiB (WARNING ok).
    PER_EVIDENCE_GRAPH_BASE_MB = 4
    PER_EVIDENCE_PATH_MB = 0  # paths are post-processing; negligible vs object-flow
    PER_NATIVE_MB = 3
    PER_TERM_MB = 1
    PER_DEX_MB_BYTES = 2  # dex_total_mb * 2 when context

    BASE_RUNTIME_S = 15
    PER_INPUT_RUNTIME = 1  # per 4 MiB
    PER_DEX_RUNTIME = 8
    PER_DEX_CONTEXT_RUNTIME = 35
    PER_XREF_RUNTIME = 25  # * depth * dex
    PER_BT_RUNTIME = 30  # * dex (min 1 if bt and dex>0 else 0)
    PER_BT_CALLER_DEPTH_RT = 5  # * caller_depth * dex
    PER_BT_DATAFLOW_DEPTH_RT = 6  # * dataflow_depth * dex
    PER_BT_DATAFLOW_NODES_RT = 2  # * (nodes // 100) * dex
    PER_BT_INTERPROC_BASE_RT = 8
    PER_BT_METHOD_HOP_RT = 3  # * method_hops * dex
    PER_BT_FIELD_HOP_RT = 2  # * field_hops * dex
    PER_BT_OBJECT_NODES_RT = 1  # * (object_nodes // 100) * dex
    PER_EVIDENCE_GRAPH_BASE_RT = 5
    PER_EVIDENCE_PATH_RT = 0
    PER_COMM_BASE_MB = 6
    PER_COMM_BUFFER_HOP_MB = 1
    PER_COMM_BASE_RT = 8
    PER_COMM_BUFFER_HOP_RT = 1
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

    memory = BASE_MEMORY_MB
    memory += (total_size_mb * PER_INPUT_MB_FRACTION) // 100
    memory += dex_count * PER_DEX_MB
    memory += native_count * PER_NATIVE_MB
    memory += factors.search_terms * PER_TERM_MB
    memory += factors.search_regex * PER_TERM_MB

    if factors.dex_context:
        memory += dex_count * PER_DEX_MB_CONTEXT
        memory += dex_total_mb * PER_DEX_MB_BYTES
        memory += dex_count * factors.xref_depth * PER_DEX_MB_XREF
        reasons.append("dex_context enabled")
        if factors.xref_depth:
            reasons.append(f"xref_depth={factors.xref_depth}")
        if dex_count:
            reasons.append(f"{dex_count} DEX file(s)")
        if dex_total_mb:
            reasons.append(f"DEX payload ~{dex_total_mb} MiB")

    if factors.bluetooth:
        memory += PER_BT_BASE_MB
        memory += max(dex_count, 0) * PER_BT_DEX_MB
        reasons.append("bluetooth enabled")
        if factors.bt_reconstruct_callers and factors.bt_caller_depth:
            memory += max(dex_count, 0) * factors.bt_caller_depth * PER_BT_CALLER_DEPTH_MB
            reasons.append(f"bt_caller_depth={factors.bt_caller_depth}")
        if factors.bt_reconstruct_streams and factors.bt_dataflow_depth:
            memory += max(dex_count, 0) * factors.bt_dataflow_depth * PER_BT_DATAFLOW_DEPTH_MB
            reasons.append(f"bt_dataflow_depth={factors.bt_dataflow_depth}")
        if factors.bt_max_dataflow_nodes:
            memory += max(dex_count, 0) * (factors.bt_max_dataflow_nodes // 100) * PER_BT_DATAFLOW_NODES_MB
        if factors.bt_interprocedural:
            memory += PER_BT_INTERPROC_BASE_MB
            memory += max(dex_count, 0) * factors.bt_max_method_hops * PER_BT_METHOD_HOP_MB
            memory += max(dex_count, 0) * factors.bt_max_field_hops * PER_BT_FIELD_HOP_MB
            memory += max(dex_count, 0) * (factors.bt_max_object_nodes // 100) * PER_BT_OBJECT_NODES_MB
            reasons.append("bluetooth interprocedural object-flow")
            if factors.bt_max_method_hops:
                reasons.append(f"bt_max_method_hops={factors.bt_max_method_hops}")
            if factors.bt_max_field_hops:
                reasons.append(f"bt_max_field_hops={factors.bt_max_field_hops}")
    if factors.evidence_graph:
        memory += PER_EVIDENCE_GRAPH_BASE_MB
        memory += (max(factors.evidence_graph_max_paths, 0) // 10) * PER_EVIDENCE_PATH_MB
        reasons.append("evidence_graph canonicalize/paths")
        if factors.evidence_graph_max_paths:
            reasons.append(f"evidence_graph_max_paths={factors.evidence_graph_max_paths}")
    if factors.communication:
        memory += PER_COMM_BASE_MB
        memory += max(factors.communication_max_buffer_hops, 0) * PER_COMM_BUFFER_HOP_MB
        reasons.append("communication bytes/parser/message analysis")
        if factors.communication_max_paths:
            reasons.append(f"communication_max_paths={factors.communication_max_paths}")

    if total_size_mb >= 100:
        reasons.append(f"large input artifact(s) ~{total_size_mb} MiB")
    if native_count:
        reasons.append(f"{native_count} native .so")
    if len(artifacts) > 1:
        reasons.append(f"{len(artifacts)} artifacts in set")
    if factors.search_terms:
        reasons.append(f"{factors.search_terms} search terms")

    runtime = BASE_RUNTIME_S
    runtime += total_size_mb // 4 * PER_INPUT_RUNTIME
    runtime += dex_count * PER_DEX_RUNTIME
    runtime += native_count * PER_NATIVE_RUNTIME
    runtime += (factors.search_terms // 10) * PER_TERM_RUNTIME
    if factors.dex_context:
        runtime += dex_count * PER_DEX_CONTEXT_RUNTIME
        runtime += dex_count * max(factors.xref_depth, 0) * PER_XREF_RUNTIME
        # callers/callees inflate xref work slightly
        runtime += (factors.max_callers + factors.max_callees) // 20 * dex_count
    if factors.bluetooth and dex_count > 0:
        runtime += dex_count * PER_BT_RUNTIME
        if factors.bt_reconstruct_callers and factors.bt_caller_depth:
            runtime += dex_count * factors.bt_caller_depth * PER_BT_CALLER_DEPTH_RT
        if factors.bt_reconstruct_streams and factors.bt_dataflow_depth:
            runtime += dex_count * factors.bt_dataflow_depth * PER_BT_DATAFLOW_DEPTH_RT
        if factors.bt_max_dataflow_nodes:
            runtime += dex_count * (factors.bt_max_dataflow_nodes // 100) * PER_BT_DATAFLOW_NODES_RT
        if factors.bt_interprocedural:
            runtime += PER_BT_INTERPROC_BASE_RT
            runtime += dex_count * factors.bt_max_method_hops * PER_BT_METHOD_HOP_RT
            runtime += dex_count * factors.bt_max_field_hops * PER_BT_FIELD_HOP_RT
            runtime += dex_count * (factors.bt_max_object_nodes // 100) * PER_BT_OBJECT_NODES_RT
    elif factors.bluetooth:
        runtime += 10
    if factors.evidence_graph:
        runtime += PER_EVIDENCE_GRAPH_BASE_RT
        runtime += (max(factors.evidence_graph_max_paths, 0) // 10) * PER_EVIDENCE_PATH_RT
    if factors.communication:
        runtime += PER_COMM_BASE_RT
        runtime += max(factors.communication_max_buffer_hops, 0) * PER_COMM_BUFFER_HOP_RT

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
        # conservative upper-bound style estimate for result volume
        dex_contexts = min(10_000, max(50, dex_count * 40 + factors.search_terms * 5))
        xrefs = min(50_000, dex_count * max(factors.xref_depth, 1) * 200 + factors.max_callers * dex_count)

    # Estimator-local risk vs policy thresholds (guard still makes final decision)
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
    )
