"""AnalysisJob: one concrete execution of a SearchPlan on concrete inputs.

Resource Guard never silently mutates the SearchPlan.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from apk_forensics import __version__
from apk_forensics.errors import ApkForensicsError, ExitCode
from apk_forensics.hashing import file_sha256_and_size
from apk_forensics.resource_estimator import (
    ArtifactFingerprint,
    PlanFactors,
    ResourceEstimate,
    estimate_resources,
    fingerprint_apk,
    plan_factors_from_search_plan,
)
from apk_forensics.resource_guard import ResourceDecision, assert_may_start, evaluate_resources
from apk_forensics.resource_policy import ResourcePolicy, get_resource_policy
from apk_forensics.search_plan import SearchPlan
from apk_forensics.utils import utc_now_iso


class JobCancelled(ApkForensicsError):
    exit_code = ExitCode.PARTIAL_OR_WARNINGS

    def __init__(self, message: str = "cancelled") -> None:
        super().__init__(message, exit_code=ExitCode.PARTIAL_OR_WARNINGS)


class JobRuntimeLimit(ApkForensicsError):
    exit_code = ExitCode.FATAL

    def __init__(self, message: str = "runtime_limit") -> None:
        super().__init__(message, exit_code=ExitCode.FATAL)
        self.termination_reason = "runtime_limit"


class JobLimitExceeded(ApkForensicsError):
    """Hard resource result-count limit hit during analysis (not a silent truncate)."""

    exit_code = ExitCode.FATAL

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message, exit_code=ExitCode.FATAL)
        self.termination_reason = reason


class CancellationToken:
    """Cooperative cancellation checked at safe pipeline boundaries."""

    def __init__(self) -> None:
        self._cancelled = False
        self.reason: str | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self, reason: str = "cancelled") -> None:
        self._cancelled = True
        self.reason = reason

    def check(self) -> None:
        if self._cancelled:
            raise JobCancelled(self.reason or "cancelled")


@dataclass
class ResourceActual:
    runtime_seconds: float | None = None
    peak_memory_mb: int | None = None  # null if not reliably measurable
    findings: int | None = None
    dex_contexts: int | None = None
    xrefs: int | None = None
    # v1.1 optional graph/coverage counters (filled when available; else omitted/None)
    raw_node_count: int | None = None
    raw_edge_count: int | None = None
    canonical_object_count: int | None = None
    canonical_node_count: int | None = None
    evidence_path_count: int | None = None
    communication_path_count: int | None = None
    boundary_count: int | None = None
    truncation_count: int | None = None
    cpu_time_seconds: float | None = None  # null if not measurable on host

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "runtime_seconds": self.runtime_seconds,
            "peak_memory_mb": self.peak_memory_mb,
            "findings": self.findings,
            "dex_contexts": self.dex_contexts,
            "xrefs": self.xrefs,
            "raw_node_count": self.raw_node_count,
            "raw_edge_count": self.raw_edge_count,
            "canonical_object_count": self.canonical_object_count,
            "canonical_node_count": self.canonical_node_count,
            "evidence_path_count": self.evidence_path_count,
            "communication_path_count": self.communication_path_count,
            "boundary_count": self.boundary_count,
            "truncation_count": self.truncation_count,
            "cpu_time_seconds": self.cpu_time_seconds,
        }
        return payload


@dataclass
class AnalysisJob:
    job_id: str
    status: str  # queued | running | completed | failed | cancelled | rejected
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    plan_sha256: str | None = None
    input_artifact_sha256: str | None = None
    input_artifact_sha256s: list[str] = field(default_factory=list)
    resource_policy: ResourcePolicy | None = None
    resource_estimate: ResourceEstimate | None = None
    resource_decision: ResourceDecision | None = None
    resource_actual: ResourceActual = field(default_factory=ResourceActual)
    termination_reason: str | None = None
    allow_resource_warning: bool = False
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    _t0: float | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "plan_sha256": self.plan_sha256,
            "input_artifact_sha256": self.input_artifact_sha256,
            "input_artifact_sha256s": list(self.input_artifact_sha256s),
            "termination_reason": self.termination_reason,
            "allow_resource_warning": self.allow_resource_warning,
        }

    def resource_report_section(self) -> dict[str, Any]:
        return {
            "policy": self.resource_policy.to_dict() if self.resource_policy else None,
            "estimate": self.resource_estimate.to_dict() if self.resource_estimate else None,
            "actual": self.resource_actual.to_dict(),
            "decision": self.resource_decision.decision if self.resource_decision else None,
            "decision_reasons": list(self.resource_decision.reasons) if self.resource_decision else [],
            "termination_reason": self.termination_reason,
        }


def _optional_rss_mb() -> int | None:
    """Best-effort RSS; return null if unavailable (never invent a value)."""
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # Linux: kilobytes; macOS: bytes
        if usage > 10_000_000:  # treat as bytes
            return int(usage / (1024 * 1024))
        return int(usage / 1024)
    except Exception:
        return None


def make_job_id(
    *,
    plan_sha256: str | None,
    input_sha256: str,
    engine_version: str,
    created_at: str,
    creation_nonce: str,
) -> str:
    raw = "|".join(
        [
            plan_sha256 or "no-plan",
            input_sha256,
            engine_version,
            created_at,
            creation_nonce,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_analysis_job(
    *,
    apk_paths: list[Path],
    search_plan: SearchPlan | None,
    policy: ResourcePolicy | None = None,
    allow_resource_warning: bool = False,
    cli_dex_context: bool = False,
    cli_bluetooth: bool = False,
) -> tuple[AnalysisJob, list[ArtifactFingerprint], PlanFactors]:
    """Preflight: fingerprint inputs, estimate, decide. Does not start the pipeline."""
    if not apk_paths:
        raise ValueError("apk_paths required")

    policy = policy or get_resource_policy()
    created_at = utc_now_iso()
    creation_nonce = uuid.uuid4().hex[:16]

    fingerprints = [fingerprint_apk(p) for p in apk_paths]
    # Hash first artifact for primary identity (full file SHA — needed for reproducibility)
    primary_sha, _ = file_sha256_and_size(apk_paths[0])
    all_shas = [primary_sha]
    for extra in apk_paths[1:]:
        sha, _ = file_sha256_and_size(extra)
        all_shas.append(sha)

    factors = plan_factors_from_search_plan(
        search_plan,
        cli_dex=cli_dex_context,
        cli_bt=cli_bluetooth,
    )
    estimate = estimate_resources(fingerprints, factors, policy)
    decision = evaluate_resources(estimate, policy)

    plan_sha = search_plan.plan_sha256 if search_plan else None
    job_id = make_job_id(
        plan_sha256=plan_sha,
        input_sha256="+".join(all_shas),
        engine_version=__version__,
        created_at=created_at,
        creation_nonce=creation_nonce,
    )

    job = AnalysisJob(
        job_id=job_id,
        status="queued",
        created_at=created_at,
        plan_sha256=plan_sha,
        input_artifact_sha256=primary_sha,
        input_artifact_sha256s=all_shas,
        resource_policy=policy,
        resource_estimate=estimate,
        resource_decision=decision,
        allow_resource_warning=allow_resource_warning,
    )
    return job, fingerprints, factors


def preflight_or_reject(job: AnalysisJob) -> None:
    """Apply guard. On REJECT/WARNING-without-override: mark job rejected and raise."""
    assert job.resource_decision is not None
    try:
        assert_may_start(
            job.resource_decision,
            allow_resource_warning=job.allow_resource_warning,
        )
    except Exception:
        job.status = "rejected"
        job.finished_at = utc_now_iso()
        if job.resource_decision.decision == "REJECT":
            job.termination_reason = "resource_reject"
        else:
            job.termination_reason = "resource_warning_blocked"
        raise


def mark_running(job: AnalysisJob) -> None:
    job.status = "running"
    job.started_at = utc_now_iso()
    job._t0 = time.perf_counter()


def mark_completed(job: AnalysisJob, *, findings: int, dex_contexts: int | None, xrefs: int | None) -> None:
    job.status = "completed"
    job.finished_at = utc_now_iso()
    job.termination_reason = None
    _fill_actual(job, findings=findings, dex_contexts=dex_contexts, xrefs=xrefs)


def mark_failed(job: AnalysisJob, reason: str, *, findings: int | None = None) -> None:
    job.status = "failed"
    job.finished_at = utc_now_iso()
    job.termination_reason = reason
    _fill_actual(job, findings=findings, dex_contexts=None, xrefs=None)


def mark_cancelled(job: AnalysisJob, reason: str = "cancelled") -> None:
    job.status = "cancelled"
    job.finished_at = utc_now_iso()
    job.termination_reason = reason
    _fill_actual(job, findings=None, dex_contexts=None, xrefs=None)


def _fill_actual(
    job: AnalysisJob,
    *,
    findings: int | None,
    dex_contexts: int | None,
    xrefs: int | None,
) -> None:
    elapsed = None
    if job._t0 is not None:
        elapsed = round(time.perf_counter() - job._t0, 3)
    job.resource_actual = ResourceActual(
        runtime_seconds=elapsed,
        peak_memory_mb=_optional_rss_mb(),
        findings=findings,
        dex_contexts=dex_contexts,
        xrefs=xrefs,
        cpu_time_seconds=_optional_cpu_time_s(),
    )


def enrich_actual_from_report(job: AnalysisJob, report: Any) -> None:
    """Fill graph/coverage counters from a finished Report without touching the estimate."""
    bt = getattr(report, "bluetooth_path", None) or {}
    eg = (bt.get("evidence_graph") or {}) if isinstance(bt, dict) else {}
    ce = getattr(report, "communication_evidence", None) or {}
    act = job.resource_actual
    raw = eg.get("raw") or {}
    canon = eg.get("canonical") or {}
    cov = (ce.get("coverage") or {}) if isinstance(ce, dict) else {}
    act.raw_node_count = raw.get("nodes")
    act.raw_edge_count = raw.get("edges")
    act.canonical_object_count = canon.get("objects")
    act.canonical_node_count = canon.get("nodes")
    act.evidence_path_count = len(eg.get("evidence_paths") or []) if eg else None
    act.communication_path_count = (ce.get("summary") or {}).get("communication_paths") if ce else None
    act.boundary_count = len(eg.get("boundaries") or []) + len((ce.get("boundaries") or []) if ce else [])
    act.truncation_count = (cov.get("truncated") if cov else None) or (
        (eg.get("coverage") or {}).get("truncated") if eg else None
    )


def _optional_cpu_time_s() -> float | None:
    try:
        import resource as _res

        usage = _res.getrusage(_res.RUSAGE_SELF)
        return round(float(usage.ru_utime + usage.ru_stime), 3)
    except Exception:
        return None


def check_runtime_limit(job: AnalysisJob) -> None:
    """Call at pipeline checkpoints. Does not alter SearchPlan."""
    policy = job.resource_policy
    if policy is None or policy.max_runtime_seconds is None or job._t0 is None:
        return
    elapsed = time.perf_counter() - job._t0
    if elapsed > policy.max_runtime_seconds:
        raise JobRuntimeLimit(
            f"runtime_limit: elapsed {elapsed:.1f}s > max_runtime_seconds={policy.max_runtime_seconds}"
        )


def format_preflight_text(
    *,
    plan: SearchPlan | None,
    fingerprints: list[ArtifactFingerprint],
    factors: PlanFactors,
    estimate: ResourceEstimate,
    decision: ResourceDecision,
) -> str:
    lines: list[str] = []
    if plan is not None:
        lines.append("PLAN VALID")
        lines.append(f"plan_sha256: {plan.plan_sha256}")
        lines.append(f"name: {plan.plan_name}")
    else:
        lines.append("PLAN: (none — CLI defaults)")
    lines.append("")
    lines.append("INPUT")
    for fp in fingerprints:
        size_mb = fp.size_bytes / (1024 * 1024)
        lines.append(f"  {fp.file_name}")
        lines.append(f"    size: {size_mb:.1f} MiB")
        lines.append(f"    dex: {fp.dex_count}")
        lines.append(f"    native: {fp.native_so_count}")
    lines.append("")
    lines.append("MODULES")
    lines.append(f"  dex_context: {'enabled' if factors.dex_context else 'disabled'}")
    lines.append(f"  bluetooth: {'enabled' if factors.bluetooth else 'disabled'}")
    lines.append(f"  xref_depth: {factors.xref_depth}")
    lines.append("")
    lines.append("RESOURCE ESTIMATE")
    lines.append(f"  memory: {estimate.memory_mb} MiB")
    lines.append(f"  runtime: {estimate.runtime_seconds} s")
    lines.append(f"  findings: {estimate.findings}")
    lines.append(f"  dex_contexts: {estimate.dex_contexts}")
    lines.append(f"  xrefs: {estimate.xrefs}")
    lines.append("")
    lines.append("DECISION")
    lines.append(f"  {decision.decision}")
    lines.append("")
    lines.append("REASONS")
    for r in decision.reasons:
        lines.append(f"  - {r}")
    lines.append("")
    return "\n".join(lines)


def run_with_job_lifecycle(
    job: AnalysisJob,
    runner: Callable[[AnalysisJob], tuple[Any, dict[str, Path], list[str]]],
) -> tuple[Any, dict[str, Path], list[str]]:
    """Start job, run callable, finalize status. Propagates cancellation/runtime errors."""
    preflight_or_reject(job)
    mark_running(job)
    try:
        job.cancellation.check()
        check_runtime_limit(job)
        result = runner(job)
        report = result[0]
        findings_n = None
        dex_n = None
        xref_n = None
        if hasattr(report, "findings"):
            findings_n = len([f for f in report.findings if f.classification != "REJECTED"])
            dex = getattr(report, "dex_context", None) or {}
            counts = dex.get("counts") or {}
            dex_n = counts.get("contexts", len(dex.get("contexts") or []) if dex else None)
            xref_n = counts.get("xref_candidates", len(dex.get("xref_candidates") or []) if dex else None)
        elif isinstance(report, dict):
            findings_n = len(report.get("findings") or [])
            dex_n = None
            xref_n = None
        mark_completed(job, findings=findings_n or 0, dex_contexts=dex_n, xrefs=xref_n)
        return result
    except JobCancelled as exc:
        mark_cancelled(job, reason=str(exc) or "cancelled")
        raise
    except JobLimitExceeded as exc:
        mark_failed(job, exc.termination_reason)
        raise
    except JobRuntimeLimit as exc:
        mark_failed(job, getattr(exc, "termination_reason", None) or "runtime_limit")
        raise
    except Exception:
        mark_failed(job, "analysis_exception")
        raise
