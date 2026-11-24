"""ResourceGuard: OK / WARNING / REJECT decisions.

Never silently mutates SearchPlan parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from apk_forensics.errors import ApkForensicsError, ExitCode
from apk_forensics.resource_estimator import ResourceEstimate
from apk_forensics.resource_policy import ResourcePolicy


class ResourceRejectedError(ApkForensicsError):
    """Hard resource rejection — analysis must not start."""

    exit_code = ExitCode.RESOURCE_REJECTED

    def __init__(self, message: str, *, decision: "ResourceDecision") -> None:
        super().__init__(message, exit_code=ExitCode.RESOURCE_REJECTED)
        self.decision = decision


class ResourceWarningBlockedError(ApkForensicsError):
    """WARNING without --allow-resource-warning — analysis must not start."""

    exit_code = ExitCode.RESOURCE_WARNING_BLOCKED

    def __init__(self, message: str, *, decision: "ResourceDecision") -> None:
        super().__init__(message, exit_code=ExitCode.RESOURCE_WARNING_BLOCKED)
        self.decision = decision


@dataclass
class ResourceDecision:
    decision: str  # OK | WARNING | REJECT
    reasons: list[str] = field(default_factory=list)
    estimate: ResourceEstimate | None = None
    policy_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reasons": list(self.reasons),
            "policy": self.policy_name,
            "estimate": self.estimate.to_dict() if self.estimate else None,
        }


def evaluate_resources(
    estimate: ResourceEstimate,
    policy: ResourcePolicy,
) -> ResourceDecision:
    """Map estimate + policy thresholds to a final decision. Does not alter the plan."""
    reasons: list[str] = []
    decision = "OK"

    def _check_mem(value: int) -> None:
        nonlocal decision
        if policy.warn_estimated_memory_mb is not None and value >= policy.warn_estimated_memory_mb:
            decision = "WARNING"
            reasons.append(
                f"estimated memory {value} MiB exceeds warning threshold "
                f"{policy.warn_estimated_memory_mb} MiB"
            )
        if policy.reject_estimated_memory_mb is not None and value >= policy.reject_estimated_memory_mb:
            decision = "REJECT"
            reasons.append(
                f"estimated memory {value} MiB exceeds hard limit "
                f"{policy.reject_estimated_memory_mb} MiB"
            )

    def _check_rt(value: int) -> None:
        nonlocal decision
        if policy.warn_estimated_runtime_seconds is not None and value >= policy.warn_estimated_runtime_seconds:
            if decision != "REJECT":
                decision = "WARNING"
            reasons.append(
                f"estimated runtime {value}s exceeds warning threshold "
                f"{policy.warn_estimated_runtime_seconds}s"
            )
        if (
            policy.reject_estimated_runtime_seconds is not None
            and value >= policy.reject_estimated_runtime_seconds
        ):
            decision = "REJECT"
            reasons.append(
                f"estimated runtime {value}s exceeds hard limit "
                f"{policy.reject_estimated_runtime_seconds}s"
            )

    _check_mem(estimate.memory_mb)
    _check_rt(estimate.runtime_seconds)

    # Carry estimator structural rejects
    for r in estimate.reasons:
        if "exceeds" in r and decision != "REJECT":
            # input size / artifact count already flagged in estimate.risk
            pass
    if estimate.risk == "reject":
        decision = "REJECT"
        for r in estimate.reasons:
            if r not in reasons:
                reasons.append(r)

    if decision == "OK" and estimate.risk == "warning":
        decision = "WARNING"
        for r in estimate.reasons:
            if r not in reasons:
                reasons.append(r)

    if decision == "WARNING" and not reasons:
        reasons.extend(estimate.reasons)
    if decision == "OK" and not reasons:
        reasons.append("within policy budgets")

    # Deduplicate while preserving order
    seen: set[str] = set()
    uniq: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            uniq.append(r)

    return ResourceDecision(
        decision=decision,
        reasons=uniq,
        estimate=estimate,
        policy_name=policy.name,
    )


def assert_may_start(
    decision: ResourceDecision,
    *,
    allow_resource_warning: bool = False,
) -> None:
    """Raise if the job must not start. Never rewrites the SearchPlan."""
    if decision.decision == "REJECT":
        raise ResourceRejectedError(
            "RESOURCE REJECT — analysis not started\n"
            + "\n".join(f"- {r}" for r in decision.reasons),
            decision=decision,
        )
    if decision.decision == "WARNING" and not allow_resource_warning:
        raise ResourceWarningBlockedError(
            "RESOURCE WARNING — analysis not started "
            "(pass --allow-resource-warning to proceed explicitly)\n"
            + "\n".join(f"- {r}" for r in decision.reasons),
            decision=decision,
        )
