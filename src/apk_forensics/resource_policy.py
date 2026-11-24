"""Explicit resource policies for AnalysisJob execution.

SearchPlan limits = fachliche Ergebnisbegrenzung.
Resource limits   = System-/Laufzeitbegrenzung.
These must not be mixed or silently rewrite the SearchPlan.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ResourcePolicy:
    """Named budget for job execution. Defaults are safe (standard)."""

    name: str
    max_memory_mb: int | None
    warning_memory_mb: int | None
    max_runtime_seconds: int | None
    warning_runtime_seconds: int | None
    max_findings: int | None
    max_dex_contexts: int | None
    max_xrefs: int | None
    max_input_size_mb: int | None
    max_artifacts: int | None
    # Estimator reject/warn thresholds (may mirror max_*); None = unlimited for that axis
    reject_estimated_memory_mb: int | None
    warn_estimated_memory_mb: int | None
    reject_estimated_runtime_seconds: int | None
    warn_estimated_runtime_seconds: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Explicit, documented defaults — no hidden magic numbers elsewhere.
POLICY_PRESETS: dict[str, ResourcePolicy] = {
    "conservative": ResourcePolicy(
        name="conservative",
        max_memory_mb=1024,
        warning_memory_mb=512,
        max_runtime_seconds=300,
        warning_runtime_seconds=120,
        max_findings=5_000,
        max_dex_contexts=100,
        max_xrefs=1_000,
        max_input_size_mb=256,
        max_artifacts=4,
        reject_estimated_memory_mb=1024,
        warn_estimated_memory_mb=512,
        reject_estimated_runtime_seconds=300,
        warn_estimated_runtime_seconds=120,
    ),
    "standard": ResourcePolicy(
        name="standard",
        max_memory_mb=2048,
        warning_memory_mb=1024,
        max_runtime_seconds=900,
        warning_runtime_seconds=300,
        max_findings=20_000,
        max_dex_contexts=500,
        max_xrefs=5_000,
        max_input_size_mb=512,
        max_artifacts=8,
        reject_estimated_memory_mb=2048,
        warn_estimated_memory_mb=1024,
        reject_estimated_runtime_seconds=900,
        warn_estimated_runtime_seconds=300,
    ),
    "unlimited": ResourcePolicy(
        name="unlimited",
        # Unlimited = this guard axis is not bounded. OS OOM remains an error.
        max_memory_mb=None,
        warning_memory_mb=None,
        max_runtime_seconds=None,
        warning_runtime_seconds=None,
        max_findings=None,
        max_dex_contexts=None,
        max_xrefs=None,
        max_input_size_mb=None,
        max_artifacts=None,
        reject_estimated_memory_mb=None,
        warn_estimated_memory_mb=None,
        reject_estimated_runtime_seconds=None,
        warn_estimated_runtime_seconds=None,
    ),
}

DEFAULT_POLICY_NAME = "standard"


def get_resource_policy(name: str | None = None) -> ResourcePolicy:
    key = (name or DEFAULT_POLICY_NAME).strip().lower()
    if key not in POLICY_PRESETS:
        raise ValueError(
            f"Unknown resource policy {name!r}. Choose one of: {', '.join(sorted(POLICY_PRESETS))}"
        )
    return POLICY_PRESETS[key]
