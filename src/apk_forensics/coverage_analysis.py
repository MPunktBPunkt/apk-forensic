"""v1.1 Analysis Coverage — separate from resource estimation.

Annotates evidence / communication paths with completion status without
changing FACT/INFERENCE/UNKNOWN evidence classifications.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

COVERAGE_STATUSES = frozenset(
    {
        "COMPLETE",
        "TRUNCATED",
        "BOUNDARY",
        "UNRESOLVED",
        "NO_CONTINUATION",
    }
)

# Analyzer / plan limits (not APK semantic gaps)
TRUNCATION_REASONS = frozenset(
    {
        "MAX_METHOD_HOPS",
        "MAX_FIELD_HOPS",
        "MAX_OBJECT_NODES",
        "MAX_DATAFLOW_NODES",
        "MAX_DATAFLOW_PATHS",
        "METHOD_RETENTION_CAP",
        "RESULT_LIMIT",
        "CYCLE_GUARD",
        "RESOURCE_LIMIT",
        "MAX_BUFFER_HOPS",
        "MAX_PARSER_HOPS",
        "MAX_MESSAGE_HOPS",
    }
)

# True analysis / APK boundaries
BOUNDARY_REASONS = frozenset(
    {
        "NATIVE",
        "REFLECTION",
        "NATIVE_BOUNDARY",
        "REFLECTION_BOUNDARY",
        "MISSING_XREF",
        "UNRESOLVED_RETURN",
        "UNRESOLVED_ALIAS",
        "UNKNOWN_HELPER",
        "unresolved_callee",
        "unsupported_pattern",
        "return_no_move_result",
        "unresolved_parameter",
        "unresolved_field",
    }
)

_LIMIT_ALIASES = {
    "max_method_hops": "MAX_METHOD_HOPS",
    "max_field_hops": "MAX_FIELD_HOPS",
    "max_object_nodes": "MAX_OBJECT_NODES",
    "max_dataflow_nodes": "MAX_DATAFLOW_NODES",
    "max_dataflow_paths": "MAX_DATAFLOW_PATHS",
    "max_buffer_hops": "MAX_BUFFER_HOPS",
    "max_parser_hops": "MAX_PARSER_HOPS",
    "max_message_hops": "MAX_MESSAGE_HOPS",
    "cycle": "CYCLE_GUARD",
    "cycle_detected": "CYCLE_GUARD",
    "METHOD_RETENTION_CAP": "METHOD_RETENTION_CAP",
    "NATIVE": "NATIVE_BOUNDARY",
    "REFLECTION": "REFLECTION_BOUNDARY",
}

_COMPLETE_INBOUND_ENDS = frozenset(
    {"MESSAGE_OBJECT", "DECODER", "PARSER", "PRIMITIVE_DECODE", "STRING_DECODE"}
)
_COMPLETE_OUTBOUND_ENDS = frozenset({"OUTPUT_WRITE"})
_COMPLETE_TRANSPORT_KINDS = frozenset(
    {"SOCKET_PATH", "INPUT_PATH", "OUTPUT_PATH", "COMBINED_COMMUNICATION_PATH"}
)


def normalize_reason(reason: str | None) -> str | None:
    if not reason:
        return None
    r = str(reason).strip()
    if r in _LIMIT_ALIASES:
        return _LIMIT_ALIASES[r]
    upper = r.upper().replace("-", "_").replace(" ", "_")
    if upper in TRUNCATION_REASONS or upper in BOUNDARY_REASONS:
        return upper
    if r in TRUNCATION_REASONS or r in BOUNDARY_REASONS:
        return r
    return _LIMIT_ALIASES.get(r, r)


def classify_reason(reason: str | None) -> str:
    """Return TRUNCATION | BOUNDARY | OTHER for a normalized reason."""
    n = normalize_reason(reason)
    if n is None:
        return "OTHER"
    if n in TRUNCATION_REASONS or n in {
        "MAX_METHOD_HOPS",
        "MAX_FIELD_HOPS",
        "MAX_OBJECT_NODES",
        "MAX_DATAFLOW_NODES",
        "MAX_DATAFLOW_PATHS",
        "METHOD_RETENTION_CAP",
        "RESULT_LIMIT",
        "CYCLE_GUARD",
        "RESOURCE_LIMIT",
        "MAX_BUFFER_HOPS",
        "MAX_PARSER_HOPS",
        "MAX_MESSAGE_HOPS",
    }:
        return "TRUNCATION"
    if n in BOUNDARY_REASONS or n.endswith("_BOUNDARY"):
        return "BOUNDARY"
    return "OTHER"


def _boundary_reasons(path: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for b in path.get("boundaries") or []:
        if isinstance(b, dict):
            r = normalize_reason(b.get("reason"))
            if r:
                out.append(r)
        elif isinstance(b, str):
            r = normalize_reason(b)
            if r:
                out.append(r)
    b0 = path.get("boundary")
    if isinstance(b0, dict):
        r = normalize_reason(b0.get("reason"))
        if r:
            out.append(r)
    return out


def annotate_path_coverage(
    path: dict[str, Any],
    *,
    retention_capped: bool = False,
    max_depth: int | None = None,
) -> dict[str, Any]:
    """Attach coverage metadata; never mutates evidence classification fields."""
    reasons = _boundary_reasons(path)
    steps = list(path.get("steps") or [])
    depth = len(steps)
    types = {s.get("node_type") for s in steps}
    direction = path.get("direction")
    kind = path.get("kind") or ""

    status = "NO_CONTINUATION"
    reason: str | None = None
    resource_limited = False
    analysis_boundary = False

    trunc = [r for r in reasons if classify_reason(r) == "TRUNCATION"]
    bounds = [r for r in reasons if classify_reason(r) == "BOUNDARY"]

    if retention_capped and not trunc:
        trunc.append("METHOD_RETENTION_CAP")

    if trunc:
        status = "TRUNCATED"
        reason = trunc[0]
        resource_limited = True
    elif bounds:
        status = "BOUNDARY"
        reason = bounds[0]
        analysis_boundary = True
    else:
        complete = False
        if direction == "INBOUND":
            complete = bool(types & _COMPLETE_INBOUND_ENDS) and "INPUT_READ" in types
        elif direction == "OUTBOUND":
            complete = bool(types & _COMPLETE_OUTBOUND_ENDS)
        elif kind in _COMPLETE_TRANSPORT_KINDS:
            # Transport paths: complete when multi-step without open boundary
            complete = depth >= 2
        elif depth >= 2 and (
            ("INPUT_READ" in types and types & _COMPLETE_INBOUND_ENDS)
            or ("OUTPUT_WRITE" in types)
            or ("MESSAGE_OBJECT" in types and "SERIALIZER" in types)
        ):
            complete = True

        if complete:
            status = "COMPLETE"
            reason = None
        elif depth <= 1:
            status = "NO_CONTINUATION"
            reason = "NO_CONTINUATION"
        else:
            status = "UNRESOLVED"
            reason = "UNRESOLVED"

    if max_depth is not None and depth >= max_depth and status == "COMPLETE":
        # Depth reached a hop cap without explicit boundary record — still COMPLETE
        # if structural end was reached; otherwise would already be TRUNCATED.
        pass

    coverage = {
        "status": status,
        "reason": reason,
        "depth_reached": depth,
        "resource_limited": resource_limited,
        "analysis_boundary": analysis_boundary,
        "termination_reason": reason,
    }
    # Non-destructive: keep original classification/confidence
    path["coverage"] = coverage
    path["coverage_status"] = status
    path["termination_reason"] = reason
    path["depth_reached"] = depth
    path["resource_limited"] = resource_limited
    path["analysis_boundary"] = analysis_boundary
    return path


def summarize_coverage(paths: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    trunc_counts: Counter[str] = Counter()
    boundary_counts: Counter[str] = Counter()
    for p in paths:
        cov = p.get("coverage") or {}
        st = cov.get("status") or p.get("coverage_status") or "UNRESOLVED"
        status_counts[st] += 1
        reason = cov.get("reason") or p.get("termination_reason")
        if st == "TRUNCATED" and reason:
            trunc_counts[str(reason)] += 1
        if st == "BOUNDARY" and reason:
            boundary_counts[str(reason)] += 1
    primary_trunc = trunc_counts.most_common(1)[0][0] if trunc_counts else None
    primary_bound = boundary_counts.most_common(1)[0][0] if boundary_counts else None
    return {
        "paths_total": len(paths),
        "complete": status_counts.get("COMPLETE", 0),
        "truncated": status_counts.get("TRUNCATED", 0),
        "boundary": status_counts.get("BOUNDARY", 0),
        "unresolved": status_counts.get("UNRESOLVED", 0),
        "no_continuation": status_counts.get("NO_CONTINUATION", 0),
        "truncation_reasons": dict(trunc_counts),
        "boundary_reasons": dict(boundary_counts),
        "primary_truncation": primary_trunc,
        "primary_boundary": primary_bound,
        "note": (
            "Coverage status does not reclassify FACT/INFERENCE/UNKNOWN evidence. "
            "Resource warning is not evidence failure."
        ),
    }


def annotate_paths(
    paths: list[dict[str, Any]],
    *,
    retention_capped: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    annotated = [
        annotate_path_coverage(dict(p), retention_capped=retention_capped) for p in paths
    ]
    return annotated, summarize_coverage(annotated)
