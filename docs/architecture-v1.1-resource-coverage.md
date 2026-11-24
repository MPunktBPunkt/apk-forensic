# Architecture — Resource Calibration & Coverage (v1.1)

## Separation

```text
RESOURCE ESTIMATE          ≠          ANALYSIS COVERAGE
─────────────────                     ─────────────────
preflight prediction                  path completeness
Guard OK/WARNING/REJECT               COMPLETE/TRUNCATED/BOUNDARY/…
estimate vs actual                    truncation vs APK boundary
```

These must never be mixed: a resource WARNING is not evidence failure.

## Guard order (immutable)

```text
Estimate → Guard decision → Run → Actual measurement
```

Actuals must not rewrite the estimate or Guard decision for the same run.

## Guard semantics

| Decision | Meaning |
|---|---|
| OK | Within warning thresholds; may start |
| WARNING | Exceeds warning threshold; needs `--allow-resource-warning` |
| REJECT | Exceeds hard limit; **no override** |

## Estimator breakdown (existing coefficients)

Components sum to Guard-facing totals:

- `baseline_input_dex_native`
- `dex_context_xref`
- `bluetooth_path_analysis`
- `caller_reconstruction`
- `object_flow`
- `evidence_graph`
- `communication_dataflow`

INPUT SIZE (APK/DEX/native) is distinct from ANALYSIS COMPLEXITY (hops/nodes/modules).

## Calibration policy

Historical `actual/estimate` ratios are observational.

**Forbidden:** `estimated_memory *= 0.66` from a single BMW run.

**Allowed:** documented component-wise heuristics with multi-run evidence — not applied to Guard in v1.1.

## Coverage statuses

| Status | Meaning |
|---|---|
| COMPLETE | Structural end reached with proven steps |
| TRUNCATED | Analyzer/plan limit (MAX_* / METHOD_RETENTION_CAP / …) |
| BOUNDARY | APK/analysis gap (NATIVE / REFLECTION / UNKNOWN_HELPER / …) |
| UNRESOLVED | Multi-step without clear end or classified stop |
| NO_CONTINUATION | Single-step / no further static continuation |

Coverage never reclassifies FACT → UNKNOWN.

## Method retention

`METHOD_RETENTION_CAP` is an **analyzer** bound on streamed method bodies.
It is not a native/reflection proof gap.
