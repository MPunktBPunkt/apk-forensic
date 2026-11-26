# SearchPlan Builder

## What is a SearchPlan?

A **SearchPlan** is a declarative investigation contract: *what* to search and *how deep* to explore statically. It is **not** a findings document and never asserts that a protocol was found.

```text
Investigation Goal  →  SearchPlan (+ plan_sha256)  →  Resource Guard  →  Analyzer  →  Evidence
```

## SearchPlan vs Profile

- **Profile** (optional): naming / context path (`profile.name` / relative `profile.path`)
- **SearchPlan**: the actual analysis contract (modules, search, traversal, evidence *filter*)

## SearchPlan vs Resource Policy

| | SearchPlan | Resource Policy |
|---|---|---|
| Question | What / how deep to investigate? | How much CPU/RAM/time may be used? |
| Example | `max_method_hops = 5` | `reject_estimated_memory_mb` |
| Guard | never silently rewritten | may OK / WARNING / REJECT |

## Plan Builder

In the Workbench under **New Analysis → Neuen SearchPlan erstellen**:

1. Enter an investigation goal (intention metadata)
2. Optionally **Plan aus Untersuchungsfrage ableiten** (deterministic heuristics)
3. Edit search targets / areas / traversal
4. Preview YAML / normalized JSON
5. Validate → Save user plan → Estimate → Run

User plans are stored under `work/user-plans/*.yaml` with a separate `*.provenance.json` (not mixed into the SearchPlan schema).

Built-in `plans/*.yaml` are not overwritten; use **Plan klonen**.

## Plan Suggestion

Deterministic topic → terms/modules mapping (e.g. iAP2 → search terms + bluetooth/communication flags).

**Never** means `iAP2 = FOUND`. The analyzer alone produces evidence.

## Evidence integrity

The builder does not create or upgrade:

`FACT` `INFERENCE` `CORRELATION` `UNKNOWN` `NOT_PROVEN` `REJECTED` `INPUT_MISSING`

## Pipeline limits (Workbench)

| Stage | Status |
|---|---|
| Base static analysis (`run_pipeline`) | AVAILABLE |
| Extended diagnose-* / application-flow / V001 deep forensic | NOT AUTOMATIC |
| Runtime instrumentation | SEPARATE WORKFLOW |
| Runtime/Wire correlation | INPUT-DEPENDENT |

## APIs

- `POST /api/plans/suggest`
- `POST /api/plans/validate` / `preview`
- `POST /api/plans/save`
- `POST /api/plans/clone`
