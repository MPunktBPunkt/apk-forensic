# IMPLEMENTATION SUMMARY — Search Plan Builder

## 1. Existing SearchPlan architecture

FACT: Reused `search_plan.py` (`validate_and_normalize`, `load_plan_yaml`, `compute_plan_sha256`, `to_canonical_dict`), `schemas/search_plan.schema.json`, bundled `plans/*.yaml`, Workbench job controller, Resource Estimator/Guard, `run_pipeline`.

## 2. Files changed

- `src/apk_forensics/ui/plan_builder.py` (new)
- `src/apk_forensics/ui/workbench.py` (list/load user plans; suggest/validate/save/clone)
- `src/apk_forensics/ui/server.py` (API routes)
- `src/apk_forensics/ui/static/{index.html,app.js,styles.css}`
- `tests/test_plan_builder.py` (new)
- `docs/UI.md`, `docs/SEARCHPLAN_BUILDER.md`
- `output/ui/FORENSIC_SEARCHPLAN_BUILDER_IMPLEMENTATION.md`

## 3. New UI components

FACT: New Analysis mode tabs — existing plan vs builder; investigation goal; suggest; search targets; areas; traversal; preview; YAML/JSON dump; save; clone.

## 4. New backend components

FACT: Deterministic `suggest_plan_from_goal`, form→raw builder, preview/capabilities, user-plan store + provenance sidecar, clone.

## 5. SearchPlan schema changes

NOT_IMPLEMENTED: No schema break. Provenance is a sidecar JSON (`plan_provenance.v1`), not SearchPlan fields.

## 6. Validation changes

FACT: All plans still go through existing `validate_and_normalize`. UI surfaces `INVALID_SEARCH_PLAN` errors.

## 7. Plan suggestion mechanism

FACT: Local keyword heuristics (iAP2, AOA, RFCOMM, auth, media, BCL, Etch/RHMI). Configurable depth presets shallow/standard/deep.

LIMITATION: No LLM integration (by design for now).

## 8. User plan storage

FACT: `work/user-plans/<name>.yaml` + `<name>.provenance.json`.

## 9. Clone behavior

FACT: Clone writes user plan; built-in file unchanged.

NOT_IMPLEMENTED: Explicit “overwrite built-in” with confirmation (safer clone-only).

## 10. Resource Policy separation

FACT: Builder never writes resource thresholds into SearchPlan; Estimate/Guard remain separate.

## 11. Workbench integration

FACT: Saved user plans selectable as `user:<name>` for estimate/start via existing job path.

## 12. Pipeline limitations

FACT: UI shows coverage:
- Base static analysis: AVAILABLE
- Extended diagnose-* / application-flow / V001 deep: NOT AUTOMATIC
- Runtime instrumentation: SEPARATE WORKFLOW
- Runtime/Wire correlation: INPUT-DEPENDENT

## 13. Evidence integrity

FACT: Suggestion/provenance explicitly non-evidence; no FACT upgrade; topic terms are search targets only.

## 14. Tests

`tests/test_plan_builder.py` + existing workbench/search_plan/UI suites.

## 15. Test count

See pytest summary at commit time.

## 16. Example generated plan

Goal: “Untersuche iAP2-Kommunikation…”
→ terms include iAP2/iAP/Accessory Protocol; bluetooth+communication+evidence_graph typically enabled; `plan_sha256` deterministic.

## 17. Known limitations

- diagnose-* chain not auto-run after Workbench scan
- Built-in overwrite not offered
- Suggestion vocabulary is finite heuristics
- Structured Values module is not a SearchPlan enum module (post-process)

## 18. Next recommended step

Optional post-scan orchestration of selected `diagnose-*` steps behind an explicit Workbench checkbox, without implying automatic protocol semantics.

---

### Feature matrix

| Function | Status |
|---|---|
| Existing plan select/configure/estimate/run | IMPLEMENTED |
| New plan builder UI | IMPLEMENTED |
| Deterministic suggest-from-goal | IMPLEMENTED |
| Preview YAML/JSON | IMPLEMENTED |
| Validate via existing schema | IMPLEMENTED |
| Save user plan + provenance | IMPLEMENTED |
| Clone built-in | IMPLEMENTED |
| Overwrite built-in | NOT_IMPLEMENTED |
| LLM suggestion | NOT_IMPLEMENTED |
| Auto diagnose-* chain | NOT_IMPLEMENTED (documented LIMITATION) |
| Evidence from goal | NOT_IMPLEMENTED (forbidden) |
