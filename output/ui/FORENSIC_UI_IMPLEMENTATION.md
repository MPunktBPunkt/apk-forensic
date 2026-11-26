# Forensic UI Implementation Report

## Implemented views

1. Analysis Overview (APK, status strip, pipeline, counters)
2. Interactive Analysis Path (VALUE-V001 focus)
3. Values catalog (neutral structured values)
4. Open Edges / boundaries
5. Runtime / Wire / Correlation separation + SESSION_MISMATCH → REJECTED
6. What we know + Next Required Experiment
7. Timeline (analysis milestones only)
8. Evidence sources list
9. Detail panel (node / edge / source)

## Data sources used

| Role | Typical path |
|---|---|
| Value forensic | `output/v16-value-analysis/VALUE_V001_FORENSIC.json` |
| App flow | `output/v15-flow/application_flow.bmw-connected.json` |
| Cross-apk counters | `output/v14-value/CROSS_APK_EVALUATION_REPORT.json` |
| Runtime readiness | `output/v17-runtime-evidence/RUNTIME_EVIDENCE_V1_READINESS.json` |
| Wire capture (separate) | LAB_B3 path under readiness / wire artifacts |
| Baseline meta | `META.json` / case baseline |

Aggregator: `apk_forensics.ui.snapshot.build_ui_snapshot` → `analysis_ui_snapshot.v1`.

No new analyzer evidence. Snapshot only references and aggregates.

## New / updated files

- `src/apk_forensics/ui/__init__.py`
- `src/apk_forensics/ui/snapshot.py`
- `src/apk_forensics/ui/server.py`
- `src/apk_forensics/ui/static/{index.html,app.js,styles.css}`
- CLI: `ui-snapshot`, `ui` in `cli.py`
- `pyproject.toml` package-data for `ui/static`
- `tests/test_forensic_ui.py`
- `docs/UI.md`
- `output/ui/FORENSIC_UI_IMPLEMENTATION.md` (this file)
- Example snapshot: `output/ui/analysis_ui_snapshot.bmw-connected.json` (local; may be gitignored)

## Tests

`tests/test_forensic_ui.py` covers:

1. Full BMW static state loads
2. VALUE-V001 FACT path
3. Classification preservation (FACT / UNKNOWN / NOT_PROVEN / INPUT_MISSING)
4. SESSION_MISMATCH → REJECTED
5. Wire capture not marked as runtime evidence
6. No fake runtime nodes when input missing
7. FULL_CHAIN only when engine says so
8. Missing optional runtime fields do not crash
9. Empty / no structured-values case
10. BimmerLink / Serial BT case presets build

## Start

```bash
apk-forensics ui-snapshot --case bmw-connected -o output/ui/analysis_ui_snapshot.bmw-connected.json
apk-forensics ui --snapshot output/ui/analysis_ui_snapshot.bmw-connected.json
```

## Open UI gaps

- No live reload when reports change (rebuild snapshot manually)
- Correlation graph is schematic until a real same-session correlation run JSON is wired in
- Large per-APK application-flow reports are not fully inlined (counters prefer compact cross-apk / meta)
- No PNG screenshots committed (browser local only)
