# Forensic Workbench Implementation

## Architecture

```text
SPA (static/)  →  Job API (server.py)  →  WorkbenchController (workbench.py)
                                              ↓
                         existing: SearchPlan, Resource Estimator/Guard,
                         AnalysisJob, run_pipeline / run_bundle_pipeline
                                              ↓
                         report.json + workbench_job.json + analysis_ui_snapshot.json
                                              ↓
                         Forensic Explorer (unchanged classification rules)
```

Orchestrator only — no second analyzer.

## Upload

- `POST /api/upload` → `work/ui-uploads/<stamp>/<safe-name>`
- Filename sanitized (`safe_upload_filename`)
- Fingerprint via `fingerprint_apk` + SHA-256

## Server path

- `POST /api/validate` with `{ "paths": ["/abs/or/repo-relative.apk"] }`
- Explicit UI label: **Server-side path** on analysis host

## Profiles / Plans

- Only `plans/*.yaml` (no fake “BMW Connected” preset)
- Criteria form maps to SearchPlan YAML fields; overrides re-validated → new `plan_sha256`

## SearchPlan vs Resource Policy

- Separate UI sections
- Estimator/Guard never rewrite SearchPlan

## Preflight / stage estimates

- `create_analysis_job` + existing breakdown components
- Display kind: `HEURISTIC_ESTIMATE`
- Unmapped stages: “Not separately estimated”

## Job system

- Background thread (HTTP request does not block on full scan)
- Progress stages via optional `analysis_job.on_stage` from pipeline checkpoints
- Persist `workbench_job.v1` under `output/ui-jobs/`
- ETA = heuristic remaining from preflight estimate

## Results

- Paths collected from pipeline `outputs` + output dir artefacts
- `/api/result?path=` only serves files under uploads/jobs (no `/etc/passwd`)
- Best-effort `analysis_ui_snapshot.json` after COMPLETE → Explorer refresh

## Security

- Default `127.0.0.1`; warn on `0.0.0.0`
- REJECT non-overridable; WARNING needs Proceed / allow flag
- No shell composition from user strings

## Tests

`tests/test_forensic_workbench.py` — input validation, plans, upload, estimate, WARNING/REJECT gates, job COMPLETE (mocked pipeline), path traversal, HTTP meta/validate, nav presence.

Existing `tests/test_forensic_ui.py` — Explorer snapshot regressions.

## Open gaps

- Full diagnose-* chain (application-flow / value forensic) not auto-run after scan yet
- Live per-stage elapsed during deep Bluetooth still coarse (checkpoint-based)
- Split-APK UX uploads multiple files then validates as multi-path; bundle directory picker not separate
- Mobile: responsive nav/buttons; large tables still horizontal-scroll

## Start

```bash
apk-forensics ui --root . --host 127.0.0.1 --port 8765
```
