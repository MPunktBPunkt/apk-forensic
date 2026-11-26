# Forensic Analysis UI / Workbench

Local UI for apk-forensics:

1. **Forensic Explorer** — read-only visualization of `analysis_ui_snapshot.v1`
2. **New Analysis Workbench** — orchestrates the *existing* analyzer (scan / estimate / SearchPlan / Resource Guard)

```text
APK / path
   ↓
Workbench Job API  (stdlib HTTP)
   ↓
create_analysis_job → Resource Guard → run_pipeline
   ↓
report.json / report.md
   ↓
ui-snapshot (existing aggregator)
   ↓
Forensic Explorer
```

The UI does **not** invent evidence, XREFs, protocol semantics, or resource estimates.

## Important scope

| Capability | Status |
|---|---|
| Static APK analysis | Supported (orchestrates CLI/pipeline) |
| APK execution | **Not supported / not claimed** |
| Runtime instrumentation | Separate workflow (`INPUT_MISSING` until real evidence) |
| Evidence classes | Unchanged (`FACT` / `INFERENCE` / …) |

SearchPlan limits ≠ Resource Policy limits — shown as separate UI sections.

## Architecture

| Piece | Role |
|---|---|
| `apk_forensics.ui.snapshot` | Deterministic report → snapshot aggregator |
| `apk_forensics.ui.workbench` | Upload workspace, plan catalog, estimate, job runner |
| `apk_forensics.ui.server` | stdlib `ThreadingHTTPServer` + JSON APIs |
| `apk_forensics/ui/static/*` | SPA (Explorer + Workbench) |
| CLI `ui-snapshot` / `ui` | Build snapshot / serve UI |

No Flask/FastAPI. No cloud. No external API. No LLM.

## Data sources (Explorer)

Snapshots from existing reports (`CASE_PRESETS` or job output). Counters and classifications come from reports only.

## Workbench APIs

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/snapshot` | Current Explorer snapshot |
| GET | `/api/meta` | Plans, policies, bind warning |
| GET | `/api/plans` | Bundled `plans/*.yaml` only |
| GET | `/api/plans/{id}/criteria` | Grouped SearchPlan criteria |
| POST | `/api/upload` | APK upload → `work/ui-uploads/` |
| POST | `/api/validate` | Server-side path fingerprint |
| POST | `/api/estimate` | Existing Resource Estimator + Guard decision |
| POST | `/api/jobs/start` | Start background analysis job |
| GET | `/api/jobs/{id}/status` | Progress / logs / results |
| POST | `/api/jobs/{id}/cancel` | Cooperative cancel |
| GET | `/api/result?path=` | Read file **only** under uploads/jobs workspace |

Jobs persist `output/ui-jobs/<stamp>-<id>/workbench_job.json` (`apk_forensics.workbench_job.v1`).

## UI pages

Overview · **New Analysis** · **Analysis Job** · Analysis Path · Values · Open Edges · Runtime/Wire · What we know · Timeline · Sources

## Security

- Default bind `127.0.0.1`
- Explicit warning when bound to `0.0.0.0`
- Upload names sanitized; no path traversal
- Result download restricted to workbench workspace roots
- Resource `REJECT` cannot be overridden; `WARNING` needs explicit Proceed
- Only validated bundled SearchPlans accepted

## Start

```bash
# Explorer only (optional snapshot)
apk-forensics ui --snapshot output/ui/analysis_ui_snapshot.bmw-connected.json --root .

# Workbench + Explorer (default)
apk-forensics ui --root . --host 127.0.0.1 --port 8765

# Read-only Explorer (no job APIs)
apk-forensics ui --snapshot PATH --no-workbench
```

Open `http://127.0.0.1:8765/` — use **New Analysis** to upload or enter a **server-side** APK path.

## Extension points

- Add YAML under `plans/` (automatically listed)
- Do not embed analyzer logic in `app.js`
- Diagnose-* chains after scan can be added as optional post-steps later
