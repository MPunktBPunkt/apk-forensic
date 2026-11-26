# Forensic Analysis UI

Read-only local UI for inspecting existing apk-forensics evidence.

The UI does **not** analyze APKs, compute XREFs, invent protocol semantics, or run correlation.

```text
Analyzer / offline diagnose-*  →  JSON reports  →  ui-snapshot  →  UI
```

## Architecture

| Piece | Role |
|---|---|
| `apk_forensics.ui.snapshot` | Deterministic aggregator → `analysis_ui_snapshot.v1` |
| `apk_forensics.ui.server` | stdlib `ThreadingHTTPServer` serving static files + snapshot JSON |
| `apk_forensics/ui/static/*` | Single-page UI (HTML/CSS/JS) |
| CLI `ui-snapshot` / `ui` | Build snapshot / serve UI |

No Flask/FastAPI/React dependency. No cloud. No external API.

## Data sources

Snapshots are built from **existing** report paths (case presets):

- `bmw-connected` — v13/v14/v15/v16 value + runtime readiness + cross-apk counters
- `bimmerlink` — META + optional v15 flow
- `serial-bt` — serial v15 flow

Counters are read from reports (e.g. `CROSS_APK_EVALUATION_REPORT.json`, baseline meta, application-flow). Nothing is hard-coded as evidence.

## Evidence model in the UI

Status classes shown with **label + text mark + color**:

`FACT` `INFERENCE` `CORRELATION` `UNKNOWN` `NOT_PROVEN` `INPUT_MISSING` `REJECTED` (+ pipeline states like `COMPLETE` / `NOT_EXECUTED` / `DYNAMIC_DISPATCH`)

Open edges distinguish boundaries from negatives (`NOT_FOUND` is not used for missing runtime).

`FULL_CHAIN` is displayed only when the snapshot’s correlation graph says `full_chain_present=true` (today: false until a real same-session run exists).

## UI pages

1. Overview — APK identity, analysis status, pipeline, counters  
2. Analysis Path — VALUE-V001 (or focus) node/edge chain  
3. Values — neutral VALUE-V### catalog  
4. Open Edges — DYNAMIC_DISPATCH / NOT_PROVEN / INPUT_MISSING / …  
5. Runtime / Wire — separation + session-mismatch rule  
6. What we know — proven / not proven / missing input + next experiment  
7. Timeline — analysis milestones (no synthetic runtime clocks)  
8. Sources — referenced report paths + presence  

Detail panel on the right shows the selected node/edge/source fields.

## Start

```bash
# from repo root, with reports present under output/
apk-forensics ui-snapshot --case bmw-connected --output /tmp/ui-snap.json
apk-forensics ui --snapshot /tmp/ui-snap.json --port 8765
# open http://127.0.0.1:8765/
```

## Extension points

- Add a case preset in `CASE_PRESETS` mapping roles → report paths  
- Optionally pass richer correlation run JSON later (still read-only)  
- Do **not** embed analyzer logic in `app.js`

## Reproducibility

Same report inputs → same `content_sha256` on the snapshot (canonical JSON hash).
