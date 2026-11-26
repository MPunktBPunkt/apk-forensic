# apk-forensics

**Local static APK forensics — evidence first, no guessing.**

Turn Android APKs into reproducible fingerprints and bounded dataflow evidence: hashes, inventories, strings, Bluetooth/transport paths, communication graphs, and offline closure reports. Runs entirely on your machine. No install, no execution, no network.

```text
APK  →  SearchPlan  →  Resource Guard  →  Pipeline  →  Evidence Report
```

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.6.1-informational.svg)](CHANGELOG.md)

---

## Why this exists

Reverse-engineering APKs often mixes **what the binary contains** with **what we wish it meant**. apk-forensics keeps those apart:

| Classification | Meaning |
|---|---|
| **FACT** | Directly observed in the APK |
| **CORRELATION** | Linked to a profile or another finding |
| **INFERENCE** | Cautious chained interpretation |
| **UNKNOWN** | Hints present, meaning unclear |
| **REJECTED** | Discarded candidate |

Protocol names in method strings (`BCL`, `Etch`, `SAS`, …) are **labels**, not proof. Domain vocabularies live in optional `profiles/` — never hard-wired into the core scanners.

---

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

apk-forensics scan ./app.apk --output ./output/app
```

Optional parsers:

```bash
pip install -e ".[android,elf]"   # androguard + pyelftools
# or
pip install -e ".[all]"
```

---

## What you get

- **Static inventory** — ZIP, manifest, DEX, native libs, strings, UUIDs, API candidates  
- **SearchPlan** — declarative YAML investigation contract (`plan_sha256` for reproducibility)  
- **Resource Guard** — estimate before deep work (`OK` / `WARNING` / `REJECT`)  
- **Bluetooth / transport paths** — RFCOMM → streams → bounded object-flow → evidence graph  
- **Communication evidence** — bytes/buffers → decoder/encoder candidates → `PATH-COMM-*`  
- **Offline diagnose-\*** — transport closure, buffer semantics, application-flow, runtime/wire correlation  
- **UI / Workbench** — local explorer + Search Plan Builder + job orchestration  
- **Workspace hygiene** — managed `work/` / `cache/`; your original APKs are never auto-deleted  

---

## Core workflow

```bash
# 1. Validate & estimate (no deep analysis)
apk-forensics plan validate plans/bluetooth_rfcomm.yaml
apk-forensics estimate ./app.apk --plan plans/bluetooth_rfcomm.yaml --json

# 2. Scan with SearchPlan
apk-forensics scan ./app.apk \
  --plan plans/bluetooth_rfcomm.yaml \
  --resource-policy standard \
  --output ./output/app-bt

# 3. Optional: communication layer on a persisted transport report
apk-forensics postprocess-communication \
  --from-report ./output/app-bt/report.json \
  --apk ./app.apk \
  --plan plans/communication_evidence.yaml \
  --output ./output/app-comm
```

**Resource Guard**

| Decision | Behaviour |
|---|---|
| `OK` | Analysis starts |
| `WARNING` | Needs `--allow-resource-warning` |
| `REJECT` | Never starts — no override |

The guard never silently lowers hops, disables modules, or rewrites your SearchPlan.

---

## Architecture at a glance

```text
                    ┌─────────────┐
                    │ SearchPlan  │  (what / how deep)
                    └──────┬──────┘
                           ▼
                    ┌─────────────┐
                    │  Estimator  │
                    │ + Resource  │  (how much CPU/RAM/time)
                    │    Guard    │
                    └──────┬──────┘
              REJECT / WARNING / OK
                           ▼
                    ┌─────────────┐
                    │  Pipeline   │  scan → evidence → report
                    └──────┬──────┘
                           ▼
              ┌────────────┴────────────┐
              ▼                         ▼
     Transport Evidence          Communication Evidence
     (socket → stream → IO)      (bytes → buffer → message)
              │                         │
              └────────────┬────────────┘
                           ▼
                  diagnose-* closures
            (T0–T6 · S0–S4 · VALUE-V### · wire)
```

SearchPlan limits ≠ Resource limits. Keep them separate.

---

## CLI map

| Command | Purpose |
|---|---|
| `scan` | Full static analysis of an APK or ArtifactBundle |
| `plan` / `estimate` | Validate plans · preflight resource estimate |
| `postprocess-communication` | Communication graph on an existing transport report |
| `diagnose-transport-closure` | T0–T6 transport→byte closure |
| `diagnose-buffer-semantics` | Buffer/T5 audit · optional interface / Etch seed expand |
| `diagnose-application-flow` | Structured `VALUE-V###` lineage |
| `diagnose-field-coverage` | Field/alias hop accounting |
| `diagnose-runtime-correlation` | Static ↔ runtime/wire join (optional inputs) |
| `calibrate` | Estimate-vs-actual + path coverage |
| `ui` / `ui-snapshot` | Local Forensic UI + Workbench |
| `storage` / `clean` | Workspace usage · safe cleanup |

```bash
apk-forensics --help
apk-forensics ui --help
```

Official plans live under `plans/`. Schema: `schemas/search_plan.schema.json`.

---

## Evidence discipline

```text
FACT          observed invoke / field / buffer op
INFERENCE     multi-step path as a whole
CORRELATION   profile vocabulary match
UNKNOWN       unresolved boundary (JNI, dynamic dispatch, …)
REJECTED      discarded candidate
```

**Non-goals:** no APK execution, no network, no secret hunting, no unbounded decompilation, no protocol reconstruction, no silent plan rewriting, no cloud, no automatic deletion of your originals.

> APK-Forensics manages analysis artefacts — it does not take ownership of user-provided APKs.

---

## Bundles, workspace, cleanup

```bash
# Base + splits
apk-forensics scan ./base.apk --split ./config.arm64_v8a.apk -o ./output/bundle

# Storage & cleanup (dry-run by default)
apk-forensics storage
apk-forensics clean --dry-run
apk-forensics clean --execute                  # work/ + cache/ only
apk-forensics clean --execute --output         # also reports
```

```text
workspace/
├── artifacts/     # yours — never auto-deleted
├── work/          # session temps
├── output/        # reports
├── cache/
└── .apk-forensics-workspace.json
```

---

## Local UI

```bash
apk-forensics ui
# Explorer + Workbench + Search Plan Builder (local only)
```

Build a snapshot from existing reports without re-scanning:

```bash
apk-forensics ui-snapshot --case bmw-connected -o ./output/ui
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

---

## Real APKs

Place samples under `artifacts/` (gitignored). Reports under `output/` — large scan dumps stay local; selected forensic write-ups may be tracked.

---

## Versioning

See **[CHANGELOG.md](CHANGELOG.md)** for the full lineage (v0.x → v1.6.1): communication graph, resource calibration, transport/buffer/application-flow closures, and static↔runtime/wire correlation.

---

## License

MIT — see [LICENSE](LICENSE).
