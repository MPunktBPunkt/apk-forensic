# apk-forensics

Local, static APK forensics toolkit (v0.7.0).

It turns Android APKs into reproducible static fingerprints: hashes, ZIP inventory, manifest metadata (when available), DEX/native inventories, readable strings, UUID/port/API candidates, optional profile correlations, optional DEX context / Bluetooth RFCOMM path analysis with **bounded caller & stream dataflow reconstruction**, **ArtifactBundles**, controlled **workspace storage lifecycle**, a declarative **SearchPlan** layer, and an **AnalysisJob + Resource Guard** for deterministic preflight budgeting.

## Purpose

- Analyze APK files **as files** on Debian/Linux
- Produce machine-readable and human-readable evidence reports
- Keep domain knowledge (e.g. BMW Connected vocabulary) in **external profiles**
- Stay generic so the same core can scan any APK
- Manage analysis artifacts without uncontrolled disk growth
- Accept the same declarative analysis request from multiple frontends

## Ownership principle

> APK-Forensics verwaltet Analyseartefakte, übernimmt aber nicht automatisch das Eigentum an vom Benutzer bereitgestellten Originaldateien.

User-provided original APKs are never auto-deleted. Cleanup only touches paths the tool clearly manages (`work/`, `cache/`, and optionally `output/`).

## Non-goals

- No APK install/execution
- No network access
- No signature bypass / decryption
- No credential or secret hunting
- No full DEX decompilation or unbounded call graph
- No native disassembly or JNI correlation
- No protocol reconstruction or wire-capture correlation
- No automatic vehicle/head-unit identification
- No automatic deletion of original APKs
- No cloud storage
- No LLM / autonomous agent / GUI
- No silent SearchPlan rewriting by the Resource Guard

## Architecture

```text
SearchPlan
    │
    ▼
Validator
    │
    ▼
Resource Estimator
    │
    ├── REJECT ──────► Job rejected (no pipeline)
    │
    ├── WARNING ─────► needs --allow-resource-warning
    │
    └── OK
          │
          ▼
      Analysis Job
          │
          ▼
       Pipeline → Evidence → Report
```

SearchPlan limits = fachliche Ergebnisbegrenzung.  
Resource limits = System-/Laufzeitbegrenzung. Nicht vermischen.

> Ein SearchPlan beschreibt eine Untersuchung. Er ist keine Ergebnisdatei und darf keine Evidenz oder Schlussfolgerungen vortäuschen.

BMW-/Connected-specific knowledge must live only under `profiles/`, never in the core scanners.

## Security model

1. APK is opened read-only (in place; not copied unless explicitly requested)
2. No install, no execution, no shelling out to external RE tools
3. No network connections
4. Zip-slip paths are detected and marked
5. Large entries are size-bounded
6. Cleanup is dry-run by default, workspace-bounded, symlink-safe
7. Original sources are never owned/deleted automatically

## Installation

Python 3.11+ required.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Optional parsers:

```bash
pip install -e ".[android,elf]"
# or
pip install -e ".[all]"
```

## CLI

### 1. Single APK

```bash
apk-forensics scan ./app.apk --output ./output/app
```

With SearchPlan:

```bash
apk-forensics scan ./app.apk \
  --plan plans/bluetooth_rfcomm.yaml \
  --output ./output/app-bt
```

External path (no copy into the repo):

```bash
apk-forensics scan /data/apks/myapp.apk --output ./output/myapp
```

### SearchPlan

Declarative YAML (`schemas/search_plan.schema.json`). Pipeline:

```text
YAML → validate → normalize → plan_sha256 → engine → report
```

```bash
apk-forensics plan validate plans/bluetooth_rfcomm.yaml
apk-forensics plan show plans/bluetooth_rfcomm.yaml --json
```

Supported modules: `manifest`, `zip_inventory`, `dex`, `strings`, `uuid`, `candidate`, `bluetooth`, `dex_context`, `xref`, `native`.

Search supports literal `terms`, explicit `regex`, normalized `uuids`, and generic `api_patterns`. Terms are never auto-promoted to regex.

Example plans: `plans/bluetooth_rfcomm.yaml`, `plans/native_static.yaml`, `plans/communication_stack.yaml`.

Reproducibility identity: input SHA-256 + engine version + `plan_sha256` + profile + relevant options.

### Analysis Job + Resource Guard

```bash
apk-forensics plan estimate ./app.apk --plan plans/bluetooth_rfcomm.yaml
apk-forensics estimate ./app.apk --plan plans/bluetooth_rfcomm.yaml --json
```

Policies: `conservative` | `standard` (default) | `unlimited`  
(`unlimited` = guard does not bound that axis; OS OOM remains an error.)

```bash
apk-forensics scan ./app.apk \
  --plan plans/bluetooth_rfcomm.yaml \
  --resource-policy standard \
  --allow-resource-warning \
  --output ./output/app
```

- `OK` → start  
- `WARNING` → blocked unless `--allow-resource-warning`  
- `REJECT` → never started (no override)  

The guard **never** silently lowers `xref_depth`, disables modules, or rewrites the plan.

### Bluetooth RFCOMM Dataflow (v0.7)

Extends path analysis with bounded reconstruction — not a full call graph:

```text
RFCOMM Target
     │
     ├───────────────► Caller Reconstruction (depth ≤ 2)
     │
     ▼
BluetoothSocket
     │
     ├───────────────► connect()
     │
     ├───────────────► InputStream
     │                      │
     │                      ▼
     │                    read()
     │                      │
     │                      ▼
     │                    Consumer (or UNKNOWN)
     │
     └───────────────► OutputStream
                            │
                            ▼
                          write()
                            │
                            ▼
                          Producer (or UNKNOWN)
```

SearchPlan bluetooth knobs (all hard-capped):

- `caller_depth` (0–2), `dataflow_depth` (0–3)
- `reconstruct_callers` / `reconstruct_streams` / `reconstruct_read_write`
- `max_callers` / `max_callees` ≤ 100
- `max_dataflow_paths` ≤ 100, `max_dataflow_nodes` ≤ 500

Evidence rules:

- Exact DEX invoke / register-linked socket I/O → **FACT**
- Same-method window co-occurrence or name heuristics → **INFERENCE** / `METHOD_NAME_CANDIDATE`
- Missing consumer/producer → **UNKNOWN** (never REJECTED)
- End-to-end RFCOMM path stays **INFERENCE**; `runtime_execution_proven: false` unless runtime evidence exists
- Profile tokens (SCN6, BCL, Etch, …) remain **CORRELATION** only — never APK FACT

### 2. Artifact Bundle (base + splits)

```bash
apk-forensics scan ./base.apk \
  --split ./config.arm64_v8a.apk \
  --output ./output/app-bundle
```

Or a directory of related APKs:

```bash
apk-forensics scan --bundle ./artifacts/myapp-splits/ --output ./output/myapp-bundle
```

Bundle correlation uses package name + version code (+ version name when present). Filename hints alone never establish FACT membership. Insufficient evidence → `UNKNOWN` (no invented merge).

### 3. Base / Split provenance

Physical files stay distinct. Findings carry:

- `source.artifact` — APK file name
- `source.artifact_sha256` — input identity
- `source.entry` / `source.offset` — location inside that APK

Example: a native `.so` from `config.arm64_v8a.apk` is never attributed to the base APK inventory.

### 4. Workspace structure

```text
workspace/
├── artifacts/           # user-provided (never auto-deleted)
│   └── source/          # optional managed copies (explicit only)
├── work/                # temporary sessions (auto-cleaned after scan)
├── output/              # reports (kept; optional clean)
├── cache/               # optional bounded cache
└── .apk-forensics-workspace.json
```

### 5. Temporary files

Scan creates a managed `work/<session>/` directory. After a successful or failed scan it is deleted unless:

```bash
apk-forensics scan ./app.apk --output ./output/app --keep-work
```

Default: `keep_work = false`.

### 6. Cleanup

Dry-run by default:

```bash
apk-forensics clean --dry-run
```

Actually delete work/cache:

```bash
apk-forensics clean --execute
```

Include reports:

```bash
apk-forensics clean --execute --output
```

### 7. Dry-run

```text
Would remove:
  work/...
  cache/...

Would keep:
  artifacts/ (user-provided; never auto-deleted)
  output/ (reports kept unless --output)
```

### 8. Storage report

```bash
apk-forensics storage
```

Shows sizes for source artifacts, work, cache, reports (managed workspace only).

### 9. Retention

```bash
apk-forensics clean --execute --older-than 30d
```

Only managed areas; sources never deleted; combine with `--dry-run` first.

### 10. Safety rules

- Only known workspace areas (`work/`, `cache/`, optional `output/`)
- No recursive delete outside the workspace
- Symlinks are not followed/removed as escape hatches
- Managed markers (`.apk-forensics-managed.json`) for work sessions
- Uncertain ownership → do not delete

## Optional deep analysis (v0.2 / v0.3)

```bash
apk-forensics scan ./app.apk \
  --output ./output/app-deep \
  --profile bmw_connected \
  --dex-context \
  --bluetooth-path \
  --xref-depth 1
```

See CHANGELOG for DEX context and Bluetooth RFCOMM path details. Claims remain static-only.

## Optional cache

```bash
apk-forensics scan ./app.apk --output ./output/app --use-cache
```

Cache key = input SHA-256 + tool version + schema version + relevant options. Stale entries are never silently reused. Default: off.

## Profiles

Profiles are YAML candidate vocabularies under `profiles/`. Matches are `CORRELATION` only.

## Classification meanings

- `FACT`: directly observed evidence
- `CORRELATION`: linked to profile knowledge or another finding
- `INFERENCE`: cautious technical interpretation
- `UNKNOWN`: hints present, meaning unclear
- `REJECTED`: discarded candidate (debug only by default)

## Output / reproducibility

Reports always include at least:

- input SHA-256
- input filename / path
- package / version (when available)
- analysis tool version
- schema version
- profile (if used)
- timestamp
- artifact identity (SHA-256)

If the original file is later removed, SHA-256 still identifies what was analyzed.

- Single scan: `report.json` / `report.md`
- Bundle: `bundle.json` / `bundle.md` plus per-member reports under `members/`

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success |
| 1 | warnings / partial |
| 2 | invalid CLI args |
| 3 | input missing/unreadable |
| 4 | not a valid APK/ZIP |
| 5 | fatal analysis error |

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Real APK artifacts

Place real APKs under `artifacts/` (gitignored). Example MyBMW bundle:

```bash
apk-forensics scan \
  ./artifacts/de.bmw.connected.mobile20.row.apk \
  --split ./artifacts/config.arm64_v8a.apk \
  --output ./output/mybmw-v04 \
  --profile bmw_connected
```

Expected provenance (regression):

- Base: 4 DEX, 0 native `.so`
- `config.arm64_v8a`: 0 DEX, 23 native `.so`
