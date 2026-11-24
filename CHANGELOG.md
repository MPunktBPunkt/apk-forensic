# Changelog

## 1.0.0

- **Communication Evidence Graph**: bounded static dataflow above Bluetooth transport
  (`InputStream`/`OutputStream` → `byte[]`/`ByteBuffer` → decoder/encoder → message/object)
- New SearchPlan section `communication:` + official plan `plans/communication_evidence.yaml`
- CLI: `--communication`, `postprocess-communication` (offline on persisted transport reports)
- Evidence separation: `method_name_candidate=FACT`, `dataflow_role=INFERENCE`, `protocol_semantics=UNKNOWN`
- Compact `PATH-COMM-*` paths with direction `INBOUND`/`OUTBOUND`, provenance, boundaries
- Resource Guard estimates communication buffer/parser work — no silent plan rewrite
- Transport Evidence Graph classifications are never rewritten by the communication layer
- Synthetic fixtures A–G + negative protocol-name tests
- Architecture note: expensive transport analysis → persist → cheap communication postprocess

## 0.9.0

- **Evidence Graph**: Raw object/dataflow → canonical objects/nodes/edges → compact `PATH-*` evidence paths
- Deterministic object IDs (`socket:S*`, `input:I*`, `output:O*`) with provenance back to raw evidence
- Exact UNKNOWN **boundaries** (`return_no_move_result`, hop/node caps, cycles, unresolved parameter/field, …)
- Deduplication of duplicate field/call/stream transfers without dropping raw provenance
- Ranking for review order only — never changes FACT/INFERENCE/UNKNOWN
- Method names never imply protocol semantics (`doBclHandshake` ≠ BCL)
- Cross-version evidence scaffold (`ADDED`/`REMOVED`/`UNCHANGED`/`CHANGED` fingerprints)
- SearchPlan `evidence_graph` (default disabled; official `bluetooth_rfcomm` enables it)
- Resource estimator accounts for evidence-graph work without silent plan rewrite
- Report: executive summary + evidence paths + boundaries; raw vs canonical counts separated

## 0.8.0

- **Cross-method Bluetooth object-flow**: bounded return / parameter / field / constructor tracking for `BluetoothSocket`, `InputStream`, `OutputStream`
- Stream wrappers (`Buffered*` / `Data*`) with object-linked read/write detection
- Cycle detection + hard caps: `max_method_hops`, `max_field_hops`, `max_object_nodes`
- Caller reduction: direct / depth_1 / depth_2 / duplicate / truncated (+ unique chains)
- SearchPlan: `interprocedural` (default `false` for backward compatibility); official `bluetooth_rfcomm` plan enables it
- Extended `BluetoothDataflowPath` (`objects`, `edges`, `boundaries`, `input_read_chain` / `output_write_chain`, ranking)
- Resource estimator accounts for interprocedural hops/nodes without silent plan rewrite
- End-to-end path stays **INFERENCE**; unresolved boundaries are **UNKNOWN** (never REJECTED)

## 0.7.0

- **RFCOMM caller reconstruction** (bounded depth ≤ 2; multi-caller FACT via DEX invoke refs)
- **Socket object tracking** with register-linked create → connect → getInputStream/getOutputStream
- **InputStream consumer / OutputStream producer** reconstruction (read/write; missing → UNKNOWN)
- **BluetoothDataflowPath** evidence (`BTDATA-*`) with PARTIAL structure + FACT/INFERENCE/UNKNOWN stages
- SearchPlan bluetooth knobs: `caller_depth`, `reconstruct_*`, `max_callers` / `max_callees` / `max_dataflow_paths` / `max_dataflow_nodes`
- Resource estimator accounts for caller/dataflow depth and node caps (no silent plan rewrite)
- Report: `bluetooth_dataflow` section + Markdown “Bluetooth RFCOMM Dataflow”
- Targets prioritized: create+connect+streams → create+connect → create
- End-to-end path classification remains **INFERENCE**; no SCN6/BCL/Etch/runtime upgrade from names or profiles

## 0.6.0

- **AnalysisJob** layer: job_id, status machine, timestamps, termination_reason
- **ResourcePolicy** presets: `conservative` / `standard` (default) / `unlimited`
- **ResourceEstimator** deterministic preflight (ZIP metadata + plan factors; no deep analysis)
- **ResourceGuard** decisions: `OK` / `WARNING` / `REJECT` — never silently rewrites SearchPlan
- CLI: `plan estimate` / `estimate`, `--resource-policy`, `--allow-resource-warning`
- WARNING without override blocks start; REJECT is never overridden
- Runtime / finding / context / xref hard limits fail closed (no silent truncation)
- Cooperative `CancellationToken` checkpoints in the pipeline
- Reports include `analysis_job` + `resource` (estimate vs actual; null when unmeasured)
- Work session created only after successful preflight (rejected → no work dir)

## 0.5.0

- Declarative **SearchPlan** layer (`schema_version: 1.0`) — describes investigations, never findings
- YAML load → validate → normalize → `plan_sha256` → deterministic engine run
- CLI: `scan --plan`, `plan validate`, `plan show`
- JSON Schema: `schemas/search_plan.schema.json`
- Example plans: `plans/bluetooth_rfcomm.yaml`, `plans/native_static.yaml`, `plans/communication_stack.yaml`
- Search terms / explicit regex / UUID / api_patterns wired into candidate scanners with provenance tags
- Reports include `search_plan` + `analysis.plan_sha256` / `engine_version`
- Evidence classification list is a report filter only (does not reclassify)
- Rejects executable directives, arbitrary output paths, and profile path traversal
- Designed so CLI / YAML / future GUI / future AI all feed the same plan into the engine
- No LLM, GUI, or autonomous agent in this release
- Note: very large ABI-split APKs with deep `bluetooth`+`dex_context` plans may be memory-heavy; prefer scoped plans per artifact role when needed

## 0.4.0

- Generic **ArtifactBundle** model for base APK + configuration splits
- Bundle correlation via package / versionCode / versionName (filename hints are weak only; insufficient evidence → UNKNOWN)
- Unified bundle reports with per-member provenance (`source.artifact`, `source.artifact_sha256`)
- Workspace lifecycle: `artifacts/source`, `work/`, `output/`, `cache/`
- Scan analyzes external APKs in place (no automatic copy of user originals)
- `--keep-work` to retain temporary sessions; default cleans work after scan
- CLI `storage` report (sizes, file counts, largest files)
- CLI `clean` with dry-run default, `--execute`, `--output`, `--older-than`, symlink/outside-workspace protection
- Optional bounded `--use-cache` (off by default; versioned keys)
- Report schema `0.4` for bundle reports; single-APK schemas unchanged (0.1–0.3)
- Ownership principle: tool never auto-deletes user-provided original APKs

## 0.3.0

- Optional `--bluetooth-path` analysis for RFCOMM create/connect/stream paths
- Bounded UUID argument resolution (`fromString`, static fields, register moves)
- BluetoothDevice source analysis and same-method socket/I/O context
- Candidate Bluetooth paths as `INFERENCE` with explicit no-runtime / no-SCN6 limits
- Report schema `0.3` when Bluetooth path analysis is enabled

## 0.2.0

- Optional `--dex-context` analysis for method/instruction localization
- Bounded caller/callee XREF candidates (`--xref-depth` 0–2)
- Cautious same-method candidate chains
- Report schema `0.2` when DEX context is enabled; shallow scans remain schema `0.1`
- Androguard adapter with instruction-scan XREFs (no full unbounded call graph)
- Markdown/JSON report sections for DEX contexts, XREFs, and chains

## 0.1.0

- Initial shallow static APK fingerprint toolkit
