# Changelog

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
