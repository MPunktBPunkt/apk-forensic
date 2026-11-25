# Architecture — v1.6 Static ↔ Runtime/Wire Correlation

## Question

Does a statically reconstructed application-flow path correlate with observed runtime and/or wire behaviour?

## Layers (strictly separate)

```
APK STATIC  →  VALUE / FIELD / APPLICATION FLOW
      ↕
RUNTIME     →  method / read / write / value / event
      ↕
WIRE        →  timestamp / direction / bytes / length
```

Each layer keeps its own provenance. Joining layers yields `CORRELATION`, never automatic protocol semantics.

## Evidence types (neutral)

- Static: `STATIC_METHOD`, `STATIC_VALUE`, `STATIC_FIELD`, …
- Runtime: `RUNTIME_METHOD`, `RUNTIME_READ`, `RUNTIME_WRITE`, …
- Wire: `WIRE_PACKET`, `WIRE_BYTES`, …

No `BMW_COMMAND` / `BCL_PACKET` evidence types.

## Strength

Rule-based discrete strength: `EXACT`, `STRONG`, `MODERATE`, `WEAK`, `AMBIGUOUS`, `NONE`, `UNKNOWN`.

Insufficient alone for positive claims: length-only, method-name-only, timestamp-window-only.

## Missing input

Repo audit found no structured runtime/wire artefacts. Interface:

- `apk_forensics.runtime_evidence.v1`
- `apk_forensics.wire_evidence.v1`

Absent files → `INPUT_MISSING` / `NO_EXTERNAL_EVIDENCE`.

## Resource model

Indexed bucket lookups (method / length / time / hex) — not unbounded pairwise comparison. Caps: `max_runtime_events`, `max_wire_packets`, `max_correlations`.

## Unchanged from v1.5

Catalog 24 / stores 8 / loads 63 / params 191 / returns 5 / branches 36 / state 6 / collections 2 / roundtrip 13 / PATH-COMM 12 / `max_field_hops=2` / protocol `UNKNOWN`.
