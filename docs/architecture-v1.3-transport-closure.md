# Architecture — v1.3 Transport-to-Byte Evidence Closure

## Purpose

After v1.2 corrected field/alias hop accounting (`max_field_hops` stays **2**), v1.3 asks:

> How far does static evidence close from Bluetooth transport to concrete bytes — and where exactly does it stop?

Not: more graph reach. Not: protocol reconstruction from names.

## Stages (each edge classified)

```
T0 Socket → T1 Stream → T2 read/write → T3 Buffer → T4 Consumer/Producer
  → T5 Decoder/Encoder candidate → T6 Communication Evidence
```

Protocol semantics remain **UNKNOWN** unless a future version has direct static proof (not method names).

## FACT / CORRELATION / INFERENCE / UNKNOWN

- **FACT**: DEX instruction, field, return/parameter, `read([B)` buffer register
- **CORRELATION**: independent FACTs joined (stream object ↔ PATH-COMM source method)
- **INFERENCE**: end-to-end path composition; primitive-decode *candidate*
- **UNKNOWN**: wire meaning, peer/HU, runtime session, BMW protocol claims
- **REJECTED**: merge-by-type / name-as-protocol

## Offline workflow

1. Freeze v1.2 baseline (`output/v13-baseline/`) — do not overwrite
2. `apk-forensics diagnose-transport-closure --from-report … --output …`
3. Reports: `TRANSPORT_EVIDENCE_CLOSURE_REPORT`, `OBJECT_IDENTITY_COVERAGE_REPORT`, `BUFFER_DATAFLOW_REPORT`, `PATH_TERMINATION_ANALYSIS`

## Limits

Do **not** raise `max_field_hops` / `max_method_hops` / `max_object_nodes` / `dataflow_depth` unless a reproducible proof shows a limit cuts real evidence (with before/after coverage, evidence, runtime, RSS).

## Coverage vs Evidence

Coverage = how far the analyzer walked. Evidence = what the found data proves. Never interchange them.
