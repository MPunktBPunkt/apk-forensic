# Architecture — Communication Evidence Graph (v1.0)

## Layering

```text
v0.8 Raw Analysis Graph  ──persist──►  v0.9 Transport Evidence Graph
                                              │
                                              ▼
                                   v1.0 Communication Dataflow
                                              │
                                              ▼
                                   Communication Evidence Graph
                                   (PATH-COMM-*)
```

Prefer **offline postprocessing** (`apk-forensics postprocess-communication`) when a
persisted transport report already exists. Live scans with
`plans/communication_evidence.yaml` re-run transport then attach the communication layer.

## Provenance fields (required for offline)

| Field | Meaning |
|---|---|
| `source_dataset` | Input APK path / file name from source report |
| `source_engine_version` | Engine that produced the transport report |
| `source_plan_sha256` | SearchPlan hash of the source run |
| `source_artifact_sha256` | APK content hash |
| `postprocessing_version` | Engine version that built communication evidence |
| `mode` | `live_post_transport` or `offline_postprocess` |

## What is FACT vs INFERENCE vs UNKNOWN

| Claim | Class |
|---|---|
| `InputStream.read([B)` observed | FACT |
| `byte[]` register written by read | FACT |
| Method name contains `decode` / `Bcl` | FACT (name evidence only) |
| Buffer flows into named decode method | CORRELATION / INFERENCE (role) |
| End-to-end read→decode→Message path | INFERENCE |
| Wire protocol = BCL / Etch / RHMI / SCN6 | UNKNOWN (never from names) |
| Runtime execution / peer / actual bytes | UNKNOWN |

## Boundaries

Gaps are explicit: `UNKNOWN_HELPER`, `NATIVE`, `REFLECTION`, hop caps
(`max_buffer_hops`, `max_parser_hops`, `max_message_hops`, `max_method_hops`).
No silent end-to-end invention across unresolved helpers.

## Resource Guard

Communication factors feed the estimator (`communication`, buffer hops, path caps).
Decisions remain `OK` / `WARNING` / `REJECT`. The guard never rewrites the SearchPlan.

## Hard bans (unchanged)

No APK execution, network, Frida, secret recovery, signature bypass, global unbounded
call-graph, or automatic protocol identity from method/type names.
