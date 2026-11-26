# iAP / iAP2 SearchPlan Forensic Analysis

**Date:** 2026-11-26  
**Tool:** apk-forensics 1.6.1  
**Mechanism:** Search Plan Builder → validated SearchPlan → Resource Guard → `run_pipeline`  
**Commit baseline:** 98fd93b (+ this analysis artifact commit if any)

---

## 1. Untersuchungsziel

> Untersuche eine Android-APK auf Hinweise auf iAP / iAP2 bzw. das Apple iPod Accessory Protocol und verfolge die damit verbundenen Kommunikations-, Byte-, Buffer-, Object- und Application-Flows so weit, wie die vorhandene statische Analyse dies unterstützt.

Suchziele (Intention, **keine** vorausgesetzten Protokollfakten): iAP, iAP2, iPod Accessory Protocol, Apple accessory communication, Accessory Protocol, authentication, handshake, framing, message parsing, binary payload handling, USB, Bluetooth, RFCOMM, AccessorySocket, Socket, InputStream, OutputStream, ByteBuffer, …

---

## 2. Verwendeter SearchPlan

| Field | Value |
|---|---|
| Name | `iap2_accessory_investigation` |
| Kind | User plan (`work/user-plans/`) |
| Origin | Deterministic suggest (`iap2` topic) + manual term enrichment |
| Depth preset | `deep` |
| Correlation flag | `false` (no runtime INPUT expected) |

Artifacts:

- `work/user-plans/iap2_accessory_investigation.yaml`
- `work/user-plans/iap2_accessory_investigation.provenance.json`
- `output/iap2-searchplan/iap2_accessory_investigation.{yaml,normalized.json,provenance.json}`

### 2.1 Gewählte Traversal-Tiefe

| Parameter | Value | Why |
|---|---|---|
| `bluetooth.dataflow_depth` | 3 | Follow socket/stream hops beyond first wrapper |
| `bluetooth.max_method_hops` | 5 | Deep interprocedural object flow (schema max) |
| `bluetooth.max_field_hops` | 4 | Schema max field hops |
| `communication.max_buffer_hops` | 8 | Longer buffer chains |
| `communication.max_method_hops` | 5 | Schema max |
| `dex_context.xref_depth` | 2 | Schema max XREF depth |
| `correlation.enabled` | false | No runtime session available |

SearchPlan limits ≠ Resource Policy. Caps prevent unbounded call-graph search.

---

## 3. plan_sha256

```
0da3732baf5e3e1108081a360ce88054ed581ceedf487d2c873ea6fe2eb4071b
```

---

## 4. APK / SHA256

| Field | Value |
|---|---|
| File | `artifacts/de.bmw.connected-6.0.0.4962.apk` |
| Package | `de.bmw.connected` |
| Version | 6.0.0.4962 |
| SHA256 | `b1135e357b62a1f54b3b791609684cb54a184fa29c0e65a3f80e58ee22f496bd` |

---

## 5. Resource Preflight

| Item | Value |
|---|---|
| Policy | `standard` |
| Estimated runtime | ~11:06 (666 s) **HEURISTIC** |
| Estimated memory | 1779 MiB **HEURISTIC** |
| Guard | **WARNING** (mem ≥ 1024 MiB warn; runtime ≥ 300 s warn) |
| Proceed | Explicit `--allow-resource-warning` |
| Actual runtime | 317.8 s |
| Actual peak RSS | 1169 MiB |

`conservative` would have been **REJECT** (not overridden).

Source: `output/iap2-searchplan/RESOURCE_PREFLIGHT.json`

---

## 6. Tatsächlich ausgeführte Module

Base pipeline (`run_pipeline`) with plan modules:

- inventory / manifest / dex / strings / uuid / candidate / native
- dex_context / xref (partial: contexts=0, xref_candidates=9; androguard full XREF graph limitation warning)
- bluetooth (+ callers/streams/read-write/interprocedural)
- evidence_graph
- communication

**NOT AUTOMATIC in this Workbench base scan:**

- diagnose-application-flow / structured value catalog
- V001 deep forensic closure
- offline runtime/wire correlation ingest

Analysis status: **partial** (warnings present; shallow findings capped/report volume high).

---

## 7. Search Hits

Exact `matched_text` counts (STATIC SEARCH HIT / engine classifies string presence as FACT = “string exists”, **not** protocol identity):

| Term | Exact hits | Notes |
|---|---|---|
| **iAP2** | **0** | No APK string/API hit |
| **iAP** | **1** | Native binary substring in `libRoadLineRebuildAPI.so` (armeabi-v7a); context is non-semantic binary noise → **STATIC SEARCH HIT only**, not protocol proof |
| iPod | 0 (exact) | — |
| EASession | 0 | — |
| Accessory Protocol | 0 | — |
| Apple Accessory | 0 | — |
| AccessorySocket | 14 | DEX strings/APIs — BMW accessory stack |
| UsbAccessory | 6 | DEX |
| BluetoothSocket | 2 | DEX |
| ByteBuffer | 15 | DEX |
| handshake | 13 | DEX (name tokens only) |
| authenticate | 19 | DEX (name tokens only) |

Generic terms (`frame`, `message`, `buffer`, …) produce many low-value native/DEX hits and must not be read as framing-protocol FACT.

---

## 8. Bluetooth / USB / Socket Evidence

| Item | Result | Class |
|---|---|---|
| RFCOMM targets | 4 | FACT (inventory) |
| Bluetooth paths | 4 | FACT/INFERENCE per path |
| Evidence paths | 13 | matches prior BMW baseline |
| Strongest path | PATH-000001 `COMBINED_COMMUNICATION_PATH` | INFERENCE / medium |
| Target example | `BtAccessorySocket.connectAccessory()` | FACT method identity |
| Caller example | `LegacyBtHandler.doBclHandshake` → `openAccessorySocket` → `connectAccessory` | FACT call edges; **protocol semantics UNKNOWN** (name ≠ meaning) |
| UsbAccessory / AccessorySocket | string/API presence | FACT search hits |

**No path is labeled iAP/iAP2.** Accessory stack evidence is the known BMW Connected transport surface, not Apple iAP2 proof.

---

## 9. Communication Paths

| Item | Result |
|---|---|
| Communication paths | 4 |
| Strongest | PATH-COMM-000001 OUTBOUND_BUFFER_WRITE | INFERENCE |
| PATH-COMM-000002 | INBOUND_DECODE `BtAccessorySocket.read([BII)I` | INFERENCE |
| PATH-COMM-000003 | OUTBOUND write | INFERENCE |
| PATH-COMM-000004 | INBOUND read | INFERENCE |
| protocol_semantics | UNKNOWN on all |
| runtime_execution_proven | false |
| wire_correlation_available | false |

These are **static communication evidence paths**, not proof that bytes are iAP2.

---

## 10. Buffer / Byte Evidence

| Item | Result |
|---|---|
| Socket transfers | 91 |
| Stream transfers | 287 |
| InputStream consumers | 3 |
| OutputStream producers | 3 |
| Comm byte_processing counter | 0 (in this communication summary) |
| ByteBuffer string hits | 15 |

Byte/buffer flows are **PARTIAL**: transport read/write to `byte[]`/`OutputStream` is visible; deep buffer→parser→message closure beyond base communication module is limited in this run.

---

## 11. Decoder / Encoder Evidence

| Item | This SearchPlan base scan | Prior BMW diagnose-* baseline |
|---|---|---|
| communication `decoder_candidates` | 0 | — |
| Prior structured decoder candidates | — | 20 |
| Prior encoder candidates | — | 18 |

**FACT:** Base scan did not emit decoder/encoder candidate lists comparable to the prior offline diagnose pipeline.

**LIMITATION:** Structured decoder/encoder / VALUE catalog requires extended post-processing (**NOT AUTOMATIC**).

Prior VALUE-V001 (`Info.decodeVersion`) remains a separate static FACT from earlier forensic work — **not re-derived or linked to iAP2 by this plan**.

---

## 12. Structured Values

| Item | Result |
|---|---|
| Structured values in this scan output | **Not produced** (base pipeline) |
| Prior BMW catalog | 24 structured values |

---

## 13. Application Flow

**NOT AUTOMATIC** in this run. No new APPLICATION_FLOW report generated by the SearchPlan job.

Prior BMW application-flow / V001 forward flow remains the reference for accessory→BCL packet decode — still **protocol semantics UNKNOWN** w.r.t. iAP2.

---

## 14. Evidence Graph

| Item | Result |
|---|---|
| Evidence paths | 13 |
| Canonical nodes | 191 |
| Raw nodes / edges | 414 / 297 |
| Strongest | PATH-000001 INFERENCE |
| protocol_semantics | UNKNOWN |
| runtime_execution | UNKNOWN |

Consistent with prior BMW Connected transport/evidence-graph baseline (4 RFCOMM targets, 13 evidence paths).

---

## 15. Runtime Evidence

**INPUT_MISSING** — no instrumented APK session for this job.

---

## 16. Wire Evidence

Existing LAB_B3 capture remains **separate wire evidence** (available in workspace history) and was **not** joined as same-session to this static run.

For this job: Wire correlation **NOT_EXECUTED**.

---

## 17. Runtime/Wire Correlation

| Item | Status |
|---|---|
| Same session | UNKNOWN / not established |
| Correlation | NOT_EXECUTED |
| FULL_CHAIN | false |
| SESSION_MISMATCH | not applicable (no runtime session id) |

---

## 18. iAP / iAP2 Assessment

| Question | Answer | Basis |
|---|---|---|
| A. Static indicators for iAP/iAP2? | **NO** for iAP2 string/API; **WEAK HIT** for literal `iAP` in one native .so (non-semantic context) → overall **NO meaningful iAP/iAP2 indicator** beyond noise | Search hits |
| B. Static communication path? | **YES** | Accessory/BT paths (BMW stack) — **not iAP2-attributed** |
| C. Byte/buffer flows? | **PARTIAL** | read/write↔byte[] visible; deep parser chain limited here |
| D. Decoder/Encoder? | **PARTIAL / UNKNOWN in this run** | 0 comm decoder candidates; prior diagnose had candidates **unrelated to iAP2 proof** |
| E. Protocol semantics proven? | **NO / UNKNOWN** | All path `protocol_semantics=UNKNOWN` |
| F. Runtime evidence? | **INPUT_MISSING** | — |
| G. Wire evidence? | **YES (external LAB_B3 exists)** but **not used** in this job join | Separate artefact |
| H. Runtime ↔ Wire correlated? | **NOT_EXECUTED** | — |
| I. iAP2 proven as used protocol? | **NO** | No static chain binds accessory/BCL flows to iAP2; no iAP2 string; native `iAP` substring is not protocol evidence |

### Verdict (short)

**iAP2 as implemented/used protocol: NOT_PROVEN (effectively NO on current static evidence).**

What the new SearchPlan *did* enable:

```text
Investigation goal
  → deterministic + enriched SearchPlan (sha256 0da3732b…)
  → reproducible WARNING-approved scan
  → search hits + transport/communication evidence
  → forensic separation: SEARCH HIT ≠ PROTOCOL FACT
```

It did **not** only “grep iAP2”; it also re-ran the full Bluetooth/communication/evidence-graph stack under an iAP2-themed contract and showed that the BMW accessory communication surface is present **without** iAP2 identification.

---

## Comparison with prior BMW Connected evidence

| Metric | Prior baseline | This iAP2 plan scan |
|---|---|---|
| RFCOMM targets | 4 | 4 |
| Evidence paths | 13 | 13 |
| Communication paths | 12 (cross-apk table) / prior flow | 4 (this communication module summary) |
| Structured values | 24 | not produced (NOT AUTOMATIC) |
| Decoder / encoder candidates | 20 / 18 | 0 / 0 in comm summary |
| iAP2 string | not a prior FACT | **0 hits** |
| AccessorySocket | known | re-confirmed search hits |

**Additionally found by thematic plan:** explicit negative/positive search accounting for iAP2/iAP/EASession/…; documentation that accessory paths are **not** iAP2-labeled.

**Not found / not repeated here:** structured-value catalog & V001 deep closure (requires diagnose-* chain).

Existing findings were **not overwritten**; this is a separate output tree under `output/iap2-searchplan/scan/`.

---

## Provenance

| Field | Value |
|---|---|
| Investigation Goal | see §1 |
| plan_sha256 | `0da3732baf5e3e11…eb4071b` |
| created_by | plan_builder + manual enrichment |
| base_plan | none (new user plan from suggest) |
| Resource Policy | standard + allow warning |
| Analyzer | 1.6.1 |

---

## Method note

String hit classification FACT means **the bytes/string exist in the APK**.  
It does **not** mean **iAP2 IMPLEMENTED**.
