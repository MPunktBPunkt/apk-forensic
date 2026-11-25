# Runtime Capture Report — VALUE-V001

**Final verdict:** `INPUT_MISSING`

```text
STATIC → RUNTIME          = INPUT_MISSING
RUNTIME → WIRE            = NOT_EXECUTED
VALUE-V001 → Runtime → Wire = NOT_PROVEN
```

**First unclosed edge:** `STATIC → RUNTIME`  
**Boundary:** `RUNTIME_LIMIT` / `INPUT_MISSING`  
**Causes:** `NO_DEVICE`, `NO_FRIDA`, `NO_PROCESS`, `NO_LIVE_SESSION`, `NO_INSTRUMENTATION_ACCESS`

Capture ID: `RUNTIME_CAPTURE_ATTEMPT_20261125T083913Z`  
No simulation. No LABSIM substitution. No v1.7. No correlation-engine change.

## A. Environment

| Item | Result |
|---|---|
| Git | `main` @ `8ea69d1` (= `origin/main`); working tree clean before attempt |
| Host adb | present (`34.0.5-debian`) |
| `adb devices` | **empty** |
| Frida CLI / Python | **NOT_FOUND** |
| Emulator / KVM / Docker | **NOT_FOUND** |
| USB Android device | **NOT_OBSERVED** |
| USB observed | CP210x UART, QinHeng serial, Intel BT adapter, hubs |
| Capture time (UTC) | `2026-11-25T08:39:18.545874+00:00` |
| Instrumentation | none started |

### Inventory (re-verified)

| Artefact | Status |
|---|---|
| v1.5/v1.6 reports | present (`output/v16-*`) |
| `runtime_evidence.v1` | present, **events=[]**, status=`INPUT_MISSING` |
| `wire_evidence.v1` | present (LAB_B3 normalized, 10 packets) |
| B3 capture | present under `bt-analyzer/.../LAB_B3_TCP_FULLAUTH_20261120T090004Z` |
| bt-analyzer | present (`/home/martin/projects/bt-analyzer`) |
| Frida / ADB runtime infra | Frida absent; adb present but no device |
| APK | `artifacts/de.bmw.connected-6.0.0.4962.apk` (sha256 verified) |

## B. Process identity

| Field | Value |
|---|---|
| PID | null |
| process | null |
| package | null (target would be `de.bmw.connected`) |
| Observed | **false** |

Rejected substitutes: `mybmw_sim`, LABSIM `phone.jsonl`, host-only tools, MyBMW `mobile20.row` as stand-in for Connected VALUE-V001.

## C. Hook target (planned, not executed)

| Field | Value |
|---|---|
| VALUE | **VALUE-V001** |
| Class | `com.bmwgroup.connected.core.services.accessory.bcl.packet.Info` |
| Method | `decodeVersion` |
| Descriptor | `([B)S` |
| DEX | `Lcom/bmwgroup/connected/core/services/accessory/bcl/packet/Info;->decodeVersion([B)S` |
| Field | `BclConnection;->mVersion S` |
| Reachable at runtime | UNKNOWN (not tested) |
| Alternative used | no |

Static APK for this VALUE: **`de.bmw.connected` 6.0.0.4962**.  
Method-name → protocol meaning: **REJECTED** without runtime/wire evidence.

## D. Runtime events

*None.*

| Timestamp | Process | Class | Method | Descriptor | Event | Direction | Length | Bytes? | Return |
|---|---|---|---|---|---|---|---|---|---|
| — | — | — | — | — | — | — | — | — | — |

## E. Static mapping

| Runtime method | Static method | VALUE |
|---|---|---|
| *(none)* | `Info;->decodeVersion([B)S` | **VALUE-V001** |

Static FACT unchanged: decode → `mVersion` store/load/branch/roundtrip candidates. Protocol semantics **UNKNOWN**.

## F. Wire mapping

| Item | Result |
|---|---|
| Status | NOT_EXECUTED |
| Existing wire | LAB_B3 FULLAUTH → 10 packets (`wire_evidence.v1`) |
| Same session? | **SESSION_MISMATCH / NOT_APPLICABLE** |

LAB_B3 must not be joined to an absent/future APK runtime capture without independent same-session proof.  
No `STATIC_RUNTIME_WIRE_CORRELATION.*` emitted (correlation not successful).

## G. Negative controls

| ID | Case | Result |
|---|---|---|
| NEG-A | Static VALUE without runtime call | `NO_RUNTIME_CORRELATION` |
| NEG-B | LABSIM / size-only logcat as APK runtime | `REJECTED` |
| NEG-C | Simulated runtime↔LAB wire | `NOT_EXECUTED` / `SESSION_MISMATCH` |
| NEG-D | `decodeVersion` name ⇒ „version message“ | `REJECTED` |

## H. Coverage

| Metric | Value |
|---|---:|
| static_values_total | 24 |
| runtime_events_total | 0 |
| runtime_events_correlated | 0 |
| wire_packets_total | 10 |
| runtime_wire_correlations | 0 |
| full_chain_correlations | 0 |

## I. Evidence classification

- **FACT:** no device; no Frida; VALUE-V001 static mapping; LAB_B3 wire artefact exists externally; zero runtime events
- **CORRELATION:** none
- **INFERENCE:** without instrumentable Connected process, STATIC→RUNTIME cannot close
- **REJECTED:** LABSIM-as-APK-runtime; simulated hooks; cross-session wire join; protocol meaning from method name
- **UNKNOWN:** live reachability of `decodeVersion`; runtime bytes; JNI; protocol/message/HU/request-response meaning

## J. Central result record

```text
VALUE-V001
  static_method:        Info.decodeVersion([B)S
  runtime_event:        null
  runtime_timestamp:    null
  input_length:         null
  input_bytes:          null
  wire_packet:          null
  wire_timestamp:       null
  wire_direction:       null
  wire_payload_slice:   null
  byte_match:           null
  session_match:        false
  confidence:           null
  classification:       UNKNOWN
```

## K. Final verdict

`INPUT_MISSING`

### Closing answers (§22)

1. **VALUE-V001 real ausgeführt?** Nein.
2. **Runtime-Methode beobachtet?** Keine.
3. **Konkrete Input-Bytes?** Keine (`null`).
4. **Passendes Wire-Ereignis?** Nein (Korrelation nicht ausgeführt).
5. **Dieselbe Session?** Nein / nicht anwendbar.
6. **Byte-Match exakt oder Slice?** `null` — kein Matchversuch.
7. **Wire-Richtung?** `null`.
8. **Evidenzklassen:** Static mapping = FACT; Runtime = INPUT_MISSING; Wire-Existenz LAB_B3 = FACT (extern); Runtime↔Wire = NOT_EXECUTED; Semantik = UNKNOWN.
9. **Konkurrierende Kandidaten?** Keine — kein Runtime-Ereignis.
10. **UNKNOWN:** Reachability, Bytes, Session-Bindung, Protokoll-/Message-/HU-/RR-Bedeutung.
11. **Warum keine Korrelation?** Erste nicht schließbare Kante = STATIC→RUNTIME (NO_DEVICE / NO_FRIDA / NO_PROCESS / NO_LIVE_SESSION / NO_INSTRUMENTATION_ACCESS).
12. **Grenze:** `RUNTIME_LIMIT` / `INPUT_MISSING`.
13. **Evidenzsemantik geändert?** Nein.
14. **Tests ausgeführt?** Nein (Abbruch vor Instrumentierung).
15. **Working Tree clean?** Vor Beginn ja; nach Report-/Log-Aktualisierung siehe `git status` (nur Capture-Artefakte, kein Engine-Code).

## Artefacts

- `runtime_evidence.v1.json` — schema-valid, `status=INPUT_MISSING`, `events=[]`
- `RUNTIME_CAPTURE_REPORT.json` / `.md`
- `metadata.json`
- `raw/` / `logs/` — empty instrumentation; probe logs only (`adb_devices`, `frida_probe`, `lsusb`)
