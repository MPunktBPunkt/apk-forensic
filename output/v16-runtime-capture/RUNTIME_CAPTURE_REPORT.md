# Runtime Capture Report — VALUE-V001

**Final verdict:** `INPUT_MISSING`

```text
STATIC → RUNTIME          = INPUT_MISSING
RUNTIME → WIRE            = NOT_EXECUTED
VALUE-V001 → Runtime → Wire = NOT_PROVEN
```

No simulation. No LABSIM substitution. No v1.7. No correlation-engine change.

## A. Environment

| Item | Result |
|---|---|
| Host adb | present |
| `adb devices` | **empty** |
| Frida CLI / Python | **NOT_FOUND** |
| Emulator | **NOT_FOUND** |
| USB Android device | **NOT_OBSERVED** |
| Capture time (UTC) | `2026-11-25T06:36:27.106398+00:00` |
| Instrumentation | none started |

## B. Process identity

| Field | Value |
|---|---|
| PID | null |
| process | null |
| package | null (target would be `de.bmw.connected`) |
| Observed | **false** |

Rejected substitutes: `mybmw_sim`, LABSIM `phone.jsonl`, host-only tools.

## C. Hook target (planned, not executed)

| Field | Value |
|---|---|
| Class | `com.bmwgroup.connected.core.services.accessory.bcl.packet.Info` |
| Method | `decodeVersion` |
| Descriptor | `([B)S` |
| DEX | `Lcom/bmwgroup/connected/core/services/accessory/bcl/packet/Info;->decodeVersion([B)S` |
| Reachable at runtime | UNKNOWN (not tested) |
| Alternative used | no |

Static APK for this VALUE: **`de.bmw.connected` 6.0.0.4962** (not MyBMW `mobile20.row`).

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

LAB_B3 must not be joined to a future APK runtime capture without independent same-session proof.

## G. Negative controls

| ID | Case | Result |
|---|---|---|
| NEG-A | Static VALUE without runtime call | `NO_RUNTIME_CORRELATION` |
| NEG-B | LABSIM / size-only logcat as APK runtime | `REJECTED` |
| NEG-C | Simulated runtime↔LAB wire | `NOT_EXECUTED` |

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

- **FACT:** no device; no Frida; VALUE-V001 static mapping; zero runtime events recorded
- **CORRELATION:** none
- **REJECTED:** LABSIM-as-APK-runtime; simulated hooks; cross-session wire join
- **UNKNOWN:** live reachability of `decodeVersion`; runtime bytes; JNI; protocol meaning

## J. Final verdict

`INPUT_MISSING`

### Closing answers

1. **Instrumented?** No.  
2. **`decodeVersion` observed?** No.  
3. **Real runtime bytes?** No.  
4. **Same-session runtime↔wire?** No.  
5. **Unique runtime→wire correlation?** No.  
6. **VALUE-V001 → Runtime → Wire proven?** No.  
7. **Missing building block:** Android device/emulator with matching `de.bmw.connected` process + Frida/ART hooks + live Connected/RFCOMM session + **same-session** wire capture.

## Artefacts

- `runtime_evidence.v1.json` — schema-valid, `status=INPUT_MISSING`, `events=[]`
- `RUNTIME_CAPTURE_REPORT.json` / `.md`
- `metadata.json`
- `raw/` / `logs/` — empty with reason notes
