# Runtime Bridge Analysis (v1.6.1)

**Verdict:** `INPUT_MISSING`

```text
STATIC → RUNTIME = INPUT_MISSING
RUNTIME → WIRE  = NOT_EXECUTED  (no APK runtime event)
STATIC → RUNTIME → WIRE = NOT_EXECUTED
```

No simulation. No correlation-engine change. No v1.7.

## Selected static candidate

- **VALUE-V001** (`V5_ROUNDTRIP`)
- API: `Lcom/bmwgroup/connected/core/services/accessory/bcl/packet/Info;->decodeVersion([B)S`
- Field: `Lcom/bmwgroup/connected/core/services/accessory/bcl/BclConnection;->mVersion S`
- Class: `FACT` / protocol `UNKNOWN`

Rationale:
- Clear source: Info.decodeVersion([B)S (DECODE_RETURN_PRIMITIVE)
- Clear buffer relation: byte[] decode API
- Field store: BclConnection.mVersion
- Consumers: FIELD_LOAD + BRANCH + PARAMETER + ROUNDTRIP_FROM_FIELD
- V5_ROUNDTRIP class (static)
- Lower ambiguity than Packet ports/data (V005–V008) which share similar decode patterns

## Runtime inventory (classification)

### bt-analyzer LAB B3 FULLAUTH phone.jsonl
- File: `docs/evidence/LAB_B3_TCP_FULLAUTH_20261120T090004Z/phone.jsonl`
- Classification: **INDIRECT RUNTIME EVIDENCE (simulator) — NOT APK process runtime**

### bt-analyzer LAB B3 FULLAUTH b3.jsonl + raw bins
- File: `docs/evidence/LAB_B3_TCP_FULLAUTH_20261120T090004Z/{b3.jsonl,raw/*.bin}`
- Classification: **WIRE-ONLY**

### Android BT stack verbose logcat (FIELD)
- File: `docs/bluetooth_20261114_083313_01892.txt / bmw_aaidrive_field_reduced_20261114.txt`
- Classification: **INDIRECT RUNTIME EVIDENCE (Bluetooth stack I/O sizes) — INSUFFICIENT for VALUE binding**

### FIELD_B3_GATEB forensic timelines
- File: `docs/evidence/FIELD_B3_GATEB_20261121T112446Z/forensic/*`
- Classification: **WIRE-ONLY / INDIRECT (session) — not APK Dalvik runtime**

### apk-forensics v1.5 application-flow
- File: `output/v15-application-flow/APPLICATION_FLOW_EVIDENCE_REPORT.json`
- Classification: **STATIC-ONLY**

### Frida / Xposed / ART method trace / app instrumentation
- File: `NOT_FOUND for BMW Connected APK process`
- Classification: **INSUFFICIENT — DIRECT APK RUNTIME EVIDENCE ABSENT**

## Static → Runtime

NOT CORRELATED / INPUT_MISSING

Attempts:
- DEX method identity ↔ LABSIM sess.method names → REJECTED (name-only + different process; sas_* ≠ decodeVersion)
- VALUE field mVersion ↔ wire handshake version field → REJECTED (protocol/semantic guess without runtime)
- RFCOMM UID 10479 logcat writes ↔ VALUE-V001 → INSUFFICIENT (sizes only, no payload, no decode event)

## Runtime → Wire

- APK runtime→wire: `NOT_EXECUTED`
- LABSIM→wire: **not strong** — phone tx segmentation (7) ≠ wire PHONE_TO_HU packets (4); naive zip rejected as unique CORRELATION. Still not APK runtime.

## Triple correlation

`exists: false` — no CORR-0001 record.

## Coverage

- static values: 24
- with runtime: 0
- runtime→wire: 0
- full chain: 0

## Answers Q1–Q19

### Q1
LABSIM phone/hu/b3 jsonl+bins; FIELD BT logcat (sizes); FIELD_B3 wire forensics; static APK reports. No Frida/ART method traces for Connected.

### Q2
LABSIM = indirect/simulator runtime; logcat = indirect stack I/O; B3 bins = wire-only; APK reports = static-only. No DIRECT APK runtime evidence.

### Q3
No unambiguous runtime anchor for a BMW VALUE-V###.

### Q4
VALUE-V001 (best static candidate for a future bridge).

### Q5
decodeVersion→mVersion with store/load/branch/roundtrip consumers; clearest single-field lineage.

### Q6
No — INPUT_MISSING / NOT CORRELATED.

### Q7
Not for APK runtime. LABSIM→Wire prefix matches exist but are out-of-scope as APK runtime.

### Q8
No — VALUE→Runtime→Wire does not exist yet.

### Q9
BYTE_LEVEL_CORRELATION = UNKNOWN (no runtime buffer observation for VALUE).

### Q10
No wire-backed roundtrip for VALUE-V001.

### Q11
protocol semantics; HU identity from APK; which VALUE instance produced which bytes; request/response; runtime execution of decodeVersion.

### Q12
wrong-value/name-only; wrong-direction; LABSIM≠APK runtime; size-only logcat; ordered hex_head mismatch.

### Q13
No true schema gap — missing input artefact.

### Q14
No code change.

### Q15
n/a

### Q16
24 static / 0 runtime-correlated / 0 wire-correlated / 0 full-chain.

### Q17
None elevated by this bridge attempt.

### Q18
All protocol/message/request-response hypotheses remain UNKNOWN.

### Q19
No — capture APK-process runtime_evidence.v1 first; v1.7 architecture not justified.

## What is missing (exact)

Need `runtime_evidence.v1` produced from the **BMW Connected APK process**, e.g.:

- `RUNTIME_METHOD` / `RUNTIME_READ` / `RUNTIME_WRITE`
- DEX method identity matching static (e.g. `Info;->decodeVersion([B)S`)
- `timestamp_ms`, `direction`, `length`, preferably `bytes_hex`
- provenance: instrumented app / ART trace — not LABSIM, not stack-size-only logcat

Then existing v1.6 correlation can join Static ↔ Runtime ↔ Wire without schema redesign.

