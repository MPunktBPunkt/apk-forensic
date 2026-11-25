# v1.6 Cross-APK Evaluation & Real Wire Evidence Correlation

Engine: **1.6.0** — correlation engine not redesigned; CASE-B normalizer only.

## STATIC FACTS — Comparison table

| Metric | BMW Connected | MyBMW | Serial BT 1.52 |
|---|---:|---:|---:|
| rfcomm_targets | 4 | 5 | 1 |
| bluetooth_paths | 4 | 5 | 1 |
| evidence_paths | 13 | 8 | 4 |
| PATH_COMM | 12 | 9 | 2 |
| structured_values | 24 | UNKNOWN / NOT_REPORTED | 12 |
| V0_SOURCE_ONLY | 1 | UNKNOWN / NOT_REPORTED | 0 |
| V1_FIELD_STATE | 2 | UNKNOWN / NOT_REPORTED | 0 |
| V2_CONSUMED | 13 | UNKNOWN / NOT_REPORTED | 0 |
| V3_CONTROL_FLOW | 2 | UNKNOWN / NOT_REPORTED | 8 |
| V4_APPLICATION_ACTION | 0 | UNKNOWN / NOT_REPORTED | 4 |
| V5_ROUNDTRIP | 6 | UNKNOWN / NOT_REPORTED | 0 |
| field_stores | 8 | UNKNOWN / NOT_REPORTED | 8 |
| field_loads | 63 | UNKNOWN / NOT_REPORTED | 14 |
| parameters | 191 | UNKNOWN / NOT_REPORTED | 1000 |
| returns | 5 | UNKNOWN / NOT_REPORTED | 29 |
| branches | 36 | UNKNOWN / NOT_REPORTED | 249 |
| state_mutations | 6 | UNKNOWN / NOT_REPORTED | 13 |
| collections | 2 | UNKNOWN / NOT_REPORTED | 55 |
| roundtrip_candidates | 13 | UNKNOWN / NOT_REPORTED | 0 |
| decoder_candidates | 20 | 0 | 0 |
| encoder_candidates | 18 | 0 | 0 |
| protocol_semantics | UNKNOWN | UNKNOWN / NOT_REPORTED | UNKNOWN |

## DERIVED METRICS

### BMW_Connected
- `values_per_communication_path` = `2.0` (*DERIVED METRIC*)
- `field_loads_per_field_store` = `7.875` (*DERIVED METRIC*)
- `branches_per_value` = `1.5` (*DERIVED METRIC*)
- `state_mutations_per_value` = `0.25` (*DERIVED METRIC*)
- `roundtrip_candidates_per_value` = `0.5417` (*DERIVED METRIC*)

### MyBMW
- `values_per_communication_path` = `UNKNOWN / NOT_REPORTED` (*DERIVED METRIC*)
- `field_loads_per_field_store` = `UNKNOWN / NOT_REPORTED` (*DERIVED METRIC*)
- `branches_per_value` = `UNKNOWN / NOT_REPORTED` (*DERIVED METRIC*)
- `state_mutations_per_value` = `UNKNOWN / NOT_REPORTED` (*DERIVED METRIC*)
- `roundtrip_candidates_per_value` = `UNKNOWN / NOT_REPORTED` (*DERIVED METRIC*)

### Serial_BT_Terminal_1_52
- `values_per_communication_path` = `6.0` (*DERIVED METRIC*)
- `field_loads_per_field_store` = `1.75` (*DERIVED METRIC*)
- `branches_per_value` = `20.75` (*DERIVED METRIC*)
- `state_mutations_per_value` = `1.0833` (*DERIVED METRIC*)
- `roundtrip_candidates_per_value` = `0.0` (*DERIVED METRIC*)

## Serial Terminal directional paths

### INBOUND (`comm-6ba27e0f6ec7`)
- Evidence class: `INFERENCE`
- End: `Ljava/io/IOException;-><init>(Ljava/lang/String;)V`
- Chain (reported): RFCOMM/SPP → Socket → Stream → read-oriented path → buffer/helper boundary (UNKNOWN_HELPER) → IOException ctor end
- Boundaries: 4

### OUTBOUND (`comm-6051db14c98c`)
- Evidence class: `INFERENCE`
- End: `Ljava/io/OutputStream;->write([B)V`
- Chain (reported): RFCOMM/SPP → Socket → Stream → OutputStream.write([B) end
- Boundaries: 0

## Wire inventory (selected)

- **bt-analyzer** `docs/evidence/LAB_B3_TCP_FULLAUTH_20261120T090004Z/raw/phone_to_hu.bin` — usable=YES after CASE-B normalization dir=PHONE_TO_HU
- **bt-analyzer** `docs/evidence/LAB_B3_TCP_FULLAUTH_20261120T090004Z/raw/hu_to_phone.bin` — usable=YES after CASE-B normalization dir=HU_TO_PHONE
- **bt-analyzer** `docs/evidence/LAB_B3_TCP_FULLAUTH_20261120T090004Z/b3.jsonl` — usable=YES as slicing guide + metadata; payloads from bins dir=phone->hu / hu->phone
- **bt-analyzer** `docs/evidence/FIELD_AUTH_PROBE_*/hci1.btsnoop + btmon.log` — usable=NOT directly — needs HCI→RFCOMM payload extraction (possible future CASE B/C) dir=HCI-level (not RFCOMM payload stream)
- **hu-probe** `sessions/* / derived/*` — usable=NOT as drop-in wire_evidence.v1 without dedicated normalizer dir=vehicle/HU probe context

## CORRELATIONS

- BMW + B3 wire: runtime=`INPUT_MISSING`, wire packets=`10`, E2E=`0`
- VALUE↔WIRE: **NONE** (runtime INPUT_MISSING)
- SBT negative control E2E: `0`

## COVERAGE (separate from evidence class)

- BMW: {'values_total': 24, 'values_with_consumer': 6, 'values_without_consumer': 18, 'values_with_field_store': 8, 'field_stores_without_proven_load': 2, 'values_with_branch': 6, 'values_with_state_mutation': 0, 'values_with_roundtrip_candidate': 6, 'values_with_wire_correlation': 0, 'values_without_external_evidence': 24, 'dimension': 'COVERAGE (not evidence class)'}
- Serial: {'values_total': 12, 'values_with_consumer': 8, 'values_without_consumer': 4, 'values_with_field_store': 8, 'field_stores_without_proven_load': 0, 'values_with_branch': 8, 'values_with_state_mutation': 0, 'values_with_roundtrip_candidate': 0, 'values_with_wire_correlation': 0, 'values_without_external_evidence': 12, 'dimension': 'COVERAGE (not evidence class)'}

## JNI / Native

- {'apk': 'BMW Connected', 'status': 'OBSERVED_SO_IN_ZIP', 'so_files': ['lib/arm64-v8a/libBMWCrypto.so', 'lib/arm64-v8a/libGNaviData.so', 'lib/arm64-v8a/libGNaviMap.so', 'lib/arm64-v8a/libGNaviMapex.so', 'lib/arm64-v8a/libGNaviSearch.so', 'lib/arm64-v8a/libGNaviUtils.so', 'lib/arm64-v8a/libRoadLineRebuildAPI.so', 'lib/arm64-v8a/libView3D.so', 'lib/arm64-v8a/libaudio.so', 'lib/arm64-v8a/libsqlcipher.so', 'lib/armeabi-v7a/libBMWCrypto.so', 'lib/armeabi-v7a/libGNaviData.so', 'lib/armeabi-v7a/libGNaviMap.so', 'lib/armeabi-v7a/libGNaviMapex.so', 'lib/armeabi-v7a/libGNaviSearch.so', 'lib/armeabi-v7a/libGNaviUtils.so', 'lib/armeabi-v7a/libRoadLineRebuildAPI.so', 'lib/armeabi-v7a/libView3D.so', 'lib/armeabi-v7a/libaudio.so', 'lib/armeabi-v7a/libsqlcipher.so'], 'path_linked_to_value': 'NOT_OBSERVED'}
- {'apk': 'MyBMW', 'status': 'NOT_OBSERVED', 'note': 'No .so / JNI boundary tied to analyzed RFCOMM→value paths in available reports'}
- {'apk': 'Serial BT Terminal', 'status': 'NOT_OBSERVED', 'note': 'No .so / JNI boundary tied to analyzed RFCOMM→value paths in available reports'}

## Answers Q1–Q16

### Q1
YES — BMW Connected v1.5/v1.6 artefacts reproducible; Serial BT Terminal 1.52 scan+diagnostics reproduced under output/serial-bt-terminal-152; MyBMW v11 transport/communication present but application-flow NOT_REPORTED.

### Q2
YES as positive control for RFCOMM→Socket→Stream→read/write (FACT/INFERENCE transport). Application-flow Values exist (12) but are STRING_FROM_BYTES in obfuscated helpers — weaker semantic chain than BMW Packet path; still valid RFCOMM smoke control.

### Q3
BMW: more RFCOMM targets/paths, PATH-COMM=12, V5_ROUNDTRIP present (6), higher field_loads (63), decoder/serializer candidates in expanded comm (20/18). Serial: 1 RFCOMM path, PATH-COMM=2, no V5_ROUNDTRIP, value classes dominated by V3/V4, higher raw branch/collection counts in retained methods (analyzer-scope sensitive).

### Q4
FACT/reported: absolute counts from reports/baseline. DERIVED: values/PATH-COMM, loads/stores, branches/values, etc. Protocol complexity claims are NOT FACT.

### Q5
YES — real wire artefacts in bt-analyzer (B3 phone_to_hu/hu_to_phone bins + jsonl). hu-probe sessions exist but not drop-in.

### Q6
LAB_B3_TCP_FULLAUTH_20261120T090004Z (complete directional bins + jsonl byte events; stream_slice_complete=true).

### Q7
YES after CASE-B normalization to wire_evidence.v1 (10 WIRE_PACKET).

### Q8
NORMALIZATION ONLY (CASE B) — not a true interface gap for byte/direction/offset/length.

### Q9
NO belastbare VALUE↔Wire Frame CORRELATION — runtime INPUT_MISSING; engine correctly yields 0 RW / 0 E2E. Wire is ingested as external evidence only.

### Q10
NO Roundtrip CORRELATION to wire — no runtime bridge; static V5_ROUNDTRIP remains APK-static only.

### Q11
All BMW 24 and Serial 12 values remain without external correlation (unknown stubs).

### Q12
See coverage section — consumers/stores/branches/roundtrip; wire correlation coverage=0 without runtime.

### Q13
NOT_OBSERVED for path-linked JNI/native boundaries in these reports (no proven VALUE→JNI edge).

### Q14
protocol_semantics, peer/HU identity as vehicle identity, request/response meaning, message meaning, runtime execution of specific VALUE instances.

### Q15
No prior protocol hypothesis strengthened to FACT. Wire proves LAB bytes exist with direction (external FACT of capture). Does not map to VALUE-V###. SBT↔BMW-wire negative control produced no false E2E.

### Q16
Not required for schema expansion. Optional next step is runtime evidence capture for BMW (method/read with bytes) OR keep v1.6 and add only more normalizers. Full v1.7 architecture NOT justified by this audit.

## REJECTED / UNKNOWN (summary)

- Rejected: simulated correlations; protocol naming from external labels; SBT↔BMW-wire E2E; branch-count⇒protocol-complexity
- Unknown: protocol semantics, HU identity, VALUE instance↔wire slice binding, request/response

