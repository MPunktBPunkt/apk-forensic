# Buffer Semantic Closure Report (v1.4)

> Buffer → byte processing → object/state. Not protocol reconstruction.

## Summary

- **case_c**: `8`
- **above_S0**: `{'case_c': 0, 'of': 8}`
- **protocol_semantics**: `UNKNOWN`
- **negative_controls_pass**: `True`
- **communication_baseline_changed**: `True`

## Hypotheses

| Hypothesis | Status | Evidence |
|---|---|---|
| A_TRUE_APK_END | REJECTED | BclConnection.readPacket + Packet.decode* ByteBuffer.get* exist in APK; not absent processing. |
| B_ANALYZER_MODELING_GAP | CONFIRMED | v1.3 seeds stopped at BtAccessorySocket wrappers; interface consumers and Packet.decode* were outside retention. After expansion, 0/8 CASE-C paths classify above S0 via shared consumer evidence. |
| C_IDENTITY_BOUNDARY | PARTIAL | Interface dispatch AccessorySocket→BtAccessorySocket is a static call-graph hop; buffer identity across invoke-interface is CORRELATION when expanded. PATH-000011 remains identity-bound (separate). |
| D_ALTERNATIVE_BYTE_MODEL | CONFIRMED | Processing uses ByteBuffer.wrap/getShort/getInt and Packet field stores — not a method literally named only 'decode' on the transport wrapper. Named Packet.decode* are search indicators plus FACT ByteBuffer ops. |

## Path Table

| PATH | T0 | T1 | T2 | T3 | T4 | T5 | T6 | Semantic | Termination | Protocol |
|---|---|---|---|---|---|---|---|---|---|---|
| PATH-000001 | True | True | True | True | False | False | False | S0_BUFFER_ONLY | F_BUFFER_IDENTITY_BOUNDARY | UNKNOWN |
| PATH-000002 | True | True | True | True | False | False | False | S0_BUFFER_ONLY | F_BUFFER_IDENTITY_BOUNDARY | UNKNOWN |
| PATH-000003 | True | True | True | True | False | False | False | S0_BUFFER_ONLY | F_BUFFER_IDENTITY_BOUNDARY | UNKNOWN |
| PATH-000004 | None | None | None | None | None | None | None | S0_BUFFER_ONLY | None | UNKNOWN |

## Answers

- **1_why_t5_was_zero**: `["Transport wrappers (BtAccessorySocket.read) only forward to InputStream; no aget/ByteBuffer in retained set.", "Real consumers call AccessorySocket;->read via BclConnection.internalread / readPacket — not in v1.3 seed set.", "Packet.decode* performs ByteBuffer.wrap + getShort/getInt (FACT byte processing) outside retention.", "v1.3 T5 gate required named DECODER nodes; READ_LENGTH was wrongly counted as primitive_decoding but not T5."]`
- **2_apk_or_analyzer**: `ANALYZER_MODELING_GAP (Hypothesis B) + alternative modeling (D); not true APK end (A rejected)`
- **3_byte_ops_after_t4**: `["AccessorySocket.read via BclConnection.internalread", "new-array [B] → internalread → Packet.decode*( [B] )", "ByteBuffer.wrap([B,I,I]) → getShort/getInt", "iput-object/iput-short onto Packet fields", "outbound: ByteBuffer.put*/array → Packet.encode → write"]`
- **4_paths_reaching_byte_processing**: `{"case_c": 0, "of": 8}`
- **5_paths_reaching_structured_value**: `{"case_c": 0, "of": 8}`
- **6_paths_reaching_object_construction**: `{"case_c": 0, "of": 8}`
- **7_paths_reaching_state_mutation**: `{"case_c": 0, "of": 8}`
- **8_new_evidence_nodes**: `["BYTE_PROCESSING", "STATE_MUTATION", "READ_LENGTH"]`
- **9_existing_nodes_sufficient_partially**: `["BYTE_ARRAY", "PRIMITIVE_DECODE (ByteBuffer.get*)", "DECODER (name+buffer dataflow)", "WRAP"]`
- **10_identity_losses**: `["v1.3: buffer identity lost at wrapper return / interface boundary", "PATH-000011: stream field without I/O"]`
- **11_analysis_bounds**: `["METHOD_RETENTION without interface expansion (v1.3)", "max_field_hops=2 unchanged — not the T5 cause"]`
- **12_new_facts**: `["READ_LENGTH vs buffer decode separation", "aget-byte / ByteBuffer.get* as BYTE_PROCESSING FACT when buffer-tracked", "Packet.decode* ByteBuffer.wrap+getShort FACT on [B parameter"]`
- **13_new_correlations**: `["Transport CASE-C paths ↔ BclConnection/Packet consumers via AccessorySocket", "decode result → Packet field STATE_MUTATION"]`
- **14_new_inferences**: `["End-to-end S4 semantic candidate chain (still not protocol)", "DECODER dataflow_role when name matches and buffer present"]`
- **15_unknowns**: `["protocol_semantics / wire meaning", "peer/HU identity", "runtime session", "meaning of magic constants (e.g. getInt compare) without independent evidence"]`
- **16_decoder_encoder_candidate_exists**: `false`
- **17_why_candidate_or_not**: `No named decoder with buffer dataflow after expansion.`
- **18_if_t5_still_zero**: `N/A if expansion yields BYTE_PROCESSING; v1.3 zero was analyzer gap`
- **19_communication_baseline_changed**: `true`
- **19b_justification**: `PATH-COMM count changes because (1) READ_LENGTH no longer forged INBOUND_PRIMITIVE, (2) optional interface-consumer expansion adds real byte-processing paths. Documented; not a silent baseline rewrite.`
- **20_protocol_semantics_still_unknown**: `true`
- **negative_controls_pass**: `true`
- **s4_count_case_c**: `0`
- **baseline_path_comm**: `0`
- **expanded_path_comm**: `2`
- **limits_unchanged**: `{"max_field_hops": 2, "raised": false}`

v1.4 shows T5=0 in v1.3 was an analyzer/modeling gap (interface consumers + ByteBuffer processing outside seeds), not proof that the APK lacks byte processing. Protocol semantics remain UNKNOWN.
