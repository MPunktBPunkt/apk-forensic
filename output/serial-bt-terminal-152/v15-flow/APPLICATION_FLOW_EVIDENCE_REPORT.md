# Application Flow Evidence Report (v1.5)

> Structured Value → Application Flow. Not protocol reconstruction.

## Interpretation

v1.5 closes Structured Value → Application Flow with FACT/CORRELATION edges. It does not close Application Flow → Protocol Semantics.

## PATH-COMM provenance

- **baseline_v14_path_comm**: `12`
- **current_path_comm**: `12`
- **changed**: `False`
- **provenance_note**: `v1.4 PATH-COMM=12 from READ_LENGTH correction + interface seed expansion (analyzer expansion, not APK change).`
- **v15_note**: `v1.5 does not silently rewrite PATH-COMM. Application-flow analysis is additive. Any PATH-COMM delta must cite seed expansion / READ_LENGTH / new analysis — not APK change.`
- **analyzer_expansion_vs_apk**: `PATH-COMM growth from v1.3→v1.4 was analyzer expansion, not new APK bytes.`

## Answers

- **1_structured_values_from_s4**: `{"catalog_count": 12, "sample_ids": ["VALUE-V001", "VALUE-V002", "VALUE-V003", "VALUE-V004", "VALUE-V005", "VALUE-V006", "VALUE-V007", "VALUE-V008", "VALUE-V009", "VALUE-V010", "VALUE-V011", "VALUE-V012"], "note": "Neutral VALUE-V### IDs; no semantic naming"}`
- **2_written_to_fields**: `8`
- **3_later_loaded**: `14`
- **4_passed_to_methods**: `1000`
- **5_returned**: `29`
- **6_influence_branches**: `249`
- **7_application_state_mutations**: `13`
- **8_collections_maps**: `55`
- **9_object_construction**: `0`
- **10_output_dataflow**: `0`
- **11_true_roundtrip_correlations**: `false`
- **12_where_lineage_ends**: `["Intra-method: return / last use / overwrite", "Cross-method: field descriptor CORRELATION without proven instance", "Call-graph / retention boundary beyond expanded seed set"]`
- **13_true_apk_ends**: `["Some values are logging-only consumers", "Some branches compare to constants without further static sink"]`
- **14_analyzer_bounds**: `["Bounded method retention / seed expansion", "No full SSA; register overwrite ends local lineage", "Interface/instance identity across Packet args is CORRELATION"]`
- **15_new_facts**: `["STRUCTURED_VALUE from ByteBuffer.get*/aget/decode return", "FIELD_STORE_FROM_BYTES instruction-level", "BRANCH_ON_VALUE / BRANCH_ON_FIELD_VALUE"]`
- **16_new_correlations**: `["Field store descriptor → later iget consumers", "Byte-derived field → setState / further decode on mData", "Optional ROUNDTRIP_FROM_FIELD when encode/write reached"]`
- **17_allowed_inferences**: `["End-to-end application-flow path composition is INFERENCE", "Method-name search indicators (decode/setState) never protocol proof"]`
- **18_unknowns**: `["protocol_semantics", "meaning of compared constants", "peer/HU identity", "runtime session / which Packet instance"]`
- **19_path_comm_changed**: `false`
- **20_path_comm_why**: `v1.5 does not silently rewrite PATH-COMM. Application-flow analysis is additive. Any PATH-COMM delta must cite seed expansion / READ_LENGTH / new analysis — not APK change.`
- **21_protocol_semantics_unknown**: `true`
- **22_application_level_evidence_chain**: `true`
- **value_class_counts**: `{"V3_CONTROL_FLOW": 8, "V4_APPLICATION_ACTION": 4}`
- **path_comm_provenance**: `{"baseline_v14_path_comm": 12, "current_path_comm": 12, "changed": false, "provenance_note": "v1.4 PATH-COMM=12 from READ_LENGTH correction + interface seed expansion (analyzer expansion, not APK change).", "v15_note": "v1.5 does not silently rewrite PATH-COMM. Application-flow analysis is additive. Any PATH-COMM delta must cite seed expansion / READ_LENGTH / new analysis — not APK change.", "analyzer_expansion_vs_apk": "PATH-COMM growth from v1.3→v1.4 was analyzer expansion, not new APK bytes."}`
- **limits_unchanged**: `{"max_field_hops": 2, "raised": false}`
- **negative_controls**: `{"CASE_F": ["PATH-000009", "PATH-000010", "PATH-000012", "PATH-000013"], "CASE_D": ["PATH-000011"], "must_not_gain_structured_value_from_transport": true}`

Protocol semantics: **UNKNOWN**
