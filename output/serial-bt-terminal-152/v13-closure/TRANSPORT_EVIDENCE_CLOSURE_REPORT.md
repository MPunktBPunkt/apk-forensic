# Transport Evidence Closure Report (v1.3)

> Evidence closure from Bluetooth transport to bytes — not protocol reconstruction.

## Summary

- **transport_paths**: `4`
- **path_comm**: `0`
- **reaching_T2_IO**: `3`
- **reaching_T3_BUFFER**: `3`
- **reaching_T4**: `0`
- **reaching_T5**: `0`
- **protocol_semantics**: `UNKNOWN`
- **limits_raised**: `False`

## Inventory

| PATH | Transport | Object Flow | Stream | I/O | Buffer | Consumer/Producer | Ende | Reason | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| PATH-000001 | COMBINED_COMMUNICATION_PATH | socket:S1,input:I1,output:O1 | Y | Y | Y | N | Ljava/io/OutputStream;->write([B)V | F_BUFFER_IDENTITY_BOUNDARY | CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN |
| PATH-000002 | INPUT_PATH | socket:S1,input:I1,output:O1 | Y | Y | Y | N | Ljava/io/InputStream;->read([B)I | F_BUFFER_IDENTITY_BOUNDARY | CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN |
| PATH-000003 | OUTPUT_PATH | socket:S1,input:I1,output:O1 | Y | Y | Y | N | Ljava/io/OutputStream;->write([B)V | F_BUFFER_IDENTITY_BOUNDARY | CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN |
| PATH-000004 | SOCKET_PATH | socket:S1,input:I1,output:O1 | N | N | N | N | BluetoothSocket.connect | A_TRUE_GRAPH_END | CASE_F_TRUE_END |

## Per-Path Closure Chains

### PATH-000001 — `CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN`

- Kind: `COMBINED_COMMUNICATION_PATH`
- Highest stage: `T3_BUFFER`
- Termination: `F_BUFFER_IDENTITY_BOUNDARY`
- Protocol semantics: `UNKNOWN`
- Stages:
  - `T0_SOCKET`: REACHED (FACT)
  - `T1_STREAM`: REACHED (FACT)
  - `T2_IO`: REACHED (FACT)
  - `T3_BUFFER`: REACHED (FACT)
  - `T4_CONSUMER_PRODUCER`: open
  - `T5_DECODER_ENCODER`: open
  - `T6_COMMUNICATION`: open
- Edge chain:
  - `None → T0_SOCKET` [FACT] SOCKET node / createRfcomm* in path steps
  - `T0_SOCKET → T1_STREAM` [FACT] getInputStream/getOutputStream or stream field on path
  - `T1_STREAM → T2_IO` [FACT] I/O on path: read=True write=True flush=False
  - `T2_IO → T3_BUFFER` [FACT] read/write signature with [B or ByteBuffer on path step
  - `T4_CONSUMER_PRODUCER → T5_DECODER_ENCODER` [UNKNOWN] No FACT byte-processing edge from tracked buffer on this path linkage [not closed]

### PATH-000002 — `CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN`

- Kind: `INPUT_PATH`
- Highest stage: `T3_BUFFER`
- Termination: `F_BUFFER_IDENTITY_BOUNDARY`
- Protocol semantics: `UNKNOWN`
- Stages:
  - `T0_SOCKET`: REACHED (FACT)
  - `T1_STREAM`: REACHED (FACT)
  - `T2_IO`: REACHED (FACT)
  - `T3_BUFFER`: REACHED (FACT)
  - `T4_CONSUMER_PRODUCER`: open
  - `T5_DECODER_ENCODER`: open
  - `T6_COMMUNICATION`: open
- Edge chain:
  - `None → T0_SOCKET` [FACT] SOCKET node / createRfcomm* in path steps
  - `T0_SOCKET → T1_STREAM` [FACT] getInputStream/getOutputStream or stream field on path
  - `T1_STREAM → T2_IO` [FACT] I/O on path: read=True write=False flush=False
  - `T2_IO → T3_BUFFER` [FACT] read/write signature with [B or ByteBuffer on path step
  - `T4_CONSUMER_PRODUCER → T5_DECODER_ENCODER` [UNKNOWN] No FACT byte-processing edge from tracked buffer on this path linkage [not closed]

### PATH-000003 — `CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN`

- Kind: `OUTPUT_PATH`
- Highest stage: `T3_BUFFER`
- Termination: `F_BUFFER_IDENTITY_BOUNDARY`
- Protocol semantics: `UNKNOWN`
- Stages:
  - `T0_SOCKET`: REACHED (FACT)
  - `T1_STREAM`: REACHED (FACT)
  - `T2_IO`: REACHED (FACT)
  - `T3_BUFFER`: REACHED (FACT)
  - `T4_CONSUMER_PRODUCER`: open
  - `T5_DECODER_ENCODER`: open
  - `T6_COMMUNICATION`: open
- Edge chain:
  - `None → T0_SOCKET` [FACT] SOCKET node / createRfcomm* in path steps
  - `T0_SOCKET → T1_STREAM` [FACT] getInputStream/getOutputStream or stream field on path
  - `T1_STREAM → T2_IO` [FACT] I/O on path: read=False write=True flush=False
  - `T2_IO → T3_BUFFER` [FACT] read/write signature with [B or ByteBuffer on path step
  - `T4_CONSUMER_PRODUCER → T5_DECODER_ENCODER` [UNKNOWN] No FACT byte-processing edge from tracked buffer on this path linkage [not closed]

### PATH-000004 — `CASE_F_TRUE_END`

- Kind: `SOCKET_PATH`
- Highest stage: `T0_SOCKET`
- Termination: `A_TRUE_GRAPH_END`
- Protocol semantics: `UNKNOWN`
- Stages:
  - `T0_SOCKET`: REACHED (FACT)
  - `T1_STREAM`: open
  - `T2_IO`: open
  - `T3_BUFFER`: open
  - `T4_CONSUMER_PRODUCER`: open
  - `T5_DECODER_ENCODER`: open
  - `T6_COMMUNICATION`: open
- Edge chain:
  - `None → T0_SOCKET` [FACT] SOCKET node / createRfcomm* in path steps

## PATH-COMM Linkage


## Closure Answers (1–17)

- **1_paths_reaching_read_write**: `{"count": 3, "of": 4}`
- **2_paths_reaching_buffer**: `{"count": 3, "of": 4}`
- **3_paths_reaching_buffer_consumer_producer**: `{"count": 0, "of": 4}`
- **4_paths_reaching_decoder_encoder_candidate**: `{"count": 0, "of": 4}`
- **5_break_object_identity**: `[]`
- **6_break_buffer_identity**: `["PATH-000001", "PATH-000002", "PATH-000003"]`
- **7_break_return_parameter_wrapper**: `[]`
- **8_true_graph_ends**: `["PATH-000004"]`
- **9_remaining_analyzer_limits**: `[]`
- **10_new_facts_vs_v12**: `["Explicit T0–T6 stage closure per PATH-*", "read([B)/write([B) buffer_arg_present / buffer_register FACT on object-flow (when re-scanned)", "BUFFER_ARG nodes + read_into_buffer / write_from_buffer transfers", "Offline CORRELATION of transport object identity to dataflow buffer ops and PATH-COMM"]`
- **11_new_correlations**: `["Transport stream object ↔ dataflow read([B) buffer argument", "Transport PATH-* ↔ PATH-COMM via source_method / object identity"]`
- **12_inferences_remaining**: `["End-to-end PATH / PATH-COMM composition remains INFERENCE", "PRIMITIVE_DECODE as byte-handling candidate (not protocol)"]`
- **13_unknowns_unchanged**: `["protocol_semantics", "wire format / message meaning", "peer/HU identity", "runtime session behavior"]`
- **14_communication_baseline_changed**: `false`
- **15_justification_if_changed**: `null`
- **16_protocol_semantics_statically_provable**: `false`
- **17_why_protocol_remains_unknown**: `Static DEX shows transport I/O and some byte[] arguments / PATH-COMM FACT steps, but no statically proven decoder that assigns wire/message meaning. Method/class names are not protocol evidence.`
- **case_counts**: `{"CASE_C_BUFFER_CLOSED_SEMANTICS_OPEN": 3, "CASE_F_TRUE_END": 1}`
- **termination_counts**: `{"F_BUFFER_IDENTITY_BOUNDARY": 3, "A_TRUE_GRAPH_END": 1}`
- **path_comm_count**: `0`
- **protocol_semantics**: `UNKNOWN`
- **limits_unchanged**: `{"max_field_hops": 2, "max_method_hops": 3, "max_object_nodes": 500, "dataflow_depth": 3, "raised": false}`

## Interpretation

v1.3 answers how far static evidence closes Bluetooth transport to bytes. It does not claim protocol discovery. Coverage ≠ evidence.
