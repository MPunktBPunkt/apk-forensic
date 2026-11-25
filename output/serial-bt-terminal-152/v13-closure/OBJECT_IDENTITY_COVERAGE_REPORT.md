# Object Identity Coverage Report (v1.3)

## Rules

- **same_type_not_alias**: FACT/REJECTED merge-by-type
- **same_field**: Same static field position in object context; not automatic same instance across contexts
- **move_result_overwrite**: Ends local register identity
- **cycle_guard**: Real field/object cycle stops tracking
- **stream_wrapper_new_identity**: New stream/wrapper object starts hops=0

## Summary

- **identity_break_records**: `1`
- **same_field_notes**: `0`
- **false_alias_candidate_rows**: `4`

## Identity Breaks (sample)

- `{'path': 'BTDATA-000001', 'kind': 'move_result_overwrite', 'object_id': 'input:I1', 'method': 'La00;->run()V', 'classification': 'FACT', 'note': 'Local identity ends; same type must not merge'}`

## False-Alias Candidates

- `{'path': 'PATH-000001', 'socket_object': 'socket:S1', 'rule': 'REJECTED: merge-by-type', 'note': 'Equal type BluetoothSocket ≠ same object identity across paths'}`
- `{'path': 'PATH-000002', 'socket_object': 'socket:S1', 'rule': 'REJECTED: merge-by-type', 'note': 'Equal type BluetoothSocket ≠ same object identity across paths'}`
- `{'path': 'PATH-000003', 'socket_object': 'socket:S1', 'rule': 'REJECTED: merge-by-type', 'note': 'Equal type BluetoothSocket ≠ same object identity across paths'}`
- `{'path': 'PATH-000004', 'socket_object': 'socket:S1', 'rule': 'REJECTED: merge-by-type', 'note': 'Equal type BluetoothSocket ≠ same object identity across paths'}`
