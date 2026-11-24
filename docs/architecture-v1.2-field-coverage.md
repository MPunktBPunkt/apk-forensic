# Architecture — Field/Alias Coverage (v1.2)

## Question answered

Why do 9/13 Transport PATH-* show `MAX_FIELD_HOPS` on BMW Connected v1.1?

## Diagnosis (FACT from persisted transfers)

Repeated `field_store` / `field_load` of the **same** fields (`mBtSocket`, `mInputStream`, `mOutputStream`)
burned the hop counter. Chains are **not** deep Holder→Holder→Socket nesting.

Also: stream objects previously **inherited** the socket’s `field_hops`, so their first
store often hit the limit immediately. Register reuse could attribute unrelated `iput`s
to a tracked stream (same type ≠ same object).

**Case:** B/C — wrapper/same-field re-entry + object-identity/hop accounting  
**Not:** A (true deep field depth) as the primary cause  
**Action:** fix semantics; **do not** raise default `max_field_hops`

## Field-hop rules (v1.2)

| Event | Effect on `field_hops` |
|---|---|
| First store to field F | +1; append F to `field_chain` |
| Re-store/load same F | 0 (alias continuation) |
| Store to new field G | +1; append G |
| Re-enter earlier field in chain | `CYCLE_GUARD` |
| `getInputStream` / wrapper new object | new identity; hops=0 |
| `move-object` | proven alias; no hop |
| `move-result` overwrite of tracked reg | local identity ends |
| same Java type alone | **not** an alias |

## Defaults

`bluetooth.max_field_hops` default remains **2**.

## Protocol

`protocol_semantics = UNKNOWN` unchanged.
