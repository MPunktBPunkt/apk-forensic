# Architecture — v1.4 Buffer-to-Semantics Closure

## Question

Why was T5 (decoder/encoder) **0/13** after v1.3 transport closure?

## Answer (evidence-based)

**Primary: Hypothesis B — analyzer/modeling gap**, with **D — alternative byte modeling**.

- v1.3 retained only transport wrappers (`BtAccessorySocket.read` → `InputStream.read`).
- Real consumers call `AccessorySocket;->read` from `BclConnection.internalread` / `readPacket`.
- `Packet.decode*` performs `ByteBuffer.wrap` + `getShort`/`getInt` (FACT byte processing) and field stores (STATE_MUTATION).
- v1.3 also mis-tagged `read` length `move-result` as `PRIMITIVE_DECODE` (corrected to `READ_LENGTH`).

**Hypothesis A (true APK end) is REJECTED** for the eight CASE-C paths: static byte processing exists above the interface.

## T5 operational definition

T5 = tracked buffer identity has a FACT edge into:

- `aget-byte` / `aget`
- `ByteBuffer.wrap` / `get*` / `put*`
- `String([B)`
- parse/decode-named invoke **with** buffer dataflow

T5 excludes: read length; names alone; protocol claims.

## S0–S4

Semantic class for buffer→processing chains. **S4 ≠ protocol found.**

## Limits

`max_field_hops=2` unchanged. Seed expansion is not a SearchPlan limit raise.
