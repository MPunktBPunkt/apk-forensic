# T5 Decoder Audit (v1.4)

**Requires:** Tracked byte[]/ByteBuffer identity has a FACT edge into at least one of: aget-byte/aget; ByteBuffer.wrap/get*/put*; String([B); or a parse/decode-named invoke that also receives the tracked buffer (dataflow_role).

**Excludes:** InputStream/AccessorySocket read()I or read([B)I *length* move-result (READ_LENGTH); method/class names alone; copy-only without further processing; protocol/message meaning claims.

**v1.3 saw:** Transport wrapper read/write; BYTE_ARRAY arg; mis-tagged PRIMITIVE_DECODE from read length; PATH-COMM INBOUND_PRIMITIVE without real byte ops.

**v1.3 could not see:** Interface consumers (AccessorySocket;->read in BclConnection); Packet.decode* ByteBuffer.getShort/getInt; aget-byte loops; state mutation onto Packet fields after decode.

## Root cause of T5=0

- Primary: `B_ANALYZER_MODELING_GAP`
- Transport wrappers (BtAccessorySocket.read) only forward to InputStream; no aget/ByteBuffer in retained set.
- Real consumers call AccessorySocket;->read via BclConnection.internalread / readPacket — not in v1.3 seed set.
- Packet.decode* performs ByteBuffer.wrap + getShort/getInt (FACT byte processing) outside retention.
- v1.3 T5 gate required named DECODER nodes; READ_LENGTH was wrongly counted as primitive_decoding but not T5.

- Not primary: A_TRUE_APK_END — byte processing exists statically above the interface.

## v1.4 after expansion

- **byte_processing**: `0`
- **state_mutations**: `0`
- **decoder_candidates**: `0`
- **primitive_decoding**: `0`
- **read_lengths**: `1`
- **path_comm**: `2`

Protocol semantics: **UNKNOWN**
