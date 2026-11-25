# VALUE-V001 Forensic Analysis (Static Closure)

**Status:** `STATIC_ANALYSIS_COMPLETED`  
**Boundary:** `STATIC_ANALYSIS_BOUNDARY = REACHED`  
**Protocol semantics:** `UNKNOWN`  
**Runtime:** `INPUT_MISSING` / `NOT_EXECUTED` (no runtime facts invented)

```text
AccessorySocket.read([BII)I     ← first open edge (DYNAMIC_DISPATCH)
        ↓ FACT
BclConnection.internalread
        ↓ FACT
BclConnection.readPacket → Packet.mData [B
        ↓ FACT
Info.decodeVersion([B)S
        = ByteBuffer.wrap(buf, 0, 2).getShort()   ← BIG_ENDIAN
        ↓ FACT
BclConnection.mVersion S
        ↓ FACT
loads / clamp(≤4) / branches / mIsSingleSA / write gating
        ↓
encode(mVersion)→wire bytes     = NOT_PROVEN
```

---

## A. Identity

| Field | Value |
|---|---|
| VALUE | **VALUE-V001** |
| Class | `com.bmwgroup.connected.core.services.accessory.bcl.packet.Info` |
| Method | `decodeVersion` |
| Descriptor | `([B)S` |
| Full | `Lcom/bmwgroup/connected/core/services/accessory/bcl/packet/Info;->decodeVersion([B)S` |
| Access | `public static` |
| APK | `artifacts/de.bmw.connected-6.0.0.4962.apk` |
| Package | `de.bmw.connected` `6.0.0.4962` |
| SHA256 | `b1135e357b62a1f54b3b791609684cb54a184fa29c0e65a3f80e58ee22f496bd` |
| DEX | `classes.dex` (sha256 prefix `80ca4defdaafd4d8`) |
| code_offset | `4418708` |
| Instructions | 7 |
| Classification | **FACT** |

---

## B. Decoder

### Transformation (closed)

```text
VERSION_OFFSET = 0          // Info.<clinit> FACT
slice_length   = 2          // const/4 FACT

return ByteBuffer.wrap(input, VERSION_OFFSET, 2).getShort();
// byte order: BIG_ENDIAN (ByteBuffer.wrap default; no order() call) FACT
// equivalent indices: input[0], input[1]
```

### Instructions

```text
0000  sget v0, Info;->VERSION_OFFSET I
0001  const/4 v1, 2
0002  invoke-static v2, v0, v1, ByteBuffer;->wrap([B I I)Ljava/nio/ByteBuffer;
0003  move-result-object v0
0004  invoke-virtual v0, ByteBuffer;->getShort()S
0005  move-result v0
0006  return v0
```

### Helpers

| Helper | Role | Resolution |
|---|---|---|
| `ByteBuffer.wrap([BII)` | slice at offset 0, len 2 | platform API — FACT |
| `ByteBuffer.getShort()` | read BE short | platform API — FACT |

No app-level helper beyond platform APIs. No native call inside `decodeVersion`.

Null/length checks: **none inside method** (runtime exceptions possible — not handled here).

**Byte-transformation closed:** YES.

---

## C. Input Provenance

### Closed chain (to interface)

| Step | Edge | Class |
|---|---|---|
| 1 | `AccessorySocket.read([BII)I` → `BclConnection.internalread` | FACT (interface invoke) |
| 2 | `internalread` ← `readPacket` (header 8 B, then payload `mDataLen`) | FACT |
| 3 | `readPacket` → `Packet.mData [B` | FACT |
| 4 | `BclConnection$2.run` `iget-object Packet.mData` (idx 68) | FACT |
| 5 | `invoke-static decodeVersion(mData)` (idx 69) | FACT |

### Caller context (`BclConnection$2.run`)

- `readPacket(Packet)` then require `mData != null`
- Command compared to `Command.HANDSHAKE` (DEX name only — protocol meaning **UNKNOWN**)
- Then `decodeVersion(mData)` → store `mVersion`

### Transport relation

- **Resolved:** bytes enter via `AccessorySocket` interface read path.  
- **Unresolved:** concrete implementing class / BT vs USB peer.  
- **Must not claim:** “Bluetooth payload” as FACT for VALUE-V001 without further evidence-graph closure.

**byte[] provenance closed:** PARTIAL (closed to interface; open at DYNAMIC_DISPATCH).

---

## D. Forward Application Flow

| Step | Detail | Class |
|---|---|---|
| Store | `iput-short` → `BclConnection.mVersion S` (idx 71) | FACT |
| Clamp | if `mVersion > 4` then `mVersion = 4` | FACT |
| Branch | `mVersion == 4` ∧ `mSrcPort == 1` → `mIsSingleSA = true` | FACT |
| State | `setState("GOT_HANDSHAKE")` | FACT (string = identifier only) |
| Write consumer | `write([BZ)` uses `mVersion` as index into `MAX_HU_BUF_SIZE[]` for gating/ack/NOP | FACT |

**mVersion usage closed:** YES (direct consumers in `run` + `write`).

---

## E. Roundtrip

| Question | Result |
|---|---|
| `Info.encodeVersion` | **NOT_FOUND** |
| `Packet.encode(...)` exists | FACT (generic packet builder) — linkage to `mVersion` bytes **NOT_PROVEN** |
| `mVersion` influences `write` | FACT (control / buffer-limit index) |
| `mVersion` re-encoded into written payload | **NOT_PROVEN** |

v1.5 `ROUNDTRIP_FROM_FIELD` near `AccessorySocket.write` = baseline **CORRELATION** heuristic. Manual review: written buffer is the separate `[B` argument or `sNOP`, not the version short. Refined: **CONTROL_PATH_CORRELATION**; value re-encode roundtrip **NOT_PROVEN**.

`ROUNDTRIP = NOT_PROVEN` (not “NO_ROUNDTRIP_EXISTS”).

---

## F. Evidence Matrix (summary)

| ID | FROM → TO | RELATION | CLASS | LIMIT |
|---|---|---|---|---|
| E001 | DEX → `decodeVersion` | identity | FACT | — |
| E002 | `<clinit>` → `VERSION_OFFSET=0` | init | FACT | — |
| E003 | `byte[]` → `short` | transform | FACT | — |
| E004 | `Packet.mData` → decode arg | param | FACT | — |
| E005 | `readPacket` → `mData` | buffer fill | FACT | — |
| E006 | `AccessorySocket.read` → buffer | interface read | FACT | DYNAMIC_DISPATCH |
| E007 | return → `mVersion` | store | FACT | — |
| E008 | `mVersion` → branches/state | control | FACT | — |
| E009 | `mVersion` → write gating | control index | FACT | — |
| E010 | `mVersion` → outbound Info bytes | re-encode | NOT_PROVEN | — |
| E011 | VALUE ↔ LAB_B3 packet | runtime/wire join | REJECTED / NOT_EXECUTED | SESSION_MISMATCH |
| E012 | name → protocol meaning | semantics | REJECTED | — |

---

## G. Boundary

**`STATIC_ANALYSIS_BOUNDARY = REACHED`**

| Field | Value |
|---|---|
| first_unclosed_edge | `AccessorySocket.read([BII)I` → concrete transport implementation / peer bytes |
| boundary_type | `DYNAMIC_DISPATCH` |
| secondary | `RUNTIME_LIMIT` / `INPUT_MISSING` for observed execution & bytes |
| secondary | wire identity requires same-session capture (`SESSION_MISMATCH` if using LAB_B3 alone) |
| required_external_evidence | concrete `AccessorySocket` impl binding; Android runtime hook on `decodeVersion`; optional same-session wire |

No new analyzer layer. Stop here for static deepening.

### Wire control (optional, non-runtime)

Static need: payload length ≥ 2 at offset 0.  
LAB_B3: **COMPATIBILITY_CANDIDATE** only (`CORRELATION/CANDIDATE`).  
**Not claimed:** `VALUE-V001 == B3 packet X`.

---

## Closing answers (§16)

1. `decodeVersion([B)S` fully reconstructed? **YES**  
2. `byte[]` provenance closed? **PARTIAL**  
3. Byte transformation closed? **YES**  
4. `mVersion` usage closed? **YES**  
5. Roundtrip encode/write proven? **NO**  
6. First remaining open edge? **`AccessorySocket.read` → concrete transport (DYNAMIC_DISPATCH)**; runtime bytes also missing  
7. Can that edge be closed statically? **UNKNOWN** (needs impl resolution / more XREF than this bounded pass)  
8. Required external evidence? Concrete socket impl + runtime/wire if identity required  
9. Static analysis boundary reached? **YES**

---

## Artefacts

- `VALUE_V001_FORENSIC_ANALYSIS.json` / `.md`
- `raw/` — DEX instruction dumps for `decodeVersion`, related `Info.*`, `BclConnection$2.run`, `readPacket`, `write`, `internalread`, `Packet.encode`

Catalog value count unchanged: **24**. No engine/schema change. No runtime fakes.
