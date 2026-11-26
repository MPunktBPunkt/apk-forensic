# SAS / Authentication Forensic Analysis

**Date:** 2026-11-26  
**Tool:** apk-forensics 1.6.1  
**Mechanism:** Search Plan Builder → focused User SearchPlan → Resource Guard → `run_pipeline`

---

## 1. Investigation Goal

> Untersuche die APK auf statische Hinweise auf SAS bzw. eine SAS-artige Authentifizierungs-/Credential-Kommunikation und verfolge mögliche Challenge-, Response-, Credential-, Signatur- und Kryptographie-Flows bis zur Accessory-/Transport-Schicht, soweit die vorhandene statische Analyse dies unterstützt.

Hypothesized chain (investigation only, **not** assumed result):

```text
Accessory/Transport → bytes → parser → challenge/credential → crypto →
signature/response → encoder → write
```

**Method rule:** `"SAS"` / `authenticate()` / `sign()` are search targets or names — not BMW-SAS protocol FACT by themselves.

---

## 2. SearchPlan

| Field | Value |
|---|---|
| Name | `sas_authentication_investigation` |
| Kind | User plan |
| Path | `work/user-plans/sas_authentication_investigation.yaml` |
| Depth | focused standard (method_hops=4, buffer_hops=6, dataflow_depth=3) |
| Modules | search + dex_context/xref + bluetooth + evidence_graph + communication |
| correlation.enabled | false |

Copies: `output/sas-searchplan/sas_authentication_investigation.{yaml,normalized.json,provenance.json}`

---

## 3. PLAN_SHA256

```
9c81b949858f7c6b0eff0f680140d7bdec063d4a0ff374b810153f9514aa5956
```

---

## 4. APK_SHA256

| Field | Value |
|---|---|
| File | `de.bmw.connected-6.0.0.4962.apk` |
| Package | `de.bmw.connected` |
| Version | 6.0.0.4962 (4962) |
| SHA256 | `b1135e357b62a1f54b3b791609684cb54a184fa29c0e65a3f80e58ee22f496bd` |

---

## 5. Resource Guard

| Item | Value |
|---|---|
| Policy | `standard` |
| Estimate | ~11:00 / 1802 MiB (**HEURISTIC**) |
| Guard | **WARNING** |
| Proceed | `--allow-resource-warning` |
| Actual runtime | **286.3 s** |
| Actual peak RSS | **1247 MiB** |

`conservative` would REJECT — not used/overridden.

---

## 6. Search Hits (STATIC SEARCH HIT)

Exact `matched_text` (engine may classify string presence as FACT = “bytes exist”):

| Bucket | Notable exact hits | Interpretation |
|---|---|---|
| SAS | `SAS` / case variants many; contexts include `ERROR_RM_SAS_*`, `SAS_ADAPTER`, `SAS_MANAGER`, `SasAdapter`, “Failed to login to SAS” | **YES** remoting/SAS **naming** in DEX |
| AUTH | authenticate 102, authentication 27, credential(s) 14, token 177 (noisy) | AUTH-related strings present |
| Challenge/Response | challenge 8; `ERROR_RM_SAS_NO_CHALLENGE_RESPONSE`; verify/signature/sign (sign heavily noisy) | Challenge **vocabulary** present in SAS error strings |
| Crypto | Cipher/RSA/AES/… very large counts (many false-substring risks); **CryptoUtil** / `Cipher` XREFs are stronger | Crypto APIs present |
| Accessory | AccessorySocket 14, BtAccessorySocket 5, BclConnection 9, doBclHandshake 2, streams/ByteBuffer | Known accessory surface |

Isolated short tokens (`sign`, `token`, `Mac`) are **not** treated as protocol evidence.

---

## 7. Authentication Candidates

| ID | Static evidence | Notes | Class |
|---|---|---|---|
| AUTH-CAND-001 | Strings `ERROR_RM_SAS_*`, “Failed to login to SAS…”, `SAS_ADAPTER` / `SAS_MANAGER` | Remoting error/login vocabulary | SEARCH HIT / FACT (string) |
| AUTH-CAND-002 | Type string `…/remoting/SasAdapter` | Class name indicator | SEARCH HIT / FACT (string) |
| AUTH-CAND-003 | Strings authenticate / authentication / credential | Generic; many apps | SEARCH HIT only |

No closed static method-flow from these strings into AccessorySocket was established in this base scan.

---

## 8. Challenge/Response Candidates

| ID | Evidence | Class |
|---|---|---|
| CR-CAND-001 | `ERROR_RM_SAS_NO_CHALLENGE_RESPONSE` (DEX string) | SEARCH HIT / FACT (string) |
| CR-CAND-002 | exact `challenge` string hits (8) | SEARCH HIT |
| CR-CAND-003 | verify / signature / signed (counts inflated by short `sign`) | SEARCH HIT; **not** proven challenge-response protocol |

---

## 9. Credential Candidates

| ID | Evidence | Class |
|---|---|---|
| CRED-CAND-001 | credential / credentials strings | SEARCH HIT |
| CRED-CAND-002 | `ERROR_RM_SAS_CERTIFICATE`, `SAS.CertificateType`, `SAS_CERTIFICATE_TYPE*` | SEARCH HIT (certificate **naming** near SAS remoting) |
| CRED-CAND-003 | KeyStore / Certificate / PublicKey / PrivateKey string noise | C1-ish API **names** only unless XREF-backed |

---

## 10. Crypto Candidates

| ID | Evidence | Crypto class | Transport link | Auth link |
|---|---|---|---|---|
| CRYPTO-CAND-001 | `CryptoUtil.encodeWithAes` / `decodeWithAes` + XREF to `Cipher.getInstance` / `doFinal` / `SecretKeySpec` | **C1 FACT** (crypto API used in method) | **NO** closed link in this run | **NO** closed SAS dataflow |
| CRYPTO-CAND-002 | `…/remoting/security/util/Utils.encryptSymmetric` DEX context | **C1 FACT** | **NO** closed accessory link here | Package near remoting/SAS **INFERENCE only** (proximity ≠ flow) |
| CRYPTO-CAND-003 | Mass RSA/AES/Cipher string hits | SEARCH HIT / noisy | NO | NO |

**C3/C4** (crypto processes accessory bytes / result written back): **NOT closed** by this pipeline.

---

## 11. Accessory / Transport Paths

| Item | Result | Class |
|---|---|---|
| RFCOMM targets | 4 | FACT |
| Evidence paths | 13 | matches prior BMW baseline |
| Strongest | PATH-000001 `COMBINED_COMMUNICATION_PATH` | INFERENCE / medium |
| Target | `BtAccessorySocket.connectAccessory()` | FACT method id |
| Callers | `LegacyBtHandler.doBclHandshake` → `openAccessorySocket` → `connectAccessory` | FACT edges; **protocol_semantics UNKNOWN** |
| Comm paths | 4 (`BtAccessorySocket` read/write ↔ byte[]/streams) | INFERENCE |

`doBclHandshake` is a **DEX identifier**. It is **not** SAS proof.

---

## 12. Object / Dataflow

| Item | Result |
|---|---|
| Dataflow paths | 4 |
| Dataflow nodes | 415 |
| Socket / stream transfers | 91 / 287 |
| DEX contexts | 27 |
| XREF candidates | 974 |

Object flow supports accessory byte read/write reconstruction. It does **not**, in this report, close SAS remoting ↔ accessory byte identity.

---

## 13. Input → Crypto → Output Candidates

| Pattern | Status |
|---|---|
| Accessory read → … → CryptoUtil/Cipher → … → Accessory write | **NOT closed** (NOT_PROVEN / open edge) |
| Remoting SAS login vocabulary ↔ remoting security Utils | **PARTIAL name/package proximity** only |
| BCL handshake path ↔ accessory connect | **YES** (prior/known accessory INFERENCE path) — **SAS link UNKNOWN** |

---

## 14. Authentication State

Strings / errors: `ERROR_RM_SAS_ALREADY_LOGGED_IN`, `…_SESSION_NOT_LOGGED_IN`, `…_LOGIN_ATTEMPTS`, “Failed to login to SAS…”.

→ **SEARCH HIT** for login/session **vocabulary**.  
→ **No** reconstructed branch/state machine tied to accessory bytes in this base scan → Auth state **PARTIAL** (names) / flow **UNKNOWN**.

---

## 15. Evidence Graph

| Item | Value |
|---|---|
| Evidence paths | 13 |
| Canonical nodes | 191 |
| Strongest | PATH-000001 INFERENCE |
| protocol_semantics | UNKNOWN |
| runtime_execution | UNKNOWN |

---

## 16. Runtime

**INPUT_MISSING**

---

## 17. Wire

External LAB_B3_TCP_FULLAUTH may exist in workspace history as **separate** wire evidence.  
**Not joined** to this static job. Same-session: **UNKNOWN**.

---

## 18. Correlation

**NOT_EXECUTED** (no runtime session; correlation flag off in plan)

---

## 19. Open Edges

| Edge | Status |
|---|---|
| SAS remoting strings → AccessorySocket byte flow | NOT_PROVEN |
| CryptoUtil ↔ Accessory read/write bytes | NOT_PROVEN |
| Challenge/response object reconstruction | NOT_PROVEN / NOT analyzed deeply |
| Structured values / diagnose-* auth objects | NOT_PRODUCED_BY_CURRENT_WORKBENCH_PIPELINE |
| Runtime execution of SAS login | INPUT_MISSING |
| Wire same-session join | NOT_EXECUTED |
| Concrete AccessorySocket receiver impl uniqueness | DYNAMIC_DISPATCH / NOT_PROVEN (prior) |

---

## 20. SAS Assessment (A–J)

| # | Question | Answer |
|---|---|---|
| A | SAS search hits | **YES** |
| B | Authentication code | **YES** (strings + remoting login messages; method-level auth flow not fully closed) |
| C | Challenge/Response code | **PARTIAL** (SAS error string `NO_CHALLENGE_RESPONSE`; no closed CR object flow) |
| D | Credential/Key processing | **PARTIAL** (certificate/SAS cert type strings; KeyStore/Certificate noise) |
| E | Crypto processing | **YES** (CryptoUtil AES / Cipher XREF = C1) |
| F | Crypto ↔ authentication data | **UNKNOWN / PARTIAL** (remoting security Utils near SAS naming; no closed dataflow) |
| G | Auth ↔ Accessory transport | **UNKNOWN / PARTIAL** (both present; **no closed join** in this run) |
| H | Auth result ↔ outbound write | **NOT_PROVEN** |
| I | Authentication state | **PARTIAL** (logged-in / login-error vocabulary) |
| J | SAS assignment | **NOT_PROVEN** |

Closest prior pattern fit: **F** — indicators + crypto + accessory exist separately; SAS-as-accessory-auth **not** statically proven.

---

## 21. Static Analysis Boundary

| Capability | Status |
|---|---|
| Base static scan | AVAILABLE (this report) |
| Extended diagnose-* / structured values | **NOT_PRODUCED_BY_CURRENT_WORKBENCH_PIPELINE** (≠ “not found”) |
| Full androguard XREF graph | Limited (dex_context partial warning) |
| Native deep crypto | BOUNDARY if only in `.so` (not primary SAS hits here — DEX remoting strings dominate) |
| Runtime / wire | Separate layers |

---

## 22. Evidence table

| Candidate | Static Evidence | Transport Link | Crypto Link | Outbound Link | Classification |
|---|---|---|---|---|---|
| AUTH-CAND-001 SAS remoting errors/login | YES (strings) | NO closed | NO closed | NO | SEARCH HIT / FACT(string) |
| AUTH-CAND-002 SasAdapter type | YES | NO closed | NO closed | NO | SEARCH HIT / FACT(string) |
| CR-CAND-001 NO_CHALLENGE_RESPONSE | YES | NO closed | NO | NO | SEARCH HIT / FACT(string) |
| CRYPTO-CAND-001 CryptoUtil AES | YES (XREF Cipher) | NO closed | YES (C1) | NO closed | FACT (API use) |
| CRYPTO-CAND-002 remoting encryptSymmetric | YES (DEX ctx) | NO closed | YES (C1) | NO closed | FACT (API use) / INFERENCE(package) |
| PATH-000001 accessory+BCL handshake callers | YES | YES (accessory) | NO | connect/write surface | INFERENCE (transport) |
| PATH-COMM-000001..4 read/write byte[] | YES | YES | NO | YES (write paths) | INFERENCE |

---

## 23. Comparison with prior BMW evidence

| Topic | Prior / external | This SAS plan |
|---|---|---|
| AccessorySocket / Bt paths | Known FACT/INFERENCE | Reconfirmed |
| doBclHandshake | Known name in caller chain | Reconfirmed; **≠ SAS** |
| VALUE-V001 / decodeVersion | Prior static FACT | Not re-run (diagnose-* not automatic) |
| iAP2 plan | No iAP2 protocol proof | Orthogonal |
| LAB_B3 FULLAUTH wire | EXTERNAL wire | Not correlated |
| SAS remoting strings | Not emphasized in iAP2 report | **Newly centered SEARCH HITs** |

External/prior SAS knowledge must **not** be copied into APK FACT. APK contributes its own string/API/path evidence above.

---

## 24. Conclusion

**FACT**

- DEX contains remoting SAS naming (`ERROR_RM_SAS_*`, `SasAdapter`, `SAS_ADAPTER` / `SAS_MANAGER`, login-to-SAS messages).
- Crypto APIs used in `CryptoUtil` / remoting `encryptSymmetric` (C1).
- Accessory Bluetooth communication paths exist (`BtAccessorySocket` read/write; PATH-000001 with `doBclHandshake` callers).

**INFERENCE**

- Remoting package hosts both SAS-named types and security Utils — **suggests** a remoting/SAS security surface, not a proven accessory byte protocol.
- Accessory transport stack remains the same BMW Connected surface as prior analyses.

**NOT_PROVEN**

- Closed Input → SAS-auth → Crypto → Output via AccessorySocket.
- That remoting “SAS” **is** the vehicle accessory authentication protocol.
- Runtime/wire same-session SAS authentication (INPUT_MISSING / NOT_EXECUTED).

**SAS_VERDICT: NOT_PROVEN**  
**AUTH_VERDICT: authentication-related static indicators YES; accessory-bound auth flow NOT_PROVEN**
