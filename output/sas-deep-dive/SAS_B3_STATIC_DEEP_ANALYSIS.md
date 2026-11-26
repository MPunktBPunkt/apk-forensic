# SAS/B3 Static Deep Dive – APK-interne Auflösung der B3-Authentifizierung

**Date:** 2026-11-26  
**APK:** `de.bmw.connected` 6.0.0.4962  
**APK_SHA256:** `b1135e357b62a1f54b3b791609684cb54a184fa29c0e65a3f80e58ee22f496bd`  
**Method:** DEX method/xref/bytecode (androguard); B3 wire = search anchor only  
**RUNTIME:** `INPUT_MISSING` · **WIRE:** available as external reference only

---

## 1. Executive Summary

Die untersuchte APK enthält einen **statisch geschlossenen Java-/Binder-/Etch-Authentifizierungspfad**:

`CarSecurityManager.login` → Zertifikat-`byte[]` → `SasAdapter.getChallenge` → `RemoteBMWRemotingServer.sas_certificate` → Challenge-`byte[]` → `ICarSecurityService.signChallenge` → Response-`byte[]` → `SasAdapter.login` → `sas_login`.

Die eigentliche Signatur endet in **JNI** (`AudioModule.g` → `libaudio.so`).  
Die Kante **Etch-TcpTransport → BclConnection → AccessorySocket** für dieselben `sas_*`-Bytes ist **statisch nicht geschlossen** (`SAS_ACCESSORY_LINK = NOT_PROVEN`).

**Verdict-Klasse:** `PARTIALLY_CLOSED` (+ `JNI_NATIVE` auf Crypto).

---

## 2. Ausgangslage

### SAS SearchPlan (statisch, vorangegangen)

SearchPlan `sas_authentication_investigation` (`PLAN_SHA256` `9c81b949…`) fand u.a. `SasAdapter`, `SAS_ADAPTER`, Remoting-/Error-Strings, Crypto-/Accessory-Treffer — **ohne** geschlossenen End-to-End-Datenfluss (`output/sas-searchplan/`).

### B3 Wire Evidence (Anker, nicht APK-FACT)

Beobachtete Wire-Sequenz (extern): Etch → `sas_certificate` → Challenge → Signatur/Response → `sas_login`.

### Offene Kanten vor diesem Deep Dive

- Remoting-Symbole vs. Security/Crypto vs. Accessory: Join `NOT_PROVEN`
- Keine Methodenauflösung `sas_certificate` / `signChallenge` / Caller

---

## 3. B3 Reference Model (Anker)

| Op | Rolle im Wire-Modell |
|---|---|
| `sas_certificate` | Zertifikat senden, Challenge empfangen |
| `_result_sas_certificate` | Challenge-Bytes |
| challenge | Input für Signing |
| `signChallenge` | Response erzeugen |
| `sas_login` / `_result_sas_login` | Response einloggen |

Diese Namen dienten nur der **gezielten APK-Suche**, nicht der FACT-Klassifikation.

---

## 4. APK Candidate Inventory

| Kandidat | Klasse | Status |
|---|---|---|
| `SasAdapter` | `…/remoting/SasAdapter` | Interface **FACT** |
| Impl | `EtchCarConnection$2` | **FACT** |
| Orchestrator | `CarSecurityManager.login` | **FACT** |
| Binder | `ICarSecurityService` / `CarSecurityService` | **FACT** |
| Native facade | `SecurityModule` → `AudioModule` | **FACT** |
| Etch RPC | `RemoteBMWRemotingServer.sas_*` | **FACT** + Caller |
| Etch types | `ValueFactoryBMWRemoting._mt_…_sas_*` / `_result_*` | **FACT** |
| `CryptoUtil` | AES/XOR | **FACT** (nur P7B-Decrypt-Pfad) |
| BCL | `BclConnection` → `AccessorySocket` | **FACT** (separater Stack) |

---

## 5. SAS Candidate Resolution

### 5.1 `SasAdapter` (Interface)

```text
getChallenge([B)[B
login([B)V
logout()V
updateCrl([B)V
```

### 5.2 Resolution `SAS_ADAPTER`

`CarSecurityManager.<init>`:

```text
CarContext.getCarConnection()
  → CarConnection.getService("SAS_ADAPTER")
  → check-cast SasAdapter
  → field mSasAdapter
```

`EtchCarConnection.getService("SAS_ADAPTER")` liefert `mSasAdapter` (= `EtchCarConnection$2`).  
**DYNAMIC_DISPATCH** am Interface; unter Etch-`CarConnection` ist die Impl eindeutig.

### 5.3 `EtchCarConnection$2` (Impl)

| Methode | Callee |
|---|---|
| `getChallenge([B)[B` | `RemoteBMWRemotingServer.sas_certificate([B)[B` |
| `login([B)V` | `sas_login([B, VersionInfo)` mit `VersionInfo = null` |

**Nicht** nur Symbol: konkrete Caller existieren.

---

## 6. Certificate Flow

```text
CarSecurityService.getCertificateContainerFromPackage(appName)
  → CarAssetManagerAndroid.openP7BFile()
  → CryptoUtil.decodeWithAes([B)          # AES decrypt container
  → SecurityModule.addAndVerifyCertificateFromPackage
  → AudioModule.e(I [B)   [native]

CarSecurityManager.login:
  ICarSecurityService.getCertificates(handle)[B
    → CarSecurityService$1 → SecurityModule.getCertificates
    → AudioModule.f(I)[B   [native]
  → SasAdapter.getChallenge(certBytes)
```

**Klassifikation:** Cert-Container-AES = **FACT**. Cert-Export-Inhalt nach JNI = **FACT** bis Boundary, Bytes selbst **UNKNOWN**.

---

## 7. Challenge Flow

```text
certBytes
  → SasAdapter.getChallenge(certBytes)          [interface]
  → EtchCarConnection$2.getChallenge
  → RemoteBMWRemotingServer.sas_certificate
  → _Async._begin_sas_certificate:
       Message(type=_mt_…_sas_certificate)
       put(_mf_data, byte[])
       _begincall → Mailbox
  → _end_sas_certificate:
       _endcall(_mt_…__result_sas_certificate) → byte[] challenge
  → zurück an CarSecurityManager.login
  → ICarSecurityService.signChallenge(handle, challenge)
```

**A–E (Brief §6):**  
A Symbol+Caller (**nicht** nur generiert unbenutzt) · B Caller = `EtchCarConnection$2` / `CarSecurityManager` · C cert `byte[]` von `getCertificates` · D Return → lokale Variable → `signChallenge` · E ja.

---

## 8. Crypto / Signing Flow

```text
ICarSecurityService.signChallenge(J [B)[B
  → Binder Stub/Proxy onTransact
  → CarSecurityService$1.signChallenge
  → SecurityModule.signChallenge(I [B)[B
  → AudioModule.g(I [B)[B     # public static native
       ↑ System.loadLibrary("audio") → libaudio.so
```

| Frage | Antwort | Class |
|---|---|---|
| Gibt es Crypto-Aufruf auf Challenge? | Ja, benannt `signChallenge`, implementiert native | **FACT** |
| Algorithmus (RSA/AES/…)? | Nicht in Java sichtbar | **UNKNOWN** / `JNI_NATIVE` |
| Nutzt SAS `CryptoUtil` zum Signieren? | Nein nachweisbar | **REJECTED** / `NOT_PROVEN` |

`CryptoUtil` = **CO-LOCATION** + getrennter P7B-AES-Pfad — **kein** Challenge-Signing-Flow.

---

## 9. Response Flow

```text
AudioModule.g → byte[] response
  → Binder return
  → CarSecurityManager.login
  → SasAdapter.login(response)
  → EtchCarConnection$2.login
  → RemoteBMWRemotingServer.sas_login(response, null)
```

**H–I:** Response-`byte[]` entsteht an JNI-Grenze; Übergabe an `sas_login` ist **statisch geschlossen**.

---

## 10. sas_login Flow

```text
_begin_sas_login:
  Message(_mt_…_sas_login)
  put(_mf_data, byte[])
  put(_mf_version, VersionInfo|null)
  _begincall
_end_sas_login:
  _result_sas_login → String
  (von EtchCarConnection$2.login verworfen; Methode void)
```

`sas_login` ist Etch-RPC mit **DeliveryService** — **FACT**.

---

## 11. BCL / Etch / Accessory Flow

### Etch-Transport (SAS-Pfad)

```text
EtchCarConnection.<init>
  mConnectionString = format("tcp://%s:%d?Packetizer.maxPktSize=8388608&TcpTransport.noDelay=true", …)
connect():
  BMWRemotingHelper.newServer(mConnectionString, …)
    → TransportFactory.getTransport(uri)
    → DefaultDeliveryService
    → RemoteBMWRemotingServer
```

### BCL → Accessory (eigener Stack)

```text
BclConnection.write([B Z) / initSession / …
  → AccessorySocket.write([B I I)     # interface
BclConnection.internalread → AccessorySocket.read
```

Konkrete Socket-Klasse (`BtAccessorySocket` / USB / Eth): **DYNAMIC_DISPATCH**.

### Join Etch → BCL

Kein Klassen-/Invoke-Pfad gefunden, der `sas_certificate`/`sas_login`-Message-Bytes an `BclConnection.write` übergibt.  
`127.0.0.1`-Listener bei Accessory-Services und Etch-`tcp://` sind höchstens **INFERENCE** (lokaler Bridge), nicht **FACT**-Datenfluss.

**SAS_ACCESSORY_LINK = NOT_PROVEN**

---

## 12. End-to-End Static Graph

```text
CarContext / performLogin
    │
    ▼
CarSecurityManager.login()                          [ORCHESTRATOR]
    │
    ├─► ICarSecurityService.createSecurityContext     [Binder]
    │         └─► SecurityModule → AudioModule.c      [JNI]
    │
    ├─► getCertificates(handle) → byte[] cert         [JNI f]
    │         │
    │         ▼
    ├─► SasAdapter.getChallenge(cert)                 [DYNAMIC_DISPATCH]
    │         └─► EtchCarConnection$2
    │               └─► sas_certificate → Etch Mailbox
    │                     └─► byte[] challenge
    │
    ├─► signChallenge(handle, challenge) → byte[] resp [JNI g]  ← STATIC_BOUNDARY
    │
    └─► SasAdapter.login(resp)
              └─► sas_login → Etch DeliveryService
                    │
                    ▼
              TcpTransport (tcp://host:port)
                    │
                    ✗ NOT_PROVEN static edge
                    │
              BclConnection.write ──► AccessorySocket   [separater FACT-Pfad]
```

---

## 13. Static ↔ B3 Correlation Matrix

| Element | APK STATIC | B3 WIRE | STATIC↔WIRE |
|---|---|---|---|
| `sas_certificate` | FACT (Methode+Caller) | beobachtet | CORRELATED (Symbol) |
| certificate bytes | FACT (Typ `byte[]`, Herkunft JNI) | beobachtet | NOT_CORRELATED (Bytes) |
| challenge | FACT (Return `sas_certificate`) | beobachtet | CORRELATED (Rolle) |
| challenge consumer | FACT (`signChallenge`) | indirekt | CORRELATED (Rolle) |
| `signChallenge` | FACT (Binder+native) | erwartet/korreliert | CORRELATED (Symbol); Algo UNKNOWN |
| response bytes | FACT → `sas_login`-Arg | beobachtet | CORRELATED (Rolle); Bytes NOT_CORRELATED |
| `sas_login` | FACT (Methode+Caller) | beobachtet | CORRELATED (Symbol) |
| BCL transport | FACT (Klasse+Accessory-Link) | beobachtet | NOT_CORRELATED zu sas_*-Bytes |
| Etch destination | FACT (RemoteBMWRemotingServer) | beobachtet | CORRELATED (Stack) |
| Accessory transport | FACT (über BCL) | beobachtet | NOT_CORRELATED zu sas_*-Bytes |

---

## 14. Open Edges

| ID | Kante | Status |
|---|---|---|
| OE1 | `AudioModule.g` / `libaudio.so` Signing | `JNI_NATIVE` OPEN |
| OE2 | Etch TcpTransport → `BclConnection.write` | `NOT_PROVEN` |
| OE3 | B3-Wire-`byte[]` ↔ APK-Value | `NOT_CORRELATED` / `INPUT_MISSING` |
| OE4 | Konkrete `AccessorySocket`-Impl | `DYNAMIC_DISPATCH` |

---

## 15. Analyzer / JNI / Dynamic Dispatch Boundaries

```text
SecurityModule.signChallenge(I [B)[B
    ↓
AudioModule.g(I [B)[B     native
    ↓
libaudio.so
    ↓
OPEN
```

Weitere Boundaries: `SasAdapter` Interface; `AccessorySocket` Interface; Runtime dieser APK fehlt.

---

## 16. Evidence Classification

| Claim | Class |
|---|---|
| SAS/Etch/Binder-Auth-Orchestrierung existiert | **FACT** |
| `sas_certificate`/`sas_login` haben Caller | **FACT** |
| Challenge → signChallenge → Response → sas_login (Java) | **FACT** |
| Signing-Algorithmus = RSA4096 o.ä. | **NOT_PROVEN** / **REJECTED** ohne JNI |
| SAS nutzt CryptoUtil zum Signieren | **REJECTED** |
| SAS-Bytes laufen über BclConnection/AccessorySocket | **NOT_PROVEN** |
| B3-Op-Namen entsprechen APK-Etch/Binder-Symbolen | **CORRELATION** |
| B3-Bytes = APK-Parameterbytes | **NOT_CORRELATED** |
| Etch und BCL teilen localhost-Bridge | **HYPOTHESIS** / **INFERENCE** |

---

## 17. Final Verdict

**Ergebnis B (+ D):** PARTIALLY_CLOSED — Java/Etch/Binder-Kette geschlossen; Crypto-JNI und Etch→BCL/Accessory offen.

### Q1–Q10

| Q | Antwort |
|---|---|
| **Q1** Ist SAS-Auth statisch geschlossen? | **Teilweise.** Bis `sas_login`-Etch-Aufruf ja; native Crypto + Transport zur Accessory **nein**. |
| **Q2** challenge → signChallenge → response? | **Ja** (Java/Binder); Algorithmus **JNI OPEN**. |
| **Q3** response → sas_login? | **Ja.** |
| **Q4** sas_login ↔ Etch/BCL? | **Etch: Ja.** **BCL: NOT_PROVEN.** |
| **Q5** Etch/BCL ↔ AccessorySocket? | **BCL→AccessorySocket: Ja.** **Etch→BCL: NOT_PROVEN.** |
| **Q6** SAS ↔ BMW-Accessory-Pfad? | **NOT_PROVEN** (`SAS_ACCESSORY_LINK`). |
| **Q7** Erste nicht geschlossene High-Value-Kante? | **OE2** Etch→BCL (parallel **OE1** JNI-Algo). |
| **Q8** Nur per Runtime schließbar? | OE2/OE3 (Session-Bridge + Byte-Identität); OE1 auch via Native-RE. |
| **Q9** B3-Bytearray ↔ APK-Value? | **Nein** (`NOT_CORRELATED`). |
| **Q10** Minimaler nächster Schritt? | Runtime-Hooks: `CarSecurityManager.login`, `sas_certificate`/`sas_login`, `BclConnection.write` **derselben** Session; optional `libaudio.so` JNI `g`. |

---

## 18. Next Step

1. **Runtime (bevorzugt für OE2/OE3):** Instrumentierung derselben APK — gleiche Session, gleiche `byte[]` von Challenge/Response bis Socket-Write.  
2. **Native (OE1):** `libaudio.so` Export/`JNI_OnLoad` für `AudioModule.g`.  
3. Keine weitere reine String-/Co-Location-Suche — die Java-Orchestrierung ist ausreichend aufgelöst.

---

## Appendix – Key method signatures

```text
CarSecurityManager.login()V
ICarSecurityService.getCertificates(J)[B
ICarSecurityService.signChallenge(J [B)[B
SasAdapter.getChallenge([B)[B
SasAdapter.login([B)V
RemoteBMWRemotingServer.sas_certificate([B)[B
RemoteBMWRemotingServer.sas_login([B Lde/bmw/idrive/BMWRemoting$VersionInfo;)Ljava/lang/String;
SecurityModule.signChallenge(I [B)[B
AudioModule.g(I [B)[B   native   // loadLibrary("audio")
CryptoUtil.decodeWithAes([B)[B   // P7B path only
BclConnection.write([B Z)V → AccessorySocket.write([B I I)V
```
