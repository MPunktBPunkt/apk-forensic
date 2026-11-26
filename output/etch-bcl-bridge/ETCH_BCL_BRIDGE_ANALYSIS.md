# Etch → BCL Transport Bridge Deep Dive

**Date:** 2026-11-26  
**APK:** `de.bmw.connected` 6.0.0.4962  
**APK_SHA256:** `b1135e357b62a1f54b3b791609684cb54a184fa29c0e65a3f80e58ee22f496bd`  
**Plan:** `etch_bcl_transport_bridge` · `plan_sha256` `f6425312bd7a6f8a070fed3a371fcc74ccdf9b5a90a0e8bf146cb8a201d5d4db`  
**RUNTIME:** `INPUT_MISSING` · **B3 bytes:** `NOT_CORRELATED`

---

## 1. Executive Summary

Die Etch-Seite der SAS-RPCs ist bis **TCP/`TcpTransport.send`** statisch geschlossen.  
Die BCL-Seite bis **`AccessorySocket`** bleibt der bekannte FACT-Pfad.  

Zwischen beiden Stacks gibt es **keine** statische Invoke-/Objekt-Kante `Etch* → BclConnection` (`APK_PATH_NOT_FOUND`).  
Accessory-Services nutzen `127.0.0.1` / `EXTRA_HOST`/`EXTRA_PORT` — das stützt höchstens **Model-A-Hypothese** (lokaler Proxy), nicht einen geschlossenen APK-Datenfluss.

**Verdict:** `PARTIALLY_CLOSED` (Etch→TCP CLOSED · Etch→BCL `APK_PATH_NOT_FOUND` · BCL→Accessory CLOSED).

---

## 2. Existing Evidence

### SAS/B3 Deep Dive

Geschlossen: `challenge → signChallenge → response → sas_login → Etch`.  
Offen geblieben: Etch→BCL; `libaudio.so` out of scope.

### BCL → Accessory (übernommen)

```text
BclConnection.write/read → AccessorySocket.write/read   [FACT]
concrete Socket impl                                     [DYNAMIC_DISPATCH]
```

---

## 3. Analyzer Coverage

### Verwendet

| Analyzer | Rolle |
|---|---|
| `plan validate` / `estimate` + Resource Guard | Preflight |
| `diagnose-buffer-semantics --expand-interface-consumers --expand-etch-transport` | Comm-Seed + PATH-COMM |
| `diagnose-application-flow` (+ gleiche Flags) | Structured values / field consumers |
| `communication_evidence.expand_buffer_consumer_seeds(include_etch_transport=True)` | **neue Primitive** |
| DEX invoke-edge scan (apk_forensics `dex_model_adapter`) | Etch↔BCL / TcpTransport / IPC |
| Prior reports | sas-searchplan, bmw-connected-600-v10/v11, v13–v16, sas-deep-dive |

### Resource Guard

Full rescan estimate: **WARNING** (~1754 MiB / ~626 s) → **nicht gestartet**.  
Offline diagnose auf `output/sas-searchplan/scan/report.json` statt Full-Scan.

### Analyzer Gap (behoben, bounded)

Vorherige Seeds kannten `AccessorySocket`/`BclConnection`, nicht Etch Remoting.  
Neue CLI: `--expand-etch-transport` (Seed-Expansion, **kein** Protokoll-FACT).

---

## 4. sas_certificate Transport Path

```text
EtchCarConnection$2.getChallenge(cert)
  → RemoteBMWRemotingServer.sas_certificate([B)[B
  → _begin_sas_certificate: Message(_mt_sas_certificate) + put(_mf_data)
  → RemoteBase._begincall → DeliveryService/Mailbox
  → same stack as connect(): BMWRemotingHelper.newServer(tcp://…)
```

**Status:** CLOSED bis Etch-Transport-Stack · **FACT**

---

## 5. sas_login Transport Path

```text
EtchCarConnection$2.login(response)
  → sas_login([B, null)
  → _begin_sas_login: Message + _mf_data + _mf_version
  → _begincall → DeliveryService
```

**Same transport object:** `EtchCarConnection.mRemoteServer` für certificate **und** login → **FACT** `SAME_PROXY_FIELD`.

---

## 6. Etch Message Construction

| Element | Status |
|---|---|
| `ValueFactoryBMWRemoting` message types | FACT |
| `_mf_data` / `_result_*` | FACT |
| Symbol-only ohne Caller | **REJECTED** (Caller vorhanden) |

---

## 7. Etch Session / Transport Object

```text
EtchCarConnection.<init>
  mConnectionString = format("tcp://%s:%d?Packetizer.maxPktSize=8388608&TcpTransport.noDelay=true")
connect():
  BMWRemotingHelper.newServer(mConnectionString, …)
    → TransportFactory.getTransport(uri)
    → PlainMailboxManager → DefaultDeliveryService
    → RemoteBMWRemotingServer(DeliveryService, ValueFactory)
```

`TcpTransport.send([B I I)` / `transportData(FlexBuffer)` existieren in der APK · **FACT**.

---

## 8. TCP / IPC / Intent Bridge

### Etch-Host/Port

```text
CarContext.connect(String host, int port, …)
  → CarConnection.createCarConnection(ctx, host, port, …)
  → EtchCarConnection
```

**FACT.** Kein `EXTRA_HOST` in derselben Methode wie `EtchCarConnection` → Join Intent→Etch **NOT_PROVEN**.

### Accessory / BCL IPC (eigene Schicht)

| Site | Tokens |
|---|---|
| `BtServiceBroadcastHandler.sendOnAttached` | `EXTRA_HOST`, `EXTRA_PORT`, `EXTRA_INSTANCE` |
| `UsbService` / `EthService.onAttached` | `127.0.0.1` + EXTRA_* |
| `BclWorker.start` | `127.0.0.1` |
| `HmiConnectionHelper` | `127.0.0.1`, `10.0.2.2`, Intent `address`/`port` |

**FACT** als Strings/Calls.  
`localhost TCP = BCL` automatisch: **REJECTED** ohne Objektfluss.

---

## 9. BCL Candidate Paths

Vollständiger DEX-Invoke-Scan:

- Etch/idrive/apache.etch → `BclConnection` / `AccessorySocket`: **0 Kanten**
- `BclConnection.write/data`-Caller: nur interne BCL/`BclWatchdog`/`BclWorker`

→ **Model B (interne Etch→BclConnection) statisch: `APK_PATH_NOT_FOUND`.**

---

## 10. BclConnection / Accessory Path

Unverändert geschlossen (übernommen + bestätigt):

```text
BclConnection.write([B Z) → AccessorySocket.write([B I I)
```

---

## 11. response[] Dataflow

| Step | Status |
|---|---|
| signChallenge → login arg | CLOSED (SAS deep dive) |
| → `sas_login` → `Message.put(_mf_data)` | CLOSED |
| → `_begincall` / DeliveryService | CLOSED |
| Packetizer → `TcpTransport.send` buffer identity | PARTIAL (`ANALYZER_LIMIT`) |
| → `BclConnection.write` | **NOT_PROVEN** |

Communication-Evidence nach Etch-Expansion: PATH-COMM bleiben BCL-lastig; Retention-Cap 200 · Etch-Serialisierung nicht als vollständiger Buffer-Pfad exportiert.

---

## 12. Combined Static Evidence Graph

```text
CarSecurityManager.login
        ↓
SasAdapter.login(response)
        ↓
RemoteBMWRemotingServer.sas_login
        ↓
Etch Message (_mf_data)
        ↓
_begincall / DefaultDeliveryService
        ↓
TransportFactory / TcpTransport
        ↓
java.net.Socket ───────────────✗ NOT_PROVEN ──► BclConnection
        │                                              ↓
        │                                         AccessorySocket
        │
   CarContext.connect(host,port)   ←──✗ NOT_PROVEN── EXTRA_HOST/PORT (Accessory Intent)
```

---

## 13. B3 Correlation Boundary

| | |
|---|---|
| WIRE | `sas_certificate` / `sas_login` beobachtet |
| STATIC | dieselben RPC-Namen + Transport-Stack |
| Bytes WIRE↔APK write | **NOT_CORRELATED** |
| RUNTIME | **INPUT_MISSING** |

---

## 14. Open Edges

| ID | Kante | Status |
|---|---|---|
| OE-T1 | `TcpTransport` → `BclConnection.write` | NOT_PROVEN / APK_PATH_NOT_FOUND |
| OE-T2 | Accessory `EXTRA_HOST/PORT` → `CarContext.connect` | NOT_PROVEN |
| OE-T3 | Message → FlexBuffer → `send` byte identity | PARTIAL / ANALYZER_LIMIT |
| OE-T4 | B3 packet ↔ APK write | NOT_CORRELATED |

---

## 15. Analyzer Boundaries

- `METHOD_RETENTION_CAP` (200) nach Seed-Expansion  
- `DYNAMIC_DISPATCH` (`AccessorySocket`)  
- `APK_PATH_NOT_FOUND` (Etch→BCL invoke)  
- `RESOURCE_WARNING` (Full-Scan nicht gestartet)  
- `INPUT_MISSING` (Runtime)

---

## 16. JADX Fallback Findings

**Nicht benötigt.** Offene Kante ist fehlende Cross-Stack-Kante (0 Invokes), kein unaufgelöster Interface-Receiver auf dem Etch→TCP-Pfad.

---

## 17. Final Verdict

**PARTIALLY_CLOSED**

| Zweig | Ergebnis |
|---|---|
| Etch Message / Session / TCP | CLOSED |
| BCL → Accessory | CLOSED |
| Etch → BCL | **APK_PATH_NOT_FOUND** |
| Architektur | Model **C** (Etch=TCP) belegt; Model **B** verworfen; Model **A** nur Hypothese |

---

## 18. Next Minimal Step

1. **Runtime:** dieselbe Session — Hook `TcpTransport.send` + `BclConnection.write` + `CarContext.connect(host,port)` und Accessory-`EXTRA_HOST`/`PORT`.  
2. Optional Full-Scan nur mit expliziter `--allow-resource-warning`-Freigabe.  
3. Kein weiteres JADX für eine nicht existente Invoke-Kante.

---

## Q1–Q12

| Q | Answer |
|---|---|
| **Q1** | `diagnose-buffer-semantics`, `diagnose-application-flow`, `communication_evidence` (+ `--expand-etch-transport`), DEX invoke scan, prior graphs |
| **Q2** | sas-searchplan report, bmw-connected-600-v10/v11, v13–v16 closures, sas-deep-dive |
| **Q3** | **YES** — `sas_login` → Etch Message CLOSED |
| **Q4** | **YES** — Message → DeliveryService/Transport CLOSED |
| **Q5** | **YES** — Transport → `TcpTransport`/`Socket` CLOSED |
| **Q6** | Accessory IPC FACT; Join zu Etch-Host **NOT_PROVEN** |
| **Q7** | **NO** — Etch → `BclConnection` `APK_PATH_NOT_FOUND` |
| **Q8** | **YES** — bekannter BCL→Accessory-Pfad |
| **Q9** | bis Message/`_begincall` ja; bis `TcpTransport.send`-Buffer PARTIAL; bis BCL nein |
| **Q10** | **OE-T1** TcpTransport ↔ BclConnection |
| **Q11** | In dieser APK statisch nicht nachweisbar; JADX hilft nicht; **Runtime** für Model-A-Join |
| **Q12** | **Nein** — `B3 Byte Correlation = NOT_CORRELATED` |
