# APK Forensics postprocess-communication

Source report: `/home/martin/projects/apk-forensics/output/serial-bt-terminal-152/report.json`

Transport sections preserved in JSON; communication layer below.

## Communication Evidence (v1.0)

> Transport Evidence Graph and Communication Evidence Graph are separate layers.  
> Method names never establish protocol identity (BCL/Etch/RHMI/SCN6 remain UNKNOWN).

### Summary

| Metric | Value |
|---|---:|
| Read sites | 1 |
| Write sites | 1 |
| Buffer operations | 2 |
| Decoder candidates | 0 |
| Serializer candidates | 0 |
| Message constructions | 1 |
| Communication paths | 2 |
| Inbound | 1 |
| Outbound | 1 |
| Boundaries | 9 |
| Coverage complete | 1 |
| Coverage truncated | 0 |
| Coverage boundary | 1 |
| Coverage unresolved | 0 |
| Coverage no_continuation | 0 |

### Method Retention

- retained_methods: `5`
- candidate_methods: `5`
- discarded_methods: `0`
- discard_reason: ``
- capped: `False`

_METHOD_RETENTION_CAP is an analyzer limit, not an APK semantic boundary._

**Strongest:** `PATH-COMM-000001` — `INFERENCE` · protocol=`UNKNOWN` · runtime=`UNKNOWN`

### Provenance

- mode: `offline_postprocess`
- source_dataset: `/home/martin/projects/apk-forensics/artifacts/de.kai_morich.serial_bluetooth_terminal-1.52.apk`
- source_engine_version: `1.6.0`
- source_plan_sha256: `0a211deda9574bf9c68b9dbf286d5b88479c76d72d629311aabe5b65a81d07aa`
- source_artifact_sha256: `e44ab3b93e1701fcca67869169ba49ef2e918416d28928a56a135e8bff343192`
- postprocessing_version: `1.6.0`

### Communication Paths

#### PATH-COMM-000001

- Direction: `INBOUND`
- End-to-end: `INFERENCE` / `medium`
- Protocol semantics: `UNKNOWN`

```text
Ljava/io/InputStream;->read([B)I  [FACT/high]
new-array [B:v1  [FACT/high]
Ljava/util/Arrays;->copyOf([B I)[B  [FACT/high]
Ljava/io/IOException;-><init>(Ljava/lang/String;)V  [FACT/high]
```

- Boundary: `UNKNOWN_HELPER` last=`Lvz;->f(Ljava/util/Date; [B)V` [UNKNOWN]

#### PATH-COMM-000002

- Direction: `OUTBOUND`
- End-to-end: `INFERENCE` / `medium`
- Protocol semantics: `UNKNOWN`

```text
byte[]:v2  [FACT/medium]
Ljava/io/OutputStream;->write([B)V  [FACT/high]
```

### Boundaries

- `UNKNOWN_HELPER` method=`La00;->run()V` detail=`La00;->run()V`
- `UNKNOWN_HELPER` method=`La00;->run()V` detail=`La00;->run()V`
- `UNKNOWN_HELPER` method=`La00;->run()V` detail=`La00;->run()V`
- `UNKNOWN_HELPER` method=`La00;->run()V` detail=`La00;->run()V`
- `UNKNOWN_HELPER` method=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I` detail=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- `UNKNOWN_HELPER` method=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I` detail=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- `UNKNOWN_HELPER` method=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I` detail=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- `UNKNOWN_HELPER` method=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I` detail=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- `UNKNOWN_HELPER` method=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I` detail=`Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`

