# Value Lineage Report (v1.5)

> Neutral VALUE-V### IDs. No protocol naming.

## Definition

A STRUCTURED_VALUE is a FACT when a tracked byte[]/ByteBuffer identity is transformed by a concrete DEX instruction into a typed register value (primitive, String, or object ref) that is distinct from READ_LENGTH.

## Catalog

### VALUE-V001 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Lve0;->c Ljava/lang/Object;`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE c Ljava/lang/Object;
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V002 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Lve0;->c Ljava/lang/Object;`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE c Ljava/lang/Object;
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V003 — `V4_APPLICATION_ACTION`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Llf0;->zzc Llg0;`
- T6: `T6.4_APPLICATION_ACTION`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE zzc Llg0;
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V004 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Lmf0;->b [I`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE b [I
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V005 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Lmf0;->b [I`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE b [I
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V006 — `V4_APPLICATION_ACTION`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Lxf0;->a Z`
- T6: `T6.4_APPLICATION_ACTION`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE a Z
  - CONSUMER FIELD_LOAD @ Landroidx/activity/b;->b()V
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Landroidx/activity/b;->b()V
  - CONSUMER FIELD_LOAD @ Landroidx/activity/b;->b()V
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Landroidx/activity/b;->b()V
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V007 — `V4_APPLICATION_ACTION`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Llf0;->zzc Llg0;`
- T6: `T6.4_APPLICATION_ACTION`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE zzc Llg0;
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V008 — `V4_APPLICATION_ACTION`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `Llf0;->zzc Llg0;`
- T6: `T6.4_APPLICATION_ACTION`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER → FIELD_STORE zzc Llg0;
  - CONSUMER FIELD_LOAD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER BRANCH_ON_FIELD_VALUE @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I
  - CONSUMER VALUE_PARAMETER_FROM_FIELD @ Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I

### VALUE-V009 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `None`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER v8
  - NO_FIELD_STORE

### VALUE-V010 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `None`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER v8
  - NO_FIELD_STORE

### VALUE-V011 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `None`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER v13
  - NO_FIELD_STORE

### VALUE-V012 — `V3_CONTROL_FLOW`

- Source method: `Lbg0;->t(Ljava/lang/Object; [B I I I Lve0;)I`
- Source: `STRING_FROM_BYTES` / `Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V`
- Type: `string`
- Field: `None`
- T6: `T6.3_CONTROL_FLOW`
- Protocol: `UNKNOWN`
- Lineage:
  - BYTES → Ljava/lang/String;-><init>([B I I Ljava/nio/charset/Charset;)V
  - REGISTER v13
  - NO_FIELD_STORE
