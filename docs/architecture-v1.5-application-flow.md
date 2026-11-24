# Architecture — v1.5 Structured-Value & Application-Flow Closure

## Question

What happens to structured values extracted from transport bytes?

## Chain

```
BUFFER → BYTE PROCESSING → STRUCTURED VALUE → FIELD STORE
  → FIELD LOAD → BRANCH / PARAM / STATE / COLLECTION → optional OUTPUT
```

## Rules

- Neutral IDs: `VALUE-V001` … (never “message ID”)
- Same field *descriptor* across methods = **CORRELATION**, not proven same instance
- Field/method/class names are search indicators only
- Protocol semantics stay **UNKNOWN**

## V0–V5

Dataflow classes only — not protocol classes.

## PATH-COMM

v1.4 PATH-COMM=12 remains provenance-tagged as analyzer expansion (READ_LENGTH + interface seeds), not an APK change.
