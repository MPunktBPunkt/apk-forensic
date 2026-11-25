No raw instrumentation logs were produced.

Reason (FACT, re-verified 2026-11-25T08:39:13Z):
- NO_DEVICE: adb devices empty (no Android device/emulator)
- NO_FRIDA: Frida CLI and Python module absent
- NO_PROCESS: no de.bmw.connected process observed
- NO_LIVE_SESSION: no Connected/RFCOMM session to instrument
- NO_INSTRUMENTATION_ACCESS: cannot attach ART/JVMTI/Frida without process+device

Rejected substitutes:
- LABSIM phone.jsonl as APK runtime
- Simulated Info.decodeVersion([B)S events
- Cross-session join to LAB_B3_TCP_FULLAUTH_20261120T090004Z
