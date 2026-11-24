from __future__ import annotations

from apk_forensics.bluetooth_uuid import resolve_rfcomm_uuid_argument
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref


def _ins(index: int, opcode: str, text: str, **kwargs) -> InstructionInfo:
    regs = kwargs.pop("registers", None)
    if regs is None:
        import re

        regs = re.findall(r"\bv\d+\b", text)
    ref_m = kwargs.get("referenced_method")
    if ref_m is None and "->" in text and opcode.startswith("invoke"):
        import re

        m = re.search(r"(L[^;]+;->[^(]+\([^)]*\)[^ ]*)", text)
        if m:
            ref_m = parse_method_ref(m.group(1))
    return InstructionInfo(
        index=index,
        offset=None,
        opcode=opcode,
        text=text,
        registers=regs,
        referenced_method=ref_m,
        referenced_string=kwargs.get("referenced_string"),
        referenced_field=kwargs.get("referenced_field"),
    )


def _transport_methods() -> tuple[MethodInfo, MethodInfo, MethodInfo]:
    clinit = MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/BluetoothTransport;",
        class_name_normalized="com.example.BluetoothTransport",
        method_name="<clinit>",
        method_descriptor="()V",
        access_flags=["static"],
        is_external=False,
        code_present=True,
        instruction_count=4,
        code_offset=None,
        instructions=[
            _ins(
                0,
                "const-string",
                'const-string v0, "00001101-0000-1000-8000-00805F9B34FB"',
                referenced_string="00001101-0000-1000-8000-00805F9B34FB",
                registers=["v0"],
            ),
            _ins(
                1,
                "invoke-static",
                "invoke-static v0, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;",
                registers=["v0"],
            ),
            _ins(2, "move-result-object", "move-result-object v0", registers=["v0"]),
            _ins(
                3,
                "sput-object",
                "sput-object v0, Lcom/example/BluetoothTransport;->SPP_UUID Ljava/util/UUID;",
                registers=["v0"],
                referenced_field="Lcom/example/BluetoothTransport;->SPP_UUID Ljava/util/UUID;",
            ),
        ],
    )
    connect = MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/BluetoothTransport;",
        class_name_normalized="com.example.BluetoothTransport",
        method_name="connect",
        method_descriptor="()V",
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=8,
        code_offset=None,
        instructions=[
            _ins(
                0,
                "iget-object",
                "iget-object v0, v1, Lcom/example/BluetoothTransport;->device Landroid/bluetooth/BluetoothDevice;",
                registers=["v0", "v1"],
                referenced_field="Lcom/example/BluetoothTransport;->device Landroid/bluetooth/BluetoothDevice;",
            ),
            _ins(
                1,
                "sget-object",
                "sget-object v2, Lcom/example/BluetoothTransport;->SPP_UUID Ljava/util/UUID;",
                registers=["v2"],
                referenced_field="Lcom/example/BluetoothTransport;->SPP_UUID Ljava/util/UUID;",
            ),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v0, v2, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
                registers=["v0", "v2"],
            ),
            _ins(3, "move-result-object", "move-result-object v0", registers=["v0"]),
            _ins(
                4,
                "invoke-virtual",
                "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->connect()V",
                registers=["v0"],
            ),
            _ins(
                5,
                "invoke-virtual",
                "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->getInputStream()Ljava/io/InputStream;",
                registers=["v0"],
            ),
            _ins(6, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(
                7,
                "invoke-virtual",
                "invoke-virtual v0, Landroid/bluetooth/BluetoothSocket;->getOutputStream()Ljava/io/OutputStream;",
                registers=["v0"],
            ),
        ],
    )
    unrelated = MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/Other;",
        class_name_normalized="com.example.Other",
        method_name="unrelatedMethod",
        method_descriptor="()V",
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=1,
        code_offset=None,
        instructions=[
            _ins(
                0,
                "const-string",
                'const-string v0, "00001101-0000-1000-8000-00805F9B34FB"',
                referenced_string="00001101-0000-1000-8000-00805F9B34FB",
                registers=["v0"],
            )
        ],
    )
    return clinit, connect, unrelated


def test_uuid_static_field_linked_to_rfcomm() -> None:
    clinit, connect, _ = _transport_methods()
    resolved = resolve_rfcomm_uuid_argument(
        connect,
        2,
        class_methods=[clinit, connect],
        dataflow_depth=2,
    )
    assert resolved["uuid"] == "00001101-0000-1000-8000-00805f9b34fb"
    assert resolved["source_type"] == "uuid_static_field"
    assert resolved["classification"] == "FACT"
    assert resolved["resolution"] == "static"


def test_uuid_unknown_when_depth_zero() -> None:
    clinit, connect, _ = _transport_methods()
    resolved = resolve_rfcomm_uuid_argument(
        connect,
        2,
        class_methods=[clinit, connect],
        dataflow_depth=0,
    )
    assert resolved["uuid"] is None
    assert resolved["classification"] == "UNKNOWN"


def test_unrelated_uuid_string_not_auto_linked() -> None:
    clinit, connect, unrelated = _transport_methods()
    # Creating RFCOMM in connect still resolves via field, not via unrelated method string.
    resolved = resolve_rfcomm_uuid_argument(
        connect,
        2,
        class_methods=[clinit, connect, unrelated],
        dataflow_depth=2,
    )
    assert resolved["uuid"] == "00001101-0000-1000-8000-00805f9b34fb"
    assert "unrelatedMethod" not in (resolved.get("source") or "")
