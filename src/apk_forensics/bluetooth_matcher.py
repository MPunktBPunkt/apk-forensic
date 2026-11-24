"""Recognize Bluetooth/RFCOMM-relevant DEX operations."""

from __future__ import annotations

from dataclasses import dataclass

from apk_forensics.dex_model_adapter import MethodInfo


RFCOMM_CREATE = {
    "createRfcommSocketToServiceRecord",
    "createInsecureRfcommSocketToServiceRecord",
}
RFCOMM_LISTEN = {
    "listenUsingRfcommWithServiceRecord",
    "listenUsingInsecureRfcommWithServiceRecord",
}
SOCKET_CONNECT = {"connect"}  # only with BluetoothSocket
STREAM_APIS = {"getInputStream", "getOutputStream"}
UUID_APIS = {"fetchUuidsWithSdp", "getUuids"}
DEVICE_APIS = {
    "getRemoteDevice",
    "getBondedDevices",
    "getAddress",
    "getName",
    "getUuids",
    "fetchUuidsWithSdp",
}
ADAPTER_CLASSES = {
    "Landroid/bluetooth/BluetoothAdapter;",
    "android.bluetooth.BluetoothAdapter",
}
DEVICE_CLASSES = {
    "Landroid/bluetooth/BluetoothDevice;",
    "android.bluetooth.BluetoothDevice",
}
SOCKET_CLASSES = {
    "Landroid/bluetooth/BluetoothSocket;",
    "android.bluetooth.BluetoothSocket",
    "Landroid/bluetooth/BluetoothServerSocket;",
    "android.bluetooth.BluetoothServerSocket",
}

SPP_UUID = "00001101-0000-1000-8000-00805f9b34fb"


@dataclass
class BluetoothHit:
    method: MethodInfo
    instruction_index: int
    api: str
    match_type: str
    priority: str
    category: str
    text: str


def _method_name_from_ref(raw: str | None) -> str | None:
    if not raw or "->" not in raw:
        return None
    return raw.split("->", 1)[1].split("(", 1)[0]


def classify_instruction(method: MethodInfo, index: int) -> BluetoothHit | None:
    ins = method.instructions[index]
    text = ins.text
    ref = ins.referenced_method or {}
    raw = ref.get("raw") or ""
    name = ref.get("method_name") or _method_name_from_ref(raw)
    class_name = ref.get("class_name") or ""

    if name in RFCOMM_CREATE:
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api=name,
            match_type="method_reference",
            priority="high",
            category="rfcomm_create",
            text=text,
        )
    if name in RFCOMM_LISTEN:
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api=name,
            match_type="method_reference",
            priority="high",
            category="rfcomm_listen",
            text=text,
        )
    if name == "connect" and "BluetoothSocket" in (class_name + raw + text):
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api="BluetoothSocket.connect",
            match_type="method_reference",
            priority="high",
            category="socket_connect",
            text=text,
        )
    if name in STREAM_APIS and "BluetoothSocket" in (class_name + raw + text):
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api=name,
            match_type="method_reference",
            priority="medium",
            category="socket_stream",
            text=text,
        )
    if name in UUID_APIS:
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api=name,
            match_type="method_reference",
            priority="medium",
            category="uuid_discovery",
            text=text,
        )
    if name in {"getRemoteDevice", "getBondedDevices"}:
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api=name,
            match_type="method_reference",
            priority="medium",
            category="device_source",
            text=text,
        )
    if ins.opcode.startswith("const-string") and ins.referenced_string:
        value = ins.referenced_string.lower()
        if value == SPP_UUID:
            return BluetoothHit(
                method=method,
                instruction_index=index,
                api="spp_uuid_literal",
                match_type="string",
                priority="high",
                category="uuid_literal",
                text=text,
            )
    if ins.referenced_class:
        for cls in DEVICE_CLASSES | SOCKET_CLASSES | ADAPTER_CLASSES:
            if cls.replace("/", ".").rstrip(";") in (ins.referenced_class or "") or cls in (ins.referenced_class or ""):
                return BluetoothHit(
                    method=method,
                    instruction_index=index,
                    api=ins.referenced_class or cls,
                    match_type="class_reference",
                    priority="medium",
                    category="class_reference",
                    text=text,
                )
    if ins.referenced_field and "UUID" in (ins.referenced_field or ""):
        return BluetoothHit(
            method=method,
            instruction_index=index,
            api=ins.referenced_field,
            match_type="field_reference",
            priority="medium",
            category="uuid_field",
            text=text,
        )
    return None


def find_bluetooth_hits(
    methods: list[MethodInfo],
    *,
    target_query: str | None = None,
    max_results: int = 100,
) -> list[BluetoothHit]:
    hits: list[BluetoothHit] = []
    for method in methods:
        if target_query:
            blob = f"{method.class_name} {method.method_name} {method.class_name_normalized}"
            if target_query.lower() not in blob.lower():
                # still allow if instruction text matches later
                pass
        for ins in method.instructions:
            hit = classify_instruction(method, ins.index)
            if not hit:
                continue
            if target_query:
                q = target_query.lower()
                hay = " ".join(
                    [
                        hit.api,
                        hit.text,
                        method.class_name,
                        method.method_name,
                        method.class_name_normalized or "",
                    ]
                ).lower()
                if q not in hay:
                    continue
            hits.append(hit)
            if len(hits) >= max_results * 5:
                break
        if len(hits) >= max_results * 5:
            break
    # Prefer RFCOMM create / high priority
    rank = {"high": 0, "medium": 1, "low": 2}
    hits.sort(
        key=lambda h: (
            rank.get(h.priority, 9),
            0 if h.category == "rfcomm_create" else 1,
            h.method.dex_entry,
            h.method.class_name,
            h.method.method_name,
            h.instruction_index,
        )
    )
    return hits[:max_results]
