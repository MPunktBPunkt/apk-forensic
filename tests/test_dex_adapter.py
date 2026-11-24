from __future__ import annotations

from apk_forensics.dex_model_adapter import (
    get_androguard_version,
    is_androguard_available,
    normalize_class_name,
    parse_method_ref,
)


def test_normalize_class_name() -> None:
    assert normalize_class_name("Lcom/example/Foo;") == "com.example.Foo"
    assert normalize_class_name("com.example.Foo") == "com.example.Foo"


def test_parse_method_ref() -> None:
    raw = "Lcom/example/Foo;->connect(Landroid/bluetooth/BluetoothDevice;)Z"
    parsed = parse_method_ref(raw)
    assert parsed["class_name"] == "com.example.Foo"
    assert parsed["method_name"] == "connect"
    assert parsed["descriptor"] == "(Landroid/bluetooth/BluetoothDevice;)Z"
    assert parsed["raw"] == raw


def test_androguard_detection() -> None:
    available = is_androguard_available()
    version = get_androguard_version()
    if available:
        assert version is not None
    else:
        assert version is None
