from __future__ import annotations

from pathlib import Path

from apk_forensics.zip_inventory import build_zip_inventory, open_apk_zip


def test_zip_inventory_detects_entries(synthetic_apk: Path) -> None:
    with open_apk_zip(synthetic_apk) as zf:
        result = build_zip_inventory(zf, compute_hashes=True)
    names = {e["name"] for e in result.data["entries"]}
    assert "AndroidManifest.xml" in names
    assert "classes.dex" in names
    assert "classes2.dex" in names
    assert "lib/arm64-v8a/libsample.so" in names
    assert result.data["has_manifest"] is True
    assert result.data["has_dex"] is True
    assert result.data["has_native"] is True


def test_zip_slip_detected(synthetic_apk: Path) -> None:
    with open_apk_zip(synthetic_apk) as zf:
        result = build_zip_inventory(zf, compute_hashes=False)
    suspicious = [e for e in result.data["entries"] if e["suspicious"]]
    assert any("../evil.txt" in e["name"] for e in suspicious)
