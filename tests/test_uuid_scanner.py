from __future__ import annotations

from apk_forensics.candidate_scanner import ScanBlob, scan_uuids


def test_full_uuid_normalized() -> None:
    data = b"prefix 00001101-0000-1000-8000-00805F9B34FB suffix"
    findings = scan_uuids(
        ScanBlob(entry="classes.dex", file_type="dex", data=data),
        artifact_sha256="abc",
    )
    assert len(findings) == 1
    assert findings[0].normalized_value == "00001101-0000-1000-8000-00805f9b34fb"
    assert findings[0].classification == "FACT"


def test_invalid_uuid_rejected() -> None:
    data = b"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
    findings = scan_uuids(
        ScanBlob(entry="classes.dex", file_type="dex", data=data),
        artifact_sha256="abc",
    )
    assert findings == []


def test_short_uuid_not_expanded() -> None:
    data = b"code 0x1101 here"
    findings = scan_uuids(
        ScanBlob(entry="classes.dex", file_type="dex", data=data),
        artifact_sha256="abc",
    )
    assert len(findings) == 1
    assert findings[0].value.lower() == "0x1101"
    assert "00001101-0000-1000-8000-00805f9b34fb" not in findings[0].value.lower()
    assert any("full UUID not inferred" in n for n in findings[0].notes)
