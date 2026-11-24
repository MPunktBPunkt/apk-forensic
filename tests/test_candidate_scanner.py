from __future__ import annotations

from apk_forensics.candidate_scanner import ScanBlob, run_candidate_scanner, scan_apis, scan_ports
from apk_forensics.string_scanner import extract_strings


def test_api_candidates() -> None:
    data = (
        b"createRfcommSocketToServiceRecord\n"
        b"fetchUuidsWithSdp\n"
        b"InputStream\n"
        b"OutputStream\n"
    )
    findings = scan_apis(
        ScanBlob(entry="classes.dex", file_type="dex", data=data),
        artifact_sha256="abc",
    )
    values = {f.value for f in findings}
    assert "createRfcommSocketToServiceRecord" in values
    assert "fetchUuidsWithSdp" in values
    assert "InputStream" in values
    assert "OutputStream" in values
    assert all("does not prove runtime execution" in " ".join(f.notes) for f in findings)


def test_ports_contextual_not_isolated() -> None:
    data = b"port=4004\nhello 12345 world\n42\n"
    blob = ScanBlob(entry="classes.dex", file_type="dex", data=data)
    strings = extract_strings(data)
    findings = scan_ports(strings, blob=blob, artifact_sha256="abc")
    ports = {f.value for f in findings}
    assert "4004" in ports
    assert "42" not in ports


def test_run_candidate_scanner() -> None:
    blob = ScanBlob(
        entry="classes.dex",
        file_type="dex",
        data=b"createRfcommSocketToServiceRecord port=4004 00001101-0000-1000-8000-00805F9B34FB",
    )
    result = run_candidate_scanner([blob], artifact_sha256="abc")
    assert result.name == "candidate_scanner"
    assert len(result.findings) >= 3
