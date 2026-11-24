"""Generic candidate scanners for UUIDs, ports, and Android/Bluetooth APIs."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from apk_forensics.config import AnalysisConfig
from apk_forensics.finding_factory import make_finding
from apk_forensics.models import Classification, Confidence, Finding
from apk_forensics.string_scanner import ExtractedString, extract_strings
from apk_forensics.utils import context_around, timed_ms
from apk_forensics.models import AnalysisStatus, ScannerResult


GENERIC_API_CANDIDATES: list[dict[str, str]] = [
    {"value": "android.bluetooth.BluetoothAdapter", "category": "bluetooth", "subcategory": "bluetooth.adapter"},
    {"value": "android.bluetooth.BluetoothDevice", "category": "bluetooth", "subcategory": "bluetooth.device"},
    {"value": "android.bluetooth.BluetoothSocket", "category": "bluetooth", "subcategory": "bluetooth.socket"},
    {"value": "android.bluetooth.BluetoothGatt", "category": "bluetooth", "subcategory": "bluetooth.gatt"},
    {"value": "android.bluetooth.BluetoothGattCallback", "category": "bluetooth", "subcategory": "bluetooth.gatt"},
    {"value": "createRfcommSocketToServiceRecord", "category": "bluetooth", "subcategory": "bluetooth.rfcomm"},
    {"value": "createInsecureRfcommSocketToServiceRecord", "category": "bluetooth", "subcategory": "bluetooth.rfcomm"},
    {"value": "fetchUuidsWithSdp", "category": "bluetooth", "subcategory": "bluetooth.sdp"},
    {"value": "getUuids", "category": "bluetooth", "subcategory": "bluetooth.sdp"},
    {"value": "BluetoothProfile", "category": "bluetooth", "subcategory": "bluetooth.profile"},
    {"value": "BluetoothA2dp", "category": "bluetooth", "subcategory": "bluetooth.a2dp"},
    {"value": "BluetoothHeadset", "category": "bluetooth", "subcategory": "bluetooth.headset"},
    {"value": "BluetoothGattCharacteristic", "category": "bluetooth", "subcategory": "bluetooth.gatt"},
    {"value": "UsbManager", "category": "usb", "subcategory": "usb.manager"},
    {"value": "UsbDevice", "category": "usb", "subcategory": "usb.device"},
    {"value": "UsbAccessory", "category": "usb", "subcategory": "usb.accessory"},
    {"value": "ParcelFileDescriptor", "category": "android", "subcategory": "android.parcel"},
    {"value": "java.net.Socket", "category": "network", "subcategory": "network.socket"},
    {"value": "java.net.DatagramSocket", "category": "network", "subcategory": "network.datagram"},
    {"value": "java.nio.ByteBuffer", "category": "android", "subcategory": "android.nio"},
    {"value": "getInputStream", "category": "network", "subcategory": "network.stream"},
    {"value": "getOutputStream", "category": "network", "subcategory": "network.stream"},
    {"value": "InputStream", "category": "network", "subcategory": "network.stream"},
    {"value": "OutputStream", "category": "network", "subcategory": "network.stream"},
    {"value": "connect", "category": "network", "subcategory": "network.connect"},
    {"value": "close", "category": "network", "subcategory": "network.close"},
]

API_NOTE = "API symbol/string presence does not prove runtime execution."

UUID_RE = re.compile(
    rb"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
SHORT_BT_UUID_RE = re.compile(rb"(?i)\b0x([0-9a-f]{4})\b|\b([0-9a-f]{4})\b")

PORT_CONTEXT_RE = re.compile(
    r"(?i)(?:port\s*[=:]\s*|:\s*|socket\s*\(\s*|channel\s+)(\d{1,5})\b"
)


@dataclass
class ScanBlob:
    entry: str
    file_type: str
    data: bytes


def scan_uuids(
    blob: ScanBlob,
    *,
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
) -> list[Finding]:
    cfg = config or AnalysisConfig()
    findings: list[Finding] = []
    for match in UUID_RE.finditer(blob.data):
        raw = match.group().decode("ascii")
        try:
            normalized = str(uuid.UUID(raw)).lower()
        except ValueError:
            continue
        offset = match.start()
        before, after = context_around(blob.data, offset, len(match.group()), cfg.max_context_length)
        findings.append(
            make_finding(
                artifact_sha256=artifact_sha256,
                kind="uuid",
                category="bluetooth",
                subcategory="bluetooth.uuid",
                value=raw,
                normalized_value=normalized,
                classification=Classification.FACT.value,
                confidence=Confidence.HIGH.value,
                source_entry=blob.entry,
                file_type=blob.file_type,
                offset=offset,
                length=len(match.group()),
                matched_text=raw,
                context_before=before,
                context_after=after,
                pattern="uuid",
                scanner="uuid_scanner",
                tags=["uuid"],
            )
        )
        if len(findings) >= cfg.max_findings_per_scanner:
            break

    # Short Bluetooth UUID forms; do not expand to full UUID as FACT.
    for match in SHORT_BT_UUID_RE.finditer(blob.data):
        short = (match.group(1) or match.group(2) or b"").decode("ascii").lower()
        if not short:
            continue
        # Avoid treating parts of full UUIDs as short forms when surrounded by UUID pattern.
        start = match.start()
        window = blob.data[max(0, start - 20) : start + 40]
        if UUID_RE.search(window):
            continue
        # Keep only common Bluetooth-ish short codes or explicit 0xNNNN forms.
        raw_text = match.group().decode("ascii")
        if not raw_text.lower().startswith("0x") and short not in {"1101", "110a", "110b", "111e", "112f"}:
            continue
        offset = match.start()
        before, after = context_around(blob.data, offset, len(match.group()), cfg.max_context_length)
        value = raw_text if raw_text.lower().startswith("0x") else f"0x{short}"
        findings.append(
            make_finding(
                artifact_sha256=artifact_sha256,
                kind="uuid",
                category="bluetooth",
                subcategory="bluetooth.uuid.short",
                value=value,
                normalized_value=value.lower(),
                classification=Classification.FACT.value,
                confidence=Confidence.MEDIUM.value,
                source_entry=blob.entry,
                file_type=blob.file_type,
                offset=offset,
                length=len(match.group()),
                matched_text=raw_text,
                context_before=before,
                context_after=after,
                pattern="short_bt_uuid",
                scanner="uuid_scanner",
                tags=["uuid", "short"],
                notes=["short Bluetooth UUID; full UUID not inferred"],
            )
        )
        if len(findings) >= cfg.max_findings_per_scanner:
            break
    return findings


def scan_ports(
    strings: list[ExtractedString],
    *,
    blob: ScanBlob,
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
) -> list[Finding]:
    cfg = config or AnalysisConfig()
    findings: list[Finding] = []
    for item in strings:
        for match in PORT_CONTEXT_RE.finditer(item.value):
            port = int(match.group(1))
            if not 1 <= port <= 65535:
                continue
            findings.append(
                make_finding(
                    artifact_sha256=artifact_sha256,
                    kind="port",
                    category="network",
                    subcategory="network.port",
                    value=str(port),
                    normalized_value=str(port),
                    classification=Classification.FACT.value,
                    confidence=Confidence.MEDIUM.value,
                    source_entry=blob.entry,
                    file_type=blob.file_type,
                    offset=item.offset + match.start(1),
                    length=len(match.group(1)),
                    matched_text=match.group(0),
                    context_before=item.context_before,
                    context_after=item.context_after,
                    pattern="port_context",
                    scanner="port_scanner",
                    tags=["port"],
                    notes=["Port candidate only; usage not proven."],
                )
            )
            if len(findings) >= cfg.max_findings_per_scanner:
                return findings
    return findings


GENERIC_SHORT_APIS = {"connect", "close"}


def _is_token_boundary(data: bytes, start: int, length: int) -> bool:
    """Avoid matching short API names inside longer identifiers."""
    left_ok = start == 0 or not (chr(data[start - 1]).isalnum() or data[start - 1] in b"._$")
    end = start + length
    right_ok = end >= len(data) or not (chr(data[end]).isalnum() or data[end] in b"._$")
    return left_ok and right_ok


def scan_apis(
    blob: ScanBlob,
    *,
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
    candidates: list[dict[str, str]] | None = None,
) -> list[Finding]:
    cfg = config or AnalysisConfig()
    findings: list[Finding] = []
    api_list = candidates or GENERIC_API_CANDIDATES

    # Prefer exact binary substring matches with offsets.
    for api in api_list:
        needle = api["value"].encode("utf-8")
        is_short = api["value"] in GENERIC_SHORT_APIS
        start = 0
        while True:
            idx = blob.data.find(needle, start)
            if idx < 0:
                break
            if is_short and not _is_token_boundary(blob.data, idx, len(needle)):
                start = idx + len(needle)
                continue
            before, after = context_around(blob.data, idx, len(needle), cfg.max_context_length)
            confidence = Confidence.HIGH.value
            notes = [API_NOTE]
            if is_short:
                confidence = Confidence.LOW.value
                notes.append("Short generic API token; high false-positive risk.")
            findings.append(
                make_finding(
                    artifact_sha256=artifact_sha256,
                    kind="api",
                    category=api["category"],
                    subcategory=api.get("subcategory"),
                    value=api["value"],
                    normalized_value=api["value"],
                    classification=Classification.FACT.value,
                    confidence=confidence,
                    source_entry=blob.entry,
                    file_type=blob.file_type,
                    offset=idx,
                    length=len(needle),
                    matched_text=api["value"],
                    context_before=before,
                    context_after=after,
                    pattern="api_literal",
                    scanner="api_scanner",
                    tags=["api", api["category"]],
                    notes=notes,
                )
            )
            start = idx + len(needle)
            if len(findings) >= cfg.max_findings_per_scanner:
                return findings
    return findings


def scan_blob_candidates(
    blob: ScanBlob,
    *,
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
) -> tuple[list[Finding], list[ExtractedString], list[str]]:
    cfg = config or AnalysisConfig()
    warnings: list[str] = []
    findings: list[Finding] = []
    try:
        strings = extract_strings(blob.data, config=cfg)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"String extraction failed for {blob.entry}: {exc}")
        strings = []

    findings.extend(scan_uuids(blob, artifact_sha256=artifact_sha256, config=cfg))
    findings.extend(scan_ports(strings, blob=blob, artifact_sha256=artifact_sha256, config=cfg))
    findings.extend(scan_apis(blob, artifact_sha256=artifact_sha256, config=cfg))
    return findings, strings, warnings


def run_candidate_scanner(
    blobs: list[ScanBlob],
    *,
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
) -> ScannerResult:
    cfg = config or AnalysisConfig()
    with timed_ms() as timing:
        findings: list[Finding] = []
        warnings: list[str] = []
        errors: list[str] = []
        string_count = 0
        for blob in blobs:
            try:
                blob_findings, strings, blob_warnings = scan_blob_candidates(
                    blob,
                    artifact_sha256=artifact_sha256,
                    config=cfg,
                )
                findings.extend(blob_findings)
                warnings.extend(blob_warnings)
                string_count += len(strings)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Candidate scan failed for {blob.entry}: {exc}")
        status = AnalysisStatus.COMPLETE.value
        if errors:
            status = AnalysisStatus.FAILED.value
        elif warnings:
            status = AnalysisStatus.PARTIAL.value
    return ScannerResult(
        name="candidate_scanner",
        status=status,
        duration_ms=timing["duration_ms"],
        warnings=warnings,
        errors=errors,
        data={"string_count": string_count, "blob_count": len(blobs)},
        findings=findings[: cfg.max_findings_per_scanner],
    )
