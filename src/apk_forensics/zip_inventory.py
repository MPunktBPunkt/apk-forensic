"""ZIP inventory and APK structure checks."""

from __future__ import annotations

import zipfile
from pathlib import Path

from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import InvalidApkError
from apk_forensics.hashing import zip_entry_sha256
from apk_forensics.models import AnalysisStatus, ScannerResult, ZipEntryInfo
from apk_forensics.utils import classify_zip_entry, compression_name, safe_relpath_check, timed_ms


def open_apk_zip(path: Path) -> zipfile.ZipFile:
    if not zipfile.is_zipfile(path):
        raise InvalidApkError(f"File is not a valid APK/ZIP: {path}")
    try:
        return zipfile.ZipFile(path, "r")
    except zipfile.BadZipFile as exc:
        raise InvalidApkError(f"File is not a valid APK/ZIP: {path}") from exc


def build_zip_inventory(
    zf: zipfile.ZipFile,
    *,
    config: AnalysisConfig | None = None,
    compute_hashes: bool = True,
) -> ScannerResult:
    cfg = config or AnalysisConfig()
    with timed_ms() as timing:
        entries: list[ZipEntryInfo] = []
        warnings: list[str] = []
        errors: list[str] = []
        counts = {
            "manifest": 0,
            "dex": 0,
            "native": 0,
            "resources": 0,
            "assets": 0,
            "res": 0,
            "meta-inf": 0,
            "other": 0,
            "directory": 0,
            "suspicious": 0,
        }

        for info in zf.infolist():
            name = info.filename
            suspicious, reasons = safe_relpath_check(name)
            entry_type = classify_zip_entry(name)
            sha256 = None
            if compute_hashes and not info.is_dir() and info.file_size <= cfg.max_entry_read_bytes:
                try:
                    sha256 = zip_entry_sha256(
                        zf,
                        name,
                        chunk_size=cfg.hash_chunk_size,
                        max_bytes=cfg.max_entry_read_bytes,
                    )
                except Exception as exc:  # noqa: BLE001 - capture per-entry issues
                    warnings.append(f"Failed to hash ZIP entry '{name}': {exc}")
            elif compute_hashes and not info.is_dir() and info.file_size > cfg.max_entry_read_bytes:
                warnings.append(
                    f"Skipped hash for large ZIP entry '{name}' ({info.file_size} bytes)."
                )

            entry = ZipEntryInfo(
                name=name,
                size_bytes=info.file_size,
                compressed_size_bytes=info.compress_size,
                compression=compression_name(info.compress_type),
                crc32=f"{info.CRC:08x}",
                sha256=sha256,
                is_directory=info.is_dir(),
                entry_type=entry_type,
                suspicious=suspicious,
                suspicion_reasons=reasons,
            )
            entries.append(entry)
            counts[entry_type] = counts.get(entry_type, 0) + 1
            if suspicious:
                counts["suspicious"] += 1
                warnings.append(f"Suspicious ZIP path detected: {name} ({', '.join(reasons)})")

        status = AnalysisStatus.COMPLETE.value
        if errors:
            status = AnalysisStatus.PARTIAL.value

        data = {
            "entry_count": len(entries),
            "counts": counts,
            "entries": [e.to_dict() for e in entries],
            "has_manifest": counts.get("manifest", 0) > 0,
            "has_dex": counts.get("dex", 0) > 0,
            "has_native": counts.get("native", 0) > 0,
        }

    return ScannerResult(
        name="zip_inventory",
        status=status,
        duration_ms=timing["duration_ms"],
        warnings=warnings,
        errors=errors,
        data=data,
    )


def list_entry_names(zf: zipfile.ZipFile) -> list[str]:
    return [info.filename for info in zf.infolist()]
