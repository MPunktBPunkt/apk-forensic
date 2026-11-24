"""DEX inventory and limited string extraction."""

from __future__ import annotations

import re
import zipfile
from typing import Any

from apk_forensics.candidate_scanner import ScanBlob
from apk_forensics.config import AnalysisConfig
from apk_forensics.hashing import bytes_sha256
from apk_forensics.models import AnalysisStatus, ScannerResult
from apk_forensics.string_scanner import extract_strings
from apk_forensics.utils import timed_ms

DEX_NAME_RE = re.compile(r"^classes\d*\.dex$", re.IGNORECASE)


def _optional_androguard_dex_stats(data: bytes) -> tuple[dict[str, Any] | None, bool, str | None]:
    try:
        from androguard.core.dex import DEX  # type: ignore
    except Exception:
        return None, True, None
    try:
        dex = DEX(data)
        classes = list(dex.get_classes())
        methods = list(dex.get_methods())
        fields = list(dex.get_fields())
        return {
            "class_count": len(classes),
            "method_count": len(methods),
            "field_count": len(fields),
            "optional_semantics": True,
            "sample_class_names": [str(c.get_name()) for c in classes[:20]],
        }, False, None
    except Exception as exc:  # noqa: BLE001
        return None, False, str(exc)


def analyze_dex(
    zf: zipfile.ZipFile,
    *,
    config: AnalysisConfig | None = None,
) -> ScannerResult:
    cfg = config or AnalysisConfig()
    with timed_ms() as timing:
        inventory: list[dict[str, Any]] = []
        blobs: list[ScanBlob] = []
        warnings: list[str] = []
        errors: list[str] = []
        optional_missing = False

        dex_names = sorted(
            info.filename
            for info in zf.infolist()
            if not info.is_dir() and DEX_NAME_RE.match(info.filename.split("/")[-1])
        )

        for name in dex_names:
            entry: dict[str, Any] = {
                "entry": name,
                "size_bytes": None,
                "sha256": None,
                "parse_status": "inventory_only",
                "string_count": 0,
                "classes": None,
                "methods": None,
                "fields": None,
                "optional_semantics": False,
            }
            try:
                info = zf.getinfo(name)
                if info.file_size > cfg.max_entry_read_bytes:
                    warnings.append(f"DEX entry too large for full read: {name}")
                    entry["size_bytes"] = info.file_size
                    entry["parse_status"] = "partial"
                    inventory.append(entry)
                    continue
                raw = zf.read(name)
                entry["size_bytes"] = len(raw)
                entry["sha256"] = bytes_sha256(raw)
                strings = extract_strings(raw, config=cfg)
                entry["string_count"] = len(strings)
                blobs.append(ScanBlob(entry=name, file_type="dex", data=raw))

                stats, missing, err = _optional_androguard_dex_stats(raw)
                if missing:
                    optional_missing = True
                elif err:
                    warnings.append(f"Optional DEX semantics failed for {name}: {err}")
                    entry["parse_status"] = "partial"
                elif stats:
                    entry.update(
                        {
                            "parse_status": "parsed_optional",
                            "classes": stats.get("class_count"),
                            "methods": stats.get("method_count"),
                            "fields": stats.get("field_count"),
                            "optional_semantics": True,
                            "sample_class_names": stats.get("sample_class_names", []),
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Failed to analyze DEX entry {name}: {exc}")
                entry["parse_status"] = "failed"
            inventory.append(entry)

        status = AnalysisStatus.COMPLETE.value
        if warnings:
            status = AnalysisStatus.PARTIAL.value
        if optional_missing:
            warnings.append(
                "androguard not installed; DEX semantic counts unavailable. "
                "Inventory and string offsets remain available."
            )
            status = AnalysisStatus.PARTIAL.value

    result = ScannerResult(
        name="dex_analyzer",
        status=status,
        duration_ms=timing["duration_ms"],
        warnings=warnings,
        errors=errors,
        optional_dependency_missing=optional_missing,
        data={"inventory": inventory, "blobs": blobs},
    )
    return result
