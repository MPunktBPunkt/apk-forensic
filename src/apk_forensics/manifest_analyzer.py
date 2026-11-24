"""AndroidManifest.xml analysis with optional androguard support."""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from apk_forensics.config import AnalysisConfig
from apk_forensics.hashing import bytes_sha256
from apk_forensics.models import AnalysisStatus, ScannerResult
from apk_forensics.utils import timed_ms


def _try_androguard_parse(apk_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        from androguard.core.apk import APK  # type: ignore
    except Exception:
        return None, "androguard_missing"

    try:
        # Prefer full APK path; androguard needs the complete package, not manifest bytes alone.
        apk = APK(str(apk_path))
        permissions = sorted(set(apk.get_permissions() or []))
        activities = sorted(set(apk.get_activities() or []))
        services = sorted(set(apk.get_services() or []))
        receivers = sorted(set(apk.get_receivers() or []))
        providers = sorted(set(apk.get_providers() or []))
        intent_filters: list[dict[str, Any]] = []
        # Best-effort intent filter extraction; APIs vary by androguard version.
        try:
            for activity in activities:
                filters = apk.get_intent_filters("activity", activity) or {}
                if filters:
                    intent_filters.append({"component": activity, "type": "activity", "filters": filters})
        except Exception:
            pass

        exported: dict[str, list[str]] = {"activities": [], "services": [], "receivers": [], "providers": []}
        return {
            "parse_status": "parsed",
            "package_name": apk.get_package(),
            "version_name": apk.get_androidversion_name(),
            "version_code": str(apk.get_androidversion_code()) if apk.get_androidversion_code() is not None else None,
            "min_sdk": str(apk.get_min_sdk_version()) if apk.get_min_sdk_version() is not None else None,
            "target_sdk": str(apk.get_target_sdk_version()) if apk.get_target_sdk_version() is not None else None,
            "permissions": permissions,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "intent_filters": intent_filters,
            "exported": exported,
        }, None
    except Exception as exc:  # noqa: BLE001
        return None, f"androguard_parse_failed: {exc}"


def analyze_manifest(
    zf: zipfile.ZipFile,
    *,
    apk_path: Path | None = None,
    config: AnalysisConfig | None = None,
) -> ScannerResult:
    _ = config
    with timed_ms() as timing:
        warnings: list[str] = []
        errors: list[str] = []
        optional_missing = False
        data: dict[str, Any] = {
            "present": False,
            "parse_status": "unavailable",
            "entry": "AndroidManifest.xml",
            "size_bytes": None,
            "sha256": None,
        }

        names = {info.filename for info in zf.infolist()}
        if "AndroidManifest.xml" not in names:
            warnings.append("AndroidManifest.xml not found in APK.")
            return ScannerResult(
                name="manifest_analyzer",
                status=AnalysisStatus.PARTIAL.value,
                duration_ms=timing["duration_ms"],
                warnings=warnings,
                errors=errors,
                data=data,
            )

        try:
            raw = zf.read("AndroidManifest.xml")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Failed to read AndroidManifest.xml: {exc}")
            data["parse_status"] = "failed"
            return ScannerResult(
                name="manifest_analyzer",
                status=AnalysisStatus.FAILED.value,
                duration_ms=timing["duration_ms"],
                warnings=warnings,
                errors=errors,
                data=data,
            )

        data["present"] = True
        data["size_bytes"] = len(raw)
        data["sha256"] = bytes_sha256(raw)

        if apk_path is None:
            optional_missing = True
            data["parse_status"] = "unavailable"
            warnings.append(
                "Binary AndroidManifest.xml detected; semantic parsing unavailable. "
                "Install the optional android dependency to enable manifest parsing."
            )
            status = AnalysisStatus.PARTIAL.value
        else:
            parsed, err = _try_androguard_parse(apk_path)
            if err == "androguard_missing":
                optional_missing = True
                data["parse_status"] = "unavailable"
                warnings.append(
                    "Binary AndroidManifest.xml detected; semantic parsing unavailable. "
                    "Install the optional android dependency to enable manifest parsing."
                )
                status = AnalysisStatus.PARTIAL.value
            elif parsed is None:
                data["parse_status"] = "failed"
                warnings.append(f"Manifest parsing failed: {err}")
                status = AnalysisStatus.PARTIAL.value
            else:
                data.update(parsed)
                status = AnalysisStatus.COMPLETE.value

    return ScannerResult(
        name="manifest_analyzer",
        status=status,
        duration_ms=timing["duration_ms"],
        warnings=warnings,
        errors=errors,
        optional_dependency_missing=optional_missing,
        data=data,
    )
