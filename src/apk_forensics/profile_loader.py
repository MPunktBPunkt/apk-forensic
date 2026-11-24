"""YAML profile loading and candidate correlation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ProfileError
from apk_forensics.finding_factory import make_finding
from apk_forensics.models import (
    AnalysisStatus,
    Classification,
    Confidence,
    Finding,
    ProfileMatchRef,
    ScannerResult,
)
from apk_forensics.utils import resolve_profile_path, timed_ms


@dataclass
class ProfileEntry:
    value: Any
    category: str
    profile_confidence: str = Confidence.MEDIUM.value
    tags: list[str] = field(default_factory=list)


@dataclass
class AnalysisProfile:
    name: str
    version: str
    description: str = ""
    strings: list[ProfileEntry] = field(default_factory=list)
    apis: list[ProfileEntry] = field(default_factory=list)
    uuids: list[ProfileEntry] = field(default_factory=list)
    ports: list[ProfileEntry] = field(default_factory=list)
    regexes: list[ProfileEntry] = field(default_factory=list)
    source_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "source_path": self.source_path,
            "counts": {
                "strings": len(self.strings),
                "apis": len(self.apis),
                "uuids": len(self.uuids),
                "ports": len(self.ports),
                "regexes": len(self.regexes),
            },
        }


def _parse_entries(items: Any, *, field_name: str) -> list[ProfileEntry]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ProfileError(f"Profile field '{field_name}' must be a list.")
    entries: list[ProfileEntry] = []
    for item in items:
        if not isinstance(item, dict) or "value" not in item or "category" not in item:
            raise ProfileError(f"Invalid profile entry in '{field_name}'.")
        entries.append(
            ProfileEntry(
                value=item["value"],
                category=str(item["category"]),
                profile_confidence=str(item.get("profile_confidence", Confidence.MEDIUM.value)),
                tags=[str(t) for t in item.get("tags", [])],
            )
        )
    return entries


def load_profile(path_or_name: str, *, profiles_dir: Path | None = None) -> AnalysisProfile:
    try:
        path = resolve_profile_path(path_or_name, profiles_dir=profiles_dir)
    except FileNotFoundError as exc:
        raise ProfileError(str(exc)) from exc
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ProfileError(f"Failed to load profile YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ProfileError("Profile root must be a mapping.")
    if "name" not in raw or "version" not in raw:
        raise ProfileError("Profile must contain 'name' and 'version'.")

    # regexes use pattern key
    regex_items = []
    for item in raw.get("regexes") or []:
        if not isinstance(item, dict):
            raise ProfileError("Invalid regex profile entry.")
        if "pattern" not in item or "category" not in item:
            raise ProfileError("Regex entries require 'pattern' and 'category'.")
        regex_items.append(
            {
                "value": item["pattern"],
                "category": item["category"],
                "profile_confidence": item.get("profile_confidence", Confidence.MEDIUM.value),
                "tags": item.get("tags", []),
            }
        )

    return AnalysisProfile(
        name=str(raw["name"]),
        version=str(raw["version"]),
        description=str(raw.get("description", "")),
        strings=_parse_entries(raw.get("strings"), field_name="strings"),
        apis=_parse_entries(raw.get("apis"), field_name="apis"),
        uuids=_parse_entries(raw.get("uuids"), field_name="uuids"),
        ports=_parse_entries(raw.get("ports"), field_name="ports"),
        regexes=_parse_entries(regex_items, field_name="regexes"),
        source_path=str(path),
    )


def _attach_or_create_correlation(
    *,
    findings: list[Finding],
    artifact_sha256: str,
    profile: AnalysisProfile,
    entry: ProfileEntry,
    kind: str,
    matched_value: str,
    source_entry: str,
    file_type: str | None,
    offset: int | None,
    length: int | None,
    matched_text: str,
    context_before: str = "",
    context_after: str = "",
    pattern: str | None = None,
) -> Finding:
    profile_ref = ProfileMatchRef(
        profile=profile.name,
        profile_confidence=entry.profile_confidence,
        category=entry.category,
        tags=list(entry.tags),
    )
    # Prefer attaching to an existing FACT with same normalized value + entry.
    # Exact offset match first, then same entry/value fallback.
    candidates = [
        finding
        for finding in findings
        if finding.normalized_value.lower() == matched_value.lower()
        and finding.source.entry == source_entry
    ]
    exact = [f for f in candidates if offset is None or f.source.offset == offset]
    for finding in exact or candidates:
        # Avoid duplicate profile refs
        already = any(
            pm.profile == profile_ref.profile and pm.category == profile_ref.category
            for pm in finding.profile_matches
        )
        if not already:
            finding.profile_matches.append(profile_ref)
            if "profile_correlated" not in finding.tags:
                finding.tags.append("profile_correlated")
            # Keep original FACT classification; correlation is via profile_matches.
            finding.notes.append(
                f"Profile '{profile.name}' correlation for category '{entry.category}' "
                "(candidate only; not proof of protocol/device usage)."
            )
        return finding

    return make_finding(
        artifact_sha256=artifact_sha256,
        kind=kind,
        category=entry.category.split(".", 1)[0] if "." in entry.category else entry.category,
        subcategory=entry.category,
        value=matched_value,
        normalized_value=matched_value.lower() if kind == "uuid" else matched_value,
        classification=Classification.CORRELATION.value,
        confidence=Confidence.MEDIUM.value,
        source_entry=source_entry,
        file_type=file_type,
        offset=offset,
        length=length,
        matched_text=matched_text,
        context_before=context_before,
        context_after=context_after,
        pattern=pattern,
        scanner="profile_loader",
        tags=["profile_match", *entry.tags],
        notes=[
            "Profile match is a candidate correlation only.",
            "Does not prove vehicle, head unit, or protocol usage.",
        ],
        profile_matches=[profile_ref],
    )


def apply_profile(
    profile: AnalysisProfile,
    *,
    blobs: list[tuple[str, str, bytes]],
    existing_findings: list[Finding],
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
) -> ScannerResult:
    cfg = config or AnalysisConfig()
    with timed_ms() as timing:
        new_findings: list[Finding] = []
        warnings: list[str] = []
        errors: list[str] = []
        match_count = 0

        # Index existing findings for attachment
        working = list(existing_findings)

        for entry_name, file_type, data in blobs:
            text_ascii = data  # search in raw bytes
            # strings / apis / uuids as literal byte search
            literal_groups = [
                ("string", profile.strings),
                ("api", profile.apis),
                ("uuid", profile.uuids),
            ]
            for kind, entries in literal_groups:
                for entry in entries:
                    needle = str(entry.value).encode("utf-8")
                    # UUIDs: case-insensitive search via lower/upper variants
                    variants = [needle]
                    if kind == "uuid":
                        variants = [str(entry.value).lower().encode(), str(entry.value).upper().encode()]
                    for variant in variants:
                        start = 0
                        while True:
                            idx = text_ascii.find(variant, start)
                            if idx < 0:
                                break
                            finding = _attach_or_create_correlation(
                                findings=working,
                                artifact_sha256=artifact_sha256,
                                profile=profile,
                                entry=entry,
                                kind="profile_match" if kind == "string" else kind,
                                matched_value=str(entry.value),
                                source_entry=entry_name,
                                file_type=file_type,
                                offset=idx,
                                length=len(variant),
                                matched_text=variant.decode("utf-8", errors="ignore"),
                                pattern=f"profile_{kind}",
                            )
                            if finding not in working:
                                working.append(finding)
                                new_findings.append(finding)
                            match_count += 1
                            start = idx + len(variant)
                            if match_count >= cfg.max_findings_per_scanner:
                                break
                        if match_count >= cfg.max_findings_per_scanner:
                            break
                    if match_count >= cfg.max_findings_per_scanner:
                        break
                if match_count >= cfg.max_findings_per_scanner:
                    break

            # ports as decimal literals in context-ish data
            for entry in profile.ports:
                port = str(entry.value)
                needle = port.encode("ascii")
                start = 0
                while True:
                    idx = text_ascii.find(needle, start)
                    if idx < 0:
                        break
                    # require some nearby context suggestive of ports / numbers in strings
                    window = text_ascii[max(0, idx - 12) : idx + len(needle) + 12]
                    if not re.search(rb"(?i)port|channel|socket|[=:]", window):
                        start = idx + len(needle)
                        continue
                    finding = _attach_or_create_correlation(
                        findings=working,
                        artifact_sha256=artifact_sha256,
                        profile=profile,
                        entry=entry,
                        kind="port",
                        matched_value=port,
                        source_entry=entry_name,
                        file_type=file_type,
                        offset=idx,
                        length=len(needle),
                        matched_text=port,
                        pattern="profile_port",
                    )
                    if finding not in working:
                        working.append(finding)
                        new_findings.append(finding)
                    match_count += 1
                    start = idx + len(needle)
                    if match_count >= cfg.max_findings_per_scanner:
                        break

            # regexes over decoded latin-1 preview for simplicity
            preview = data.decode("latin-1", errors="ignore")
            for entry in profile.regexes:
                try:
                    pattern = re.compile(str(entry.value))
                except re.error as exc:
                    warnings.append(f"Invalid profile regex '{entry.value}': {exc}")
                    continue
                regex_matches = 0
                for match in pattern.finditer(preview):
                    finding = _attach_or_create_correlation(
                        findings=working,
                        artifact_sha256=artifact_sha256,
                        profile=profile,
                        entry=entry,
                        kind="profile_match",
                        matched_value=match.group(0),
                        source_entry=entry_name,
                        file_type=file_type,
                        offset=match.start(),
                        length=len(match.group(0)),
                        matched_text=match.group(0),
                        pattern=str(entry.value),
                    )
                    if finding not in working:
                        working.append(finding)
                        new_findings.append(finding)
                    match_count += 1
                    regex_matches += 1
                    if regex_matches >= cfg.max_profile_regex_matches:
                        warnings.append(
                            f"Regex match limit reached for pattern '{entry.value}' in {entry_name}."
                        )
                        break
                    if match_count >= cfg.max_findings_per_scanner:
                        break

        status = AnalysisStatus.COMPLETE.value
        if warnings:
            status = AnalysisStatus.PARTIAL.value

    return ScannerResult(
        name="profile_loader",
        status=status,
        duration_ms=timing["duration_ms"],
        warnings=warnings,
        errors=errors,
        data={"profile": profile.to_dict(), "match_count": match_count},
        findings=new_findings,
    )
