"""Finding construction and stable ID generation."""

from __future__ import annotations

import hashlib
from typing import Iterable

from apk_forensics.models import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    ProfileMatchRef,
    SourceRef,
)


def stable_finding_id(
    *,
    artifact_sha256: str,
    source_entry: str,
    offset: int | None,
    kind: str,
    category: str,
    normalized_value: str,
) -> str:
    stable_key = "|".join(
        [
            artifact_sha256,
            source_entry,
            str(offset),
            kind,
            category,
            normalized_value,
        ]
    )
    digest = hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:20]
    return f"finding-{digest}"


def make_finding(
    *,
    artifact_sha256: str,
    kind: str,
    category: str,
    value: str,
    normalized_value: str | None = None,
    classification: str = Classification.FACT.value,
    confidence: str = Confidence.HIGH.value,
    source_entry: str,
    file_type: str | None = None,
    offset: int | None = None,
    length: int | None = None,
    matched_text: str | None = None,
    context_before: str = "",
    context_after: str = "",
    pattern: str | None = None,
    scanner: str,
    subcategory: str | None = None,
    tags: list[str] | None = None,
    notes: list[str] | None = None,
    profile_matches: list[ProfileMatchRef] | None = None,
    section: str | None = None,
    class_name: str | None = None,
    method_name: str | None = None,
) -> Finding:
    norm = normalized_value if normalized_value is not None else value
    finding_id = stable_finding_id(
        artifact_sha256=artifact_sha256,
        source_entry=source_entry,
        offset=offset,
        kind=kind,
        category=category,
        normalized_value=norm,
    )
    return Finding(
        id=finding_id,
        display_id="",  # assigned later
        kind=kind,
        category=category,
        subcategory=subcategory,
        value=value,
        normalized_value=norm,
        classification=classification,
        confidence=confidence,
        source=SourceRef(
            entry=source_entry,
            file_type=file_type,
            offset=offset,
            length=length,
            section=section,
            class_name=class_name,
            method_name=method_name,
        ),
        evidence=Evidence(
            matched_text=matched_text if matched_text is not None else value,
            context_before=context_before,
            context_after=context_after,
            pattern=pattern,
            scanner=scanner,
        ),
        profile_matches=list(profile_matches or []),
        tags=list(tags or []),
        notes=list(notes or []),
    )


def finding_sort_key(finding: Finding) -> tuple:
    offset = finding.source.offset
    # None offsets sort after numeric offsets for stability
    offset_key = (1, 0) if offset is None else (0, offset)
    return (
        finding.source.entry or "",
        offset_key,
        finding.category or "",
        finding.kind or "",
        finding.normalized_value or "",
    )


def sort_and_assign_display_ids(findings: Iterable[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=finding_sort_key)
    # Deduplicate by stable id while preserving order
    unique: list[Finding] = []
    seen: set[str] = set()
    for finding in ordered:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        unique.append(finding)
    for index, finding in enumerate(unique, start=1):
        finding.display_id = f"F{index:06d}"
    return unique
