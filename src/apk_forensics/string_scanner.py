"""Readable string extraction from binary blobs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from apk_forensics.config import (
    HIGH_ENTROPY_MIN_LENGTH,
    MAX_STRING_VALUE_LENGTH,
    AnalysisConfig,
)
from apk_forensics.utils import context_around, looks_high_entropy, truncate


ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % 4)


@dataclass
class ExtractedString:
    value: str
    encoding: str
    offset: int
    length: int
    context_before: str
    context_after: str


def _ascii_pattern(min_length: int) -> re.Pattern[bytes]:
    return re.compile(rb"[\x20-\x7e]{" + str(min_length).encode("ascii") + rb",}")


def _utf16le_pattern(min_length: int) -> re.Pattern[bytes]:
    # ASCII-range UTF-16LE printable sequences
    unit = rb"[\x20-\x7e]\x00"
    return re.compile(unit * min_length + rb"(?:" + unit + rb")*")


def extract_strings(
    data: bytes,
    *,
    config: AnalysisConfig | None = None,
    include_utf16le: bool = True,
) -> list[ExtractedString]:
    cfg = config or AnalysisConfig()
    results: list[ExtractedString] = []
    seen_offsets: set[tuple[str, int]] = set()

    for match in _ascii_pattern(cfg.min_string_length).finditer(data):
        raw = match.group()
        value = raw.decode("ascii", errors="ignore")
        if len(value) > MAX_STRING_VALUE_LENGTH:
            continue
        if looks_high_entropy(value, min_length=HIGH_ENTROPY_MIN_LENGTH):
            continue
        offset = match.start()
        before, after = context_around(data, offset, len(raw), cfg.max_context_length)
        key = ("ascii", offset)
        if key in seen_offsets:
            continue
        seen_offsets.add(key)
        results.append(
            ExtractedString(
                value=truncate(value, MAX_STRING_VALUE_LENGTH),
                encoding="ascii",
                offset=offset,
                length=len(raw),
                context_before=before,
                context_after=after,
            )
        )

    if include_utf16le:
        for match in _utf16le_pattern(cfg.min_string_length).finditer(data):
            raw = match.group()
            try:
                value = raw.decode("utf-16le")
            except UnicodeDecodeError:
                continue
            if len(value) > MAX_STRING_VALUE_LENGTH:
                continue
            if looks_high_entropy(value, min_length=HIGH_ENTROPY_MIN_LENGTH):
                continue
            offset = match.start()
            before, after = context_around(data, offset, len(raw), cfg.max_context_length)
            key = ("utf16le", offset)
            if key in seen_offsets:
                continue
            seen_offsets.add(key)
            results.append(
                ExtractedString(
                    value=truncate(value, MAX_STRING_VALUE_LENGTH),
                    encoding="utf-16le",
                    offset=offset,
                    length=len(raw),
                    context_before=before,
                    context_after=after,
                )
            )

    results.sort(key=lambda item: (item.offset, item.encoding, item.value))
    return results
