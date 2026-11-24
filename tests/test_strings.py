from __future__ import annotations

from pathlib import Path

from apk_forensics.config import AnalysisConfig
from apk_forensics.string_scanner import extract_strings


def test_ascii_strings_and_offset(sample_binary: Path) -> None:
    data = sample_binary.read_bytes()
    strings = extract_strings(data, config=AnalysisConfig(min_string_length=4))
    values = {s.value for s in strings}
    assert "createRfcommSocketToServiceRecord" in values
    hit = next(s for s in strings if s.value == "createRfcommSocketToServiceRecord")
    assert data[hit.offset : hit.offset + hit.length] == b"createRfcommSocketToServiceRecord"


def test_min_length_and_context(sample_binary: Path) -> None:
    data = sample_binary.read_bytes()
    strings = extract_strings(data, config=AnalysisConfig(min_string_length=8, max_context_length=10))
    assert all(len(s.value) >= 8 for s in strings)
    assert all(len(s.context_before) <= 10 for s in strings)
    assert all(len(s.context_after) <= 10 for s in strings)


def test_high_entropy_filtered() -> None:
    blob = b"safe_string_here\n" + (b"A" * 80) + b"\n"
    # Pure repeated A is low entropy; use random-looking hex
    blob = b"safe_string_here\n" + b"a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef0123456789abcd\n"
    strings = extract_strings(blob, config=AnalysisConfig(min_string_length=4))
    values = [s.value for s in strings]
    assert "safe_string_here" in values
    assert not any(len(v) >= 40 and all(c in "0123456789abcdef" for c in v.lower()) for v in values)
