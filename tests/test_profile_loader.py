from __future__ import annotations

from pathlib import Path

import pytest

from apk_forensics.errors import ProfileError
from apk_forensics.finding_factory import make_finding
from apk_forensics.models import Classification
from apk_forensics.profile_loader import apply_profile, load_profile


def test_load_profile(sample_profile: Path) -> None:
    profile = load_profile(str(sample_profile))
    assert profile.name == "sample_profile"
    assert profile.strings


def test_invalid_profile(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("just: a string root\n", encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profile(str(bad))


def test_profile_match_is_correlation_not_fact_override(sample_profile: Path) -> None:
    profile = load_profile(str(sample_profile))
    existing = [
        make_finding(
            artifact_sha256="abc",
            kind="api",
            category="bluetooth",
            value="createRfcommSocketToServiceRecord",
            source_entry="classes.dex",
            offset=10,
            length=34,
            scanner="api_scanner",
            classification=Classification.FACT.value,
        )
    ]
    data = b"xxxxcreateRfcommSocketToServiceRecordyyyy"
    result = apply_profile(
        profile,
        blobs=[("classes.dex", "dex", data)],
        existing_findings=existing,
        artifact_sha256="abc",
    )
    # Original classification remains FACT; profile attached
    assert existing[0].classification == Classification.FACT.value
    assert existing[0].profile_matches
    assert existing[0].profile_matches[0].profile == "sample_profile"
    assert result.status in {"complete", "partial"}
