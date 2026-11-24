from __future__ import annotations

from pathlib import Path

import pytest

from apk_forensics.artifact_bundle import (
    Artifact,
    ArtifactIdentity,
    ArtifactMeta,
    correlate_artifacts,
    inspect_artifact,
)


def _art(
    name: str,
    *,
    package: str | None,
    version_code: str | None,
    version_name: str | None = "1.0",
    role: str = "unknown",
    split_name: str | None = None,
    sha: str | None = None,
) -> Artifact:
    return Artifact(
        identity=ArtifactIdentity(
            path=f"/tmp/{name}",
            file_name=name,
            sha256=sha or ("a" * 64 if role != "split" else "b" * 64),
            size_bytes=10,
        ),
        meta=ArtifactMeta(
            package_name=package,
            version_name=version_name,
            version_code=version_code,
            split_name=split_name,
            role=role,
        ),
    )


def test_singleton_bundle() -> None:
    a = _art("app.apk", package="com.example", version_code="1", role="base")
    b = correlate_artifacts([a])
    assert b.correlation_status == "singleton"
    assert b.base is a


def test_correlate_base_and_split() -> None:
    base = _art("app.apk", package="com.example", version_code="42", role="base", sha="1" * 64)
    split = _art(
        "config.arm64_v8a.apk",
        package="com.example",
        version_code="42",
        role="split",
        split_name="config.arm64_v8a",
        sha="2" * 64,
    )
    b = correlate_artifacts([base, split])
    assert b.correlation_status == "correlated"
    assert b.base is base
    assert split in b.splits
    assert "package_name=com.example" in b.correlation_reasons


def test_reject_different_package() -> None:
    a = _art("a.apk", package="com.a", version_code="1", role="base", sha="1" * 64)
    b = _art("b.apk", package="com.b", version_code="1", role="split", sha="2" * 64)
    bundle = correlate_artifacts([a, b])
    assert bundle.correlation_status == "unknown"
    assert any("package_mismatch" in u for u in bundle.unknowns)


def test_reject_different_version_code() -> None:
    a = _art("a.apk", package="com.a", version_code="1", role="base", sha="1" * 64)
    b = _art("b.apk", package="com.a", version_code="2", role="split", sha="2" * 64)
    bundle = correlate_artifacts([a, b])
    assert bundle.correlation_status == "unknown"
    assert any("version_code_mismatch" in u for u in bundle.unknowns)


def test_reject_different_version_name() -> None:
    a = _art("a.apk", package="com.a", version_code="1", version_name="1.0", role="base", sha="1" * 64)
    b = _art("b.apk", package="com.a", version_code="1", version_name="2.0", role="split", sha="2" * 64)
    bundle = correlate_artifacts([a, b])
    assert bundle.correlation_status == "unknown"
    assert any("version_name_mismatch" in u for u in bundle.unknowns)


def test_filename_alone_not_enough(synthetic_apk: Path, tmp_path: Path) -> None:
    # Synthetic APK has no parseable manifest → role/package UNKNOWN; correlating
    # two differently named copies without meta must stay unknown.
    other = tmp_path / "config.arm64_v8a.apk"
    other.write_bytes(synthetic_apk.read_bytes())
    a = inspect_artifact(synthetic_apk)
    b = inspect_artifact(other)
    # Force missing identity keys if androguard somehow filled them from garbage
    if not a.meta.package_name or not b.meta.package_name:
        bundle = correlate_artifacts([a, b])
        assert bundle.correlation_status in {"unknown", "partial", "correlated", "singleton"}
        if not a.meta.package_name:
            assert bundle.correlation_status == "unknown"
            assert any("not_correlated" in u or "missing" in u for u in bundle.unknowns)
    else:
        pytest.skip("androguard unexpectedly parsed synthetic manifest")
