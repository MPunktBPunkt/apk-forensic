from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from apk_forensics.bundle_pipeline import run_bundle_pipeline
from apk_forensics.cli import main
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ExitCode
from apk_forensics.pipeline import run_pipeline


def _make_apk(path: Path, *, dex: bool, native: bool, payload: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x00SYNTH")
        if dex:
            zf.writestr("classes.dex", b"dex\n" + payload)
        if native:
            zf.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + payload)
    return path


def test_single_apk_unchanged(synthetic_apk: Path, tmp_path: Path) -> None:
    report, outputs, _ = run_pipeline(
        synthetic_apk,
        tmp_path / "out",
        config=AnalysisConfig(formats=("json",)),
    )
    assert report.input.sha256
    assert report.artifact.sha256 == report.input.sha256
    assert report.findings
    assert all(f.source.artifact == synthetic_apk.name for f in report.findings)
    assert outputs["json"].exists()


def test_bundle_preserves_provenance(tmp_path: Path) -> None:
    base = _make_apk(tmp_path / "base.apk", dex=True, native=False, payload=b"BASE")
    split = _make_apk(tmp_path / "config.arm64_v8a.apk", dex=False, native=True, payload=b"SPLIT")
    bundle_report, outputs, _ = run_bundle_pipeline(
        [base, split],
        tmp_path / "bundle-out",
        config=AnalysisConfig(formats=("json", "markdown")),
    )
    assert outputs["json"].exists()
    members = {m["file_name"]: m for m in bundle_report["members"]}
    assert members["base.apk"]["dex_count"] >= 1
    assert members["base.apk"]["native_so_count"] == 0
    assert members["config.arm64_v8a.apk"]["dex_count"] == 0
    assert members["config.arm64_v8a.apk"]["native_so_count"] >= 1

    # Must NOT look like base absorbed split natives
    assert members["base.apk"]["native_so_count"] != members["config.arm64_v8a.apk"]["native_so_count"] or (
        members["base.apk"]["native_so_count"] == 0
    )

    for finding in bundle_report["findings"]:
        assert finding["source"].get("artifact")
        assert finding["source"].get("artifact_sha256")


def test_bundle_cli_unrelated_packages(tmp_path: Path) -> None:
    # Without parseable manifests correlation is UNKNOWN — still produces reports
    a = _make_apk(tmp_path / "a.apk", dex=True, native=False)
    b = _make_apk(tmp_path / "b.apk", dex=False, native=True)
    code = main(
        [
            "scan",
            str(a),
            "--split",
            str(b),
            "--output",
            str(tmp_path / "out"),
            "--format",
            "json",
        ]
    )
    assert code in {ExitCode.SUCCESS, ExitCode.PARTIAL_OR_WARNINGS}
    data = json.loads((tmp_path / "out" / "bundle.json").read_text(encoding="utf-8"))
    assert data["artifact_bundle"]["correlation_status"] in {"unknown", "partial", "correlated"}


def test_reproducibility_same_sha(synthetic_apk: Path, tmp_path: Path) -> None:
    r1, _, _ = run_pipeline(synthetic_apk, tmp_path / "o1", config=AnalysisConfig(formats=("json",)))
    r2, _, _ = run_pipeline(synthetic_apk, tmp_path / "o2", config=AnalysisConfig(formats=("json",)))
    assert r1.input.sha256 == r2.input.sha256
    assert r1.artifact.sha256 == r2.artifact.sha256
    assert r1.input.file_name == r2.input.file_name


@pytest.mark.skipif(
    not (Path("artifacts/de.bmw.connected.mobile20.row.apk").exists()
         and Path("artifacts/config.arm64_v8a.apk").exists()),
    reason="MyBMW artifacts not present",
)
def test_mybmw_bundle_regression(tmp_path: Path) -> None:
    base = Path("artifacts/de.bmw.connected.mobile20.row.apk")
    split = Path("artifacts/config.arm64_v8a.apk")
    bundle_report, _, _ = run_bundle_pipeline(
        [base, split],
        tmp_path / "mybmw-v04",
        config=AnalysisConfig(formats=("json", "markdown")),
    )
    members = {m["file_name"]: m for m in bundle_report["members"]}
    base_m = members[base.name]
    split_m = members[split.name]
    assert base_m["dex_count"] == 4
    assert base_m["native_so_count"] == 0
    assert split_m["dex_count"] == 0
    assert split_m["native_so_count"] == 23
    assert bundle_report["artifact_bundle"]["correlation_status"] in {"correlated", "partial"}
    # Base must not appear to own the 23 natives
    assert base_m["native_so_count"] != 23
