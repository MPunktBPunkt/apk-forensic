"""Analysis pipeline orchestration."""

from __future__ import annotations

import platform
import sys
import uuid
from pathlib import Path
from typing import Any

from apk_forensics import (
    __schema_version__,
    __schema_version_bluetooth_path__,
    __schema_version_dex_context__,
    __version__,
)
from apk_forensics.bluetooth_path import run_bluetooth_path_analysis
from apk_forensics.candidate_scanner import ScanBlob, run_candidate_scanner
from apk_forensics.config import AnalysisConfig
from apk_forensics.dex_analyzer import analyze_dex
from apk_forensics.dex_context_runner import run_dex_context_analysis
from apk_forensics.errors import InputError, InvalidApkError
from apk_forensics.finding_factory import sort_and_assign_display_ids
from apk_forensics.hashing import file_sha256_and_size
from apk_forensics.manifest_analyzer import analyze_manifest
from apk_forensics.models import (
    AnalysisInfo,
    AnalysisStatus,
    ArtifactInfo,
    Finding,
    InputInfo,
    Report,
    ScannerResult,
    ToolInfo,
)
from apk_forensics.native_analyzer import analyze_native
from apk_forensics.profile_loader import AnalysisProfile, apply_profile, load_profile
from apk_forensics.report_writer import write_json_report, write_markdown_report
from apk_forensics.utils import timed_ms, utc_now_iso
from apk_forensics.zip_inventory import build_zip_inventory, open_apk_zip


DEFAULT_LIMITATIONS = [
    "Static analysis only; no APK execution or runtime tracing.",
    "API/string presence does not prove runtime execution.",
    "No full DEX decompilation or unbounded call graph.",
    "No native disassembly or JNI correlation in v0.2.",
    "Profile matches are candidate correlations only.",
    "No credential/secret hunting is performed.",
    "Static DEX XREFs and candidate chains do not prove runtime paths.",
    "User-provided original APKs are never owned or auto-deleted by cleanup.",
    "A SearchPlan describes an investigation request; it is not evidence and invents no findings.",
    "Resource Guard never silently rewrites SearchPlan parameters; WARNING/REJECT are explicit.",
]


def _job_checkpoint(analysis_job: Any | None) -> None:
    if analysis_job is None:
        return
    from apk_forensics.analysis_job import check_runtime_limit

    token = getattr(analysis_job, "cancellation", None)
    if token is not None:
        token.check()
    check_runtime_limit(analysis_job)


def stamp_finding_provenance(
    report: Report,
    *,
    artifact_file: str,
    artifact_sha256: str,
) -> None:
    """Attach which physical APK each finding came from (bundle provenance)."""
    for finding in report.findings:
        finding.source.artifact = artifact_file
        finding.source.artifact_sha256 = artifact_sha256
    report.artifact.file_name = artifact_file
    report.artifact.sha256 = artifact_sha256


def _merge_status(statuses: list[str]) -> str:
    if any(s == AnalysisStatus.FAILED.value for s in statuses):
        # Pipeline may still be partial unless invalid apk
        return AnalysisStatus.PARTIAL.value
    if any(s == AnalysisStatus.PARTIAL.value for s in statuses):
        return AnalysisStatus.PARTIAL.value
    if any(s == AnalysisStatus.SKIPPED.value for s in statuses):
        return AnalysisStatus.PARTIAL.value
    return AnalysisStatus.COMPLETE.value


def _read_selected_blobs(zf, names: list[str], *, max_bytes: int) -> list[ScanBlob]:
    blobs: list[ScanBlob] = []
    for name in names:
        try:
            info = zf.getinfo(name)
            if info.file_size > max_bytes:
                continue
            data = zf.read(name)
            lower = name.lower()
            if lower.endswith(".dex"):
                file_type = "dex"
            elif lower.endswith(".so"):
                file_type = "native"
            elif lower.endswith("androidmanifest.xml"):
                file_type = "manifest"
            else:
                file_type = "other"
            blobs.append(ScanBlob(entry=name, file_type=file_type, data=data))
        except Exception:
            continue
    return blobs


def _apply_evidence_filter(findings: list[Finding], cfg: AnalysisConfig) -> list[Finding]:
    """Report filter only — does not reclassify findings."""
    allowed = cfg.evidence_classifications
    if not allowed:
        return findings
    allowed_set = set(allowed)
    return [f for f in findings if f.classification in allowed_set]


def run_pipeline(
    apk_path: Path,
    output_dir: Path,
    *,
    config: AnalysisConfig | None = None,
    profile_path: str | None = None,
    artifact_meta: Any | None = None,
    copy_input: bool = False,
    search_plan: Any | None = None,
    analysis_job: Any | None = None,
) -> tuple[Report, dict[str, Path], list[str]]:
    """Run shallow (+ optional deep) analysis on a single APK.

    The input APK is opened in place and is not copied unless ``copy_input`` is True.
    ``search_plan`` is an optional normalized SearchPlan describing the request.
    ``analysis_job`` optional v0.6 job for cancellation / runtime checkpoints / report section.
    """
    cfg = config or AnalysisConfig()
    warnings: list[str] = []
    errors: list[str] = []
    scanners: list[ScannerResult] = []
    findings: list[Finding] = []
    profile: AnalysisProfile | None = None
    started = utc_now_iso()
    plan_section = None
    if search_plan is not None and hasattr(search_plan, "to_report_section"):
        plan_section = search_plan.to_report_section()
    elif isinstance(search_plan, dict):
        plan_section = search_plan

    with timed_ms() as total_timing:
        if not apk_path.exists() or not apk_path.is_file():
            raise InputError(f"Input file does not exist or is not readable: {apk_path}")
        apk_path = apk_path.resolve()
        if copy_input:
            warnings.append("copy_input requested but deferred; analyzing source path in place")

        try:
            sha256, size_bytes = file_sha256_and_size(apk_path, chunk_size=cfg.hash_chunk_size)
        except InputError:
            raise
        except OSError as exc:
            raise InputError(f"Input file is not readable: {apk_path}") from exc

        try:
            zf = open_apk_zip(apk_path)
        except InvalidApkError:
            raise

        with zf:
            _job_checkpoint(analysis_job)
            zip_result = build_zip_inventory(zf, config=cfg, compute_hashes=True)
            scanners.append(zip_result)
            warnings.extend(zip_result.warnings)
            errors.extend(zip_result.errors)

            if profile_path:
                try:
                    profile = load_profile(profile_path)
                except Exception as exc:  # noqa: BLE001
                    raise InputError(f"Failed to load profile: {exc}", exit_code=2) from exc

            _job_checkpoint(analysis_job)
            manifest_result = analyze_manifest(zf, apk_path=apk_path, config=cfg)
            scanners.append(manifest_result)
            warnings.extend(manifest_result.warnings)
            errors.extend(manifest_result.errors)

            _job_checkpoint(analysis_job)
            dex_result = analyze_dex(zf, config=cfg)
            scanners.append(dex_result)
            warnings.extend(dex_result.warnings)
            errors.extend(dex_result.errors)
            dex_blobs: list[ScanBlob] = list(dex_result.data.get("blobs") or [])

            _job_checkpoint(analysis_job)
            native_result = analyze_native(zf, artifact_sha256=sha256, config=cfg)
            scanners.append(native_result)
            warnings.extend(native_result.warnings)
            errors.extend(native_result.errors)
            findings.extend(native_result.findings)
            native_blobs: list[ScanBlob] = list(native_result.data.get("blobs") or [])

            # Candidate scan over DEX + native (+ manifest bytes if present)
            blobs = list(dex_blobs) + list(native_blobs)
            if "AndroidManifest.xml" in zf.namelist():
                try:
                    manifest_raw = zf.read("AndroidManifest.xml")
                    if len(manifest_raw) <= cfg.max_entry_read_bytes:
                        blobs.append(
                            ScanBlob(
                                entry="AndroidManifest.xml",
                                file_type="manifest",
                                data=manifest_raw,
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"Could not include manifest in candidate scan: {exc}")

            _job_checkpoint(analysis_job)
            candidate_result = run_candidate_scanner(
                blobs,
                artifact_sha256=sha256,
                config=cfg,
            )
            scanners.append(candidate_result)
            warnings.extend(candidate_result.warnings)
            errors.extend(candidate_result.errors)
            findings.extend(candidate_result.findings)

            # Resource finding limit: fail closed (no silent truncation / plan rewrite)
            policy = getattr(analysis_job, "resource_policy", None) if analysis_job else None
            if policy is not None and policy.max_findings is not None:
                non_rejected = [f for f in findings if f.classification != "REJECTED"]
                if len(non_rejected) > policy.max_findings:
                    from apk_forensics.analysis_job import JobLimitExceeded

                    raise JobLimitExceeded(
                        "finding_limit",
                        f"finding_limit: {len(non_rejected)} findings exceed "
                        f"max_findings={policy.max_findings}",
                    )

            if profile is not None:
                profile_blobs = [(b.entry, b.file_type, b.data) for b in blobs]
                profile_result = apply_profile(
                    profile,
                    blobs=profile_blobs,
                    existing_findings=findings,
                    artifact_sha256=sha256,
                    config=cfg,
                )
                scanners.append(profile_result)
                warnings.extend(profile_result.warnings)
                errors.extend(profile_result.errors)
                findings.extend(profile_result.findings)

            # Normalize findings: drop REJECTED from main list unless debug
            if not cfg.debug:
                findings = [f for f in findings if f.classification != "REJECTED"]
            # Optional SearchPlan evidence filter (report wish only)
            findings = _apply_evidence_filter(findings, cfg)
            findings = sort_and_assign_display_ids(findings)

            dex_context_section = None
            if cfg.dex_context:
                _job_checkpoint(analysis_job)
                dex_context_section = run_dex_context_analysis(
                    apk_path,
                    findings,
                    artifact_sha256=sha256,
                    config=cfg,
                )
                warnings.extend(dex_context_section.get("warnings") or [])
                scanners.append(
                    ScannerResult(
                        name="dex_context",
                        status=dex_context_section.get("status") or AnalysisStatus.PARTIAL.value,
                        duration_ms=int(dex_context_section.get("duration_ms") or 0),
                        warnings=list(dex_context_section.get("warnings") or []),
                        errors=[],
                        optional_dependency_missing=(
                            dex_context_section.get("status") == "skipped"
                            and "androguard" in " ".join(dex_context_section.get("warnings") or []).lower()
                        ),
                    )
                )
                if policy is not None:
                    counts = (dex_context_section or {}).get("counts") or {}
                    ctx_n = counts.get("contexts", len((dex_context_section or {}).get("contexts") or []))
                    xref_n = counts.get(
                        "xref_candidates",
                        len((dex_context_section or {}).get("xref_candidates") or []),
                    )
                    if policy.max_dex_contexts is not None and ctx_n > policy.max_dex_contexts:
                        from apk_forensics.analysis_job import JobLimitExceeded

                        raise JobLimitExceeded(
                            "context_limit",
                            f"context_limit: {ctx_n} contexts exceed "
                            f"max_dex_contexts={policy.max_dex_contexts}",
                        )
                    if policy.max_xrefs is not None and xref_n > policy.max_xrefs:
                        from apk_forensics.analysis_job import JobLimitExceeded

                        raise JobLimitExceeded(
                            "xref_limit",
                            f"xref_limit: {xref_n} xrefs exceed max_xrefs={policy.max_xrefs}",
                        )

            bluetooth_section = None
            if cfg.bluetooth_path:
                _job_checkpoint(analysis_job)
                bluetooth_section = run_bluetooth_path_analysis(
                    apk_path,
                    findings,
                    artifact_sha256=sha256,
                    config=cfg,
                )
                warnings.extend(bluetooth_section.get("warnings") or [])
                scanners.append(
                    ScannerResult(
                        name="bluetooth_path",
                        status=bluetooth_section.get("status") or AnalysisStatus.PARTIAL.value,
                        duration_ms=int(bluetooth_section.get("duration_ms") or 0),
                        warnings=list(bluetooth_section.get("warnings") or []),
                        errors=[],
                        optional_dependency_missing=(
                            bluetooth_section.get("status") == "skipped"
                            and "androguard" in " ".join(bluetooth_section.get("warnings") or []).lower()
                        ),
                    )
                )

            role = None
            split_name = None
            if artifact_meta is not None:
                role = getattr(getattr(artifact_meta, "meta", None), "role", None)
                split_name = getattr(getattr(artifact_meta, "meta", None), "split_name", None)

            artifact = ArtifactInfo(
                type="apk",
                package_name=(manifest_result.data or {}).get("package_name"),
                version_name=(manifest_result.data or {}).get("version_name"),
                version_code=(manifest_result.data or {}).get("version_code"),
                min_sdk=(manifest_result.data or {}).get("min_sdk"),
                target_sdk=(manifest_result.data or {}).get("target_sdk"),
                role=role,
                split_name=split_name,
                sha256=sha256,
                file_name=apk_path.name,
            )

            analysis_status = _merge_status([s.status for s in scanners])
            if errors and cfg.fail_on_error:
                analysis_status = AnalysisStatus.FAILED.value

            if cfg.bluetooth_path:
                schema_version = __schema_version_bluetooth_path__
            elif cfg.dex_context:
                schema_version = __schema_version_dex_context__
            else:
                schema_version = __schema_version__

            finished = utc_now_iso()
            report = Report(
                schema_version=schema_version,
                report_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{sha256}|{started}")),
                generated_at_utc=finished,
                tool=ToolInfo(
                    name="apk-forensics",
                    version=__version__,
                    python_version=platform.python_version(),
                    platform=platform.platform(),
                ),
                input=InputInfo(
                    path=str(apk_path),
                    file_name=apk_path.name,
                    size_bytes=size_bytes,
                    sha256=sha256,
                    is_readable=True,
                    is_zip=True,
                ),
                artifact=artifact,
                analysis=AnalysisInfo(
                    status=analysis_status,
                    started_at_utc=started,
                    finished_at_utc=finished,
                    duration_ms=total_timing["duration_ms"],
                    scanners=[s.to_dict() for s in scanners],
                    warnings=warnings,
                    errors=errors,
                    engine_version=__version__,
                    plan_sha256=getattr(cfg, "search_plan_sha256", None),
                    search_plan_schema_version=(
                        plan_section.get("schema_version") if plan_section else None
                    ),
                ),
                manifest={
                    k: v
                    for k, v in (manifest_result.data or {}).items()
                    if k not in {"blobs"}
                },
                zip_inventory={
                    k: v
                    for k, v in (zip_result.data or {}).items()
                },
                dex_inventory=list((dex_result.data or {}).get("inventory") or []),
                native_inventory=[
                    {k: v for k, v in item.items() if k != "findings" or True}
                    for item in ((native_result.data or {}).get("inventory") or [])
                ],
                findings=findings,
                profile_matches=[
                    {
                        "finding_id": f.id,
                        "display_id": f.display_id,
                        "profile": pm.profile,
                        "category": pm.category,
                        "profile_confidence": pm.profile_confidence,
                    }
                    for f in findings
                    for pm in f.profile_matches
                ],
                limitations=list(DEFAULT_LIMITATIONS),
                dex_context=dex_context_section,
                bluetooth_path=bluetooth_section,
                bluetooth_dataflow=(
                    (bluetooth_section or {}).get("bluetooth_dataflow")
                    if bluetooth_section is not None
                    else None
                ),
                search_plan=plan_section,
                analysis_job=analysis_job.to_dict() if analysis_job is not None else None,
                resource=(
                    analysis_job.resource_report_section() if analysis_job is not None else None
                ),
            )
            stamp_finding_provenance(
                report,
                artifact_file=apk_path.name,
                artifact_sha256=sha256,
            )

            if cfg.include_raw:
                report.raw = {
                    "profile": profile.to_dict() if profile else None,
                    "scanner_data_keys": {s.name: sorted(s.data.keys()) for s in scanners},
                }

            output_dir.mkdir(parents=True, exist_ok=True)
            outputs: dict[str, Path] = {}
            formats = set(cfg.formats)
            if "all" in formats:
                formats = {"json", "markdown"}
            if "json" in formats:
                json_path = output_dir / "report.json"
                write_json_report(report, json_path)
                outputs["json"] = json_path
            if "markdown" in formats or "md" in formats:
                md_path = output_dir / "report.md"
                write_markdown_report(report, md_path)
                outputs["markdown"] = md_path

    return report, outputs, warnings
