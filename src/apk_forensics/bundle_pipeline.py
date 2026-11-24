"""Unified ArtifactBundle analysis: per-member provenance preserved."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from apk_forensics import __schema_version_bundle__, __version__
from apk_forensics.artifact_bundle import (
    Artifact,
    ArtifactBundle,
    correlate_artifacts,
    inspect_artifact,
)
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import InputError
from apk_forensics.models import Report
from apk_forensics.pipeline import run_pipeline, stamp_finding_provenance
from apk_forensics.report_writer import write_json_report
from apk_forensics.utils import ensure_parent, utc_now_iso
from apk_forensics.workspace import WorkSession, write_managed_manifest


def _member_summary(report: Report, artifact: Artifact) -> dict[str, Any]:
    dex_count = len(report.dex_inventory or [])
    native_count = len(report.native_inventory or [])
    return {
        "file_name": artifact.identity.file_name,
        "path": artifact.identity.path,
        "sha256": artifact.identity.sha256,
        "size_bytes": artifact.identity.size_bytes,
        "role": artifact.meta.role,
        "split_name": artifact.meta.split_name,
        "abi": artifact.meta.abi,
        "density": artifact.meta.density,
        "locale": artifact.meta.locale,
        "package_name": report.artifact.package_name or artifact.meta.package_name,
        "version_name": report.artifact.version_name or artifact.meta.version_name,
        "version_code": report.artifact.version_code or artifact.meta.version_code,
        "dex_count": dex_count,
        "native_so_count": native_count,
        "finding_count": len([f for f in report.findings if f.classification != "REJECTED"]),
        "analysis_status": report.analysis.status,
        "report_path": None,
    }


def _render_bundle_markdown(bundle_report: dict[str, Any]) -> str:
    b = bundle_report.get("artifact_bundle") or {}
    lines = [
        "# APK Forensics Bundle Report",
        "",
        "## Bundle Summary",
        "",
        f"- Bundle ID: `{b.get('bundle_id')}`",
        f"- Correlation: `{b.get('correlation_status')}`",
        f"- Package: `{b.get('package_name')}`",
        f"- Version: `{b.get('version_name')}` (code `{b.get('version_code')}`)",
        f"- Tool: apk-forensics `{bundle_report.get('tool', {}).get('version')}`",
        f"- Schema: `{bundle_report.get('schema_version')}`",
        f"- Generated: `{bundle_report.get('generated_at_utc')}`",
        "",
        "Physical APK files remain distinct. Findings keep `source.artifact` provenance.",
        "",
        "## Members",
        "",
        "| Role | File | SHA-256 | DEX | Native .so | Findings |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for m in bundle_report.get("members") or []:
        lines.append(
            "| {role} | `{file}` | `{sha}` | {dex} | {native} | {findings} |".format(
                role=m.get("role"),
                file=m.get("file_name"),
                sha=(m.get("sha256") or "")[:16] + "…",
                dex=m.get("dex_count"),
                native=m.get("native_so_count"),
                findings=m.get("finding_count"),
            )
        )
    if b.get("correlation_reasons"):
        lines.extend(["", "## Correlation Evidence", ""])
        for r in b["correlation_reasons"]:
            lines.append(f"- {r}")
    if b.get("unknowns"):
        lines.extend(["", "## Unknowns", ""])
        for u in b["unknowns"]:
            lines.append(f"- {u}")
    lines.extend(
        [
            "",
            "## Provenance Note",
            "",
            "Base and split inventories are never merged into a single physical artifact.",
            "A native library found in an ABI split is attributed to that split APK only.",
            "",
        ]
    )
    return "\n".join(lines)


def run_bundle_pipeline(
    apk_paths: list[Path],
    output_dir: Path,
    *,
    config: AnalysisConfig | None = None,
    profile_path: str | None = None,
    work_session: WorkSession | None = None,
    search_plan: Any | None = None,
) -> tuple[dict[str, Any], dict[str, Path], list[str]]:
    """Analyze each APK separately, then emit a unified bundle view."""
    cfg = config or AnalysisConfig()
    if not apk_paths:
        raise InputError("No APK paths provided for bundle analysis")

    artifacts = [inspect_artifact(p) for p in apk_paths]
    bundle = correlate_artifacts(artifacts)

    if bundle.correlation_status == "unknown" and len(artifacts) > 1:
        # Do not invent a merge; still analyze members separately with clear UNKNOWN status
        pass

    output_dir.mkdir(parents=True, exist_ok=True)
    write_managed_manifest(
        output_dir,
        kind="output",
        meta={"bundle_id": bundle.bundle_id, "member_count": len(artifacts)},
    )

    member_reports: list[tuple[Artifact, Report, dict[str, Path]]] = []
    warnings: list[str] = list(bundle.unknowns)

    for artifact in artifacts:
        member_dir = output_dir / "members" / artifact.identity.sha256[:16]
        member_dir.mkdir(parents=True, exist_ok=True)
        report, outputs, member_warnings = run_pipeline(
            Path(artifact.identity.path),
            member_dir,
            config=cfg,
            profile_path=profile_path,
            artifact_meta=artifact,
            search_plan=search_plan,
        )
        stamp_finding_provenance(
            report,
            artifact_file=artifact.identity.file_name,
            artifact_sha256=artifact.identity.sha256,
        )
        # Re-write reports after provenance stamp
        if "json" in outputs:
            write_json_report(report, outputs["json"])
        member_reports.append((artifact, report, outputs))
        warnings.extend(member_warnings)

    members_out: list[dict[str, Any]] = []
    unified_findings: list[dict[str, Any]] = []
    for artifact, report, outputs in member_reports:
        summary = _member_summary(report, artifact)
        if "json" in outputs:
            summary["report_path"] = str(outputs["json"])
        members_out.append(summary)
        for finding in report.findings:
            if finding.classification == "REJECTED" and not cfg.debug:
                continue
            fd = finding.to_dict()
            fd.setdefault("source", {})
            # Ensure provenance even if stamp missed
            fd["source"]["artifact"] = artifact.identity.file_name
            fd["source"]["artifact_sha256"] = artifact.identity.sha256
            unified_findings.append(fd)

    started = utc_now_iso()
    plan_section = None
    if search_plan is not None and hasattr(search_plan, "to_report_section"):
        plan_section = search_plan.to_report_section()
    elif isinstance(search_plan, dict):
        plan_section = search_plan
    bundle_report: dict[str, Any] = {
        "schema_version": __schema_version_bundle__,
        "report_id": str(uuid.uuid5(uuid.NAMESPACE_URL, bundle.bundle_id + "|" + started)),
        "generated_at_utc": started,
        "tool": {"name": "apk-forensics", "version": __version__},
        "artifact_bundle": bundle.to_dict(),
        "members": members_out,
        "findings": unified_findings,
        "analysis": {
            "status": (
                "complete"
                if bundle.correlation_status in {"correlated", "singleton"}
                and not any(m["analysis_status"] == "failed" for m in members_out)
                else "partial"
            ),
            "warnings": warnings,
            "member_count": len(members_out),
            "engine_version": __version__,
            "plan_sha256": getattr(cfg, "search_plan_sha256", None),
        },
        "limitations": [
            "Bundle view aggregates separate per-APK analyses; files are not merged.",
            "Correlation without matching package+versionCode remains UNKNOWN.",
            "Filename hints alone never establish FACT membership.",
            "Static analysis only; no runtime execution.",
            "A SearchPlan describes an investigation request; it is not evidence.",
        ],
    }
    if plan_section is not None:
        bundle_report["search_plan"] = plan_section

    outputs_all: dict[str, Path] = {}
    formats = set(cfg.formats)
    if "all" in formats:
        formats = {"json", "markdown"}
    if "json" in formats:
        json_path = output_dir / "bundle.json"
        ensure_parent(json_path)
        json_path.write_text(json.dumps(bundle_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        outputs_all["json"] = json_path
        # Also write report.json alias for consistency with single-scan layout
        report_alias = output_dir / "report.json"
        report_alias.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
        outputs_all["report_json"] = report_alias
    if "markdown" in formats or "md" in formats:
        md_path = output_dir / "bundle.md"
        md_path.write_text(_render_bundle_markdown(bundle_report), encoding="utf-8")
        outputs_all["markdown"] = md_path
        (output_dir / "report.md").write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")

    if work_session is not None:
        work_session.cleanup()

    return bundle_report, outputs_all, warnings
