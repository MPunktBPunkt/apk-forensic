"""Orchestrate optional DEX context analysis for v0.2."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from apk_forensics.candidate_chains import build_candidate_chains
from apk_forensics.config import AnalysisConfig
from apk_forensics.dex_context import build_contexts, empty_dex_context_section
from apk_forensics.dex_matcher import select_queries_from_findings, stream_find_dex_matches
from apk_forensics.dex_model_adapter import (
    DexSession,
    get_androguard_version,
    is_androguard_available,
    load_dex_entries_from_apk,
)
from apk_forensics.dex_xrefs import build_xref_candidates, stream_collect_callers
from apk_forensics.models import Finding
from apk_forensics.utils import timed_ms


DEX_CONTEXT_LIMITATIONS = [
    "Static DEX context does not prove runtime execution.",
    "Static XREFs do not prove that a connection path is taken.",
    "Profile matches are correlations, not protocol proof.",
    "Instruction offsets may be unavailable depending on the parser API.",
    "XREF discovery uses bounded instruction scans, not a full call graph.",
    "Base APK and split APKs are analyzed as separate artifacts.",
]


def run_dex_context_analysis(
    apk_path: Path,
    findings: list[Finding],
    *,
    artifact_sha256: str,
    config: AnalysisConfig,
) -> dict[str, Any]:
    configuration = {
        "instruction_window": config.instruction_window,
        "xref_depth": config.xref_depth,
        "max_results": config.max_dex_context_results,
        "max_callers": config.max_callers,
        "max_callees": config.max_callees,
        "finding_id": config.dex_finding_id,
        "query": config.dex_query,
        "category": config.dex_category,
        "kind": config.dex_kind,
        "include_unmatched": config.include_unmatched,
    }

    if not config.dex_context:
        return empty_dex_context_section(
            enabled=False,
            status="skipped",
            configuration=configuration,
            limitations=["DEX context analysis not requested."],
        )

    if not is_androguard_available():
        msg = (
            "DEX context analysis requires the optional dependency 'androguard'.\n"
            "Install with:\n"
            "  pip install 'apk-forensics[android]'"
        )
        return empty_dex_context_section(
            enabled=True,
            status="skipped",
            warnings=[msg],
            limitations=DEX_CONTEXT_LIMITATIONS
            + ["androguard missing; semantic DEX context unavailable."],
            configuration=configuration,
            parser={"name": "androguard", "version": None},
        )

    warnings: list[str] = []
    with timed_ms() as timing:
        try:
            dex_entries = load_dex_entries_from_apk(
                apk_path,
                max_entry_bytes=config.max_entry_read_bytes,
            )
            queries = select_queries_from_findings(
                findings,
                finding_id=config.dex_finding_id,
                query=config.dex_query,
                category=config.dex_category,
                kind=config.dex_kind,
                include_unmatched=config.include_unmatched,
                max_queries=max(50, config.max_dex_context_results * 2),
            )
            units, matches, load_warnings, version, methods_indexed = stream_find_dex_matches(
                dex_entries,
                queries,
                max_results=config.max_dex_context_results,
            )
            warnings.extend(load_warnings)
            warnings.append(
                "External method inventory uses class-prefix heuristics; "
                "full androguard Analysis XREF graph is not built in v0.2."
            )

            # Session contains only matched methods (with instructions).
            matched_methods = []
            seen = set()
            for match in matches:
                key = match.method.full_name + "|" + match.method.dex_entry
                if key not in seen:
                    seen.add(key)
                    matched_methods.append(match.method)
            session = DexSession(
                units=units,
                methods=matched_methods,
                parser_name="androguard",
                parser_version=version,
                warnings=list(warnings),
                methods_indexed=methods_indexed,
            )

            contexts = build_contexts(
                matches,
                instruction_window=config.instruction_window,
                artifact_sha256=artifact_sha256,
            )
            xref_candidates = build_xref_candidates(
                session,
                contexts,
                xref_depth=config.xref_depth,
                max_callers=config.max_callers,
                max_callees=config.max_callees,
                dex_entries=dex_entries if config.xref_depth >= 1 else None,
            )
            chains = build_candidate_chains(contexts, xref_candidates=xref_candidates)

            context_by_finding: dict[str, list[str]] = {}
            for ctx in contexts:
                for fid in ctx.get("finding_ids") or []:
                    context_by_finding.setdefault(fid, []).append(ctx["context_id"])
                fid = ctx.get("finding_id")
                if fid:
                    context_by_finding.setdefault(fid, [])
                    if ctx["context_id"] not in context_by_finding[fid]:
                        context_by_finding[fid].append(ctx["context_id"])

            for finding in findings:
                ids = context_by_finding.get(finding.id, [])
                finding.context_ids = ids
                if ids:
                    finding.context_status = "matched"
                elif finding.source.file_type == "dex" or (finding.source.entry or "").endswith(".dex"):
                    finding.context_status = "not_matched"
                else:
                    finding.context_status = "not_applicable"

            status = "complete"
            if warnings or any(u.parse_status != "complete" for u in session.units):
                status = "partial"
            if not session.units:
                status = "failed"
                warnings.append("No DEX units could be loaded for context analysis.")

        except Exception as exc:  # noqa: BLE001
            return empty_dex_context_section(
                enabled=True,
                status="failed",
                warnings=[str(exc)],
                limitations=DEX_CONTEXT_LIMITATIONS,
                configuration=configuration,
                parser={"name": "androguard", "version": get_androguard_version()},
            )

    return {
        "enabled": True,
        "status": status,
        "parser": {
            "name": "androguard",
            "version": version,
        },
        "configuration": configuration,
        "units": [u.to_dict() for u in units],
        "contexts": contexts,
        "xref_candidates": xref_candidates,
        "candidate_chains": chains,
        "warnings": warnings,
        "limitations": list(DEX_CONTEXT_LIMITATIONS),
        "duration_ms": timing["duration_ms"],
        "counts": {
            "contexts": len(contexts),
            "xref_candidates": len(xref_candidates),
            "candidate_chains": len(chains),
            "methods_indexed": methods_indexed,
        },
    }
