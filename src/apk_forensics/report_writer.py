"""JSON and Markdown report writers."""

from __future__ import annotations

import json
from pathlib import Path

from apk_forensics.models import Finding, Report
from apk_forensics.utils import ensure_parent


CLASSIFICATION_MARKERS = {
    "FACT": "`FACT`",
    "CORRELATION": "`CORRELATION`",
    "INFERENCE": "`INFERENCE`",
    "UNKNOWN": "`UNKNOWN`",
    "REJECTED": "`REJECTED`",
}


def _md_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def write_json_report(report: Report, path: Path) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _findings_by_top_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    buckets = {
        "Android": [],
        "Bluetooth": [],
        "Network": [],
        "Native": [],
        "Protocol": [],
        "USB": [],
        "Other": [],
    }
    for finding in findings:
        if finding.classification == "REJECTED":
            continue
        cat = (finding.category or "").lower()
        sub = (finding.subcategory or "").lower()
        if cat == "android" or sub.startswith("android"):
            buckets["Android"].append(finding)
        elif cat == "bluetooth" or sub.startswith("bluetooth"):
            buckets["Bluetooth"].append(finding)
        elif cat == "network" or sub.startswith("network"):
            buckets["Network"].append(finding)
        elif cat == "native" or sub.startswith("native") or cat == "jni":
            buckets["Native"].append(finding)
        elif cat == "protocol" or sub.startswith("protocol") or cat == "vehicle":
            buckets["Protocol"].append(finding)
        elif cat == "usb" or sub.startswith("usb"):
            buckets["USB"].append(finding)
        else:
            buckets["Other"].append(finding)
    return buckets


def render_markdown(report: Report) -> str:
    d = report.to_dict()
    findings = [f for f in report.findings if f.classification != "REJECTED"]
    lines: list[str] = []
    lines.append("# APK Forensics Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Input: `{_md_escape(d['input']['path'])}`")
    lines.append(f"- SHA-256: `{_md_escape(d['input']['sha256'])}`")
    lines.append(f"- Package: `{_md_escape(d['artifact'].get('package_name'))}`")
    lines.append(f"- Version: `{_md_escape(d['artifact'].get('version_name'))}`")
    lines.append(f"- Analysis status: `{_md_escape(d['analysis']['status'])}`")
    lines.append(f"- Finding count: {len(findings)}")
    lines.append(f"- Warning count: {len(d['analysis'].get('warnings') or [])}")
    if d.get("search_plan") or d.get("analysis", {}).get("plan_sha256"):
        sp = d.get("search_plan") or {}
        plan_name = (sp.get("plan") or {}).get("name")
        plan_hash = d.get("analysis", {}).get("plan_sha256") or sp.get("plan_sha256")
        lines.append(f"- SearchPlan: `{_md_escape(plan_name)}`")
        lines.append(f"- plan_sha256: `{_md_escape(plan_hash)}`")
    if d.get("analysis_job"):
        lines.append(f"- Job ID: `{_md_escape((d.get('analysis_job') or {}).get('job_id'))}`")
        lines.append(f"- Job status: `{_md_escape((d.get('analysis_job') or {}).get('status'))}`")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for item in d.get("limitations") or ["No limitations recorded."]:
        lines.append(f"- {_md_escape(item)}")
    lines.append("")
    lines.append("## Artifact")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| File | {_md_escape(d['input']['file_name'])} |")
    lines.append(f"| Size | {d['input']['size_bytes']} |")
    lines.append(f"| SHA-256 | `{_md_escape(d['input']['sha256'])}` |")
    lines.append("")

    job = d.get("analysis_job") or {}
    resource = d.get("resource") or {}
    if job or resource:
        lines.append("## Analysis Job")
        lines.append("")
        lines.append(f"- Job ID: `{_md_escape(job.get('job_id'))}`")
        lines.append(f"- Status: `{_md_escape(job.get('status'))}`")
        lines.append(f"- Plan SHA-256: `{_md_escape(job.get('plan_sha256'))}`")
        lines.append(f"- Input SHA-256: `{_md_escape(job.get('input_artifact_sha256'))}`")
        lines.append(f"- Created: `{_md_escape(job.get('created_at'))}`")
        lines.append(f"- Started: `{_md_escape(job.get('started_at'))}`")
        lines.append(f"- Finished: `{_md_escape(job.get('finished_at'))}`")
        lines.append("")
        lines.append("## Resource Policy")
        lines.append("")
        pol = (resource.get("policy") or {}) if resource else {}
        lines.append(f"- Policy: `{_md_escape(pol.get('name'))}`")
        lines.append(f"- Memory limit: `{_md_escape(pol.get('max_memory_mb'))}` MiB")
        lines.append(f"- Runtime limit: `{_md_escape(pol.get('max_runtime_seconds'))}` s")
        lines.append(f"- Finding limit: `{_md_escape(pol.get('max_findings'))}`")
        lines.append("")
        lines.append("## Resource Preflight")
        lines.append("")
        est = resource.get("estimate") or {}
        lines.append(f"- Decision: `{_md_escape(resource.get('decision'))}`")
        lines.append(f"- Estimated memory: `{_md_escape(est.get('memory_mb'))}` MiB")
        lines.append(f"- Estimated runtime: `{_md_escape(est.get('runtime_seconds'))}` s")
        lines.append(f"- Risk: `{_md_escape(est.get('risk'))}`")
        lines.append("")
        breakdown = est.get("breakdown") or {}
        comps = [c for c in (breakdown.get("components") or []) if c.get("name") != "TOTAL"]
        if comps:
            lines.append("### Estimate Breakdown")
            lines.append("")
            lines.append("| Component | Memory (MiB) | Runtime (s) |")
            lines.append("|---|---:|---:|")
            for c in comps:
                lines.append(
                    f"| {_md_escape(c.get('name'))} | {c.get('memory_mb')} | {c.get('runtime_seconds')} |"
                )
            total = next((c for c in (breakdown.get("components") or []) if c.get("name") == "TOTAL"), None)
            if total:
                lines.append(
                    f"| **TOTAL** | **{total.get('memory_mb')}** | **{total.get('runtime_seconds')}** |"
                )
            lines.append("")
        lines.append("Reasons:")
        lines.append("")
        for reason in resource.get("decision_reasons") or est.get("reasons") or []:
            lines.append(f"- {_md_escape(reason)}")
        lines.append("")
        lines.append("## Resource Actual")
        lines.append("")
        act = resource.get("actual") or {}
        lines.append(f"- Runtime: `{_md_escape(act.get('runtime_seconds'))}` s")
        lines.append(f"- Peak memory: `{_md_escape(act.get('peak_memory_mb'))}` MiB")
        lines.append(f"- CPU time: `{_md_escape(act.get('cpu_time_seconds'))}` s")
        lines.append(f"- Findings: `{_md_escape(act.get('findings'))}`")
        lines.append(f"- DEX contexts: `{_md_escape(act.get('dex_contexts'))}`")
        lines.append(f"- XREFs: `{_md_escape(act.get('xrefs'))}`")
        lines.append(f"- Raw nodes/edges: `{_md_escape(act.get('raw_node_count'))}` / `{_md_escape(act.get('raw_edge_count'))}`")
        lines.append(
            f"- Canonical objects/nodes: `{_md_escape(act.get('canonical_object_count'))}` / "
            f"`{_md_escape(act.get('canonical_node_count'))}`"
        )
        lines.append(f"- Evidence paths: `{_md_escape(act.get('evidence_path_count'))}`")
        lines.append(f"- Communication paths: `{_md_escape(act.get('communication_path_count'))}`")
        lines.append(f"- Boundaries / truncations: `{_md_escape(act.get('boundary_count'))}` / `{_md_escape(act.get('truncation_count'))}`")
        lines.append(f"- Termination: `{_md_escape(resource.get('termination_reason'))}`")
        if est.get("memory_mb") is not None and act.get("peak_memory_mb") is not None:
            from apk_forensics.resource_calibration import compare_estimate_actual

            cmp_ = compare_estimate_actual(est, act)
            lines.append("")
            lines.append("### Estimate vs Actual")
            lines.append("")
            lines.append("| Metric | Estimate | Actual | Actual/Estimate |")
            lines.append("|---|---:|---:|---:|")
            for row in cmp_.get("table") or []:
                lines.append(
                    f"| {row.get('metric')} | {row.get('estimate')} | {row.get('actual')} | "
                    f"{row.get('actual_over_estimate')} |"
                )
            lines.append("")
            lines.append(
                "_Ratios are observational and do not rewrite the Guard decision for this run._"
            )
        lines.append("")

    manifest = d.get("manifest") or {}
    lines.append("## Manifest")
    lines.append("")
    lines.append("### Package Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Package | {_md_escape(manifest.get('package_name') or d['artifact'].get('package_name'))} |")
    lines.append(f"| Version name | {_md_escape(manifest.get('version_name') or d['artifact'].get('version_name'))} |")
    lines.append(f"| Version code | {_md_escape(manifest.get('version_code') or d['artifact'].get('version_code'))} |")
    lines.append(f"| Min SDK | {_md_escape(manifest.get('min_sdk') or d['artifact'].get('min_sdk'))} |")
    lines.append(f"| Target SDK | {_md_escape(manifest.get('target_sdk') or d['artifact'].get('target_sdk'))} |")
    lines.append(f"| Parse status | {_md_escape(manifest.get('parse_status'))} |")
    lines.append("")
    lines.append("### Permissions")
    lines.append("")
    perms = manifest.get("permissions") or []
    if perms:
        for perm in perms:
            lines.append(f"- `{_md_escape(perm)}`")
    else:
        lines.append("- None available / not parsed")
    lines.append("")
    lines.append("### Components")
    lines.append("")
    for key in ("activities", "services", "receivers", "providers"):
        items = manifest.get(key) or []
        lines.append(f"- **{key}**: {len(items)}")
        for item in items[:20]:
            lines.append(f"  - `{_md_escape(item)}`")
        if len(items) > 20:
            lines.append(f"  - ... ({len(items) - 20} more)")
    lines.append("")

    lines.append("## ZIP Inventory")
    lines.append("")
    lines.append("| Entry | Size | Compressed | SHA-256 | Type |")
    lines.append("|---|---:|---:|---|---|")
    for entry in (d.get("zip_inventory") or {}).get("entries") or []:
        sha = entry.get("sha256") or ""
        sha_short = sha[:16] + "…" if len(sha) > 16 else sha
        lines.append(
            f"| `{_md_escape(entry.get('name'))}` | {entry.get('size_bytes')} | "
            f"{entry.get('compressed_size_bytes')} | `{_md_escape(sha_short)}` | "
            f"{_md_escape(entry.get('entry_type'))} |"
        )
    lines.append("")

    lines.append("## DEX Inventory")
    lines.append("")
    lines.append("| Entry | Size | SHA-256 | Parse status | Classes | Methods |")
    lines.append("|---|---:|---|---|---:|---:|")
    for entry in d.get("dex_inventory") or []:
        sha = entry.get("sha256") or ""
        sha_short = sha[:16] + "…" if len(sha) > 16 else sha
        lines.append(
            f"| `{_md_escape(entry.get('entry'))}` | {entry.get('size_bytes')} | "
            f"`{_md_escape(sha_short)}` | {_md_escape(entry.get('parse_status'))} | "
            f"{_md_escape(entry.get('classes'))} | {_md_escape(entry.get('methods'))} |"
        )
    lines.append("")

    lines.append("## Native Libraries")
    lines.append("")
    lines.append("| Path | ABI | Size | SHA-256 | ELF status |")
    lines.append("|---|---|---:|---|---|")
    for entry in d.get("native_inventory") or []:
        sha = entry.get("sha256") or ""
        sha_short = sha[:16] + "…" if len(sha) > 16 else sha
        elf_status = (entry.get("elf") or {}).get("parse_status")
        lines.append(
            f"| `{_md_escape(entry.get('path'))}` | {_md_escape(entry.get('abi'))} | "
            f"{entry.get('size_bytes')} | `{_md_escape(sha_short)}` | {_md_escape(elf_status)} |"
        )
    lines.append("")

    lines.append("## Findings by Category")
    lines.append("")
    buckets = _findings_by_top_category(findings)
    for title, items in buckets.items():
        lines.append(f"### {title}")
        lines.append("")
        if not items:
            lines.append("_None_")
            lines.append("")
            continue
        for finding in items:
            marker = CLASSIFICATION_MARKERS.get(finding.classification, finding.classification)
            lines.append(
                f"- `{finding.display_id}` {marker} **{_md_escape(finding.kind)}** "
                f"`{_md_escape(finding.value)}` "
                f"(conf={_md_escape(finding.confidence)}; "
                f"src=`{_md_escape(finding.source.entry)}`:"
                f"{finding.source.offset})"
            )
            if finding.notes:
                lines.append(f"  - notes: {_md_escape('; '.join(finding.notes))}")
        lines.append("")

    lines.append("## Profile Matches")
    lines.append("")
    lines.append("| Finding | Profile | Category | Profile confidence |")
    lines.append("|---|---|---|---|")
    any_match = False
    for finding in findings:
        for pm in finding.profile_matches:
            any_match = True
            lines.append(
                f"| `{finding.display_id}` | {_md_escape(pm.profile)} | "
                f"{_md_escape(pm.category)} | {_md_escape(pm.profile_confidence)} |"
            )
    if not any_match:
        lines.append("| — | — | — | — |")
    lines.append("")

    lines.append("## Scanner Status")
    lines.append("")
    lines.append("| Scanner | Status | Warnings |")
    lines.append("|---|---|---|")
    for scanner in d["analysis"].get("scanners") or []:
        warn_n = len(scanner.get("warnings") or [])
        lines.append(
            f"| `{_md_escape(scanner.get('name'))}` | {_md_escape(scanner.get('status'))} | {warn_n} |"
        )
    lines.append("")

    dex = d.get("dex_context")
    if dex is not None:
        lines.extend(_render_dex_context_markdown(dex))

    bt = d.get("bluetooth_path")
    if bt is not None:
        lines.extend(_render_bluetooth_path_markdown(bt))

    comm = d.get("communication_evidence")
    if comm is not None:
        lines.extend(_render_communication_evidence_markdown(comm))

    lines.append("## Reproducibility")
    lines.append("")
    lines.append(f"- Tool version: `{_md_escape(d['tool']['version'])}`")
    lines.append(f"- Schema version: `{_md_escape(d['schema_version'])}`")
    lines.append(f"- Python version: `{_md_escape(d['tool']['python_version'])}`")
    lines.append(f"- Platform: `{_md_escape(d['tool']['platform'])}`")
    profiles = [
        m.profile
        for f in findings
        for m in f.profile_matches
    ]
    unique_profiles = sorted({p for p in profiles if p})
    lines.append(f"- Profiles: {_md_escape(', '.join(unique_profiles) if unique_profiles else 'none')}")
    lines.append("")
    lines.append(
        "> A string or API hit proves presence of a string/reference only. "
        "It does not prove runtime use, connection path, target device, or protocol."
    )
    lines.append("")
    return "\n".join(lines)


def _render_dex_context_markdown(dex: dict) -> list[str]:
    lines: list[str] = []
    cfg = dex.get("configuration") or {}
    parser = dex.get("parser") or {}
    lines.append("## DEX Context Analysis")
    lines.append("")
    lines.append("### Configuration")
    lines.append("")
    lines.append("| Parameter | Value |")
    lines.append("|---|---|")
    lines.append(f"| Enabled | {'yes' if dex.get('enabled') else 'no'} |")
    lines.append(f"| Status | {_md_escape(dex.get('status'))} |")
    lines.append(
        f"| Parser | {_md_escape(parser.get('name'))} "
        f"{_md_escape(parser.get('version'))} |"
    )
    lines.append(f"| Instruction window | {_md_escape(cfg.get('instruction_window'))} |")
    lines.append(f"| XREF depth | {_md_escape(cfg.get('xref_depth'))} |")
    lines.append(f"| Max results | {_md_escape(cfg.get('max_results'))} |")
    lines.append("")
    lines.append(
        "> Static DEX context does not prove runtime execution.  \n"
        "> Static XREFs do not prove that a connection path is taken.  \n"
        "> Profile matches are correlations, not protocol proof."
    )
    lines.append("")

    lines.append("### High-Priority DEX Contexts")
    lines.append("")
    contexts = list(dex.get("contexts") or [])
    high = [c for c in contexts if c.get("priority") == "high"]
    show = high or contexts[:20]
    if not show:
        lines.append("_None_")
        lines.append("")
    for ctx in show[:30]:
        lines.append(f"#### Context {_md_escape(ctx.get('display_id') or ctx.get('context_id'))}")
        lines.append("")
        lines.append(f"- Finding: `{_md_escape(ctx.get('finding_id'))}`")
        lines.append(f"- DEX: `{_md_escape(ctx.get('dex_entry'))}`")
        lines.append(f"- Class: `{_md_escape(ctx.get('class_name_normalized') or ctx.get('class_name'))}`")
        lines.append(f"- Method: `{_md_escape(ctx.get('method_name'))}`")
        lines.append(f"- Descriptor: `{_md_escape(ctx.get('method_descriptor'))}`")
        match = ctx.get("match") or {}
        lines.append(f"- Match type: `{_md_escape(match.get('match_type'))}`")
        lines.append(f"- Match value: `{_md_escape(match.get('value'))}`")
        lines.append(f"- Classification: `{_md_escape(ctx.get('classification'))}`")
        lines.append(f"- Confidence: `{_md_escape(ctx.get('confidence'))}`")
        lines.append(f"- Evidence level: `{_md_escape(ctx.get('evidence_level'))}`")
        lines.append(f"- Priority: `{_md_escape(ctx.get('priority'))}` ({ctx.get('priority_score')})")
        for reason in ctx.get("priority_reasons") or []:
            lines.append(f"  - reason: {_md_escape(reason)}")
        for lim in ctx.get("limitations") or []:
            lines.append(f"- Limitation: {_md_escape(lim)}")
        lines.append("")
        lines.append("##### Instruction Context")
        lines.append("")
        lines.append("```text")
        window = ctx.get("instruction_window") or {}
        for ins in window.get("before") or []:
            lines.append(f"  {ins.get('index')}: {ins.get('text')}")
        for ins in window.get("match") or []:
            lines.append(f">>{ins.get('index')}: {ins.get('text')}")
        for ins in window.get("after") or []:
            lines.append(f"  {ins.get('index')}: {ins.get('text')}")
        lines.append("```")
        lines.append("")
        symbols = ctx.get("referenced_symbols") or {}
        lines.append("##### Referenced Methods")
        lines.append("")
        methods = symbols.get("methods") or []
        if methods:
            for item in methods[:30]:
                lines.append(f"- `{_md_escape(item)}`")
        else:
            lines.append("- _None_")
        lines.append("")
        lines.append("##### Referenced Classes")
        lines.append("")
        classes = symbols.get("classes") or []
        if classes:
            for item in classes[:30]:
                lines.append(f"- `{_md_escape(item)}`")
        else:
            lines.append("- _None_")
        lines.append("")
        lines.append("##### Referenced Strings")
        lines.append("")
        strings = symbols.get("strings") or []
        if strings:
            for item in strings[:30]:
                lines.append(f"- `{_md_escape(item)}`")
        else:
            lines.append("- _None_")
        lines.append("")

    lines.append("### XREF Candidates")
    lines.append("")
    lines.append("| Source | Relationship | Target | Resolution | Confidence |")
    lines.append("|---|---|---|---|---|")
    xrefs = dex.get("xref_candidates") or []
    if not xrefs:
        lines.append("| — | — | — | — | — |")
    for item in xrefs[:50]:
        lines.append(
            f"| `{_md_escape(item.get('source_method'))}` | {_md_escape(item.get('relationship'))} | "
            f"`{_md_escape(item.get('target_method'))}` | {_md_escape(item.get('resolution'))} | "
            f"{_md_escape(item.get('confidence'))} |"
        )
    lines.append("")

    lines.append("### Candidate Chains")
    lines.append("")
    chains = dex.get("candidate_chains") or []
    if not chains:
        lines.append("_None_")
        lines.append("")
    for chain in chains[:20]:
        lines.append(f"#### Chain {_md_escape(chain.get('display_id') or chain.get('chain_id'))}")
        lines.append("")
        lines.append("```text")
        lines.append(_md_escape(chain.get("summary")))
        lines.append("```")
        lines.append("")
        lines.append(f"- Classification: `{_md_escape(chain.get('classification'))}`")
        lines.append(f"- Confidence: `{_md_escape(chain.get('confidence'))}`")
        lines.append(f"- Runtime execution proven: {'yes' if chain.get('runtime_execution_proven') else 'no'}")
        lines.append(
            f"- Wire correlation available: {'yes' if chain.get('wire_correlation_available') else 'no'}"
        )
        method = chain.get("method") or {}
        lines.append(
            f"- Method: `{_md_escape(method.get('class_name_normalized') or method.get('class_name'))}."
            f"{_md_escape(method.get('method_name'))}`"
        )
        lines.append("")
    return lines


def _render_bluetooth_path_markdown(bt: dict) -> list[str]:
    lines: list[str] = []
    counts = bt.get("counts") or {}
    lines.append("## Bluetooth RFCOMM Path Analysis")
    lines.append("")
    lines.append("### Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Enabled | {'yes' if bt.get('enabled') else 'no'} |")
    lines.append(f"| Status | {_md_escape(bt.get('status'))} |")
    lines.append(f"| RFCOMM targets | {counts.get('targets', len(bt.get('targets') or []))} |")
    lines.append(
        f"| UUID resolutions | {counts.get('uuid_resolutions', len(bt.get('uuid_resolutions') or []))} |"
    )
    lines.append(
        f"| Device sources | {counts.get('device_sources', len(bt.get('device_sources') or []))} |"
    )
    lines.append(f"| Socket paths | {counts.get('socket_paths', len(bt.get('socket_paths') or []))} |")
    lines.append(f"| I/O paths | {counts.get('io_paths', len(bt.get('io_paths') or []))} |")
    lines.append(f"| Candidate paths | {counts.get('paths', len(bt.get('paths') or []))} |")
    lines.append(f"| RFCOMM callers | {counts.get('caller_paths', len(bt.get('caller_paths') or []))} |")
    lines.append(
        f"| Dataflow paths | {counts.get('dataflow_paths', len(bt.get('dataflow_paths') or []))} |"
    )
    lines.append(f"| Dataflow nodes | {counts.get('dataflow_nodes', 0)} |")
    lines.append(f"| Socket transfers | {counts.get('socket_transfers', 0)} |")
    lines.append(f"| Stream transfers | {counts.get('stream_transfers', 0)} |")
    lines.append(f"| InputStream consumers | {counts.get('input_consumers', 0)} |")
    lines.append(f"| OutputStream producers | {counts.get('output_producers', 0)} |")
    lines.append(f"| Raw dataflow nodes | {counts.get('dataflow_nodes', 0)} |")
    lines.append(f"| Raw dataflow edges | {counts.get('dataflow_edges', 0)} |")
    lines.append(f"| Canonical objects | {counts.get('canonical_objects', 0)} |")
    lines.append(f"| Canonical nodes | {counts.get('canonical_nodes', 0)} |")
    lines.append(f"| Evidence paths | {counts.get('evidence_paths', 0)} |")
    lines.append("")
    lines.append(
        "> A statically reconstructed Bluetooth path is not proof of runtime execution.  \n"
        "> A statically resolved SPP UUID is not proof that an RFCOMM channel was opened at runtime.  \n"
        "> The analyzer does not infer RFCOMM channel numbers such as SCN6.  \n"
        "> Profile matches are correlations and do not constitute protocol proof.  \n"
        "> Raw node/edge counts are not communication-operation counts."
    )
    lines.append("")
    lines.extend(_render_evidence_graph_markdown(bt))

    lines.append("### High-Priority Paths")
    lines.append("")
    paths = list(bt.get("paths") or [])
    if not paths:
        lines.append("_None_")
        lines.append("")
    for path in paths[:30]:
        uuid_res = path.get("uuid_resolution") or {}
        device = path.get("device_source") or {}
        socket = path.get("socket_path") or {}
        lines.append(f"#### {_md_escape(path.get('display_id') or path.get('path_id'))}")
        lines.append("")
        lines.append(
            f"- Class: `{_md_escape(path.get('class_name_normalized') or path.get('class_name'))}`"
        )
        lines.append(f"- Method: `{_md_escape(path.get('method_name'))}`")
        lines.append(f"- Descriptor: `{_md_escape(path.get('method_descriptor'))}`")
        lines.append(f"- RFCOMM API: `{_md_escape(path.get('rfcomm_api'))}`")
        lines.append(f"- UUID: `{_md_escape(uuid_res.get('uuid'))}`")
        lines.append(
            f"- UUID source: `{_md_escape(uuid_res.get('source_type'))}` "
            f"`{_md_escape(uuid_res.get('source'))}`"
        )
        lines.append(
            f"- BluetoothDevice source: `{_md_escape(device.get('source_type'))}` "
            f"`{_md_escape(device.get('source'))}`"
        )
        lines.append(f"- Connect: `{_md_escape(socket.get('has_connect'))}`")
        lines.append(f"- InputStream: `{_md_escape(socket.get('has_input_stream'))}`")
        lines.append(f"- OutputStream: `{_md_escape(socket.get('has_output_stream'))}`")
        lines.append(f"- Classification: `{_md_escape(path.get('classification'))}`")
        lines.append(f"- Confidence: `{_md_escape(path.get('confidence'))}`")
        lines.append(
            f"- Runtime execution proven: {'yes' if path.get('runtime_execution_proven') else 'no'}"
        )
        lines.append("")
        lines.append("### Static Path")
        lines.append("")
        lines.append("```text")
        lines.append(_md_escape(path.get("summary")))
        lines.append("```")
        lines.append("")
        lines.append("### Evidence")
        lines.append("")
        for edge in path.get("edges") or []:
            lines.append(
                f"- `{_md_escape(edge.get('from'))}` "
                f"--{_md_escape(edge.get('relationship'))}--> "
                f"`{_md_escape(edge.get('to'))}` "
                f"[{_md_escape(edge.get('classification'))}]"
            )
        for corr in path.get("profile_correlations") or []:
            lines.append(
                f"- profile CORRELATION `{_md_escape(corr.get('profile_match'))}` "
                f"scope=`{_md_escape(corr.get('scope'))}`"
            )
        lines.append("")
        lines.append("### Limitations")
        lines.append("")
        for lim in path.get("limitations") or path.get("notes") or []:
            lines.append(f"- {_md_escape(lim)}")
        lines.append("")

    lines.extend(_render_bluetooth_dataflow_markdown(bt))
    return lines


def _render_communication_evidence_markdown(comm: dict) -> list[str]:
    lines: list[str] = []
    if not comm.get("enabled"):
        return lines
    summary = comm.get("summary") or {}
    counts = comm.get("counts") or {}
    lines.append("## Communication Evidence (v1.0)")
    lines.append("")
    lines.append(
        "> Transport Evidence Graph and Communication Evidence Graph are separate layers.  \n"
        "> Method names never establish protocol identity (BCL/Etch/RHMI/SCN6 remain UNKNOWN)."
    )
    lines.append("")
    lines.append("### Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Read sites | {counts.get('read_sites', summary.get('read_sites', 0))} |")
    lines.append(f"| Write sites | {counts.get('write_sites', summary.get('write_sites', 0))} |")
    lines.append(f"| Buffer operations | {counts.get('buffer_operations', 0)} |")
    lines.append(f"| Decoder candidates | {counts.get('decoder_candidates', summary.get('decoder_candidates', 0))} |")
    lines.append(
        f"| Serializer candidates | {counts.get('serializer_candidates', summary.get('serializer_candidates', 0))} |"
    )
    lines.append(
        f"| Message constructions | {counts.get('message_constructions', summary.get('message_constructions', 0))} |"
    )
    lines.append(f"| Communication paths | {summary.get('communication_paths', 0)} |")
    lines.append(f"| Inbound | {summary.get('inbound_paths', 0)} |")
    lines.append(f"| Outbound | {summary.get('outbound_paths', 0)} |")
    lines.append(f"| Boundaries | {summary.get('boundaries', 0)} |")
    cov = summary.get("coverage") or comm.get("coverage") or {}
    if cov:
        lines.append(f"| Coverage complete | {cov.get('complete', 0)} |")
        lines.append(f"| Coverage truncated | {cov.get('truncated', 0)} |")
        lines.append(f"| Coverage boundary | {cov.get('boundary', 0)} |")
        lines.append(f"| Coverage unresolved | {cov.get('unresolved', 0)} |")
        lines.append(f"| Coverage no_continuation | {cov.get('no_continuation', 0)} |")
    lines.append("")
    ret = comm.get("method_retention") or {}
    if ret:
        lines.append("### Method Retention")
        lines.append("")
        lines.append(f"- retained_methods: `{_md_escape(ret.get('retained_methods'))}`")
        lines.append(f"- candidate_methods: `{_md_escape(ret.get('candidate_methods'))}`")
        lines.append(f"- discarded_methods: `{_md_escape(ret.get('discarded_methods'))}`")
        lines.append(f"- discard_reason: `{_md_escape(ret.get('discard_reason'))}`")
        lines.append(f"- capped: `{_md_escape(ret.get('capped'))}`")
        lines.append("")
        lines.append(
            "_METHOD_RETENTION_CAP is an analyzer limit, not an APK semantic boundary._"
        )
        lines.append("")
    lines.append(
        f"**Strongest:** `{_md_escape(summary.get('strongest_path_id'))}` — "
        f"`{_md_escape(summary.get('strongest_classification'))}` · "
        f"protocol=`{_md_escape(summary.get('protocol_semantics'))}` · "
        f"runtime=`{_md_escape(summary.get('runtime_execution'))}`"
    )
    lines.append("")
    prov = comm.get("provenance") or {}
    if prov:
        lines.append("### Provenance")
        lines.append("")
        for k in (
            "mode",
            "source_dataset",
            "source_engine_version",
            "source_plan_sha256",
            "source_artifact_sha256",
            "postprocessing_version",
        ):
            if prov.get(k) is not None:
                lines.append(f"- {k}: `{_md_escape(prov.get(k))}`")
        lines.append("")
    lines.append("### Communication Paths")
    lines.append("")
    for path in list(comm.get("paths") or [])[:20]:
        lines.append(f"#### {_md_escape(path.get('display_id') or path.get('path_id'))}")
        lines.append("")
        lines.append(f"- Direction: `{_md_escape(path.get('direction'))}`")
        lines.append(
            f"- End-to-end: `{_md_escape(path.get('classification'))}` / "
            f"`{_md_escape(path.get('confidence'))}`"
        )
        lines.append(f"- Protocol semantics: `{_md_escape(path.get('protocol_semantics'))}`")
        lines.append("")
        lines.append("```text")
        for step in path.get("steps") or []:
            lines.append(
                f"{step.get('label')}  [{step.get('classification')}/{step.get('confidence')}]"
            )
        lines.append("```")
        lines.append("")
        if path.get("boundaries"):
            b = path["boundaries"][0]
            lines.append(
                f"- Boundary: `{_md_escape(b.get('reason'))}` "
                f"last=`{_md_escape(b.get('last_proven'))}` "
                f"[{_md_escape(b.get('classification'))}]"
            )
            lines.append("")
    lines.append("### Boundaries")
    lines.append("")
    boundaries = list(comm.get("boundaries") or [])
    if not boundaries:
        lines.append("_None recorded._")
        lines.append("")
    else:
        for b in boundaries[:40]:
            lines.append(
                f"- `{_md_escape(b.get('reason'))}` "
                f"method=`{_md_escape(b.get('method'))}` "
                f"detail=`{_md_escape(b.get('detail') or b.get('last_proven'))}`"
            )
        lines.append("")
    return lines


def _render_evidence_graph_markdown(bt: dict) -> list[str]:
    lines: list[str] = []
    eg = bt.get("evidence_graph") or {}
    if not eg.get("enabled"):
        return lines
    summary = eg.get("summary") or {}
    raw = eg.get("raw") or {}
    canon = eg.get("canonical") or {}
    lines.append("## Evidence Graph (v0.9)")
    lines.append("")
    lines.append("### Executive Summary")
    lines.append("")
    lines.append("| Layer | Metric | Value |")
    lines.append("|---|---|---:|")
    lines.append(f"| Raw | nodes | {raw.get('nodes', 0)} |")
    lines.append(f"| Raw | edges | {raw.get('edges', 0)} |")
    lines.append(f"| Raw | transfers | {raw.get('transfers', 0)} |")
    lines.append(f"| Canonical | objects | {canon.get('objects', 0)} |")
    lines.append(f"| Canonical | nodes | {canon.get('nodes', 0)} |")
    lines.append(f"| Canonical | edges | {canon.get('edges', 0)} |")
    lines.append(f"| Evidence | paths | {summary.get('evidence_paths', 0)} |")
    lines.append(f"| Evidence | input paths | {summary.get('input_paths', 0)} |")
    lines.append(f"| Evidence | output paths | {summary.get('output_paths', 0)} |")
    lines.append(
        f"| Evidence | combined communication paths | {summary.get('combined_communication_paths', 0)} |"
    )
    lines.append("")
    lines.append(
        f"**Strongest path:** `{_md_escape(summary.get('strongest_path_id'))}` "
        f"({_md_escape(summary.get('strongest_path_kind'))}) — "
        f"`{_md_escape(summary.get('strongest_classification'))}` / "
        f"`{_md_escape(summary.get('strongest_confidence'))}`"
    )
    lines.append("")
    lines.append(f"- Runtime execution: `{_md_escape(summary.get('runtime_execution'))}`")
    lines.append(f"- Wire correlation: `{_md_escape(summary.get('wire_correlation'))}`")
    lines.append(f"- Protocol semantics: `{_md_escape(summary.get('protocol_semantics'))}`")
    lines.append("")
    lines.append("### Evidence Paths")
    lines.append("")
    for path in list(eg.get("evidence_paths") or [])[:20]:
        lines.append(f"#### {_md_escape(path.get('display_id') or path.get('path_id'))}")
        lines.append("")
        lines.append(f"- Kind: `{_md_escape(path.get('kind'))}`")
        lines.append(
            f"- End-to-end: `{_md_escape(path.get('classification'))}` / "
            f"`{_md_escape(path.get('confidence'))}`"
        )
        lines.append(f"- Protocol semantics: `{_md_escape(path.get('protocol_semantics'))}`")
        lines.append("")
        lines.append("```text")
        for step in path.get("steps") or []:
            lines.append(
                f"{step.get('label')}  [{step.get('classification')}/{step.get('confidence')}]"
            )
        lines.append("```")
        lines.append("")
        if path.get("boundary"):
            b = path["boundary"]
            lines.append(
                f"- Boundary: reason=`{_md_escape(b.get('reason'))}` "
                f"object=`{_md_escape(b.get('object'))}` "
                f"classification=`{_md_escape(b.get('classification'))}`"
            )
            lines.append("")
    lines.append("### Boundaries")
    lines.append("")
    boundaries = list(eg.get("boundaries") or [])
    if not boundaries:
        lines.append("_No explicit UNKNOWN boundaries on extracted evidence paths._")
        lines.append("")
    else:
        for b in boundaries[:30]:
            lines.append(
                f"- `{_md_escape(b.get('boundary_id'))}` "
                f"reason=`{_md_escape(b.get('reason'))}` "
                f"object=`{_md_escape(b.get('object'))}` "
                f"method=`{_md_escape(b.get('method'))}` "
                f"[{_md_escape(b.get('classification'))}]"
            )
        lines.append("")
    return lines


def _render_bluetooth_dataflow_markdown(bt: dict) -> list[str]:
    lines: list[str] = []
    df = bt.get("bluetooth_dataflow") or {}
    paths = list(df.get("paths") or bt.get("dataflow_paths") or [])
    lines.append("## Bluetooth RFCOMM Dataflow")
    lines.append("")
    if not paths:
        lines.append("_No dataflow paths reconstructed._")
        lines.append("")
        return lines

    for path in paths[:20]:
        lines.append(f"### Target")
        lines.append("")
        lines.append(f"`{_md_escape(path.get('target'))}`")
        lines.append("")
        lines.append(f"#### {_md_escape(path.get('display_id') or path.get('id'))}")
        lines.append("")

        lines.append("### Caller Reconstruction")
        lines.append("")
        callers = ((path.get("caller_reconstruction") or {}).get("callers")) or []
        if not callers:
            lines.append("_UNKNOWN — no static callers in bounded scan_")
            lines.append("")
        else:
            for c in callers[:20]:
                lines.append(
                    f"- `{_md_escape(c.get('method'))}` "
                    f"[{_md_escape(c.get('classification'))}/{_md_escape(c.get('confidence'))}] "
                    f"depth={c.get('depth')}"
                )
            lines.append("")

        lines.append("### Socket Reconstruction")
        lines.append("")
        for key in ("socket_creation", "connect", "input", "output"):
            stage = path.get(key)
            if not stage:
                lines.append(f"- `{key}`: UNKNOWN")
                continue
            lines.append(
                f"- `{_md_escape(stage.get('method') or key)}` "
                f"[{_md_escape(stage.get('classification'))}/"
                f"{_md_escape(stage.get('confidence'))}]"
            )
        lines.append("")

        lines.append("### InputStream")
        lines.append("")
        reads = path.get("read_chain") or []
        if not reads:
            lines.append("_UNKNOWN — no bounded read consumer_")
            lines.append("")
        else:
            for r in reads[:10]:
                lines.append(
                    f"- `{_md_escape(r.get('text') or r.get('raw'))}` "
                    f"[{_md_escape(r.get('classification'))}]"
                )
            lines.append("")

        lines.append("### OutputStream")
        lines.append("")
        writes = path.get("write_chain") or []
        if not writes:
            lines.append("_UNKNOWN — no bounded write producer_")
            lines.append("")
        else:
            for w in writes[:10]:
                lines.append(
                    f"- `{_md_escape(w.get('text') or w.get('raw'))}` "
                    f"[{_md_escape(w.get('classification'))}]"
                )
            lines.append("")

        lines.append("### Dataflow Paths")
        lines.append("")
        lines.append(
            f"- structure=`{_md_escape(path.get('structure'))}` "
            f"classification=`{_md_escape(path.get('classification'))}` "
            f"confidence=`{_md_escape(path.get('confidence'))}`"
        )
        lines.append(
            f"- runtime_execution_proven="
            f"{'yes' if path.get('runtime_execution_proven') else 'no'}"
        )
        lines.append(
            f"- wire_correlation_available="
            f"{'yes' if path.get('wire_correlation_available') else 'no'}"
        )
        lines.append("")

        lines.append("### Evidence Classification")
        lines.append("")
        for node in path.get("nodes") or []:
            lines.append(
                f"- `{_md_escape(node.get('role') or node.get('type'))}` "
                f"`{_md_escape(node.get('value'))}` "
                f"[{_md_escape(node.get('classification'))}/"
                f"{_md_escape(node.get('confidence'))}]"
            )
        lines.append("")
    return lines


def write_markdown_report(report: Report, path: Path) -> None:
    ensure_parent(path)
    path.write_text(render_markdown(report), encoding="utf-8")
