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
    lines.append("")
    lines.append(
        "> A statically reconstructed Bluetooth path is not proof of runtime execution.  \n"
        "> A statically resolved SPP UUID is not proof that an RFCOMM channel was opened at runtime.  \n"
        "> The analyzer does not infer RFCOMM channel numbers such as SCN6.  \n"
        "> Profile matches are correlations and do not constitute protocol proof."
    )
    lines.append("")

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
    return lines


def write_markdown_report(report: Report, path: Path) -> None:
    ensure_parent(path)
    path.write_text(render_markdown(report), encoding="utf-8")
