"""v1.0 Communication Evidence Graph orchestration + offline postprocessing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from apk_forensics.communication_dataflow import (
    analyze_communication_methods,
    empty_communication_section,
)
from apk_forensics.coverage_analysis import annotate_paths
from apk_forensics.dex_model_adapter import (
    MethodInfo,
    load_dex_entries_from_apk,
    stream_methods_with_instructions,
)
from apk_forensics.utils import timed_ms


def _collect_io_method_keys(bluetooth_section: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    df = bluetooth_section.get("bluetooth_dataflow") or {}
    for path in df.get("paths") or bluetooth_section.get("dataflow_paths") or []:
        for step in path.get("input_read_chain") or path.get("read_chain") or []:
            if step.get("method"):
                keys.add(str(step["method"]))
        for step in path.get("output_write_chain") or path.get("write_chain") or []:
            if step.get("method"):
                keys.add(str(step["method"]))
        for c in (path.get("caller_chain") or []):
            keys.add(str(c))
    for detail in df.get("input_consumer_details") or bluetooth_section.get("input_consumers") or []:
        if isinstance(detail, dict):
            if detail.get("method"):
                keys.add(str(detail["method"]))
            for rc in detail.get("read_calls") or []:
                if rc.get("method"):
                    keys.add(str(rc["method"]))
    for detail in df.get("output_producer_details") or bluetooth_section.get("output_producers") or []:
        if isinstance(detail, dict):
            if detail.get("method"):
                keys.add(str(detail["method"]))
            for wc in detail.get("write_calls") or []:
                if wc.get("method"):
                    keys.add(str(wc["method"]))
    return keys


def _method_key(m: MethodInfo) -> str:
    return f"{m.class_name}->{m.method_name}{m.method_descriptor}"


def load_methods_for_communication(
    apk_path: Path,
    wanted_keys: set[str],
    *,
    max_methods: int = 200,
    also_same_class: bool = True,
) -> tuple[list[MethodInfo], list[str], dict[str, Any]]:
    """Load a bounded set of MethodInfo bodies relevant to communication analysis.

    Retention stats distinguish analyzer METHOD_RETENTION_CAP from APK boundaries.
    """
    warnings: list[str] = []
    retention: dict[str, Any] = {
        "candidate_methods": 0,
        "retained_methods": 0,
        "discarded_methods": 0,
        "discard_reason": None,
        "cap": max_methods,
        "capped": False,
        "limit_kind": "analyzer",
        "note": "Retention cap is an analyzer bound, not a native/reflection APK boundary.",
    }
    if not wanted_keys:
        return [], ["No transport I/O method keys available for communication analysis."], retention
    wanted_classes = set()
    for k in wanted_keys:
        if "->" in k:
            wanted_classes.add(k.split("->", 1)[0])

    dex = load_dex_entries_from_apk(apk_path, max_entry_bytes=64 * 1024 * 1024)
    _units, it, load_warnings, _v = stream_methods_with_instructions(dex)
    warnings.extend(load_warnings)
    selected: list[MethodInfo] = []
    seen: set[str] = set()
    candidates = 0
    for method in it:
        key = _method_key(method)
        take = key in wanted_keys
        if also_same_class and method.class_name in wanted_classes:
            # Prefer methods that look communication-related to limit size
            name = method.method_name or ""
            desc = method.method_descriptor or ""
            if take or any(
                x in name.lower()
                for x in (
                    "read",
                    "write",
                    "parse",
                    "decode",
                    "encode",
                    "serial",
                    "buffer",
                    "flush",
                    "message",
                    "packet",
                    "frame",
                )
            ):
                take = True
            if "[B" in desc or "ByteBuffer" in desc or "InputStream" in desc or "OutputStream" in desc:
                take = True
        if take and key not in seen:
            candidates += 1
            if len(selected) >= max_methods:
                # Still count remaining candidates until stream ends would be expensive;
                # mark capped and stop scanning further DEX bodies.
                retention["capped"] = True
                retention["discard_reason"] = "METHOD_RETENTION_CAP"
                warnings.append(
                    f"Communication method retention capped at {max_methods}; analysis is bounded."
                )
                break
            selected.append(method)
            seen.add(key)
    retention["candidate_methods"] = candidates if not retention["capped"] else max(candidates, len(selected))
    # When capped, discarded is at least the unseen remainder unknown; report retained vs cap.
    retention["retained_methods"] = len(selected)
    if retention["capped"]:
        retention["discarded_methods"] = max(0, retention["candidate_methods"] - len(selected))
        # candidate_methods counted only until cap hit; mark undercount explicitly
        retention["candidate_methods_undercount"] = True
        retention["candidate_methods"] = len(selected)  # lower bound known at stop
        retention["discarded_methods"] = "UNKNOWN"  # cannot know without full scan past cap
        retention["note"] = (
            "METHOD_RETENTION_CAP stopped DEX method streaming early; "
            "discarded_methods beyond the cap are UNKNOWN without a full re-scan."
        )
    else:
        retention["discarded_methods"] = 0
    return selected, warnings, retention


def build_communication_evidence(
    methods: list[MethodInfo],
    *,
    bluetooth_section: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = config or {}
    if not cfg.get("enabled", True):
        return empty_communication_section(enabled=False)

    result = analyze_communication_methods(
        methods,
        max_buffer_hops=int(cfg.get("max_buffer_hops", 5)),
        max_parser_hops=int(cfg.get("max_parser_hops", 3)),
        max_message_hops=int(cfg.get("max_message_hops", 3)),
        max_method_hops=int(cfg.get("max_method_hops", 3)),
        max_methods=int(cfg.get("max_object_nodes", 500)),
    )

    # Link to transport evidence without rewriting classifications
    transport = {
        "evidence_graph_enabled": bool((bluetooth_section or {}).get("evidence_graph", {}).get("enabled")),
        "transport_path_ids": [
            p.get("display_id") or p.get("path_id")
            for p in ((bluetooth_section or {}).get("evidence_graph") or {}).get("evidence_paths") or []
        ],
        "rfcomm_targets": ((bluetooth_section or {}).get("counts") or {}).get("targets"),
        "note": "Communication analysis does not reclassify transport evidence.",
    }
    result["transport_link"] = transport
    result["provenance"] = provenance or {}
    result["configuration"] = {
        "max_buffer_hops": int(cfg.get("max_buffer_hops", 5)),
        "max_parser_hops": int(cfg.get("max_parser_hops", 3)),
        "max_message_hops": int(cfg.get("max_message_hops", 3)),
        "max_method_hops": int(cfg.get("max_method_hops", 3)),
        "max_dataflow_paths": int(cfg.get("max_dataflow_paths", 100)),
        "interprocedural": bool(cfg.get("interprocedural", True)),
    }
    # Cap paths
    max_paths = int(cfg.get("max_dataflow_paths", 100))
    paths = list(result.get("paths") or [])[:max_paths]
    retention = (provenance or {}).get("method_retention") or cfg.get("method_retention") or {}
    retention_capped = bool(retention.get("capped"))
    annotated, coverage = annotate_paths(paths, retention_capped=retention_capped)
    for i, p in enumerate(annotated, start=1):
        p["display_id"] = f"PATH-COMM-{i:06d}"
    result["paths"] = annotated
    result["coverage"] = coverage
    result["method_retention"] = retention
    result["summary"]["communication_paths"] = len(annotated)
    result["summary"]["coverage"] = {
        "complete": coverage.get("complete"),
        "truncated": coverage.get("truncated"),
        "boundary": coverage.get("boundary"),
        "unresolved": coverage.get("unresolved"),
        "no_continuation": coverage.get("no_continuation"),
        "primary_truncation": coverage.get("primary_truncation"),
    }
    return result


def run_communication_analysis(
    apk_path: Path,
    bluetooth_section: dict[str, Any],
    *,
    config: dict[str, Any],
    artifact_sha256: str | None = None,
    engine_version: str | None = None,
    plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Live communication analysis seeded by transport I/O method keys."""
    if not config.get("enabled"):
        return empty_communication_section(enabled=False)

    with timed_ms() as timing:
        keys = _collect_io_method_keys(bluetooth_section)
        methods, warnings, retention = load_methods_for_communication(
            apk_path,
            keys,
            max_methods=min(int(config.get("max_object_nodes", 500)), 200),
        )
        provenance = {
            "mode": "live_post_transport",
            "source_engine_version": engine_version,
            "source_plan_sha256": plan_sha256,
            "source_artifact_sha256": artifact_sha256,
            "postprocessing_version": engine_version,
            "seed_method_keys": sorted(keys)[:50],
            "seed_method_key_count": len(keys),
            "method_retention": retention,
        }
        result = build_communication_evidence(
            methods,
            bluetooth_section=bluetooth_section,
            config={**config, "method_retention": retention},
            provenance=provenance,
        )
        result["warnings"] = warnings
        result["status"] = "complete" if result.get("paths") or methods else "partial"
    result["duration_ms"] = timing["duration_ms"]
    return result


def postprocess_communication_from_report(
    report: dict[str, Any],
    apk_path: Path | None,
    *,
    config: dict[str, Any],
    postprocessing_version: str,
) -> dict[str, Any]:
    """Prefer offline postprocessing on a persisted report's transport evidence."""
    bt = report.get("bluetooth_path") or {}
    tool = report.get("tool") or {}
    analysis = report.get("analysis") or {}
    inp = report.get("input") or {}
    provenance = {
        "mode": "offline_postprocess",
        "source_dataset": inp.get("path") or inp.get("file_name"),
        "source_engine_version": tool.get("version") or analysis.get("engine_version"),
        "source_plan_sha256": analysis.get("plan_sha256")
        or (report.get("search_plan") or {}).get("plan_sha256"),
        "source_artifact_sha256": inp.get("sha256") or (report.get("artifact") or {}).get("sha256"),
        "postprocessing_version": postprocessing_version,
    }
    if apk_path is None or not Path(apk_path).is_file():
        # Without APK bodies we can only emit an empty/partial scaffold with provenance.
        empty = empty_communication_section(enabled=True)
        empty["status"] = "partial"
        empty["warnings"] = [
            "APK path unavailable; communication postprocess requires method bodies."
        ]
        empty["provenance"] = provenance
        return empty

    keys = _collect_io_method_keys(bt)
    methods, warnings, retention = load_methods_for_communication(
        Path(apk_path),
        keys,
        max_methods=min(int(config.get("max_object_nodes", 500)), 200),
    )
    provenance["method_retention"] = retention
    result = build_communication_evidence(
        methods,
        bluetooth_section=bt,
        config={**config, "method_retention": retention},
        provenance=provenance,
    )
    result["warnings"] = warnings
    result["status"] = "complete" if methods else "partial"
    return result
