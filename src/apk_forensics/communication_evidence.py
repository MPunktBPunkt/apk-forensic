"""v1.0 Communication Evidence Graph orchestration + offline postprocessing.

v1.4: optional expansion of method seeds to interface buffer consumers
(AccessorySocket / Packet.decode*) that sit above transport wrappers.
"""

from __future__ import annotations

import re
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

# Methods whose bodies reference these APIs are buffer consumers above transport wrappers.
_BUFFER_CONSUMER_SEED_RE = re.compile(
    r"(?:AccessorySocket|DeviceManagerSocket);"
    r"->(?:read|write)\(|"
    r"BclConnection;->(?:internalread|readPacket|write|knock|data)\(|"
    r"packet/Packet;->(?:decode|encode)|"
    r"BufferedBclConnection"
)

# Etch remoting transport invoke refs (v1.x gap: BCL seeds alone miss sas_*/DeliveryService/Tcp path).
# Name tokens are search seeds only — not protocol FACT.
_ETCH_TRANSPORT_SEED_RE = re.compile(
    r"(?:RemoteBMWRemotingServer|RemoteBMWRemoting);"
    r"->(?:sas_|_begin|_end|_begincall|_endcall|_newMessage)|"
    r"BMWRemotingHelper;->newServer|"
    r"ValueFactoryBMWRemoting|"
    r"DefaultDeliveryService|"
    r"org/apache/etch/[^;\s]+;"
    r"->(?:"
    r"begincall|endcall|transportMessage|sessionMessage|"
    r"data|packet|write|flush|send|"
    r"getTransport|newTransport|connect"
    r")|"
    r"TcpTransport|"
    r"TcpTransportFactory|"
    r"MguTransportFactory|"
    r"TransportFactory;->getTransport"
)


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


def expand_buffer_consumer_seeds(
    apk_path: Path,
    seed_keys: set[str],
    *,
    max_extra: int = 80,
    include_etch_transport: bool = False,
) -> tuple[set[str], dict[str, Any]]:
    """Add methods that invoke AccessorySocket/Packet buffer APIs (v1.4 gap fix).

    Optional ``include_etch_transport`` also retains methods that invoke Etch
    remoting/transport APIs (DeliveryService / TcpTransport / sas_* proxy). This is
    seed expansion for object/dataflow tracking — not a protocol identity claim.

    Does not raise SearchPlan limits; only widens the offline/live method seed set
    when transport wrappers alone hide real byte processing behind interfaces.
    """
    meta: dict[str, Any] = {
        "enabled": True,
        "max_extra": max_extra,
        "added": [],
        "added_bcl_accessory": [],
        "added_etch_transport": [],
        "scanned_methods": 0,
        "include_etch_transport": bool(include_etch_transport),
        "note": (
            "Expansion follows concrete invoke refs to AccessorySocket/Packet/"
            "BclConnection buffer APIs"
            + (" and Etch remoting/transport APIs" if include_etch_transport else "")
            + " — not method-name protocol claims."
        ),
    }
    if max_extra <= 0:
        meta["enabled"] = False
        return set(seed_keys), meta
    dex = load_dex_entries_from_apk(apk_path, max_entry_bytes=64 * 1024 * 1024)
    _units, it, _w, _v = stream_methods_with_instructions(dex)
    expanded = set(seed_keys)
    added: list[str] = []
    added_bcl: list[str] = []
    added_etch: list[str] = []
    for method in it:
        meta["scanned_methods"] += 1
        key = _method_key(method)
        if key in expanded:
            continue
        body = " ".join((ins.text or "") for ins in (method.instructions or []))
        hit_bcl = bool(
            _BUFFER_CONSUMER_SEED_RE.search(body)
            or (
                "packet/Packet" in method.class_name
                and (method.method_name or "").startswith(("decode", "encode"))
            )
        )
        hit_etch = bool(include_etch_transport and _ETCH_TRANSPORT_SEED_RE.search(body))
        if hit_bcl or hit_etch:
            expanded.add(key)
            added.append(key)
            if hit_bcl:
                added_bcl.append(key)
            if hit_etch:
                added_etch.append(key)
            if len(added) >= max_extra:
                break
    meta["added"] = added
    meta["added_count"] = len(added)
    meta["added_bcl_accessory"] = added_bcl
    meta["added_etch_transport"] = added_etch
    meta["added_bcl_accessory_count"] = len(added_bcl)
    meta["added_etch_transport_count"] = len(added_etch)
    return expanded, meta


def load_methods_for_communication(
    apk_path: Path,
    wanted_keys: set[str],
    *,
    max_methods: int = 200,
    also_same_class: bool = True,
    expand_interface_consumers: bool = False,
    expand_etch_transport: bool = False,
    max_expand_extra: int = 80,
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
        "seed_expansion": None,
    }
    if not wanted_keys and not expand_interface_consumers and not expand_etch_transport:
        return [], ["No transport I/O method keys available for communication analysis."], retention

    keys = set(wanted_keys)
    if expand_interface_consumers or expand_etch_transport:
        # Allow etch-only expansion even when transport I/O keys are empty (ANALYZER_GAP fix).
        keys, exp_meta = expand_buffer_consumer_seeds(
            apk_path,
            keys,
            max_extra=max_expand_extra,
            include_etch_transport=bool(expand_etch_transport),
        )
        retention["seed_expansion"] = exp_meta
        warnings.append(
            f"v1.4 seed expansion added {exp_meta.get('added_count', 0)} "
            f"interface/buffer"
            f"{'/etch-transport' if expand_etch_transport else ''} consumer methods."
        )

    wanted_classes = set()
    for k in keys:
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
        take = key in keys
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
                    "knock",
                    "handshake",
                    "sas_",
                    "begincall",
                    "endcall",
                    "transport",
                    "connect",
                    "send",
                )
            ):
                take = True
            if "[B" in desc or "ByteBuffer" in desc or "InputStream" in desc or "OutputStream" in desc:
                take = True
            # Etch/BMW remoting classes retained when etch-transport expansion seeded them
            if "idrive" in (method.class_name or "").lower() or "apache/etch" in (
                method.class_name or ""
            ).lower():
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
            expand_interface_consumers=bool(config.get("expand_interface_consumers", False)),
            expand_etch_transport=bool(config.get("expand_etch_transport", False)),
            max_expand_extra=int(config.get("max_expand_extra", 80)),
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
        expand_interface_consumers=bool(config.get("expand_interface_consumers", False)),
        expand_etch_transport=bool(config.get("expand_etch_transport", False)),
        max_expand_extra=int(config.get("max_expand_extra", 80)),
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
