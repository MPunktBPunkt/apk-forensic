"""Bluetooth RFCOMM path + caller/dataflow analysis orchestration."""

from __future__ import annotations

import gc
from collections import defaultdict
from pathlib import Path
from typing import Any

from apk_forensics.bluetooth_callers import (
    prioritize_rfcomm_targets,
    reconstruct_caller_paths,
    summarize_caller_reconstruction,
)
from apk_forensics.bluetooth_dataflow import (
    build_candidate_path,
    build_dataflow_path,
    collect_profile_correlations,
)
from apk_forensics.bluetooth_device import analyze_device_source
from apk_forensics.bluetooth_matcher import find_bluetooth_hits
from apk_forensics.bluetooth_object_flow import trace_object_flow
from apk_forensics.bluetooth_socket import analyze_io_path, analyze_socket_path
from apk_forensics.bluetooth_uuid import resolve_rfcomm_uuid_argument, resolve_uuid_literal_in_method
from apk_forensics.config import AnalysisConfig
from apk_forensics.evidence_graph import build_evidence_graph, empty_evidence_graph
from apk_forensics.dex_model_adapter import (
    MethodInfo,
    get_androguard_version,
    is_androguard_available,
    load_dex_entries_from_apk,
    stream_methods_with_instructions,
)
from apk_forensics.dex_xrefs import stream_collect_callers
from apk_forensics.models import Finding
from apk_forensics.utils import timed_ms


BT_LIMITATIONS = [
    "A statically reconstructed Bluetooth path is not proof of runtime execution.",
    "A statically resolved SPP UUID is not proof that the corresponding RFCOMM channel was opened at runtime.",
    "The analyzer does not infer RFCOMM channel numbers such as SCN6.",
    "Profile matches are correlations and do not constitute protocol proof.",
    "Bounded register/field dataflow only; no full SSA or global data-flow graph.",
    "Base APK and split APKs remain separate artifacts.",
    "Caller / stream reconstruction is bounded; missing consumers are UNKNOWN, not REJECTED.",
]


def empty_bluetooth_section(
    *,
    enabled: bool,
    status: str,
    warnings: list[str] | None = None,
    configuration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "enabled": enabled,
        "status": status,
        "configuration": configuration or {},
        "targets": [],
        "uuid_resolutions": [],
        "device_sources": [],
        "socket_paths": [],
        "io_paths": [],
        "paths": [],
        "caller_paths": [],
        "dataflow_paths": [],
        "input_consumers": [],
        "output_producers": [],
        "evidence_graph": empty_evidence_graph(enabled=False),
        "warnings": list(warnings or []),
        "limitations": list(BT_LIMITATIONS),
    }


def empty_bluetooth_dataflow_section() -> dict[str, Any]:
    return {
        "targets": 0,
        "caller_paths": 0,
        "dataflow_paths": 0,
        "input_consumers": 0,
        "output_producers": 0,
        "paths": [],
        "caller_reconstructions": [],
    }


def _index_methods_by_class(methods: list[MethodInfo]) -> dict[str, list[MethodInfo]]:
    by: dict[str, list[MethodInfo]] = defaultdict(list)
    for method in methods:
        by[method.class_name].append(method)
    return by


def _method_key(method: MethodInfo) -> str:
    return f"{method.class_name}->{method.method_name}{method.method_descriptor}"


def _merge_stream_callers_into_retained(
    retained: list[MethodInfo],
    dex_entries: list[tuple[str, bytes]],
    needles: list[str],
    *,
    max_extra: int,
) -> tuple[list[MethodInfo], list[str]]:
    """Second-pass: pull caller methods that may lack Bluetooth tokens in-body."""
    if not needles or max_extra <= 0:
        return retained, []
    warnings: list[str] = []
    existing = {_method_key(m) for m in retained}
    xref_hits = stream_collect_callers(dex_entries, needles, max_callers=max_extra * 4)
    wanted_keys = {h.get("source_method") for h in xref_hits if h.get("source_method")}
    if not wanted_keys:
        return retained, warnings

    # Re-stream to materialize MethodInfo bodies for caller methods only.
    _units, method_iter, load_warnings, _version = stream_methods_with_instructions(dex_entries)
    warnings.extend(load_warnings)
    extra: list[MethodInfo] = []
    for method in method_iter:
        key = _method_key(method)
        if key in wanted_keys and key not in existing:
            extra.append(method)
            existing.add(key)
            if len(extra) >= max_extra:
                warnings.append("Bluetooth caller retention cap reached; caller analysis is bounded.")
                break
    return retained + extra, warnings


def run_bluetooth_path_analysis(
    apk_path: Path,
    findings: list[Finding],
    *,
    artifact_sha256: str,
    config: AnalysisConfig,
) -> dict[str, Any]:
    configuration = {
        "bluetooth_window": config.bluetooth_window,
        "bluetooth_dataflow_depth": config.bluetooth_dataflow_depth,
        "bluetooth_max_paths": config.bluetooth_max_paths,
        "bluetooth_max_results": config.bluetooth_max_results,
        "bluetooth_target": config.bluetooth_target,
        "bluetooth_caller_depth": config.bluetooth_caller_depth,
        "bluetooth_reconstruct_callers": config.bluetooth_reconstruct_callers,
        "bluetooth_reconstruct_streams": config.bluetooth_reconstruct_streams,
        "bluetooth_reconstruct_read_write": config.bluetooth_reconstruct_read_write,
        "bluetooth_max_callers": config.bluetooth_max_callers,
        "bluetooth_max_callees": config.bluetooth_max_callees,
        "bluetooth_max_dataflow_paths": config.bluetooth_max_dataflow_paths,
        "bluetooth_max_dataflow_nodes": config.bluetooth_max_dataflow_nodes,
        "bluetooth_interprocedural": config.bluetooth_interprocedural,
        "bluetooth_max_method_hops": config.bluetooth_max_method_hops,
        "bluetooth_max_field_hops": config.bluetooth_max_field_hops,
        "bluetooth_max_object_nodes": config.bluetooth_max_object_nodes,
        "evidence_graph": config.evidence_graph,
        "evidence_graph_canonicalize": config.evidence_graph_canonicalize,
        "evidence_graph_deduplicate": config.evidence_graph_deduplicate,
        "evidence_graph_extract_paths": config.evidence_graph_extract_paths,
        "evidence_graph_include_boundaries": config.evidence_graph_include_boundaries,
        "evidence_graph_max_paths": config.evidence_graph_max_paths,
    }

    if not config.bluetooth_path:
        return empty_bluetooth_section(
            enabled=False,
            status="skipped",
            configuration=configuration,
            warnings=["Bluetooth path analysis not requested."],
        )

    if not is_androguard_available():
        return empty_bluetooth_section(
            enabled=True,
            status="skipped",
            configuration=configuration,
            warnings=[
                "Bluetooth path analysis requires the optional dependency 'androguard'.\n"
                "Install with:\n"
                "  pip install 'apk-forensics[android]'"
            ],
        )

    warnings: list[str] = []
    with timed_ms() as timing:
        try:
            dex_entries = load_dex_entries_from_apk(
                apk_path,
                max_entry_bytes=config.max_entry_read_bytes,
            )
            units, method_iter, load_warnings, version = stream_methods_with_instructions(dex_entries)
            warnings.extend(load_warnings)
            _ = units

            kept: list[MethodInfo] = []
            indexed = 0
            interesting_tokens = (
                "createRfcomm",
                "BluetoothSocket",
                "BluetoothDevice",
                "00001101-0000-1000-8000-00805",
                "fromString",
                "getInputStream",
                "getOutputStream",
                "fetchUuidsWithSdp",
                "getRemoteDevice",
                "BtAccessory",
                "BluetoothTransport",
                "BtPairing",
                "InputStream",
                "OutputStream",
            )
            for method in method_iter:
                indexed += 1
                blob = " ".join(ins.text for ins in method.instructions)
                cls = method.class_name_normalized or method.class_name
                if config.bluetooth_target:
                    q = config.bluetooth_target.lower()
                    if q not in cls.lower() and q not in method.method_name.lower() and q not in blob.lower():
                        continue
                if any(tok.lower() in blob.lower() or tok.lower() in cls.lower() for tok in interesting_tokens):
                    kept.append(method)
                if len(kept) >= max(2000, config.bluetooth_max_results * 20):
                    warnings.append("Bluetooth method retention cap reached; analysis is bounded.")
                    break

            hits = find_bluetooth_hits(
                kept,
                target_query=config.bluetooth_target,
                max_results=config.bluetooth_max_results,
            )
            rfcomm_hits = [h for h in hits if h.category == "rfcomm_create"]
            if not rfcomm_hits:
                rfcomm_hits = [h for h in hits if h.category in {"rfcomm_create", "rfcomm_listen"}]

            # Priority order: create+connect+streams > create+connect > create
            prelim: list[tuple[Any, dict[str, Any]]] = []
            for hit in rfcomm_hits:
                sock = analyze_socket_path(hit.method, hit.instruction_index, window=config.bluetooth_window)
                prelim.append((hit, sock))
            ordered_hits = prioritize_rfcomm_targets(prelim)[: config.bluetooth_max_paths]

            # Expand retained methods with callers of prioritized targets (bounded).
            if config.bluetooth_reconstruct_callers and ordered_hits:
                needles: list[str] = []
                for hit in ordered_hits:
                    m = hit.method
                    needles.extend(
                        [
                            f"{m.class_name}->{m.method_name}",
                            f"->{m.method_name}(",
                        ]
                    )
                kept, extra_warnings = _merge_stream_callers_into_retained(
                    kept,
                    dex_entries,
                    needles,
                    max_extra=min(config.bluetooth_max_callers * 2, 200),
                )
                warnings.extend(extra_warnings)

            by_class = _index_methods_by_class(kept)

            targets: list[dict[str, Any]] = []
            uuid_resolutions: list[dict[str, Any]] = []
            device_sources: list[dict[str, Any]] = []
            socket_paths: list[dict[str, Any]] = []
            io_paths: list[dict[str, Any]] = []
            paths: list[dict[str, Any]] = []
            caller_paths: list[dict[str, Any]] = []
            dataflow_paths: list[dict[str, Any]] = []
            input_consumers: list[dict[str, Any]] = []
            output_producers: list[dict[str, Any]] = []
            caller_reconstructions: list[dict[str, Any]] = []

            for method in kept:
                for lit in resolve_uuid_literal_in_method(method):
                    if lit.get("uuid"):
                        lit["method"] = f"{method.class_name}->{method.method_name}{method.method_descriptor}"
                        lit["dex_entry"] = method.dex_entry
                        if len([u for u in uuid_resolutions if u.get("source_type") == "uuid_literal_direct"]) < 50:
                            uuid_resolutions.append(lit)

            socket_cache = {id(h): s for h, s in prelim}

            for hit in ordered_hits:
                method = hit.method
                class_methods = by_class.get(method.class_name, [method])
                uuid_res = resolve_rfcomm_uuid_argument(
                    method,
                    hit.instruction_index,
                    class_methods=class_methods,
                    dataflow_depth=config.bluetooth_dataflow_depth,
                )
                uuid_res["dex_entry"] = method.dex_entry
                uuid_res["api"] = hit.api
                uuid_resolutions.append(uuid_res)

                device = analyze_device_source(
                    method,
                    hit.instruction_index,
                    window=config.bluetooth_window,
                )
                device["dex_entry"] = method.dex_entry
                device_sources.append(device)

                socket = socket_cache.get(id(hit)) or analyze_socket_path(
                    method,
                    hit.instruction_index,
                    window=config.bluetooth_window,
                )
                socket["dex_entry"] = method.dex_entry
                socket_paths.append(socket)

                if config.bluetooth_reconstruct_streams or config.bluetooth_reconstruct_read_write:
                    io_info = analyze_io_path(
                        method,
                        hit.instruction_index,
                        window=config.bluetooth_window,
                        socket_tracking=socket,
                    )
                else:
                    io_info = {
                        "method": _method_key(method),
                        "create_index": hit.instruction_index,
                        "getInputStream": socket.get("getInputStream") or [],
                        "getOutputStream": socket.get("getOutputStream") or [],
                        "read_calls": [],
                        "write_calls": [],
                        "buffer_refs": [],
                        "classification": socket.get("classification") or "UNKNOWN",
                        "confidence": socket.get("confidence") or "low",
                        "notes": ["Stream reconstruction disabled by configuration."],
                    }
                io_info["dex_entry"] = method.dex_entry
                io_paths.append(io_info)

                consumers = (io_info.get("input_consumers") or {}) if config.bluetooth_reconstruct_read_write else {}
                producers = (io_info.get("output_producers") or {}) if config.bluetooth_reconstruct_read_write else {}

                caller_rec = None
                caller_summary = None
                if config.bluetooth_reconstruct_callers:
                    caller_rec = reconstruct_caller_paths(
                        method,
                        kept,
                        caller_depth=config.bluetooth_caller_depth,
                        max_callers=config.bluetooth_max_callers,
                    )
                    caller_summary = summarize_caller_reconstruction(
                        caller_rec, max_callers_cap=config.bluetooth_max_callers
                    )
                    caller_rec["summary"] = caller_summary
                    caller_reconstructions.append(caller_rec)
                    for p in caller_rec.get("paths") or []:
                        caller_paths.append(p)

                object_flow = None
                if config.bluetooth_interprocedural and config.bluetooth_reconstruct_streams:
                    object_flow = trace_object_flow(
                        method,
                        hit.instruction_index,
                        kept,
                        socket_register=socket.get("socket_register"),
                        max_method_hops=config.bluetooth_max_method_hops,
                        max_field_hops=config.bluetooth_max_field_hops,
                        # Analysis budget separate from report truncation (max_dataflow_nodes).
                        max_object_nodes=config.bluetooth_max_object_nodes,
                        window=config.bluetooth_window,
                    )
                    # Prefer object-flow read/write when present
                    if object_flow.get("input_read_chain"):
                        consumers = {
                            **consumers,
                            "read_calls": object_flow["input_read_chain"],
                            "classification": "FACT",
                            "consumer_status": "FACT",
                            "confidence": "high",
                        }
                        io_info["read_calls"] = object_flow["input_read_chain"]
                        io_info["input_consumers"] = consumers
                    if object_flow.get("output_write_chain"):
                        producers = {
                            **producers,
                            "write_calls": object_flow["output_write_chain"],
                            "classification": "FACT",
                            "producer_status": "FACT",
                            "confidence": "high",
                        }
                        io_info["write_calls"] = object_flow["output_write_chain"]
                        io_info["output_producers"] = producers

                if consumers:
                    input_consumers.append({"target": _method_key(method), **consumers})
                if producers:
                    output_producers.append({"target": _method_key(method), **producers})

                method_text = "\n".join(ins.text for ins in method.instructions)
                profiles = collect_profile_correlations(method_text, scope="same_method")

                path = build_candidate_path(
                    method_class=method.class_name,
                    method_class_normalized=method.class_name_normalized,
                    method_name=method.method_name,
                    method_descriptor=method.method_descriptor,
                    dex_entry=method.dex_entry,
                    rfcomm_api=hit.api,
                    create_index=hit.instruction_index,
                    uuid_resolution=uuid_res,
                    device_source=device,
                    socket_path=socket,
                    io_path=io_info,
                    profile_correlations=profiles,
                )
                path["caller_reconstruction"] = caller_rec
                path["caller_summary"] = caller_summary
                path["object_flow"] = object_flow
                path["artifact_sha256"] = artifact_sha256
                paths.append(path)

                # BluetoothDataflowPath
                if len(dataflow_paths) < config.bluetooth_max_dataflow_paths:
                    sock_cls = socket.get("classification") or "FACT"
                    connect_info = None
                    if socket.get("has_connect"):
                        connect_info = {
                            "method": "BluetoothSocket.connect",
                            "classification": sock_cls,
                            "confidence": socket.get("confidence") or "medium",
                            "evidence_level": "instruction_context",
                        }
                    input_info = None
                    if socket.get("has_input_stream") or any(
                        t.get("kind") == "get_input_stream" for t in (object_flow or {}).get("transfers") or []
                    ):
                        input_info = {
                            "method": "BluetoothSocket.getInputStream",
                            "classification": sock_cls,
                            "confidence": socket.get("confidence") or "medium",
                            "evidence_level": "instruction_context",
                        }
                    output_info = None
                    if socket.get("has_output_stream") or any(
                        t.get("kind") == "get_output_stream" for t in (object_flow or {}).get("transfers") or []
                    ):
                        output_info = {
                            "method": "BluetoothSocket.getOutputStream",
                            "classification": sock_cls,
                            "confidence": socket.get("confidence") or "medium",
                            "evidence_level": "instruction_context",
                        }
                    read_chain = list(consumers.get("read_calls") or [])[: config.bluetooth_dataflow_depth + 1]
                    write_chain = list(producers.get("write_calls") or [])[: config.bluetooth_dataflow_depth + 1]
                    depth = max(0, min(config.bluetooth_dataflow_depth, 3))
                    read_chain = read_chain[: max(1, depth)] if depth else []
                    write_chain = write_chain[: max(1, depth)] if depth else []
                    if not config.bluetooth_reconstruct_read_write:
                        read_chain = []
                        write_chain = []

                    df = build_dataflow_path(
                        target_method=_method_key(method),
                        path_id=path["path_id"],
                        socket_creation={
                            "method": hit.api,
                            "classification": "FACT",
                            "confidence": "high",
                            "evidence_level": "dex_reference",
                        },
                        connect=connect_info,
                        input_info=input_info,
                        output_info=output_info,
                        read_chain=read_chain,
                        write_chain=write_chain,
                        caller_reconstruction={
                            "caller_count": (caller_rec or {}).get("caller_count", 0),
                            "callers": (caller_rec or {}).get("callers") or [],
                            "classification": (caller_rec or {}).get("classification"),
                            "summary": caller_summary,
                        }
                        if caller_rec
                        else None,
                        max_nodes=config.bluetooth_max_dataflow_nodes,
                        object_flow=object_flow,
                        caller_summary=caller_summary,
                    )
                    dataflow_paths.append(df)
                    # Drop bulky per-path object_flow graphs after BTDATA materialization.
                    if object_flow is not None:
                        path["object_flow"] = {
                            "objects": object_flow.get("objects"),
                            "boundaries": object_flow.get("boundaries"),
                            "socket_transfers": object_flow.get("socket_transfers"),
                            "stream_transfers": object_flow.get("stream_transfers"),
                            "input_read_chain": object_flow.get("input_read_chain"),
                            "output_write_chain": object_flow.get("output_write_chain"),
                            "ranking_score": object_flow.get("ranking_score"),
                            "confidence": object_flow.get("confidence"),
                            "limitations": object_flow.get("limitations"),
                        }
                    gc.collect()

                targets.append(
                    {
                        "class_name": method.class_name,
                        "class_name_normalized": method.class_name_normalized,
                        "method_name": method.method_name,
                        "method_descriptor": method.method_descriptor,
                        "dex_entry": method.dex_entry,
                        "api": hit.api,
                        "match_type": hit.match_type,
                        "priority": hit.priority,
                        "instruction_index": hit.instruction_index,
                        "path_id": path["path_id"],
                        "uuid": uuid_res.get("uuid"),
                        "uuid_source_type": uuid_res.get("source_type"),
                        "caller_count": (caller_rec or {}).get("caller_count", 0),
                        "caller_summary": caller_summary,
                    }
                )

            uuid_to_paths: dict[str, list[str]] = defaultdict(list)
            for path in paths:
                u = (path.get("uuid_resolution") or {}).get("uuid")
                if u:
                    uuid_to_paths[u].append(path["path_id"])
            for path in paths:
                u = (path.get("uuid_resolution") or {}).get("uuid")
                if u and len(uuid_to_paths[u]) > 1:
                    path["shared_uuid"] = True
                    path["shared_uuid_path_ids"] = list(uuid_to_paths[u])
                    path["notes"].append(
                        "Same UUID appears in multiple static paths; not proof of same runtime path."
                    )

            # Keep priority order from ordered_hits (already strongest-first).
            for idx, path in enumerate(paths, start=1):
                path["display_id"] = f"BTPATH-{idx:06d}"
            # Ranking reorders review priority only — does not change classifications.
            dataflow_paths.sort(key=lambda d: (-int(d.get("ranking_score") or 0), d.get("target") or ""))
            for idx, df in enumerate(dataflow_paths, start=1):
                df["display_id"] = f"BTDATA-{idx:06d}"

            path_ids_by_value: dict[str, list[str]] = defaultdict(list)
            for path in paths:
                for key in (
                    path.get("rfcomm_api"),
                    (path.get("uuid_resolution") or {}).get("uuid"),
                ):
                    if key:
                        path_ids_by_value[str(key).lower()].append(path["path_id"])
            for finding in findings:
                ids = path_ids_by_value.get(finding.normalized_value.lower()) or path_ids_by_value.get(
                    finding.value.lower()
                )
                if ids:
                    finding.bluetooth_path_ids = sorted(set(ids))

            status = "complete"
            if warnings:
                status = "partial"
            if not targets and not uuid_resolutions:
                status = "partial"
                warnings.append("No RFCOMM create targets found in retained Bluetooth-related methods.")

        except Exception as exc:  # noqa: BLE001
            return empty_bluetooth_section(
                enabled=True,
                status="failed",
                configuration=configuration,
                warnings=[str(exc)],
            )

    socket_transfers = sum(len((p.get("object_flow") or {}).get("socket_transfers") or []) for p in paths)
    stream_transfers = sum(len((p.get("object_flow") or {}).get("stream_transfers") or []) for p in paths)
    dataflow_nodes = sum(int((d.get("node_count") or 0)) for d in dataflow_paths)
    dataflow_edges = sum(int((d.get("edge_count") or 0)) for d in dataflow_paths)
    caller_summaries = [c.get("summary") for c in caller_reconstructions if c.get("summary")]
    dataflow_section = {
        "targets": len(targets),
        "caller_paths": len(caller_paths),
        "caller_summaries": caller_summaries,
        "dataflow_paths": len(dataflow_paths),
        "dataflow_nodes": dataflow_nodes,
        "dataflow_edges": dataflow_edges,
        "socket_transfers": socket_transfers,
        "stream_transfers": stream_transfers,
        "input_consumers": len(
            [c for c in input_consumers if (c.get("read_calls") or c.get("consumer_status") not in (None, "UNKNOWN"))]
        ),
        "output_producers": len(
            [p for p in output_producers if (p.get("write_calls") or p.get("producer_status") not in (None, "UNKNOWN"))]
        ),
        "paths": dataflow_paths,
        "caller_reconstructions": caller_reconstructions,
        "input_consumer_details": input_consumers,
        "output_producer_details": output_producers,
    }

    if config.evidence_graph:
        evidence_graph = build_evidence_graph(
            dataflow_paths=dataflow_paths,
            apk_sha256=artifact_sha256,
            enabled=True,
            canonicalize=config.evidence_graph_canonicalize,
            deduplicate=config.evidence_graph_deduplicate,
            extract_paths=config.evidence_graph_extract_paths,
            include_boundaries=config.evidence_graph_include_boundaries,
            max_evidence_paths=config.evidence_graph_max_paths,
        )
        # Fill cross-version comparable counts from this analysis.
        cv = evidence_graph.get("cross_version_evidence") or {}
        comparable = cv.get("comparable") or {}
        comparable.update(
            {
                "rfcomm_targets": len(targets),
                "uuid_resolutions": len(uuid_resolutions),
                "bluetooth_paths": len(paths),
                "caller_paths": len(caller_paths),
                "input_consumers": dataflow_section["input_consumers"],
                "output_producers": dataflow_section["output_producers"],
            }
        )
        cv["comparable"] = comparable
        evidence_graph["cross_version_evidence"] = cv
    else:
        evidence_graph = empty_evidence_graph(enabled=False)

    return {
        "enabled": True,
        "status": status,
        "parser": {"name": "androguard", "version": version},
        "configuration": configuration,
        "targets": targets,
        "uuid_resolutions": uuid_resolutions,
        "device_sources": device_sources,
        "socket_paths": socket_paths,
        "io_paths": io_paths,
        "paths": paths,
        "caller_paths": caller_paths,
        "dataflow_paths": dataflow_paths,
        "input_consumers": input_consumers,
        "output_producers": output_producers,
        "bluetooth_dataflow": dataflow_section,
        "evidence_graph": evidence_graph,
        "warnings": warnings,
        "limitations": list(BT_LIMITATIONS),
        "duration_ms": timing["duration_ms"],
        "counts": {
            "targets": len(targets),
            "uuid_resolutions": len(uuid_resolutions),
            "device_sources": len(device_sources),
            "socket_paths": len(socket_paths),
            "io_paths": len(io_paths),
            "paths": len(paths),
            "caller_paths": len(caller_paths),
            "dataflow_paths": len(dataflow_paths),
            "dataflow_nodes": dataflow_nodes,
            "dataflow_edges": dataflow_edges,
            "socket_transfers": socket_transfers,
            "stream_transfers": stream_transfers,
            "input_consumers": dataflow_section["input_consumers"],
            "output_producers": dataflow_section["output_producers"],
            "raw_nodes": (evidence_graph.get("raw") or {}).get("nodes", 0),
            "raw_edges": (evidence_graph.get("raw") or {}).get("edges", 0),
            "canonical_objects": (evidence_graph.get("canonical") or {}).get("objects", 0),
            "canonical_nodes": (evidence_graph.get("canonical") or {}).get("nodes", 0),
            "canonical_edges": (evidence_graph.get("canonical") or {}).get("edges", 0),
            "evidence_paths": (evidence_graph.get("canonical") or {}).get("paths", 0),
            "methods_indexed": indexed,
            "methods_retained": len(kept),
        },
    }
