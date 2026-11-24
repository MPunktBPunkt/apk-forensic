"""v0.3 Bluetooth RFCOMM path analysis orchestration."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from apk_forensics.bluetooth_dataflow import build_candidate_path, collect_profile_correlations
from apk_forensics.bluetooth_device import analyze_device_source
from apk_forensics.bluetooth_matcher import RFCOMM_CREATE, find_bluetooth_hits
from apk_forensics.bluetooth_socket import analyze_io_path, analyze_socket_path
from apk_forensics.bluetooth_uuid import resolve_rfcomm_uuid_argument, resolve_uuid_literal_in_method
from apk_forensics.config import AnalysisConfig
from apk_forensics.dex_model_adapter import (
    MethodInfo,
    get_androguard_version,
    is_androguard_available,
    load_dex_entries_from_apk,
    stream_methods_with_instructions,
)
from apk_forensics.models import Finding
from apk_forensics.utils import timed_ms


BT_LIMITATIONS = [
    "A statically reconstructed Bluetooth path is not proof of runtime execution.",
    "A statically resolved SPP UUID is not proof that the corresponding RFCOMM channel was opened at runtime.",
    "The analyzer does not infer RFCOMM channel numbers such as SCN6.",
    "Profile matches are correlations and do not constitute protocol proof.",
    "Bounded register/field dataflow only; no full SSA or global data-flow graph.",
    "Base APK and split APKs remain separate artifacts.",
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
        "warnings": list(warnings or []),
        "limitations": list(BT_LIMITATIONS),
    }


def _index_methods_by_class(methods: list[MethodInfo]) -> dict[str, list[MethodInfo]]:
    by: dict[str, list[MethodInfo]] = defaultdict(list)
    for method in methods:
        by[method.class_name].append(method)
    return by


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
    }

    if not config.bluetooth_path:
        return empty_bluetooth_section(
            enabled=False,
            status="skipped",
            configuration=configuration,
            warnings=["Bluetooth path analysis not requested."],
        )

    # bluetooth-path implies need for androguard / DEX semantics
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

            # Keep methods that look Bluetooth-related to bound memory.
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
                # safety bound
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
                # fallback: also accept listen APIs as targets
                rfcomm_hits = [h for h in hits if h.category in {"rfcomm_create", "rfcomm_listen"}]

            by_class = _index_methods_by_class(kept)

            targets: list[dict[str, Any]] = []
            uuid_resolutions: list[dict[str, Any]] = []
            device_sources: list[dict[str, Any]] = []
            socket_paths: list[dict[str, Any]] = []
            io_paths: list[dict[str, Any]] = []
            paths: list[dict[str, Any]] = []

            # Also collect standalone SPP literals for correlation (not auto-linked)
            for method in kept:
                for lit in resolve_uuid_literal_in_method(method):
                    if lit.get("uuid"):
                        lit["method"] = f"{method.class_name}->{method.method_name}{method.method_descriptor}"
                        lit["dex_entry"] = method.dex_entry
                        # avoid flooding
                        if len([u for u in uuid_resolutions if u.get("source_type") == "uuid_literal_direct"]) < 50:
                            uuid_resolutions.append(lit)

            for hit in rfcomm_hits[: config.bluetooth_max_paths]:
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

                socket = analyze_socket_path(
                    method,
                    hit.instruction_index,
                    window=config.bluetooth_window,
                )
                socket["dex_entry"] = method.dex_entry
                socket_paths.append(socket)

                io_info = analyze_io_path(
                    method,
                    hit.instruction_index,
                    window=config.bluetooth_window,
                )
                io_info["dex_entry"] = method.dex_entry
                io_paths.append(io_info)

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
                paths.append(path)

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
                    }
                )

            # Mark shared UUIDs across paths (not same runtime path)
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

            paths.sort(
                key=lambda p: (
                    0 if (p.get("uuid_resolution") or {}).get("uuid") else 1,
                    p.get("class_name_normalized") or "",
                    p.get("method_name") or "",
                    p.get("path_id") or "",
                )
            )
            for idx, path in enumerate(paths, start=1):
                path["display_id"] = f"BTPATH-{idx:06d}"

            # Link findings loosely by value
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
            "methods_indexed": indexed,
            "methods_retained": len(kept),
        },
    }
