"""Cautious static candidate chains from DEX context evidence."""

from __future__ import annotations

import hashlib
from typing import Any


CHAIN_NOTE = (
    "Static candidate chain only; runtime execution not established. "
    "No wire correlation is implied."
)

PROFILE_TOKENS = {"BCL", "RHMI", "Etch", "SAS", "CDS", "AV"}
TRANSPORT_TOKENS = {
    "createRfcommSocketToServiceRecord",
    "createInsecureRfcommSocketToServiceRecord",
    "BluetoothSocket;->connect",
    "getInputStream",
    "getOutputStream",
    "00001101-0000-1000-8000-00805f9b34fb",
}


def _node_id(label: str, method_key: str) -> str:
    key = f"{method_key}|{label}"
    return "node-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _chain_id(method_key: str, labels: list[str]) -> str:
    key = "|".join([method_key, *labels])
    return "chain-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def _method_key_from_context(ctx: dict[str, Any]) -> str:
    return f"{ctx['class_name']}->{ctx['method_name']}{ctx['method_descriptor']}"


def _labels_in_context(ctx: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (label, evidence_kind) pairs found in one method context."""
    labels: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(label: str, kind: str) -> None:
        if label not in seen:
            seen.add(label)
            labels.append((label, kind))

    match_val = (ctx.get("match") or {}).get("value") or ""
    match_type = (ctx.get("match") or {}).get("match_type") or "unknown"
    if match_val:
        add(match_val, match_type)

    symbols = ctx.get("referenced_symbols") or {}
    for method_ref in symbols.get("methods") or []:
        if "createRfcommSocketToServiceRecord" in method_ref:
            add("createRfcommSocketToServiceRecord", "method_reference")
        if "createInsecureRfcommSocketToServiceRecord" in method_ref:
            add("createInsecureRfcommSocketToServiceRecord", "method_reference")
        if "BluetoothSocket;->connect" in method_ref:
            add("BluetoothSocket;->connect", "method_reference")
        if "getInputStream" in method_ref:
            add("getInputStream", "method_reference")
        if "getOutputStream" in method_ref:
            add("getOutputStream", "method_reference")
        if "fetchUuidsWithSdp" in method_ref:
            add("fetchUuidsWithSdp", "method_reference")
        if "BluetoothDevice" in method_ref:
            add("BluetoothDevice", "method_reference")
    for class_ref in symbols.get("classes") or []:
        if "BluetoothSocket" in class_ref:
            add("BluetoothSocket", "class_reference")
        if "BluetoothDevice" in class_ref:
            add("BluetoothDevice", "class_reference")
    for string_ref in symbols.get("strings") or []:
        lower = string_ref.lower()
        if "00001101-0000-1000-8000-00805f9b34fb" in lower:
            add("00001101-0000-1000-8000-00805f9b34fb", "string")
        for token in PROFILE_TOKENS:
            if token.lower() == string_ref.lower() or token == string_ref:
                add(token, "string")

    # Keep stable interesting order
    order = [
        "BluetoothDevice",
        "createRfcommSocketToServiceRecord",
        "createInsecureRfcommSocketToServiceRecord",
        "00001101-0000-1000-8000-00805f9b34fb",
        "BluetoothSocket;->connect",
        "BluetoothSocket",
        "getInputStream",
        "getOutputStream",
        "fetchUuidsWithSdp",
        *sorted(PROFILE_TOKENS),
    ]
    rank = {name: idx for idx, name in enumerate(order)}
    labels.sort(key=lambda item: (rank.get(item[0], 1000), item[0]))
    return labels


def build_candidate_chains(
    contexts: list[dict[str, Any]],
    *,
    xref_candidates: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Create candidate chains only when multiple evidence nodes share a method."""
    _ = xref_candidates  # reserved for future same-caller hops; unused in v0.2 depth-0 chains
    by_method: dict[str, list[dict[str, Any]]] = {}
    for ctx in contexts:
        key = _method_key_from_context(ctx)
        by_method.setdefault(key, []).append(ctx)

    chains: list[dict[str, Any]] = []
    for method_key, ctxs in sorted(by_method.items()):
        # Merge symbols across all contexts of same method
        merged_labels: dict[str, str] = {}
        for ctx in ctxs:
            for label, kind in _labels_in_context(ctx):
                merged_labels.setdefault(label, kind)

        interesting = [
            label
            for label in merged_labels
            if label in TRANSPORT_TOKENS
            or label in PROFILE_TOKENS
            or label in {"BluetoothDevice", "BluetoothSocket", "fetchUuidsWithSdp"}
        ]
        if len(interesting) < 2:
            continue

        # Prefer transport-oriented ordering
        ordered = []
        for preferred in [
            "BluetoothDevice",
            "createRfcommSocketToServiceRecord",
            "createInsecureRfcommSocketToServiceRecord",
            "00001101-0000-1000-8000-00805f9b34fb",
            "BluetoothSocket;->connect",
            "getInputStream",
            "getOutputStream",
            "BluetoothSocket",
            "fetchUuidsWithSdp",
            "BCL",
            "RHMI",
            "Etch",
            "SAS",
            "CDS",
            "AV",
        ]:
            if preferred in interesting and preferred not in ordered:
                ordered.append(preferred)
        for label in sorted(interesting):
            if label not in ordered:
                ordered.append(label)

        nodes = []
        edges = []
        for label in ordered:
            nid = _node_id(label, method_key)
            nodes.append(
                {
                    "node_id": nid,
                    "label": label,
                    "kind": merged_labels.get(label, "unknown"),
                }
            )
        for left, right in zip(nodes, nodes[1:]):
            edges.append(
                {
                    "from": left["node_id"],
                    "to": right["node_id"],
                    "relationship": "same_method",
                    "evidence_level": "instruction_context",
                    "classification": "FACT",
                    "confidence": "medium",
                }
            )

        sample = ctxs[0]
        chain = {
            "chain_id": _chain_id(method_key, ordered),
            "display_id": "",
            "method": {
                "dex_entry": sample.get("dex_entry"),
                "class_name": sample.get("class_name"),
                "class_name_normalized": sample.get("class_name_normalized"),
                "method_name": sample.get("method_name"),
                "method_descriptor": sample.get("method_descriptor"),
            },
            "nodes": nodes,
            "edges": edges,
            "context_ids": [c.get("context_id") for c in ctxs],
            "classification": "INFERENCE",
            "confidence": "low",
            "evidence_level": "candidate_chain",
            "runtime_execution_proven": False,
            "wire_correlation_available": False,
            "notes": [
                CHAIN_NOTE,
                (
                    "The static DEX evidence forms a candidate chain from related "
                    "symbols in the same method. This is not protocol or device proof."
                ),
            ],
            "summary": " -> ".join(ordered),
        }
        chains.append(chain)

    chains.sort(key=lambda c: (c.get("summary") or "", c.get("chain_id") or ""))
    for idx, chain in enumerate(chains, start=1):
        chain["display_id"] = f"CHAIN-{idx:06d}"
    return chains
