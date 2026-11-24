"""Bounded RFCOMM caller reconstruction (instruction-scan XREFs, no full call graph)."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from apk_forensics.dex_model_adapter import MethodInfo


CALLER_LIMITATION = "Static invoke reference only; runtime execution not established."


def _method_key(method: MethodInfo) -> str:
    return f"{method.class_name}->{method.method_name}{method.method_descriptor}"


def _caller_id(*parts: str) -> str:
    return "btcaller-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


def _evidence_step(
    method: MethodInfo,
    *,
    instruction_index: int | None,
    instruction_offset: int | None,
    reference_type: str,
    target_method: str,
    classification: str = "FACT",
    confidence: str = "high",
) -> dict[str, Any]:
    return {
        "dex_entry": method.dex_entry,
        "class_name": method.class_name,
        "class_name_normalized": method.class_name_normalized,
        "method_name": method.method_name,
        "method_descriptor": method.method_descriptor,
        "instruction_index": instruction_index,
        "instruction_offset": instruction_offset,
        "reference_type": reference_type,
        "target_method": target_method,
        "evidence_level": "dex_reference",
        "classification": classification,
        "confidence": confidence,
        "limitations": [CALLER_LIMITATION],
    }


def _invoke_matches_target(text: str, raw: str | None, needles: list[str]) -> bool:
    blob = f"{text} {raw or ''}"
    return any(n and n in blob for n in needles)


def _needles_for_target(target: MethodInfo | str) -> list[str]:
    if isinstance(target, MethodInfo):
        key = _method_key(target)
        return [
            key,
            f"{target.class_name}->{target.method_name}",
            f"->{target.method_name}(",
            f"{target.class_name_normalized}.{target.method_name}" if target.class_name_normalized else "",
        ]
    text = str(target)
    if "->" in text:
        name = text.split("->", 1)[1].split("(", 1)[0]
        return [text, f"->{name}(", name]
    return [text, f"->{text}("]


def find_direct_callers(
    target: MethodInfo | str,
    methods: Iterable[MethodInfo],
    *,
    max_callers: int,
) -> list[dict[str, Any]]:
    """Return exact DEX invoke callers of *target* (FACT). Multiple callers preserved."""
    needles = [n for n in _needles_for_target(target) if n]
    target_key = _method_key(target) if isinstance(target, MethodInfo) else str(target)
    target_name = (
        target.method_name if isinstance(target, MethodInfo) else target_key.split("->")[-1].split("(")[0]
    )
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for method in methods:
        if method.is_external or not method.instructions:
            continue
        # Do not treat the target method body as a caller of itself via internal invokes.
        if isinstance(target, MethodInfo) and _method_key(method) == target_key:
            continue
        for ins in method.instructions:
            if not ins.opcode.startswith("invoke"):
                continue
            raw = (ins.referenced_method or {}).get("raw")
            if not _invoke_matches_target(ins.text, raw, needles):
                continue
            # Prefer method-name token to reduce false positives on shared prefixes.
            if target_name and f"->{target_name}(" not in ins.text and (
                raw is None or f"->{target_name}(" not in raw
            ):
                continue
            source = _method_key(method)
            target_raw = raw or target_key
            dedupe = f"{source}|{target_raw}|{ins.index}"
            if dedupe in seen:
                continue
            seen.add(dedupe)
            results.append(
                {
                    "caller_id": _caller_id(source, target_raw, str(ins.index)),
                    "method": source,
                    "class_name": method.class_name,
                    "class_name_normalized": method.class_name_normalized,
                    "method_name": method.method_name,
                    "method_descriptor": method.method_descriptor,
                    "dex_entry": method.dex_entry,
                    "target_method": target_raw,
                    "depth": 1,
                    "classification": "FACT",
                    "confidence": "high",
                    "evidence_level": "dex_reference",
                    "evidence": _evidence_step(
                        method,
                        instruction_index=ins.index,
                        instruction_offset=ins.offset,
                        reference_type=ins.opcode,
                        target_method=target_raw,
                    ),
                    "limitations": [CALLER_LIMITATION],
                }
            )
            if len(results) >= max_callers:
                return results
    return results


def reconstruct_caller_paths(
    target: MethodInfo,
    methods: list[MethodInfo],
    *,
    caller_depth: int,
    max_callers: int,
) -> dict[str, Any]:
    """Bounded multi-hop caller reconstruction (depth capped; no unbounded recursion)."""
    depth_limit = max(0, min(int(caller_depth), 2))
    max_n = max(0, min(int(max_callers), 100))
    target_key = _method_key(target)
    if depth_limit == 0 or max_n == 0:
        return {
            "target": target_key,
            "caller_count": 0,
            "callers": [],
            "paths": [],
            "classification": "UNKNOWN",
            "confidence": "low",
            "limitations": ["Caller reconstruction disabled or depth=0."],
        }

    by_key = {_method_key(m): m for m in methods if not m.is_external}
    direct = find_direct_callers(target, methods, max_callers=max_n)
    all_callers: list[dict[str, Any]] = list(direct)
    paths: list[dict[str, Any]] = []

    for caller in direct:
        chain = [
            {
                "method": caller["method"],
                "classification": caller["classification"],
                "confidence": caller["confidence"],
                "depth": 1,
                "evidence": caller["evidence"],
            },
            {
                "method": target_key,
                "classification": "FACT",
                "confidence": "high",
                "depth": 0,
                "role": "target",
            },
        ]
        paths.append(
            {
                "path_id": _caller_id("path", caller["method"], target_key),
                "depth": 1,
                "chain": chain,
                "classification": "FACT",
                "confidence": "high",
                "runtime_execution_proven": False,
            }
        )

    # Depth-2: callers of direct callers (bounded).
    if depth_limit >= 2 and direct:
        remaining = max_n - len(all_callers)
        for parent in list(direct):
            if remaining <= 0:
                break
            parent_method = by_key.get(parent["method"])
            if parent_method is None:
                continue
            grandparents = find_direct_callers(parent_method, methods, max_callers=min(remaining, max_n))
            for gp in grandparents:
                gp = dict(gp)
                gp["depth"] = 2
                all_callers.append(gp)
                remaining -= 1
                paths.append(
                    {
                        "path_id": _caller_id("path", gp["method"], parent["method"], target_key),
                        "depth": 2,
                        "chain": [
                            {
                                "method": gp["method"],
                                "classification": "FACT",
                                "confidence": "high",
                                "depth": 2,
                                "evidence": gp["evidence"],
                            },
                            {
                                "method": parent["method"],
                                "classification": "FACT",
                                "confidence": "high",
                                "depth": 1,
                                "evidence": parent["evidence"],
                            },
                            {
                                "method": target_key,
                                "classification": "FACT",
                                "confidence": "high",
                                "depth": 0,
                                "role": "target",
                            },
                        ],
                        "classification": "FACT",
                        "confidence": "high",
                        "runtime_execution_proven": False,
                    }
                )
                if remaining <= 0:
                    break

    if not all_callers:
        classification = "UNKNOWN"
        confidence = "low"
    else:
        classification = "FACT"
        confidence = "high"

    return {
        "target": target_key,
        "target_class": target.class_name,
        "target_class_normalized": target.class_name_normalized,
        "target_method_name": target.method_name,
        "target_descriptor": target.method_descriptor,
        "dex_entry": target.dex_entry,
        "caller_count": len(all_callers),
        "callers": all_callers[:max_n],
        "paths": paths[:max_n],
        "classification": classification,
        "confidence": confidence,
        "limitations": [CALLER_LIMITATION, "Bounded caller depth only; no full APK call graph."],
    }


def summarize_caller_reconstruction(
    rec: dict[str, Any],
    *,
    max_callers_cap: int | None = None,
) -> dict[str, Any]:
    """Reduce broad caller lists into depth / duplicate / truncated summary."""
    callers = list(rec.get("callers") or [])
    paths = list(rec.get("paths") or [])
    direct = [c for c in callers if int(c.get("depth") or 0) == 1]
    depth2 = [c for c in callers if int(c.get("depth") or 0) == 2]

    unique_chains: list[dict[str, Any]] = []
    duplicate = 0
    seen_chain: set[tuple[str, ...]] = set()
    evidence_by_chain: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for path in paths:
        chain_methods = tuple(
            str(step.get("method") or "") for step in (path.get("chain") or []) if step.get("method")
        )
        if not chain_methods:
            continue
        ev = []
        for step in path.get("chain") or []:
            if step.get("evidence"):
                ev.append(step["evidence"])
        if chain_methods in seen_chain:
            duplicate += 1
            evidence_by_chain[chain_methods].extend(ev)
            continue
        seen_chain.add(chain_methods)
        evidence_by_chain[chain_methods] = list(ev)
        unique_chains.append(
            {
                "path_id": path.get("path_id"),
                "depth": path.get("depth"),
                "chain": list(chain_methods),
                "classification": path.get("classification"),
                "confidence": path.get("confidence"),
                "evidence": evidence_by_chain[chain_methods],
            }
        )

    cap = max_callers_cap if max_callers_cap is not None else None
    truncated = 0
    if cap is not None and int(rec.get("caller_count") or 0) >= cap:
        # Hit the reconstruction cap — additional callers may exist beyond retained set.
        truncated = max(0, int(rec.get("caller_count") or 0) - len({c.get("method") for c in callers}))
        if truncated == 0:
            truncated = max(0, int(rec.get("caller_count") or 0) - len(unique_chains))

    # Prefer primary chain: longest unique chain ending at target (depth-2 if present).
    primary = None
    if unique_chains:
        primary = sorted(unique_chains, key=lambda c: (-int(c.get("depth") or 0), c.get("path_id") or ""))[0]

    return {
        "target": rec.get("target"),
        "direct_callers": len({c.get("method") for c in direct}),
        "depth_1": len({c.get("method") for c in direct}),
        "depth_2": len({c.get("method") for c in depth2}),
        "duplicate": duplicate,
        "truncated": truncated,
        "unique_chains": len(unique_chains),
        "chains": unique_chains,
        "primary_chain": primary,
        "raw_caller_count": int(rec.get("caller_count") or 0),
        "classification": rec.get("classification"),
        "confidence": rec.get("confidence"),
    }


def prioritize_rfcomm_targets(
    hits_with_socket: list[tuple[Any, dict[str, Any]]],
) -> list[Any]:
    """Order RFCOMM hits: create+connect+streams > create+connect > create > other."""

    def score(item: tuple[Any, dict[str, Any]]) -> tuple[int, str]:
        hit, socket = item
        has_c = bool(socket.get("has_connect"))
        has_i = bool(socket.get("has_input_stream"))
        has_o = bool(socket.get("has_output_stream"))
        if has_c and has_i and has_o:
            tier = 0
        elif has_c:
            tier = 1
        else:
            tier = 2
        key = f"{hit.method.class_name}->{hit.method.method_name}"
        return (tier, key)

    ordered = sorted(hits_with_socket, key=score)
    return [h for h, _ in ordered]
