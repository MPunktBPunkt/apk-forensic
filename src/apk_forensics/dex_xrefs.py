"""Bounded static caller/callee candidate discovery via instruction scans."""

from __future__ import annotations

import hashlib
from typing import Any

from apk_forensics.dex_model_adapter import DexSession, MethodInfo, parse_method_ref
from apk_forensics.models import Classification, Confidence


XREF_LIMITATION = "Static reference only; runtime execution not established."


def _method_key(method: MethodInfo) -> str:
    return f"{method.class_name}->{method.method_name}{method.method_descriptor}"


def _xref_id(source: str, target: str, relationship: str) -> str:
    key = "|".join([source, relationship, target])
    return "xref-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def _is_external_target(session: DexSession, class_name: str | None, method_name: str | None) -> bool:
    if not class_name or not method_name:
        return False
    for method in session.methods:
        if method.is_external and method.class_name == class_name and method.method_name == method_name:
            return True
    # Framework / android.* without local body
    if class_name.startswith("Landroid/") or class_name.startswith("Ljava/"):
        # if no internal method body exists for this class+name, treat as external
        for method in session.methods:
            if (
                not method.is_external
                and method.class_name == class_name
                and method.method_name == method_name
                and method.code_present
            ):
                return False
        return True
    return False


def collect_callees(
    method: MethodInfo,
    session: DexSession,
    *,
    max_callees: int,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    source = _method_key(method)
    for ins in method.instructions:
        if not ins.opcode.startswith("invoke") or not ins.referenced_method:
            continue
        ref = ins.referenced_method
        raw = ref.get("raw") or ""
        if not raw or raw in seen:
            continue
        seen.add(raw)
        class_raw = None
        # reconstruct class descriptor if needed
        parsed = parse_method_ref(raw)
        class_name = None
        # Prefer descriptor form from raw
        m = raw.split("->", 1)[0] if "->" in raw else None
        class_name = m
        external = _is_external_target(session, class_name, parsed.get("method_name"))
        results.append(
            {
                "xref_id": _xref_id(source, raw, "callee"),
                "source_method": source,
                "target_method": raw,
                "relationship": "callee",
                "resolution": "external" if external else "exact",
                "is_external": external,
                "classification": Classification.FACT.value,
                "evidence_level": "xref_candidate",
                "confidence": Confidence.MEDIUM.value,
                "limitations": [XREF_LIMITATION],
                "instruction_index": ins.index,
                "dex_entry": method.dex_entry,
            }
        )
        if len(results) >= max_callees:
            break
    return results


def collect_callers(
    target: MethodInfo | str,
    session: DexSession,
    *,
    max_callers: int,
) -> list[dict[str, Any]]:
    """Find callers by scanning invoke instructions for the target method name/ref."""
    if isinstance(target, MethodInfo):
        target_name = target.method_name
        target_key = _method_key(target)
        needles = [
            f"->{target.method_name}(",
            target_key,
            f"{target.class_name}->{target.method_name}",
        ]
    else:
        target_name = target
        target_key = target
        needles = [target, f"->{target.split('->')[-1]}" if "->" in target else f"->{target}("]

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for method in session.methods:
        if method.is_external or not method.instructions:
            continue
        for ins in method.instructions:
            if not ins.opcode.startswith("invoke"):
                continue
            text = ins.text
            if not any(n in text for n in needles if n):
                continue
            # Prefer matching the method name token
            if target_name and f"->{target_name}(" not in text and target_name not in text:
                continue
            source = _method_key(method)
            target_raw = (ins.referenced_method or {}).get("raw") or target_key
            key = f"{source}|{target_raw}"
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "xref_id": _xref_id(source, target_raw, "caller"),
                    "source_method": source,
                    "target_method": target_raw,
                    "relationship": "caller",
                    "resolution": "exact",
                    "is_external": False,
                    "classification": Classification.FACT.value,
                    "evidence_level": "xref_candidate",
                    "confidence": Confidence.MEDIUM.value,
                    "limitations": [XREF_LIMITATION],
                    "instruction_index": ins.index,
                    "dex_entry": method.dex_entry,
                    "caller_class": method.class_name,
                    "caller_method": method.method_name,
                }
            )
            if len(results) >= max_callers:
                return results
    return results


def stream_collect_callers(
    dex_entries: list[tuple[str, bytes]],
    needles: list[str],
    *,
    max_callers: int,
) -> list[dict[str, Any]]:
    """Second-pass streaming caller scan without retaining all method bodies."""
    from apk_forensics.dex_model_adapter import stream_methods_with_instructions

    _units, method_iter, _warnings, _version = stream_methods_with_instructions(dex_entries)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    useful = [n for n in needles if n]
    for method in method_iter:
        for ins in method.instructions:
            if not ins.opcode.startswith("invoke"):
                continue
            if not any(n in ins.text for n in useful):
                continue
            source = _method_key(method)
            target_raw = (ins.referenced_method or {}).get("raw") or next(
                (n for n in useful if n in ins.text),
                useful[0],
            )
            key = f"{source}|{target_raw}"
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "xref_id": _xref_id(source, target_raw, "caller"),
                    "source_method": source,
                    "target_method": target_raw,
                    "relationship": "caller",
                    "resolution": "exact",
                    "is_external": False,
                    "classification": Classification.FACT.value,
                    "evidence_level": "xref_candidate",
                    "confidence": Confidence.MEDIUM.value,
                    "limitations": [XREF_LIMITATION],
                    "instruction_index": ins.index,
                    "dex_entry": method.dex_entry,
                    "caller_class": method.class_name,
                    "caller_method": method.method_name,
                }
            )
            if len(results) >= max_callers:
                return results
    return results


def build_xref_candidates(
    session: DexSession,
    contexts: list[dict[str, Any]],
    *,
    xref_depth: int,
    max_callers: int,
    max_callees: int,
    dex_entries: list[tuple[str, bytes]] | None = None,
) -> list[dict[str, Any]]:
    """Build bounded XREF candidates for methods that own DEX contexts.

    xref_depth:
      0 = only callees of matched methods (same-method references)
      1 = also callers of matched methods / referenced APIs
      2 = one additional hop from those callers/callees (still capped)
    """
    xref_depth = max(0, min(2, xref_depth))
    results: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    by_key = {_method_key(m): m for m in session.methods if not m.is_external}

    seed_methods: list[MethodInfo] = []
    for ctx in contexts:
        key = f"{ctx['class_name']}->{ctx['method_name']}{ctx['method_descriptor']}"
        method = by_key.get(key)
        if method and method not in seed_methods:
            seed_methods.append(method)

    for method in seed_methods:
        for item in collect_callees(method, session, max_callees=max_callees):
            if item["xref_id"] not in seen_ids:
                seen_ids.add(item["xref_id"])
                results.append(item)

    if xref_depth >= 1:
        needles: list[str] = []
        for method in seed_methods:
            needles.append(f"{method.class_name}->{method.method_name}")
            needles.append(f"->{method.method_name}(")
        needles.extend(
            [
                "createRfcommSocketToServiceRecord",
                "createInsecureRfcommSocketToServiceRecord",
                "fetchUuidsWithSdp",
                "BluetoothSocket;->connect",
            ]
        )
        if dex_entries is not None:
            for item in stream_collect_callers(
                dex_entries,
                needles,
                max_callers=max_callers * max(1, len(seed_methods)),
            ):
                if item["xref_id"] not in seen_ids:
                    seen_ids.add(item["xref_id"])
                    results.append(item)
        else:
            for method in seed_methods:
                for item in collect_callers(method, session, max_callers=max_callers):
                    if item["xref_id"] not in seen_ids:
                        seen_ids.add(item["xref_id"])
                        results.append(item)

    if xref_depth >= 2:
        caller_methods = []
        for item in list(results):
            if item["relationship"] != "caller":
                continue
            source = item["source_method"]
            method = by_key.get(source)
            if method:
                caller_methods.append(method)
        for method in caller_methods[:max_callers]:
            for item in collect_callees(method, session, max_callees=max_callees):
                if item["xref_id"] not in seen_ids:
                    seen_ids.add(item["xref_id"])
                    results.append(item)

    results.sort(
        key=lambda x: (
            x.get("relationship") or "",
            x.get("source_method") or "",
            x.get("target_method") or "",
            x.get("xref_id") or "",
        )
    )
    return results
