"""v1.6 Static ↔ Runtime ↔ Wire evidence correlation (offline, bounded).

Does not invent protocol semantics. Strength is discrete and rule-based.
Missing external evidence → UNKNOWN / NO_EXTERNAL_EVIDENCE — never simulated.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from apk_forensics.runtime_wire_evidence import (
    DIRECTION_IN,
    DIRECTION_OUT,
    DIRECTION_UNKNOWN,
    app_direction,
    load_runtime_evidence,
    load_static_evidence_from_application_flow,
    load_wire_evidence,
)

STRENGTH_EXACT = "EXACT"
STRENGTH_STRONG = "STRONG"
STRENGTH_MODERATE = "MODERATE"
STRENGTH_WEAK = "WEAK"
STRENGTH_AMBIGUOUS = "AMBIGUOUS"
STRENGTH_NONE = "NONE"
STRENGTH_UNKNOWN = "UNKNOWN"

RESULT_MATCH_CONFIRMED = "MATCH_CONFIRMED"
RESULT_MATCH_CORRELATED = "MATCH_CORRELATED"
RESULT_MATCH_AMBIGUOUS = "MATCH_AMBIGUOUS"
RESULT_NO_MATCH = "NO_MATCH"
RESULT_REJECTED = "REJECTED"
RESULT_UNKNOWN = "UNKNOWN"

CLASS_CORRELATION = "CORRELATION"
CLASS_INFERENCE = "INFERENCE"
CLASS_UNKNOWN = "UNKNOWN"
CLASS_REJECTED = "REJECTED"
CLASS_FACT = "FACT"

NEGATIVE_PATHS = {
    "PATH-000009",
    "PATH-000010",
    "PATH-000011",
    "PATH-000012",
    "PATH-000013",
}

KEY_STRENGTH = {
    "method_identity": "STRONG",
    "exact_bytes": "EXACT",
    "byte_prefix": "STRONG",
    "length": "WEAK",
    "timestamp_window": "MODERATE",
    "direction": "MODERATE",
    "socket_id": "STRONG",
    "stream_id": "STRONG",
    "method_name_only": "WEAK",
    "value_id": "STRONG",
    "field_identity": "MODERATE",
    "sequence": "MODERATE",
}


def estimate_correlation_work(
    *,
    static_count: int,
    runtime_count: int,
    wire_count: int,
    max_runtime_events: int,
    max_wire_packets: int,
    max_correlations: int,
    timestamp_window_ms: int,
) -> dict[str, Any]:
    """Preflight estimate — indexed lookups, not unbounded pairwise."""
    rt = min(runtime_count, max_runtime_events)
    wr = min(wire_count, max_wire_packets)
    st = static_count
    # Indexed: per-event method bucket + length bucket + time bucket probes
    probes = rt * 3 + wr * 3 + st
    memory_mb = 8 + (rt + wr + st) // 50 + (probes // 500)
    runtime_seconds = 1 + (probes // 2000) + (max_correlations // 100)
    risk = "ok"
    reasons = [
        f"static={st}",
        f"runtime_capped={rt}/{runtime_count}",
        f"wire_capped={wr}/{wire_count}",
        f"timestamp_window_ms={timestamp_window_ms}",
        "strategy=indexed_buckets_not_cartesian",
    ]
    if runtime_count > max_runtime_events or wire_count > max_wire_packets:
        risk = "warning"
        reasons.append("input exceeds plan caps; surplus ignored")
    if probes > 50_000:
        risk = "warning"
        reasons.append(f"high probe count={probes}")
    if probes > 500_000:
        risk = "reject"
        reasons.append("probe count exceeds hard bound")
    return {
        "memory_mb": int(memory_mb),
        "runtime_seconds": int(runtime_seconds),
        "probes": int(probes),
        "risk": risk,
        "reasons": reasons,
        "max_correlations": max_correlations,
    }


def _method_short(method: str | None) -> str | None:
    if not method:
        return None
    if "->" in method:
        return method.split("->", 1)[1]
    return method


def _in_window(a: int | None, b: int | None, window_ms: int) -> bool:
    if a is None or b is None:
        return False
    return abs(int(a) - int(b)) <= int(window_ms)


def _bytes_relation(a: str | None, b: str | None) -> str:
    if not a or not b:
        return "none"
    if a == b:
        return "exact"
    if a.startswith(b) or b.startswith(a):
        return "prefix"
    # containment / overlap for fragmentation
    if a in b or b in a:
        return "partial"
    return "mismatch"


def _score_keys(keys: list[str]) -> str:
    if not keys:
        return STRENGTH_NONE
    keyset = set(keys)
    # Without byte identity, length / name / time / direction alone stay WEAK
    # (insufficient for a positive correlation claim).
    weak_only = {"length", "method_name_only", "timestamp_window", "direction"}
    if keyset and keyset <= weak_only:
        return STRENGTH_WEAK
    # exact bytes elevates when combined with identity or time
    if "exact_bytes" in keyset and (
        "method_identity" in keyset or "socket_id" in keyset or "stream_id" in keyset
    ):
        return STRENGTH_EXACT
    if "exact_bytes" in keyset and "timestamp_window" in keyset:
        return STRENGTH_EXACT
    if "exact_bytes" in keyset or "byte_prefix" in keyset:
        return STRENGTH_STRONG
    if "method_identity" in keyset and "timestamp_window" in keyset and "direction" in keyset:
        return STRENGTH_STRONG if "length" in keyset else STRENGTH_MODERATE
    if "method_identity" in keyset and ("length" in keyset or "timestamp_window" in keyset or "field_identity" in keyset):
        return STRENGTH_MODERATE
    if "method_identity" in keyset or "value_id" in keyset:
        return STRENGTH_MODERATE
    if "socket_id" in keyset or "stream_id" in keyset:
        return STRENGTH_STRONG if "timestamp_window" in keyset else STRENGTH_MODERATE
    return STRENGTH_WEAK


def _classify_from_strength(strength: str, *, rejected: bool = False) -> tuple[str, str]:
    if rejected:
        return RESULT_REJECTED, CLASS_REJECTED
    if strength == STRENGTH_EXACT:
        return RESULT_MATCH_CONFIRMED, CLASS_CORRELATION
    if strength in {STRENGTH_STRONG, STRENGTH_MODERATE}:
        return RESULT_MATCH_CORRELATED, CLASS_CORRELATION
    if strength == STRENGTH_AMBIGUOUS:
        return RESULT_MATCH_AMBIGUOUS, CLASS_INFERENCE
    if strength == STRENGTH_WEAK:
        # weak alone never becomes a positive correlation claim
        return RESULT_NO_MATCH, CLASS_REJECTED
    if strength == STRENGTH_UNKNOWN:
        return RESULT_UNKNOWN, CLASS_UNKNOWN
    return RESULT_NO_MATCH, CLASS_UNKNOWN


def correlate_static_runtime(
    static: dict[str, Any],
    runtime: dict[str, Any],
    *,
    timestamp_window_ms: int = 50,
    max_correlations: int = 500,
) -> list[dict[str, Any]]:
    events = list(runtime.get("events") or [])
    values = list(static.get("values") or [])
    if not events:
        # Preserve one UNKNOWN stub per static value when external runtime is missing/empty.
        return [
            {
                "id": f"SR-{v.get('id')}-NONE",
                "link_type": "STATIC_RUNTIME_LINK",
                "static_id": v.get("id"),
                "static_method": v.get("method"),
                "runtime_id": None,
                "correlation_keys": [],
                "correlation_rule": "no_runtime_evidence",
                "strength": STRENGTH_UNKNOWN,
                "result": RESULT_UNKNOWN,
                "classification": CLASS_UNKNOWN,
                "protocol_semantics": "UNKNOWN",
                "notes": [
                    "NO_EXTERNAL_EVIDENCE"
                    if runtime.get("status") == "INPUT_MISSING"
                    else "runtime_evidence_empty"
                ],
            }
            for v in values[:max_correlations]
        ]

    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_value: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev.get("method"):
            by_method[str(ev["method"])].append(ev)
            short = _method_short(str(ev["method"]))
            if short:
                by_name[short].append(ev)
        if ev.get("method_name"):
            by_name[str(ev["method_name"])].append(ev)
        if ev.get("value_id"):
            by_value[str(ev["value_id"])].append(ev)

    out: list[dict[str, Any]] = []
    for val in static.get("values") or []:
        if len(out) >= max_correlations:
            break
        candidates: list[dict[str, Any]] = []
        vid = val.get("id")
        if vid and vid in by_value:
            for ev in by_value[vid]:
                candidates.append(_sr_link(val, ev, keys=["value_id", "method_identity"] if ev.get("method") == val.get("method") else ["value_id"]))
        method = val.get("method")
        api = val.get("source_api")
        for m in {method, api}:
            if not m:
                continue
            for ev in by_method.get(str(m), []):
                keys = ["method_identity"]
                if ev.get("timestamp_ms") is not None:
                    keys.append("timestamp_window")  # presence only; static has no time — see note
                if ev.get("field") and val.get("field") and ev.get("field") == val.get("field"):
                    keys.append("field_identity")
                if ev.get("bytes_hex"):
                    keys.append("exact_bytes")  # runtime observation only — still useful identity
                link = _sr_link(val, ev, keys=keys)
                # Static has no timestamp: timestamp_window alone is not claimed without explicit bridge
                if "timestamp_window" in keys and method:
                    link["notes"] = ["static has no timestamp; runtime method identity is primary key"]
                    link["correlation_keys"] = [k for k in keys if k != "timestamp_window"]
                    if not link["correlation_keys"]:
                        link["correlation_keys"] = ["method_identity"]
                    link["strength"] = _score_keys(link["correlation_keys"])
                    link["result"], link["classification"] = _classify_from_strength(link["strength"])
                candidates.append(link)
            short = _method_short(str(m))
            if short:
                for ev in by_name.get(short, []):
                    if ev.get("method") and ev.get("method") != m:
                        # same short name, different class — weak only
                        candidates.append(_sr_link(val, ev, keys=["method_name_only"], reject_weak=True))

        # Dedup by runtime id keeping strongest
        best_by_rt: dict[str, dict[str, Any]] = {}
        for c in candidates:
            rid = c["runtime_id"]
            prev = best_by_rt.get(rid)
            if prev is None or _strength_rank(c["strength"]) < _strength_rank(prev["strength"]):
                best_by_rt[rid] = c
        ranked = sorted(best_by_rt.values(), key=lambda x: (_strength_rank(x["strength"]), x["runtime_id"]))
        positive = [c for c in ranked if c["classification"] == CLASS_CORRELATION]
        if len(positive) > 1:
            # ambiguous if multiple EXACT/STRONG without distinguishing bytes
            top = positive[0]["strength"]
            peers = [c for c in positive if c["strength"] == top]
            if len(peers) > 1 and top in {STRENGTH_EXACT, STRENGTH_STRONG, STRENGTH_MODERATE}:
                for c in peers:
                    c["strength"] = STRENGTH_AMBIGUOUS
                    c["result"] = RESULT_MATCH_AMBIGUOUS
                    c["classification"] = CLASS_INFERENCE
                    c["notes"] = list(c.get("notes") or []) + ["multiple equally strong runtime candidates"]
                out.extend(peers)
                continue
        if ranked:
            out.append(ranked[0])
        else:
            out.append(
                {
                    "id": f"SR-{val.get('id')}-NONE",
                    "link_type": "STATIC_RUNTIME_LINK",
                    "static_id": val.get("id"),
                    "static_method": val.get("method"),
                    "runtime_id": None,
                    "correlation_keys": [],
                    "correlation_rule": "no_runtime_candidate",
                    "strength": STRENGTH_UNKNOWN,
                    "result": RESULT_UNKNOWN,
                    "classification": CLASS_UNKNOWN,
                    "protocol_semantics": "UNKNOWN",
                    "notes": ["NO_EXTERNAL_EVIDENCE for this value"] if not events else ["no method/value match"],
                }
            )
    return out[:max_correlations]


def _sr_link(
    val: dict[str, Any],
    ev: dict[str, Any],
    *,
    keys: list[str],
    reject_weak: bool = False,
) -> dict[str, Any]:
    strength = _score_keys(keys)
    rejected = reject_weak and strength == STRENGTH_WEAK
    result, classification = _classify_from_strength(strength, rejected=rejected)
    return {
        "id": f"SR-{val.get('id')}-{ev.get('id')}",
        "link_type": "STATIC_RUNTIME_LINK",
        "static_id": val.get("id"),
        "static_type": "STATIC_VALUE",
        "static_method": val.get("method"),
        "static_field": val.get("field"),
        "static_source": {"type": "STATIC_VALUE", "id": val.get("id")},
        "runtime_id": ev.get("id"),
        "runtime_type": ev.get("type"),
        "runtime_method": ev.get("method"),
        "runtime_timestamp_ms": ev.get("timestamp_ms"),
        "runtime_source": {
            "type": ev.get("type"),
            "id": ev.get("id"),
            "artifact": ev.get("source_artifact"),
        },
        "correlation_keys": list(keys),
        "correlation_rule": "+".join(keys) if keys else "none",
        "strength": strength,
        "result": result,
        "classification": classification,
        "protocol_semantics": "UNKNOWN",
        "notes": [],
    }


def correlate_runtime_wire(
    runtime: dict[str, Any],
    wire: dict[str, Any],
    *,
    timestamp_window_ms: int = 50,
    max_correlations: int = 500,
) -> list[dict[str, Any]]:
    events = list(runtime.get("events") or [])
    packets = list(wire.get("packets") or [])
    if not events or not packets:
        return []

    # Index packets by length, time bucket, hex
    by_len: dict[int, list[dict[str, Any]]] = defaultdict(list)
    by_hex: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_time: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for p in packets:
        if p.get("length") is not None:
            by_len[int(p["length"])].append(p)
        if p.get("bytes_hex"):
            by_hex[str(p["bytes_hex"])].append(p)
        if p.get("timestamp_ms") is not None:
            bucket = int(p["timestamp_ms"]) // max(timestamp_window_ms, 1)
            by_time[bucket].append(p)
            by_time[bucket - 1].append(p)
            by_time[bucket + 1].append(p)

    out: list[dict[str, Any]] = []
    for ev in events:
        if len(out) >= max_correlations:
            break
        etype = str(ev.get("type") or "")
        if etype not in {"RUNTIME_READ", "RUNTIME_WRITE", "RUNTIME_BUFFER", "RUNTIME_EVENT", "RUNTIME_METHOD"}:
            continue
        cand_map: dict[str, dict[str, Any]] = {}

        # Exact byte match
        if ev.get("bytes_hex") and ev["bytes_hex"] in by_hex:
            for p in by_hex[ev["bytes_hex"]]:
                keys = ["exact_bytes"]
                if _in_window(ev.get("timestamp_ms"), p.get("timestamp_ms"), timestamp_window_ms):
                    keys.append("timestamp_window")
                if _direction_compatible(ev, p):
                    keys.append("direction")
                elif _direction_conflict(ev, p):
                    cand_map[p["id"]] = _rw_link(ev, p, keys=["exact_bytes"], rejected=True, reason="direction_mismatch")
                    continue
                if ev.get("length") is not None and p.get("length") == ev.get("length"):
                    keys.append("length")
                cand_map[p["id"]] = _rw_link(ev, p, keys=keys)

        # Fragmentation: runtime bytes == concat of wire fragments
        if ev.get("bytes_hex") and ev.get("aggregate_of") is None:
            frag = _try_fragment_match(ev, packets, timestamp_window_ms)
            if frag:
                cand_map[frag["wire_id"]] = frag

        # Aggregation: multiple runtime reads → one wire block
        if ev.get("bytes_hex") is None and ev.get("aggregate_of"):
            pass  # handled via dedicated aggregation pass below

        # Length + time without bytes → WEAK / reject for positive claim
        if ev.get("length") is not None and not ev.get("bytes_hex"):
            for p in by_len.get(int(ev["length"]), []):
                if p["id"] in cand_map:
                    continue
                keys = ["length"]
                if _in_window(ev.get("timestamp_ms"), p.get("timestamp_ms"), timestamp_window_ms):
                    keys.append("timestamp_window")
                if _direction_compatible(ev, p):
                    keys.append("direction")
                elif _direction_conflict(ev, p):
                    cand_map[p["id"]] = _rw_link(ev, p, keys=keys, rejected=True, reason="direction_mismatch")
                    continue
                cand_map[p["id"]] = _rw_link(ev, p, keys=keys, reject_weak=True)

        # Byte mismatch with same length/time → REJECTED false positive
        if ev.get("bytes_hex") and ev.get("length") is not None:
            for p in by_len.get(int(ev["length"]), []):
                if p["id"] in cand_map:
                    continue
                rel = _bytes_relation(ev.get("bytes_hex"), p.get("bytes_hex"))
                if rel == "mismatch" and _in_window(ev.get("timestamp_ms"), p.get("timestamp_ms"), timestamp_window_ms):
                    cand_map[p["id"]] = _rw_link(
                        ev,
                        p,
                        keys=["length", "timestamp_window", "method_name_only"]
                        if ev.get("method_name")
                        else ["length", "timestamp_window"],
                        rejected=True,
                        reason="byte_mismatch_same_length_time",
                    )

        ranked = sorted(cand_map.values(), key=lambda x: (_strength_rank(x["strength"]), x["wire_id"]))
        positive = [c for c in ranked if c["classification"] == CLASS_CORRELATION]
        if len(positive) > 1:
            top = min(positive, key=lambda x: _strength_rank(x["strength"]))["strength"]
            peers = [c for c in positive if c["strength"] == top]
            if len(peers) > 1:
                for c in peers:
                    c["strength"] = STRENGTH_AMBIGUOUS
                    c["result"] = RESULT_MATCH_AMBIGUOUS
                    c["classification"] = CLASS_INFERENCE
                    c["notes"] = list(c.get("notes") or []) + ["multiple equally strong wire candidates"]
                out.extend(peers)
                continue
        if ranked:
            # prefer non-rejected
            preferred = [c for c in ranked if c["classification"] != CLASS_REJECTED] or ranked
            out.append(preferred[0])

    # Aggregation pass: wire packet composed of multiple runtime reads
    out.extend(_aggregation_links(events, packets, timestamp_window_ms, already=len(out), cap=max_correlations))
    return out[:max_correlations]


def _try_fragment_match(
    ev: dict[str, Any],
    packets: list[dict[str, Any]],
    window_ms: int,
) -> dict[str, Any] | None:
    target = ev.get("bytes_hex")
    if not target or len(target) < 4:
        return None
    # Greedy: ordered packets in time window whose concat equals target
    timed = [p for p in packets if p.get("bytes_hex") and _in_window(ev.get("timestamp_ms"), p.get("timestamp_ms"), window_ms * 3)]
    timed.sort(key=lambda p: (p.get("timestamp_ms") is None, p.get("timestamp_ms") or 0, p.get("id")))
    acc = ""
    used: list[dict[str, Any]] = []
    for p in timed:
        if not _direction_compatible(ev, p) and not (ev.get("app_direction") == DIRECTION_UNKNOWN or p.get("app_direction") == DIRECTION_UNKNOWN):
            if _direction_conflict(ev, p):
                continue
        nxt = acc + p["bytes_hex"]
        if target.startswith(nxt):
            acc = nxt
            used.append(p)
            if acc == target and len(used) >= 2:
                return {
                    "id": f"RW-{ev.get('id')}-FRAG",
                    "link_type": "RUNTIME_WIRE_LINK",
                    "runtime_id": ev.get("id"),
                    "wire_id": "+".join(p["id"] for p in used),
                    "wire_ids": [p["id"] for p in used],
                    "correlation_keys": ["exact_bytes", "timestamp_window", "direction"]
                    if all(_direction_compatible(ev, p) or p.get("app_direction") == DIRECTION_UNKNOWN for p in used)
                    else ["exact_bytes", "timestamp_window"],
                    "correlation_rule": "fragmentation_concat",
                    "strength": STRENGTH_EXACT,
                    "result": RESULT_MATCH_CONFIRMED,
                    "classification": CLASS_CORRELATION,
                    "protocol_semantics": "UNKNOWN",
                    "fragmentation": True,
                    "aggregation": False,
                    "byte_relation": "exact_via_fragments",
                    "notes": [f"runtime read equals {len(used)} wire fragments"],
                    "runtime_source": {"type": ev.get("type"), "id": ev.get("id")},
                    "wire_source": {"type": "WIRE_PACKET", "ids": [p["id"] for p in used]},
                }
        elif not target.startswith(nxt):
            # reset if first packet doesn't start match
            if not used:
                continue
            break
    return None


def _aggregation_links(
    events: list[dict[str, Any]],
    packets: list[dict[str, Any]],
    window_ms: int,
    *,
    already: int,
    cap: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    reads = [e for e in events if e.get("bytes_hex") and e.get("type") in {"RUNTIME_READ", "RUNTIME_BUFFER", "RUNTIME_EVENT"}]
    for p in packets:
        if already + len(out) >= cap:
            break
        target = p.get("bytes_hex")
        if not target or len(target) < 4:
            continue
        timed = [
            e
            for e in reads
            if _in_window(e.get("timestamp_ms"), p.get("timestamp_ms"), window_ms * 3)
            and not _direction_conflict(e, p)
        ]
        timed.sort(key=lambda e: (e.get("timestamp_ms") is None, e.get("timestamp_ms") or 0, e.get("id")))
        acc = ""
        used: list[dict[str, Any]] = []
        for e in timed:
            nxt = acc + e["bytes_hex"]
            if target.startswith(nxt):
                acc = nxt
                used.append(e)
                if acc == target and len(used) >= 2:
                    out.append(
                        {
                            "id": f"RW-AGG-{p.get('id')}",
                            "link_type": "RUNTIME_WIRE_LINK",
                            "runtime_id": "+".join(e["id"] for e in used),
                            "runtime_ids": [e["id"] for e in used],
                            "wire_id": p.get("id"),
                            "correlation_keys": ["exact_bytes", "timestamp_window"],
                            "correlation_rule": "aggregation_concat",
                            "strength": STRENGTH_EXACT,
                            "result": RESULT_MATCH_CONFIRMED,
                            "classification": CLASS_CORRELATION,
                            "protocol_semantics": "UNKNOWN",
                            "fragmentation": False,
                            "aggregation": True,
                            "byte_relation": "exact_via_aggregation",
                            "notes": [f"{len(used)} runtime reads compose one wire packet"],
                            "runtime_source": {"type": "RUNTIME_READ", "ids": [e["id"] for e in used]},
                            "wire_source": {"type": p.get("type"), "id": p.get("id")},
                        }
                    )
                    break
            elif used:
                break
    return out


def _direction_compatible(a: dict[str, Any], b: dict[str, Any]) -> bool:
    da = a.get("app_direction") or app_direction(a.get("direction"))
    db = b.get("app_direction") or app_direction(b.get("direction"))
    if da == DIRECTION_UNKNOWN or db == DIRECTION_UNKNOWN:
        return True
    return da == db


def _direction_conflict(a: dict[str, Any], b: dict[str, Any]) -> bool:
    da = a.get("app_direction") or app_direction(a.get("direction"))
    db = b.get("app_direction") or app_direction(b.get("direction"))
    if da in {DIRECTION_IN, DIRECTION_OUT} and db in {DIRECTION_IN, DIRECTION_OUT}:
        return da != db
    return False


def _rw_link(
    ev: dict[str, Any],
    p: dict[str, Any],
    *,
    keys: list[str],
    rejected: bool = False,
    reject_weak: bool = False,
    reason: str | None = None,
) -> dict[str, Any]:
    strength = _score_keys(keys)
    if rejected or (reject_weak and strength in {STRENGTH_WEAK, STRENGTH_NONE}):
        result, classification = RESULT_REJECTED, CLASS_REJECTED
        strength = STRENGTH_NONE if rejected else strength
    else:
        result, classification = _classify_from_strength(strength)
    notes = []
    if reason:
        notes.append(reason)
    return {
        "id": f"RW-{ev.get('id')}-{p.get('id')}",
        "link_type": "RUNTIME_WIRE_LINK",
        "runtime_id": ev.get("id"),
        "runtime_type": ev.get("type"),
        "wire_id": p.get("id"),
        "wire_type": p.get("type"),
        "correlation_keys": list(keys),
        "correlation_rule": "+".join(keys) if keys else "none",
        "strength": strength,
        "result": result,
        "classification": classification,
        "protocol_semantics": "UNKNOWN",
        "fragmentation": False,
        "aggregation": False,
        "byte_relation": _bytes_relation(ev.get("bytes_hex"), p.get("bytes_hex")),
        "runtime_direction": ev.get("direction"),
        "wire_direction": p.get("direction"),
        "notes": notes,
        "runtime_source": {"type": ev.get("type"), "id": ev.get("id"), "artifact": ev.get("source_artifact")},
        "wire_source": {"type": p.get("type"), "id": p.get("id"), "artifact": p.get("source_artifact")},
    }


def correlate_end_to_end(
    static_runtime: list[dict[str, Any]],
    runtime_wire: list[dict[str, Any]],
    *,
    max_correlations: int = 500,
) -> list[dict[str, Any]]:
    """Join SR and RW links on runtime id. Requires both sides CORRELATION (not WEAK-only)."""
    rw_by_rt: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for link in runtime_wire:
        if link.get("classification") not in {CLASS_CORRELATION}:
            continue
        rid = link.get("runtime_id")
        if rid and "+" not in str(rid):
            rw_by_rt[str(rid)].append(link)
        for rid2 in link.get("runtime_ids") or []:
            rw_by_rt[str(rid2)].append(link)

    out: list[dict[str, Any]] = []
    for sr in static_runtime:
        if len(out) >= max_correlations:
            break
        if sr.get("classification") != CLASS_CORRELATION:
            continue
        rid = sr.get("runtime_id")
        if not rid:
            continue
        for rw in rw_by_rt.get(str(rid), []):
            # Negative controls: never close PATH-009..013 via join alone
            static_id = str(sr.get("static_id") or "")
            if any(p in static_id for p in NEGATIVE_PATHS):
                out.append(
                    {
                        "id": f"E2E-{sr.get('id')}-{rw.get('id')}-NEG",
                        "link_type": "END_TO_END_CORRELATION",
                        "static_id": sr.get("static_id"),
                        "runtime_id": rid,
                        "wire_id": rw.get("wire_id"),
                        "strength": STRENGTH_NONE,
                        "result": RESULT_REJECTED,
                        "classification": CLASS_REJECTED,
                        "protocol_semantics": "UNKNOWN",
                        "correlation_keys": ["negative_control"],
                        "correlation_rule": "negative_path_guard",
                        "notes": ["CASE-F/D negative path must not gain e2e from correlation join"],
                        "static_runtime": sr.get("id"),
                        "runtime_wire": rw.get("id"),
                    }
                )
                continue
            keys = sorted(set((sr.get("correlation_keys") or []) + (rw.get("correlation_keys") or [])))
            # length/name alone across both still insufficient
            if set(keys) <= {"length", "method_name_only", "timestamp_window"}:
                strength = STRENGTH_WEAK
                result, classification = RESULT_REJECTED, CLASS_REJECTED
            else:
                strength = STRENGTH_EXACT if "exact_bytes" in keys and "method_identity" in keys else _score_keys(keys)
                if strength == STRENGTH_WEAK:
                    result, classification = RESULT_REJECTED, CLASS_REJECTED
                else:
                    result, classification = _classify_from_strength(strength)
            out.append(
                {
                    "id": f"E2E-{sr.get('static_id')}-{rid}-{rw.get('wire_id')}",
                    "link_type": "END_TO_END_CORRELATION",
                    "static_id": sr.get("static_id"),
                    "runtime_id": rid,
                    "wire_id": rw.get("wire_id"),
                    "correlation_keys": keys,
                    "correlation_rule": "static_runtime_wire_join",
                    "strength": strength,
                    "result": result,
                    "classification": classification,
                    "protocol_semantics": "UNKNOWN",
                    "byte_lineage": [
                        f"WIRE:{rw.get('wire_id')}",
                        f"RUNTIME:{rid}",
                        f"STATIC:{sr.get('static_id')}",
                    ],
                    "notes": [],
                    "static_runtime": sr.get("id"),
                    "runtime_wire": rw.get("id"),
                    "static_source": sr.get("static_source"),
                    "runtime_source": sr.get("runtime_source"),
                    "wire_source": rw.get("wire_source"),
                }
            )
    return out[:max_correlations]


def _strength_rank(s: str) -> int:
    order = [
        STRENGTH_EXACT,
        STRENGTH_STRONG,
        STRENGTH_MODERATE,
        STRENGTH_AMBIGUOUS,
        STRENGTH_WEAK,
        STRENGTH_NONE,
        STRENGTH_UNKNOWN,
    ]
    try:
        return order.index(s)
    except ValueError:
        return 99


def _count_strength(links: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for link in links:
        out[str(link.get("strength") or "UNKNOWN")] += 1
        out[f"class:{link.get('classification')}"] += 1
        out[f"result:{link.get('result')}"] += 1
    return dict(sorted(out.items()))


def build_answers(
    *,
    static: dict[str, Any],
    runtime: dict[str, Any],
    wire: dict[str, Any],
    sr: list[dict[str, Any]],
    rw: list[dict[str, Any]],
    e2e: list[dict[str, Any]],
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    baseline = baseline or {}
    sr_pos = [x for x in sr if x.get("classification") == CLASS_CORRELATION]
    rw_pos = [x for x in rw if x.get("classification") == CLASS_CORRELATION]
    e2e_pos = [x for x in e2e if x.get("classification") == CLASS_CORRELATION]
    frag = sum(1 for x in rw if x.get("fragmentation"))
    agg = sum(1 for x in rw if x.get("aggregation"))
    dir_clear = sum(
        1
        for x in rw_pos
        if x.get("runtime_direction") not in (None, DIRECTION_UNKNOWN)
        and x.get("wire_direction") not in (None, DIRECTION_UNKNOWN)
    )

    no_ext = runtime.get("status") == "INPUT_MISSING" and wire.get("status") == "INPUT_MISSING"

    return {
        "1_static_methods_correlated": sorted(
            {x.get("static_method") for x in sr_pos if x.get("static_method")}
        ),
        "2_values_with_runtime": sorted({x.get("static_id") for x in sr_pos if x.get("static_id")}),
        "3_strength_counts": _count_strength(sr + rw + e2e),
        "4_unknown_static_values": sorted(
            {
                v.get("id")
                for v in (static.get("values") or [])
                if v.get("id") not in {x.get("static_id") for x in sr_pos}
            }
        ),
        "5_runtime_wire_reads_writes": [x.get("id") for x in rw_pos],
        "6_fragmentation": frag > 0,
        "6_fragmentation_count": frag,
        "7_aggregation": agg > 0,
        "7_aggregation_count": agg,
        "8_directions_clear": dir_clear,
        "9_end_to_end_values": sorted({x.get("static_id") for x in e2e_pos if x.get("static_id")}),
        "10_byte_ranges_to_values": [
            {"static_id": x.get("static_id"), "wire_id": x.get("wire_id"), "lineage": x.get("byte_lineage")}
            for x in e2e_pos
        ],
        "11_field_runtime": sorted(
            {x.get("static_field") for x in sr_pos if x.get("static_field")}
        ),
        "12_branch_runtime": "UNKNOWN" if no_ext else "see runtime events with branch field",
        "13_state_runtime": "UNKNOWN" if no_ext else "see runtime events with state markers",
        "14_unknowns_promoted_to_correlation": [
            "execution observed (runtime method)" if sr_pos else None,
            "bytes on wire correlated to runtime I/O" if rw_pos else None,
            "static↔runtime↔wire join" if e2e_pos else None,
        ],
        "15_remain_unknown": [
            "protocol_semantics",
            "peer/HU identity (unless peer field present)",
            "request/response semantics",
            "message meaning",
        ],
        "16_semantic_evidence": False,
        "17_semantic_source": None,
        "18_correlation_ends": [
            "missing runtime/wire input" if no_ext else "join boundaries / caps",
            "WEAK keys alone (length/name/time)",
            "direction conflicts",
            "ambiguous equal-strength candidates",
        ],
        "19_analyzer_limits": [
            "max_runtime_events / max_wire_packets / max_correlations",
            "indexed bucket strategy (no full cartesian)",
            "timestamp_window_ms",
        ],
        "20_missing_external_only": no_ext,
        "21_false_positive_classes": [
            "length_only",
            "method_name_only",
            "timestamp_window_only",
            "byte_mismatch_same_length_time",
            "direction_mismatch",
        ],
        "22_new_limits": True,
        "baseline_v15_unchanged": {
            "catalog_values": baseline.get("catalog_values"),
            "field_stores": baseline.get("field_stores"),
            "field_loads": baseline.get("field_loads"),
            "parameters": baseline.get("parameters"),
            "returns": baseline.get("returns"),
            "branches": baseline.get("branches"),
            "state_mutations": baseline.get("state_mutations"),
            "collections": baseline.get("collections"),
            "roundtrip_candidates": baseline.get("roundtrip_candidates"),
            "path_comm": baseline.get("path_comm"),
            "max_field_hops": baseline.get("max_field_hops", 2),
            "note": "v1.6 references baseline; does not rewrite application-flow counts",
        },
        "protocol_semantics": "UNKNOWN",
        "external_status": {
            "runtime": runtime.get("status"),
            "wire": wire.get("status"),
            "no_external_evidence": no_ext,
        },
    }


def run_correlation(
    *,
    static_flow: dict[str, Any] | None,
    runtime_path: Path | None,
    wire_path: Path | None,
    baseline: dict[str, Any] | None = None,
    static_source: str | None = None,
    timestamp_window_ms: int = 50,
    max_runtime_events: int = 10_000,
    max_wire_packets: int = 10_000,
    max_correlations: int = 500,
    guard_memory_mb: int | None = None,
    allow_resource_warning: bool = False,
) -> dict[str, Any]:
    static = load_static_evidence_from_application_flow(static_flow, source=static_source)
    runtime = load_runtime_evidence(runtime_path)
    wire = load_wire_evidence(wire_path)

    # Cap inputs (plan/result limits)
    if len(runtime.get("events") or []) > max_runtime_events:
        runtime = dict(runtime)
        runtime["events"] = list(runtime["events"])[:max_runtime_events]
        runtime["truncated"] = True
    if len(wire.get("packets") or []) > max_wire_packets:
        wire = dict(wire)
        wire["packets"] = list(wire["packets"])[:max_wire_packets]
        wire["truncated"] = True

    estimate = estimate_correlation_work(
        static_count=int((static.get("counts") or {}).get("values") or 0),
        runtime_count=int((runtime.get("counts") or {}).get("events") or 0),
        wire_count=int((wire.get("counts") or {}).get("packets") or 0),
        max_runtime_events=max_runtime_events,
        max_wire_packets=max_wire_packets,
        max_correlations=max_correlations,
        timestamp_window_ms=timestamp_window_ms,
    )
    guard = {
        "estimate": estimate,
        "decision": "OK",
        "allow_resource_warning": allow_resource_warning,
    }
    if estimate["risk"] == "reject":
        guard["decision"] = "REJECT"
        return {
            "schema": "apk_forensics.correlation_run.v1",
            "guard": guard,
            "executed": False,
            "static": static,
            "runtime": {"status": runtime.get("status"), "counts": runtime.get("counts")},
            "wire": {"status": wire.get("status"), "counts": wire.get("counts")},
            "error": "resource_guard_reject",
        }
    if estimate["risk"] == "warning" and not allow_resource_warning:
        guard["decision"] = "WARNING_BLOCKED"
        return {
            "schema": "apk_forensics.correlation_run.v1",
            "guard": guard,
            "executed": False,
            "static": static,
            "runtime": {"status": runtime.get("status"), "counts": runtime.get("counts")},
            "wire": {"status": wire.get("status"), "counts": wire.get("counts")},
            "error": "resource_guard_warning",
        }
    if estimate["risk"] == "warning":
        guard["decision"] = "WARNING_ALLOWED"

    if guard_memory_mb is not None and estimate["memory_mb"] > guard_memory_mb:
        guard["decision"] = "REJECT"
        return {
            "schema": "apk_forensics.correlation_run.v1",
            "guard": guard,
            "executed": False,
            "error": "memory_cap",
        }

    sr = correlate_static_runtime(
        static, runtime, timestamp_window_ms=timestamp_window_ms, max_correlations=max_correlations
    )
    rw = correlate_runtime_wire(
        runtime, wire, timestamp_window_ms=timestamp_window_ms, max_correlations=max_correlations
    )
    e2e = correlate_end_to_end(sr, rw, max_correlations=max_correlations)
    answers = build_answers(
        static=static, runtime=runtime, wire=wire, sr=sr, rw=rw, e2e=e2e, baseline=baseline
    )

    return {
        "schema": "apk_forensics.correlation_run.v1",
        "guard": guard,
        "executed": True,
        "static": static,
        "runtime": runtime,
        "wire": wire,
        "static_runtime": sr,
        "runtime_wire": rw,
        "end_to_end": e2e,
        "counts": {
            "static_values": int((static.get("counts") or {}).get("values") or 0),
            "runtime_events": int((runtime.get("counts") or {}).get("events") or 0),
            "wire_packets": int((wire.get("counts") or {}).get("packets") or 0),
            "static_runtime": len(sr),
            "runtime_wire": len(rw),
            "end_to_end": len(e2e),
            "exact": sum(1 for x in sr + rw + e2e if x.get("strength") == STRENGTH_EXACT),
            "strong": sum(1 for x in sr + rw + e2e if x.get("strength") == STRENGTH_STRONG),
            "ambiguous": sum(1 for x in sr + rw + e2e if x.get("strength") == STRENGTH_AMBIGUOUS),
            "rejected": sum(1 for x in sr + rw + e2e if x.get("classification") == CLASS_REJECTED),
            "unknown": sum(1 for x in sr + rw + e2e if x.get("classification") == CLASS_UNKNOWN),
        },
        "answers": answers,
        "limits": {
            "timestamp_window_ms": timestamp_window_ms,
            "max_runtime_events": max_runtime_events,
            "max_wire_packets": max_wire_packets,
            "max_correlations": max_correlations,
            "max_field_hops": 2,
        },
    }


def write_correlation_reports(out_dir: Path, run: dict[str, Any]) -> dict[str, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    def dump(name: str, payload: dict[str, Any], md_lines: list[str]) -> None:
        jp = out_dir / f"{name}.json"
        mp = out_dir / f"{name}.md"
        jp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        mp.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
        written[name + ".json"] = jp
        written[name + ".md"] = mp

    counts = run.get("counts") or {}
    answers = run.get("answers") or {}
    sr = run.get("static_runtime") or []
    rw = run.get("runtime_wire") or []
    e2e = run.get("end_to_end") or []

    sr_report = {
        "schema": "apk_forensics.static_runtime_correlation_report.v1",
        "counts": counts,
        "links": sr,
        "answers_subset": {k: answers.get(k) for k in ("1_static_methods_correlated", "2_values_with_runtime", "3_strength_counts", "4_unknown_static_values")},
        "guard": run.get("guard"),
        "executed": run.get("executed"),
        "protocol_semantics": "UNKNOWN",
    }
    dump(
        "STATIC_RUNTIME_CORRELATION_REPORT",
        sr_report,
        [
            "# Static ↔ Runtime Correlation",
            "",
            f"- Executed: `{run.get('executed')}`",
            f"- Static values: `{counts.get('static_values')}`",
            f"- Runtime events: `{counts.get('runtime_events')}`",
            f"- Links: `{len(sr)}`",
            f"- Protocol semantics: `UNKNOWN`",
            "",
            "## Links",
            "",
            *[
                f"- `{x.get('id')}` strength=`{x.get('strength')}` class=`{x.get('classification')}` "
                f"keys=`{','.join(x.get('correlation_keys') or [])}`"
                for x in sr[:80]
            ],
        ],
    )

    rw_report = {
        "schema": "apk_forensics.runtime_wire_correlation_report.v1",
        "counts": counts,
        "links": rw,
        "answers_subset": {k: answers.get(k) for k in ("5_runtime_wire_reads_writes", "6_fragmentation", "7_aggregation", "8_directions_clear")},
        "protocol_semantics": "UNKNOWN",
    }
    dump(
        "RUNTIME_WIRE_CORRELATION_REPORT",
        rw_report,
        [
            "# Runtime ↔ Wire Correlation",
            "",
            f"- Wire packets: `{counts.get('wire_packets')}`",
            f"- Links: `{len(rw)}`",
            f"- Fragmentation: `{answers.get('6_fragmentation')}`",
            f"- Aggregation: `{answers.get('7_aggregation')}`",
            "",
            "## Links",
            "",
            *[
                f"- `{x.get('id')}` strength=`{x.get('strength')}` frag=`{x.get('fragmentation')}` "
                f"agg=`{x.get('aggregation')}` class=`{x.get('classification')}`"
                for x in rw[:80]
            ],
        ],
    )

    e2e_report = {
        "schema": "apk_forensics.end_to_end_correlation_report.v1",
        "counts": counts,
        "links": e2e,
        "answers_subset": {k: answers.get(k) for k in ("9_end_to_end_values", "10_byte_ranges_to_values")},
        "protocol_semantics": "UNKNOWN",
    }
    dump(
        "END_TO_END_CORRELATION_REPORT",
        e2e_report,
        [
            "# End-to-End Correlation (Static ↔ Runtime ↔ Wire)",
            "",
            f"- E2E links: `{len(e2e)}`",
            f"- Values: `{answers.get('9_end_to_end_values')}`",
            "",
            "## Links",
            "",
            *[
                f"- `{x.get('id')}` strength=`{x.get('strength')}` class=`{x.get('classification')}` "
                f"lineage=`{' → '.join(x.get('byte_lineage') or [])}`"
                for x in e2e[:80]
            ],
        ],
    )

    coverage = {
        "schema": "apk_forensics.correlation_coverage_report.v1",
        "static_with_runtime": len(answers.get("2_values_with_runtime") or []),
        "static_total": counts.get("static_values"),
        "runtime_with_wire": len(answers.get("5_runtime_wire_reads_writes") or []),
        "e2e_values": len(answers.get("9_end_to_end_values") or []),
        "external_status": answers.get("external_status"),
        "strength_counts": answers.get("3_strength_counts"),
        "limits": run.get("limits"),
        "negative_controls": sorted(NEGATIVE_PATHS),
    }
    dump(
        "CORRELATION_COVERAGE_REPORT",
        coverage,
        [
            "# Correlation Coverage",
            "",
            f"- Static with runtime: `{coverage['static_with_runtime']}` / `{coverage['static_total']}`",
            f"- Runtime↔wire positive links: `{coverage['runtime_with_wire']}`",
            f"- E2E values: `{coverage['e2e_values']}`",
            f"- External: `{coverage['external_status']}`",
        ],
    )

    table = []
    for group, links in (("static_runtime", sr), ("runtime_wire", rw), ("end_to_end", e2e)):
        for x in links:
            table.append(
                {
                    "group": group,
                    "id": x.get("id"),
                    "static_id": x.get("static_id"),
                    "runtime_id": x.get("runtime_id"),
                    "wire_id": x.get("wire_id"),
                    "keys": x.get("correlation_keys"),
                    "rule": x.get("correlation_rule"),
                    "strength": x.get("strength"),
                    "result": x.get("result"),
                    "classification": x.get("classification"),
                    "protocol_semantics": "UNKNOWN",
                }
            )
    table_path = out_dir / "CORRELATION_TABLE.json"
    table_path.write_text(json.dumps(table, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written["CORRELATION_TABLE.json"] = table_path

    forensic = {
        "schema": "apk_forensics.correlation_forensic_report.v1",
        "A_apk_proves": {
            "note": "Static FACT only — unchanged by correlation layer",
            "baseline": answers.get("baseline_v15_unchanged"),
            "static_counts": (run.get("static") or {}).get("counts"),
        },
        "B_apk_plus_external_correlate": {
            "static_runtime": [x for x in sr if x.get("classification") == CLASS_CORRELATION],
            "runtime_wire": [x for x in rw if x.get("classification") == CLASS_CORRELATION],
            "end_to_end": [x for x in e2e if x.get("classification") == CLASS_CORRELATION],
        },
        "C_still_unknown": answers.get("15_remain_unknown"),
        "answers": answers,
        "counts": counts,
        "guard": run.get("guard"),
        "protocol_semantics": "UNKNOWN",
        "peer_hu_identity": "UNKNOWN",
        "request_response_semantics": "UNKNOWN",
        "message_meaning": "UNKNOWN",
    }
    dump(
        "CORRELATION_FORENSIC_REPORT",
        forensic,
        [
            "# Correlation Forensic Report (v1.6)",
            "",
            "## A — APK proves (static FACT)",
            "",
            f"- Baseline catalog values: `{(answers.get('baseline_v15_unchanged') or {}).get('catalog_values')}`",
            f"- PATH-COMM: `{(answers.get('baseline_v15_unchanged') or {}).get('path_comm')}`",
            "",
            "## B — APK + Runtime/Wire correlate",
            "",
            f"- Static↔Runtime CORRELATION: `{sum(1 for x in sr if x.get('classification')==CLASS_CORRELATION)}`",
            f"- Runtime↔Wire CORRELATION: `{sum(1 for x in rw if x.get('classification')==CLASS_CORRELATION)}`",
            f"- End-to-end CORRELATION: `{sum(1 for x in e2e if x.get('classification')==CLASS_CORRELATION)}`",
            "",
            "## C — Still UNKNOWN",
            "",
            *[f"- {u}" for u in (answers.get("15_remain_unknown") or [])],
            "",
            "Protocol semantics, peer/HU identity, request/response, and message meaning remain UNKNOWN "
            "unless independent evidence elevates them (not done by correlation alone).",
        ],
    )

    # full run dump
    run_path = out_dir / "correlation_run.json"
    run_path.write_text(json.dumps(run, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written["correlation_run.json"] = run_path
    return written
