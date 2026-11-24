"""Match shallow findings / queries against DEX instruction contexts."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable

from apk_forensics.dex_model_adapter import DexSession, MethodInfo, method_window
from apk_forensics.models import Finding


HIGH_PRIORITY_METHOD_NAMES = {
    "createRfcommSocketToServiceRecord",
    "createInsecureRfcommSocketToServiceRecord",
    "fetchUuidsWithSdp",
    "getUuids",
    "connect",  # only with BluetoothSocket context
    "getInputStream",
    "getOutputStream",
}

HIGH_PRIORITY_VALUES = {
    "createRfcommSocketToServiceRecord",
    "createInsecureRfcommSocketToServiceRecord",
    "fetchUuidsWithSdp",
    "getUuids",
    "android.bluetooth.BluetoothDevice",
    "android.bluetooth.BluetoothSocket",
    "android.bluetooth.BluetoothAdapter",
    "android.bluetooth.BluetoothGatt",
    "android.bluetooth.BluetoothGattCharacteristic",
    "00001101-0000-1000-8000-00805f9b34fb",
    "getInputStream",
    "getOutputStream",
}

MEDIUM_PRIORITY_VALUES = {
    "BCL",
    "RHMI",
    "Etch",
    "SAS",
    "CDS",
    "AV",
    "4004",
    "5001",
    "InputStream",
    "OutputStream",
    "java.nio.ByteBuffer",
    "java.net.Socket",
}


@dataclass
class MatchQuery:
    value: str
    kind: str
    finding_ids: list[str] = field(default_factory=list)
    category: str | None = None
    priority_hint: str | None = None


@dataclass
class DexMatch:
    method: MethodInfo
    instruction_index: int
    match_type: str
    matched_value: str
    query: MatchQuery
    priority: str
    priority_score: int
    priority_reasons: list[str]


def _stable_context_id(
    *,
    dex_entry: str,
    class_name: str,
    method_name: str,
    descriptor: str,
    match_type: str,
    matched_value: str,
    instruction_index: int,
) -> str:
    key = "|".join(
        [
            dex_entry,
            class_name,
            method_name,
            descriptor,
            match_type,
            matched_value,
            str(instruction_index),
        ]
    )
    return "dexctx-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def prioritize_value(value: str, *, kind: str | None = None, instruction_text: str = "") -> tuple[str, int, list[str]]:
    reasons: list[str] = []
    score = 10
    priority = "low"
    lower = value.lower()

    if value in HIGH_PRIORITY_VALUES or lower in {v.lower() for v in HIGH_PRIORITY_VALUES}:
        priority = "high"
        score = 90
        reasons.append("high-priority transport/API candidate")
    if "createRfcommSocketToServiceRecord" in value or "createRfcommSocketToServiceRecord" in instruction_text:
        priority = "high"
        score = max(score, 95)
        reasons.append("exact RFCOMM method reference")
    if "00001101-0000-1000-8000-00805f9b34fb" in lower:
        priority = "high"
        score = max(score, 92)
        reasons.append("SPP UUID")
    if "BluetoothSocket;->connect" in instruction_text or (
        value == "connect" and "BluetoothSocket" in instruction_text
    ):
        priority = "high"
        score = max(score, 93)
        reasons.append("BluetoothSocket.connect reference")
    if any(value == v or value.lower() == v.lower() for v in MEDIUM_PRIORITY_VALUES):
        if priority != "high":
            priority = "medium"
            score = max(score, 55)
        reasons.append("medium-priority profile/network candidate")
    if kind == "api" and priority == "low":
        priority = "medium"
        score = max(score, 40)
        reasons.append("API finding")
    if not reasons:
        reasons.append("generic candidate")
    return priority, score, reasons


def select_queries_from_findings(
    findings: Iterable[Finding],
    *,
    finding_id: str | None = None,
    query: str | None = None,
    category: str | None = None,
    kind: str | None = None,
    include_unmatched: bool = False,
    max_queries: int = 200,
) -> list[MatchQuery]:
    selected: dict[str, MatchQuery] = {}
    for finding in findings:
        if finding_id and finding.id != finding_id and finding.display_id != finding_id:
            continue
        if category and finding.category != category and (finding.subcategory or "") != category:
            continue
        if kind and finding.kind != kind:
            continue
        if query and query.lower() not in finding.value.lower() and query.lower() not in finding.normalized_value.lower():
            continue
        # Skip very generic low-value tokens unless explicitly queried
        if finding.value in {"connect", "close"} and not query and not finding_id:
            if "bluetooth" not in (finding.category or "").lower() and "bluetooth" not in (finding.subcategory or "").lower():
                continue
        key = finding.normalized_value.lower()
        if key not in selected:
            selected[key] = MatchQuery(
                value=finding.value,
                kind=finding.kind,
                finding_ids=[finding.id],
                category=finding.category,
            )
        else:
            selected[key].finding_ids.append(finding.id)
        if len(selected) >= max_queries:
            break

    # Always include high-priority seeds for dex-context runs unless filtered tightly
    if not finding_id and not query and not kind:
        for seed in sorted(HIGH_PRIORITY_VALUES):
            key = seed.lower()
            if key not in selected:
                selected[key] = MatchQuery(value=seed, kind="api", finding_ids=[], priority_hint="high")

    queries = list(selected.values())
    if include_unmatched:
        return queries
    return queries


def _match_type_for_instruction(ins_text: str, opcode: str, value: str) -> str | None:
    lower_val = value.lower()
    lower_text = ins_text.lower()
    short_token = len(value) <= 3

    # Short tokens (AV, SAS, CDS, ...) are string-only to avoid class/method substring noise.
    if short_token:
        if opcode.startswith("const-string") and (
            f'"{value}"' in ins_text or f'"{value}"' in ins_text.replace("\\", "")
            or referenced_string_equals(ins_text, value)
        ):
            return "string"
        return None

    if lower_val not in lower_text and value not in ins_text:
        if not (opcode.startswith("invoke") and value in ins_text):
            return None
    if opcode.startswith("invoke") and (
        f"->{value}(" in ins_text
        or f"->{value} (" in ins_text
        or (value in HIGH_PRIORITY_METHOD_NAMES and f"->{value}" in ins_text)
    ):
        return "method_reference"
    if opcode.startswith("const-string") and lower_val in lower_text:
        return "string"
    if opcode in {"new-instance", "check-cast", "const-class"} and value.replace(".", "/") in ins_text.replace(".", "/"):
        return "class_reference"
    if opcode.startswith(("iget", "iput", "sget", "sput")) and value in ins_text:
        return "field_reference"
    if value.lower() in lower_text:
        if opcode.startswith("invoke") and f"->{value}" in ins_text:
            return "method_reference"
        if opcode.startswith("const-string"):
            return "string"
        return None
    return None


def referenced_string_equals(ins_text: str, value: str) -> bool:
    import re

    m = re.search(r'"((?:\\.|[^"\\])*)"', ins_text)
    if not m:
        return False
    return m.group(1) == value


def _match_method_against_queries(method: MethodInfo, ordered_queries: list[MatchQuery]) -> list[DexMatch]:
    found: list[DexMatch] = []
    if method.is_external or not method.instructions:
        return found
    for ins in method.instructions:
        for query in ordered_queries:
            if query.value == "connect" and "BluetoothSocket" not in ins.text:
                continue
            if query.value in {"InputStream", "OutputStream"} and not (
                ins.opcode.startswith("invoke") or "Ljava/io/" in ins.text
            ):
                if query.value not in ins.text:
                    continue
            match_type = _match_type_for_instruction(ins.text, ins.opcode, query.value)
            if not match_type:
                continue
            if query.kind == "uuid" or re.fullmatch(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                query.value,
            ):
                if query.value.lower() not in ins.text.lower():
                    continue
                match_type = "string" if ins.opcode.startswith("const-string") else match_type
            priority, score, reasons = prioritize_value(
                query.value,
                kind=query.kind,
                instruction_text=ins.text,
            )
            if match_type == "method_reference":
                score = min(100, score + 5)
                reasons.append("exact method reference")
            found.append(
                DexMatch(
                    method=method,
                    instruction_index=ins.index,
                    match_type=match_type,
                    matched_value=query.value,
                    query=query,
                    priority=priority,
                    priority_score=score,
                    priority_reasons=reasons,
                )
            )
            break
    return found


def find_dex_matches(
    session: DexSession,
    queries: list[MatchQuery],
    *,
    max_results: int = 100,
) -> list[DexMatch]:
    ordered_queries = sorted(queries, key=lambda q: len(q.value), reverse=True)
    matches: list[DexMatch] = []
    for method in session.methods:
        matches.extend(_match_method_against_queries(method, ordered_queries))
        if len(matches) >= max_results * 5:
            break
    matches.sort(
        key=lambda m: (
            -m.priority_score,
            m.method.dex_entry,
            m.method.class_name,
            m.method.method_name,
            m.instruction_index,
            m.matched_value,
        )
    )
    return matches[:max_results]


def stream_find_dex_matches(
    dex_entries: list[tuple[str, bytes]],
    queries: list[MatchQuery],
    *,
    max_results: int = 100,
) -> tuple[list, list[DexMatch], list[str], str, int]:
    """Memory-safe streaming match: keep instructions only for matched methods."""
    from apk_forensics.dex_model_adapter import stream_methods_with_instructions

    units, method_iter, warnings, version = stream_methods_with_instructions(dex_entries)
    # Prefer longer and high-priority seeds first within each instruction.
    ordered_queries = sorted(
        queries,
        key=lambda q: (
            0 if (q.priority_hint == "high" or q.value in HIGH_PRIORITY_VALUES) else 1,
            -len(q.value),
            q.value,
        ),
    )
    matches: list[DexMatch] = []
    indexed = 0
    high_count = 0

    for method in method_iter:
        indexed += 1
        method_matches = _match_method_against_queries(method, ordered_queries)
        if not method_matches:
            continue
        for match in method_matches:
            match.method = method
            matches.append(match)
            if match.priority == "high":
                high_count += 1
        # Stop early only once we have enough high-priority hits, or a hard safety cap.
        if high_count >= max_results and len(matches) >= max_results:
            break
        if len(matches) >= max(max_results * 20, 500):
            break

    matches.sort(
        key=lambda m: (
            -m.priority_score,
            m.method.dex_entry,
            m.method.class_name,
            m.method.method_name,
            m.instruction_index,
            m.matched_value,
        )
    )
    trimmed = matches[:max_results]
    return units, trimmed, warnings, version, indexed


def collect_method_symbols(method: MethodInfo, around_index: int | None = None, window: int = 8) -> dict[str, list[str]]:
    methods: set[str] = set()
    classes: set[str] = set()
    fields: set[str] = set()
    strings: set[str] = set()
    if around_index is None:
        instructions = method.instructions
    else:
        start = max(0, around_index - window)
        end = min(len(method.instructions), around_index + window + 1)
        instructions = method.instructions[start:end]
    for ins in instructions:
        if ins.referenced_method and ins.referenced_method.get("raw"):
            methods.add(str(ins.referenced_method["raw"]))
        if ins.referenced_class:
            classes.add(ins.referenced_class)
        if ins.referenced_field:
            fields.add(ins.referenced_field)
        if ins.referenced_string is not None:
            strings.add(ins.referenced_string)
    return {
        "methods": sorted(methods),
        "classes": sorted(classes),
        "fields": sorted(fields),
        "strings": sorted(strings),
    }


def make_context_id(match: DexMatch) -> str:
    return _stable_context_id(
        dex_entry=match.method.dex_entry,
        class_name=match.method.class_name,
        method_name=match.method.method_name,
        descriptor=match.method.method_descriptor,
        match_type=match.match_type,
        matched_value=match.matched_value,
        instruction_index=match.instruction_index,
    )
