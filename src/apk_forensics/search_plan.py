"""Declarative SearchPlan: describes *what* to investigate, never *what was found*.

Frontends (CLI, YAML, GUI, future AI) all produce the same normalized SearchPlan.
The engine stays deterministic; the plan never invents evidence or classifications.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from apk_forensics import __version__
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ApkForensicsError, ExitCode

SEARCH_PLAN_SCHEMA_VERSION = "1.0"

SUPPORTED_MODULES = frozenset(
    {
        "manifest",
        "zip_inventory",
        "dex",
        "strings",
        "uuid",
        "candidate",
        "bluetooth",
        "dex_context",
        "xref",
        "native",
    }
)

KNOWN_API_PATTERNS = frozenset(
    {
        "bluetooth",
        "rfcomm",
        "usb",
        "network",
        "socket",
        "gatt",
        "android",
    }
)

ALLOWED_CLASSIFICATIONS = frozenset({"FACT", "CORRELATION", "INFERENCE", "UNKNOWN", "REJECTED"})

FORBIDDEN_KEYS = frozenset(
    {
        "exec",
        "python",
        "shell",
        "bash",
        "cmd",
        "command",
        "subprocess",
        "system",
        "eval",
        "execfile",
        "import",
        "__import__",
        "compile",
        "bytecode",
        "os.system",
        "popen",
        "run",
        "script",
        "code",
        "lambda",
    }
)

FORBIDDEN_OUTPUT_PATH_KEYS = frozenset(
    {
        "path",
        "paths",
        "directory",
        "dir",
        "file",
        "filename",
        "outdir",
        "output_dir",
        "output_path",
        "destination",
        "dest",
        "target",
        "write_to",
    }
)

# Hard caps — never unbounded even if a plan asks for more
LIMIT_BOUNDS = {
    "max_results": (1, 10_000),
    "max_contexts": (1, 10_000),
    "max_xrefs": (1, 5_000),
    "max_chains": (1, 500),
    "max_findings": (1, 50_000),
}

DEX_CONTEXT_BOUNDS = {
    "instruction_window": (0, 100),
    "xref_depth": (0, 2),
    "max_callers": (0, 500),
    "max_callees": (0, 500),
}

BLUETOOTH_BOUNDS = {
    "dataflow_depth": (0, 3),
    "window": (0, 100),
    "max_paths": (1, 500),
    "max_results": (1, 500),
    "caller_depth": (0, 2),
    "max_callers": (0, 100),
    "max_callees": (0, 100),
    "max_dataflow_paths": (0, 100),
    "max_dataflow_nodes": (0, 500),
    "max_method_hops": (0, 5),
    "max_field_hops": (0, 4),
    "max_object_nodes": (0, 500),
}

BLUETOOTH_BOOL_FIELDS = {
    "reconstruct_callers",
    "reconstruct_streams",
    "reconstruct_read_write",
    "interprocedural",
}

MAX_SEARCH_TERMS = 500
MAX_REGEX_PATTERNS = 100
MAX_REGEX_LENGTH = 256
MAX_UUIDS = 200
MAX_API_PATTERNS = 50


class PlanValidationError(ApkForensicsError):
    """SearchPlan failed validation — do not start a scan."""

    exit_code = ExitCode.INVALID_ARGS

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        msg = "PLAN INVALID\n" + "\n".join(f"- {e}" for e in self.errors)
        super().__init__(msg, exit_code=ExitCode.INVALID_ARGS)


@dataclass
class SearchPlan:
    """Normalized, validated analysis request (not a results document)."""

    schema_version: str
    plan_name: str
    plan_description: str
    modules: list[str]
    search_terms: list[str] = field(default_factory=list)
    search_regex: list[str] = field(default_factory=list)
    search_uuids: list[str] = field(default_factory=list)
    api_patterns: list[str] = field(default_factory=list)
    dex_context_enabled: bool = False
    instruction_window: int = 8
    xref_depth: int = 0
    max_callers: int = 20
    max_callees: int = 20
    bluetooth_enabled: bool = False
    bluetooth_dataflow_depth: int = 2
    bluetooth_window: int = 12
    bluetooth_max_paths: int = 50
    bluetooth_max_results: int = 100
    bluetooth_target: str | None = None
    bluetooth_caller_depth: int = 2
    bluetooth_reconstruct_callers: bool = True
    bluetooth_reconstruct_streams: bool = True
    bluetooth_reconstruct_read_write: bool = True
    bluetooth_max_callers: int = 50
    bluetooth_max_callees: int = 50
    bluetooth_max_dataflow_paths: int = 50
    bluetooth_max_dataflow_nodes: int = 200
    bluetooth_interprocedural: bool = False
    bluetooth_max_method_hops: int = 3
    bluetooth_max_field_hops: int = 2
    bluetooth_max_object_nodes: int = 500
    evidence_graph_enabled: bool = False
    evidence_graph_canonicalize: bool = True
    evidence_graph_deduplicate: bool = True
    evidence_graph_extract_paths: bool = True
    evidence_graph_include_boundaries: bool = True
    evidence_graph_max_paths: int = 50
    communication_enabled: bool = False
    communication_interprocedural: bool = True
    communication_max_method_hops: int = 3
    communication_max_field_hops: int = 2
    communication_max_object_nodes: int = 500
    communication_max_dataflow_paths: int = 100
    communication_max_buffer_hops: int = 5
    communication_max_parser_hops: int = 3
    communication_max_message_hops: int = 3
    evidence_classifications: list[str] = field(
        default_factory=lambda: ["FACT", "CORRELATION", "INFERENCE", "UNKNOWN"]
    )
    max_results: int = 100
    max_contexts: int = 100
    max_xrefs: int = 1000
    max_chains: int = 20
    max_findings: int = 10_000
    output_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    include_raw: bool = False
    profile_name: str | None = None
    profile_path: str | None = None
    plan_sha256: str = ""

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical representation used for hashing and plan show."""
        return {
            "schema_version": self.schema_version,
            "plan": {
                "name": self.plan_name,
                "description": self.plan_description,
                "modules": list(self.modules),
            },
            "search": {
                "terms": list(self.search_terms),
                "regex": list(self.search_regex),
                "uuids": list(self.search_uuids),
                "api_patterns": list(self.api_patterns),
            },
            "dex_context": {
                "enabled": self.dex_context_enabled,
                "instruction_window": self.instruction_window,
                "xref_depth": self.xref_depth,
                "max_callers": self.max_callers,
                "max_callees": self.max_callees,
            },
            "bluetooth": {
                "enabled": self.bluetooth_enabled,
                "dataflow_depth": self.bluetooth_dataflow_depth,
                "window": self.bluetooth_window,
                "max_paths": self.bluetooth_max_paths,
                "max_results": self.bluetooth_max_results,
                "target": self.bluetooth_target,
                "caller_depth": self.bluetooth_caller_depth,
                "reconstruct_callers": self.bluetooth_reconstruct_callers,
                "reconstruct_streams": self.bluetooth_reconstruct_streams,
                "reconstruct_read_write": self.bluetooth_reconstruct_read_write,
                "max_callers": self.bluetooth_max_callers,
                "max_callees": self.bluetooth_max_callees,
                "max_dataflow_paths": self.bluetooth_max_dataflow_paths,
                "max_dataflow_nodes": self.bluetooth_max_dataflow_nodes,
                "interprocedural": self.bluetooth_interprocedural,
                "max_method_hops": self.bluetooth_max_method_hops,
                "max_field_hops": self.bluetooth_max_field_hops,
                "max_object_nodes": self.bluetooth_max_object_nodes,
            },
            "evidence_graph": {
                "enabled": self.evidence_graph_enabled,
                "canonicalize": self.evidence_graph_canonicalize,
                "deduplicate": self.evidence_graph_deduplicate,
                "extract_paths": self.evidence_graph_extract_paths,
                "include_boundaries": self.evidence_graph_include_boundaries,
                "max_evidence_paths": self.evidence_graph_max_paths,
            },
            "communication": {
                "enabled": self.communication_enabled,
                "interprocedural": self.communication_interprocedural,
                "max_method_hops": self.communication_max_method_hops,
                "max_field_hops": self.communication_max_field_hops,
                "max_object_nodes": self.communication_max_object_nodes,
                "max_dataflow_paths": self.communication_max_dataflow_paths,
                "max_buffer_hops": self.communication_max_buffer_hops,
                "max_parser_hops": self.communication_max_parser_hops,
                "max_message_hops": self.communication_max_message_hops,
            },
            "evidence": {
                "classifications": list(self.evidence_classifications),
            },
            "limits": {
                "max_results": self.max_results,
                "max_contexts": self.max_contexts,
                "max_xrefs": self.max_xrefs,
                "max_chains": self.max_chains,
                "max_findings": self.max_findings,
            },
            "output": {
                "format": list(self.output_formats),
                "include_raw": self.include_raw,
            },
            "profile": {
                "name": self.profile_name,
                "path": self.profile_path,
            },
        }

    def to_report_section(self) -> dict[str, Any]:
        payload = self.to_canonical_dict()
        payload["plan_sha256"] = self.plan_sha256
        payload["note"] = (
            "SearchPlan describes an investigation request. "
            "It is not a results document and must not invent evidence."
        )
        return payload


def _collect_forbidden_keys(obj: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_l = str(key).lower().replace("-", "_")
            here = f"{path}.{key}" if path else str(key)
            if key_l in FORBIDDEN_KEYS or any(f in key_l for f in ("os.system", "subprocess")):
                errors.append(f"forbidden executable directive rejected: {here}")
            errors.extend(_collect_forbidden_keys(value, here))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            errors.extend(_collect_forbidden_keys(item, f"{path}[{i}]"))
    return errors


def _require_mapping(value: Any, name: str, errors: list[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.append(f"{name} must be a mapping")
        return {}
    return value


def _as_str_list(value: Any, name: str, errors: list[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{name} must be a list of strings")
        return []
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{name}[{i}] must be a non-empty string")
            continue
        out.append(item.strip())
    return out


def _as_bool(value: Any, name: str, errors: list[str], default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        errors.append(f"{name} must be a boolean")
        return default
    return value


def _as_int_in_bounds(
    value: Any,
    name: str,
    bounds: tuple[int, int],
    errors: list[str],
    default: int,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{name} must be an integer")
        return default
    lo, hi = bounds
    if value < lo or value > hi:
        errors.append(f"{name} must be between {lo} and {hi}")
        return default
    return value


def normalize_uuid(value: str) -> str:
    return str(uuid.UUID(value.strip())).lower()


def compute_plan_sha256(canonical: dict[str, Any]) -> str:
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_plan_yaml(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise PlanValidationError([f"plan file not found: {path}"])
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanValidationError([f"cannot read plan file: {exc}"]) from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PlanValidationError([f"invalid YAML: {exc}"]) from exc
    if data is None:
        raise PlanValidationError(["empty plan document"])
    if not isinstance(data, dict):
        raise PlanValidationError(["plan root must be a mapping"])
    return data


def validate_and_normalize(raw: dict[str, Any]) -> SearchPlan:
    errors: list[str] = []
    errors.extend(_collect_forbidden_keys(raw))

    # Reject unknown top-level keys (strict for AI/GUI safety)
    allowed_top = {
        "schema_version",
        "plan",
        "input",
        "search",
        "dex_context",
        "bluetooth",
        "evidence_graph",
        "communication",
        "evidence",
        "limits",
        "output",
        "profile",
    }
    for key in raw:
        if key not in allowed_top:
            errors.append(f"unknown field: {key}")

    schema_version = raw.get("schema_version")
    if schema_version is None:
        errors.append("missing schema_version")
    elif schema_version != SEARCH_PLAN_SCHEMA_VERSION:
        errors.append(f"unsupported schema_version: {schema_version!r} (expected {SEARCH_PLAN_SCHEMA_VERSION})")

    plan_sec = _require_mapping(raw.get("plan"), "plan", errors)
    plan_name = plan_sec.get("name")
    if not isinstance(plan_name, str) or not plan_name.strip():
        errors.append("plan.name is required")
        plan_name = ""
    else:
        plan_name = plan_name.strip()
    plan_description = plan_sec.get("description") or ""
    if plan_description is not None and not isinstance(plan_description, str):
        errors.append("plan.description must be a string")
        plan_description = ""
    else:
        plan_description = str(plan_description).strip()

    modules = _as_str_list(plan_sec.get("modules"), "plan.modules", errors)
    if not modules:
        errors.append("plan.modules must list at least one module")
    unknown_modules = sorted({m for m in modules if m not in SUPPORTED_MODULES})
    for m in unknown_modules:
        errors.append(f"unknown module: {m}")
    # Preserve first-seen order, drop dups
    seen_m: set[str] = set()
    modules_norm: list[str] = []
    for m in modules:
        if m in SUPPORTED_MODULES and m not in seen_m:
            seen_m.add(m)
            modules_norm.append(m)
    modules_norm = sorted(modules_norm)

    # input: descriptive only — no path ownership
    input_sec = _require_mapping(raw.get("input"), "input", errors)
    for key in input_sec:
        key_l = str(key).lower()
        if key_l in FORBIDDEN_OUTPUT_PATH_KEYS or key_l in {"apk", "apks", "artifact", "artifacts", "copy"}:
            errors.append(f"input.{key} is not allowed (paths are owned by CLI/workspace)")
        elif key_l not in {"description", "notes", "note", "label"}:
            errors.append(f"unknown field: input.{key}")

    search_sec = _require_mapping(raw.get("search"), "search", errors)
    for key in search_sec:
        if key not in {"terms", "regex", "uuids", "api_patterns"}:
            errors.append(f"unknown field: search.{key}")

    terms = _as_str_list(search_sec.get("terms"), "search.terms", errors)
    if len(terms) > MAX_SEARCH_TERMS:
        errors.append(f"search.terms exceeds max of {MAX_SEARCH_TERMS}")
    terms = sorted(set(terms))

    regexes = _as_str_list(search_sec.get("regex"), "search.regex", errors)
    if len(regexes) > MAX_REGEX_PATTERNS:
        errors.append(f"search.regex exceeds max of {MAX_REGEX_PATTERNS}")
    regex_norm: list[str] = []
    for i, pattern in enumerate(regexes):
        if len(pattern) > MAX_REGEX_LENGTH:
            errors.append(f"search.regex[{i}] exceeds max length {MAX_REGEX_LENGTH}")
            continue
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"search.regex[{i}] invalid: {exc}")
            continue
        regex_norm.append(pattern)
    regex_norm = sorted(set(regex_norm))

    uuid_raw = _as_str_list(search_sec.get("uuids"), "search.uuids", errors)
    if len(uuid_raw) > MAX_UUIDS:
        errors.append(f"search.uuids exceeds max of {MAX_UUIDS}")
    uuids_norm: list[str] = []
    for i, u in enumerate(uuid_raw):
        try:
            uuids_norm.append(normalize_uuid(u))
        except ValueError:
            errors.append(f"search.uuids[{i}] is not a valid UUID: {u!r}")
    uuids_norm = sorted(set(uuids_norm))

    api_patterns = _as_str_list(search_sec.get("api_patterns"), "search.api_patterns", errors)
    if len(api_patterns) > MAX_API_PATTERNS:
        errors.append(f"search.api_patterns exceeds max of {MAX_API_PATTERNS}")
    api_norm: list[str] = []
    for p in api_patterns:
        pl = p.lower()
        if pl not in KNOWN_API_PATTERNS:
            errors.append(f"unknown api_pattern: {p}")
        else:
            api_norm.append(pl)
    api_norm = sorted(set(api_norm))

    dex_sec = _require_mapping(raw.get("dex_context"), "dex_context", errors)
    for key in dex_sec:
        if key not in {"enabled", "instruction_window", "xref_depth", "max_callers", "max_callees"}:
            errors.append(f"unknown field: dex_context.{key}")
    dex_enabled = _as_bool(dex_sec.get("enabled"), "dex_context.enabled", errors, default=False)
    if "dex_context" in modules_norm or "xref" in modules_norm:
        if "enabled" not in dex_sec:
            dex_enabled = True
    instruction_window = _as_int_in_bounds(
        dex_sec.get("instruction_window"),
        "dex_context.instruction_window",
        DEX_CONTEXT_BOUNDS["instruction_window"],
        errors,
        8,
    )
    xref_depth = _as_int_in_bounds(
        dex_sec.get("xref_depth"),
        "dex_context.xref_depth",
        DEX_CONTEXT_BOUNDS["xref_depth"],
        errors,
        0,
    )
    if "xref" in modules_norm and "xref_depth" not in dex_sec:
        xref_depth = max(xref_depth, 1)
    max_callers = _as_int_in_bounds(
        dex_sec.get("max_callers"),
        "dex_context.max_callers",
        DEX_CONTEXT_BOUNDS["max_callers"],
        errors,
        20,
    )
    max_callees = _as_int_in_bounds(
        dex_sec.get("max_callees"),
        "dex_context.max_callees",
        DEX_CONTEXT_BOUNDS["max_callees"],
        errors,
        20,
    )

    bt_sec = _require_mapping(raw.get("bluetooth"), "bluetooth", errors)
    bt_allowed = {
        "enabled",
        "dataflow_depth",
        "window",
        "max_paths",
        "max_results",
        "target",
        "caller_depth",
        "reconstruct_callers",
        "reconstruct_streams",
        "reconstruct_read_write",
        "max_callers",
        "max_callees",
        "max_dataflow_paths",
        "max_dataflow_nodes",
        "interprocedural",
        "max_method_hops",
        "max_field_hops",
        "max_object_nodes",
    }
    for key in bt_sec:
        if key not in bt_allowed:
            errors.append(f"unknown field: bluetooth.{key}")
    bt_enabled = _as_bool(bt_sec.get("enabled"), "bluetooth.enabled", errors, default=False)
    if "bluetooth" in modules_norm and "enabled" not in bt_sec:
        bt_enabled = True
    bt_depth = _as_int_in_bounds(
        bt_sec.get("dataflow_depth"),
        "bluetooth.dataflow_depth",
        BLUETOOTH_BOUNDS["dataflow_depth"],
        errors,
        2,
    )
    bt_window = _as_int_in_bounds(
        bt_sec.get("window"),
        "bluetooth.window",
        BLUETOOTH_BOUNDS["window"],
        errors,
        12,
    )
    bt_max_paths = _as_int_in_bounds(
        bt_sec.get("max_paths"),
        "bluetooth.max_paths",
        BLUETOOTH_BOUNDS["max_paths"],
        errors,
        50,
    )
    bt_max_results = _as_int_in_bounds(
        bt_sec.get("max_results"),
        "bluetooth.max_results",
        BLUETOOTH_BOUNDS["max_results"],
        errors,
        100,
    )
    bt_target = bt_sec.get("target")
    if bt_target is not None and not isinstance(bt_target, str):
        errors.append("bluetooth.target must be a string")
        bt_target = None
    elif isinstance(bt_target, str) and not bt_target.strip():
        bt_target = None
    elif isinstance(bt_target, str):
        bt_target = bt_target.strip()
    bt_caller_depth = _as_int_in_bounds(
        bt_sec.get("caller_depth"),
        "bluetooth.caller_depth",
        BLUETOOTH_BOUNDS["caller_depth"],
        errors,
        2,
    )
    bt_reconstruct_callers = _as_bool(
        bt_sec.get("reconstruct_callers"), "bluetooth.reconstruct_callers", errors, default=True
    )
    bt_reconstruct_streams = _as_bool(
        bt_sec.get("reconstruct_streams"), "bluetooth.reconstruct_streams", errors, default=True
    )
    bt_reconstruct_read_write = _as_bool(
        bt_sec.get("reconstruct_read_write"),
        "bluetooth.reconstruct_read_write",
        errors,
        default=True,
    )
    bt_max_callers = _as_int_in_bounds(
        bt_sec.get("max_callers"),
        "bluetooth.max_callers",
        BLUETOOTH_BOUNDS["max_callers"],
        errors,
        50,
    )
    bt_max_callees = _as_int_in_bounds(
        bt_sec.get("max_callees"),
        "bluetooth.max_callees",
        BLUETOOTH_BOUNDS["max_callees"],
        errors,
        50,
    )
    bt_max_dataflow_paths = _as_int_in_bounds(
        bt_sec.get("max_dataflow_paths"),
        "bluetooth.max_dataflow_paths",
        BLUETOOTH_BOUNDS["max_dataflow_paths"],
        errors,
        50,
    )
    bt_max_dataflow_nodes = _as_int_in_bounds(
        bt_sec.get("max_dataflow_nodes"),
        "bluetooth.max_dataflow_nodes",
        BLUETOOTH_BOUNDS["max_dataflow_nodes"],
        errors,
        200,
    )
    bt_interprocedural = _as_bool(
        bt_sec.get("interprocedural"), "bluetooth.interprocedural", errors, default=False
    )
    bt_max_method_hops = _as_int_in_bounds(
        bt_sec.get("max_method_hops"),
        "bluetooth.max_method_hops",
        BLUETOOTH_BOUNDS["max_method_hops"],
        errors,
        3,
    )
    bt_max_field_hops = _as_int_in_bounds(
        bt_sec.get("max_field_hops"),
        "bluetooth.max_field_hops",
        BLUETOOTH_BOUNDS["max_field_hops"],
        errors,
        2,
    )
    bt_max_object_nodes = _as_int_in_bounds(
        bt_sec.get("max_object_nodes"),
        "bluetooth.max_object_nodes",
        BLUETOOTH_BOUNDS["max_object_nodes"],
        errors,
        500,
    )

    eg_sec = _require_mapping(raw.get("evidence_graph"), "evidence_graph", errors)
    for key in eg_sec:
        if key not in {
            "enabled",
            "canonicalize",
            "deduplicate",
            "extract_paths",
            "include_boundaries",
            "max_evidence_paths",
        }:
            errors.append(f"unknown field: evidence_graph.{key}")
    eg_enabled = _as_bool(eg_sec.get("enabled"), "evidence_graph.enabled", errors, default=False)
    eg_canonicalize = _as_bool(
        eg_sec.get("canonicalize"), "evidence_graph.canonicalize", errors, default=True
    )
    eg_deduplicate = _as_bool(
        eg_sec.get("deduplicate"), "evidence_graph.deduplicate", errors, default=True
    )
    eg_extract_paths = _as_bool(
        eg_sec.get("extract_paths"), "evidence_graph.extract_paths", errors, default=True
    )
    eg_include_boundaries = _as_bool(
        eg_sec.get("include_boundaries"), "evidence_graph.include_boundaries", errors, default=True
    )
    eg_max_paths = _as_int_in_bounds(
        eg_sec.get("max_evidence_paths"),
        "evidence_graph.max_evidence_paths",
        (0, 500),
        errors,
        50,
    )

    comm_sec = _require_mapping(raw.get("communication"), "communication", errors)
    for key in comm_sec:
        if key not in {
            "enabled",
            "interprocedural",
            "max_method_hops",
            "max_field_hops",
            "max_object_nodes",
            "max_dataflow_paths",
            "max_buffer_hops",
            "max_parser_hops",
            "max_message_hops",
        }:
            errors.append(f"unknown field: communication.{key}")
    comm_enabled = _as_bool(comm_sec.get("enabled"), "communication.enabled", errors, default=False)
    comm_interprocedural = _as_bool(
        comm_sec.get("interprocedural"), "communication.interprocedural", errors, default=True
    )
    comm_max_method_hops = _as_int_in_bounds(
        comm_sec.get("max_method_hops"), "communication.max_method_hops", (0, 5), errors, 3
    )
    comm_max_field_hops = _as_int_in_bounds(
        comm_sec.get("max_field_hops"), "communication.max_field_hops", (0, 4), errors, 2
    )
    comm_max_object_nodes = _as_int_in_bounds(
        comm_sec.get("max_object_nodes"), "communication.max_object_nodes", (0, 500), errors, 500
    )
    comm_max_dataflow_paths = _as_int_in_bounds(
        comm_sec.get("max_dataflow_paths"), "communication.max_dataflow_paths", (0, 200), errors, 100
    )
    comm_max_buffer_hops = _as_int_in_bounds(
        comm_sec.get("max_buffer_hops"), "communication.max_buffer_hops", (0, 10), errors, 5
    )
    comm_max_parser_hops = _as_int_in_bounds(
        comm_sec.get("max_parser_hops"), "communication.max_parser_hops", (0, 5), errors, 3
    )
    comm_max_message_hops = _as_int_in_bounds(
        comm_sec.get("max_message_hops"), "communication.max_message_hops", (0, 5), errors, 3
    )

    evidence_sec = _require_mapping(raw.get("evidence"), "evidence", errors)
    for key in evidence_sec:
        if key not in {"classifications"}:
            errors.append(f"unknown field: evidence.{key}")
    classifications = _as_str_list(evidence_sec.get("classifications"), "evidence.classifications", errors)
    if not classifications:
        classifications = ["FACT", "CORRELATION", "INFERENCE", "UNKNOWN"]
    for c in classifications:
        if c not in ALLOWED_CLASSIFICATIONS:
            errors.append(f"unknown evidence classification: {c}")
    # Preserve requested order, unique
    seen_c: set[str] = set()
    class_norm: list[str] = []
    for c in classifications:
        if c in ALLOWED_CLASSIFICATIONS and c not in seen_c:
            seen_c.add(c)
            class_norm.append(c)

    limits_sec = _require_mapping(raw.get("limits"), "limits", errors)
    for key in limits_sec:
        if key not in LIMIT_BOUNDS:
            errors.append(f"unknown field: limits.{key}")
    max_results = _as_int_in_bounds(
        limits_sec.get("max_results"), "limits.max_results", LIMIT_BOUNDS["max_results"], errors, 100
    )
    max_contexts = _as_int_in_bounds(
        limits_sec.get("max_contexts"), "limits.max_contexts", LIMIT_BOUNDS["max_contexts"], errors, 100
    )
    max_xrefs = _as_int_in_bounds(
        limits_sec.get("max_xrefs"), "limits.max_xrefs", LIMIT_BOUNDS["max_xrefs"], errors, 1000
    )
    max_chains = _as_int_in_bounds(
        limits_sec.get("max_chains"), "limits.max_chains", LIMIT_BOUNDS["max_chains"], errors, 20
    )
    max_findings = _as_int_in_bounds(
        limits_sec.get("max_findings"), "limits.max_findings", LIMIT_BOUNDS["max_findings"], errors, 10_000
    )

    output_sec = _require_mapping(raw.get("output"), "output", errors)
    for key in output_sec:
        key_l = str(key).lower()
        if key_l in FORBIDDEN_OUTPUT_PATH_KEYS:
            errors.append(f"output.{key} path directive rejected (workspace owns output paths)")
        elif key not in {"format", "include_raw"}:
            errors.append(f"unknown field: output.{key}")
    formats = _as_str_list(output_sec.get("format"), "output.format", errors)
    if not formats:
        formats = ["json", "markdown"]
    fmt_norm: list[str] = []
    for f in formats:
        fl = f.lower()
        if fl == "md":
            fl = "markdown"
        if fl == "all":
            fmt_norm.extend(["json", "markdown"])
            continue
        if fl not in {"json", "markdown"}:
            errors.append(f"unsupported output format: {f}")
        else:
            fmt_norm.append(fl)
    # unique preserve order
    seen_f: set[str] = set()
    formats_out: list[str] = []
    for f in fmt_norm:
        if f not in seen_f:
            seen_f.add(f)
            formats_out.append(f)
    include_raw = _as_bool(output_sec.get("include_raw"), "output.include_raw", errors, default=False)

    profile_sec = _require_mapping(raw.get("profile"), "profile", errors)
    for key in profile_sec:
        if key not in {"name", "path"}:
            errors.append(f"unknown field: profile.{key}")
    profile_name = profile_sec.get("name")
    profile_path = profile_sec.get("path")
    if profile_name is not None and not isinstance(profile_name, str):
        errors.append("profile.name must be a string")
        profile_name = None
    if profile_path is not None and not isinstance(profile_path, str):
        errors.append("profile.path must be a string")
        profile_path = None
    if isinstance(profile_path, str):
        # Block path traversal / absolute escapes into arbitrary FS writes
        if ".." in Path(profile_path).parts:
            errors.append("profile.path path traversal blocked")
        if profile_path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", profile_path):
            # Absolute paths allowed only under workspace profiles/ — still reject absolute for safety
            errors.append("profile.path must be a relative path (e.g. profiles/bmw_connected.yaml)")

    if errors:
        raise PlanValidationError(errors)

    plan = SearchPlan(
        schema_version=SEARCH_PLAN_SCHEMA_VERSION,
        plan_name=plan_name,
        plan_description=plan_description,
        modules=modules_norm,
        search_terms=terms,
        search_regex=regex_norm,
        search_uuids=uuids_norm,
        api_patterns=api_norm,
        dex_context_enabled=dex_enabled,
        instruction_window=instruction_window,
        xref_depth=xref_depth,
        max_callers=max_callers,
        max_callees=max_callees,
        bluetooth_enabled=bt_enabled,
        bluetooth_dataflow_depth=bt_depth,
        bluetooth_window=bt_window,
        bluetooth_max_paths=bt_max_paths,
        bluetooth_max_results=bt_max_results,
        bluetooth_target=bt_target,
        bluetooth_caller_depth=bt_caller_depth,
        bluetooth_reconstruct_callers=bt_reconstruct_callers,
        bluetooth_reconstruct_streams=bt_reconstruct_streams,
        bluetooth_reconstruct_read_write=bt_reconstruct_read_write,
        bluetooth_max_callers=bt_max_callers,
        bluetooth_max_callees=bt_max_callees,
        bluetooth_max_dataflow_paths=bt_max_dataflow_paths,
        bluetooth_max_dataflow_nodes=bt_max_dataflow_nodes,
        bluetooth_interprocedural=bt_interprocedural,
        bluetooth_max_method_hops=bt_max_method_hops,
        bluetooth_max_field_hops=bt_max_field_hops,
        bluetooth_max_object_nodes=bt_max_object_nodes,
        evidence_graph_enabled=eg_enabled,
        evidence_graph_canonicalize=eg_canonicalize,
        evidence_graph_deduplicate=eg_deduplicate,
        evidence_graph_extract_paths=eg_extract_paths,
        evidence_graph_include_boundaries=eg_include_boundaries,
        evidence_graph_max_paths=eg_max_paths,
        communication_enabled=comm_enabled,
        communication_interprocedural=comm_interprocedural,
        communication_max_method_hops=comm_max_method_hops,
        communication_max_field_hops=comm_max_field_hops,
        communication_max_object_nodes=comm_max_object_nodes,
        communication_max_dataflow_paths=comm_max_dataflow_paths,
        communication_max_buffer_hops=comm_max_buffer_hops,
        communication_max_parser_hops=comm_max_parser_hops,
        communication_max_message_hops=comm_max_message_hops,
        evidence_classifications=class_norm,
        max_results=max_results,
        max_contexts=max_contexts,
        max_xrefs=max_xrefs,
        max_chains=max_chains,
        max_findings=max_findings,
        output_formats=formats_out,
        include_raw=include_raw,
        profile_name=profile_name.strip() if isinstance(profile_name, str) and profile_name.strip() else None,
        profile_path=profile_path.strip() if isinstance(profile_path, str) and profile_path.strip() else None,
    )
    plan.plan_sha256 = compute_plan_sha256(plan.to_canonical_dict())
    return plan


def load_search_plan(path: Path) -> SearchPlan:
    return validate_and_normalize(load_plan_yaml(path))


def format_plan_valid_summary(plan: SearchPlan) -> str:
    lines = [
        "PLAN VALID",
        f"schema_version: {plan.schema_version}",
        f"name: {plan.plan_name}",
        f"modules: {len(plan.modules)}",
        f"search terms: {len(plan.search_terms)}",
        f"search regex: {len(plan.search_regex)}",
        f"search uuids: {len(plan.search_uuids)}",
        f"api patterns: {len(plan.api_patterns)}",
        f"dex_context: {plan.dex_context_enabled}",
        f"xref depth: {plan.xref_depth}",
        f"bluetooth: {plan.bluetooth_enabled}",
        f"plan_sha256: {plan.plan_sha256}",
        f"engine_version: {__version__}",
    ]
    return "\n".join(lines) + "\n"


def apply_search_plan_to_config(plan: SearchPlan, config: AnalysisConfig) -> AnalysisConfig:
    """Map a normalized SearchPlan onto AnalysisConfig. Does not invent findings."""
    config.formats = tuple(plan.output_formats)
    config.include_raw = plan.include_raw
    config.dex_context = bool(plan.dex_context_enabled)
    config.instruction_window = plan.instruction_window
    config.xref_depth = plan.xref_depth
    config.max_callers = plan.max_callers
    config.max_callees = plan.max_callees
    config.max_dex_context_results = min(plan.max_results, plan.max_contexts)
    config.bluetooth_path = bool(plan.bluetooth_enabled)
    config.bluetooth_dataflow_depth = plan.bluetooth_dataflow_depth
    config.bluetooth_window = plan.bluetooth_window
    config.bluetooth_max_paths = plan.bluetooth_max_paths
    config.bluetooth_max_results = plan.bluetooth_max_results
    if plan.bluetooth_target:
        config.bluetooth_target = plan.bluetooth_target
    config.bluetooth_caller_depth = plan.bluetooth_caller_depth
    config.bluetooth_reconstruct_callers = plan.bluetooth_reconstruct_callers
    config.bluetooth_reconstruct_streams = plan.bluetooth_reconstruct_streams
    config.bluetooth_reconstruct_read_write = plan.bluetooth_reconstruct_read_write
    config.bluetooth_max_callers = plan.bluetooth_max_callers
    config.bluetooth_max_callees = plan.bluetooth_max_callees
    config.bluetooth_max_dataflow_paths = plan.bluetooth_max_dataflow_paths
    config.bluetooth_max_dataflow_nodes = plan.bluetooth_max_dataflow_nodes
    config.bluetooth_interprocedural = plan.bluetooth_interprocedural
    config.bluetooth_max_method_hops = plan.bluetooth_max_method_hops
    config.bluetooth_max_field_hops = plan.bluetooth_max_field_hops
    config.bluetooth_max_object_nodes = plan.bluetooth_max_object_nodes
    config.evidence_graph = plan.evidence_graph_enabled
    config.evidence_graph_canonicalize = plan.evidence_graph_canonicalize
    config.evidence_graph_deduplicate = plan.evidence_graph_deduplicate
    config.evidence_graph_extract_paths = plan.evidence_graph_extract_paths
    config.evidence_graph_include_boundaries = plan.evidence_graph_include_boundaries
    config.evidence_graph_max_paths = plan.evidence_graph_max_paths
    config.communication = plan.communication_enabled
    config.communication_interprocedural = plan.communication_interprocedural
    config.communication_max_method_hops = plan.communication_max_method_hops
    config.communication_max_field_hops = plan.communication_max_field_hops
    config.communication_max_object_nodes = plan.communication_max_object_nodes
    config.communication_max_dataflow_paths = plan.communication_max_dataflow_paths
    config.communication_max_buffer_hops = plan.communication_max_buffer_hops
    config.communication_max_parser_hops = plan.communication_max_parser_hops
    config.communication_max_message_hops = plan.communication_max_message_hops
    config.max_findings_per_scanner = plan.max_findings
    config.max_xrefs = plan.max_xrefs
    config.max_chains = plan.max_chains
    config.search_terms = list(plan.search_terms)
    config.search_regex = list(plan.search_regex)
    config.search_uuids = list(plan.search_uuids)
    config.api_patterns = list(plan.api_patterns)
    config.evidence_classifications = list(plan.evidence_classifications)
    config.search_plan_sha256 = plan.plan_sha256
    config.enabled_modules = set(plan.modules)

    # Prefer first search term as dex query when not already set by CLI
    if plan.search_terms and not config.dex_query:
        # Join is avoided; use first term as focus query for bounded context
        config.dex_query = plan.search_terms[0]
    return config


def resolve_profile_from_plan(plan: SearchPlan, cli_profile: str | None) -> str | None:
    """CLI profile overrides plan; plan may set name or relative path."""
    if cli_profile:
        return cli_profile
    if plan.profile_path:
        return plan.profile_path
    if plan.profile_name:
        return plan.profile_name
    return None
