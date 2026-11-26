"""Forensic Analysis Workbench — orchestrates existing analyzer APIs only.

Does not invent evidence, resource estimates, or protocol semantics.
Static APK analysis only — does not execute the Android app.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apk_forensics import __version__
from apk_forensics.analysis_job import (
    create_analysis_job,
    enrich_actual_from_report,
    mark_cancelled,
    mark_completed,
    mark_failed,
    mark_running,
    preflight_or_reject,
)
from apk_forensics.bundle_pipeline import run_bundle_pipeline
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ApkForensicsError, InputError, InvalidApkError
from apk_forensics.hashing import file_sha256_and_size
from apk_forensics.pipeline import run_pipeline
from apk_forensics.resource_estimator import fingerprint_apk
from apk_forensics.resource_guard import ResourceRejectedError, ResourceWarningBlockedError
from apk_forensics.resource_policy import POLICY_PRESETS, get_resource_policy
from apk_forensics.search_plan import (
    PlanValidationError,
    SearchPlan,
    load_plan_yaml,
    load_search_plan,
    validate_and_normalize,
    apply_search_plan_to_config,
)
from apk_forensics.utils import utc_now_iso

WORKBENCH_JOB_SCHEMA = "apk_forensics.workbench_job.v1"

STAGE_DEFS = [
    {"id": "input_validation", "label": "Input validation"},
    {"id": "inventory", "label": "Inventory"},
    {"id": "dex", "label": "DEX / Native / Candidates"},
    {"id": "dex_context_xref", "label": "DEX Context / XREF"},
    {"id": "bluetooth", "label": "Bluetooth path analysis"},
    {"id": "communication", "label": "Communication"},
    {"id": "reports", "label": "Reports"},
    {"id": "ui_snapshot", "label": "UI Snapshot"},
]

# Estimator component name → UI stage (heuristic display only)
ESTIMATE_COMPONENT_TO_STAGE = {
    "baseline_input_dex_native": "dex",
    "dex_context_xref": "dex_context_xref",
    "bluetooth_path_analysis": "bluetooth",
    "caller_reconstruction": "bluetooth",
    "object_flow": "bluetooth",
    "evidence_graph": "bluetooth",
    "communication_dataflow": "communication",
    "static_runtime_correlation": None,  # offline / not part of scan
}

_SAFE_UPLOAD_NAME = re.compile(r"[^A-Za-z0-9._+-]+")


def _git_commit(root: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except Exception:  # noqa: BLE001
        return None
    return None


def safe_upload_filename(name: str) -> str:
    base = Path(name).name
    cleaned = _SAFE_UPLOAD_NAME.sub("_", base).strip("._")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = f"upload-{uuid.uuid4().hex[:8]}.apk"
    if len(cleaned) > 180:
        cleaned = cleaned[:180]
    return cleaned


def resolve_under(root: Path, candidate: Path) -> Path:
    """Resolve candidate and require it stays under root (no traversal)."""
    root_r = root.resolve()
    path = candidate.resolve()
    try:
        path.relative_to(root_r)
    except ValueError as exc:
        raise PermissionError(f"path outside allowed root: {candidate}") from exc
    return path


def format_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    s = int(round(float(seconds)))
    if s < 0:
        s = 0
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{sec:02d}"
    return f"{m:02d}:{sec:02d}"


def list_bundled_plans(root: Path) -> list[dict[str, Any]]:
    plans_dir = (root / "plans").resolve()
    if not plans_dir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(plans_dir.glob("*.yaml")):
        try:
            plan = load_search_plan(path)
        except Exception as exc:  # noqa: BLE001
            out.append(
                {
                    "id": path.stem,
                    "path": str(path.relative_to(root.resolve())),
                    "error": str(exc),
                    "valid": False,
                    "kind": "builtin",
                }
            )
            continue
        out.append(
            {
                "id": plan.plan_name,
                "path": str(path.relative_to(root.resolve())),
                "name": plan.plan_name,
                "description": plan.plan_description,
                "modules": list(plan.modules),
                "plan_sha256": plan.plan_sha256,
                "dex_context_enabled": plan.dex_context_enabled,
                "bluetooth_enabled": plan.bluetooth_enabled,
                "evidence_graph_enabled": plan.evidence_graph_enabled,
                "communication_enabled": plan.communication_enabled,
                "correlation_enabled": plan.correlation_enabled,
                "valid": True,
                "kind": "builtin",
                "note": (
                    "Correlation flags refer to offline static↔runtime/wire join, "
                    "not APK execution."
                    if plan.correlation_enabled
                    else None
                ),
            }
        )
    return out


def list_all_plans(root: Path) -> list[dict[str, Any]]:
    from apk_forensics.ui.plan_builder import list_user_plans

    return list_bundled_plans(root) + list_user_plans(root)


def plan_criteria_view(plan: SearchPlan) -> dict[str, Any]:
    """Grouped criteria for UI — SearchPlan limits only (not resource policy)."""
    inventory = {
        "manifest": "manifest" in plan.modules,
        "zip_inventory": "zip_inventory" in plan.modules,
        "dex": "dex" in plan.modules,
        "strings": "strings" in plan.modules,
        "uuid": "uuid" in plan.modules,
    }
    return {
        "inventory": inventory,
        "dex_xref": {
            "enabled": plan.dex_context_enabled,
            "xref_depth": plan.xref_depth,
            "max_callers": plan.max_callers,
            "max_callees": plan.max_callees,
            "instruction_window": plan.instruction_window,
        },
        "bluetooth": {
            "enabled": plan.bluetooth_enabled,
            "reconstruct_callers": plan.bluetooth_reconstruct_callers,
            "reconstruct_streams": plan.bluetooth_reconstruct_streams,
            "reconstruct_read_write": plan.bluetooth_reconstruct_read_write,
            "interprocedural": plan.bluetooth_interprocedural,
            "caller_depth": plan.bluetooth_caller_depth,
            "dataflow_depth": plan.bluetooth_dataflow_depth,
            "max_method_hops": plan.bluetooth_max_method_hops,
            "max_field_hops": plan.bluetooth_max_field_hops,
            "max_object_nodes": plan.bluetooth_max_object_nodes,
        },
        "evidence_graph": {
            "enabled": plan.evidence_graph_enabled,
            "max_paths": plan.evidence_graph_max_paths,
        },
        "communication": {
            "enabled": plan.communication_enabled,
            "max_method_hops": plan.communication_max_method_hops,
            "max_field_hops": plan.communication_max_field_hops,
            "max_buffer_hops": plan.communication_max_buffer_hops,
            "max_parser_hops": plan.communication_max_parser_hops,
            "max_message_hops": plan.communication_max_message_hops,
            "max_dataflow_paths": plan.communication_max_dataflow_paths,
        },
        "runtime_correlation": {
            "enabled": plan.correlation_enabled,
            "note": (
                "Offline correlation limits only. "
                "Start Analysis does NOT execute the APK or collect runtime evidence."
            ),
            "max_runtime_events": plan.correlation_max_runtime_events,
            "max_wire_packets": plan.correlation_max_wire_packets,
            "max_correlations": plan.correlation_max_correlations,
        },
        "search_plan_limits_note": "SearchPlan limits ≠ Resource Policy limits.",
    }


def _set_nested(raw: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    cur: dict[str, Any] = raw
    for key in path[:-1]:
        nxt = cur.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[key] = nxt
        cur = nxt
    cur[path[-1]] = value


def apply_plan_overrides(base_plan_path: Path, overrides: dict[str, Any] | None) -> SearchPlan:
    """Load plan YAML, optionally merge UI overrides, re-validate (new plan_sha256)."""
    raw = load_plan_yaml(base_plan_path)
    if not overrides:
        return validate_and_normalize(raw)

    # Map UI criteria groups → SearchPlan YAML paths
    mapping: dict[str, tuple[str, ...]] = {
        "dex_xref.enabled": ("dex_context", "enabled"),
        "dex_xref.xref_depth": ("dex_context", "xref_depth"),
        "dex_xref.max_callers": ("dex_context", "max_callers"),
        "dex_xref.max_callees": ("dex_context", "max_callees"),
        "dex_xref.instruction_window": ("dex_context", "instruction_window"),
        "bluetooth.enabled": ("bluetooth", "enabled"),
        "bluetooth.reconstruct_callers": ("bluetooth", "reconstruct_callers"),
        "bluetooth.reconstruct_streams": ("bluetooth", "reconstruct_streams"),
        "bluetooth.reconstruct_read_write": ("bluetooth", "reconstruct_read_write"),
        "bluetooth.interprocedural": ("bluetooth", "interprocedural"),
        "bluetooth.caller_depth": ("bluetooth", "caller_depth"),
        "bluetooth.dataflow_depth": ("bluetooth", "dataflow_depth"),
        "bluetooth.max_method_hops": ("bluetooth", "max_method_hops"),
        "bluetooth.max_field_hops": ("bluetooth", "max_field_hops"),
        "bluetooth.max_object_nodes": ("bluetooth", "max_object_nodes"),
        "evidence_graph.enabled": ("evidence_graph", "enabled"),
        "evidence_graph.max_paths": ("evidence_graph", "max_evidence_paths"),
        "communication.enabled": ("communication", "enabled"),
        "communication.max_method_hops": ("communication", "max_method_hops"),
        "communication.max_field_hops": ("communication", "max_field_hops"),
        "communication.max_buffer_hops": ("communication", "max_buffer_hops"),
        "communication.max_parser_hops": ("communication", "max_parser_hops"),
        "communication.max_message_hops": ("communication", "max_message_hops"),
        "communication.max_dataflow_paths": ("communication", "max_dataflow_paths"),
        # Correlation overrides allowed for offline plan fidelity; scan still does not execute APK
        "runtime_correlation.enabled": ("correlation", "enabled"),
    }

    def walk(prefix: str, obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and key not in mapping:
                walk(key, v)
            elif key in mapping:
                _set_nested(raw, mapping[key], v)

    walk("", overrides)
    return validate_and_normalize(raw)


def validate_input_paths(paths: list[Path]) -> dict[str, Any]:
    """Fingerprint + SHA without deep analysis."""
    if not paths:
        raise InputError("No APK path provided")
    artifacts: list[dict[str, Any]] = []
    for p in paths:
        if not p.exists():
            raise InputError(f"Path does not exist: {p}")
        if not p.is_file():
            raise InputError(f"Path is not a file: {p}")
        try:
            fp = fingerprint_apk(p)
        except InvalidApkError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise InvalidApkError(f"File is not a valid APK/ZIP: {p}") from exc
        sha, size = file_sha256_and_size(p)
        artifacts.append(
            {
                **fp.to_dict(),
                "sha256": sha,
                "size_bytes": size,
                "zip_apk_valid": True,
                "filename": p.name,
            }
        )
    primary = artifacts[0]
    return {
        "filename": primary["filename"],
        "size_bytes": primary["size_bytes"],
        "sha256": primary["sha256"],
        "zip_apk_valid": True,
        "dex_count": primary["dex_count"],
        "dex_size": primary["dex_total_bytes"],
        "native_so_count": primary["native_so_count"],
        "native_size": primary["native_total_bytes"],
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "paths": [str(p.resolve()) for p in paths],
    }


def stage_estimates_from_breakdown(breakdown: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Map estimator components to UI stages. Heuristic only."""
    comps = (breakdown or {}).get("components") or []
    by_stage: dict[str, int] = {}
    for c in comps:
        name = c.get("name")
        if name == "TOTAL":
            continue
        stage = ESTIMATE_COMPONENT_TO_STAGE.get(name)
        if stage is None:
            continue
        by_stage[stage] = by_stage.get(stage, 0) + int(c.get("runtime_seconds") or 0)
    rows: list[dict[str, Any]] = []
    for s in STAGE_DEFS:
        if s["id"] in {"input_validation", "reports", "ui_snapshot"}:
            rows.append(
                {
                    "stage": s["id"],
                    "label": s["label"],
                    "estimate_seconds": None,
                    "display": "Not separately estimated",
                    "kind": "HEURISTIC_ESTIMATE",
                }
            )
            continue
        sec = by_stage.get(s["id"])
        if sec is None:
            rows.append(
                {
                    "stage": s["id"],
                    "label": s["label"],
                    "estimate_seconds": None,
                    "display": "Not separately estimated",
                    "kind": "HEURISTIC_ESTIMATE",
                }
            )
        else:
            rows.append(
                {
                    "stage": s["id"],
                    "label": s["label"],
                    "estimate_seconds": sec,
                    "display": format_duration(sec),
                    "kind": "HEURISTIC_ESTIMATE",
                }
            )
    total = None
    if breakdown and isinstance(breakdown.get("total_runtime_seconds"), (int, float)):
        total = int(breakdown["total_runtime_seconds"])
    elif comps:
        for c in comps:
            if c.get("name") == "TOTAL":
                total = int(c.get("runtime_seconds") or 0)
    return rows + [
        {
            "stage": "TOTAL",
            "label": "TOTAL",
            "estimate_seconds": total,
            "display": format_duration(total) if total is not None else "—",
            "kind": "HEURISTIC_ESTIMATE",
            "note": "Heuristic estimate — not a guaranteed runtime.",
        }
    ]


def initial_stages(plan: SearchPlan) -> list[dict[str, Any]]:
    enabled = {
        "input_validation": True,
        "inventory": True,
        "dex": True,
        "dex_context_xref": plan.dex_context_enabled,
        "bluetooth": plan.bluetooth_enabled,
        "communication": plan.communication_enabled,
        "reports": True,
        "ui_snapshot": True,
    }
    stages = []
    for s in STAGE_DEFS:
        stages.append(
            {
                "id": s["id"],
                "label": s["label"],
                "status": "QUEUED" if enabled[s["id"]] else "SKIPPED",
                "elapsed_seconds": None,
                "started_at": None,
                "finished_at": None,
            }
        )
    return stages


@dataclass
class WorkbenchJob:
    job_id: str
    status: str
    root: Path
    output_dir: Path
    apk_paths: list[Path]
    plan_path: Path
    plan: SearchPlan
    resource_policy: str
    allow_resource_warning: bool
    created_at: str
    input_meta: dict[str, Any]
    estimate: dict[str, Any] | None = None
    decision: dict[str, Any] | None = None
    stages: list[dict[str, Any]] = field(default_factory=list)
    logs: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    elapsed_seconds: float | None = None
    estimated_runtime_seconds: int | None = None
    estimated_memory_mb: int | None = None
    analysis_job_id: str | None = None
    snapshot_path: str | None = None
    error: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _t0: float | None = field(default=None, repr=False)
    _stage_t0: dict[str, float] = field(default_factory=dict, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _analysis_job: Any = field(default=None, repr=False)

    def log(self, level: str, message: str) -> None:
        with self._lock:
            self.logs.append(
                {"ts": utc_now_iso(), "level": level.upper(), "message": message}
            )
            if len(self.logs) > 2000:
                self.logs = self.logs[-1500:]

    def set_stage(self, stage_id: str) -> None:
        with self._lock:
            now = time.perf_counter()
            iso = utc_now_iso()
            found = False
            for s in self.stages:
                if s["id"] == stage_id:
                    found = True
                    if s["status"] in {"COMPLETE", "SKIPPED", "FAILED"}:
                        break
                    if s["status"] != "RUNNING":
                        # close previous RUNNING
                        for prev in self.stages:
                            if prev["status"] == "RUNNING" and prev["id"] != stage_id:
                                prev["status"] = "COMPLETE"
                                t0 = self._stage_t0.get(prev["id"])
                                if t0 is not None:
                                    prev["elapsed_seconds"] = round(now - t0, 3)
                                prev["finished_at"] = iso
                        s["status"] = "RUNNING"
                        s["started_at"] = iso
                        self._stage_t0[stage_id] = now
                    break
            if found:
                self.log("INFO", f"Stage → {stage_id}")

    def complete_stage(self, stage_id: str, status: str = "COMPLETE") -> None:
        with self._lock:
            now = time.perf_counter()
            iso = utc_now_iso()
            for s in self.stages:
                if s["id"] == stage_id:
                    s["status"] = status
                    t0 = self._stage_t0.get(stage_id)
                    if t0 is not None:
                        s["elapsed_seconds"] = round(now - t0, 3)
                    s["finished_at"] = iso
                    break

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            elapsed = self.elapsed_seconds
            if self.status == "RUNNING" and self._t0 is not None:
                elapsed = round(time.perf_counter() - self._t0, 3)
            est = self.estimated_runtime_seconds
            remaining = None
            if est is not None and elapsed is not None and self.status == "RUNNING":
                remaining = max(0, int(est - elapsed))
            return {
                "schema": WORKBENCH_JOB_SCHEMA,
                "job_id": self.job_id,
                "status": self.status,
                "input": dict(self.input_meta),
                "plan": {
                    "name": self.plan.plan_name,
                    "path": str(self.plan_path),
                    "sha256": self.plan.plan_sha256,
                    "description": self.plan.plan_description,
                },
                "resource": {
                    "policy": self.resource_policy,
                    "allow_resource_warning": self.allow_resource_warning,
                    "estimate": self.estimate,
                    "decision": self.decision,
                    "note": "Resource Policy ≠ SearchPlan limits.",
                },
                "timing": {
                    "created_at": self.created_at,
                    "started_at": self.started_at,
                    "finished_at": self.finished_at,
                    "elapsed_seconds": elapsed,
                    "estimated_runtime_seconds": est,
                    "estimated_remaining_seconds": remaining,
                    "elapsed_display": format_duration(elapsed),
                    "estimated_display": format_duration(est),
                    "remaining_display": format_duration(remaining),
                    "eta_kind": "HEURISTIC_ESTIMATE",
                },
                "stages": deepcopy(self.stages),
                "logs": list(self.logs[-200:]),
                "results": list(self.results),
                "output_dir": str(self.output_dir),
                "snapshot_path": self.snapshot_path,
                "analysis_job_id": self.analysis_job_id,
                "error": self.error,
                "provenance": dict(self.provenance),
                "disclaimer": (
                    "Start Analysis runs static APK forensics only. "
                    "It does not execute the Android app or collect runtime instrumentation."
                ),
            }

    def persist(self) -> Path:
        path = self.output_dir / "workbench_job.json"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path


class WorkbenchController:
    """In-process job registry + safe workspace helpers."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.uploads_dir = self.root / "work" / "ui-uploads"
        self.jobs_dir = self.root / "output" / "ui-jobs"
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, WorkbenchJob] = {}
        self._lock = threading.Lock()
        self.active_snapshot_path: Path | None = None
        self.active_snapshot_payload: bytes | None = None
        self.bind_host: str = "127.0.0.1"

    def meta(self) -> dict[str, Any]:
        return {
            "workbench": True,
            "analyzer_version": __version__,
            "git_commit": _git_commit(self.root),
            "root": str(self.root),
            "uploads_dir": str(self.uploads_dir),
            "jobs_dir": str(self.jobs_dir),
            "bind_host": self.bind_host,
            "bind_warning": (
                "Server is bound beyond 127.0.0.1. Uploads and job APIs are reachable "
                "on the network. Prefer 127.0.0.1 for local-only use."
                if self.bind_host not in {"127.0.0.1", "localhost", "::1"}
                else None
            ),
            "resource_policies": sorted(POLICY_PRESETS.keys()),
            "plans": list_all_plans(self.root),
            "pipeline_coverage": {
                "base_static_analysis": "AVAILABLE",
                "extended_forensic_post_processing": "NOT AUTOMATIC",
                "runtime_instrumentation": "SEPARATE WORKFLOW",
                "runtime_wire_correlation": "INPUT-DEPENDENT",
            },
            "disclaimer": (
                "Static APK analysis only. APK execution / runtime instrumentation "
                "is a separate workflow (INPUT_MISSING until real runtime evidence exists)."
            ),
        }

    def save_upload(self, filename: str, data: bytes) -> dict[str, Any]:
        if not data:
            raise InputError("Empty upload")
        safe = safe_upload_filename(filename)
        dest_dir = self.uploads_dir / utc_now_iso().replace(":", "").replace("-", "")[:15]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / safe
        dest.write_bytes(data)
        dest = resolve_under(self.uploads_dir, dest)
        meta = validate_input_paths([dest])
        meta["source"] = "upload"
        meta["server_path"] = str(dest)
        return meta

    def validate_server_paths(self, paths: list[str]) -> dict[str, Any]:
        resolved: list[Path] = []
        for raw in paths:
            if not raw or not str(raw).strip():
                raise InputError("Empty server path")
            p = Path(raw).expanduser()
            if not p.is_absolute():
                # Relative paths are interpreted vs analysis host root (repo root)
                p = (self.root / p).resolve()
            else:
                p = p.resolve()
            if not p.exists():
                raise InputError(f"Path does not exist on analysis host: {p}")
            resolved.append(p)
        meta = validate_input_paths(resolved)
        meta["source"] = "server_path"
        meta["server_path"] = str(resolved[0])
        meta["note"] = "Server-side path on the host running apk-forensics ui (not the browser device)."
        return meta

    def load_plan(self, plan_id: str, overrides: dict[str, Any] | None = None) -> tuple[Path, SearchPlan]:
        from apk_forensics.ui.plan_builder import user_plans_dir

        plans = {p["id"]: p for p in list_all_plans(self.root) if p.get("valid")}
        # also allow stem match / user:name without prefix
        if plan_id not in plans:
            for p in list_all_plans(self.root):
                if not p.get("valid"):
                    continue
                stem = Path(str(p.get("path") or "")).stem
                if stem == plan_id or p.get("name") == plan_id or p.get("id") == f"user:{plan_id}":
                    plans[plan_id] = p
                    break
        if plan_id not in plans:
            raise PlanValidationError([f"Unknown or invalid plan: {plan_id}"])
        entry = plans[plan_id]
        raw_path = Path(entry["path"])
        path = raw_path if raw_path.is_absolute() else (self.root / raw_path).resolve()
        # Allow built-in plans/ or user work/user-plans/
        try:
            resolve_under(self.root / "plans", path)
        except PermissionError:
            resolve_under(user_plans_dir(self.root), path)
        plan = apply_plan_overrides(path, overrides)
        return path, plan

    def suggest_plan(self, goal: str, *, plan_name: str | None = None, depth: str = "standard") -> dict[str, Any]:
        from apk_forensics.ui.plan_builder import suggest_plan_from_goal

        return suggest_plan_from_goal(goal, plan_name=plan_name, depth=depth)

    def validate_plan_raw(self, raw: dict[str, Any]) -> dict[str, Any]:
        from apk_forensics.ui.plan_builder import validate_raw_plan

        return validate_raw_plan(raw)

    def preview_plan_form(self, form: dict[str, Any]) -> dict[str, Any]:
        from apk_forensics.ui.plan_builder import build_raw_from_builder_form, validate_raw_plan

        raw = build_raw_from_builder_form(form)
        result = validate_raw_plan(raw)
        result["raw"] = raw
        return result

    def save_plan(
        self,
        raw: dict[str, Any],
        *,
        provenance: dict[str, Any] | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        from apk_forensics.ui.plan_builder import plan_preview, save_user_plan

        saved = save_user_plan(self.root, raw, provenance=provenance, overwrite=overwrite)
        return {
            "ok": True,
            "plan_id": f"user:{saved.plan.plan_name}",
            "path": str(saved.path),
            "provenance_path": str(saved.provenance_path) if saved.provenance_path else None,
            "plan": plan_preview(saved.plan),
            "plan_sha256": saved.plan.plan_sha256,
            "kind": "user",
        }

    def clone_builtin_plan(self, plan_id: str, *, new_name: str, goal_note: str | None = None) -> dict[str, Any]:
        from apk_forensics.ui.plan_builder import clone_plan, plan_preview

        path, _plan = self.load_plan(plan_id)
        # Refuse silent overwrite of builtins — clone always writes to user-plans
        if "plans" in path.parts and "user-plans" not in path.parts:
            # built-in
            pass
        saved = clone_plan(self.root, path, new_name=new_name, goal_note=goal_note)
        return {
            "ok": True,
            "plan_id": f"user:{saved.plan.plan_name}",
            "path": str(saved.path),
            "base_plan": str(path),
            "plan": plan_preview(saved.plan),
            "plan_sha256": saved.plan.plan_sha256,
            "kind": "user",
            "note": "Original built-in plan was not modified.",
        }

    def estimate(
        self,
        *,
        apk_paths: list[str],
        plan_id: str,
        resource_policy: str = "standard",
        plan_overrides: dict[str, Any] | None = None,
        allow_resource_warning: bool = False,
    ) -> dict[str, Any]:
        paths = [Path(p) for p in apk_paths]
        for p in paths:
            if not p.is_file():
                raise InputError(f"APK not found: {p}")
        plan_path, plan = self.load_plan(plan_id, plan_overrides)
        if resource_policy not in POLICY_PRESETS:
            raise InputError(f"Unknown resource policy: {resource_policy}")
        policy = get_resource_policy(resource_policy)
        job, fps, _factors = create_analysis_job(
            apk_paths=paths,
            search_plan=plan,
            policy=policy,
            allow_resource_warning=allow_resource_warning,
        )
        assert job.resource_estimate is not None
        assert job.resource_decision is not None
        stage_rows = stage_estimates_from_breakdown(job.resource_estimate.breakdown)
        return {
            "analysis_job_id": job.job_id,
            "input": {
                "artifacts": [f.to_dict() for f in fps],
                "sha256": job.input_artifact_sha256,
            },
            "plan": {
                "name": plan.plan_name,
                "sha256": plan.plan_sha256,
                "path": str(plan_path.relative_to(self.root)),
                "criteria": plan_criteria_view(plan),
            },
            "resource_policy": resource_policy,
            "allow_resource_warning": allow_resource_warning,
            "estimate": job.resource_estimate.to_dict(),
            "decision": job.resource_decision.to_dict(),
            "stage_estimates": stage_rows,
            "estimated_runtime_display": format_duration(job.resource_estimate.runtime_seconds),
            "estimated_memory_mb": job.resource_estimate.memory_mb,
            "risk": job.resource_decision.decision,
            "note": "HEURISTIC ESTIMATE from existing Resource Estimator — not guaranteed runtime.",
            "disclaimer": (
                "Preflight for static APK analysis. Does not execute the app."
            ),
        }

    def start_job(
        self,
        *,
        apk_paths: list[str],
        plan_id: str,
        resource_policy: str = "standard",
        plan_overrides: dict[str, Any] | None = None,
        allow_resource_warning: bool = False,
        confirm_warning: bool = False,
    ) -> WorkbenchJob:
        paths = [Path(p).resolve() for p in apk_paths]
        for p in paths:
            if not p.is_file():
                raise InputError(f"APK not found: {p}")
        plan_path, plan = self.load_plan(plan_id, plan_overrides)
        if resource_policy not in POLICY_PRESETS:
            raise InputError(f"Unknown resource policy: {resource_policy}")
        policy = get_resource_policy(resource_policy)
        allow = bool(allow_resource_warning or confirm_warning)
        analysis_job, _fps, _factors = create_analysis_job(
            apk_paths=paths,
            search_plan=plan,
            policy=policy,
            allow_resource_warning=allow,
        )
        assert analysis_job.resource_decision is not None
        decision = analysis_job.resource_decision
        if decision.decision == "REJECT":
            raise ResourceRejectedError(
                "RESOURCE REJECT — analysis not started\n"
                + "\n".join(f"- {r}" for r in decision.reasons),
                decision=decision,
            )
        if decision.decision == "WARNING" and not allow:
            raise ResourceWarningBlockedError(
                "RESOURCE WARNING — explicit Proceed required",
                decision=decision,
            )
        # Re-bind allow flag then preflight
        analysis_job.allow_resource_warning = allow
        preflight_or_reject(analysis_job)

        short = analysis_job.job_id[:12]
        stamp = utc_now_iso().replace(":", "").replace("-", "")[:15]
        out_dir = self.jobs_dir / f"{stamp}-{short}"
        out_dir.mkdir(parents=True, exist_ok=True)
        input_meta = validate_input_paths(paths)
        input_meta["source"] = "job"
        wb = WorkbenchJob(
            job_id=analysis_job.job_id,
            status="QUEUED",
            root=self.root,
            output_dir=out_dir,
            apk_paths=paths,
            plan_path=plan_path,
            plan=plan,
            resource_policy=resource_policy,
            allow_resource_warning=allow,
            created_at=utc_now_iso(),
            input_meta=input_meta,
            estimate=analysis_job.resource_estimate.to_dict() if analysis_job.resource_estimate else None,
            decision=decision.to_dict(),
            stages=initial_stages(plan),
            estimated_runtime_seconds=(
                analysis_job.resource_estimate.runtime_seconds if analysis_job.resource_estimate else None
            ),
            estimated_memory_mb=(
                analysis_job.resource_estimate.memory_mb if analysis_job.resource_estimate else None
            ),
            analysis_job_id=analysis_job.job_id,
            provenance={
                "analyzer_version": __version__,
                "git_commit": _git_commit(self.root),
                "engine": "apk_forensics.pipeline",
            },
            _analysis_job=analysis_job,
        )
        wb.log("INFO", "Job queued (static APK analysis — not app execution)")
        wb.persist()
        with self._lock:
            self._jobs[wb.job_id] = wb
        thread = threading.Thread(target=self._run_job, args=(wb,), daemon=True, name=f"wb-{short}")
        wb._thread = thread
        thread.start()
        return wb

    def get_job(self, job_id: str) -> WorkbenchJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel_job(self, job_id: str) -> WorkbenchJob:
        job = self.get_job(job_id)
        if job is None:
            raise InputError(f"Unknown job: {job_id}")
        aj = job._analysis_job
        if aj is not None and getattr(aj, "cancellation", None) is not None:
            aj.cancellation.cancel("cancelled_by_ui")
        job.log("INFO", "Cancel requested")
        return job

    def allowed_file(self, path: Path) -> Path:
        """Only files under uploads or jobs output may be served."""
        path = path.resolve()
        for root in (self.uploads_dir, self.jobs_dir):
            try:
                return resolve_under(root, path)
            except PermissionError:
                continue
        if self.active_snapshot_path and self.active_snapshot_path != Path("<memory>"):
            try:
                if path == self.active_snapshot_path.resolve():
                    return path
            except Exception:  # noqa: BLE001
                pass
        raise PermissionError("file not in allowed workbench workspace")

    def set_active_snapshot(self, path: Path) -> None:
        path = path.resolve()
        self.active_snapshot_path = path
        self.active_snapshot_payload = path.read_bytes()

    def _run_job(self, wb: WorkbenchJob) -> None:
        aj = wb._analysis_job
        try:
            wb.status = "RUNNING"
            wb.started_at = utc_now_iso()
            wb._t0 = time.perf_counter()
            mark_running(aj)
            wb.set_stage("input_validation")
            wb.log("INFO", "Input validated")
            wb.log("INFO", f"Resource Guard: {wb.decision.get('decision') if wb.decision else '?'}")
            wb.complete_stage("input_validation")

            def on_stage(stage: str) -> None:
                wb.set_stage(stage)

            aj.on_stage = on_stage  # type: ignore[attr-defined]

            config = AnalysisConfig()
            apply_search_plan_to_config(wb.plan, config)

            wb.log("INFO", f"Starting pipeline plan={wb.plan.plan_name}")
            if len(wb.apk_paths) == 1:
                report, outputs, warnings = run_pipeline(
                    wb.apk_paths[0],
                    wb.output_dir,
                    config=config,
                    search_plan=wb.plan,
                    analysis_job=aj,
                )
            else:
                report, outputs, warnings = run_bundle_pipeline(
                    wb.apk_paths,
                    wb.output_dir,
                    config=config,
                    search_plan=wb.plan,
                    analysis_job=aj,
                )

            for w in warnings or []:
                wb.log("WARN", str(w))

            wb.set_stage("reports")
            # Collect result paths
            results: list[dict[str, Any]] = []
            for key, p in (outputs or {}).items():
                if p and Path(p).is_file():
                    results.append({"role": key, "path": str(Path(p).resolve()), "label": Path(p).name})
            # Also index known report names under output_dir
            for pattern in ("report.json", "report.md", "*.json", "*.md"):
                for p in wb.output_dir.glob(pattern):
                    if p.is_file() and not any(r["path"] == str(p.resolve()) for r in results):
                        results.append({"role": "artifact", "path": str(p.resolve()), "label": p.name})

            findings_n = 0
            dex_n = None
            xref_n = None
            if hasattr(report, "findings"):
                findings_n = len([f for f in report.findings if getattr(f, "classification", None) != "REJECTED"])
                enrich_actual_from_report(aj, report)
            elif isinstance(report, dict):
                findings_n = len(report.get("findings") or [])

            mark_completed(aj, findings=findings_n, dex_contexts=dex_n, xrefs=xref_n)
            wb.complete_stage("reports")

            # Rewrite reports with final job sections when possible
            try:
                if hasattr(report, "analysis_job"):
                    report.analysis_job = aj.to_dict()
                    report.resource = aj.resource_report_section()
                    from apk_forensics.report_writer import write_json_report, write_markdown_report

                    json_path = outputs.get("json") if outputs else None
                    md_path = outputs.get("markdown") if outputs else None
                    if json_path:
                        write_json_report(report, Path(json_path))
                    if md_path:
                        write_markdown_report(report, Path(md_path))
            except Exception as exc:  # noqa: BLE001
                wb.log("WARN", f"Could not rewrite report job sections: {exc}")

            wb.set_stage("ui_snapshot")
            snap_path = self._build_job_snapshot(wb, report)
            if snap_path:
                wb.snapshot_path = str(snap_path)
                results.append({"role": "ui_snapshot", "path": str(snap_path), "label": snap_path.name})
                self.set_active_snapshot(snap_path)
            wb.complete_stage("ui_snapshot")

            # Mark remaining RUNNING/QUEUED enabled stages complete
            with wb._lock:
                for s in wb.stages:
                    if s["status"] == "RUNNING":
                        s["status"] = "COMPLETE"
                    elif s["status"] == "QUEUED":
                        # skipped because pipeline did not hit them
                        s["status"] = "SKIPPED"

            wb.results = results
            wb.status = "COMPLETE"
            wb.finished_at = utc_now_iso()
            if wb._t0 is not None:
                wb.elapsed_seconds = round(time.perf_counter() - wb._t0, 3)
            wb.log("INFO", f"COMPLETE elapsed={format_duration(wb.elapsed_seconds)}")
            wb.persist()
        except JobCancelLike as exc:
            mark_cancelled(aj, str(exc))
            wb.status = "CANCELLED"
            wb.error = str(exc)
            wb.finished_at = utc_now_iso()
            wb.log("INFO", f"CANCELLED: {exc}")
            wb.persist()
        except Exception as exc:  # noqa: BLE001
            from apk_forensics.analysis_job import JobCancelled

            if isinstance(exc, JobCancelled):
                mark_cancelled(aj, str(exc))
                wb.status = "CANCELLED"
            else:
                mark_failed(aj, type(exc).__name__)
                wb.status = "FAILED"
            wb.error = str(exc)
            wb.finished_at = utc_now_iso()
            if wb._t0 is not None:
                wb.elapsed_seconds = round(time.perf_counter() - wb._t0, 3)
            with wb._lock:
                for s in wb.stages:
                    if s["status"] == "RUNNING":
                        s["status"] = "FAILED"
            wb.log("ERROR", f"{type(exc).__name__}: {exc}")
            wb.persist()

    def _build_job_snapshot(self, wb: WorkbenchJob, report: Any) -> Path | None:
        """Best-effort UI snapshot from the job output + report fields."""
        try:
            from apk_forensics.ui.snapshot import build_ui_snapshot, write_ui_snapshot

            sources: dict[str, str] = {}
            report_json = wb.output_dir / "report.json"
            if report_json.is_file():
                sources["main_report"] = str(report_json.relative_to(self.root))
            # Prefer absolute via custom sources keys understood loosely by builder —
            # CASE_PRESETS may miss; builder still produces a minimal snapshot.
            snap = build_ui_snapshot(
                root=self.root,
                case=None,
                sources=sources or None,
                label=f"workbench:{wb.plan.plan_name}",
            )
            # Enrich APK identity from report when present
            apk = snap.setdefault("apk", {})
            if hasattr(report, "artifact"):
                art = report.artifact
                apk["package"] = getattr(art, "package_name", None) or apk.get("package")
                apk["version_name"] = getattr(art, "version_name", None) or apk.get("version_name")
                apk["sha256"] = getattr(art, "sha256", None) or wb.input_meta.get("sha256")
                apk["file"] = getattr(art, "file_name", None) or wb.input_meta.get("filename")
            elif isinstance(report, dict):
                art = report.get("artifact") or {}
                apk["package"] = art.get("package_name") or apk.get("package")
                apk["sha256"] = art.get("sha256") or wb.input_meta.get("sha256")
            apk["analyzer_version"] = __version__
            apk["git_commit"] = wb.provenance.get("git_commit")
            out = wb.output_dir / "analysis_ui_snapshot.json"
            write_ui_snapshot(snap, out)
            wb.log("INFO", f"UI snapshot written: {out.name}")
            return out
        except Exception as exc:  # noqa: BLE001
            wb.log("WARN", f"UI snapshot skipped: {exc}")
            return None


class JobCancelLike(Exception):
    pass
