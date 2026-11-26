"""Local stdlib HTTP server: Forensic Explorer + Analysis Workbench APIs.

Orchestrates existing analyzer APIs. Does not invent evidence.
Default bind: 127.0.0.1. Upload/job routes are local-only by design.
"""

from __future__ import annotations

import json
import re
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from apk_forensics.errors import ApkForensicsError, InputError
from apk_forensics.resource_guard import ResourceRejectedError, ResourceWarningBlockedError
from apk_forensics.search_plan import PlanValidationError
from apk_forensics.ui.workbench import WorkbenchController, plan_criteria_view

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Shared server state (set by serve_ui)
_CTRL: WorkbenchController | None = None
_SNAPSHOT_PAYLOAD: bytes = b"{}"
_SNAPSHOT_PATH: Path | Path = Path("<none>")
_HOST: str = "127.0.0.1"


def _json_bytes(obj: Any, status: int = 200) -> tuple[int, bytes, str]:
    data = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
    return status, data, "application/json; charset=utf-8"


def _error(status: int, code: str, message: str, **extra: Any) -> tuple[int, bytes, str]:
    payload = {"ok": False, "error": code, "message": message, **extra}
    return _json_bytes(payload, status=status)


def _read_json_body(handler: SimpleHTTPRequestHandler, max_bytes: int = 8_000_000) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    if length > max_bytes:
        raise InputError("Request body too large")
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"Invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError("JSON body must be an object")
    return data


def _parse_multipart(handler: SimpleHTTPRequestHandler, max_bytes: int = 600_000_000) -> tuple[str, bytes]:
    ctype = handler.headers.get("Content-Type", "")
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        raise InputError("Empty upload")
    if length > max_bytes:
        raise InputError("Upload too large")
    body = handler.rfile.read(length)
    if "multipart/form-data" in ctype:
        m = re.search(r"boundary=([^\s;]+)", ctype)
        if not m:
            raise InputError("multipart boundary missing")
        boundary = m.group(1).strip().strip('"').encode("ascii", errors="ignore")
        parts = body.split(b"--" + boundary)
        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            header, _, content = part.partition(b"\r\n\r\n")
            if not content:
                continue
            if content.endswith(b"\r\n"):
                content = content[:-2]
            if b"filename=" not in header:
                continue
            hm = re.search(br'filename="([^"]*)"', header)
            filename = hm.group(1).decode("utf-8", errors="replace") if hm else "upload.apk"
            return filename, content
        raise InputError("No file part in multipart body")
    # Raw body with X-Filename
    filename = handler.headers.get("X-Filename") or "upload.apk"
    return filename, body


class ForensicUIHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json_tuple(self, tup: tuple[int, bytes, str]) -> None:
        self._send(*tup)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in {"/api/snapshot", "/snapshot.json"}:
            data = _SNAPSHOT_PAYLOAD
            self._send(200, data, "application/json; charset=utf-8")
            return

        if path == "/api/meta":
            ctrl = _CTRL
            if ctrl is None:
                self._send_json_tuple(_error(503, "no_workbench", "Workbench not enabled"))
                return
            self._send_json_tuple(_json_bytes({"ok": True, **ctrl.meta()}))
            return

        if path == "/api/plans":
            ctrl = _CTRL
            if ctrl is None:
                self._send_json_tuple(_error(503, "no_workbench", "Workbench not enabled"))
                return
            self._send_json_tuple(_json_bytes({"ok": True, "plans": ctrl.meta()["plans"]}))
            return

        if path.startswith("/api/plans/") and path.endswith("/criteria"):
            ctrl = _CTRL
            if ctrl is None:
                self._send_json_tuple(_error(503, "no_workbench", "Workbench not enabled"))
                return
            plan_id = unquote(path[len("/api/plans/") : -len("/criteria")])
            try:
                _path, plan = ctrl.load_plan(plan_id)
                self._send_json_tuple(
                    _json_bytes(
                        {
                            "ok": True,
                            "plan": {
                                "name": plan.plan_name,
                                "sha256": plan.plan_sha256,
                                "description": plan.plan_description,
                                "criteria": plan_criteria_view(plan),
                            },
                        }
                    )
                )
            except Exception as exc:  # noqa: BLE001
                self._send_json_tuple(_error(400, "plan_error", str(exc)))
            return

        if path.startswith("/api/jobs/") and path.endswith("/status"):
            job_id = unquote(path[len("/api/jobs/") : -len("/status")])
            return self._job_status(job_id)

        if path.startswith("/api/jobs/") and not path.endswith("/status"):
            # /api/jobs/<id>
            rest = path[len("/api/jobs/") :]
            if "/" not in rest and rest:
                return self._job_status(unquote(rest))

        if path == "/api/result":
            return self._serve_result(qs)

        if path in {"/", "/index.html"}:
            self.path = "/index.html"
            return SimpleHTTPRequestHandler.do_GET(self)

        return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        ctrl = _CTRL
        if ctrl is None:
            self._send_json_tuple(_error(503, "no_workbench", "Workbench not enabled"))
            return
        try:
            if path == "/api/upload":
                filename, data = _parse_multipart(self)
                meta = ctrl.save_upload(filename, data)
                self._send_json_tuple(_json_bytes({"ok": True, "input": meta}))
                return
            body = _read_json_body(self)
            if path == "/api/validate":
                paths = body.get("paths") or []
                if isinstance(paths, str):
                    paths = [paths]
                if not paths:
                    raise InputError("paths required")
                meta = ctrl.validate_server_paths([str(p) for p in paths])
                self._send_json_tuple(_json_bytes({"ok": True, "input": meta}))
                return
            if path == "/api/estimate":
                result = ctrl.estimate(
                    apk_paths=[str(p) for p in (body.get("apk_paths") or [])],
                    plan_id=str(body.get("plan_id") or ""),
                    resource_policy=str(body.get("resource_policy") or "standard"),
                    plan_overrides=body.get("plan_overrides"),
                    allow_resource_warning=bool(body.get("allow_resource_warning")),
                )
                self._send_json_tuple(_json_bytes({"ok": True, **result}))
                return
            if path == "/api/plans/suggest":
                result = ctrl.suggest_plan(
                    str(body.get("goal") or body.get("investigation_goal") or ""),
                    plan_name=body.get("plan_name"),
                    depth=str(body.get("depth") or "standard"),
                )
                self._send_json_tuple(_json_bytes(result))
                return
            if path == "/api/plans/validate":
                raw = body.get("raw") or body.get("plan")
                if raw is None and body.get("form"):
                    result = ctrl.preview_plan_form(body["form"])
                elif isinstance(raw, dict):
                    result = ctrl.validate_plan_raw(raw)
                    result["raw"] = raw
                else:
                    raise InputError("raw plan object or form required")
                self._send_json_tuple(_json_bytes(result))
                return
            if path == "/api/plans/preview":
                if body.get("form"):
                    result = ctrl.preview_plan_form(body["form"])
                elif isinstance(body.get("raw"), dict):
                    result = ctrl.validate_plan_raw(body["raw"])
                    result["raw"] = body["raw"]
                else:
                    raise InputError("form or raw required")
                self._send_json_tuple(_json_bytes(result))
                return
            if path == "/api/plans/save":
                raw = body.get("raw")
                if not isinstance(raw, dict):
                    if body.get("form"):
                        from apk_forensics.ui.plan_builder import build_raw_from_builder_form

                        raw = build_raw_from_builder_form(body["form"])
                    else:
                        raise InputError("raw plan object required")
                result = ctrl.save_plan(
                    raw,
                    provenance=body.get("provenance"),
                    overwrite=bool(body.get("overwrite")),
                )
                self._send_json_tuple(_json_bytes(result))
                return
            if path == "/api/plans/clone":
                result = ctrl.clone_builtin_plan(
                    str(body.get("plan_id") or ""),
                    new_name=str(body.get("new_name") or ""),
                    goal_note=body.get("goal_note"),
                )
                self._send_json_tuple(_json_bytes(result))
                return
            if path == "/api/jobs/start":
                wb = ctrl.start_job(
                    apk_paths=[str(p) for p in (body.get("apk_paths") or [])],
                    plan_id=str(body.get("plan_id") or ""),
                    resource_policy=str(body.get("resource_policy") or "standard"),
                    plan_overrides=body.get("plan_overrides"),
                    allow_resource_warning=bool(body.get("allow_resource_warning")),
                    confirm_warning=bool(body.get("confirm_warning")),
                )
                self._send_json_tuple(_json_bytes({"ok": True, "job": wb.to_dict()}))
                return
            if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                job_id = unquote(path[len("/api/jobs/") : -len("/cancel")])
                wb = ctrl.cancel_job(job_id)
                self._send_json_tuple(_json_bytes({"ok": True, "job": wb.to_dict()}))
                return
            self._send_json_tuple(_error(404, "not_found", f"Unknown API path: {path}"))
        except ResourceRejectedError as exc:
            self._send_json_tuple(
                _error(
                    403,
                    "RESOURCE_REJECT",
                    str(exc),
                    decision=exc.decision.to_dict() if exc.decision else None,
                )
            )
        except ResourceWarningBlockedError as exc:
            self._send_json_tuple(
                _error(
                    409,
                    "RESOURCE_WARNING",
                    str(exc),
                    decision=exc.decision.to_dict() if exc.decision else None,
                    requires_confirm=True,
                )
            )
        except PlanValidationError as exc:
            self._send_json_tuple(_error(400, "plan_error", str(exc)))
        except (InputError, ApkForensicsError, PermissionError, FileNotFoundError, ValueError) as exc:
            self._send_json_tuple(_error(400, type(exc).__name__, str(exc)))
        except Exception as exc:  # noqa: BLE001
            self._send_json_tuple(_error(500, "internal", str(exc)))

    def _job_status(self, job_id: str) -> None:
        ctrl = _CTRL
        if ctrl is None:
            self._send_json_tuple(_error(503, "no_workbench", "Workbench not enabled"))
            return
        job = ctrl.get_job(job_id)
        if job is None:
            # try load from disk
            matches = list(ctrl.jobs_dir.glob(f"*-{job_id[:12]}")) + list(ctrl.jobs_dir.glob(f"*{job_id}*"))
            for d in matches:
                jp = d / "workbench_job.json"
                if jp.is_file():
                    data = json.loads(jp.read_text(encoding="utf-8"))
                    self._send_json_tuple(_json_bytes({"ok": True, "job": data}))
                    return
            self._send_json_tuple(_error(404, "not_found", f"Unknown job: {job_id}"))
            return
        self._send_json_tuple(_json_bytes({"ok": True, "job": job.to_dict()}))

    def _serve_result(self, qs: dict[str, list[str]]) -> None:
        ctrl = _CTRL
        if ctrl is None:
            self._send_json_tuple(_error(503, "no_workbench", "Workbench not enabled"))
            return
        raw = (qs.get("path") or [None])[0]
        if not raw:
            self._send_json_tuple(_error(400, "missing_path", "path query required"))
            return
        # Reject obvious traversal tokens before resolve
        if ".." in raw.replace("\\", "/") or raw.startswith("/etc") or "\x00" in raw:
            # still allow absolute paths under workspace after resolve check
            pass
        try:
            candidate = Path(unquote(raw))
            if not candidate.is_absolute():
                candidate = (ctrl.root / candidate).resolve()
            allowed = ctrl.allowed_file(candidate)
            if not allowed.is_file():
                self._send_json_tuple(_error(404, "not_found", "File not found"))
                return
            data = allowed.read_bytes()
            ctype = "application/json; charset=utf-8" if allowed.suffix == ".json" else "text/plain; charset=utf-8"
            if allowed.suffix == ".md":
                ctype = "text/markdown; charset=utf-8"
            self._send(200, data, ctype)
        except PermissionError as exc:
            self._send_json_tuple(_error(403, "forbidden", str(exc)))
        except Exception as exc:  # noqa: BLE001
            self._send_json_tuple(_error(400, "result_error", str(exc)))


def serve_ui(
    *,
    snapshot: Path | dict[str, Any] | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    root: Path | None = None,
    workbench: bool = True,
) -> None:
    global _CTRL, _SNAPSHOT_PAYLOAD, _SNAPSHOT_PATH, _HOST

    _HOST = host
    if isinstance(snapshot, dict):
        _SNAPSHOT_PAYLOAD = json.dumps(snapshot, indent=2, ensure_ascii=False).encode("utf-8")
        _SNAPSHOT_PATH = Path("<memory>")
    elif snapshot is not None:
        snap_path = Path(snapshot).resolve()
        if not snap_path.is_file():
            raise FileNotFoundError(f"Snapshot not found: {snap_path}")
        _SNAPSHOT_PATH = snap_path
        _SNAPSHOT_PAYLOAD = snap_path.read_bytes()
    else:
        _SNAPSHOT_PATH = Path("<none>")
        _SNAPSHOT_PAYLOAD = json.dumps(
            {
                "schema": "apk_forensics.analysis_ui_snapshot.v1",
                "label": "No snapshot loaded",
                "apk": {},
                "analysis_status": {},
                "pipeline_stages": [],
                "counters": {},
                "nodes": [],
                "edges": [],
                "values": [],
                "open_edges": [],
                "runtime_wire": {},
                "correlation_graph": {"full_chain_present": False, "nodes": [], "edges": []},
                "knowledge": {"proven_facts": [], "not_proven": [], "missing_input": []},
                "timeline": [],
                "sources": [],
                "next_experiment": {
                    "title": "NEXT REQUIRED EXPERIMENT",
                    "summary": "Load a snapshot or run New Analysis.",
                    "classification": "GUIDANCE",
                },
                "closing_assessment": {},
                "content_sha256": "",
            },
            indent=2,
        ).encode("utf-8")

    if workbench:
        repo_root = Path(root).resolve() if root else Path.cwd().resolve()
        _CTRL = WorkbenchController(repo_root)
        _CTRL.bind_host = host
        if _SNAPSHOT_PATH not in {Path("<memory>"), Path("<none>")} and Path(_SNAPSHOT_PATH).is_file():
            _CTRL.set_active_snapshot(Path(_SNAPSHOT_PATH))
            _SNAPSHOT_PAYLOAD = _CTRL.active_snapshot_payload or _SNAPSHOT_PAYLOAD
    else:
        _CTRL = None

    httpd = ThreadingHTTPServer((host, port), ForensicUIHandler)
    mode = "Workbench + Explorer" if workbench else "Explorer (read-only)"
    print(f"Forensic UI ({mode}): http://{host}:{port}/")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        print("WARNING: bound beyond 127.0.0.1 — upload/job APIs are network-reachable.")
    print(f"Snapshot: {_SNAPSHOT_PATH}")
    if workbench and _CTRL is not None:
        print(f"Root: {_CTRL.root}")
        print("Static APK analysis only — does not execute the Android app.")
    print("Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
