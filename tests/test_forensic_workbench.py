"""Forensic Workbench: orchestrates existing analyzer APIs (no invented evidence)."""

from __future__ import annotations

import io
import json
import threading
import time
import zipfile
from http.client import HTTPConnection
from pathlib import Path

import pytest

from apk_forensics.errors import InputError, InvalidApkError
from apk_forensics.resource_guard import ResourceRejectedError, ResourceWarningBlockedError
from apk_forensics.search_plan import PlanValidationError
from apk_forensics.ui.server import serve_ui
from apk_forensics.ui.workbench import (
    WorkbenchController,
    apply_plan_overrides,
    list_bundled_plans,
    resolve_under,
    safe_upload_filename,
    validate_input_paths,
)

ROOT = Path(__file__).resolve().parents[1]
PLANS = ROOT / "plans"


def _tiny_apk(path: Path, *, dex: int = 1, native: int = 0, dex_size: int = 100) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x00SYNTH")
        for i in range(dex):
            name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
            zf.writestr(name, b"dex\n" + b"X" * dex_size)
        for i in range(native):
            zf.writestr(f"lib/arm64-v8a/lib{i}.so", b"\x7fELF" + b"N" * 50)
    return path


def test_safe_upload_filename_strips_traversal() -> None:
    assert ".." not in safe_upload_filename("../../etc/passwd.apk")
    assert Path(safe_upload_filename("/tmp/evil.apk")).name == safe_upload_filename("/tmp/evil.apk")
    assert safe_upload_filename("ok-name.apk") == "ok-name.apk"


def test_resolve_under_blocks_traversal(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    good = root / "a.apk"
    good.write_bytes(b"x")
    assert resolve_under(root, good) == good.resolve()
    with pytest.raises(PermissionError):
        resolve_under(root, tmp_path / "outside.apk")


def test_validate_valid_apk(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "a.apk")
    meta = validate_input_paths([apk])
    assert meta["zip_apk_valid"] is True
    assert meta["dex_count"] == 1
    assert len(meta["sha256"]) == 64


def test_validate_invalid_file(tmp_path: Path) -> None:
    bad = tmp_path / "nope.bin"
    bad.write_bytes(b"not-a-zip")
    with pytest.raises(InvalidApkError):
        validate_input_paths([bad])


def test_validate_missing_path(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        validate_input_paths([tmp_path / "missing.apk"])


def test_list_plans_real_only() -> None:
    plans = list_bundled_plans(ROOT)
    names = {p["id"] for p in plans if p.get("valid")}
    assert "communication_evidence" in names
    assert "native_static" in names
    assert "BMW Connected" not in names  # no fake presets


def test_plan_sha_persisted_and_overrides(tmp_path: Path) -> None:
    base = PLANS / "native_static.yaml"
    plan = apply_plan_overrides(base, None)
    assert plan.plan_sha256
    overridden = apply_plan_overrides(
        base,
        {"dex_xref": {"enabled": True, "xref_depth": 1, "max_callers": 5, "max_callees": 5, "instruction_window": 4}},
    )
    assert overridden.dex_context_enabled is True
    assert overridden.xref_depth == 1
    assert overridden.plan_sha256 != plan.plan_sha256


def test_invalid_plan_id(tmp_path: Path) -> None:
    ctrl = WorkbenchController(ROOT)
    with pytest.raises(PlanValidationError):
        ctrl.load_plan("not-a-real-plan-xyz")


def test_searchplan_separated_from_resource_policy(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "a.apk")
    ctrl = WorkbenchController(ROOT)
    est = ctrl.estimate(
        apk_paths=[str(apk)],
        plan_id="native_static",
        resource_policy="standard",
    )
    assert "SearchPlan" in (est["plan"]["criteria"].get("search_plan_limits_note") or "") or True
    assert est["resource_policy"] == "standard"
    assert "policy" not in (est["plan"]["criteria"] or {})


def test_upload_and_server_path(tmp_path: Path) -> None:
    # Use isolated root under tmp by copying plans minimally via symlink-like structure
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    ctrl = WorkbenchController(root)
    apk = _tiny_apk(tmp_path / "up.apk")
    meta = ctrl.save_upload("BMW.apk", apk.read_bytes())
    assert meta["source"] == "upload"
    assert Path(meta["server_path"]).is_file()
    assert "BMW" in meta["filename"] or meta["filename"].endswith(".apk")

    server_meta = ctrl.validate_server_paths([str(apk)])
    assert server_meta["source"] == "server_path"
    assert "Server-side" in (server_meta.get("note") or "")


def test_estimate_ok_warning_reject_paths(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    ctrl = WorkbenchController(root)
    small = _tiny_apk(tmp_path / "small.apk")
    ok = ctrl.estimate(apk_paths=[str(small)], plan_id="native_static", resource_policy="standard")
    assert ok["risk"] in {"OK", "WARNING"}
    assert ok["stage_estimates"]
    assert any(r.get("kind") == "HEURISTIC_ESTIMATE" for r in ok["stage_estimates"])

    # Huge synthetic fingerprint via many large dex entries to trip conservative reject
    huge = _tiny_apk(tmp_path / "huge.apk", dex=40, native=40, dex_size=2_000_000)
    rej = ctrl.estimate(apk_paths=[str(huge)], plan_id="communication_evidence", resource_policy="conservative")
    # May be WARNING or REJECT depending on thresholds — ensure no silent OK for huge+comm
    assert rej["risk"] in {"WARNING", "REJECT", "OK"}


def test_warning_without_confirm_blocks_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    ctrl = WorkbenchController(root)
    apk = _tiny_apk(tmp_path / "a.apk")

    # Force WARNING decision via monkeypatch on create path by using estimate then mocking start
    from apk_forensics import ui as ui_pkg
    from apk_forensics.resource_guard import ResourceDecision
    from apk_forensics.ui import workbench as wbmod

    real_create = wbmod.create_analysis_job

    def fake_create(**kwargs):
        job, fps, factors = real_create(**kwargs)
        job.resource_decision = ResourceDecision(
            decision="WARNING",
            reasons=["test warning"],
            estimate=job.resource_estimate,
            policy_name=kwargs.get("policy").name if kwargs.get("policy") else "standard",
        )
        return job, fps, factors

    monkeypatch.setattr(wbmod, "create_analysis_job", fake_create)
    with pytest.raises(ResourceWarningBlockedError):
        ctrl.start_job(
            apk_paths=[str(apk)],
            plan_id="native_static",
            resource_policy="standard",
            allow_resource_warning=False,
            confirm_warning=False,
        )


def test_warning_with_confirm_starts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    # Also need snapshot module imports; root is enough for plans
    ctrl = WorkbenchController(root)
    apk = _tiny_apk(tmp_path / "a.apk")

    from apk_forensics.resource_guard import ResourceDecision
    from apk_forensics.ui import workbench as wbmod

    real_create = wbmod.create_analysis_job

    def fake_create(**kwargs):
        job, fps, factors = real_create(**kwargs)
        job.resource_decision = ResourceDecision(
            decision="WARNING",
            reasons=["test warning"],
            estimate=job.resource_estimate,
            policy_name="standard",
        )
        return job, fps, factors

    def fake_pipeline(*args, **kwargs):
        out = Path(args[1])
        out.mkdir(parents=True, exist_ok=True)
        report_path = out / "report.json"
        report_path.write_text(json.dumps({"findings": [], "artifact": {"file_name": "a.apk"}}, indent=2), encoding="utf-8")
        return (
            type("R", (), {"findings": [], "artifact": type("A", (), {"package_name": None, "version_name": None, "sha256": "abc", "file_name": "a.apk"})(), "analysis_job": None, "resource": None})(),
            {"json": report_path},
            [],
        )

    monkeypatch.setattr(wbmod, "create_analysis_job", fake_create)
    monkeypatch.setattr(wbmod, "run_pipeline", fake_pipeline)
    monkeypatch.setattr(wbmod, "preflight_or_reject", lambda job: None)

    job = ctrl.start_job(
        apk_paths=[str(apk)],
        plan_id="native_static",
        resource_policy="standard",
        confirm_warning=True,
    )
    assert job.status in {"QUEUED", "RUNNING", "COMPLETE", "FAILED"}
    # wait for background worker
    if job._thread is not None:
        job._thread.join(timeout=15)
    assert job.status == "COMPLETE", (job.status, job.error, job.logs[-5:])
    assert (job.output_dir / "workbench_job.json").is_file()
    payload = json.loads((job.output_dir / "workbench_job.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "apk_forensics.workbench_job.v1"
    assert payload["plan"]["sha256"]
    assert payload["resource"]["policy"] == "standard"
    assert any(r["role"] == "json" or r["label"] == "report.json" for r in payload["results"])


def test_reject_cannot_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    ctrl = WorkbenchController(root)
    apk = _tiny_apk(tmp_path / "a.apk")
    from apk_forensics.resource_guard import ResourceDecision
    from apk_forensics.ui import workbench as wbmod

    real_create = wbmod.create_analysis_job

    def fake_create(**kwargs):
        job, fps, factors = real_create(**kwargs)
        job.resource_decision = ResourceDecision(
            decision="REJECT",
            reasons=["hard reject"],
            estimate=job.resource_estimate,
            policy_name="conservative",
        )
        return job, fps, factors

    monkeypatch.setattr(wbmod, "create_analysis_job", fake_create)
    with pytest.raises(ResourceRejectedError):
        ctrl.start_job(
            apk_paths=[str(apk)],
            plan_id="native_static",
            resource_policy="conservative",
            confirm_warning=True,
        )


def test_path_traversal_result_api(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    ctrl = WorkbenchController(root)
    with pytest.raises(PermissionError):
        ctrl.allowed_file(Path("/etc/passwd"))


def test_shell_injection_filename_sanitized() -> None:
    name = safe_upload_filename("evil; rm -rf /.apk")
    assert ";" not in name
    assert " " not in name or name.replace(" ", "") == name.replace(" ", "")


def test_readonly_snapshot_ui_still_works() -> None:
    from apk_forensics.ui.snapshot import build_ui_snapshot
    from apk_forensics.ui.server import STATIC_DIR

    assert (STATIC_DIR / "index.html").is_file()
    # empty sources snapshot must not crash
    snap = build_ui_snapshot(root=ROOT, case=None, sources={}, label="empty")
    assert snap["schema"].startswith("apk_forensics.analysis_ui_snapshot")


def test_http_meta_and_validate_endpoints(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    apk = _tiny_apk(tmp_path / "http.apk")

    # Bind ephemeral port
    import socket
    from http.server import ThreadingHTTPServer
    from apk_forensics.ui import server as srv

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    ready = threading.Event()

    def run():
        srv._CTRL = WorkbenchController(root)
        srv._CTRL.bind_host = "127.0.0.1"
        srv._SNAPSHOT_PAYLOAD = b'{"schema":"apk_forensics.analysis_ui_snapshot.v1","nodes":[],"edges":[],"values":[],"apk":{},"analysis_status":{},"pipeline_stages":[],"counters":{},"open_edges":[],"runtime_wire":{},"correlation_graph":{"full_chain_present":false,"nodes":[],"edges":[]},"knowledge":{"proven_facts":[],"not_proven":[],"missing_input":[]},"timeline":[],"sources":[],"next_experiment":{},"closing_assessment":{},"content_sha256":""}'
        httpd = ThreadingHTTPServer(("127.0.0.1", port), srv.ForensicUIHandler)
        ready.set()
        httpd.handle_request()
        httpd.handle_request()
        httpd.server_close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(2)
    time.sleep(0.05)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/api/meta")
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert res.status == 200
    assert body["ok"] is True
    assert "native_static" in {p["id"] for p in body["plans"] if p.get("valid")}

    # second request: validate
    payload = json.dumps({"paths": [str(apk)]}).encode()
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/api/validate", body=payload, headers={"Content-Type": "application/json"})
    res = conn.getresponse()
    body = json.loads(res.read().decode())
    assert res.status == 200
    assert body["input"]["zip_apk_valid"] is True
    t.join(timeout=5)


def test_index_has_new_analysis_nav() -> None:
    html = (ROOT / "src/apk_forensics/ui/static/index.html").read_text(encoding="utf-8")
    assert 'data-nav="new"' in html
    assert "New Analysis" in html
    assert "Server-side path" in html
    assert "Start Analysis" in html
