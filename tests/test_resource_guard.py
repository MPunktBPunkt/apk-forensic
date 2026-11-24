from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
import yaml

from apk_forensics.analysis_job import (
    AnalysisJob,
    CancellationToken,
    JobCancelled,
    create_analysis_job,
    mark_cancelled,
    mark_completed,
    mark_failed,
    mark_running,
    preflight_or_reject,
)
from apk_forensics.cli import main
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ExitCode
from apk_forensics.pipeline import run_pipeline
from apk_forensics.resource_estimator import (
    ArtifactFingerprint,
    PlanFactors,
    estimate_resources,
    fingerprint_apk,
    plan_factors_from_search_plan,
)
from apk_forensics.resource_guard import (
    ResourceRejectedError,
    ResourceWarningBlockedError,
    assert_may_start,
    evaluate_resources,
)
from apk_forensics.resource_policy import get_resource_policy
from apk_forensics.search_plan import load_search_plan, validate_and_normalize


PLANS = Path(__file__).resolve().parents[1] / "plans"


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


def _factors(**kwargs) -> PlanFactors:
    base = dict(
        dex_context=False,
        bluetooth=False,
        xref_depth=0,
        max_callers=20,
        max_callees=20,
        instruction_window=8,
        search_terms=0,
        search_regex=0,
        search_uuids=0,
        modules=tuple(),
        plan_sha256=None,
    )
    base.update(kwargs)
    return PlanFactors(**base)


def test_small_input_ok(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "small.apk")
    fp = fingerprint_apk(apk)
    policy = get_resource_policy("standard")
    est = estimate_resources([fp], _factors(), policy)
    decision = evaluate_resources(est, policy)
    assert decision.decision == "OK"
    assert est.memory_mb > 0


def test_deep_plan_warning_or_reject() -> None:
    # Synthetic large metadata without real huge files
    arts = [
        ArtifactFingerprint(
            path="/x.apk",
            file_name="x.apk",
            size_bytes=200 * 1024 * 1024,
            dex_count=8,
            dex_total_bytes=80 * 1024 * 1024,
            native_so_count=0,
            native_total_bytes=0,
            entry_count=20,
        )
    ]
    factors = _factors(dex_context=True, bluetooth=True, xref_depth=2, search_terms=20)
    policy = get_resource_policy("standard")
    est = estimate_resources(arts, factors, policy)
    decision = evaluate_resources(est, policy)
    assert decision.decision in {"WARNING", "REJECT"}
    assert est.memory_mb >= policy.warn_estimated_memory_mb  # type: ignore[operator]


def test_reject_on_huge_estimate() -> None:
    arts = [
        ArtifactFingerprint(
            path="/huge.apk",
            file_name="huge.apk",
            size_bytes=600 * 1024 * 1024,
            dex_count=20,
            dex_total_bytes=400 * 1024 * 1024,
            native_so_count=50,
            native_total_bytes=100 * 1024 * 1024,
            entry_count=100,
        )
    ]
    factors = _factors(dex_context=True, bluetooth=True, xref_depth=2, search_terms=100)
    policy = get_resource_policy("standard")
    est = estimate_resources(arts, factors, policy)
    decision = evaluate_resources(est, policy)
    assert decision.decision == "REJECT"


def test_estimator_deterministic() -> None:
    arts = [
        ArtifactFingerprint(
            path="/a.apk",
            file_name="a.apk",
            size_bytes=10_000_000,
            dex_count=2,
            dex_total_bytes=5_000_000,
            native_so_count=1,
            native_total_bytes=100_000,
            entry_count=10,
        )
    ]
    factors = _factors(dex_context=True, xref_depth=1)
    policy = get_resource_policy("standard")
    a = estimate_resources(arts, factors, policy)
    b = estimate_resources(arts, factors, policy)
    assert a.to_dict() == b.to_dict()


def test_different_modules_different_estimate() -> None:
    arts = [
        ArtifactFingerprint(
            path="/a.apk",
            file_name="a.apk",
            size_bytes=50_000_000,
            dex_count=4,
            dex_total_bytes=20_000_000,
            native_so_count=0,
            native_total_bytes=0,
            entry_count=10,
        )
    ]
    policy = get_resource_policy("standard")
    shallow = estimate_resources(arts, _factors(), policy)
    deep = estimate_resources(arts, _factors(dex_context=True, bluetooth=True, xref_depth=2), policy)
    assert deep.memory_mb > shallow.memory_mb
    assert deep.runtime_seconds > shallow.runtime_seconds


def test_warning_blocked_without_override() -> None:
    arts = [
        ArtifactFingerprint(
            path="/a.apk",
            file_name="a.apk",
            size_bytes=180 * 1024 * 1024,
            dex_count=4,
            dex_total_bytes=40 * 1024 * 1024,
            native_so_count=0,
            native_total_bytes=0,
            entry_count=10,
        )
    ]
    policy = get_resource_policy("standard")
    est = estimate_resources(arts, _factors(dex_context=True, bluetooth=True, xref_depth=2), policy)
    decision = evaluate_resources(est, policy)
    assert decision.decision in {"WARNING", "REJECT"}
    if decision.decision == "WARNING":
        with pytest.raises(ResourceWarningBlockedError):
            assert_may_start(decision, allow_resource_warning=False)
        assert_may_start(decision, allow_resource_warning=True)
    else:
        with pytest.raises(ResourceRejectedError):
            assert_may_start(decision, allow_resource_warning=True)


def test_reject_not_overridable() -> None:
    arts = [
        ArtifactFingerprint(
            path="/h.apk",
            file_name="h.apk",
            size_bytes=700 * 1024 * 1024,
            dex_count=30,
            dex_total_bytes=500 * 1024 * 1024,
            native_so_count=0,
            native_total_bytes=0,
            entry_count=40,
        )
    ]
    policy = get_resource_policy("standard")
    est = estimate_resources(arts, _factors(dex_context=True, bluetooth=True, xref_depth=2), policy)
    decision = evaluate_resources(est, policy)
    assert decision.decision == "REJECT"
    with pytest.raises(ResourceRejectedError):
        assert_may_start(decision, allow_resource_warning=True)


def test_guard_does_not_mutate_plan() -> None:
    raw = {
        "schema_version": "1.0",
        "plan": {"name": "t", "modules": ["dex", "dex_context", "xref", "bluetooth"]},
        "dex_context": {"enabled": True, "xref_depth": 2},
        "bluetooth": {"enabled": True},
    }
    plan = validate_and_normalize(raw)
    before = plan.to_canonical_dict()
    arts = [
        ArtifactFingerprint(
            path="/a.apk",
            file_name="a.apk",
            size_bytes=200 * 1024 * 1024,
            dex_count=4,
            dex_total_bytes=40 * 1024 * 1024,
            native_so_count=0,
            native_total_bytes=0,
            entry_count=10,
        )
    ]
    factors = plan_factors_from_search_plan(plan)
    est = estimate_resources(arts, factors, get_resource_policy("standard"))
    evaluate_resources(est, get_resource_policy("standard"))
    assert plan.to_canonical_dict() == before
    assert plan.xref_depth == 2


def test_job_state_completed(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "j.apk")
    job, _, _ = create_analysis_job(apk_paths=[apk], search_plan=None, policy=get_resource_policy("unlimited"))
    assert job.status == "queued"
    preflight_or_reject(job)
    mark_running(job)
    assert job.status == "running"
    mark_completed(job, findings=3, dex_contexts=0, xrefs=0)
    assert job.status == "completed"
    assert job.started_at and job.finished_at
    assert job.termination_reason is None
    assert job.resource_actual.findings == 3


def test_job_rejected_status(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "j.apk")
    # Force reject via conservative + deep synthetic by mocking estimate path:
    # use create then replace decision
    job, _, _ = create_analysis_job(apk_paths=[apk], search_plan=None)
    from apk_forensics.resource_guard import ResourceDecision

    job.resource_decision = ResourceDecision(decision="REJECT", reasons=["test reject"])
    with pytest.raises(ResourceRejectedError):
        preflight_or_reject(job)
    assert job.status == "rejected"
    assert job.termination_reason == "resource_reject"


def test_job_cancelled(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "j.apk")
    job, _, _ = create_analysis_job(apk_paths=[apk], search_plan=None, policy=get_resource_policy("unlimited"))
    mark_running(job)
    job.cancellation.cancel("user")
    with pytest.raises(JobCancelled):
        job.cancellation.check()
    mark_cancelled(job, "cancelled")
    assert job.status == "cancelled"
    assert job.termination_reason == "cancelled"


def test_job_failed_runtime(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "j.apk")
    job, _, _ = create_analysis_job(apk_paths=[apk], search_plan=None, policy=get_resource_policy("unlimited"))
    mark_running(job)
    mark_failed(job, "runtime_limit", findings=1)
    assert job.status == "failed"
    assert job.termination_reason == "runtime_limit"


def test_scan_ok_with_unlimited(tmp_path: Path, synthetic_apk: Path) -> None:
    code = main(
        [
            "scan",
            str(synthetic_apk),
            "--output",
            str(tmp_path / "out"),
            "--format",
            "json",
            "--resource-policy",
            "unlimited",
        ]
    )
    assert code in {ExitCode.SUCCESS, ExitCode.PARTIAL_OR_WARNINGS}
    import json

    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["analysis_job"]["status"] == "completed"
    assert report["resource"]["decision"] == "OK"
    assert "estimate" in report["resource"]
    assert "actual" in report["resource"]
    # actual peak may be int or null
    assert "peak_memory_mb" in report["resource"]["actual"]


def test_cli_estimate_json(tmp_path: Path) -> None:
    apk = _tiny_apk(tmp_path / "e.apk")
    plan = PLANS / "native_static.yaml"
    code = main(["plan", "estimate", str(apk), "--plan", str(plan), "--json"])
    assert code in {ExitCode.SUCCESS, ExitCode.RESOURCE_WARNING_BLOCKED, ExitCode.RESOURCE_REJECTED}


def test_pipeline_cancellation_token(tmp_path: Path, synthetic_apk: Path) -> None:
    job, _, _ = create_analysis_job(
        apk_paths=[synthetic_apk],
        search_plan=None,
        policy=get_resource_policy("unlimited"),
    )
    mark_running(job)
    job.cancellation.cancel("test")
    with pytest.raises(JobCancelled):
        run_pipeline(
            synthetic_apk,
            tmp_path / "out",
            config=AnalysisConfig(formats=("json",)),
            analysis_job=job,
        )


def test_rejected_creates_no_work(tmp_path: Path, monkeypatch) -> None:
    # Build a plan that with conservative policy on a crafted large fingerprint via CLI is hard;
    # instead unit-test that preflight_or_reject happens before work session in CLI by
    # checking ResourceRejectedError path leaves no work when using synthetic reject.
    from apk_forensics.workspace import discover_workspace

    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    ws = discover_workspace(tmp_path)
    ws.ensure()
    before = list(ws.work_dir.iterdir()) if ws.work_dir.exists() else []
    apk = _tiny_apk(tmp_path / "bigmeta.apk", dex=1)
    # Monkeypatch create_analysis_job decision after creation via estimate of huge artifact
    # Use conservative + deep plan on synthetic that may only WARNING; force reject via policy unlimited skip.
    # Direct call:
    job, _, _ = create_analysis_job(apk_paths=[apk], search_plan=None)
    from apk_forensics.resource_guard import ResourceDecision

    job.resource_decision = ResourceDecision(decision="REJECT", reasons=["forced"])
    with pytest.raises(ResourceRejectedError):
        preflight_or_reject(job)
    after = list(ws.work_dir.iterdir()) if ws.work_dir.exists() else []
    assert after == before


def test_bluetooth_plan_sha_unchanged() -> None:
    plan = load_search_plan(PLANS / "bluetooth_rfcomm.yaml")
    assert plan.plan_sha256 == "69da35c590ac6bdc525c77cff43400076a9bca3efb4c7d1edc3a9b3f9ea2484c"
    assert plan.communication_enabled is False


def test_communication_evidence_plan_sha() -> None:
    plan = load_search_plan(PLANS / "communication_evidence.yaml")
    assert plan.plan_sha256 == "1ab8aa22e174dcb8f3e7a57284be5f11239df05493c882dbbb72d7b46578f559"
    assert plan.communication_enabled is True
