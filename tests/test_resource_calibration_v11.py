"""v1.1 resource estimator breakdown, calibration, coverage, guard semantics."""

from __future__ import annotations

from pathlib import Path

from apk_forensics.coverage_analysis import annotate_path_coverage, annotate_paths, classify_reason
from apk_forensics.resource_calibration import (
    compare_estimate_actual,
    extract_run_record,
    sensitivity_matrix,
)
from apk_forensics.resource_estimator import (
    ArtifactFingerprint,
    PlanFactors,
    estimate_resources,
)
from apk_forensics.resource_guard import assert_may_start, evaluate_resources
from apk_forensics.resource_policy import get_resource_policy
from apk_forensics.search_plan import load_search_plan
from apk_forensics.errors import ExitCode
from apk_forensics.resource_guard import ResourceRejectedError, ResourceWarningBlockedError

PLANS = Path(__file__).resolve().parents[1] / "plans"


def _art() -> ArtifactFingerprint:
    return ArtifactFingerprint(
        path="/a.apk",
        file_name="a.apk",
        size_bytes=20 * 1024 * 1024,
        dex_count=3,
        dex_total_bytes=10 * 1024 * 1024,
        native_so_count=2,
        native_total_bytes=1_000_000,
        entry_count=100,
    )


def _factors(**overrides) -> PlanFactors:
    base = dict(
        dex_context=True,
        bluetooth=True,
        xref_depth=2,
        max_callers=20,
        max_callees=20,
        instruction_window=8,
        search_terms=10,
        search_regex=1,
        search_uuids=1,
        modules=("bluetooth",),
        plan_sha256=None,
        bt_caller_depth=2,
        bt_dataflow_depth=3,
        bt_max_dataflow_nodes=200,
        bt_reconstruct_callers=True,
        bt_reconstruct_streams=True,
        bt_interprocedural=True,
        bt_max_method_hops=3,
        bt_max_field_hops=2,
        bt_max_object_nodes=500,
        evidence_graph=True,
        evidence_graph_max_paths=50,
        communication=False,
        communication_max_paths=0,
        communication_max_buffer_hops=0,
    )
    base.update(overrides)
    return PlanFactors(**base)


def test_estimate_deterministic_and_has_breakdown() -> None:
    policy = get_resource_policy("standard")
    a = estimate_resources([_art()], _factors(), policy)
    b = estimate_resources([_art()], _factors(), policy)
    assert a.to_dict() == b.to_dict()
    assert a.breakdown
    comps = a.breakdown["components"]
    assert any(c["name"] == "TOTAL" for c in comps)
    total = next(c for c in comps if c["name"] == "TOTAL")
    assert total["memory_mb"] == a.memory_mb
    assert total["runtime_seconds"] == a.runtime_seconds


def test_method_hops_change_cost() -> None:
    policy = get_resource_policy("standard")
    e1 = estimate_resources([_art()], _factors(bt_max_method_hops=1), policy)
    e3 = estimate_resources([_art()], _factors(bt_max_method_hops=3), policy)
    assert e3.memory_mb >= e1.memory_mb
    assert e3.runtime_seconds >= e1.runtime_seconds


def test_object_nodes_change_cost() -> None:
    policy = get_resource_policy("standard")
    e100 = estimate_resources([_art()], _factors(bt_max_object_nodes=100), policy)
    e500 = estimate_resources([_art()], _factors(bt_max_object_nodes=500), policy)
    assert e500.memory_mb >= e100.memory_mb
    assert e500.runtime_seconds >= e100.runtime_seconds


def test_communication_and_evidence_graph_toggle() -> None:
    policy = get_resource_policy("standard")
    base = estimate_resources([_art()], _factors(), policy)
    with_eg = estimate_resources([_art()], _factors(evidence_graph=True), policy)
    with_comm = estimate_resources(
        [_art()],
        _factors(communication=True, communication_max_paths=100, communication_max_buffer_hops=5),
        policy,
    )
    assert with_eg.memory_mb >= base.memory_mb
    assert with_comm.memory_mb > base.memory_mb
    assert with_comm.runtime_seconds > base.runtime_seconds


def test_compare_estimate_actual_ratios() -> None:
    cmp_ = compare_estimate_actual(
        {"memory_mb": 1741, "runtime_seconds": 631},
        {"peak_memory_mb": 1149, "runtime_seconds": 319.014},
    )
    assert cmp_["memory"]["actual_over_estimate"] == round(1149 / 1741, 4)
    assert cmp_["runtime"]["actual_over_estimate"] == round(319.014 / 631, 4)


def test_coverage_complete_vs_truncated_vs_boundary() -> None:
    complete = annotate_path_coverage(
        {
            "direction": "INBOUND",
            "steps": [
                {"node_type": "INPUT_READ", "classification": "FACT"},
                {"node_type": "BYTE_ARRAY", "classification": "FACT"},
                {"node_type": "DECODER", "classification": "INFERENCE"},
                {"node_type": "MESSAGE_OBJECT", "classification": "FACT"},
            ],
            "boundaries": [],
            "classification": "INFERENCE",
        }
    )
    assert complete["coverage"]["status"] == "COMPLETE"
    assert complete["classification"] == "INFERENCE"  # unchanged

    trunc = annotate_path_coverage(
        {
            "direction": "INBOUND",
            "steps": [
                {"node_type": "INPUT_READ", "classification": "FACT"},
                {"node_type": "BYTE_ARRAY", "classification": "FACT"},
            ],
            "boundaries": [{"reason": "max_method_hops"}],
            "classification": "INFERENCE",
        }
    )
    assert trunc["coverage"]["status"] == "TRUNCATED"
    assert trunc["coverage"]["reason"] == "MAX_METHOD_HOPS"
    assert trunc["steps"][0]["classification"] == "FACT"

    bound = annotate_path_coverage(
        {
            "direction": "INBOUND",
            "steps": [
                {"node_type": "INPUT_READ", "classification": "FACT"},
                {"node_type": "BYTE_ARRAY", "classification": "FACT"},
            ],
            "boundaries": [{"reason": "UNKNOWN_HELPER"}],
            "classification": "INFERENCE",
        }
    )
    assert bound["coverage"]["status"] == "BOUNDARY"
    assert bound["coverage"]["reason"] == "UNKNOWN_HELPER"

    native = annotate_path_coverage(
        {
            "direction": "INBOUND",
            "steps": [{"node_type": "INPUT_READ", "classification": "FACT"}],
            "boundaries": [{"reason": "NATIVE"}],
        }
    )
    assert native["coverage"]["status"] == "BOUNDARY"
    assert classify_reason(native["coverage"]["reason"]) == "BOUNDARY"

    retention = annotate_path_coverage(
        {
            "direction": "INBOUND",
            "steps": [
                {"node_type": "INPUT_READ", "classification": "FACT"},
                {"node_type": "BYTE_ARRAY", "classification": "FACT"},
            ],
            "boundaries": [],
        },
        retention_capped=True,
    )
    assert retention["coverage"]["status"] == "TRUNCATED"
    assert retention["coverage"]["reason"] == "METHOD_RETENTION_CAP"


def test_annotate_paths_summary() -> None:
    paths, summary = annotate_paths(
        [
            {
                "direction": "OUTBOUND",
                "steps": [
                    {"node_type": "SERIALIZER", "classification": "FACT"},
                    {"node_type": "BYTE_ARRAY", "classification": "FACT"},
                    {"node_type": "OUTPUT_WRITE", "classification": "FACT"},
                ],
                "boundaries": [],
            }
        ]
    )
    assert summary["complete"] == 1
    assert paths[0]["coverage_status"] == "COMPLETE"


def test_guard_ok_warning_reject_override() -> None:
    policy = get_resource_policy("standard")
    # Force OK with shallow factors on tiny art
    tiny = ArtifactFingerprint(
        path="/t.apk",
        file_name="t.apk",
        size_bytes=1024,
        dex_count=0,
        dex_total_bytes=0,
        native_so_count=0,
        native_total_bytes=0,
        entry_count=1,
    )
    ok_est = estimate_resources(
        [tiny],
        PlanFactors(
            dex_context=False,
            bluetooth=False,
            xref_depth=0,
            max_callers=1,
            max_callees=1,
            instruction_window=1,
            search_terms=0,
            search_regex=0,
            search_uuids=0,
            modules=tuple(),
            plan_sha256=None,
        ),
        policy,
    )
    ok_dec = evaluate_resources(ok_est, policy)
    assert ok_dec.decision == "OK"
    assert_may_start(ok_dec, allow_resource_warning=False)

    warn_est = estimate_resources([_art()], _factors(communication=True, communication_max_buffer_hops=5, communication_max_paths=100), policy)
    warn_dec = evaluate_resources(warn_est, policy)
    if warn_dec.decision == "WARNING":
        try:
            assert_may_start(warn_dec, allow_resource_warning=False)
            raise AssertionError("expected block")
        except ResourceWarningBlockedError:
            pass
        assert_may_start(warn_dec, allow_resource_warning=True)

    # REJECT cannot be overridden
    big = ArtifactFingerprint(
        path="/b.apk",
        file_name="b.apk",
        size_bytes=200 * 1024 * 1024,
        dex_count=8,
        dex_total_bytes=80 * 1024 * 1024,
        native_so_count=40,
        native_total_bytes=40_000_000,
        entry_count=500,
    )
    rej_est = estimate_resources([big], _factors(xref_depth=2, communication=True, communication_max_buffer_hops=5, communication_max_paths=100), policy)
    rej_dec = evaluate_resources(rej_est, policy)
    assert rej_dec.decision == "REJECT"
    try:
        assert_may_start(rej_dec, allow_resource_warning=True)
        raise AssertionError("REJECT must not be overridable")
    except ResourceRejectedError as exc:
        assert exc.exit_code == ExitCode.RESOURCE_REJECTED


def test_extract_run_record_unknowns() -> None:
    rec = extract_run_record({"tool": {"version": "1.0.0"}, "resource": {}}, label="empty")
    assert rec["estimate_memory_mb"] == "UNKNOWN"
    assert rec["engine_version"] == "1.0.0"


def test_sensitivity_matrix_runs() -> None:
    plan = load_search_plan(PLANS / "communication_evidence.yaml")
    sens = sensitivity_matrix(_art(), plan)
    assert "max_method_hops" in sens["sweeps"]
    assert len(sens["sweeps"]["max_method_hops"]) == 3
    assert len(sens["sweeps"]["communication"]) == 2


def test_provenance_fields_in_estimate_dict() -> None:
    est = estimate_resources([_art()], _factors(), get_resource_policy("standard"))
    d = est.to_dict()
    assert "breakdown" in d
    assert d["factors"]["calibration"]["applied_to_totals"] is False
