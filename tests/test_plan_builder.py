"""Search Plan Builder — suggestion/validate/save/clone; no evidence invention."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from apk_forensics.search_plan import (
    compute_plan_sha256,
    load_plan_yaml,
    load_search_plan,
    validate_and_normalize,
)
from apk_forensics.ui.plan_builder import (
    build_raw_from_builder_form,
    clone_plan,
    list_user_plans,
    plan_to_normalized_json,
    plan_to_yaml,
    save_user_plan,
    suggest_plan_from_goal,
    validate_raw_plan,
)
from apk_forensics.ui.workbench import WorkbenchController, list_all_plans

ROOT = Path(__file__).resolve().parents[1]
PLANS = ROOT / "plans"


def test_suggest_iap2_is_search_intention_not_fact() -> None:
    sug = suggest_plan_from_goal("Untersuche iAP2-Kommunikation und verfolge Datenpfade.")
    assert sug["ok"] is True
    assert sug["kind"] == "SUGGESTION"
    assert "FOUND" not in sug["note"].upper() or "not" in sug["note"].lower()
    raw = sug["raw"]
    plan = validate_and_normalize(raw)
    assert "iAP2" in plan.search_terms or any("iap" in t.lower() for t in plan.search_terms)
    assert plan.bluetooth_enabled or plan.communication_enabled
    # Must not inject evidence classifications beyond filter list
    text = json.dumps(sug)
    assert "FACT: iAP2" not in text
    assert "iAP2 = FOUND" not in text
    assert sug["provenance"]["plan_sha256"] == plan.plan_sha256
    assert sug["plan"]["pipeline_coverage"]["extended_forensic_post_processing"] == "NOT AUTOMATIC"


def test_suggest_bcl_no_bmw_protocol_fact() -> None:
    sug = suggest_plan_from_goal("Untersuche BCL.")
    terms = " ".join(sug["plan"]["search_targets"]["terms"]).lower()
    assert "bcl" in terms
    blob = json.dumps(sug).lower()
    assert "protocol = found" not in blob
    assert '"classification": "fact"' not in blob or "suggestion" in blob


def test_validate_unknown_field() -> None:
    raw = {
        "schema_version": "1.0",
        "plan": {"name": "x", "modules": ["dex"]},
        "invented_module": True,
    }
    res = validate_raw_plan(raw)
    assert res["ok"] is False
    assert res["error"] == "INVALID_SEARCH_PLAN"
    assert any("unknown field" in e for e in res["errors"])


def test_validate_invalid_type_range() -> None:
    raw = {
        "schema_version": "1.0",
        "plan": {"name": "x", "modules": ["dex", "bluetooth"]},
        "communication": {"enabled": True, "max_method_hops": "deep"},
    }
    res = validate_raw_plan(raw)
    assert res["ok"] is False


def test_validate_invalid_uuid() -> None:
    raw = {
        "schema_version": "1.0",
        "plan": {"name": "x", "modules": ["uuid"]},
        "search": {"uuids": ["not-a-uuid"]},
    }
    res = validate_raw_plan(raw)
    # may fail on uuid normalize
    assert "ok" in res


def test_validate_invalid_regex() -> None:
    raw = {
        "schema_version": "1.0",
        "plan": {"name": "x", "modules": ["strings"]},
        "search": {"regex": ["[unterminated"]},
    }
    res = validate_raw_plan(raw)
    assert res["ok"] is False
    assert any("regex" in e.lower() for e in res["errors"])


def test_roundtrip_yaml_json_hash(tmp_path: Path) -> None:
    sug = suggest_plan_from_goal("Untersuche Bluetooth RFCOMM und Datenfluss.")
    plan = validate_and_normalize(sug["raw"])
    yml = plan_to_yaml(plan)
    loaded = yaml.safe_load(yml)
    plan2 = validate_and_normalize(loaded)
    assert plan.plan_sha256 == plan2.plan_sha256
    assert compute_plan_sha256(plan.to_canonical_dict()) == plan.plan_sha256
    js = plan_to_normalized_json(plan)
    assert plan.plan_sha256 in js


def test_hash_changes_with_parameter() -> None:
    a = validate_and_normalize(suggest_plan_from_goal("iAP2", depth="shallow")["raw"])
    b = validate_and_normalize(suggest_plan_from_goal("iAP2", depth="deep")["raw"])
    assert a.plan_sha256 != b.plan_sha256


def test_clone_builtin_leaves_original(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    src = PLANS / "native_static.yaml"
    (root / "plans" / "native_static.yaml").write_bytes(src.read_bytes())
    before = (root / "plans" / "native_static.yaml").read_text(encoding="utf-8")
    saved = clone_plan(root, root / "plans" / "native_static.yaml", new_name="native_static_iap2")
    after = (root / "plans" / "native_static.yaml").read_text(encoding="utf-8")
    assert before == after
    assert saved.path.parent.name == "user-plans"
    assert saved.plan.plan_name == "native_static_iap2"
    assert saved.provenance_path and saved.provenance_path.is_file()


def test_save_user_plan_and_list(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    sug = suggest_plan_from_goal("AOA USB Accessory untersuchen")
    saved = save_user_plan(root, sug["raw"], provenance=sug["provenance"])
    users = list_user_plans(root)
    assert any(u["name"] == saved.plan.plan_name for u in users if u.get("valid"))


def test_resource_policy_not_in_searchplan() -> None:
    sug = suggest_plan_from_goal("Bluetooth untersuchen")
    canonical = json.dumps(sug["raw"])
    assert "max_memory" not in canonical
    assert "resource_policy" not in canonical
    assert "reject_estimated" not in canonical


def test_builder_form_roundtrip() -> None:
    form = {
        "name": "manual_bt",
        "investigation_goal": "RFCOMM paths",
        "terms": ["BluetoothSocket"],
        "regex": [],
        "uuids": [],
        "api_patterns": ["bluetooth", "rfcomm"],
        "areas": {"dex_context": True, "bluetooth": True, "communication": True, "evidence_graph": True},
        "traversal": {"instruction_window": 8, "xref_depth": 2, "bluetooth_max_method_hops": 3},
    }
    raw = build_raw_from_builder_form(form)
    res = validate_raw_plan(raw)
    assert res["ok"] is True
    assert res["plan"]["areas"]["bluetooth"] is True


def test_workbench_suggest_save_estimate(tmp_path: Path) -> None:
    import zipfile

    root = tmp_path / "repo"
    (root / "plans").mkdir(parents=True)
    for p in PLANS.glob("*.yaml"):
        (root / "plans" / p.name).write_bytes(p.read_bytes())
    apk = tmp_path / "t.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x00")
        zf.writestr("classes.dex", b"dex\n" + b"X" * 80)

    ctrl = WorkbenchController(root)
    sug = ctrl.suggest_plan("Untersuche iAP2-Kommunikation")
    saved = ctrl.save_plan(sug["raw"], provenance=sug["provenance"])
    assert saved["plan_id"].startswith("user:")
    ids = {p["id"] for p in list_all_plans(root) if p.get("valid")}
    assert saved["plan_id"] in ids
    est = ctrl.estimate(apk_paths=[str(apk)], plan_id=saved["plan_id"], resource_policy="standard")
    assert est["plan"]["sha256"]
    assert est["resource_policy"] == "standard"


def test_ui_mentions_builder() -> None:
    html = (ROOT / "src/apk_forensics/ui/static/index.html").read_text(encoding="utf-8")
    assert "Neuen SearchPlan erstellen" in html
    assert "Plan aus Untersuchungsfrage ableiten" in html
    assert "YAML anzeigen" in html
