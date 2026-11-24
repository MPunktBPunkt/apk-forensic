from __future__ import annotations

import os
import time
from datetime import timedelta
from pathlib import Path

from apk_forensics.storage import collect_storage_report, execute_cleanup, parse_older_than, plan_cleanup
from apk_forensics.workspace import (
    Workspace,
    create_work_session,
    discover_workspace,
    write_managed_manifest,
)


def _ws(tmp_path: Path) -> Workspace:
    root = tmp_path / "ws"
    ws = Workspace(
        root=root,
        source_dir=root / "artifacts" / "source",
        work_dir=root / "work",
        output_dir=root / "output",
        cache_dir=root / "cache",
    )
    ws.ensure()
    return ws


def test_work_session_cleanup(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    session = create_work_session(ws, run_name="t1", keep=False)
    marker = session.path / "tmp.bin"
    marker.write_bytes(b"x" * 100)
    assert session.path.exists()
    session.cleanup()
    assert not session.path.exists()


def test_keep_work(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    session = create_work_session(ws, run_name="t2", keep=True)
    (session.path / "keep.bin").write_bytes(b"y")
    session.cleanup()
    assert session.path.exists()


def test_source_never_in_cleanup_plan(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    src = ws.source_dir / "app.apk"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(b"apk")
    legacy = ws.root / "artifacts" / "user.apk"
    legacy.write_bytes(b"apk2")
    work = create_work_session(ws, run_name="w", keep=True)
    (work.path / "t").write_text("x", encoding="utf-8")

    plan = plan_cleanup(ws, clean_work=True, clean_cache=True, clean_output=False)
    joined = "\n".join(plan.would_remove)
    assert "artifacts" not in joined or all("artifacts" not in p or p.startswith("work") for p in plan.would_remove)
    assert any("source" in k or "artifacts" in k for k in plan.would_keep)
    assert any(str(work.path.relative_to(ws.root)) in p or work.path.name in p for p in plan.would_remove)


def test_dry_run_no_delete(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    session = create_work_session(ws, run_name="dry", keep=True)
    (session.path / "f").write_text("1", encoding="utf-8")
    plan = plan_cleanup(ws, clean_work=True, clean_cache=False, clean_output=False)
    execute_cleanup(ws, plan, dry_run=True)
    assert session.path.exists()


def test_execute_removes_work(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    session = create_work_session(ws, run_name="exec", keep=True)
    (session.path / "f").write_text("1", encoding="utf-8")
    plan = plan_cleanup(ws, clean_work=True, clean_cache=False, clean_output=False)
    execute_cleanup(ws, plan, dry_run=False)
    assert not session.path.exists()


def test_symlink_not_removed(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    real = tmp_path / "outside"
    real.mkdir()
    (real / "secret").write_text("no", encoding="utf-8")
    link = ws.work_dir / "escape"
    link.symlink_to(real)
    plan = plan_cleanup(ws, clean_work=True, clean_cache=False, clean_output=False)
    assert any("symlink" in k for k in plan.would_keep) or any("symlink" in e for e in plan.errors)
    execute_cleanup(ws, plan, dry_run=False)
    assert real.exists()
    assert (real / "secret").read_text(encoding="utf-8") == "no"


def test_outside_workspace_refused(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    plan = plan_cleanup(ws)
    # forge a malicious relative path
    plan.would_remove.append("../outside-escape")
    outside = tmp_path / "outside-escape"
    outside.mkdir()
    (outside / "x").write_text("x", encoding="utf-8")
    execute_cleanup(ws, plan, dry_run=False)
    assert outside.exists()


def test_output_cleanup_opt_in(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    out = ws.output_dir / "old-report"
    out.mkdir(parents=True)
    (out / "report.json").write_text("{}", encoding="utf-8")
    plan = plan_cleanup(ws, clean_work=False, clean_cache=False, clean_output=False)
    assert not any("old-report" in p for p in plan.would_remove)
    plan2 = plan_cleanup(ws, clean_work=False, clean_cache=False, clean_output=True)
    assert any("old-report" in p for p in plan2.would_remove)


def test_older_than_retention(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    old = create_work_session(ws, run_name="old", keep=True)
    (old.path / "f").write_text("1", encoding="utf-8")
    # age the directory
    old_ts = time.time() - 40 * 86400
    os.utime(old.path, (old_ts, old_ts))
    new = create_work_session(ws, run_name="new", keep=True)
    (new.path / "f").write_text("1", encoding="utf-8")

    plan = plan_cleanup(
        ws,
        clean_work=True,
        clean_cache=False,
        clean_output=False,
        older_than=parse_older_than("30d"),
    )
    assert any(old.path.name in p for p in plan.would_remove)
    assert any(new.path.name in p and "newer" in p for p in plan.would_keep)


def test_storage_report_sizes(tmp_path: Path) -> None:
    ws = _ws(tmp_path)
    (ws.output_dir / "r").mkdir()
    (ws.output_dir / "r" / "report.json").write_bytes(b"x" * 1000)
    (ws.cache_dir / "c").mkdir()
    write_managed_manifest(ws.cache_dir, kind="cache")
    (ws.cache_dir / "c" / "p.json").write_bytes(b"y" * 500)
    report = collect_storage_report(ws)
    assert report.total_bytes >= 1500
    names = {a.name for a in report.areas}
    assert "reports" in names
    assert "cache" in names
    assert report.largest_files
    data = report.to_dict()
    assert "total_human" in data


def test_discover_workspace_creates_marker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='t'\n", encoding="utf-8")
    ws = discover_workspace(tmp_path)
    ws.ensure()
    assert (ws.root / ".apk-forensics-workspace.json").exists()


def test_parse_older_than() -> None:
    assert parse_older_than("30d") == timedelta(days=30)
    assert parse_older_than("12h") == timedelta(hours=12)
