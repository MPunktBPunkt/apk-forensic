"""Workspace layout and managed-path helpers for apk-forensics."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apk_forensics.utils import utc_now_iso

WORKSPACE_MARKER = ".apk-forensics-workspace.json"
MANAGED_MARKER = ".apk-forensics-managed.json"

AREA_SOURCE = "source"
AREA_WORK = "work"
AREA_OUTPUT = "output"
AREA_CACHE = "cache"


@dataclass
class Workspace:
    root: Path
    source_dir: Path
    work_dir: Path
    output_dir: Path
    cache_dir: Path

    def ensure(self) -> None:
        for path in (self.source_dir, self.work_dir, self.output_dir, self.cache_dir):
            path.mkdir(parents=True, exist_ok=True)
        marker = self.root / WORKSPACE_MARKER
        if not marker.exists():
            marker.write_text(
                json.dumps(
                    {
                        "tool": "apk-forensics",
                        "created_at_utc": utc_now_iso(),
                        "areas": {
                            AREA_SOURCE: str(self.source_dir.relative_to(self.root)),
                            AREA_WORK: str(self.work_dir.relative_to(self.root)),
                            AREA_OUTPUT: str(self.output_dir.relative_to(self.root)),
                            AREA_CACHE: str(self.cache_dir.relative_to(self.root)),
                        },
                        "notes": [
                            "APK-Forensics manages work/cache/output lifecycle.",
                            "User-provided original APKs are not owned or auto-deleted.",
                        ],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )


def discover_workspace(start: Path | None = None) -> Workspace:
    """Resolve workspace root from CWD / project marker / explicit start."""
    start = (start or Path.cwd()).resolve()
    # Prefer existing marker walking upwards
    cur = start
    for _ in range(8):
        if (cur / WORKSPACE_MARKER).exists() or (cur / "pyproject.toml").exists():
            root = cur
            break
        if cur.parent == cur:
            root = start
            break
        cur = cur.parent
    else:
        root = start

    # Existing repo layout uses artifacts/ + output/; map source under artifacts/source
    source = root / "artifacts" / "source"
    # Keep backward-compatible artifacts/ as unmanaged source sibling
    work = root / "work"
    output = root / "output"
    cache = root / "cache"
    return Workspace(
        root=root,
        source_dir=source,
        work_dir=work,
        output_dir=output,
        cache_dir=cache,
    )


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def is_symlink_escape(path: Path, parent: Path) -> bool:
    """True if path escapes parent via symlink resolution."""
    if not path.exists() and path.is_symlink():
        return True
    try:
        resolved = path.resolve()
        parent_resolved = parent.resolve()
        resolved.relative_to(parent_resolved)
        return False
    except Exception:
        return True


def write_managed_manifest(directory: Path, *, kind: str, meta: dict[str, Any] | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "apk-forensics",
        "managed": True,
        "kind": kind,
        "created_at_utc": utc_now_iso(),
        "meta": meta or {},
    }
    path = directory / MANAGED_MARKER
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def is_managed_dir(directory: Path) -> bool:
    return (directory / MANAGED_MARKER).is_file()


def read_managed_manifest(directory: Path) -> dict[str, Any] | None:
    path = directory / MANAGED_MARKER
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


@dataclass
class WorkSession:
    """Temporary work area for one scan run."""

    path: Path
    keep: bool = False
    _cleaned: bool = False

    def cleanup(self) -> None:
        if self.keep or self._cleaned:
            return
        # Only remove if managed and under expected work root
        if not is_managed_dir(self.path):
            return
        import shutil

        if self.path.exists():
            shutil.rmtree(self.path)
        self._cleaned = True


def create_work_session(workspace: Workspace, *, run_name: str, keep: bool = False) -> WorkSession:
    workspace.ensure()
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in run_name)[:80] or "run"
    path = Path(tempfile.mkdtemp(prefix=f"{safe}-", dir=str(workspace.work_dir)))
    write_managed_manifest(
        path,
        kind="work",
        meta={"run_name": run_name, "pid": os.getpid()},
    )
    return WorkSession(path=path, keep=keep)
