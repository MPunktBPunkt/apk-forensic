"""Storage reporting and safe cleanup for managed workspace areas."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from apk_forensics.workspace import (
    AREA_CACHE,
    AREA_OUTPUT,
    AREA_SOURCE,
    AREA_WORK,
    MANAGED_MARKER,
    Workspace,
    is_managed_dir,
    is_symlink_escape,
    is_within,
)


def _human_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(n)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{n} B"


def _iter_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path


def _dir_stats(root: Path) -> tuple[int, int]:
    total = 0
    count = 0
    if not root.exists():
        return 0, 0
    for path in _iter_files(root):
        try:
            total += path.stat().st_size
            count += 1
        except OSError:
            continue
    return total, count


@dataclass
class FileStat:
    path: str
    size_bytes: int
    mtime_utc: str


@dataclass
class AreaReport:
    name: str
    path: str
    size_bytes: int
    file_count: int
    managed: bool | None = None


@dataclass
class StorageReport:
    workspace_root: str
    areas: list[AreaReport] = field(default_factory=list)
    total_bytes: int = 0
    largest_files: list[FileStat] = field(default_factory=list)
    oldest_files: list[FileStat] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "workspace_root": self.workspace_root,
            "areas": [
                {
                    "name": a.name,
                    "path": a.path,
                    "size_bytes": a.size_bytes,
                    "size_human": _human_bytes(a.size_bytes),
                    "file_count": a.file_count,
                    "managed": a.managed,
                }
                for a in self.areas
            ],
            "total_bytes": self.total_bytes,
            "total_human": _human_bytes(self.total_bytes),
            "largest_files": [f.__dict__ for f in self.largest_files],
            "oldest_files": [f.__dict__ for f in self.oldest_files],
        }

    def to_text(self) -> str:
        lines = [
            f"Workspace: {self.workspace_root}",
            "",
            f"{'Area':<28} {'Size':>10} {'Files':>8}",
            "-" * 50,
        ]
        for a in self.areas:
            lines.append(f"{a.name:<28} {_human_bytes(a.size_bytes):>10} {a.file_count:>8}")
        lines.append("-" * 50)
        lines.append(f"{'total':<28} {_human_bytes(self.total_bytes):>10}")
        if self.largest_files:
            lines.append("")
            lines.append("Largest files:")
            for f in self.largest_files[:10]:
                lines.append(f"  {_human_bytes(f.size_bytes):>10}  {f.path}")
        return "\n".join(lines) + "\n"


def collect_storage_report(workspace: Workspace, *, top_n: int = 10) -> StorageReport:
    legacy_artifacts = workspace.root / "artifacts"
    areas: list[AreaReport] = []
    total = 0
    all_files: list[FileStat] = []

    # Managed source/
    size, count = _dir_stats(workspace.source_dir)
    for f in _iter_files(workspace.source_dir):
        try:
            st = f.stat()
        except OSError:
            continue
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        rel = str(f.relative_to(workspace.root)) if is_within(f, workspace.root) else str(f)
        all_files.append(FileStat(path=rel, size_bytes=st.st_size, mtime_utc=mtime))
    areas.append(
        AreaReport(
            name="source artifacts",
            path=str(workspace.source_dir),
            size_bytes=size,
            file_count=count,
            managed=True,
        )
    )
    total += size

    # Legacy artifacts/ excluding source/ to avoid double count
    if legacy_artifacts.exists():
        size = 0
        count = 0
        for f in _iter_files(legacy_artifacts):
            if is_within(f, workspace.source_dir):
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            size += st.st_size
            count += 1
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
            rel = str(f.relative_to(workspace.root)) if is_within(f, workspace.root) else str(f)
            all_files.append(FileStat(path=rel, size_bytes=st.st_size, mtime_utc=mtime))
        areas.append(
            AreaReport(
                name="source artifacts (legacy)",
                path=str(legacy_artifacts),
                size_bytes=size,
                file_count=count,
                managed=False,
            )
        )
        total += size

    for name, path, label in (
        (AREA_WORK, workspace.work_dir, "work"),
        (AREA_OUTPUT, workspace.output_dir, "reports"),
        (AREA_CACHE, workspace.cache_dir, "cache"),
    ):
        size, count = _dir_stats(path)
        for f in _iter_files(path):
            try:
                st = f.stat()
            except OSError:
                continue
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
            rel = str(f.relative_to(workspace.root)) if is_within(f, workspace.root) else str(f)
            all_files.append(FileStat(path=rel, size_bytes=st.st_size, mtime_utc=mtime))
        areas.append(
            AreaReport(
                name=label,
                path=str(path),
                size_bytes=size,
                file_count=count,
                managed=True,
            )
        )
        total += size

    largest = sorted(all_files, key=lambda x: x.size_bytes, reverse=True)[:top_n]
    oldest = sorted(all_files, key=lambda x: x.mtime_utc)[:top_n]
    return StorageReport(
        workspace_root=str(workspace.root),
        areas=areas,
        total_bytes=total,
        largest_files=largest,
        oldest_files=oldest,
    )


_DURATION_RE = re.compile(r"^(\d+)([smhd])$", re.IGNORECASE)


def parse_older_than(value: str) -> timedelta:
    match = _DURATION_RE.match(value.strip())
    if not match:
        raise ValueError(f"Invalid --older-than value: {value!r} (use e.g. 30d, 12h, 90m)")
    amount = int(match.group(1))
    unit = match.group(2).lower()
    if unit == "s":
        return timedelta(seconds=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(days=amount)


@dataclass
class CleanupPlan:
    would_remove: list[str] = field(default_factory=list)
    would_keep: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines = ["Would remove:" if self.would_remove else "Would remove: (none)"]
        for p in self.would_remove:
            lines.append(f"  {p}")
        lines.append("")
        lines.append("Would keep:" if self.would_keep else "Would keep: (none)")
        for p in self.would_keep:
            lines.append(f"  {p}")
        if self.errors:
            lines.append("")
            lines.append("Errors:")
            for e in self.errors:
                lines.append(f"  {e}")
        return "\n".join(lines) + "\n"


def _dir_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def plan_cleanup(
    workspace: Workspace,
    *,
    clean_work: bool = True,
    clean_cache: bool = True,
    clean_output: bool = False,
    older_than: timedelta | None = None,
    protect_output_names: set[str] | None = None,
) -> CleanupPlan:
    """Build a safe cleanup plan. Never includes user source APKs."""
    plan = CleanupPlan()
    protect_output_names = protect_output_names or set()
    cutoff = None
    if older_than is not None:
        cutoff = datetime.now(tz=timezone.utc).timestamp() - older_than.total_seconds()

    if workspace.source_dir.exists():
        plan.would_keep.append(str(workspace.source_dir.relative_to(workspace.root)) + " (source; never auto-deleted)")
    legacy = workspace.root / "artifacts"
    if legacy.exists():
        plan.would_keep.append("artifacts/ (user-provided; never auto-deleted)")

    def consider_tree(root: Path, *, require_managed: bool, area_label: str) -> None:
        if not root.exists():
            return
        if is_symlink_escape(root, workspace.root):
            plan.errors.append(f"skip {area_label}: symlink escape")
            return
        if not is_within(root, workspace.root):
            plan.errors.append(f"skip {area_label}: outside workspace")
            return

        for child in sorted(root.iterdir()):
            rel = str(child.relative_to(workspace.root))
            if child.name == MANAGED_MARKER:
                continue
            if child.is_symlink():
                plan.would_keep.append(f"{rel} (symlink; not removed)")
                continue
            try:
                resolved = child.resolve()
            except OSError:
                plan.errors.append(f"skip {rel}: resolve failed")
                continue
            if not is_within(resolved, workspace.root):
                plan.errors.append(f"skip {rel}: resolves outside workspace")
                continue
            if require_managed and child.is_dir() and not is_managed_dir(child):
                if area_label == AREA_WORK:
                    plan.would_keep.append(f"{rel} (unmanaged; not removed)")
                    continue
            if cutoff is not None and _dir_mtime(child) > cutoff:
                plan.would_keep.append(f"{rel} (newer than retention)")
                continue
            if area_label == AREA_OUTPUT and child.name in protect_output_names:
                plan.would_keep.append(f"{rel} (protected)")
                continue
            plan.would_remove.append(rel)

    if clean_work:
        consider_tree(workspace.work_dir, require_managed=True, area_label=AREA_WORK)
    elif workspace.work_dir.exists():
        plan.would_keep.append("work/ (--work not selected)")

    if clean_cache:
        consider_tree(workspace.cache_dir, require_managed=False, area_label=AREA_CACHE)
    elif workspace.cache_dir.exists():
        plan.would_keep.append("cache/ (--cache not selected)")

    if clean_output:
        consider_tree(workspace.output_dir, require_managed=False, area_label=AREA_OUTPUT)
    elif workspace.output_dir.exists():
        plan.would_keep.append("output/ (reports kept unless --output)")

    return plan


def execute_cleanup(workspace: Workspace, plan: CleanupPlan, *, dry_run: bool = True) -> CleanupPlan:
    if dry_run:
        return plan

    protected_roots = [
        workspace.source_dir.resolve(),
        (workspace.root / "artifacts").resolve(),
    ]

    for rel in list(plan.would_remove):
        path = (workspace.root / rel).resolve()
        if not is_within(path, workspace.root):
            plan.errors.append(f"refused {rel}: outside workspace")
            continue
        if path.is_symlink():
            plan.errors.append(f"refused {rel}: symlink")
            continue
        refused = False
        for prot in protected_roots:
            if path == prot or is_within(path, prot):
                # Allow only if under work/cache/output — never under artifacts
                if is_within(path, workspace.work_dir) or is_within(path, workspace.cache_dir) or is_within(
                    path, workspace.output_dir
                ):
                    break
                plan.errors.append(f"refused {rel}: source/artifact protection")
                refused = True
                break
        if refused:
            continue
        # Must be under work, cache, or output
        allowed = (
            is_within(path, workspace.work_dir)
            or is_within(path, workspace.cache_dir)
            or is_within(path, workspace.output_dir)
        )
        if not allowed:
            plan.errors.append(f"refused {rel}: not in work/cache/output")
            continue
        try:
            if path.is_dir():
                shutil.rmtree(path)
            elif path.is_file():
                path.unlink()
        except OSError as exc:
            plan.errors.append(f"failed {rel}: {exc}")
    return plan
