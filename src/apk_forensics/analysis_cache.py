"""Optional, bounded analysis cache (disabled by default).

Cache key = input SHA-256 + tool version + schema version + relevant options.
Stale entries are never silently treated as current results.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apk_forensics import __schema_version__, __version__
from apk_forensics.workspace import write_managed_manifest


@dataclass(frozen=True)
class CacheKey:
    input_sha256: str
    tool_version: str
    schema_version: str
    options_digest: str

    @property
    def key_id(self) -> str:
        raw = f"{self.input_sha256}|{self.tool_version}|{self.schema_version}|{self.options_digest}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def options_digest(options: dict[str, Any]) -> str:
    payload = json.dumps(options, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def build_cache_key(
    *,
    input_sha256: str,
    options: dict[str, Any],
    schema_version: str | None = None,
) -> CacheKey:
    return CacheKey(
        input_sha256=input_sha256,
        tool_version=__version__,
        schema_version=schema_version or __schema_version__,
        options_digest=options_digest(options),
    )


class AnalysisCache:
    """Filesystem cache under workspace/cache. Opt-in only."""

    def __init__(self, cache_root: Path, *, enabled: bool = False, max_entries: int = 32) -> None:
        self.cache_root = cache_root
        self.enabled = enabled
        self.max_entries = max_entries
        if enabled:
            cache_root.mkdir(parents=True, exist_ok=True)
            write_managed_manifest(cache_root, kind="cache", meta={"max_entries": max_entries})

    def _entry_dir(self, key: CacheKey) -> Path:
        return self.cache_root / key.key_id

    def get(self, key: CacheKey) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        meta_path = self._entry_dir(key) / "meta.json"
        data_path = self._entry_dir(key) / "payload.json"
        if not meta_path.is_file() or not data_path.is_file():
            return None
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.get("tool_version") != key.tool_version:
                return None
            if meta.get("schema_version") != key.schema_version:
                return None
            if meta.get("input_sha256") != key.input_sha256:
                return None
            if meta.get("options_digest") != key.options_digest:
                return None
            return json.loads(data_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def put(self, key: CacheKey, payload: dict[str, Any]) -> None:
        if not self.enabled:
            return
        entry = self._entry_dir(key)
        entry.mkdir(parents=True, exist_ok=True)
        meta = {
            "tool": "apk-forensics",
            "tool_version": key.tool_version,
            "schema_version": key.schema_version,
            "input_sha256": key.input_sha256,
            "options_digest": key.options_digest,
            "key_id": key.key_id,
        }
        (entry / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        (entry / "payload.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        self._enforce_limit()

    def _enforce_limit(self) -> None:
        if not self.cache_root.exists():
            return
        entries = [p for p in self.cache_root.iterdir() if p.is_dir()]
        if len(entries) <= self.max_entries:
            return
        entries.sort(key=lambda p: p.stat().st_mtime)
        for old in entries[: max(0, len(entries) - self.max_entries)]:
            shutil.rmtree(old, ignore_errors=True)
