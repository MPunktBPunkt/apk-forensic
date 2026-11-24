from __future__ import annotations

from pathlib import Path

from apk_forensics.analysis_cache import AnalysisCache, build_cache_key


def test_cache_disabled_by_default(tmp_path: Path) -> None:
    cache = AnalysisCache(tmp_path / "cache", enabled=False)
    key = build_cache_key(input_sha256="abc", options={"x": 1})
    cache.put(key, {"ok": True})
    assert cache.get(key) is None


def test_cache_hit_and_version_mismatch(tmp_path: Path) -> None:
    cache = AnalysisCache(tmp_path / "cache", enabled=True, max_entries=4)
    key = build_cache_key(input_sha256="deadbeef", options={"dex_context": False})
    cache.put(key, {"findings": 1})
    assert cache.get(key) == {"findings": 1}

    # Different options → miss
    other = build_cache_key(input_sha256="deadbeef", options={"dex_context": True})
    assert cache.get(other) is None

    # Tamper meta version → miss
    entry = tmp_path / "cache" / key.key_id / "meta.json"
    text = entry.read_text(encoding="utf-8").replace(
        '"tool_version":',
        '"tool_version_keep":',
    )
    # break tool_version field
    import json

    meta = json.loads(entry.read_text(encoding="utf-8"))
    meta["tool_version"] = "0.0.0-old"
    entry.write_text(json.dumps(meta), encoding="utf-8")
    assert cache.get(key) is None
