"""Shared helpers for apk-forensics."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def timed_ms() -> Iterator[dict[str, int]]:
    state = {"duration_ms": 0}
    start = time.perf_counter()
    try:
        yield state
    finally:
        state["duration_ms"] = int((time.perf_counter() - start) * 1000)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def safe_relpath_check(name: str) -> tuple[bool, list[str]]:
    """Return (is_suspicious, reasons) for ZIP entry names."""
    reasons: list[str] = []
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        reasons.append("absolute_path")
    parts = Path(normalized).parts
    if ".." in parts:
        reasons.append("path_traversal")
    if "\x00" in name:
        reasons.append("nul_byte")
    if "//" in normalized:
        reasons.append("double_slash")
    return (len(reasons) > 0, reasons)


def classify_zip_entry(name: str) -> str:
    n = name.replace("\\", "/")
    lower = n.lower()
    if lower.endswith("/"):
        return "directory"
    if lower == "androidmanifest.xml":
        return "manifest"
    if re.fullmatch(r"classes\d*\.dex", Path(lower).name):
        return "dex"
    if lower.startswith("lib/") and lower.endswith(".so"):
        return "native"
    if lower == "resources.arsc":
        return "resources"
    if lower.startswith("assets/"):
        return "assets"
    if lower.startswith("res/"):
        return "res"
    if lower.startswith("meta-inf/"):
        return "meta-inf"
    return "other"


def compression_name(compress_type: int) -> str:
    mapping = {
        0: "stored",
        8: "deflated",
        12: "bzip2",
        14: "lzma",
    }
    return mapping.get(compress_type, f"type_{compress_type}")


def shannon_entropy(data: bytes | str) -> float:
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="ignore")
    else:
        raw = data
    if not raw:
        return 0.0
    counts = [0] * 256
    for b in raw:
        counts[b] += 1
    length = len(raw)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def looks_high_entropy(value: str, *, min_length: int = 40) -> bool:
    if len(value) < min_length:
        return False
    # Long hex/base64-like blobs are usually not useful candidate strings.
    if re.fullmatch(r"[0-9A-Fa-f+/=_-]{40,}", value):
        return True
    return shannon_entropy(value) >= 4.5


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit]


def decode_ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def context_around(
    data: bytes,
    offset: int,
    length: int,
    max_context: int,
) -> tuple[str, str]:
    before_start = max(0, offset - max_context)
    after_end = min(len(data), offset + length + max_context)
    before = decode_ascii_preview(data[before_start:offset])
    after = decode_ascii_preview(data[offset + length : after_end])
    return before, after


def abi_from_lib_path(path: str) -> str | None:
    parts = path.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0] == "lib":
        return parts[1]
    return None


def resolve_profile_path(profile: str, profiles_dir: Path | None = None) -> Path:
    candidate = Path(profile)
    if candidate.exists():
        return candidate.resolve()
    if profiles_dir is None:
        profiles_dir = Path(__file__).resolve().parents[2] / "profiles"
    name = profile
    if not name.endswith((".yaml", ".yml")):
        name = f"{name}.yaml"
    resolved = (profiles_dir / name).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Profile not found: {profile}")
    return resolved
