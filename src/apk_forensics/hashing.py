"""SHA-256 hashing helpers for APK files and ZIP entries."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from apk_forensics.config import HASH_CHUNK_SIZE
from apk_forensics.errors import InputError


def file_sha256_and_size(path: Path, *, chunk_size: int = HASH_CHUNK_SIZE) -> tuple[str, int]:
    if not path.exists():
        raise InputError(f"Input file does not exist: {path}")
    if not path.is_file():
        raise InputError(f"Input path is not a file: {path}")
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise InputError(f"Input file is not readable: {path}") from exc
    return digest.hexdigest(), size


def bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stream_sha256(handle, *, chunk_size: int = HASH_CHUNK_SIZE, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = max_bytes
    while True:
        to_read = chunk_size if remaining is None else min(chunk_size, remaining)
        if to_read <= 0:
            break
        chunk = handle.read(to_read)
        if not chunk:
            break
        digest.update(chunk)
        if remaining is not None:
            remaining -= len(chunk)
    return digest.hexdigest()


def zip_entry_sha256(
    zf: zipfile.ZipFile,
    name: str,
    *,
    chunk_size: int = HASH_CHUNK_SIZE,
    max_bytes: int | None = None,
) -> str:
    with zf.open(name, "r") as handle:
        return stream_sha256(handle, chunk_size=chunk_size, max_bytes=max_bytes)
