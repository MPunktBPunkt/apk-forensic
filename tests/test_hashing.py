from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from apk_forensics.errors import InputError
from apk_forensics.hashing import file_sha256_and_size


def test_sha256_and_size(tmp_path: Path) -> None:
    path = tmp_path / "demo.bin"
    data = b"apk-forensics-hash-test"
    path.write_bytes(data)
    digest, size = file_sha256_and_size(path)
    assert size == len(data)
    assert digest == hashlib.sha256(data).hexdigest()


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InputError):
        file_sha256_and_size(tmp_path / "missing.bin")
