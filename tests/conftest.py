from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.create_test_apk import create_synthetic_apk


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def sample_binary(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample_binary.bin"


@pytest.fixture
def sample_profile(fixtures_dir: Path) -> Path:
    return fixtures_dir / "sample_profile.yaml"


@pytest.fixture
def synthetic_apk(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic.apk"
    return create_synthetic_apk(path)
