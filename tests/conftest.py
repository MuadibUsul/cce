"""Shared fixtures: temp DB, fixed clock-free helpers, fake proxy upstream."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from db.database import Database  # noqa: E402
from core.profile_manager import ProfileManager  # noqa: E402

MASTER_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="  # 32 bytes base64


@pytest.fixture(autouse=True)
def master_key(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("CCE_MASTER_KEY", MASTER_KEY)
    return MASTER_KEY


@pytest_asyncio.fixture
async def db(tmp_path: Path):
    database = Database(tmp_path / "test.sqlite3")
    await database.connect()
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
def profiles(db: Database, tmp_path: Path) -> ProfileManager:
    return ProfileManager(db, root=tmp_path / "profiles")


@pytest.fixture
def profile_root(tmp_path: Path) -> Path:
    return tmp_path / "profiles"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return ROOT


@pytest.fixture(autouse=True)
def _chdir_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)


def seed_file(path: Path, size: int = 1024) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(os.urandom(size))
