"""State machine: which jumps are legal, and how a cooldown expires.

Status drives every branch above it, so the transition table is asserted rather
than assumed. The reaper is driven by hand here; in production the API runs it
on a timer.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from core.lifecycle import (
    COOLDOWN_MAX,
    IllegalTransition,
    allows,
    cooldown_until,
    mark,
    release_due_cooldowns,
)
from db.database import PROFILE_STATUSES, SCHEMA_PATH, Database

_PORTS = iter(range(10500, 10600))


async def _profile(db, profile_id: str = "acct-sm") -> dict:
    """A row with all the NOT NULL columns filled; only status matters here."""
    await db.insert_profile(
        {
            "profile_id": profile_id,
            "batch_id": None,
            "local_proxy_port": next(_PORTS),
            "upstream_proxy_url": "socks5h://127.0.0.1:1080",
            "expected_ip": "203.0.113.9",
            "os_type": "macos",
            "noise_seed": 7,
            "fingerprint_json": "{}",
        }
    )
    return (await db.get_profile(profile_id))


@pytest.mark.parametrize("current", PROFILE_STATUSES)
def test_every_status_may_repeat_itself(current: str) -> None:
    assert allows(current, current)


def test_banned_only_comes_back_to_idle() -> None:
    assert allows("BANNED", "IDLE")
    for target in ("BUSY", "COOLDOWN", "AUTH_EXPIRED", "PROXY_DEAD"):
        assert not allows("BANNED", target)


def test_unknown_status_is_rejected() -> None:
    with pytest.raises(ValueError):
        allows("IDLE", "SLEEPING")


def test_cooldown_deadline_is_clamped_and_never_past() -> None:
    now = datetime.now(timezone.utc)
    assert cooldown_until(now=now) > now.isoformat()
    # An absurd request is clamped rather than parking a row for a year.
    clamped = datetime.fromisoformat(cooldown_until(COOLDOWN_MAX * 4, now=now))
    assert clamped - now == COOLDOWN_MAX
    # A negative request still frees the row immediately.
    past = datetime.fromisoformat(cooldown_until(timedelta(seconds=-60), now=now))
    assert past <= now


async def test_mark_refuses_an_illegal_jump(db) -> None:
    await _profile(db)
    await mark(db, "acct-sm", "BANNED")
    with pytest.raises(IllegalTransition):
        await mark(db, "acct-sm", "BUSY")
    assert (await db.get_profile("acct-sm"))["status"] == "BANNED"


async def test_mark_can_be_forced(db) -> None:
    await _profile(db)
    await mark(db, "acct-sm", "BANNED")
    await mark(db, "acct-sm", "BUSY", force=True)
    assert (await db.get_profile("acct-sm"))["status"] == "BUSY"


async def test_mark_missing_profile_says_so(db) -> None:
    with pytest.raises(IllegalTransition):
        await mark(db, "nobody", "IDLE")


async def test_cooldown_writes_a_deadline_and_leaving_clears_it(db) -> None:
    await _profile(db)
    await mark(db, "acct-sm", "COOLDOWN")
    row = await db.get_profile("acct-sm")
    assert row["status"] == "COOLDOWN"
    assert row["cooldown_until"]

    await mark(db, "acct-sm", "IDLE", force=True)
    assert (await db.get_profile("acct-sm"))["cooldown_until"] is None


async def test_release_only_frees_expired_cooldowns(db) -> None:
    await _profile(db, "acct-old")
    await _profile(db, "acct-fresh")
    await _profile(db, "acct-busy")
    now = datetime.now(timezone.utc)
    await db.set_status("acct-old", "COOLDOWN", (now - timedelta(minutes=1)).isoformat())
    await db.set_status("acct-fresh", "COOLDOWN", (now + timedelta(minutes=30)).isoformat())
    await db.set_status("acct-busy", "BUSY")

    released = await release_due_cooldowns(db, now=now)

    assert released == ["acct-old"]
    assert (await db.get_profile("acct-old"))["status"] == "IDLE"
    assert (await db.get_profile("acct-fresh"))["status"] == "COOLDOWN"
    # A BUSY row is untouched even with no deadline.
    assert (await db.get_profile("acct-busy"))["status"] == "BUSY"


async def test_release_is_idempotent(db) -> None:
    await _profile(db)
    now = datetime.now(timezone.utc)
    await db.set_status("acct-sm", "COOLDOWN", (now - timedelta(seconds=1)).isoformat())
    assert await release_due_cooldowns(db, now=now) == ["acct-sm"]
    assert await release_due_cooldowns(db, now=now) == []


async def test_saving_credentials_clears_auth_expired(db) -> None:
    await _profile(db)
    await mark(db, "acct-sm", "AUTH_EXPIRED")
    await db.save_credentials("acct-sm", b"blob")
    row = await db.get_profile("acct-sm")
    assert row["status"] == "IDLE"
    assert row["claude_credentials_enc"] == b"blob"


async def test_saving_credentials_leaves_a_ban_alone(db) -> None:
    """A fresh blob does not un-ban an account that was killed."""
    await _profile(db)
    await mark(db, "acct-sm", "BANNED")
    await db.save_credentials("acct-sm", b"blob")
    assert (await db.get_profile("acct-sm"))["status"] == "BANNED"


async def test_saving_credentials_keeps_a_cooldown_running(db) -> None:
    await _profile(db)
    await mark(db, "acct-sm", "COOLDOWN")
    await db.save_credentials("acct-sm", b"blob")
    row = await db.get_profile("acct-sm")
    assert row["status"] == "COOLDOWN"
    assert row["cooldown_until"]


async def test_existing_database_gets_session_column(tmp_path) -> None:
    path = tmp_path / "legacy.sqlite3"
    legacy_schema = SCHEMA_PATH.read_text().replace("    active_session_id TEXT,\n", "")
    with sqlite3.connect(path) as connection:
        connection.executescript(legacy_schema)
    db = Database(path)
    await db.connect()
    try:
        await _profile(db, "acct-legacy")
        assert await db.claim_session("acct-legacy", "session-1")
        assert (await db.get_profile("acct-legacy"))["active_session_id"] == "session-1"
    finally:
        await db.close()
