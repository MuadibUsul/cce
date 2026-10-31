"""Determinism, port allocation, batch isolation and disk ceiling."""

from __future__ import annotations

import json

import pytest

from core.profile_manager import (
    PORT_RANGE,
    ProfileError,
    ProfileManager,
    noise_seed_for,
)
from db.database import Database
from conftest import seed_file


def test_noise_seed_is_deterministic_and_32_bit() -> None:
    first = noise_seed_for("acct-001")
    assert first == noise_seed_for("acct-001")
    assert 0 <= first <= 0xFFFFFFFF
    assert noise_seed_for("acct-002") != first


@pytest.mark.asyncio
async def test_create_profile_persists_frozen_fingerprint(profiles: ProfileManager) -> None:
    row = await profiles.create_profile("acct-001", expected_ip="203.0.113.9", os_type="macos")

    stored = json.loads(row["fingerprint_json"])
    assert stored["os_type"] == "macos"
    assert stored["user_agent"].startswith("Mozilla/5.0")
    assert stored["screen"]["width"] > 0
    assert int(row["noise_seed"]) == noise_seed_for("acct-001")

    # Reloading must return the identical identity, not a regenerated one.
    again = await profiles.load_fingerprint("acct-001")
    assert again.to_json() == stored


@pytest.mark.asyncio
async def test_fingerprint_os_matches_request(profiles: ProfileManager) -> None:
    windows = await profiles.create_profile("acct-win", os_type="windows")
    mac = await profiles.create_profile("acct-mac", os_type="macos")

    assert "Windows NT" in json.loads(windows["fingerprint_json"])["user_agent"] or "Win32" in json.loads(
        windows["fingerprint_json"]
    )["platform"]
    assert "Mac" in json.loads(mac["fingerprint_json"])["user_agent"]


@pytest.mark.asyncio
async def test_duplicate_profile_rejected(profiles: ProfileManager) -> None:
    await profiles.create_profile("acct-dup")
    with pytest.raises(ProfileError, match="already exists"):
        await profiles.create_profile("acct-dup")


@pytest.mark.asyncio
async def test_bad_os_rejected(profiles: ProfileManager) -> None:
    with pytest.raises(ProfileError, match="os_type"):
        await profiles.create_profile("acct-os", os_type="beos")


@pytest.mark.asyncio
async def test_ports_are_allocated_without_collision(profiles: ProfileManager, db: Database) -> None:
    first = await profiles.create_profile("acct-p1")
    second = await profiles.create_profile("acct-p2")
    assert first["local_proxy_port"] != second["local_proxy_port"]
    assert {first["local_proxy_port"], second["local_proxy_port"]} <= set(PORT_RANGE)


@pytest.mark.asyncio
async def test_explicit_port_outside_range_rejected(profiles: ProfileManager) -> None:
    with pytest.raises(ProfileError, match="outside allowed range"):
        await profiles.create_profile("acct-port", local_proxy_port=9999)


@pytest.mark.asyncio
async def test_batch_cap_enforced(profiles: ProfileManager, db: Database) -> None:
    await db.create_batch("batch-a", bin_prefix="424242", billing_country="US", max_accounts=2)
    await profiles.create_profile("acct-b1", batch_id="batch-a")
    await profiles.create_profile("acct-b2", batch_id="batch-a")

    with pytest.raises(ProfileError, match="is full"):
        await profiles.create_profile("acct-b3", batch_id="batch-a")

    # A different batch is unaffected.
    await db.create_batch("batch-b", bin_prefix="555555", billing_country="GB", max_accounts=2)
    assert (await profiles.create_profile("acct-b4", batch_id="batch-b"))["batch_id"] == "batch-b"


@pytest.mark.asyncio
async def test_unknown_batch_rejected(profiles: ProfileManager) -> None:
    with pytest.raises(ProfileError, match="unknown batch"):
        await profiles.create_profile("acct-nobatch", batch_id="nope")


@pytest.mark.asyncio
async def test_path_traversal_ids_rejected(profiles: ProfileManager) -> None:
    with pytest.raises(ProfileError):
        await profiles.create_profile("../escape")


@pytest.mark.asyncio
async def test_scrub_removes_caches_keeps_identity(profiles: ProfileManager) -> None:
    await profiles.create_profile("acct-scrub")
    data_dir = profiles.browser_data_dir("acct-scrub")

    seed_file(data_dir / "cache2" / "entries" / "blob", 4096)
    seed_file(data_dir / "shader-cache" / "shader.bin", 2048)
    seed_file(data_dir / "crashes" / "dump.dmp", 1024)
    seed_file(data_dir / "cookies.sqlite", 512)
    seed_file(data_dir / "prefs.js", 256)

    freed = profiles.scrub_profile_cache("acct-scrub")

    assert set(freed) >= {"cache2", "shader-cache", "crashes"}
    assert not (data_dir / "cache2").exists()
    assert not (data_dir / "shader-cache").exists()
    assert (data_dir / "cookies.sqlite").exists()
    assert (data_dir / "prefs.js").exists()
    assert profiles.profile_disk_usage("acct-scrub") < 10 * 1024 * 1024


@pytest.mark.asyncio
async def test_scrub_is_idempotent(profiles: ProfileManager) -> None:
    await profiles.create_profile("acct-scrub2")
    assert profiles.scrub_profile_cache("acct-scrub2") == {}
    assert profiles.scrub_profile_cache("acct-scrub2") == {}


@pytest.mark.asyncio
async def test_stored_fingerprint_is_a_complete_camoufox_config(profiles: ProfileManager) -> None:
    """The whole device is persisted, not a summary of it.

    Half a config makes Camoufox redraw the parts we omitted, so the stored UA
    stops describing the browser that is actually launched.
    """
    row = await profiles.create_profile("acct-full", os_type="macos")
    config = json.loads(row["fingerprint_json"])["camoufox_config"]

    for key in ("navigator.userAgent", "navigator.platform", "screen.width", "screen.height"):
        assert config[key]


@pytest.mark.asyncio
@pytest.mark.parametrize("os_type", ["macos", "windows", "linux"])
async def test_drawn_identity_passes_camoufox_coherence(profiles: ProfileManager, os_type: str) -> None:
    """Camoufox would silently repair an incoherent draw at launch; we persist
    the repaired one, so a created profile must already be coherent."""
    from camoufox import coherence

    target = {"macos": "mac", "windows": "win"}.get(os_type, "lin")
    for index in range(3):
        row = await profiles.create_profile(f"coh-{os_type}-{index}", os_type=os_type)
        config = json.loads(row["fingerprint_json"])["camoufox_config"]
        assert coherence.validate(config, target) == []


@pytest.mark.asyncio
async def test_ua_version_matches_installed_kernel(profiles: ProfileManager) -> None:
    """The UA must advertise the version that actually runs, or the mismatch is
    visible to any script comparing `navigator.userAgent` with the JS engine."""
    from camoufox.pkgman import installed_verstr

    row = await profiles.create_profile("acct-ua", os_type="macos")
    user_agent = json.loads(row["fingerprint_json"])["user_agent"]

    major = installed_verstr().split(".")[0]
    assert f"rv:{major}." in user_agent
    assert f"Firefox/{major}." in user_agent


@pytest.mark.asyncio
async def test_hardware_concurrency_never_exceeds_host(profiles: ProfileManager) -> None:
    """A claim the host cannot back is timing-measurable from a page."""
    from core.profile_manager import host_core_count

    row = await profiles.create_profile("acct-cores")
    assert json.loads(row["fingerprint_json"])["hardware_concurrency"] == host_core_count()


@pytest.mark.asyncio
async def test_scrub_clears_history_and_compacts(profiles: ProfileManager) -> None:
    import sqlite3

    await profiles.create_profile("acct-places")
    db_path = profiles.browser_data_dir("acct-places") / "places.sqlite"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
        conn.execute("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY)")
        conn.executemany("INSERT INTO moz_places (url) VALUES (?)", [(f"https://x/{i}",) for i in range(500)])

    profiles.scrub_profile_cache("acct-places")

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM moz_places").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_disk_ceiling_crops_but_keeps_identity(profiles: ProfileManager) -> None:
    """Over budget, the biggest disposable files go; identity files stay."""
    from core.profile_manager import DISK_CEILING

    await profiles.create_profile("acct-ceiling")
    data_dir = profiles.browser_data_dir("acct-ceiling")
    seed_file(data_dir / "cookies.sqlite", 1024)
    seed_file(data_dir / "storage" / "default" / "idb" / "blob", DISK_CEILING)
    seed_file(data_dir / "bounce-tracking-protection.sqlite", 3 * 1024 * 1024)

    size = profiles.enforce_disk_ceiling("acct-ceiling")

    assert size <= DISK_CEILING
    assert (data_dir / "cookies.sqlite").exists()
