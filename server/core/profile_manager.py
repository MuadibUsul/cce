"""Profile lifecycle: deterministic fingerprints, isolated dirs, cache scrubbing.

Two invariants drive this module:

1. **Determinism.** The fingerprint and the Camoufox noise seed are derived from
   `profile_id` alone. Creating a profile twice (or restoring one after a crash)
   yields byte-identical hardware characteristics, so the account never looks
   like it moved to a new machine.
2. **Disk ceiling.** A profile must stay under 10 MB. Browser caches are purged
   after every context exit while identity-bearing files (cookies, prefs) stay.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from camoufox import coherence
from camoufox.fingerprints import (
    PLAUSIBLE_CORE_COUNTS,
    from_fpgen,
    generate_fingerprint,
)
from camoufox.pkgman import installed_verstr

from db.database import Database

SUPPORTED_OS = ("macos", "windows", "linux")

# Purged after every context exit. Everything here is re-derivable from the web.
SCRUB_DIRS = (
    "cache2",
    "startupCache",
    "jumpListCache",
    "shader-cache",
    "crashes",
    "minidumps",
    "datareporting",
    "saved-telemetry-pings",
    "storage/default/https+++*.claude.ai/cache",
)

# Kept: cookie jar, local prefs and the fingerprint-bearing user.js.
PRESERVE_FILES = ("cookies.sqlite", "webappsstore.sqlite", "prefs.js", "user.js")

# Never dropped by the over-size sweep, even when large: identity or schema
# bearing rather than re-derivable.
SCRUB_KEEP = PRESERVE_FILES + (
    "places.sqlite",
    "favicons.sqlite",
    "key4.db",
    "cert9.db",
    "logins.db",
    "permissions.sqlite",
    "content-prefs.sqlite",
    "sessionstore.jsonlz4",
)

# Browsing trace tables per database, cleared and compacted after every run.
TRACE_TABLES = {
    "places.sqlite": ("moz_historyvisits", "moz_places", "moz_origins"),
    "favicons.sqlite": ("moz_icons_to_pages", "moz_icons", "moz_pages_w_icons"),
}

# Cropped largest-first, and only when the profile is over the ceiling.
CROP_DIRS = ("storage/default/https+++*.claude.ai", "storage", "places.sqlite-wal")

# Hard per-profile budget from the spec.
DISK_CEILING = 10 * 1024 * 1024

PROFILE_ROOT = Path("data/profiles")
PORT_RANGE = range(10001, 11001)


class ProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class FingerprintSpec:
    """The persisted, frozen identity of one profile."""

    os_type: str
    user_agent: str
    platform: str
    hardware_concurrency: int
    screen_width: int
    screen_height: int
    locale: str
    languages: tuple[str, ...]
    video_vendor: str
    video_renderer: str
    # The full CAMOU_CONFIG blob Camoufox consumes. Persisted verbatim so a
    # relaunch reproduces the same device instead of drawing a new one.
    camoufox_config: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        payload = {
            "os_type": self.os_type,
            "user_agent": self.user_agent,
            "platform": self.platform,
            "hardware_concurrency": self.hardware_concurrency,
            "screen": {"width": self.screen_width, "height": self.screen_height},
            "locale": self.locale,
            "languages": list(self.languages),
            "video_card": {"vendor": self.video_vendor, "renderer": self.video_renderer},
            "camoufox_config": self.camoufox_config,
        }
        return payload

    @classmethod
    def from_json(cls, raw: str | dict[str, Any]) -> FingerprintSpec:
        data = json.loads(raw) if isinstance(raw, str) else raw
        screen = data.get("screen") or {}
        card = data.get("video_card") or {}
        return cls(
            os_type=data["os_type"],
            user_agent=data["user_agent"],
            platform=data["platform"],
            hardware_concurrency=int(data["hardware_concurrency"]),
            screen_width=int(screen.get("width", 1920)),
            screen_height=int(screen.get("height", 1080)),
            locale=data.get("locale", "en-US"),
            languages=tuple(data.get("languages") or []),
            video_vendor=card.get("vendor", ""),
            video_renderer=card.get("renderer", ""),
            camoufox_config=data.get("camoufox_config") or {},
        )


def noise_seed_for(profile_id: str) -> int:
    """Deterministic 32-bit seed. Same id => same seed, forever."""
    digest = hashlib.sha256(profile_id.encode("utf-8")).hexdigest()
    return int(digest[:8], 16)


def host_core_count() -> int:
    """The core count the browser can actually be measured running on.

    Camoufox pins nothing by default, so a claim of more cores than the host has
    is timing-measurable. Snap the host count down into the counts real desktops
    ship, exactly as `camoufox.fingerprints.fix_hardware_concurrency` does -- we
    supply the whole navigator block, so Camoufox leaves ours alone.
    """
    try:
        available = len(os.sched_getaffinity(0))
    except AttributeError:  # pragma: no cover - non-Linux
        available = os.cpu_count() or 0
    allowed = [count for count in PLAUSIBLE_CORE_COUNTS if count <= available]
    return allowed[-1] if allowed else PLAUSIBLE_CORE_COUNTS[0]


def _fingerprint_for(profile_id: str, os_type: str) -> FingerprintSpec:
    """Generate the hardware identity. Called exactly once per profile.

    fpgen samples randomly here; the result is persisted immediately and is the
    source of truth on every later run. The draw is kept as a *complete* CAMOU
    config, not a handful of fields: Camoufox's coherence pass only repairs what
    the caller left unset, and a half-specified navigator would be relaunched
    with a fresh UA that no longer matches the running kernel.
    """
    target = _target_os(os_type)
    for _ in range(24):
        drawn = generate_fingerprint(os=os_type)
        # The kernel version is the one that is really installed, so the UA must
        # carry it; fpgen's version lags behind the shipped binary.
        drawn["navigator"]["userAgent"] = _rewrite_ua_version(
            drawn["navigator"]["userAgent"], installed_verstr()
        )
        drawn["navigator"]["hardwareConcurrency"] = host_core_count()

        config = from_fpgen(drawn, installed_verstr().split(".", 1)[0])
        gpu = drawn.get("gpu") or {}
        # from_fpgen drops the GPU pair (it is not part of FPGEN_DATA); pass it
        # on so Camoufox fills in that device's recorded WebGL parameters.
        if gpu.get("vendor"):
            config["webGl:vendor"] = gpu["vendor"]
        if gpu.get("renderer"):
            config["webGl:renderer"] = gpu["renderer"]
        # Apply the same repairs Camoufox applies at launch, so the stored row
        # describes the machine that will actually be presented. Only rules
        # with no deterministic repair survive; those mean the draw itself has
        # to change (an Intel iGPU behind 24 cores, an impossible GPU/OS pair).
        if coherence.apply(config, target):
            continue

        navigator = drawn["navigator"]
        languages = navigator.get("languages") or ["en-US"]
        return FingerprintSpec(
            os_type=os_type,
            user_agent=config["navigator.userAgent"],
            platform=config["navigator.platform"],
            hardware_concurrency=int(config["navigator.hardwareConcurrency"]),
            screen_width=int(config["screen.width"]),
            screen_height=int(config["screen.height"]),
            locale=navigator.get("language") or languages[0],
            languages=tuple(languages),
            video_vendor=str(gpu.get("vendor") or ""),
            video_renderer=str(gpu.get("renderer") or ""),
            camoufox_config=config,
        )
    raise ProfileError(f"could not draw a coherent {os_type} fingerprint")


def _target_os(os_type: str) -> str:
    """Camoufox's three-letter OS name, as its coherence rules expect it."""
    return {"macos": "mac", "windows": "win"}.get(os_type, "lin")


def _ua_version(version: str) -> str:
    """`156.0.1-beta.36` -> `156.0`: the form real user agents carry."""
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else version


def _rewrite_ua_version(user_agent: str, version: str) -> str:
    """Point a UA's Firefox version at the kernel that is actually installed."""
    import re

    target = _ua_version(version)
    user_agent = re.sub(r"rv:\d+\.\d+", f"rv:{target}", user_agent, count=1)
    return re.sub(r"Firefox/\d+\.\d+", f"Firefox/{target}", user_agent, count=1)


class ProfileManager:
    def __init__(self, database: Database, root: Path = PROFILE_ROOT) -> None:
        self._db = database
        self._root = Path(root)

    # -- paths -------------------------------------------------------------

    def profile_dir(self, profile_id: str) -> Path:
        _assert_safe_id(profile_id)
        return self._root / profile_id

    def browser_data_dir(self, profile_id: str) -> Path:
        return self.profile_dir(profile_id) / "browser_data"

    def claude_home_dir(self, profile_id: str) -> Path:
        return self.profile_dir(profile_id) / "claude_home"

    # -- creation ----------------------------------------------------------

    async def create_profile(
        self,
        profile_id: str,
        local_proxy_port: int | None = None,
        upstream_proxy_url: str = "",
        expected_ip: str = "",
        os_type: str = "macos",
        batch_id: str | None = None,
    ) -> dict[str, Any]:
        if os_type not in SUPPORTED_OS:
            raise ProfileError(f"os_type must be one of {SUPPORTED_OS}, got {os_type!r}")
        if await self._db.get_profile(profile_id) is not None:
            raise ProfileError(f"profile already exists: {profile_id}")
        if batch_id is not None:
            batch = await self._db.get_batch(batch_id)
            if batch is None:
                raise ProfileError(f"unknown batch: {batch_id}")
            if await self._db.batch_usage(batch_id) >= int(batch["max_accounts"]):
                raise ProfileError(f"batch {batch_id} is full ({batch['max_accounts']} accounts)")

        port = local_proxy_port if local_proxy_port is not None else await self.allocate_port()
        if port not in PORT_RANGE:
            raise ProfileError(f"port {port} outside allowed range {PORT_RANGE}")

        spec = _fingerprint_for(profile_id, os_type)
        self.browser_data_dir(profile_id).mkdir(parents=True, exist_ok=True)
        self.claude_home_dir(profile_id).mkdir(parents=True, exist_ok=True)

        record = {
            "profile_id": profile_id,
            "batch_id": batch_id,
            "local_proxy_port": port,
            "upstream_proxy_url": upstream_proxy_url,
            "expected_ip": expected_ip,
            "os_type": os_type,
            "noise_seed": noise_seed_for(profile_id),
            "fingerprint_json": json.dumps(spec.to_json(), separators=(",", ":")),
        }
        await self._db.insert_profile(record)
        created = await self._db.get_profile(profile_id)
        assert created is not None
        return created

    async def allocate_port(self) -> int:
        used = await self._db.used_ports()
        for port in PORT_RANGE:
            if port not in used:
                return port
        raise ProfileError("no free proxy port in range")

    # -- scrubbing ---------------------------------------------------------

    def scrub_profile_cache(self, profile_id: str) -> dict[str, int]:
        """Delete re-derivable caches and browsing traces, then compact.

        Returns bytes-freed per entry. The trace databases keep their schema (and
        so their bookmark roots) but lose their rows: after a login the account
        would otherwise carry a browsing trail the exit IP cannot explain, and
        those files are megabytes of mostly-empty pages.
        """
        data_dir = self.browser_data_dir(profile_id)
        if not data_dir.is_dir():
            return {}

        freed: dict[str, int] = {}
        for pattern in SCRUB_DIRS:
            for path in data_dir.glob(pattern):
                if not path.is_dir():
                    continue
                freed[str(path.relative_to(data_dir))] = _dir_size(path)
                shutil.rmtree(path, ignore_errors=True)

        for leftover in data_dir.glob("cache*"):
            if leftover.is_dir():
                freed[str(leftover.relative_to(data_dir))] = _dir_size(leftover)
                shutil.rmtree(leftover, ignore_errors=True)

        files = 0
        for name, tables in TRACE_TABLES.items():
            files += _vacuum_db(data_dir / name, tables)
        if files:
            freed["trace-databases"] = files
        _remove_huge(data_dir, keep=SCRUB_KEEP)
        return freed

    def profile_disk_usage(self, profile_id: str) -> int:
        return _dir_size(self.profile_dir(profile_id))

    def enforce_disk_ceiling(self, profile_id: str, ceiling: int = DISK_CEILING) -> int:
        """Scrub, then crop the largest remaining files until under `ceiling`.

        Scrub alone lands around 6 MB on a cold profile, but a single claude.ai
        visit writes ~18 MB of IndexedDB under `storage/`, and that is exactly
        the state worth keeping. The crop therefore removes trailing history /
        storage entries in size order and never touches PRESERVE_FILES or
        user.js/prefs.js. Returns the resulting size.
        """
        data_dir = self.browser_data_dir(profile_id)
        size = self.profile_disk_usage(profile_id)
        if size <= ceiling:
            return size

        for pattern in CROP_DIRS:
            for path in sorted(data_dir.glob(pattern), key=_dir_size, reverse=True):
                if size <= ceiling:
                    return size
                if path.is_dir():
                    size -= _dir_size(path)
                    shutil.rmtree(path, ignore_errors=True)

        for path in sorted((p for p in data_dir.iterdir() if p.is_file()), key=_size, reverse=True):
            if size <= ceiling:
                break
            if path.name in PRESERVE_FILES or path.suffix in (".js", ".sqlite-wal"):
                continue
            size -= _size(path)
            path.unlink(missing_ok=True)
        return self.profile_disk_usage(profile_id)

    # -- identity ----------------------------------------------------------

    async def load_fingerprint(self, profile_id: str) -> FingerprintSpec:
        profile = await self._db.get_profile(profile_id)
        if profile is None:
            raise ProfileError(f"profile not found: {profile_id}")
        return FingerprintSpec.from_json(profile["fingerprint_json"])


def _assert_safe_id(profile_id: str) -> None:
    if not profile_id or profile_id in {".", ".."}:
        raise ProfileError(f"invalid profile_id: {profile_id!r}")
    if "/" in profile_id or "\\" in profile_id:
        raise ProfileError(f"profile_id must not contain path separators: {profile_id!r}")


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _vacuum_db(db_path: Path, tables: tuple[str, ...]) -> int:
    """Empty `tables` in a Firefox SQLite database, then shrink the file.

    Firefox runs these databases in WAL mode, so the shrunk pages only become
    real once the log is checkpointed back into the main file -- otherwise the
    profile carries a full-size page store plus its WAL. Returned value is the
    bytes reclaimed; a missing or locked database is not an error, since the
    browser may still be shutting down.
    """
    if not db_path.is_file():
        return 0
    wal = db_path.with_name(db_path.name + "-wal")
    before = _size(db_path) + _size(wal)
    try:
        # isolation_level=None keeps autocommit on so VACUUM is legal.
        with sqlite3.connect(db_path, timeout=5, isolation_level=None) as conn:
            for table in tables:
                try:
                    conn.execute(f"DELETE FROM {table}")
                except sqlite3.DatabaseError:
                    pass
            conn.execute("VACUUM")
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.DatabaseError:
        return 0
    if wal.is_file() and not _size(wal):
        wal.unlink(missing_ok=True)
    return max(before - (_size(db_path) + _size(wal)), 0)


def _remove_huge(directory: Path, keep: tuple[str, ...], limit: int = 2 * 1024 * 1024) -> None:
    """Drop single files still above `limit` that nothing depends on.

    Bounce-tracking, telemetry and session-store blobs are all re-derivable, but
    they are written under random names and varying suffixes, so matching them
    by name is not enough.
    """
    for path in directory.iterdir():
        if not path.is_file() or path.name in keep or _size(path) <= limit:
            continue
        if path.suffix in (".js", ".sqlite", ".db"):
            continue
        path.unlink(missing_ok=True)


def _dir_size(path: Path) -> int:
    total = 0
    for child in path.rglob("*"):
        try:
            if child.is_file():
                total += child.stat().st_size
        except OSError:
            continue
    return total
