"""Async SQLite access layer.

One process-wide connection guarded by an asyncio lock. SQLite is only the
control-plane store (hundreds of rows, not millions), so a single writer is
plenty and avoids `database is locked` storms. WAL is enabled so a reader
inside the API does not block a writer in the browser pool.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Sequence

import aiosqlite

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

PROFILE_STATUSES = (
    "IDLE",
    "BUSY",
    "COOLDOWN",
    "AUTH_EXPIRED",
    "PROXY_DEAD",
    "BANNED",
)

PLAN_TIERS = ("pro", "max_5x", "max_20x", "env_only")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Thin, typed-ish wrapper. Callers pass SQL; rows come back as dicts."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    # -- lifecycle ---------------------------------------------------------

    async def connect(self) -> None:
        if self._conn is not None:
            return
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")
        self._conn = conn
        await self.migrate()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database.connect() must be awaited first")
        return self._conn

    async def migrate(self) -> None:
        sql = SCHEMA_PATH.read_text(encoding="utf-8")
        async with self._lock:
            await self.conn.executescript(sql)
            cursor = await self.conn.execute("PRAGMA table_info(profiles)")
            columns = {row[1] for row in await cursor.fetchall()}
            await cursor.close()
            if "active_session_id" not in columns:
                await self.conn.execute("ALTER TABLE profiles ADD COLUMN active_session_id TEXT")
            if "last_heartbeat_at" not in columns:
                await self.conn.execute("ALTER TABLE profiles ADD COLUMN last_heartbeat_at TIMESTAMP")
                # Rows that are already BUSY have no recorded lease time. Give
                # them one full window from the migration instead of freeing
                # them the moment this process starts.
                await self.conn.execute(
                    "UPDATE profiles SET last_heartbeat_at = ?"
                    " WHERE status = 'BUSY' AND last_heartbeat_at IS NULL",
                    (_now_iso(),),
                )
            await self.conn.commit()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self._lock:
            try:
                yield self.conn
                await self.conn.commit()
            except BaseException:
                await self.conn.rollback()
                raise

    # -- primitives --------------------------------------------------------

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        async with self._lock:
            await self.conn.execute(sql, params)
            await self.conn.commit()

    async def execute_many(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        async with self._lock:
            await self.conn.executemany(sql, list(rows))
            await self.conn.commit()

    async def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        async with self._lock:
            cursor = await self.conn.execute(sql, params)
            row = await cursor.fetchone()
            await cursor.close()
        return dict(row) if row is not None else None

    async def fetch_all(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        async with self._lock:
            cursor = await self.conn.execute(sql, params)
            rows = await cursor.fetchall()
            await cursor.close()
        return [dict(row) for row in rows]

    # -- batches -----------------------------------------------------------

    async def create_batch(
        self,
        batch_id: str,
        bin_prefix: str,
        billing_country: str,
        max_accounts: int = 10,
    ) -> None:
        await self.execute(
            "INSERT INTO payment_batches (batch_id, bin_prefix, billing_country, max_accounts)"
            " VALUES (?, ?, ?, ?)",
            (batch_id, bin_prefix, billing_country, max_accounts),
        )

    async def get_batch(self, batch_id: str) -> dict[str, Any] | None:
        return await self.fetch_one("SELECT * FROM payment_batches WHERE batch_id = ?", (batch_id,))

    async def batch_usage(self, batch_id: str) -> int:
        row = await self.fetch_one(
            "SELECT COUNT(*) AS n FROM profiles WHERE batch_id = ?", (batch_id,)
        )
        return int(row["n"]) if row else 0

    # -- profiles ----------------------------------------------------------

    async def insert_profile(self, record: dict[str, Any]) -> None:
        columns = (
            "profile_id",
            "batch_id",
            "local_proxy_port",
            "upstream_proxy_url",
            "expected_ip",
            "os_type",
            "noise_seed",
            "fingerprint_json",
        )
        placeholders = ", ".join("?" for _ in columns)
        await self.execute(
            f"INSERT INTO profiles ({', '.join(columns)}) VALUES ({placeholders})",
            tuple(record[column] for column in columns),
        )

    async def get_profile(self, profile_id: str) -> dict[str, Any] | None:
        return await self.fetch_one("SELECT * FROM profiles WHERE profile_id = ?", (profile_id,))

    async def list_profiles(self, status: str | None = None) -> list[dict[str, Any]]:
        if status is None:
            return await self.fetch_all("SELECT * FROM profiles ORDER BY created_at")
        return await self.fetch_all(
            "SELECT * FROM profiles WHERE status = ? ORDER BY created_at", (status,)
        )

    async def set_status(
        self,
        profile_id: str,
        status: str,
        cooldown_until: str | None = None,
    ) -> None:
        if status not in PROFILE_STATUSES:
            raise ValueError(f"unknown profile status: {status}")
        # A forced BUSY starts a fresh lease rather than inheriting a stale one.
        await self.execute(
            "UPDATE profiles SET status = ?, cooldown_until = ?,"
            " last_heartbeat_at = CASE WHEN ? = 'BUSY' THEN ? ELSE NULL END,"
            " active_session_id = CASE WHEN ? = 'BUSY' THEN active_session_id ELSE NULL END"
            " WHERE profile_id = ?",
            (status, cooldown_until, status, _now_iso(), status, profile_id),
        )

    async def claim_session(self, profile_id: str, session_id: str) -> bool:
        """Reserve an idle profile exactly once, even under concurrent requests."""
        async with self._lock:
            cursor = await self.conn.execute(
                "UPDATE profiles SET status = 'BUSY', active_session_id = ?,"
                " last_heartbeat_at = ?"
                " WHERE profile_id = ? AND status = 'IDLE'",
                (session_id, _now_iso(), profile_id),
            )
            await self.conn.commit()
            return cursor.rowcount == 1

    async def touch_heartbeat(self, profile_id: str, session_id: str) -> bool:
        """Extend the lease. False when this session no longer owns the row."""
        async with self._lock:
            cursor = await self.conn.execute(
                "UPDATE profiles SET last_heartbeat_at = ?"
                " WHERE profile_id = ? AND status = 'BUSY' AND active_session_id = ?",
                (_now_iso(), profile_id, session_id),
            )
            await self.conn.commit()
            return cursor.rowcount == 1

    async def reclaim_stale_busy(self, profile_id: str, cutoff: str) -> bool:
        """Free a BUSY row whose lease expired, unless a heartbeat just landed.

        The cutoff is re-checked in the UPDATE, so a heartbeat that arrives
        between the sweep's SELECT and this call keeps the row BUSY.
        """
        async with self._lock:
            cursor = await self.conn.execute(
                "UPDATE profiles SET status = 'IDLE', active_session_id = NULL,"
                " last_heartbeat_at = NULL, cooldown_until = NULL"
                " WHERE profile_id = ? AND status = 'BUSY'"
                " AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= ?)",
                (profile_id, cutoff),
            )
            await self.conn.commit()
            return cursor.rowcount == 1

    async def finish_session(
        self, profile_id: str, session_id: str, status: str, cooldown_until: str | None = None
    ) -> bool:
        if status not in {"IDLE", "COOLDOWN", "AUTH_EXPIRED", "PROXY_DEAD"}:
            raise ValueError(f"invalid launcher status: {status}")
        async with self._lock:
            cursor = await self.conn.execute(
                "UPDATE profiles SET status = ?, cooldown_until = ?, active_session_id = NULL,"
                " last_heartbeat_at = NULL"
                " WHERE profile_id = ? AND status = 'BUSY' AND active_session_id = ?",
                (status, cooldown_until, profile_id, session_id),
            )
            await self.conn.commit()
            return cursor.rowcount == 1

    async def save_geo(self, profile_id: str, geo_json: str) -> None:
        await self.execute("UPDATE profiles SET geo_json = ? WHERE profile_id = ?", (geo_json, profile_id))

    async def get_profile_geo(self, profile_id: str) -> dict[str, Any] | None:
        """The last verified geo for a profile, or None if it never passed."""
        raw = await self.fetch_one("SELECT geo_json FROM profiles WHERE profile_id = ?", (profile_id,))
        if not raw or not raw.get("geo_json"):
            return None
        try:
            return json.loads(raw["geo_json"])
        except ValueError:
            return None

    async def save_credentials(self, profile_id: str, blob: bytes) -> None:
        """Store a fresh credential blob and consider the auth problem solved.

        Clearing `AUTH_EXPIRED` here (rather than at every caller) means the
        sync path and the import path both recover the row, and a caller cannot
        forget. A cooldown or a ban outranks a fresh blob and is left alone.
        """
        await self.execute(
            "UPDATE profiles SET claude_credentials_enc = ?,"
            " status = CASE WHEN status IN ('AUTH_EXPIRED', 'IDLE') THEN 'IDLE' ELSE status END,"
            " cooldown_until = CASE WHEN status IN ('AUTH_EXPIRED', 'IDLE') THEN NULL"
            " ELSE cooldown_until END"
            " WHERE profile_id = ?",
            (blob, profile_id),
        )

    async def used_ports(self) -> set[int]:
        rows = await self.fetch_all("SELECT local_proxy_port FROM profiles")
        return {int(row["local_proxy_port"]) for row in rows}

    # -- delivery keys -----------------------------------------------------

    async def insert_delivery_key(self, record: dict[str, Any]) -> None:
        await self.execute(
            "INSERT INTO delivery_keys (card_key, profile_id, plan_tier, tunnel_secret, expires_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                record["card_key"],
                record["profile_id"],
                record["plan_tier"],
                record["tunnel_secret"],
                record["expires_at"],
            ),
        )

    async def get_delivery_key(self, card_key: str) -> dict[str, Any] | None:
        return await self.fetch_one("SELECT * FROM delivery_keys WHERE card_key = ?", (card_key,))

    async def list_delivery_keys(self, profile_id: str) -> list[dict[str, Any]]:
        return await self.fetch_all(
            "SELECT * FROM delivery_keys WHERE profile_id = ? ORDER BY expires_at", (profile_id,)
        )

    async def revoke_delivery_key(self, card_key: str) -> None:
        await self.execute("UPDATE delivery_keys SET is_active = 0 WHERE card_key = ?", (card_key,))

    async def active_delivery_key(self, card_key: str, now_iso: str) -> dict[str, Any] | None:
        """Resolve a key that is active *and* unexpired, joined with its profile."""
        return await self.fetch_one(
            "SELECT d.*, p.local_proxy_port, p.expected_ip, p.os_type, p.noise_seed,"
            " p.fingerprint_json, p.geo_json, p.status AS profile_status, p.active_session_id"
            " FROM delivery_keys d JOIN profiles p ON p.profile_id = d.profile_id"
            " WHERE d.card_key = ? AND d.is_active = 1 AND d.expires_at > ?",
            (card_key, now_iso),
        )

    async def set_batch(self, profile_id: str, batch_id: str) -> None:
        await self.execute("UPDATE profiles SET batch_id = ? WHERE profile_id = ?", (batch_id, profile_id))


@asynccontextmanager
async def open_database(path: str | Path) -> AsyncIterator[Database]:
    database = Database(path)
    await database.connect()
    try:
        yield database
    finally:
        await database.close()
