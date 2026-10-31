"""Profile status transitions, cooldown arithmetic and the recovery sweep.

A status is not a label here, it is a claim about what may happen next: `BUSY`
means a session owns the row, `COOLDOWN` means the account is resting after a
rhythm flag, `AUTH_EXPIRED` means the stored token no longer works. Everything
that reads a profile branches on it, so an illegal jump (say `BANNED` back to
`BUSY` without anyone looking) has to be refused rather than written.

The gateway sits on plain TLS and therefore cannot read an HTTP status inside
the tunnel, so it can never spot an expired token itself. That judgement always
comes from the launcher, which lands here through the control plane.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from db.database import PROFILE_STATUSES, Database

# Where each status may go. A status may always repeat itself: two heartbeats
# that both report drift are not an error.
ALLOWED: dict[str, frozenset[str]] = {
    "IDLE": frozenset({"BUSY", "COOLDOWN", "AUTH_EXPIRED", "PROXY_DEAD", "BANNED"}),
    "BUSY": frozenset({"IDLE", "COOLDOWN", "AUTH_EXPIRED", "PROXY_DEAD", "BANNED"}),
    "COOLDOWN": frozenset({"IDLE", "BUSY", "PROXY_DEAD", "BANNED"}),
    "AUTH_EXPIRED": frozenset({"IDLE", "BUSY", "COOLDOWN", "PROXY_DEAD", "BANNED"}),
    "PROXY_DEAD": frozenset({"IDLE", "BUSY", "BANNED"}),
    "BANNED": frozenset({"IDLE"}),
}

# How long a rhythm flag rests the account. Longer than a session so a human can
# react; short enough that the row is not lost for a day.
COOLDOWN = timedelta(minutes=30)
# The longest a single cooldown may ask for, so a bug cannot park a fleet.
COOLDOWN_MAX = timedelta(hours=24)
# How long a BUSY row may go without a heartbeat before it is reclaimed. A
# launcher that is killed or loses power never reports its own exit, so the
# lease has to expire on the server or the account is stranded forever.
LEASE_TIMEOUT = timedelta(seconds=120)


class IllegalTransition(RuntimeError):
    """Raised when a caller asks for a jump the state machine forbids."""

    def __init__(self, profile_id: str, current: str, target: str) -> None:
        super().__init__(f"{profile_id}: {current} -> {target} is not allowed")
        self.profile_id = profile_id
        self.current = current
        self.target = target


def allows(current: str, target: str) -> bool:
    if target not in PROFILE_STATUSES:
        raise ValueError(f"unknown profile status: {target}")
    return target == current or target in ALLOWED.get(current, frozenset())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def cooldown_until(duration: timedelta | None = None, *, now: datetime | None = None) -> str:
    """ISO deadline for a cooldown, clamped to the maximum."""
    span = duration or COOLDOWN
    if span > COOLDOWN_MAX:
        span = COOLDOWN_MAX
    if span < timedelta(0):
        span = timedelta(0)
    return ((now or _now()) + span).isoformat()


async def mark(
    db: Database,
    profile_id: str,
    target: str,
    *,
    until: str | None = None,
    force: bool = False,
) -> str | None:
    """Move a profile to `target`, refusing an illegal jump.

    Returns the status the row now has. With `force` the table is bypassed and
    the target is written regardless -- an operator override.
    """
    row = await db.get_profile(profile_id)
    if row is None:
        raise IllegalTransition(profile_id, "<missing>", target)

    current = row["status"]
    if not force and not allows(current, target):
        raise IllegalTransition(profile_id, current, target)

    if target == "COOLDOWN":
        await db.set_status(profile_id, target, until or cooldown_until())
        return target

    # Every other status clears the deadline, so a stale cooldown cannot keep
    # resurrecting a row that has moved on.
    if current == "COOLDOWN" and target == "IDLE" and not _due(row):
        # Recovering a cooldown early is legitimate, but say so loudly.
        pass
    await db.set_status(profile_id, target)
    return target


def _due(row: dict[str, object], *, now: datetime | None = None) -> bool:
    raw = row.get("cooldown_until")
    if not raw:
        return False
    try:
        return datetime.fromisoformat(str(raw)) <= (now or _now())
    except ValueError:
        return False


async def release_due_cooldowns(db: Database, *, now: datetime | None = None) -> list[str]:
    """Return every profile whose cooldown has run out, and free it.

    One statement does the sweep: the predicate sits in SQL so the deadline is
    compared and the write is atomic with respect to other writers.
    """
    moment = (now or _now()).isoformat()
    rows = await db.fetch_all(
        "SELECT profile_id FROM profiles"
        " WHERE status = 'COOLDOWN' AND cooldown_until IS NOT NULL AND cooldown_until <= ?",
        (moment,),
    )
    released: list[str] = []
    for row in rows:
        await mark(db, str(row["profile_id"]), "IDLE", force=True)
        released.append(str(row["profile_id"]))
    return released


async def reclaim_stale_busy(
    db: Database,
    *,
    now: datetime | None = None,
    lease: timedelta | None = None,
) -> list[str]:
    """Free BUSY rows whose launcher stopped heartbeating.

    A `kill -9` or a power loss leaves `BUSY` behind with nobody to report the
    exit. There is no callback that survives that, so the row carries a lease:
    the claim and every heartbeat stamp `last_heartbeat_at`, and here a row that
    has not been stamped within `lease` is put back to `IDLE`. The row is
    re-checked in the UPDATE, so a heartbeat racing the sweep wins.

    Rows that went BUSY before the lease column existed have no stamp; the
    migration gives them one, so a deploy does not free live sessions.
    """
    cutoff = ((now or _now()) - (lease or LEASE_TIMEOUT)).isoformat()
    rows = await db.fetch_all(
        "SELECT profile_id FROM profiles"
        " WHERE status = 'BUSY' AND (last_heartbeat_at IS NULL OR last_heartbeat_at <= ?)",
        (cutoff,),
    )
    reclaimed: list[str] = []
    for row in rows:
        profile_id = str(row["profile_id"])
        if await db.reclaim_stale_busy(profile_id, cutoff):
            reclaimed.append(profile_id)
    return reclaimed


async def sweep_reaperable(db: Database, *, now: datetime | None = None) -> list[str]:
    """Everything the periodic sweep frees: expired cooldowns and dead leases."""
    released = await release_due_cooldowns(db, now=now)
    reclaimed = await reclaim_stale_busy(db, now=now)
    return released + reclaimed
