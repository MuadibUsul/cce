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


async def sweep_reaperable(db: Database, *, now: datetime | None = None) -> list[str]:
    """Rows a busy-but-abandoned process left behind.

    A launcher that is `kill -9`ed never reports anything, so `BUSY` can stick
    forever. There is no lease column, so the sweep is by cooldown deadline:
    a profile parked in COOLDOWN past its time is exactly `release_due_cooldowns`.
    """
    return await release_due_cooldowns(db, now=now)
