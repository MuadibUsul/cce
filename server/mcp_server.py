"""FastMCP admin surface — the same operations as the HTTP admin API.

Operators drive fleet work (provision a batch, preflight, sync credentials) from
an MCP client instead of curl. Every tool is thin: it resolves the shared
services and delegates, so behaviour never forks between the two front doors.
"""

from __future__ import annotations

import json
import os
from typing import Any

from fastmcp import FastMCP

from core.browser_pool import BrowserPool
from core.profile_manager import ProfileError, ProfileManager
from core.proxy_inspector import ProxyKillSwitchError, ProxyInspector
from core.singbox_manager import SingBoxManager
from db.database import Database
from util.ids import new_card_key, new_token

DB_PATH = os.environ.get("CCE_DB_PATH", "data/cce.sqlite3")

mcp: FastMCP = FastMCP(
    name="claude-cluster-engine",
    instructions=(
        "Control plane for isolated Claude accounts. Always preflight a profile "
        "before launching it: the kill switch aborts on a dead tunnel or a drifted IP."
    ),
)

_services: dict[str, Any] = {}


async def _services_ready() -> dict[str, Any]:
    """Lazily build the service graph; MCP calls can arrive in any order."""
    if not _services:
        database = Database(DB_PATH)
        await database.connect()
        profiles = ProfileManager(database)
        inspector = ProxyInspector(database)
        _services.update(
            db=database,
            profiles=profiles,
            inspector=inspector,
            pool=BrowserPool(database, profiles, inspector),
            singbox=SingBoxManager(),
        )
    return _services


@mcp.tool(description="Create a payment batch (max N accounts, shared BIN/country).")
async def create_batch(batch_id: str, bin_prefix: str, billing_country: str, max_accounts: int = 10) -> dict[str, Any]:
    services = await _services_ready()
    await services["db"].create_batch(batch_id, bin_prefix, billing_country.upper(), max_accounts)
    return {"batch": await services["db"].get_batch(batch_id)}


@mcp.tool(description="Create an isolated profile: frozen fingerprint, proxy port, frozen egress IP.")
async def create_profile(
    profile_id: str,
    upstream_proxy_url: str,
    expected_ip: str,
    os_type: str = "macos",
    batch_id: str | None = None,
) -> dict[str, Any]:
    services = await _services_ready()
    record = await services["profiles"].create_profile(
        profile_id=profile_id,
        upstream_proxy_url=upstream_proxy_url,
        expected_ip=expected_ip,
        os_type=os_type,
        batch_id=batch_id,
    )
    services["singbox"].register(profile_id, record["local_proxy_port"], upstream_proxy_url)
    return _public(record)


@mcp.tool(description="Run the kill switch: verify the tunnel is live and egresses from the expected IP.")
async def preflight_profile(profile_id: str) -> dict[str, Any]:
    services = await _services_ready()
    try:
        geo = await services["inspector"].verify_and_inspect(profile_id)
    except ProxyKillSwitchError as exc:
        return {"ok": False, "reason": exc.reason, "detail": str(exc)}
    return {"ok": True, "profile_id": profile_id, "geo": geo.to_json()}


@mcp.tool(description="Launch the fingerprinted browser and compare observed values with the stored ones.")
async def stealth_check(profile_id: str) -> dict[str, Any]:
    services = await _services_ready()
    return await services["pool"].verify_stealth(profile_id)


@mcp.tool(description="Run `claude login` inside the profile, encrypt and store the resulting credentials.")
async def sync_credentials(profile_id: str) -> dict[str, Any]:
    services = await _services_ready()
    blob = await services["pool"].sync_claude_cli_credentials(profile_id)
    return {"profile_id": profile_id, "stored_bytes": len(blob)}


@mcp.tool(description="Scrub browser caches for a profile, keeping cookies and prefs.")
async def scrub_cache(profile_id: str) -> dict[str, Any]:
    services = await _services_ready()
    profile = await services["db"].get_profile(profile_id)
    if profile is None:
        raise ProfileError(f"profile not found: {profile_id}")
    freed = services["profiles"].scrub_profile_cache(profile_id)
    return {"profile_id": profile_id, "freed": freed, "disk_bytes": services["profiles"].profile_disk_usage(profile_id)}


@mcp.tool(description="Render sing-box config for every registered route and restart the relay.")
async def reload_relay() -> dict[str, Any]:
    services = await _services_ready()
    for row in await services["db"].list_profiles():
        services["singbox"].register(row["profile_id"], row["local_proxy_port"], row["upstream_proxy_url"])
    return await services["singbox"].reload()


@mcp.tool(description="Issue a delivery card key + tunnel secret for a profile.")
async def issue_key(profile_id: str, plan_tier: str = "pro", valid_days: int = 30) -> dict[str, Any]:
    from datetime import datetime, timedelta, timezone

    services = await _services_ready()
    profile = await services["db"].get_profile(profile_id)
    if profile is None:
        raise ProfileError(f"profile not found: {profile_id}")
    card_key = new_card_key()
    secret = new_token(18)
    expires = (datetime.now(timezone.utc) + timedelta(days=valid_days)).isoformat()
    await services["db"].insert_delivery_key(
        {
            "card_key": card_key,
            "profile_id": profile_id,
            "plan_tier": plan_tier,
            "tunnel_secret": secret,
            "expires_at": expires,
        }
    )
    return {"card_key": card_key, "tunnel_secret": secret, "expires_at": expires}


@mcp.tool(description="Fleet status: counts per state plus per-profile rows.")
async def fleet_status() -> dict[str, Any]:
    services = await _services_ready()
    rows = await services["db"].list_profiles()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {"counts": counts, "profiles": [_public(row) for row in rows]}


def _public(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile_id": row["profile_id"],
        "batch_id": row.get("batch_id"),
        "status": row["status"],
        "os_type": row["os_type"],
        "local_proxy_port": row["local_proxy_port"],
        "expected_ip": row["expected_ip"],
        "has_credentials": row.get("claude_credentials_enc") is not None,
        "fingerprint": json.loads(row["fingerprint_json"]),
    }


if __name__ == "__main__":
    mcp.run()
