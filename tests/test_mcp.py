"""MCP tool surface: registration, batch cap, failure reporting."""

from __future__ import annotations

import pytest

import mcp_server
from conftest import MASTER_KEY


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "DB_PATH", str(tmp_path / "mcp.sqlite3"))
    monkeypatch.setenv("CCE_MASTER_KEY", MASTER_KEY)
    monkeypatch.chdir(tmp_path)
    mcp_server._services.clear()
    yield
    mcp_server._services.clear()


@pytest.mark.asyncio
async def test_all_tools_registered() -> None:
    names = {tool.name for tool in await mcp_server.mcp.list_tools()}
    assert names == {
        "create_batch",
        "create_profile",
        "preflight_profile",
        "stealth_check",
        "sync_credentials",
        "scrub_cache",
        "reload_relay",
        "issue_key",
        "fleet_status",
    }


@pytest.mark.asyncio
async def test_create_profile_and_fleet_status() -> None:
    created = await mcp_server.create_profile(
        profile_id="acct-mcp",
        upstream_proxy_url="socks5://u:p@1.2.3.4:1080",
        expected_ip="203.0.113.5",
    )
    assert created["profile_id"] == "acct-mcp"
    assert created["fingerprint"]["user_agent"].startswith("Mozilla/5.0")

    status = await mcp_server.fleet_status()
    assert status["counts"] == {"IDLE": 1}
    assert status["profiles"][0]["local_proxy_port"] >= 10001


@pytest.mark.asyncio
async def test_batch_cap_surfaces_as_error() -> None:
    await mcp_server.create_batch("b-mcp", "424242", "US", 1)
    payload = {
        "upstream_proxy_url": "socks5://u:p@1.2.3.4:1080",
        "expected_ip": "203.0.113.5",
        "batch_id": "b-mcp",
    }
    await mcp_server.create_profile(profile_id="mcp-one", **payload)

    from core.profile_manager import ProfileError

    with pytest.raises(ProfileError, match="full"):
        await mcp_server.create_profile(profile_id="mcp-two", **payload)


@pytest.mark.asyncio
async def test_preflight_reports_kill_switch_failure(monkeypatch) -> None:
    await mcp_server.create_profile(
        profile_id="acct-dead",
        upstream_proxy_url="socks5://dead:1080",
        expected_ip="203.0.113.5",
    )
    services = await mcp_server._services_ready()

    async def boom(_profile_id: str):
        from core.proxy_inspector import ProxyKillSwitchError

        raise ProxyKillSwitchError("egress IP drift", reason="ip_drift")

    monkeypatch.setattr(services["inspector"], "verify_and_inspect", boom)
    result = await mcp_server.preflight_profile("acct-dead")

    assert result["ok"] is False
    assert result["reason"] == "ip_drift"


@pytest.mark.asyncio
async def test_issue_key_creates_active_key() -> None:
    await mcp_server.create_profile(
        profile_id="acct-key", upstream_proxy_url="socks5://u:p@1.2.3.4:1080", expected_ip="203.0.113.5"
    )
    issued = await mcp_server.issue_key("acct-key", "max_20x", 3)

    services = await mcp_server._services_ready()
    row = await services["db"].get_delivery_key(issued["card_key"])
    assert row is not None and row["plan_tier"] == "max_20x"
    assert row["tunnel_secret"] == issued["tunnel_secret"]


@pytest.mark.asyncio
async def test_scrub_reports_disk_usage() -> None:
    await mcp_server.create_profile(
        profile_id="acct-scrub", upstream_proxy_url="socks5://u:p@1.2.3.4:1080", expected_ip="203.0.113.5"
    )
    result = await mcp_server.scrub_cache("acct-scrub")
    assert result["profile_id"] == "acct-scrub"
    assert result["disk_bytes"] == 0


@pytest.mark.asyncio
async def test_scrub_unknown_profile_raises() -> None:
    from core.profile_manager import ProfileError

    with pytest.raises(ProfileError):
        await mcp_server.scrub_cache("ghost")
