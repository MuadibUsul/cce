"""MCP tool surface: registration, batch cap, failure reporting."""

from __future__ import annotations

import mcp_server
import pytest
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
    # SPEC 4.6 fixes three of these names; an external orchestrator calls them
    # literally, so they are part of the contract and not a style choice.
    assert names == {
        "create_isolated_profile",
        "verify_profile_stealth",
        "issue_customer_card_key",
        "create_account_batch",
        "preflight_profile",
        "sync_credentials",
        "scrub_cache",
        "reload_relay",
        "fleet_status",
    }


@pytest.mark.asyncio
async def test_create_profile_and_fleet_status() -> None:
    created = await mcp_server.create_isolated_profile(
        profile_id="acct-mcp",
        local_proxy_port=10042,
        upstream_proxy_url="socks5://u:p@1.2.3.4:1080",
        expected_ip="203.0.113.5",
    )
    assert created["profile_id"] == "acct-mcp"
    assert created["local_proxy_port"] == 10042
    assert created["fingerprint"]["user_agent"].startswith("Mozilla/5.0")

    status = await mcp_server.fleet_status()
    assert status["counts"] == {"IDLE": 1}
    assert status["profiles"][0]["local_proxy_port"] >= 10001


@pytest.mark.asyncio
async def test_batch_cap_surfaces_as_error() -> None:
    await mcp_server.create_account_batch("b-mcp", "424242", "US", 1)
    payload = {
        "upstream_proxy_url": "socks5://u:p@1.2.3.4:1080",
        "expected_ip": "203.0.113.5",
        "batch_id": "b-mcp",
    }
    await mcp_server.create_isolated_profile(profile_id="mcp-one", local_proxy_port=None, **payload)

    from core.profile_manager import ProfileError

    with pytest.raises(ProfileError, match="full"):
        await mcp_server.create_isolated_profile(profile_id="mcp-two", local_proxy_port=None, **payload)


@pytest.mark.asyncio
async def test_preflight_reports_kill_switch_failure(monkeypatch) -> None:
    await mcp_server.create_isolated_profile(
        profile_id="acct-dead",
        local_proxy_port=None,
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
async def test_issue_key_creates_active_key(tmp_path) -> None:
    await mcp_server.create_isolated_profile(
        profile_id="acct-key",
        local_proxy_port=None,
        upstream_proxy_url="socks5://u:p@1.2.3.4:1080",
        expected_ip="203.0.113.5",
    )
    issued = await mcp_server.issue_customer_card_key("acct-key", "max_20x", 3)

    services = await mcp_server._services_ready()
    row = await services["db"].get_delivery_key(issued["card_key"])
    assert row is not None and row["plan_tier"] == "max_20x"
    assert row["tunnel_secret"] == issued["tunnel_secret"]
    exported = (tmp_path / "mcp.secrets").read_text()
    assert f"{issued['card_key']} {issued['tunnel_secret']}" in exported
    assert f" {row['expires_at']} 10001\n" in exported


@pytest.mark.asyncio
async def test_scrub_reports_disk_usage() -> None:
    await mcp_server.create_isolated_profile(
        profile_id="acct-scrub",
        local_proxy_port=None,
        upstream_proxy_url="socks5://u:p@1.2.3.4:1080",
        expected_ip="203.0.113.5",
    )
    result = await mcp_server.scrub_cache("acct-scrub")
    assert result["profile_id"] == "acct-scrub"
    assert result["disk_bytes"] == 0


@pytest.mark.asyncio
async def test_scrub_unknown_profile_raises() -> None:
    from core.profile_manager import ProfileError

    with pytest.raises(ProfileError):
        await mcp_server.scrub_cache("ghost")


@pytest.mark.asyncio
async def test_knowledge_resources_are_served() -> None:
    """An orchestrator bootstraps from these; they must be real and non-empty."""
    uris = {str(resource.uri) for resource in await mcp_server.mcp.list_resources()}
    assert "veynod://knowledge/cluster-spec" in uris
    assert "veynod://knowledge/cluster-ops" in uris

    spec = (await mcp_server.mcp.read_resource("veynod://knowledge/cluster-spec")).contents[0].content
    assert "create_isolated_profile" in spec

    ops = (await mcp_server.mcp.read_resource("veynod://knowledge/cluster-ops")).contents[0].content
    assert ops.strip()


@pytest.mark.asyncio
async def test_spec_tool_names_match_the_contract() -> None:
    """Guards the SPEC 4.6 signatures; a rename here breaks other agents."""
    spec = (await mcp_server.mcp.read_resource("veynod://knowledge/cluster-spec")).contents[0].content
    for required in (
        "create_isolated_profile",
        "verify_profile_stealth",
        "issue_customer_card_key",
        'mcp.resource("veynod://knowledge/cluster-spec")',
    ):
        assert required in spec
