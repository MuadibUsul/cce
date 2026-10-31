"""sing-box config rendering: one inbound per profile, correct routing."""

from __future__ import annotations

import json

import pytest

from core.singbox_manager import SingBoxError, SingBoxManager, build_outbound


def test_register_and_render_one_route() -> None:
    manager = SingBoxManager()
    manager.register("acct-1", 10001, "socks5://user:pw@1.2.3.4:1080")

    config = manager.render()
    assert len(config["inbounds"]) == 1
    assert config["inbounds"][0]["listen_port"] == 10001
    assert config["outbounds"][0]["server"] == "1.2.3.4"
    assert config["outbounds"][0]["username"] == "user"
    routes = [rule for rule in config["route"]["rules"] if rule.get("type") == "default"]
    assert routes[0]["inbound"] == config["inbounds"][0]["tag"]
    assert routes[0]["outbound"] == config["outbounds"][0]["tag"]


def test_routes_are_isolated_per_port() -> None:
    manager = SingBoxManager()
    manager.register("acct-1", 10001, "socks5://1.1.1.1:1080")
    manager.register("acct-2", 10002, "socks5://2.2.2.2:1080")

    config = manager.render()
    assert len(config["inbounds"]) == 2
    for rule in (rule for rule in config["route"]["rules"] if rule.get("type") == "default"):
        inbound = next(i for i in config["inbounds"] if i["tag"] == rule["inbound"])
        outbound = next(o for o in config["outbounds"] if o["tag"] == rule["outbound"])
        assert inbound["listen_port"] == 10001 if outbound["server"] == "1.1.1.1" else 10002


def test_sniff_precedes_routing() -> None:
    """sing-box 1.11 moved sniffing to a route action; it must run first."""
    manager = SingBoxManager()
    manager.register("acct-1", 10001, "socks5://1.1.1.1:1080")
    rules = manager.render()["route"]["rules"]
    assert rules[0] == {"action": "sniff"}
    assert all(rule.get("type") == "default" for rule in rules[1:])


def test_unregister_removes_route() -> None:
    manager = SingBoxManager()
    manager.register("acct-1", 10001, "socks5://1.1.1.1:1080")
    manager.unregister(10001)
    assert manager.render()["inbounds"] == []


def test_http_upstream_scheme() -> None:
    outbound = build_outbound("http://user:pw@5.6.7.8:3128", 10001)
    assert outbound["type"] == "http"
    assert outbound["server_port"] == 3128


def test_unsupported_scheme() -> None:
    with pytest.raises(SingBoxError, match="unsupported"):
        build_outbound("ftp://1.2.3.4:21", 10001)


def test_missing_port() -> None:
    with pytest.raises(SingBoxError, match="host and port"):
        build_outbound("socks5://1.2.3.4", 10001)


def test_password_with_special_chars_is_decoded() -> None:
    outbound = build_outbound("socks5://u:p%40ss%3Aword@1.2.3.4:1080", 10001)
    assert outbound["password"] == "p@ss:word"


def test_write_config_creates_file(tmp_path) -> None:
    manager = SingBoxManager(config_path=tmp_path / "singbox.json")
    manager.register("acct-1", 10001, "socks5://1.1.1.1:1080")
    path = manager.write_config()

    written = json.loads(path.read_text())
    assert written["inbounds"][0]["listen_port"] == 10001


@pytest.mark.asyncio
async def test_reload_without_routes_raises() -> None:
    with pytest.raises(SingBoxError, match="no routes"):
        await SingBoxManager().reload()


@pytest.mark.asyncio
async def test_reload_without_binary_degrades_to_config_only(tmp_path) -> None:
    manager = SingBoxManager(config_path=tmp_path / "singbox.json", binary="definitely-not-installed")
    manager.register("acct-1", 10001, "socks5://1.1.1.1:1080")

    result = await manager.reload()
    assert result["applied"] is False
    assert "not found" in result["reason"]
