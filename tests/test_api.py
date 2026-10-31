"""API surface: auth gates, profile lifecycle, key issuing, launcher session."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import pytest_asyncio
from api.app import create_app
from conftest import MASTER_KEY

ADMIN = "test-admin-token"
GOOD_IP = "203.0.113.7"


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CCE_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("CCE_MASTER_KEY", MASTER_KEY)
    monkeypatch.setenv("CCE_DB_PATH", str(tmp_path / "api.sqlite3"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "profiles").mkdir(parents=True, exist_ok=True)

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        # ASGITransport skips startup events, so run them by hand.
        for handler in app.router.on_startup:
            await handler()
        try:
            yield http
        finally:
            for handler in app.router.on_shutdown:
                await handler()


def admin() -> dict[str, str]:
    return {"x-admin-token": ADMIN}


async def _create_profile(client: httpx.AsyncClient, profile_id: str = "acct-api") -> dict:
    response = await client.post(
        "/admin/profiles",
        headers=admin(),
        json={
            "profile_id": profile_id,
            "upstream_proxy_url": "socks5://u:p@1.2.3.4:1080",
            "expected_ip": GOOD_IP,
            "os_type": "macos",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_healthz_is_open(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["ok"] is True


@pytest.mark.asyncio
async def test_readyz_reports_missing_config(monkeypatch: pytest.MonkeyPatch, client: httpx.AsyncClient) -> None:
    monkeypatch.delenv("CCE_ADMIN_TOKEN", raising=False)
    response = await client.get("/readyz")
    assert response.status_code == 503
    assert "CCE_ADMIN_TOKEN unset" in response.json()["problems"]


@pytest.mark.asyncio
async def test_admin_routes_reject_without_token(client: httpx.AsyncClient) -> None:
    assert (await client.get("/admin/profiles")).status_code == 401
    assert (await client.get("/admin/profiles", headers={"x-admin-token": "wrong"})).status_code == 401


@pytest.mark.asyncio
async def test_create_profile_hides_secrets(client: httpx.AsyncClient) -> None:
    body = await _create_profile(client)
    assert body["profile_id"] == "acct-api"
    assert body["local_proxy_port"] >= 10001
    assert "upstream_proxy_url" not in body
    assert "fingerprint_json" not in body
    assert body["has_credentials"] is False


@pytest.mark.asyncio
async def test_duplicate_profile_returns_400(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    response = await client.post(
        "/admin/profiles",
        headers=admin(),
        json={
            "profile_id": "acct-api",
            "upstream_proxy_url": "socks5://u:p@1.2.3.4:1080",
            "expected_ip": GOOD_IP,
        },
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_invalid_profile_id_rejected(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/admin/profiles",
        headers=admin(),
        json={"profile_id": "bad id!", "upstream_proxy_url": "socks5://a:1", "expected_ip": GOOD_IP},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_missing_profile_404(client: httpx.AsyncClient) -> None:
    assert (await client.get("/admin/profiles/ghost", headers=admin())).status_code == 404


@pytest.mark.asyncio
async def test_batch_cap_via_api(client: httpx.AsyncClient) -> None:
    await client.post(
        "/admin/batches",
        headers=admin(),
        json={"batch_id": "b1", "bin_prefix": "424242", "billing_country": "US", "max_accounts": 1},
    )
    payload = {
        "upstream_proxy_url": "socks5://u:p@1.2.3.4:1080",
        "expected_ip": GOOD_IP,
        "batch_id": "b1",
    }
    assert (
        await client.post("/admin/profiles", headers=admin(), json={**payload, "profile_id": "b1-one"})
    ).status_code == 201
    assert (
        await client.post("/admin/profiles", headers=admin(), json={**payload, "profile_id": "b1-two"})
    ).status_code == 400


@pytest.mark.asyncio
async def test_key_issue_and_launcher_session(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    issued = await client.post(
        "/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "max_5x", "valid_days": 5}
    )
    assert issued.status_code == 201
    key = issued.json()

    session = await client.post(
        "/launcher/session",
        headers={"authorization": f"Bearer {key['card_key']}", "x-tunnel-secret": key["tunnel_secret"]},
    )
    assert session.status_code == 200
    body = session.json()
    assert body["session_id"]
    assert body["profile_id"] == "acct-api"
    assert body["plan_tier"] == "max_5x"
    assert body["fingerprint"]["user_agent"].startswith("Mozilla/5.0")
    assert "secret" not in body["tunnel"]


@pytest.mark.asyncio
async def test_launcher_session_requires_both_factors(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    key = (
        await client.post(
            "/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"}
        )
    ).json()
    auth = {"authorization": f"Bearer {key['card_key']}"}

    assert (await client.post("/launcher/session")).status_code == 401
    assert (await client.post("/launcher/session", headers=auth)).status_code == 403
    headers = auth | {"x-tunnel-secret": key["tunnel_secret"]}
    session = await client.post("/launcher/session", headers=headers)
    assert session.status_code == 200

    # Later routes need both factors and the active session identifier.
    assert (await client.post("/launcher/heartbeat", headers=auth)).status_code == 403
    assert (await client.get("/launcher/credentials", headers=auth)).status_code == 403
    assert (
        await client.get(
            "/launcher/credentials", headers=auth | {"x-tunnel-secret": "wrong"}
        )
    ).status_code == 403
    assert (await client.get("/launcher/credentials", headers=headers)).status_code == 409
    assert (await client.get("/launcher/credentials", headers=headers | {
        "x-session-id": session.json()["session_id"]
    })).status_code == 404


@pytest.mark.asyncio
async def test_issued_secret_is_exported_for_the_gateway(client: httpx.AsyncClient) -> None:
    """The gateway authorises per key, so issue/revoke has to reach its file."""
    from api import app as app_module

    await _create_profile(client)
    key = (
        await client.post(
            "/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"}
        )
    ).json()
    path = app_module.Path(app_module.state.db.path).with_suffix(".secrets")
    body = path.read_text()
    assert f"{key['card_key']} {key['tunnel_secret']}" in body
    assert " 10001\n" in body

    await client.delete(f"/admin/keys/{key['card_key']}", headers=admin())
    assert key["tunnel_secret"] not in path.read_text()


async def test_revoked_key_rejected(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    key = (
        await client.post(
            "/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"}
        )
    ).json()

    await client.delete(f"/admin/keys/{key['card_key']}", headers=admin())
    response = await client.post(
        "/launcher/session",
        headers={"authorization": f"Bearer {key['card_key']}", "x-tunnel-secret": key["tunnel_secret"]},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_session_claim_is_exclusive_and_stale_reports_cannot_finish_a_new_session(
    client: httpx.AsyncClient,
) -> None:
    await _create_profile(client)
    key = (await client.post("/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"})).json()
    auth = {"authorization": f"Bearer {key['card_key']}", "x-tunnel-secret": key["tunnel_secret"]}
    first, rejected = await asyncio.gather(
        client.post("/launcher/session", headers=auth),
        client.post("/launcher/session", headers=auth),
    )
    assert sorted([first.status_code, rejected.status_code]) == [200, 409]
    if first.status_code != 200:
        first = rejected

    await client.post("/admin/profiles/acct-api/release", headers=admin())
    second = await client.post("/launcher/session", headers=auth)
    assert second.status_code == 200
    assert second.json()["session_id"] != first.json()["session_id"]
    stale = await client.post("/launcher/status", headers=auth | {
        "x-session-id": first.json()["session_id"]
    }, json={"status": "IDLE"})
    assert stale.status_code == 409
    assert (await client.get("/admin/profiles/acct-api", headers=admin())).json()["status"] == "BUSY"


@pytest.mark.asyncio
async def test_banned_and_cooling_profiles_cannot_start_or_use_the_gateway(client: httpx.AsyncClient) -> None:
    from api import app as app_module

    await _create_profile(client)
    key = (await client.post("/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"})).json()
    auth = {"authorization": f"Bearer {key['card_key']}", "x-tunnel-secret": key["tunnel_secret"]}
    path = app_module.Path(app_module.state.db.path).with_suffix(".secrets")
    assert key["tunnel_secret"] in path.read_text()
    for blocked in ("COOLDOWN", "BANNED", "PROXY_DEAD"):
        await client.post("/admin/profiles/acct-api/status", headers=admin(), json={"status": blocked})
        assert (await client.post("/launcher/session", headers=auth)).status_code == 409
        assert key["tunnel_secret"] not in path.read_text()
    await client.post("/admin/profiles/acct-api/release", headers=admin())
    assert key["tunnel_secret"] in path.read_text()
    assert (await client.post("/launcher/session", headers=auth)).status_code == 200


@pytest.mark.asyncio
async def _launcher_headers(client: httpx.AsyncClient, profile_id: str = "acct-api") -> dict[str, str]:
    """Both factors and the claimed session, as the launcher sends them."""
    key = (
        await client.post(
            "/admin/keys", headers=admin(), json={"profile_id": profile_id, "plan_tier": "pro"}
        )
    ).json()
    headers = {
        "authorization": f"Bearer {key['card_key']}",
        "x-tunnel-secret": key["tunnel_secret"],
    }
    session = await client.post("/launcher/session", headers=headers)
    assert session.status_code == 200
    return headers | {"x-session-id": session.json()["session_id"]}


async def test_heartbeat_flags_ip_drift(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    key = (
        await client.post(
            "/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"}
        )
    ).json()
    headers = {
        "authorization": f"Bearer {key['card_key']}",
        "x-tunnel-secret": key["tunnel_secret"],
        "x-observed-ip": "198.51.100.4",
    }
    session = await client.post("/launcher/session", headers=headers)
    headers["x-session-id"] = session.json()["session_id"]

    body = (await client.post("/launcher/heartbeat", headers=headers)).json()
    assert body["ip_drift"] is True
    profile = (await client.get("/admin/profiles/acct-api", headers=admin())).json()
    assert profile["status"] == "PROXY_DEAD"


@pytest.mark.asyncio
async def test_credentials_404_when_unsynced(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    key = (
        await client.post(
            "/admin/keys", headers=admin(), json={"profile_id": "acct-api", "plan_tier": "pro"}
        )
    ).json()
    headers = {"authorization": f"Bearer {key['card_key']}", "x-tunnel-secret": key["tunnel_secret"]}
    session = await client.post("/launcher/session", headers=headers)
    response = await client.get("/launcher/credentials", headers=headers | {
        "x-session-id": session.json()["session_id"]
    })
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_singbox_state_endpoint(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    body = (await client.get("/admin/singbox", headers=admin())).json()
    assert body["config"]["inbounds"][0]["listen_port"] >= 10001


async def test_routes_are_rebuilt_from_the_database_on_startup(tmp_path, monkeypatch) -> None:
    """A restart must not orphan profiles whose ports live only in memory."""
    monkeypatch.setenv("CCE_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("CCE_MASTER_KEY", MASTER_KEY)
    monkeypatch.setenv("CCE_DB_PATH", str(tmp_path / "restart.sqlite3"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "profiles").mkdir(parents=True, exist_ok=True)

    first = create_app()
    transport = httpx.ASGITransport(app=first)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        for handler in first.router.on_startup:
            await handler()
        await _create_profile(http)
        for handler in first.router.on_shutdown:
            await handler()

    second = create_app()
    transport = httpx.ASGITransport(app=second)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        for handler in second.router.on_startup:
            await handler()
        try:
            body = (await http.get("/admin/singbox", headers=admin())).json()
            assert [inbound["listen_port"] for inbound in body["config"]["inbounds"]] == [10001]
        finally:
            for handler in second.router.on_shutdown:
                await handler()


@pytest.mark.asyncio
async def test_launcher_reports_auth_expiry(client: httpx.AsyncClient) -> None:
    """The gateway cannot see HTTP status, so this report is the only trigger."""
    await _create_profile(client)
    headers = await _launcher_headers(client)

    body = (
        await client.post(
            "/launcher/status",
            headers=headers,
            json={"status": "AUTH_EXPIRED", "reason": "API Error: 401"},
        )
    ).json()

    assert body["applied"] is True
    profile = (await client.get("/admin/profiles/acct-api", headers=admin())).json()
    assert profile["status"] == "AUTH_EXPIRED"


@pytest.mark.asyncio
async def test_launcher_reports_a_cooldown_deadline(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    body = (
        await client.post(
            "/launcher/status",
            headers=await _launcher_headers(client),
            json={"status": "COOLDOWN", "reason": "usage limit", "cooldown_seconds": 7200},
        )
    ).json()

    assert body["applied"] is True
    profile = (await client.get("/admin/profiles/acct-api", headers=admin())).json()
    assert profile["status"] == "COOLDOWN"
    assert profile["cooldown_until"] is not None


@pytest.mark.asyncio
async def test_illegal_launcher_report_is_not_an_error(client: httpx.AsyncClient) -> None:
    """A late report from a session that already moved on is a no-op."""
    await _create_profile(client)
    headers = await _launcher_headers(client)
    await client.post("/admin/profiles/acct-api/status", headers=admin(), json={"status": "BANNED"})

    response = await client.post("/launcher/status", headers=headers, json={"status": "BUSY"})

    assert response.status_code == 409


@pytest.mark.asyncio
async def test_status_report_needs_the_tunnel_secret(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    headers = await _launcher_headers(client)
    del headers["x-tunnel-secret"]
    response = await client.post("/launcher/status", headers=headers, json={"status": "IDLE"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unknown_status_is_refused(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    response = await client.post(
        "/launcher/status", headers=await _launcher_headers(client), json={"status": "SLEEPING"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_admin_release_frees_a_stuck_row(client: httpx.AsyncClient) -> None:
    await _create_profile(client)
    await client.post(
        "/admin/profiles/acct-api/status", headers=admin(), json={"status": "COOLDOWN"}
    )
    body = (await client.post("/admin/profiles/acct-api/release", headers=admin())).json()
    assert body["status"] == "IDLE"
    profile = (await client.get("/admin/profiles/acct-api", headers=admin())).json()
    assert profile["status"] == "IDLE"
