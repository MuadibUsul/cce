"""Kill-switch behaviour: dead proxy, IP drift, good path, locale mapping."""

from __future__ import annotations

import httpx
import pytest

from core.profile_manager import ProfileManager
from core.proxy_inspector import (
    ProxyInspector,
    ProxyKillSwitchError,
    locale_for_country,
)
from db.database import Database

GOOD_IP = "203.0.113.7"


def _payload(ip: str = GOOD_IP, country: str = "US") -> dict[str, object]:
    return {
        "status": "success",
        "countryCode": country,
        "regionName": "Oregon",
        "city": "Portland",
        "lat": 45.52,
        "lon": -122.68,
        "timezone": "America/Los_Angeles",
        "query": ip,
    }


class FakeGeo:
    """Stands in for httpx.AsyncClient, keyed by proxy URL."""

    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        responses = self.responses
        calls = self.calls

        class _Client:
            def __init__(self, proxy: str, **_: object) -> None:
                self._proxy = proxy
                calls.append(proxy)

            async def __aenter__(self) -> "_Client":
                return self

            async def __aexit__(self, *_: object) -> None:
                return None

            async def get(self, _url: str) -> httpx.Response:
                result = responses[self._proxy]
                if isinstance(result, Exception):
                    raise result
                return httpx.Response(200, json=result, request=httpx.Request("GET", _url))

        monkeypatch.setattr(httpx, "AsyncClient", _Client)


def _inspector(monkeypatch: pytest.MonkeyPatch, db: Database, responses: dict[str, object]) -> ProxyInspector:
    FakeGeo(responses).install(monkeypatch)
    return ProxyInspector(db)


@pytest.mark.asyncio
async def test_good_proxy_returns_geo(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    inspector = _inspector(monkeypatch, db, {"socks5://ok:1080": _payload()})
    geo = await inspector.inspect("socks5://ok:1080", GOOD_IP)

    assert geo.ip == GOOD_IP
    assert geo.country_code == "US"
    assert geo.locale == "en-US"
    assert geo.timezone == "America/Los_Angeles"


@pytest.mark.asyncio
async def test_ip_drift_aborts(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    inspector = _inspector(monkeypatch, db, {"socks5://ok:1080": _payload(ip="198.51.100.1")})
    with pytest.raises(ProxyKillSwitchError, match="egress IP drift") as info:
        await inspector.inspect("socks5://ok:1080", GOOD_IP)
    assert info.value.reason == "ip_drift"


@pytest.mark.asyncio
async def test_dead_proxy_aborts(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    inspector = _inspector(monkeypatch, db, {"socks5://dead:1080": httpx.ConnectError("refused")})
    with pytest.raises(ProxyKillSwitchError, match="unreachable") as info:
        await inspector.inspect("socks5://dead:1080", GOOD_IP)
    assert info.value.reason == "unreachable"


@pytest.mark.asyncio
async def test_timeout_aborts(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    inspector = _inspector(monkeypatch, db, {"socks5://slow:1080": httpx.TimeoutException("slow")})
    with pytest.raises(ProxyKillSwitchError) as info:
        await inspector.inspect("socks5://slow:1080", GOOD_IP)
    assert info.value.reason == "timeout"


@pytest.mark.asyncio
async def test_geo_failure_status_aborts(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = {"status": "fail", "message": "reserved range"}
    inspector = _inspector(monkeypatch, db, {"socks5://ok:1080": bad})
    with pytest.raises(ProxyKillSwitchError, match="geo lookup failed") as info:
        await inspector.inspect("socks5://ok:1080", GOOD_IP)
    assert info.value.reason == "geo_failed"


@pytest.mark.asyncio
async def test_missing_timezone_aborts(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _payload()
    payload.pop("timezone")
    inspector = _inspector(monkeypatch, db, {"socks5://ok:1080": payload})
    with pytest.raises(ProxyKillSwitchError, match="timezone") as info:
        await inspector.inspect("socks5://ok:1080", GOOD_IP)
    assert info.value.reason == "no_timezone"


@pytest.mark.asyncio
async def test_verify_marks_dead_profile(
    db: Database, profiles: ProfileManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    await profiles.create_profile("acct-dead", upstream_proxy_url="socks5://dead:1080", expected_ip=GOOD_IP)
    inspector = _inspector(monkeypatch, db, {"socks5://dead:1080": httpx.ConnectError("refused")})

    with pytest.raises(ProxyKillSwitchError) as info:
        await inspector.verify_and_inspect("acct-dead")

    assert info.value.profile_id == "acct-dead"
    profile = await db.get_profile("acct-dead")
    assert profile is not None and profile["status"] == "PROXY_DEAD"


@pytest.mark.asyncio
async def test_verify_persists_geo(
    db: Database, profiles: ProfileManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    await profiles.create_profile("acct-ok", upstream_proxy_url="socks5://ok:1080", expected_ip=GOOD_IP)
    inspector = _inspector(monkeypatch, db, {"socks5://ok:1080": _payload()})

    await inspector.verify_and_inspect("acct-ok")

    profile = await db.get_profile("acct-ok")
    assert profile is not None and profile["geo_json"] is not None
    assert "Oregon" in (profile["geo_json"] or "")


@pytest.mark.asyncio
async def test_verify_unknown_profile(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    inspector = _inspector(monkeypatch, db, {})
    with pytest.raises(ProxyKillSwitchError, match="profile not found"):
        await inspector.verify_and_inspect("ghost")


def test_locale_mapping() -> None:
    assert locale_for_country("US") == "en-US"
    assert locale_for_country("jp") == "ja-JP"
    assert locale_for_country("DE") == "de-DE"
    assert locale_for_country(None) == "en-US"
    assert locale_for_country("ZZ") == "en-US"
