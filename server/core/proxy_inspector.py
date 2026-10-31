"""Pre-flight proxy verification — the kill switch.

Nothing launches a browser or a CLI session before this passes. It proves the
proxy actually works *and* that traffic egresses from the IP the profile was
created with. A drifting exit IP is the single most common cause of a ban
cluster, so a mismatch aborts instead of "trying anyway".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import httpx

from core.secret_export import export_secrets
from db.database import Database

GEO_ENDPOINT = "http://ip-api.com/json/?fields=status,message,countryCode,regionName,city,lat,lon,timezone,query"

# country -> BCP 47 locale, used for navigator.language / Accept-Language.
# Deliberately a small explicit table: guessing region variants produces
# identities that look wrong to Cloudflare ("en" on a US residential IP).
LOCALE_BY_COUNTRY: dict[str, str] = {
    "US": "en-US",
    "GB": "en-GB",
    "CA": "en-CA",
    "AU": "en-AU",
    "NZ": "en-NZ",
    "IE": "en-IE",
    "SG": "en-SG",
    "IN": "en-IN",
    "DE": "de-DE",
    "AT": "de-AT",
    "CH": "de-CH",
    "FR": "fr-FR",
    "BE": "fr-BE",
    "NL": "nl-NL",
    "ES": "es-ES",
    "MX": "es-MX",
    "AR": "es-AR",
    "IT": "it-IT",
    "PT": "pt-PT",
    "BR": "pt-BR",
    "SE": "sv-SE",
    "NO": "nb-NO",
    "DK": "da-DK",
    "FI": "fi-FI",
    "PL": "pl-PL",
    "CZ": "cs-CZ",
    "JP": "ja-JP",
    "KR": "ko-KR",
    "TW": "zh-TW",
    "HK": "zh-HK",
    "CN": "zh-CN",
    "IL": "he-IL",
    "TR": "tr-TR",
    "RU": "ru-RU",
    "UA": "uk-UA",
    "ZA": "en-ZA",
    "AE": "en-AE",
}

FALLBACK_LOCALE = "en-US"


class ProxyKillSwitchError(RuntimeError):
    """Raised when a profile must not start: dead tunnel or drifted egress IP."""

    def __init__(self, message: str, *, profile_id: str | None = None, reason: str = "unknown") -> None:
        super().__init__(message)
        self.profile_id = profile_id
        self.reason = reason


@dataclass(frozen=True)
class ProxyGeoInfo:
    ip: str
    country_code: str
    timezone: str
    latitude: float
    longitude: float
    locale: str
    region: str = ""
    city: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def locale_for_country(country_code: str | None) -> str:
    if not country_code:
        return FALLBACK_LOCALE
    return LOCALE_BY_COUNTRY.get(country_code.upper(), FALLBACK_LOCALE)


class ProxyInspector:
    def __init__(self, database: Database, *, timeout: float = 8.0) -> None:
        self._db = database
        self._timeout = timeout

    async def inspect(self, proxy_url: str, expected_ip: str | None = None) -> ProxyGeoInfo:
        """Query the geo endpoint *through* the proxy and validate the result."""
        try:
            async with httpx.AsyncClient(proxy=proxy_url, timeout=self._timeout, trust_env=False) as client:
                response = await client.get(GEO_ENDPOINT)
                response.raise_for_status()
                payload = response.json()
        except httpx.TimeoutException as exc:
            raise ProxyKillSwitchError(f"proxy timed out: {exc}", reason="timeout") from exc
        except httpx.HTTPError as exc:
            raise ProxyKillSwitchError(f"proxy unreachable: {exc}", reason="unreachable") from exc
        except ValueError as exc:
            raise ProxyKillSwitchError(f"geo lookup returned non-JSON: {exc}", reason="bad_payload") from exc

        if payload.get("status") != "success":
            raise ProxyKillSwitchError(
                f"geo lookup failed: {payload.get('message', 'unknown')}", reason="geo_failed"
            )

        actual_ip = str(payload.get("query") or "").strip()
        if not actual_ip:
            raise ProxyKillSwitchError("geo lookup returned no egress IP", reason="no_ip")

        if expected_ip and actual_ip != expected_ip.strip():
            raise ProxyKillSwitchError(
                f"egress IP drift: expected {expected_ip}, got {actual_ip}", reason="ip_drift"
            )

        timezone = str(payload.get("timezone") or "")
        if not timezone:
            raise ProxyKillSwitchError("geo lookup returned no timezone", reason="no_timezone")

        return ProxyGeoInfo(
            ip=actual_ip,
            country_code=str(payload.get("countryCode") or "").upper(),
            timezone=timezone,
            latitude=float(payload.get("lat") or 0.0),
            longitude=float(payload.get("lon") or 0.0),
            locale=locale_for_country(payload.get("countryCode")),
            region=str(payload.get("regionName") or ""),
            city=str(payload.get("city") or ""),
        )

    async def verify_and_inspect(self, profile_id: str) -> ProxyGeoInfo:
        """Profile-scoped variant: marks the row PROXY_DEAD on any failure."""
        profile = await self._db.get_profile(profile_id)
        if profile is None:
            raise ProxyKillSwitchError(f"profile not found: {profile_id}", profile_id=profile_id)

        try:
            geo = await self.inspect(profile["upstream_proxy_url"], profile["expected_ip"])
        except ProxyKillSwitchError as exc:
            exc.profile_id = profile_id
            await self._db.set_status(profile_id, "PROXY_DEAD")
            await export_secrets(self._db)
            raise

        await self._db.save_geo(profile_id, _json_dumps(geo.to_json()))
        return geo


def _json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, separators=(",", ":"))
