"""Camoufox worker pool.

Owns the *only* place a browser is launched, so concurrency, the kill switch and
cache scrubbing cannot be bypassed by a caller. Semaphore-capped because each
Camoufox instance is a full Firefox with its own process tree; five is what a
2 vCPU / 4 GB box carries comfortably.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import tarfile
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from camoufox.async_api import AsyncCamoufox

from core.profile_manager import ProfileManager
from core.proxy_inspector import ProxyGeoInfo, ProxyInspector
from db.database import Database

CLAUDE_URL = "https://claude.ai"
STEALTH_URL = "https://ipinfo.io/json"


class BrowserPoolError(RuntimeError):
    pass


class BrowserPool:
    def __init__(
        self,
        database: Database,
        profiles: ProfileManager,
        inspector: ProxyInspector,
        *,
        max_concurrent: int = 5,
        headless: bool = True,
    ) -> None:
        self._db = database
        self._profiles = profiles
        self._inspector = inspector
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._headless = headless
        self._active: set[str] = set()

    @property
    def active(self) -> frozenset[str]:
        return frozenset(self._active)

    @asynccontextmanager
    async def acquire_context(
        self, profile_id: str, *, headless: bool | None = None, start_url: str | None = None
    ) -> AsyncIterator[Any]:
        """Yield a persistent, fingerprinted BrowserContext, or raise.

        Ordering is deliberate: kill switch first (cheap, network), then dirs,
        then launch. The scrub runs in `finally` so a crash still frees disk.
        """
        async with self._semaphore:
            profile = await self._db.get_profile(profile_id)
            if profile is None:
                raise BrowserPoolError(f"profile not found: {profile_id}")

            geo: ProxyGeoInfo = await self._inspector.verify_and_inspect(profile_id)
            fingerprint = json.loads(profile["fingerprint_json"])
            self._profiles.browser_data_dir(profile_id).mkdir(parents=True, exist_ok=True)
            await self._db.set_status(profile_id, "BUSY")
            self._active.add(profile_id)
            try:
                proxy = _camoufox_proxy(profile["upstream_proxy_url"])
                options: dict[str, Any] = {
                    "headless": self._headless if headless is None else headless,
                    "persistent_context": True,
                    "user_data_dir": str(self._profiles.browser_data_dir(profile_id)),
                    "os": profile["os_type"],
                    "humanize": True,
                    "proxy": proxy,
                    # The whole device is pinned from storage: the identity is a
                    # fixed machine, not a redraw per launch.
                    "fingerprint": _camoufox_fingerprint(fingerprint),
                    "config": _camoufox_config(fingerprint, geo),
                    "i_know_what_im_doing": True,
                }
                async with AsyncCamoufox(**options) as context:
                    if start_url:
                        page = await context.new_page()
                        await page.goto(start_url, wait_until="domcontentloaded")
                    yield context
                await self._db.set_status(profile_id, "IDLE")
            except BaseException:
                # Leave the row usable; PROXY_DEAD is already set by the inspector.
                current = await self._db.get_profile(profile_id)
                if current and current["status"] == "BUSY":
                    await self._db.set_status(profile_id, "IDLE")
                raise
            finally:
                self._active.discard(profile_id)
                self._profiles.scrub_profile_cache(profile_id)
                self._profiles.enforce_disk_ceiling(profile_id)

    async def verify_stealth(self, profile_id: str) -> dict[str, Any]:
        """Open ipinfo inside the real browser and report observed vs. stored."""
        async with self.acquire_context(profile_id, headless=True) as context:
            page = await context.new_page()
            await page.goto(STEALTH_URL, wait_until="domcontentloaded")
            body = await page.inner_text("body")
            try:
                observed = json.loads(body)
            except ValueError:
                observed = {"raw": body[:500]}

            navigator = await page.evaluate(
                """() => ({
                    ua: navigator.userAgent,
                    platform: navigator.platform,
                    cores: navigator.hardwareConcurrency,
                    lang: navigator.language,
                    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    screen: [screen.width, screen.height],
                    webdriver: navigator.webdriver,
                })"""
            )

        stored = await self._profiles.load_fingerprint(profile_id)
        profile = await self._db.get_profile(profile_id)
        assert profile is not None
        geo = await self._db.get_profile_geo(profile_id)

        # The presented locale follows the exit node, not the stored drawing: a
        # US residential IP beside `it` is the classic mismatch. Check the
        # language against the geo, and the timezone against the exit IP's zone.
        expected_locale = (geo or {}).get("locale") or stored.locale
        checks = {
            "ip_matches": observed.get("ip") == profile["expected_ip"],
            "ua_matches": navigator["ua"] == stored.user_agent,
            "cores_matches": navigator["cores"] == stored.hardware_concurrency,
            "locale_matches": navigator["lang"] == expected_locale,
            "timezone_matches": bool(geo) and navigator["tz"] == geo.get("timezone"),
            "screen_matches": navigator["screen"] == [stored.screen_width, stored.screen_height],
            "webdriver_hidden": navigator["webdriver"] in (False, None),
        }
        return {
            "profile_id": profile_id,
            "passed": all(checks.values()),
            "checks": checks,
            "observed": {**observed, "navigator": navigator},
            "expected_ip": profile["expected_ip"],
        }

    # -- credential sync ---------------------------------------------------

    async def sync_claude_cli_credentials(self, profile_id: str, *, timeout: float = 600.0) -> bytes:
        """Run `claude login`, approve it inside the browser, archive + encrypt.

        The CLI runs with HOME pointed at the profile's claude_home and its proxy
        pointed at the profile's sing-box port, so the OAuth exchange happens from
        the same IP/fingerprint as everything else.
        """
        profile = await self._db.get_profile(profile_id)
        if profile is None:
            raise BrowserPoolError(f"profile not found: {profile_id}")

        home = self._profiles.claude_home_dir(profile_id)
        home.mkdir(parents=True, exist_ok=True)
        proxy_url = f"http://127.0.0.1:{profile['local_proxy_port']}"

        async with self.acquire_context(profile_id, headless=self._headless, start_url=None) as context:
            proc = await asyncio.create_subprocess_exec(
                "claude",
                "login",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={
                    "HOME": str(home),
                    "PATH": _shell_path(),
                    "HTTPS_PROXY": proxy_url,
                    "HTTP_PROXY": proxy_url,
                },
            )
            output = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            log = output[0].decode("utf-8", "replace") if output[0] else ""
            if proc.returncode != 0:
                raise BrowserPoolError(f"claude login failed ({proc.returncode}): {log[-800:]}")

            url = _extract_url(log)
            if url:
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded")
                await _wait_for_credentials(home, timeout=timeout)

        blob = _archive_and_encrypt(self._profiles.claude_home_dir(profile_id).parent / "claude_home")
        await self._db.save_credentials(profile_id, blob)
        return blob


def _camoufox_proxy(proxy_url: str) -> dict[str, str]:
    """Split `scheme://user:pass@host:port` into Camoufox's proxy dict."""
    from urllib.parse import unquote, urlparse

    parsed = urlparse(proxy_url)
    if not parsed.hostname:
        raise BrowserPoolError(f"invalid proxy URL: {proxy_url}")
    scheme = parsed.scheme or "http"
    server = f"{scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    proxy = {"server": server}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
    if parsed.password:
        proxy["password"] = unquote(parsed.password)
    return proxy


def _camoufox_fingerprint(fingerprint: dict[str, Any]) -> dict[str, Any]:
    """The stored device drawing, in the shape `generate_fingerprint` returns.

    Camoufox accepts this instead of drawing a new one, so the identity survives
    a relaunch. The stored config is rebuilt from the drawing rather than the
    other way round because only the drawing carries the GPU pair.
    """
    screen = fingerprint.get("screen") or {}
    card = fingerprint.get("video_card") or {}
    drawing: dict[str, Any] = {
        "navigator": {
            "userAgent": fingerprint["user_agent"],
            "platform": fingerprint["platform"],
            "hardwareConcurrency": int(fingerprint["hardware_concurrency"]),
            "language": fingerprint.get("locale", "en-US"),
            "languages": list(fingerprint.get("languages") or ["en-US"]),
        },
        "screen": {
            "width": int(screen.get("width", 1920)),
            "height": int(screen.get("height", 1080)),
        },
    }
    if card.get("vendor") and card.get("renderer"):
        drawing["gpu"] = {"vendor": card["vendor"], "renderer": card["renderer"]}
    return drawing


def _camoufox_config(fingerprint: dict[str, Any], geo: ProxyGeoInfo) -> dict[str, Any]:
    """The stored CAMOU_CONFIG, plus the geo the proxy actually resolves to.

    Screen, navigator and GPU come from storage so they are identical on every
    launch; only the proxy-dependent fields (IP, timezone, locale, coordinates)
    are taken live, because they must follow the exit node.
    """
    config: dict[str, Any] = dict(fingerprint.get("camoufox_config") or {})
    locale = geo.locale or fingerprint.get("locale") or "en-US"
    language, _, region = locale.partition("-")
    config.update(
        {
            "webrtc:ipv4": geo.ip,
            "timezone": geo.timezone,
            "geolocation:latitude": geo.latitude,
            "geolocation:longitude": geo.longitude,
            "locale:language": language,
        }
    )
    if region:
        config["locale:region"] = region
    return config


def _shell_path() -> str:
    import os

    return os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")


def _extract_url(text: str) -> str | None:
    for token in text.replace("\n", " ").split():
        if token.startswith("https://") and ("anthropic" in token or "claude" in token):
            return token.strip(".,)")
    return None


async def _wait_for_credentials(home: Path, timeout: float, interval: float = 1.0) -> None:
    """Poll for the credential file the CLI writes after OAuth completes."""
    deadline = asyncio.get_running_loop().time() + timeout
    candidates = [home / ".claude" / ".credentials.json", home / ".claude.json"]
    while asyncio.get_running_loop().time() < deadline:
        if any(path.exists() for path in candidates):
            return
        await asyncio.sleep(interval)
    raise BrowserPoolError("timed out waiting for claude credentials after login")


def _archive_and_encrypt(claude_home: Path) -> bytes:
    """tar.gz the `.claude` dir, then hand the bytes to the crypto layer."""
    from core.crypto import encrypt_blob

    dot_claude = claude_home / ".claude"
    target = dot_claude if dot_claude.is_dir() else claude_home
    with tempfile.TemporaryFile() as buffer:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(target, arcname=".claude")
        buffer.seek(0)
        return encrypt_blob(buffer.read())
