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

    async def sync_claude_cli_credentials(
        self, profile_id: str, *, email: str | None = None, timeout: float = 600.0
    ) -> bytes:
        """Run `claude auth login`, approve it in the profile's browser, archive it.

        `auth login` (not the `login` TUI step) prints the authorization URL and
        then waits for a pasted code, so its output has to be read while it is
        still running -- awaiting `communicate()` first would find nothing but the
        final exit. The CLI runs with HOME pointed at the profile's claude_home
        and its proxy pointed at the profile's sing-box port, so the whole OAuth
        exchange leaves from the same IP and fingerprint as everything else.
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
                "auth",
                "login",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                stdin=asyncio.subprocess.PIPE,
                env={
                    "HOME": str(home),
                    "PATH": _shell_path(),
                    "HTTPS_PROXY": proxy_url,
                    "HTTP_PROXY": proxy_url,
                },
            )
            try:
                url = await asyncio.wait_for(_read_authorize_url(proc, home), timeout=timeout)
                if url:
                    page = await context.new_page()
                    code = await _drive_consent(page, url, email=email, timeout=timeout)
                    if code:
                        # The CLI is blocked on its prompt; without this write
                        # the browser would have authenticated nothing.
                        assert proc.stdin is not None
                        proc.stdin.write(code.encode() + b"\n")
                        await proc.stdin.drain()
                await _wait_for_credentials(home, timeout=timeout)
            finally:
                # The token is already on disk; a still-waiting prompt must not
                # outlive the call.
                if proc.returncode is None:
                    proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=10)
                except asyncio.TimeoutError:
                    proc.kill()

        blob = _archive_and_encrypt(self._profiles.claude_home_dir(profile_id), associated=profile_id)
        await self._db.save_credentials(profile_id, blob)
        return blob

    async def import_claude_credentials(self, profile_id: str, dot_claude: Path) -> bytes:
        """Seal an already-authenticated `.claude` dir without a browser.

        Ops escape hatch for a host where the interactive OAuth flow cannot run:
        the directory is treated exactly like one produced by the flow, so the
        delivery path downstream is identical.
        """
        if not dot_claude.is_dir():
            raise BrowserPoolError(f"not a directory: {dot_claude}")
        blob = _archive_and_encrypt(dot_claude.parent, associated=profile_id)
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


async def _drive_consent(page: Any, url: str, *, email: str | None, timeout: float) -> str | None:
    """Walk the sign-in page until it hands back the authorization code.

    Returns None when the browser ends somewhere the caller can finish by hand
    (a password / SSO prompt, say) instead of pretending success. A brand-new
    account is the fully automatic path: the email is already known, Cloudflare
    is passed by the real kernel, and the consent button is the only click.
    """
    from core.login import (
        auto_consent,
        captcha_token,
        click_email_login,
        extract_code,
        fill_email,
        needs_human,
        solve_captcha,
    )

    await page.goto(url, wait_until="commit", timeout=timeout * 1000)
    deadline = asyncio.get_running_loop().time() + timeout
    submitted_email = False
    captcha_tries = 0
    while asyncio.get_running_loop().time() < deadline:
        current = page.url or ""
        code = extract_code(current)
        if code:
            return code
        if needs_human(current):
            return None
        try:
            if email and not submitted_email and await fill_email(page, email):
                submitted_email = True
                await auto_consent(page)
                # The form only posts once a token exists; the widget mounts a
                # moment after the email step, so give it one pass first.
                await asyncio.sleep(1.0)
                if await captcha_token(page) <= 0 and captcha_tries < 3:
                    captcha_tries += 1
                    if await solve_captcha(page):
                        continue
            elif not await auto_consent(page) and not submitted_email:
                await click_email_login(page)
        except Exception:  # noqa: BLE001 - a page mid-render is not a failure
            pass
        await asyncio.sleep(1.0)
    return None


def _extract_url(text: str) -> str | None:
    for token in text.replace("\n", " ").split():
        if token.startswith("https://") and ("anthropic" in token or "claude" in token):
            return token.strip(".,)")
    return None


async def _read_authorize_url(
    proc: asyncio.subprocess.Process, home: Path, *, idle: float = 2.0
) -> str | None:
    """Watch the login output until it prints the authorization URL.

    Also stops early when the credential file appears first, and returns the
    tail of the output on an early exit so the caller can report why. The wait
    between lines is short because a cached identity writes the file without
    printing anything, so the poll is what ends the loop.
    """
    assert proc.stdout is not None
    seen: list[str] = []
    credentials = home / ".claude" / ".credentials.json"
    while True:
        if credentials.exists():
            return _extract_url(" ".join(seen))
        try:
            raw = await asyncio.wait_for(proc.stdout.readline(), timeout=idle)
        except asyncio.TimeoutError:
            continue
        if not raw:
            if proc.returncode not in (None, 0):
                tail = " ".join(seen)[-500:]
                raise BrowserPoolError(f"claude auth login exited {proc.returncode}: {tail}")
            return None
        line = raw.decode("utf-8", "replace")
        seen.append(line.strip())
        url = _extract_url(line)
        if url:
            return url


async def _wait_for_credentials(home: Path, timeout: float, interval: float = 1.0) -> None:
    """Poll for the credential file the CLI writes after OAuth completes."""
    deadline = asyncio.get_running_loop().time() + timeout
    candidates = [home / ".claude" / ".credentials.json", home / ".claude.json"]
    while asyncio.get_running_loop().time() < deadline:
        if any(path.exists() for path in candidates):
            return
        await asyncio.sleep(interval)
    raise BrowserPoolError("timed out waiting for claude credentials after login")


def _archive_and_encrypt(claude_home: Path, *, associated: str | None = None) -> bytes:
    """tar.gz the `.claude` dir, then hand the bytes to the crypto layer.

    The associated data binds the blob to its profile, so a swapped ciphertext
    cannot be replayed against another account.
    """
    from core.crypto import encrypt_blob

    dot_claude = claude_home / ".claude"
    target = dot_claude if dot_claude.is_dir() else claude_home
    with tempfile.TemporaryFile() as buffer:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.add(target, arcname=".claude")
        buffer.seek(0)
        return encrypt_blob(buffer.read(), associated=associated.encode() if associated else None)
