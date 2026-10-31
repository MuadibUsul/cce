"""Driving the Claude sign-in page far enough to obtain an authorization code.

The page is a React shell served behind Cloudflare, so nothing here may assume
markup that exists at load time: every lookup goes through a Playwright locator,
which waits. Only the *stable* parts are used -- visible text on the consent
button and the redirect that carries `code`.

Deliberately narrow: this returns None (rather than hanging) as soon as the flow
needs a secret only a human has.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

# Where the OAuth exchange lands. The CLI's redirect_uri, not a guess.
CALLBACK_HOST = "platform.claude.com"

# Text on the "allow this app" button. Matched case-insensitively, in order.
CONSENT_LABELS = ("authorize", "allow", "approve", "continue", "accept")

# A page that wants a password, SSO metadata or a second factor is beyond us.
# Note there is no bare "login" marker: that page is drivable via the email path.
HUMAN_MARKERS = ("sso", "password", "passkey", "two-factor", "verification code")


def extract_code(url: str) -> str | None:
    """Pull `code` out of a callback URL, if that is what this is."""
    parsed = urlparse(url)
    if CALLBACK_HOST not in parsed.netloc:
        return None
    query = parse_qs(parsed.query)
    for value in query.get("code", []):
        if value:
            return value
    return None


def needs_human(url: str) -> bool:
    """True when the browser has stopped somewhere only a person can finish.

    The whole URL is searched, not just the path: the password step announces
    itself in the query string (`/login?password=1`), never in the path.
    """
    haystack = url.lower().replace(" ", "-")
    return any(marker.replace(" ", "-") in haystack for marker in HUMAN_MARKERS)


def looks_signed_out(url: str) -> bool:
    """A login page that also asks for the account, i.e. never been here before."""
    parsed = urlparse(url)
    return "/login" in parsed.path and "selectAccount" not in parsed.query


async def click_email_login(page: Any) -> bool:
    """Choose the email path; the passwordless one is all an agent can drive."""
    for name in ("Continue with email", "Continue with email address"):
        locator = page.get_by_role("button", name=name, exact=False)
        if await locator.count():
            await locator.first.click()
            return True
    return False


async def fill_email(page: Any, email: str) -> bool:
    field = page.get_by_role("textbox", name=re.compile("email", re.I))
    if not await field.count():
        field = page.locator('input[type="email"]')
    if not await field.count():
        return False
    await field.first.fill(email)
    return True


async def auto_consent(page: Any) -> bool:
    """Click through whatever this page is, if it is something we recognise."""
    for label in CONSENT_LABELS:
        for role in ("button", "link"):
            locator = page.get_by_role(role, name=re.compile(label, re.I))
            if await locator.count():
                await locator.first.click()
                return True
    return False


def _captcha_pending(page: Any) -> bool:
    """The magic-link form is gated on an hCaptcha token that is still empty.

    Claude's widget renders the checkbox inside a *nested* hCaptcha frame, so
    nothing on the top-level document matches it; `solve_captcha` walks frames.
    """
    pages = getattr(page, "frames", None)
    return bool(pages)




async def solve_captcha(page: Any) -> bool:
    """Click the hCaptcha checkbox wherever it is nested.

    Frame indices are used rather than a selector because hCaptcha serves
    several identically-titled iframes and any name-based locator is ambiguous.
    A checked box is not a token: the widget still has to settle, so this only
    reports that a click landed. Returning False lets the caller retry.
    """
    boxes = await page.locator("iframe").count()
    for index in range(boxes):
        frame = page.frame_locator("iframe").nth(index)
        try:
            if not await frame.locator("#checkbox").count():
                continue
            await frame.locator("#checkbox").first.click(timeout=8000)
            return True
        except Exception:  # noqa: BLE001 - a frame mid-attach is not a failure
            continue
    return False


async def captcha_token(page: Any) -> int:
    """Length of the hCaptcha response the page currently holds (0 = unsigned)."""
    try:
        return await page.evaluate(
            "() => { const t = document.querySelector('textarea[name=h-captcha-response]');"
            " return t ? t.value.length : -1; }"
        )
    except Exception:  # noqa: BLE001
        return -1

