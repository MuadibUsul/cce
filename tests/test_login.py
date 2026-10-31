"""Unit tests for the sign-in page helpers: URL parsing and error tolerance."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))

from core.login import (  # noqa: E402
    auto_consent,
    captcha_token,
    extract_code,
    looks_signed_out,
    needs_human,
    solve_captcha,
)


class FakeLocator:
    def __init__(self, count: int, name: str = "") -> None:
        self._count = count
        self.name = name
        self.clicked = False
        self.filled = ""

    async def count(self) -> int:
        return self._count

    @property
    def first(self) -> "FakeLocator":
        return self

    async def click(self) -> None:
        self.clicked = True

    async def fill(self, value: str) -> None:
        self.filled = value


class FakePage:
    """A page whose buttons are whatever the test says they are."""

    def __init__(self, labels: dict[str, int] | None = None) -> None:
        self.labels = labels or {}
        self.clicked: list[str] = []

    def get_by_role(self, role: str, name: object = None, **_kw: object) -> FakeLocator:
        pattern = getattr(name, "pattern", str(name or "")).lower()
        for label, count in self.labels.items():
            if label.lower() in pattern or pattern in label.lower():
                locator = FakeLocator(count, label)

                async def click(_self: FakeLocator = locator, label: str = label) -> None:
                    _self.clicked = True
                    self.clicked.append(label)

                locator.click = click  # type: ignore[method-assign]
                return locator
        return FakeLocator(0)


def test_extract_code_reads_only_the_callback() -> None:
    assert extract_code("https://platform.claude.com/oauth/code/callback?code=abc123&state=x") == "abc123"
    assert extract_code("https://claude.ai/oauth/authorize?code=true") is None
    assert extract_code("https://platform.claude.com/oauth/code/callback?error=denied") is None


def test_needs_human_recognises_blocking_steps() -> None:
    assert needs_human("https://claude.ai/login?password=1") is True
    # A bare login page still offers "Continue with email", so it is drivable.
    assert needs_human("https://claude.ai/login") is False
    assert needs_human("https://claude.ai/magic-link") is False
    assert needs_human("https://claude.ai/login?two-factor=1") is True
    assert needs_human("https://claude.ai/oauth/authorize?client_id=x") is False


def test_looks_signed_out_only_without_a_selected_account() -> None:
    assert looks_signed_out("https://claude.ai/login") is True
    assert looks_signed_out("https://claude.ai/login?selectAccount=true") is False


async def test_auto_consent_prefers_the_authorize_button() -> None:
    page = FakePage({"Authorize": 1, "Continue": 1})
    assert await auto_consent(page) is True
    assert page.clicked[0] == "Authorize"


async def test_auto_consent_reports_nothing_to_click() -> None:
    assert await auto_consent(FakePage()) is False


class CaptchaLocator:
    """One step of the frame walk; `count` is decided when it is created."""

    def __init__(self, page: "CaptchaPage", count: int = 1, index: int = 0) -> None:
        self._page = page
        self._count = count
        self._index = index

    def nth(self, index: int) -> "CaptchaLocator":
        hit = 1 if self._page.checkbox_at == index else 0
        return CaptchaLocator(self._page, hit, index)

    def locator(self, _selector: str) -> "CaptchaLocator":
        return self

    async def count(self) -> int:
        return self._count

    @property
    def first(self) -> "CaptchaLocator":
        return self

    async def click(self, **_kw: object) -> None:
        self._page.clicked_frames.append(self._index)


class CaptchaPage:
    """Reports nested iframes and the hCaptcha token the page holds.

    hCaptcha serves several identically-titled frames, so the helper must walk
    indices; only the frame that actually carries `#checkbox` may be clicked.
    """

    def __init__(self, token: int, checkbox_at: int | None) -> None:
        self.token = token
        self.checkbox_at = checkbox_at
        self.clicked_frames: list[int] = []
        self._frames = 3

    def locator(self, _selector: str) -> CaptchaLocator:
        return CaptchaLocator(self, self._frames)

    def frame_locator(self, _selector: str) -> CaptchaLocator:
        return CaptchaLocator(self)

    async def evaluate(self, _script: str) -> int:
        return self.token
async def test_solve_captcha_clicks_only_the_frame_holding_the_box() -> None:
    page = CaptchaPage(token=0, checkbox_at=2)
    assert await solve_captcha(page) is True
    assert page.clicked_frames == [2]


async def test_solve_captcha_reports_false_when_the_widget_is_absent() -> None:
    assert await solve_captcha(CaptchaPage(token=0, checkbox_at=None)) is False


async def test_captcha_token_distinguishes_unsigned_from_missing() -> None:
    assert await captcha_token(CaptchaPage(token=412, checkbox_at=0)) == 412
    assert await captcha_token(CaptchaPage(token=0, checkbox_at=0)) == 0
    assert await captcha_token(object()) == -1
