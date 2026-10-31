"""Credential sync: the login handshake and the blob it produces.

`claude auth login` prints an authorization URL and then waits. The flow is
therefore driven with a fake binary that reproduces exactly that shape, plus a
stand-in browser context, so the sequencing can be asserted without a kernel or
a network.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path

import pytest
from core.browser_pool import BrowserPool, BrowserPoolError, _extract_url
from core.crypto import decrypt_blob
from db.database import Database


class FakePage:
    """Stands in for a Playwright page: records visits, reports a stable URL.

    The consent loop re-reads `page.url` until the deadline, so the fake keeps
    the address it was sent to instead of growing an attribute per test.
    """

    def __init__(self, log: list[str]) -> None:
        self._log = log
        self.url = "about:blank"

    async def goto(self, url: str, **_kwargs: object) -> None:
        self._log.append(url)
        self.url = url


class FakeContext:
    def __init__(self, log: list[str]) -> None:
        self._log = log

    async def new_page(self) -> FakePage:
        return FakePage(self._log)


class FakePool(BrowserPool):
    """BrowserPool with the kernel swapped for a recorded context."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.visited: list[str] = []

    def acquire_context(self, *args: object, **kwargs: object):  # type: ignore[override]
        pool = self

        class _Ctx:
            async def __aenter__(self) -> FakeContext:
                return FakeContext(pool.visited)

            async def __aexit__(self, *exc: object) -> None:
                return None

        return _Ctx()


def fake_claude(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "claude"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


@pytest.fixture
async def pool(db: Database, profiles: object) -> FakePool:
    from core.proxy_inspector import ProxyInspector

    instance = FakePool(db, profiles, ProxyInspector(db))  # type: ignore[arg-type]
    yield instance


@pytest.mark.skipif(os.name == "nt", reason="fake Claude executable is a POSIX shell script")
async def test_credentials_are_sealed_under_the_profile(db: Database, profiles: object, pool: FakePool,
                                                        tmp_path: Path) -> None:
    record = await profiles.create_profile(  # type: ignore[attr-defined]
        profile_id="acct-login", upstream_proxy_url="socks5://1.2.3.4:1080",
        expected_ip="203.0.113.5", os_type="linux",
    )
    assert record["local_proxy_port"]
    home = profiles.claude_home_dir("acct-login")  # type: ignore[attr-defined]

    # The fake prints the URL, then writes the credential file while still alive
    # -- the real CLI keeps waiting for a pasted code at this point.
    fake_claude(
        tmp_path,
        'echo "Opening browser to sign in…"\n'
        'echo "visit: https://claude.com/cai/oauth/authorize?code=true&state=xyz"\n'
        f'mkdir -p "{home}/.claude" && echo \'{{"accessToken":"t"}}\' > "{home}/.claude/.credentials.json"\n'
        "exec sleep 30\n",
    )
    monkey = pytest.MonkeyPatch()
    monkey.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    try:
        blob = await pool.sync_claude_cli_credentials("acct-login", timeout=30)
    finally:
        monkey.undo()

    assert pool.visited and pool.visited[0].startswith("https://claude.com/cai/oauth/authorize")
    names = archive_names(decrypt_blob(blob, associated=b"acct-login"))
    assert ".claude/.credentials.json" in names
    stored = await db.get_profile("acct-login")
    assert stored and stored["claude_credentials_enc"]


@pytest.mark.skipif(os.name == "nt", reason="fake Claude executable is a POSIX shell script")
async def test_a_login_that_never_prints_a_url_still_completes(
    db: Database, profiles: object, pool: FakePool, tmp_path: Path
) -> None:
    """A cached identity can skip straight to the credential file."""
    await profiles.create_profile(  # type: ignore[attr-defined]
        profile_id="acct-quiet", upstream_proxy_url="socks5://1.2.3.4:1080",
        expected_ip="203.0.113.5", os_type="linux",
    )
    home = profiles.claude_home_dir("acct-quiet")  # type: ignore[attr-defined]
    fake_claude(
        tmp_path,
        f'mkdir -p "{home}/.claude" && echo \'{{"accessToken":"t"}}\' > "{home}/.claude/.credentials.json"\n'
        "exec sleep 30\n",
    )
    monkey = pytest.MonkeyPatch()
    monkey.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    try:
        blob = await pool.sync_claude_cli_credentials("acct-quiet", timeout=60)
    finally:
        monkey.undo()

    assert pool.visited == []
    assert ".claude/.credentials.json" in archive_names(decrypt_blob(blob, associated=b"acct-quiet"))


@pytest.mark.skipif(os.name == "nt", reason="fake Claude executable is a POSIX shell script")
async def test_an_early_exit_reports_the_output(db: Database, profiles: object, pool: FakePool,
                                                tmp_path: Path) -> None:
    await profiles.create_profile(  # type: ignore[attr-defined]
        profile_id="acct-fail", upstream_proxy_url="socks5://1.2.3.4:1080",
        expected_ip="203.0.113.5", os_type="linux",
    )
    claude = fake_claude(tmp_path, 'echo "Not logged in · Please run /login"\nexit 0\n')
    monkey = pytest.MonkeyPatch()
    monkey.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    try:
        with pytest.raises(BrowserPoolError) as caught:
            await pool.sync_claude_cli_credentials("acct-fail", timeout=5)
    finally:
        monkey.undo()
    assert "credentials after login" in str(caught.value) or "/login" in str(caught.value)
    assert claude.exists()


def archive_names(archive: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        return tar.getnames()


def test_extract_url_prefers_an_oauth_url() -> None:
    line = "If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?x=1."
    assert _extract_url(line) == "https://claude.com/cai/oauth/authorize?x=1"
    assert _extract_url("nothing here") is None


def test_module_imports_are_stable() -> None:
    assert sys.version_info >= (3, 11)
