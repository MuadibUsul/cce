"""Desktop mode end to end: the real Camoufox kernel behind the real gateway.

Asserts the browser presents the stored machine (UA, Accept-Language, timezone
offset) while only reaching whitelisted hosts. Needs an extracted kernel:

    CCE_RUNTIME=~/.cache/camoufox/browsers/official/<ver> \\
      .venv/bin/python tests/e2e/run_desktop.py

`DESK_SECONDS` controls how long the browser is left running.
"""

from __future__ import annotations

import os
import subprocess
import sys

from harness import (
    EXIT_IP,
    Control,
    Origin,
    build,
    certificates,
    free_port,
    report,
    serve,
    wait_port,
    wipe,
)

PROFILE = "acct-desk"
RUNTIME = os.path.expanduser(os.environ.get("CCE_RUNTIME", ""))


def nss_import(profile_root: str, ca: str) -> str:
    """Firefox trusts NSS, not SSL_CERT_FILE: seed the store the kernel will open."""
    os.makedirs(profile_root, mode=0o700, exist_ok=True)
    subprocess.run(["certutil", "-N", "-d", f"sql:{profile_root}", "--empty-password"],
                   check=True, capture_output=True)
    subprocess.run(["certutil", "-A", "-d", f"sql:{profile_root}", "-n", "cce-e2e",
                    "-t", "C,,", "-a", "-i", ca], check=True, capture_output=True)
    return profile_root


def main() -> int:
    if not RUNTIME or not os.path.isdir(RUNTIME):
        raise SystemExit("set CCE_RUNTIME to an extracted Camoufox bundle")

    chain, key, ca = certificates()
    origin_port, gateway_port, control_port = free_port(), free_port(), free_port()
    # The gateway only routes ports the sing-box map owns, so the fake relay has
    # to sit inside that range: it stands in for a residential port.
    relay_port = free_port(10001, 11000)
    origin = Origin(origin_port)
    serve(origin)

    relay = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__), "relay.py"),
         str(relay_port), str(origin_port)]
    )
    wait_port(relay_port)

    control = serve(Control(control_port, {
        "session_id": "e2e-session",
        "profile_id": PROFILE,
        "expected_ip": EXIT_IP,
        "local_proxy_port": relay_port,
        "os_type": "linux",
        "noise_seed": 42,
        "geo": {"ip": EXIT_IP, "timezone": "Europe/Berlin", "locale": "de-DE",
                "latitude": 52.52, "longitude": 13.405},
        "fingerprint": {
            "user_agent": "STORED/1.0 rv:156.0 Firefox/156.0",
            "platform": "Linux x86_64",
            "locale": "de-DE",
            "screen": {"width": 1920, "height": 1080},
            "camoufox_config": {
                "navigator.userAgent": "STORED/1.0 rv:156.0 Firefox/156.0",
                "navigator.platform": "Linux x86_64",
                "navigator.hardwareConcurrency": 8,
                "screen.width": 1920, "screen.height": 1080,
                "timezone": "America/New_York",
                "locale:language": "en", "locale:region": "US",
            },
        },
        "tunnel": {"host": "127.0.0.1", "port": gateway_port, "secret": "s3cret"},
    }))

    secrets_path = os.path.join(os.path.dirname(chain), "e2e-secrets")
    with open(secrets_path, "w") as out:
        out.write(f"test_001 s3cret 2099-01-01T00:00:00Z {relay_port}\n")

    gateway = subprocess.Popen(
        [build("gateway", "gateway"), "--listen", f"127.0.0.1:{gateway_port}", "--debug"],
        env=dict(os.environ, CCE_TUNNEL_SECRETS=secrets_path, CCE_TUNNEL_CERT=chain, CCE_TUNNEL_KEY=key),
    )
    wait_port(gateway_port)

    profile_root = wipe(PROFILE)
    nss_import(os.path.join(profile_root, "browser_data"), ca)
    try:
        launcher = subprocess.Popen(
            [build("claude-box", "client-launcher"), "desktop", "--key", "test_001", "--secret", "s3cret",
             "--host", f"http://127.0.0.1:{control_port}", "--runtime", RUNTIME, "-v"],
            env=dict(os.environ, CCE_TUNNEL_CA=ca, SSL_CERT_FILE=ca, CCE_HEADLESS="1"),
            stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        import time
        time.sleep(int(os.environ.get("DESK_SECONDS", "45")))
        launcher.terminate()
        out, err = launcher.communicate(timeout=60)
    finally:
        for proc in (gateway, relay):
            proc.terminate()
        control.shutdown()
        origin.shutdown()

    run = subprocess.CompletedProcess([], launcher.returncode, out, err)
    report(run, origin.seen)
    # Desktop mode is killed on purpose, so the exit status is a signal: what
    # counts is that the kill switch verified and handed over to the browser.
    served = "egress verified as" in (err or "")

    page = origin.navigations()
    offsets = [int(row["path"].split("o=")[-1])
               for row in origin.seen if str(row["path"]).startswith("/tz")]
    ua = (page[-1]["ua"] or "") if page else ""
    lang = (page[-1]["lang"] or "") if page else ""
    # Berlin in October is CET (UTC+1), so JS reports getTimezoneOffset() == -60.
    identity = bool(page) and "STORED/1.0" in ua and lang.startswith("de-DE") and offsets[-1:] == [-60]
    print("ASSERT identity (ua/lang/tz):", identity, "| offsets:", offsets)
    print("control:", control.calls)
    return 0 if served and identity else 1


if __name__ == "__main__":
    sys.exit(main())
