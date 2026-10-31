"""CLI mode end to end: session, kill switch, credential swap, fake `claude`.

    .venv/bin/python tests/e2e/run_cli.py           # happy path
    E2E_EXPECTED=198.51.100.4 ... run_cli.py        # IP drift must abort
    E2E_DEAD_RELAY=1 ... run_cli.py                 # dead exit must abort
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

PROFILE = "acct-e2e"


def main() -> int:
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
    if os.environ.get("E2E_DEAD_RELAY"):
        relay.terminate()
        relay.wait()
    else:
        wait_port(relay_port)

    control = serve(Control(control_port, {
        "profile_id": PROFILE,
        "expected_ip": os.environ.get("E2E_EXPECTED", EXIT_IP),
        "local_proxy_port": relay_port,
        "noise_seed": 42,
        "geo": {"timezone": "Europe/Berlin", "locale": "de-DE"},
        "tunnel": {"host": "127.0.0.1", "port": gateway_port, "secret": "s3cret"},
    }))

    gateway = subprocess.Popen(
        [build("gateway", "gateway"), "--listen", f"127.0.0.1:{gateway_port}", "--debug"],
        env=dict(os.environ, CCE_TUNNEL_SECRET="s3cret", CCE_TUNNEL_CERT=chain, CCE_TUNNEL_KEY=key),
    )
    wait_port(gateway_port)

    fake = os.path.join(os.environ.get("E2E_BIN", "/tmp/claude-cluster-engine-e2e"), "fake-claude")
    with open(fake, "w") as fh:
        fh.write('#!/bin/sh\necho "CLAUDE RAN dir=$CLAUDE_CONFIG_DIR proxy=$HTTPS_PROXY args=$*"\n')
    os.chmod(fake, 0o755)

    wipe(PROFILE)
    try:
        run = subprocess.run(
            [build("claude-box", "client-launcher"), "cli", "--key", "test_001",
             "--host", f"http://127.0.0.1:{control_port}", "--claude", fake, "-v"],
            env=dict(os.environ, CCE_TUNNEL_CA=ca, SSL_CERT_FILE=ca),
            capture_output=True, text=True, timeout=120,
        )
    finally:
        for proc in (gateway, relay):
            proc.terminate()
        control.shutdown()
        origin.shutdown()

    print("control:", control.calls)
    # A run is only correct if the expected outcome was reached: happy path
    # launches Claude, the two failure modes abort before it.
    want = 1 if os.environ.get("E2E_EXPECTED") or os.environ.get("E2E_DEAD_RELAY") else 0
    launched = "CLAUDE RAN" in run.stdout
    ok = report(run, origin.seen) if want == 0 else run.returncode != 0
    assert launched == (want == 0), f"claude launched={launched}, expected {want == 0}"
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
