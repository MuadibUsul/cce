"""Live run: real control plane, sing-box port map, gateway and `claude` CLI.

Needs an upstream SOCKS proxy in `CCE_UPSTREAM` (default a local sing-box
direct instance on 12080) and the real `claude` binary. Everything is bound to
loopback except that upstream hop.

    python tests/live.py "claude --version"
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

DB = os.environ.get("CCE_DB_PATH", "/tmp/live/cce.sqlite3")
PORT = int(os.environ.get("LIVE_PORT", "18000"))
ADMIN = "live-admin"
ARGS = os.environ.get("CCE_ARGS", "claude --version").split()


def call(path: str, payload: dict | None = None, headers: dict | None = None) -> dict:
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, headers=headers or {})
    if data:
        request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{path} -> {exc.code}: {exc.read().decode()[-800:]}")


def main() -> int:
    base = dict(
        os.environ,
        CCE_ADMIN_TOKEN=ADMIN,
        CCE_MASTER_KEY=Admin_key(),
        CCE_DB_PATH=DB,
        CCE_TUNNEL_HOST="127.0.0.1",
        CCE_TUNNEL_PORT="18443",
        CCE_TUNNEL_SECRETS="/tmp/live/secrets",
        CCE_TUNNEL_CERT="/tmp/live/tls.crt",
        CCE_TUNNEL_KEY="/tmp/live/tls.key",
        CCE_TUNNEL_SAN="127.0.0.1",
    )
    os.makedirs("/tmp/live", exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(DB + suffix)
        except FileNotFoundError:
            pass
    exit_ip = subprocess.run(
        ["curl", "-s", "--max-time", "20", "-x", os.environ.get("CCE_UPSTREAM", "socks5h://127.0.0.1:12080"),
         "https://ipinfo.io/ip"], capture_output=True, text=True, check=True,
    ).stdout.strip()
    print("residential exit:", exit_ip)

    server = subprocess.Popen(
        [".venv/bin/uvicorn", "api.app:create_app", "--factory", "--app-dir", "server",
         "--host", "127.0.0.1", "--port", str(PORT)],
        env=base,
        stdout=subprocess.DEVNULL, stderr=open("/tmp/live/server.log", "w"),
    )
    gateway: list[subprocess.Popen] = []
    # The gateway reads the exported secret file at startup; issue first, then start.
    admin = {"x-admin-token": ADMIN}
    try:
        for _ in range(120):
            try:
                call("/readyz")
                break
            except OSError:
                time.sleep(0.25)
        print("readyz:", call("/readyz"))

        call("/admin/batches", {"batch_id": "live", "bin_prefix": "424242",
                                "billing_country": "DE"}, admin)
        call("/admin/profiles", {"profile_id": "test_001", "batch_id": "live",
                                 "upstream_proxy_url": os.environ.get(
                                     "CCE_UPSTREAM", "socks5://127.0.0.1:12080"),
                                 "expected_ip": exit_ip, "os_type": "linux"}, admin)
        print("preflight:", call("/admin/profiles/test_001/preflight", {}, admin))
        print("singbox reload:", call("/admin/singbox/reload", {}, admin))
        seeded = os.environ.get("CCE_SEED_CREDS", "/tmp/live/claude_home/.claude")
        if os.path.isdir(seeded):
            print("import credentials:", call(
                "/admin/profiles/test_001/import-credentials", {"path": seeded}, admin))
        key = call("/admin/keys", {"profile_id": "test_001", "plan_tier": "pro"}, admin)
        print("key:", key["card_key"])
        # The gateway shares only this directory with the control plane.
        gateway.append(subprocess.Popen(
            ["/tmp/live/gateway", "--listen", "127.0.0.1:18443", "--debug"], env=base,
            stdout=open("/tmp/live/gw.log", "w"), stderr=subprocess.STDOUT))
        wait_port(18443)

        session = call("/launcher/session", {}, {"authorization": f"Bearer {key['card_key']}",
                                                 "x-tunnel-secret": key["tunnel_secret"]})
        session["tunnel"]["secret"] = key["tunnel_secret"]
        print("session ip/port:", session["expected_ip"], session["local_proxy_port"])
        print("api reachable:", api_probe(session))
        call("/launcher/status", {"status": "IDLE"}, {"authorization": f"Bearer {key['card_key']}",
              "x-tunnel-secret": key["tunnel_secret"], "x-session-id": session["session_id"]})

        run = subprocess.run(
            ["/tmp/live/claude-box", "cli", "--key", key["card_key"], "--secret", key["tunnel_secret"],
             "--host", f"http://127.0.0.1:{PORT}", "-v", "--"] + ARGS, cwd=".",
            env=dict(base, CCE_TUNNEL_CA="/tmp/live/tls.crt", SSL_CERT_FILE="/tmp/live/tls.crt"),
            capture_output=True, text=True, timeout=600,
        )
        print("launcher stderr:", run.stderr[-1500:])
        print("launcher stdout:", run.stdout[-1500:])
        return run.returncode
    finally:
        for proc in gateway:
            proc.terminate()
        server.terminate()
        call_safe("/admin/singbox/reload")


def api_probe(session: dict) -> str:
    """Hit api.anthropic.com through the profile port, independent of the launcher.

    The egress IP is already verified, so a status line here proves the rest of
    the chain (gateway auth, whitelist, end-to-end TLS) and that Anthropic itself
    accepts the connection. 401 is the expected answer to a bogus key.
    """
    run = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_version} %{http_code}", "--max-time", "40",
         "-x", f"http://127.0.0.1:{session['local_proxy_port']}",
         "-H", f"Proxy-Authorization: Bearer {session['tunnel']['secret']}",
         "-H", "x-api-key: sk-ant-invalid", "-H", "anthropic-version: 2023-06-01",
         "https://api.anthropic.com/v1/models"],
        capture_output=True, text=True, env=dict(os.environ, CCE_TUNNEL_CA="/tmp/live/tls.crt"),
    )
    return f"HTTP/{run.stdout.strip()}" if run.stdout else run.stderr.strip()


def wait_port(port: int) -> None:
    for _ in range(80):
        with socket.socket() as probe:
            try:
                probe.connect(("127.0.0.1", port))
                return
            except OSError:
                time.sleep(0.1)
    raise SystemExit(f"port {port} never opened")


def Admin_key() -> str:
    import base64
    return base64.b64encode(b"0" * 32).decode()


def call_safe(path: str) -> None:
    try:
        call(path, {}, {"x-admin-token": ADMIN})
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
