"""End-to-end harness: real launcher + real gateway, fake control plane/origin.

Nothing here talks to Anthropic. The chain is

    claude-box ──▶ gateway (whitelist) ──▶ fake sing-box relay ──▶ TLS origin

and the origin pretends to be `ipinfo.io` / `ip-api.com` (the kill-switch
probes) as well as `claude.ai` (the page the browser opens), so both modes can
be exercised without a real residential exit.

Certificates are generated per run: a CA plus a leaf covering the whitelisted
names. Firefox validates against NSS, so the desktop harness imports the CA into
the profile it is about to launch.
"""

from __future__ import annotations

import http.server
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
EXIT_IP = os.environ.get("E2E_IP", "203.0.113.7")

# Names the origin has to answer for: two probes, plus the page itself.
CERT_NAMES = ["claude.ai", "ipinfo.io", "ip-api.com"]


def build(name: str, module: str) -> str:
    """Compile a Go binary into a temp dir (cached across runs in E2E_BIN)."""
    out = os.path.join(bin_dir(), name)
    if os.path.exists(out):
        return out
    source = os.path.join(os.path.dirname(os.path.dirname(ROOT)), module)
    subprocess.run(["go", "build", "-o", out, "."], cwd=source, check=True)
    return out


def bin_dir() -> str:
    path = os.environ.get("E2E_BIN", "/tmp/claude-cluster-engine-e2e")
    os.makedirs(path, exist_ok=True)
    return path


def free_port(low: int = 0, high: int = 0) -> int:
    """An unused port, optionally inside a range the gateway will accept."""
    if not high:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]
    for port in range(low, high):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError(f"no free port in {low}-{high}")


def wait_port(port: int, timeout: float = 20.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} never opened")


def certificates() -> tuple[str, str, str]:
    """(chain, key, ca) for a throwaway CA. Cached in E2E_BIN."""
    chain = os.path.join(bin_dir(), "chain.pem")
    ca = os.path.join(bin_dir(), "ca.pem")
    key = os.path.join(bin_dir(), "key.pem")
    if os.path.exists(chain) and os.path.exists(ca):
        return chain, key, ca
    work = bin_dir()
    run = lambda *args: subprocess.run(args, cwd=work, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
        "-out", "ca.pem", "-days", "3", "-subj", "/CN=cce-e2e-ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem",
        "-out", "leaf.csr", "-subj", "/CN=claude.ai")
    san = ",".join(f"DNS:{name}" for name in CERT_NAMES) + ",IP:127.0.0.1"
    with open(os.path.join(work, "leaf.ext"), "w") as fh:
        fh.write("basicConstraints=CA:FALSE\n")
        fh.write("keyUsage=critical,digitalSignature,keyEncipherment\n")
        fh.write("extendedKeyUsage=serverAuth\n")
        fh.write(f"subjectAltName={san}\n")
    run("openssl", "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-out", "leaf.pem", "-days", "2", "-extfile", "leaf.ext")
    with open(chain, "w") as out, open(os.path.join(work, "leaf.pem")) as leaf, open(ca) as root:
        out.write(leaf.read())
        out.write(root.read())
    return chain, key, ca


class Origin(http.server.ThreadingHTTPServer):
    """Answers like a remote host, and records what the client actually sent.

    There is no TLS here; the caller wraps the socket with `tls_context()`.
    """

    protocol_version = "HTTP/1.1"

    def __init__(self, port: int) -> None:
        self.seen: list[dict[str, object]] = []
        super().__init__(("127.0.0.1", port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*certificates()[:2])
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def get_request(self):
        sock, addr = self.socket.accept()
        try:
            sock.do_handshake()
        except OSError:
            sock.close()
            return self.get_request()
        return sock, addr

    def navigations(self) -> list[dict[str, object]]:
        return [row for row in self.seen if row["path"] == "/"]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.server.seen.append(  # type: ignore[attr-defined]
            {
                "path": self.path,
                "ua": self.headers.get("User-Agent"),
                "lang": self.headers.get("Accept-Language"),
            }
        )
        if self.path.startswith("/ip"):
            body, kind = EXIT_IP.encode(), "text/plain"
        elif self.path.startswith("/line"):
            body, kind = EXIT_IP.encode() + b"\n", "text/plain"
        elif self.path.startswith("/tz"):
            offset = int(self.path.split("o=")[-1])
            body, kind = b'{"offset":%d}' % offset, "application/json"
        else:
            # Report the machine the browser thinks it is on.
            body = (
                b"<html><title>ok</title><script>"
                b"fetch('/tz?o='+new Date().getTimezoneOffset())</script>ok</html>"
            )
            kind = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


def credentials_archive() -> bytes:
    """A tar.gz rooted at `.claude`, exactly what /launcher/credentials returns."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        body = b'{"accessToken":"sk-e2e"}'
        info = tarfile.TarInfo(".claude/.credentials.json")
        info.size, info.mode = len(body), 0o600
        tar.addfile(info, io.BytesIO(body))
    return raw.getvalue()


class Control(http.server.ThreadingHTTPServer):
    """The control plane's launcher routes, and nothing else."""

    protocol_version = "HTTP/1.1"

    def __init__(self, port: int, session: dict) -> None:
        self.session = session
        self.calls: list[str] = []
        super().__init__(("127.0.0.1", port), ControlHandler)


class ControlHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, payload: dict, code: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self.server.calls.append(self.path)  # type: ignore[attr-defined]
        if self.path == "/launcher/session":
            self._json(self.server.session)  # type: ignore[attr-defined]
        elif self.path == "/launcher/heartbeat":
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)

    def do_GET(self) -> None:
        self.server.calls.append(self.path)  # type: ignore[attr-defined]
        if self.path == "/launcher/credentials":
            body = credentials_archive()
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json({"error": "not found"}, 404)

    def log_message(self, *args: object) -> None:
        pass


def serve(server: http.server.ThreadingHTTPServer) -> http.server.ThreadingHTTPServer:
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wipe(profile_id: str) -> str:
    root = os.path.expanduser(f"~/.claude-box/profiles/{profile_id}")
    shutil.rmtree(root, ignore_errors=True)
    return root


def report(run: subprocess.CompletedProcess, seen: list[dict]) -> bool:
    print("exit:", run.returncode)
    print("stderr:", (run.stderr or "")[-2500:])
    print("stdout:", (run.stdout or "")[-1500:])
    print("origin:", [row for row in seen if row["path"] != "/favicon.ico"])
    return run.returncode == 0


def main() -> int:
    raise SystemExit("run run_cli.py or run_desktop.py")


if __name__ == "__main__":
    main()
