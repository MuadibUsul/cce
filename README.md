# claude-cluster-engine

Antidetect Claude account cluster: deterministic fingerprints, one static
residential IP per account, a whitelist-only TLS gateway, and a single binary
that hands a customer a fully isolated Claude session.

Spec: `SPEC.md` · [Project guide / 项目架构与路径导览](docs/PROJECT_GUIDE.md) · Architecture: `docs/ARCHITECTURE.md` · Ops: `docs/OPERATIONS_SOP.md` · Tasks: `TASKS.md`

## Shape

```
                      control plane (this repo, server/)
   ┌──────────────────────────────────────────────────────────────┐
   │ FastAPI /admin + /launcher · FastMCP tools · SQLite · sing-box│
   │ profile_manager → deterministic fingerprint + scrubber        │
   │ proxy_inspector → kill switch (IP must equal the frozen IP)   │
   └───────────────┬──────────────────────────┬───────────────────┘
                   │ session + credentials    │ sing-box port map
                   ▼                          ▼
   claude-box (client-launcher/)         1 residential port per profile
   loopback CONNECT proxy
   kill switch, credential swap, kernel
                   │
                   ▼
   gateway/ (Go)  authenticated CONNECT whitelist, profile-bound port routing
                   │
                   ▼
   *.anthropic.com · *.claude.ai · claude.com · platform.claude.com
   *.stripe.com · *.cloudflare.com · ipinfo.io · ip-api.com
```

Everything outside that whitelist is refused at the gateway, so the browser and
the Claude CLI can only ever talk to Claude and the IP echo services the kill
switch needs.

`claude.com` and `platform.claude.com` are the one addition beyond the original
list, and they are load-bearing rather than decorative: `claude auth login`
points the browser at `claude.com/cai/oauth/authorize`, and the callback that
carries the authorization code belongs to `platform.claude.com`. Without both,
no customer behind the gateway can ever reach the page that mints a token.
`defaultDomains()` in `gateway/main.go` carries the same reasoning, so the two
cannot drift apart silently.

## Guarantees

- **One account, one static exit.** A profile is bound to a residential proxy
  port; `proxy_inspector` verifies the exit IP before anything launches and
  marks the profile `PROXY_DEAD` on mismatch.
- **Kill switch before handover.** The launcher probes the egress IP through the
  live tunnel and exits `1` without starting Claude if it differs from
  `expected_ip`.
- **Deterministic machine identity.** Seed = `sha256(profile_id)[:8]`; the
  fingerprint comes from Camoufox's own generator, is replayed verbatim through
  `CAMOU_CONFIG_n`, and is coerced until Camoufox's own coherence validator
  accepts it. Timezone, locale, geolocation and WebRTC IP are overlaid from the
  live exit IP.
- **Native profile isolation.** Each account gets its own `CLAUDE_CONFIG_DIR`
  (`~/.claude-box/profiles/<id>/.claude`, `0700`), always wiped after exit.
- **A status is a permission, not a label.** Only an `IDLE` profile can start a
  customer or operator session. Claiming it sets `BUSY` atomically and starts a
  heartbeat lease; later calls require that session's identifier. `COOLDOWN`,
  `AUTH_EXPIRED`, `PROXY_DEAD`, and `BANNED` block handover and remove the
  gateway grant. Expired cooldowns are released by the server, and a `BUSY` row
  that goes 120 s without a heartbeat is reclaimed the same way — a `kill -9`ed
  launcher no longer strands the account.
- **Failure is reported, not guessed.** The gateway is a blind TLS splice and
  never sees an HTTP status inside the tunnel, so the launcher — the only party
  that sees the CLI exit — classifies it and `POST /launcher/status` marks
  `AUTH_EXPIRED` or starts a `COOLDOWN`. A successful `sync-credentials` clears
  `AUTH_EXPIRED` by itself.
- **Credentials sealed on the server.** The store is AES-GCM sealed at rest,
  delivered over the control plane's HTTPS connection, and extracted atomically
  into the client's `<configDir>.incoming` before the swap. The local plaintext
  copy is wiped unconditionally after CLI exit, and each start first clears any
  copy a killed run left behind. The profile id is AEAD
  associated data, so a swapped ciphertext cannot authenticate as another
  account.

## Getting credentials in

`POST /profiles/{id}/sync-credentials` runs the real OAuth flow: it launches
`claude auth login`, scrapes the authorization URL off its output, drives that
URL in the profile's own browser, pastes the authorization code back on the
CLI's stdin, then seals the resulting `.credentials.json` under the profile.

`claude auth login` is used rather than `claude login` on purpose — the latter is
a full-screen TUI that blocks forever on a non-tty.

The page driving is deliberately honest about its limits. `_drive_consent`
returns `None` instead of pretending success the moment it meets something only
a person can answer (password, SSO, second factor), so a caller can tell a
finished sync from a stalled one. Cloudflare is passed by the real kernel, not by
a heuristic.

One step is genuinely hard from a datacenter exit: the magic-link form is gated
on an hCaptcha token, and hCaptcha serves that checkbox inside a *nested* frame
that sits off-screen at `y = -9999` until the widget is scrolled to. `login.py`
walks the iframes by index (`frame_locator(...).nth(i)` — the frames share a
title, so any name-based locator is ambiguous) and clicks only the one carrying
`#checkbox`; `_drive_consent` retries that up to three times. On a datacenter IP
hCaptcha often still escalates to an image puzzle, which is where the run stops.

When it does stall, `POST /profiles/{id}/import-credentials` is the documented
escape hatch: sign in once by hand, drop the `.claude` directory on the server,
and the same sealing, atomic swap and erase guarantees apply.

## Build

Requires Go 1.22+ and Python 3.11+.

```
python -m venv .venv && .venv/bin/pip install -e "server[dev]"
make all          # cross-compiles client-launcher + gateway for 4 platforms
make dist-check   # asserts claude-box-<os>-<arch> names and the kernel default
make check        # gofmt + go vet + go test
.venv/bin/python -m pytest -q
```

Artefacts are named `claude-box-<os>-<arch>` (`x64`/`arm64`). The desktop kernel
URL is baked in at link time via `KERNEL_URL` (default
`https://cdn.veynod.com/kernel/camoufox`), so a downloaded binary bootstraps
itself; `CCE_KERNEL_URL` still overrides it at runtime.

## MCP surface

`server/mcp_server.py` is the orchestrator front door. Tool names are a contract
(SPEC 4.6) and are asserted by `tests/test_mcp.py`:

```
create_isolated_profile(profile_id, local_proxy_port, upstream_proxy_url,
                        expected_ip, os_type, batch_id)
verify_profile_stealth(profile_id)
issue_customer_card_key(profile_id, plan_tier, valid_days)
```

plus `create_account_batch`, `preflight_profile`, `sync_credentials`,
`scrub_cache`, `reload_relay`, `fleet_status`, and the read-only resources
`veynod://knowledge/cluster-spec`, `.../cluster-ops`, `.../cluster-architecture`.

## Status reporting

The launcher posts `{"status": "AUTH_EXPIRED" | "COOLDOWN" | "PROXY_DEAD" |
"IDLE", ...}` to `/launcher/status` after the CLI exits. `AUTH_EXPIRED` comes
from a 401/403/`invalid_grant`/`not logged in` message, `COOLDOWN` from a 429 or
a usage-limit line (with a `try again in <n> <unit>` hint, floored at 30 min).
A clean exit reports `IDLE`; a Ctrl-C reports nothing. While a session runs the
launcher heartbeats every 30 s, and the server reclaims a `BUSY` row after 120 s
of silence. Operators can still override with
`POST /admin/profiles/{id}/status` or free a row immediately with
`POST /admin/profiles/{id}/release`.

## Run

Control plane:

```
export CCE_ADMIN_TOKEN=... CCE_MASTER_KEY=... CCE_TUNNEL_HOST=gw.example.com
export CCE_TUNNEL_CERT=data/gateway/tls.crt CCE_TUNNEL_KEY=data/gateway/tls.key
.venv/bin/uvicorn api.app:create_app --factory --host 0.0.0.0 --port 8000
```

Admin routes need `x-admin-token: $CCE_ADMIN_TOKEN`. Launcher session requests
need `Authorization: Bearer <card_key>` and `x-tunnel-secret`; later requests
also need the returned `x-session-id`.

Provision, then hand over:

```
curl -H "x-admin-token: $CCE_ADMIN_TOKEN" -d '{"batch_id":"b1","bin_prefix":"424242","billing_country":"DE"}' localhost:8000/admin/batches
curl -H "x-admin-token: $CCE_ADMIN_TOKEN" -d '{"profile_id":"acct-001","batch_id":"b1","upstream_proxy_url":"socks5://u:p@host:1080","expected_ip":"203.0.113.7","os_type":"macos","local_proxy_port":10001}' localhost:8000/admin/profiles
curl -H "x-admin-token: $CCE_ADMIN_TOKEN" -d '{"profile_id":"acct-001","plan_tier":"pro"}' localhost:8000/admin/keys
```

Customer:

```
claude-box cli     --key <CARD_KEY> --secret <TUNNEL_SECRET> --host https://cp.example.com
claude-box desktop --key <CARD_KEY> --secret <TUNNEL_SECRET> --host https://cp.example.com
```

`cli` passes everything after `--` to `claude`. `desktop` needs a Camoufox
kernel: point `--runtime` at an extracted bundle or set `CCE_KERNEL_URL`.

`plan_tier` is one of `pro`, `max_5x`, `max_20x`, `env_only`.

## Environment

Server: `CCE_ADMIN_TOKEN`, `CCE_MASTER_KEY`, `CCE_TUNNEL_HOST`, `CCE_TUNNEL_PORT`,
`CCE_TUNNEL_CERT`, `CCE_TUNNEL_KEY`, `CCE_TUNNEL_SECRETS`, `CCE_DB_PATH`,
`CCE_REAPER_INTERVAL`.

Launcher: `CCE_HOST`, `CCE_TUNNEL_SECRET`, `CCE_GATEWAY`, `CCE_TUNNEL_CA`, `CCE_KERNEL_URL`,
`CCE_HEADLESS`, `CCE_EXTRA_PREFS`.

Every card key carries a separate tunnel secret. Point `CCE_TUNNEL_SECRETS` in
the gateway at the file the control plane writes, and mount its parent directory
read-only into the gateway container (the file is atomically replaced). Each
grant binds the secret to one profile port and expiry. HTTP and MCP key issuance,
revocation, and profile state changes refresh the file. The gateway checks
expiry on every connection and closes established tunnels after a grant is
removed. `CCE_TUNNEL_SECRETS` is required to start the gateway.

`claude-box` verifies the gateway by name; a private CA goes in `CCE_TUNNEL_CA`,
and desktop mode additionally needs that CA in the browser's own store because
Firefox trusts NSS, not `SSL_CERT_FILE`.

## End-to-end harnesses

`tests/e2e/` drives the real binaries through a fake control plane, a fake
residential relay and a TLS origin that answers as `ipinfo.io`/`ip-api.com`/
`claude.ai`. No Anthropic account needed:

```
.venv/bin/python tests/e2e/run_cli.py                        # happy path
E2E_EXPECTED=198.51.100.4 .venv/bin/python tests/e2e/run_cli.py   # IP drift aborts
E2E_DEAD_RELAY=1 .venv/bin/python tests/e2e/run_cli.py      # dead exit aborts
E2E_AUTH_EXPIRED=1 .venv/bin/python tests/e2e/run_cli.py    # 401 reported as AUTH_EXPIRED
CCE_RUNTIME=<camoufox bundle> .venv/bin/python tests/e2e/run_desktop.py
```

`tests/live.py` goes further and uses the real network: real control plane, real
sing-box port map, real gateway, real `claude`. It needs an upstream SOCKS proxy
in `CCE_UPSTREAM` (default `socks5://127.0.0.1:12080`) and checks the exit IP, the
`api.anthropic.com` status through the tunnel, and the CLI itself.

The happy path also asserts the session is reported as `IDLE`; the auth scenario
asserts a failing CLI reaches the control plane as `AUTH_EXPIRED` rather than
being lost. The desktop harness asserts the browser presents the stored UA,
`Accept-Language` and timezone offset. It imports a throwaway CA with `certutil` first, because
Firefox validates against NSS rather than `SSL_CERT_FILE`.

## Notes for operators

- Camoufox needs `<runtime>/../.0.5_FLAG` (a fingerprint-database version marker);
  without it the kernel refuses to start.
- `data/` holds the SQLite database, sing-box config and gateway TLS material and
  is git-ignored.
- Verified end to end on a Linux host (CLI and desktop modes, real Camoufox
  156.0.1-beta.36): kill switch blocks a drifted or dead exit, and the browser
  presents the stored UA, `Accept-Language` and timezone offset while only ever
  reaching whitelisted hosts.
