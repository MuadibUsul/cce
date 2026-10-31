# claude-cluster-engine

Antidetect Claude account cluster: deterministic fingerprints, one static
residential IP per account, a whitelist-only TLS gateway, and a single binary
that hands a customer a fully isolated Claude session.

Spec: `SPEC.md` · Ops: `docs/OPERATIONS_SOP.md` · Tasks: `TASKS.md`

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
   gateway/ (Go)  SNI + CONNECT whitelist, bearer secret, port routing
                   │
                   ▼
   *.anthropic.com · *.claude.ai · *.stripe.com · *.cloudflare.com · ipinfo.io · ip-api.com
```

Everything outside that whitelist is refused at the gateway, so the browser and
the Claude CLI can only ever talk to Claude and the IP echo services the kill
switch needs.

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
  (`~/.claude-box/profiles/<id>/.claude`, `0700`), wiped after exit unless
  `--keep`.
- **No plaintext credentials on disk.** The store is AES-GCM sealed on the
  server, delivered over the tunnel, and extracted atomically into
  `<configDir>.incoming` before the swap.

## Build

Requires Go 1.22+ and Python 3.11+.

```
python -m venv .venv && .venv/bin/pip install -e "server[dev]"
make all          # cross-compiles client-launcher + gateway for 4 platforms
make check        # gofmt + go vet + go test
.venv/bin/python -m pytest -q
```

## Run

Control plane:

```
export CCE_ADMIN_TOKEN=... CCE_MASTER_KEY=... CCE_TUNNEL_HOST=gw.example.com
export CCE_TUNNEL_CERT=data/gateway/tls.crt CCE_TUNNEL_KEY=data/gateway/tls.key
.venv/bin/uvicorn api.app:create_app --factory --host 0.0.0.0 --port 8000
```

`/readyz` reports every missing secret. Admin routes need
`x-admin-token: $CCE_ADMIN_TOKEN`; launcher routes need
`Authorization: Bearer <card_key>`.

Provision, then hand over:

```
curl -H "x-admin-token: $CCE_ADMIN_TOKEN" -d '{"batch_id":"b1","bin_prefix":"424242","billing_country":"DE"}' localhost:8000/admin/batches
curl -H "x-admin-token: $CCE_ADMIN_TOKEN" -d '{"profile_id":"acct-001","batch_id":"b1","upstream_proxy_url":"socks5://u:p@host:1080","expected_ip":"203.0.113.7","os_type":"macos","local_proxy_port":10001}' localhost:8000/admin/profiles
curl -H "x-admin-token: $CCE_ADMIN_TOKEN" -d '{"profile_id":"acct-001","plan_tier":"pro"}' localhost:8000/admin/keys
```

Customer:

```
claude-box cli     --key <CARD_KEY> --host https://cp.example.com
claude-box desktop --key <CARD_KEY> --host https://cp.example.com
```

`cli` passes everything after `--` to `claude`. `desktop` needs a Camoufox
kernel: point `--runtime` at an extracted bundle or set `CCE_KERNEL_URL`.

`plan_tier` is one of `pro`, `max_5x`, `max_20x`, `env_only`.

## Environment

Server: `CCE_ADMIN_TOKEN`, `CCE_MASTER_KEY`, `CCE_TUNNEL_HOST`, `CCE_TUNNEL_PORT`,
`CCE_TUNNEL_CERT`, `CCE_TUNNEL_KEY`, `CCE_TUNNEL_SECRETS`, `CCE_DB_PATH`.

Launcher: `CCE_HOST`, `CCE_GATEWAY`, `CCE_TUNNEL_CA`, `CCE_KERNEL_URL`,
`CCE_HEADLESS`, `CCE_EXTRA_PREFS`.

Every card key carries its own tunnel secret, so the gateway reads a set: point
`CCE_TUNNEL_SECRETS` at the file the control plane writes (`/admin/keys`,
`/admin/keys/{card_key}` and `/admin/tunnel-secrets` keep it current) and mount
it read-only into the gateway. `CCE_TUNNEL_SECRET` still works as one static
value for a single-machine run. The file is re-read when it changes, so a
revocation lands without a restart.

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
CCE_RUNTIME=<camoufox bundle> .venv/bin/python tests/e2e/run_desktop.py
```

`tests/live.py` goes further and uses the real network: real control plane, real
sing-box port map, real gateway, real `claude`. It needs an upstream SOCKS proxy
in `CCE_UPSTREAM` (default `socks5://127.0.0.1:12080`) and checks the exit IP, the
`api.anthropic.com` status through the tunnel, and the CLI itself.

The desktop harness asserts the browser presents the stored UA, `Accept-Language`
and timezone offset. It imports a throwaway CA with `certutil` first, because
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
