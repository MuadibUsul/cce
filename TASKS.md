# Tasks — claude-cluster-engine

Spec: `SPEC.md` · Ops: `docs/OPERATIONS_SOP.md`
Legend: `[ ]` todo · `[>]` in progress · `[x]` done · `[!]` blocked

## Phase 0 — env
- [x] Install Go toolchain (apt golang-go)
- [x] Python venv + deps (fastapi, aiosqlite, httpx, camoufox[async], browserforge, cryptography, pytest)
- [x] Verify browserforge / camoufox import in venv

## Phase 1 — DB & antidetect core
- [x] server/db/schema.sql
- [x] server/db/database.py (aiosqlite CRUD)
- [x] server/core/proxy_inspector.py (kill switch + geoip)
- [x] server/core/profile_manager.py (deterministic seed, fingerprint, scrubber)
- [x] server/core/browser_pool.py (semaphore pool, camoufox context, oauth extraction)
- [x] tests: deterministic seed, kill switch, cache scrub

## Phase 2 — control plane
- [x] server/core/singbox_manager.py
- [x] server/core/crypto.py (AES-GCM)
- [x] server/api/app.py (FastAPI: key auth, credential sync)
- [x] server/mcp_server.py (FastMCP tools)

## Phase 3 — gateway
- [x] gateway/main.go (tunnel + SNI/CONNECT whitelist + key auth)
- [x] gateway: TLS termination for gateway-directed connections, profile port routing

## Phase 4 — launcher
- [x] client-launcher/main.go (cli + desktop modes, kill switch)
- [x] Makefile cross-compile darwin/arm64, darwin/amd64, windows/amd64, linux/amd64
- [x] desktop mode: promise-gated `CAMOU_CONFIG_n`/`CAMOU_PREFS_n` identity + proxy prefs

## Phase 5 — verify
- [x] pytest green (72)
- [x] go build green, go vet/gofmt clean, go test green in both modules
- [x] end-to-end CLI harness (happy path / IP drift / dead relay)
- [x] end-to-end desktop harness with the real kernel: identity + whitelist proven
- [x] end-to-end run against a real static residential IP (`claude-box cli --key test_001`)
- [x] README + run instructions

## Findings worth keeping
- Per-key tunnel secrets needed a gateway-side set, not one static value
  (`CCE_TUNNEL_SECRETS`, hot-reloaded).
- sing-box 1.11 moved inbound sniffing to a route action; 1.14 rejects the old
  field outright.
- Credential blobs must be sealed *and* opened with the profile as associated
  data, or the swap guard is worthless.
- Camoufox needs `<bundle>/../.0.5_FLAG`; without it the kernel refuses to start.
- The bare kernel has no `--fingerprint/--timezone/--lang/--proxy-server` flags —
  identity ships through `CAMOU_CONFIG_n`/`CAMOU_PREFS_n` and `-profile <dir> -no-remote`.
- Firefox validates against NSS: a test CA has to be imported with `certutil`,
  and a self-signed leaf that is also `CA:TRUE` is rejected — use a real CA.
- `api.ipify.org` is not whitelisted; the probe fallback is `ip-api.com` over HTTP.
