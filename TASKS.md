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

## Phase 6 — real OAuth `sync-credentials`
- [x] `claude auth login` (streams the URL, reads a code) instead of the `claude login` TUI
- [x] whitelist `claude.com` + `platform.claude.com`, without which no token can be minted
- [x] `_read_authorize_url()` — line-by-line scrape, early exit if credentials appear
- [x] `server/core/login.py` + `_drive_consent()` — email fill, nested-frame hCaptcha, consent, code paste-back
- [x] blob sealed/opened with the profile as associated data on both sides
- [x] routes rebuilt from the DB on control-plane restart (`_restore_routes`)
- [x] `POST /profiles/{id}/import-credentials` escape hatch
- [ ] full OAuth completion against a live account (blocked: no Anthropic account here)

## Phase 7 — production closure
- [x] `server/core/lifecycle.py`: explicit status transition table for all six
      states, `cooldown_until` arithmetic (clamped to 24 h), `IllegalTransition`.
- [x] Server-side cooldown sweeper (`CCE_REAPER_INTERVAL`, default 30 s) plus a
      startup sweep, so an expired `COOLDOWN` recovers to `IDLE` without a client.
- [x] `/launcher/status` (both factors) for launcher judgement: `AUTH_EXPIRED`,
      `COOLDOWN`, `PROXY_DEAD`, `IDLE`. An illegal late report is a 200 no-op.
- [x] `save_credentials` clears `AUTH_EXPIRED` itself, so sync and import both
      recover the row; a `BANNED` or running `COOLDOWN` is left alone.
- [x] Launcher exit classifier (`classifyRun`, `tailBuffer`) + best-effort
      report that survives a cancelled session.
- [x] Operator escape hatches: `POST /admin/profiles/{id}/status` (forced) and
      `/release`.
- [x] MCP tool names aligned to SPEC 4.6 (`create_isolated_profile`,
      `verify_profile_stealth`, `issue_customer_card_key`), with `local_proxy_port`
      as an explicit parameter.
- [x] `veynod://knowledge/cluster-spec` plus `cluster-ops` and
      `cluster-architecture` resources, asserted by tests.
- [x] Compile-time `kernelURLDefault` fallback; desktop mode no longer requires
      `CCE_KERNEL_URL` to be exported.
- [x] `claude-box-<os>-<arch>` artefact naming in `Makefile`, `make dist-check`
      asserting names and the baked default, and e2e building the released name.

## Phase 8 — BUSY lease, plaintext hard-wipe, dead files
- [x] `profiles.last_heartbeat_at` plus a `Database.migrate` backfill for rows
      that were already `BUSY`, so a deploy does not free live sessions.
- [x] The claim and every `/launcher/heartbeat` stamp the lease; the 30 s sweep
      reclaims a `BUSY` row silent for 120 s to `IDLE` and re-exports the grant.
- [x] Launcher keeps a 30 s keepalive for the whole session instead of the two
      fire-and-forget startup beats.
- [x] `--keep` removed: the CLI wipe is unconditional on exit, Ctrl-C included.
- [x] Start-time prune clears `.claude`/`.claude.incoming` left by a killed run
      while keeping `browser_data`.
- [x] `server/config/singbox_template.json` deleted; nothing read it.

## Known limits
- hCaptcha is reachable and clickable, but from a **datacenter** exit it escalates
  from the checkbox to an image puzzle and the token stays empty. Everything up
  to that point is proven; finishing needs either a residential exit or one
  human answer. `import-credentials` is the documented bypass.
- Phase 5 was verified over a Vultr datacenter IP, not a residential one, so the
  residential claim in SPEC is exercised only by the harness relays.

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
- A blind TLS splice cannot see HTTP status, so `AUTH_EXPIRED` is only as good
  as the CLI's stderr wording; the classifier is deliberately quiet on unknown
  failures rather than guessing a `COOLDOWN`.
- The hCaptcha checkbox lives in a *nested* hCaptcha frame, and identically
  titled frames make name-based locators ambiguous — walk indices instead.
- A script in `/tmp` named `click.py` shadows the PyPI `click` package (since
  `/tmp` leads `sys.path`), which cycles `camoufox -> click` and hangs the
  browser launch. Renamed to `/tmp/drive_click.py`.
- The sing-box route map is memory-only; a control-plane restart used to leave
  profiles unroutable and `reload` refusing an empty map. Now rebuilt from the DB.
- A `BUSY` flag without a clock is a lock nobody owns after a crash; the lease
  had to live in the row (`last_heartbeat_at`) so the server, not the dead
  launcher, is the authority on when the session is over.
- A heartbeat is a `WHERE status='BUSY' AND active_session_id=?` update: stamping
  unconditionally would revive a row the sweep had already handed to someone else.
