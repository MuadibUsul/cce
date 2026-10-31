# Architecture

Audience: an architect reviewing the system, or an engineer about to change it.
It describes what is built, why each seam sits where it does, and where the sharp
edges are. `SPEC.md` is the requirement; this is the implementation.

Read `docs/OPERATIONS_SOP.md` for the day-to-day operator view.

## 1. What the system is

Delivers a **named Claude CLI or Claude Desktop session** to a customer, where
the session looks like a specific physical machine on a specific residential
line, and where the browser + CLI can only reach Claude.

One row in the database is one sellable identity. Its fingerprint and its egress
IP are chosen **once, at creation**, and never regenerated — a re-drawn
fingerprint is a new device and undoes the work.

Three processes, one control plane:

```
customer                         operator
   |                                |
   | card key                       | admin token
   v                                v
claude-box (Go) --TLS--> gateway (Go)      control plane (FastAPI + MCP)
   |                        |                        |
   | local loopback         | SNI/CONNECT check      | DB, crypto,
   | CONNECT proxy          | + x-profile-port       | cam profiler, sing-box
   |                        |                        |
   v                        v                        v
Claude / Camoufox      origin :443           sing-box inbounds 10001-11000
                                                |
                                                v
                                        residential upstream
```

The launcher never spawns the gateway and the gateway never talks to the control
plane at request time. The only shared state is (a) the database, (b) the
hot-reloaded secret file the gateway watches, (c) the sing-box port map. That
keeps a control-plane restart from taking down live customer sessions.

## 2. Repository map

```
SPEC.md                     requirement
TASKS.md                    phase checklist + findings + known limits
docs/OPERATIONS_SOP.md      runbook
docs/ARCHITECTURE.md        this file

server/                     control plane (Python 3.11+, FastAPI + MCP)
  api/app.py                HTTP surface: admin + launcher + session issuance
  mcp_server.py             9 MCP tools over the same services
  core/profile_manager.py   profile lifecycle, fingerprint generation, cache scrub
  core/proxy_inspector.py   kill switch: geo + egress verification
  core/browser_pool.py      Camoufox pool, context acquisition, OAuth driving
  core/singbox_manager.py   port-map rendering + reload
  core/crypto.py            AES-GCM seal/open (CCE1)
  core/login.py             sign-in page driving primitives
  db/schema.sql             tables
  db/database.py            data access
  config/singbox_template.json
  util/ids.py               card keys, tokens

gateway/                    Go, TLS whitelist relay
client-launcher/            Go, `claude-box` cli|desktop|version

tests/                      unit + e2e harnesses + live harness
```

Roughly 7.3k lines of source. `client-launcher/main.go` (1136) > `gateway/main.go`
(693) > `profile_manager.py` (446) > `browser_pool.py` (420) > `api/app.py` (393).

## 3. Data model

`server/db/schema.sql`.

- `payment_batches` — blast-radius container. Accounts in a batch share a card
  BIN, billing country and mailbox domain; `max_accounts` caps it. A ban wave
  stops at the batch.
- `profiles` — one sellable identity. Holds the frozen `fingerprint_json`, the
  frozen `expected_ip`, `local_proxy_port` (UNIQUE), `upstream_proxy_url`,
  `os_type`, `noise_seed`, sealed `claude_credentials_enc`, a status enum and
  `cooldown_until`. Status moves only through `server/core/lifecycle.py`, whose
  transition table is exhaustive over the six states; an illegal jump raises
  `IllegalTransition` instead of being written.
- `delivery_keys` — the customer credential. `card_key` is presented by the
  launcher; `tunnel_secret` is the second factor and is **per key**, so one
  revoked card does not disturb the fleet.

`fingerprint_json` is not a summary: it is the whole `CAMOU_CONFIG` map verbatim,
replayed at launch with `i_know_what_im_doing=True`. A partial fingerprint means a
device that drifts between launches.

## 4. The five invariants

These are the load-bearing properties. Break one and the product stops working
in a way that is hard to notice.

### 4.1 Fingerprint is frozen and coherent

`_fingerprint_for()` seeds Camoufox's own fpgen from
`int(sha256(profile_id).hexdigest()[:8], 16)` and then loops `coherence.apply()`
until `validate()` reports nothing. Camoufox's generator is used rather than
`browserforge` because it produces a kernel-correct UA (`rv:156`) and a
screen/window pair the kernel agrees with.

Two deliberate deviations from a "pure" identity: the UA version is rewritten to
the installed kernel, and the CPU count snaps to the host. Both avoid an
impossible device.

Locale comes from the **exit IP's country**, never from a fixed map, and
`geoip=**` is never passed — the kernel resolving timezone itself would fight the
config.

### 4.2 Kill switch before anything expensive

`ProxyInspector.verify_and_inspect()` queries `ip-api.com` **through the profile's
own proxy** and compares the answer against the frozen `expected_ip`. Any
deviation — timeout, unreachable, non-JSON, no IP, drift — raises
`ProxyKillSwitchError` and marks the row `PROXY_DEAD`. It runs at profile creation
and before every `acquire_context()`, i.e. before a browser is burned.

The probe host `api.ipify.org` was dropped because it is not whitelisted;
`ip-api.com` is (plain HTTP).

### 4.3 Secrets never land in plaintext

`crypto.py` seals with AES-GCM under `CCE_MASTER_KEY`, prefix `CCE1`. Critically
the **profile id is the AEAD associated data**, on seal *and* on open: without it a
ciphertext copied between rows authenticates as the wrong account. On the client,
`refreshCredentials()` extracts into `<configDir>.incoming` and only then renames,
so an interrupted extraction cannot leave a half store. The directory is wiped on
exit unless `--keep`.

### 4.4 The gateway is the only door

`newWhitelist()` treats `*.x` as "suffix or apex", and `allows()` lowercases,
strips a trailing dot and any `:port`. Everything else is `403` before a dial.
Both the SNI path and the CONNECT path check it, so the two cannot disagree.

Default list: `*.anthropic.com`, `*.claude.ai`, `claude.com`,
`platform.claude.com`, `*.stripe.com`, `*.cloudflare.com`, `ipinfo.io`,
`ip-api.com`. The two `claude` entries are the one addition beyond SPEC and they
are load-bearing — `claude auth login` sends the browser to
`claude.com/cai/oauth/authorize` and the callback belongs to
`platform.claude.com`. Without both, no token can ever be minted. `defaultDomains()`
carries the same reasoning so the two cannot drift apart silently.

### 4.5 TLS is passed through, except where it must be terminated

`handle()` sniffs the first byte: `0x16` is a TLS record. `handleTLS()` then peeks
the ClientHello.

- Whitelisted SNI → the bytes are replayed and the socket spliced to the origin,
  so TLS runs **end to end** and certificate pinning inside Claude still holds.
- No SNI (an IP was dialled) or non-whitelisted SNI → the handshake is terminated
  here and the tunnel is served inside, where the CONNECT target is checked
  instead. Missing certificate is a refusal, not a silent downgrade.

Routing: the launcher stamps `x-profile-port`; `dialOrigin()` checks it against
`profileRange()` 10001-11000 so a lying launcher is harmless.

## 5. Port map

`SingBoxManager` renders one inbound per profile from
`config/singbox_template.json` and reloads. The map is **memory-only** — which
was a real outage: after a control-plane restart every profile stayed in the DB
with no inbound, and `reload` refused an empty map. `_restore_routes()` now
re-registers every row at startup and calls `reload()`, swallowing
`SingBoxError` per profile.

sing-box 1.14 rejects the legacy inbound `sniff` field; it is route rule 0 as
`{"action": "sniff"}` so that sniffing still precedes routing.

## 6. Browser isolation

`acquire_context()` is the only way to get a browser. Ordering is deliberate:
kill switch → directories → launch; the scrub is in `finally`, so a crash still
frees disk.

Per profile: own `user_data_dir`, own `CLAUDE_CONFIG_DIR`
(`<root>/<id>/claude_home/.claude`, `0700`), own sing-box inbound, own NSS store.
Desktop identity ships through `CAMOU_CONFIG_n`/`CAMOU_PREFS_n` with
`-profile <dir> -no-remote`, because the bare kernel has no
`--fingerprint/--timezone/--lang/--proxy-server` flags. Fonts are resolved to
absolute paths and `security.enterprise_roots.enabled` is on.

Disk: `SCRUB_DIRS` (cache, crashes, telemetry…) are purged each exit;
`cookies.sqlite`, `webappsstore.sqlite`, `prefs.js`, `user.js` are kept. Trace
tables in `places.sqlite`/`favicons.sqlite` are **vacuumed, not deleted**, so the
signature files survive. `enforce_disk_ceiling()` crops largest-first only above
10 MB.

## 7. Credential acquisition

Two paths, one storage format.

**`sync-credentials` (primary).** Runs `claude auth login` — not `claude login`,
which is a TUI that blocks forever on a non-tty. `auth` streams the authorize URL
and reads a code from stdin. `_read_authorize_url()` scrapes line by line, exits
early if credentials appear, and raises with an output tail otherwise.
`_drive_consent()` opens the URL in the profile's browser and walks it:
`extract_code()` → `needs_human()` → otherwise fill email, `solve_captcha()`,
consent. It returns `None` rather than pretending when it meets a password, SSO
or 2FA.

**`import-credentials` (escape hatch).** `.claude` in by hand. Same sealing,
atomic swap and erase.

`login.py` is deliberately dumb and testable: pure URL predicates plus small
locator helpers. hCaptcha serves several identically-titled frames and parks the
checkbox at `y = -9999`, so `solve_captcha()` walks frame indices and clicks only
the one carrying `#checkbox`.

## 8. Threat model / sharp edges

- **Datacenter IP blocks OAuth completion.** hCaptcha escalates to an image
  puzzle and the token stays empty; the run stops at the login page. Proven not
  to be a stealth defect: `navigator.webdriver === false`, 5 plugins, Cloudflare
  passes, and the same IP can click the checkbox on hCaptcha's own demo. Fix is a
  residential exit, not code. See `TASKS.md` known limits.
- **State root is user-owned**, `~/.claude-box` at `0700`; profile ids are
  validated (`_assert_safe_id`) before becoming path components.
- **`extractTarGz` has a traversal guard** — archives come off the wire.
- **Gateway auth is a bearer set with constant-time compare**, hot-reloaded from
  file. `CCE_TUNNEL_SECRET` (single static value) still works for one machine.
- **`/launcher/session` is the issuer** and is therefore exempt from the tunnel
  secret; it is authenticated by the card key instead.
- **A test CA must be a real CA + leaf**; Firefox rejects a self-signed leaf that
  is also `CA:TRUE`. `certutil` must seed the exact profile the kernel opens.

## 9. Verification

114 Python tests, plus `gofmt -l` (empty) / `go vet` / `go test` in both Go
modules. `tests/e2e/` drives the real binaries through a fake control plane, fake
residential relay and TLS origin — three CLI scenarios (happy, IP drift, dead
relay) and a desktop fidelity assertion. `tests/live.py` uses the real network,
the real kernel and the real gateway.

Status is covered explicitly: every transition pair, the cooldown clamp, the
sweeper's selectivity (an expired row is freed, a fresh one and a `BUSY` row are
not), and the exit classifier's quiet cases.

Unit tests never need network, an account or a kernel: the browser is faked at
the context boundary, and the login tests use a fake `claude` binary plus a
recording context.
