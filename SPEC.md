# Project Specification: Antidetect Cluster & Claude Delivery Engine

## 1. System Overview & Architectural Goals

Build an enterprise-grade, lightweight Antidetect Profile Management, Static Proxy Mesh, and Client Delivery System for managing 1,000+ isolated Claude / Claude Code environments.

### Core Architectural Principles

1. **Control Plane vs. Execution Plane Separation**:
   - **Control Plane (Python 3.11+)**: On-demand antidetect browser worker pool (`Camoufox` + `BrowserForge`) limited by an async semaphore (`max_concurrent=5`). Used strictly for registration, OAuth token extraction (`claude login`), Cloudflare challenge solving, and Stripe billing.
   - **Execution Plane (Go 1.22+)**: Lightweight cross-platform client launcher (`claude-box`) and server-side domain-whitelisted proxy relay gateway. Runs native `claude` CLI via isolated `CLAUDE_CONFIG_DIR` and encrypted proxy tunnels without spinning up heavy browsers.
2. **Deterministic Fingerprint Persistence**:
   - Generate hardware/navigator fingerprints ONCE at profile creation via `BrowserForge` and a deterministic SHA-256 noise seed derived from `profile_id`. Persist in SQLite. Never regenerate fingerprints on subsequent runs.
3. **Zero-Leak Network & Kill Switch**:
   - 1:1 binding between `profile_id` and a dedicated Static Residential ISP proxy port managed by `Sing-box`.
   - Pre-flight check before launching any browser or CLI session: verify proxy reachability, assert egress IP matches `expected_ip`, and dynamically inject matching GeoIP metadata (`timezone`, `lat/lon`, `locale`, `webrtc:ipv4`). Abort immediately on mismatch or timeout.
4. **Disk Scrubbing**:
   - Automatically purge browser cache directories (`cache2`, `startupCache`, `shader-cache`, `crashes`) upon context exit so each profile consumes less than 10MB on disk.

---

## 2. Monorepo Directory Structure

Generate the project following this exact layout:

```text
claude-cluster-engine/
├── server/
│   ├── pyproject.toml
│   ├── config/
│   │   └── singbox_template.json
│   ├── db/
│   │   ├── schema.sql
│   │   └── database.py             # Async SQLite CRUD wrapper (aiosqlite)
│   ├── core/
│   │   ├── proxy_inspector.py      # Pre-flight IP verification & GeoIP extractor (Kill Switch)
│   │   ├── singbox_manager.py      # Dynamic port mapping (10001-11000) & Sing-box reload
│   │   ├── profile_manager.py      # BrowserForge persistence, Deterministic Seed, Cache Scrubber
│   │   ├── browser_pool.py         # AsyncCamoufox Semaphore worker pool & OAuth extractor
│   │   └── crypto.py               # AES-GCM encryption for OAuth credentials & cookies
│   ├── api/
│   │   └── app.py                  # FastAPI server for Client Launcher auth & profile sync
│   └── mcp_server.py               # FastMCP server exposing cluster tools to AI agents
├── gateway/
│   ├── go.mod
│   └── main.go                     # High-concurrency SOCKS5/HTTP tunnel with SNI domain whitelist
└── client-launcher/
    ├── go.mod
    └── main.go                     # Cross-platform CLI/Desktop launcher (`claude-box`)
```

---

## 3. Database Schema (`server/db/schema.sql`)

Implement the following SQLite schema:

```sql
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS payment_batches (
    batch_id TEXT PRIMARY KEY,
    bin_prefix TEXT NOT NULL,
    billing_country TEXT NOT NULL,
    max_accounts INTEGER DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS profiles (
    profile_id TEXT PRIMARY KEY,
    batch_id TEXT,
    local_proxy_port INTEGER UNIQUE NOT NULL,
    upstream_proxy_url TEXT NOT NULL,
    expected_ip TEXT NOT NULL,
    os_type TEXT NOT NULL CHECK(os_type IN ('macos', 'windows', 'linux')),
    noise_seed INTEGER NOT NULL,
    fingerprint_json TEXT NOT NULL,
    geo_json TEXT,
    claude_credentials_enc BLOB,
    status TEXT DEFAULT 'IDLE' CHECK(status IN ('IDLE', 'BUSY', 'COOLDOWN', 'AUTH_EXPIRED', 'PROXY_DEAD', 'BANNED')),
    cooldown_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(batch_id) REFERENCES payment_batches(batch_id)
);

CREATE TABLE IF NOT EXISTS delivery_keys (
    card_key TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    plan_tier TEXT NOT NULL CHECK(plan_tier IN ('pro', 'max_5x', 'max_20x', 'env_only')),
    tunnel_secret TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY(profile_id) REFERENCES profiles(profile_id)
);
```

---

## 4. Detailed Module Specifications

### Module 4.1: Pre-Flight Proxy Inspector (`server/core/proxy_inspector.py`)

- **Input**: `proxy_url: str`, `expected_ip: Optional[str]`
- **Behavior**:
  1. Use `httpx.AsyncClient(proxy=proxy_url, timeout=8.0)` to request `http://ip-api.com/json/?fields=status,countryCode,lat,lon,timezone,query`.
  2. If the request fails, times out, or `query != expected_ip` (when `expected_ip` is set), raise `ProxyKillSwitchError` and mark profile status as `PROXY_DEAD` in SQLite.
  3. Map `countryCode` to standard BCP 47 locale (e.g., `US -> en-US`, `GB -> en-GB`, `SG -> en-SG`).
  4. Return a `ProxyGeoInfo` dataclass containing `ip`, `country_code`, `timezone`, `latitude`, `longitude`, `locale`.

### Module 4.2: Profile Manager & Cache Scrubber (`server/core/profile_manager.py`)

- **`create_profile(profile_id, local_proxy_port, upstream_proxy_url, expected_ip, os_type, batch_id)`**:
  1. Compute deterministic 32-bit integer `noise_seed`: `int(hashlib.sha256(profile_id.encode()).hexdigest()[:8], 16)`.
  2. Use `browserforge.fingerprints.FingerprintGenerator(browser="firefox", os=os_type)` to generate a realistic hardware profile (`userAgent`, `hardwareConcurrency`, `platform`, `screen`, `videoCard`).
  3. Create isolated directories: `./data/profiles/{profile_id}/browser_data` and `./data/profiles/{profile_id}/claude_home`.
  4. Insert record into `profiles` table.

- **`scrub_profile_cache(profile_id)`**:
  1. Remove heavy cache directories inside `./data/profiles/{profile_id}/browser_data`: `["cache2", "startupCache", "jumpListCache", "shader-cache", "crashes", "minidumps", "datareporting", "saved-telemetry-pings"]`.
  2. Preserve `cookies.sqlite`, `webappsstore.sqlite`, and `prefs.js`.

### Module 4.3: Camoufox Browser Worker Pool (`server/core/browser_pool.py`)

- Maintain an `asyncio.Semaphore(5)` to cap concurrent browser instances on a single machine.
- Provide `@asynccontextmanager async def acquire_context(profile_id: str, headless: bool = True)`:
  1. Fetch profile metadata from SQLite.
  2. Run `ProxyInspector.verify_and_inspect(proxy_url, expected_ip)` (Kill Switch).
  3. Launch `AsyncCamoufox` with `persistent_context=True`, `user_data_dir`, `os=record["os_type"]`, `proxy`, `humanize=True`, and `config`:
     - `"webrtc:ipv4": geo.ip`
     - `"timezone": geo.timezone`
     - `"geolocation:latitude": geo.latitude`
     - `"geolocation:longitude": geo.longitude`
     - `"locale:language": geo.locale.split("-")[0]`
     - `"locale:region": geo.locale.split("-")[1]`
     - `"screen.width": fp["screen"]["width"]`
     - `"screen.height": fp["screen"]["height"]`
     - `"navigator.hardwareConcurrency": fp["navigator"]["hardwareConcurrency"]`
  4. In the `finally` block, always invoke `scrub_profile_cache(profile_id)`.

- Provide `sync_claude_cli_credentials(profile_id: str)`:
  1. Run `claude` login flow in an isolated subprocess with `HOME=./data/profiles/{profile_id}/claude_home` and `HTTPS_PROXY=http://127.0.0.1:{local_proxy_port}`.
  2. Capture the OAuth authorization URL, open it inside `acquire_context(profile_id)`, complete authorization, tar + AES-GCM encrypt the resulting `.claude` config directory, and store it in `profiles.claude_credentials_enc`.

### Module 4.4: Domain-Whitelisted Tunnel Gateway (`gateway/main.go`)

- Listen on TLS port `8443` for client launcher connections.
- Authenticate incoming requests via header `X-Delivery-Key: <card_key>` and `X-Tunnel-Secret: <tunnel_secret>`.
- Look up the bound `local_proxy_port` (Sing-box port `10001~11000`) for the `card_key`.
- **Strict Domain Whitelist**: Inspect HTTP `CONNECT` host / TLS SNI. Allow ONLY:
  - `*.anthropic.com`
  - `*.claude.ai`
  - `*.stripe.com`
  - `*.cloudflare.com`
  - `ipinfo.io` / `ip-api.com`
- Drop any other destination immediately to prevent proxy abuse.

### Module 4.5: Cross-Platform Client Launcher (`client-launcher/main.go`)

Compile into standalone binaries (`claude-box`) for `darwin/arm64`, `darwin/amd64`, and `windows/amd64`.

- **Command 1: `claude-box cli --key <CARD_KEY>`**
  1. Authenticate with `server/api/app.py` using `<CARD_KEY>`, retrieve encrypted `.claude` credentials, expected egress IP, timezone, and tunnel endpoint.
  2. Start an in-memory local HTTP/SOCKS5 loopback proxy on `127.0.0.1:<random_port>` that forwards traffic through the authenticated `gateway` tunnel.
  3. **Client-Side Kill Switch**: Request `https://api.anthropic.com` or `https://ipinfo.io/ip` through the local loopback port. Verify egress IP matches `expected_ip`. If it fails, exit with code 1.
  4. Extract `.claude` credentials into `~/.claude-box/profiles/<profile_id>/.claude`.
  5. Execute native `claude` binary (`os/exec`) with injected environment variables:
     - `CLAUDE_CONFIG_DIR=~/.claude-box/profiles/<profile_id>/.claude`
     - `HTTPS_PROXY=http://127.0.0.1:<random_port>`
     - `HTTP_PROXY=http://127.0.0.1:<random_port>`
     - `TZ=<assigned_timezone>`

- **Command 2: `claude-box desktop --key <CARD_KEY>`**
  1. Check if antidetect browser kernel exists in `~/.claude-box/runtime/`; if not, download prebuilt archive from CDN.
  2. On macOS (`runtime.GOOS == "darwin"`), automatically run `exec.Command("xattr", "-rd", "com.apple.quarantine", runtimePath)` to bypass Gatekeeper quarantine popups.
  3. Start the local loopback tunnel proxy, verify Kill Switch, and launch the browser binary with deterministic fingerprint flags (`--fingerprint=<noise_seed>`, `--timezone=<tz>`, `--proxy-server=127.0.0.1:<random_port>`, `--user-data-dir=...`) pointing to `https://claude.ai`.

### Module 4.6: MCP Server Interface (`server/mcp_server.py`)

Use `FastMCP("Claude-Cluster-Engine")` to expose:

- `@mcp.tool() create_isolated_profile(profile_id, local_proxy_port, upstream_proxy_url, expected_ip, os_type, batch_id)`
- `@mcp.tool() verify_profile_stealth(profile_id)` -> Opens `https://ipinfo.io/json` inside Camoufox and returns fingerprint + IP consistency report.
- `@mcp.tool() issue_customer_card_key(profile_id, plan_tier, valid_days)` -> Generates a `card_key` for customer delivery.
- `@mcp.resource("veynod://knowledge/cluster-spec")` -> Returns this specification document.

---

## 5. Step-by-Step Implementation Plan for Coding Agent

Execute the build in the following order:

1. **Phase 1 (Database & Core Antidetect Engine)**: Implement `server/db/schema.sql`, `database.py`, `proxy_inspector.py`, `profile_manager.py`, and `browser_pool.py`. Write a `pytest` suite verifying deterministic fingerprint generation, Kill Switch blocking on bad proxies, and post-close cache scrubbing.
2. **Phase 2 (Sing-box & FastAPI Control Plane)**: Implement `singbox_manager.py`, `crypto.py`, `server/api/app.py`, and `server/mcp_server.py`.
3. **Phase 3 (Go Domain-Whitelisted Gateway)**: Implement `gateway/main.go` with SNI/CONNECT domain whitelisting and card_key authentication.
4. **Phase 4 (Go Cross-Platform Client Launcher)**: Implement `client-launcher/main.go` supporting both `cli` mode (wrapping native `claude` with `CLAUDE_CONFIG_DIR` and local loopback proxy) and `desktop` mode (with macOS `xattr` quarantine removal). Provide a `Makefile` to cross-compile for macOS (arm64/amd64) and Windows (amd64).
