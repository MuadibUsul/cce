PRAGMA journal_mode=WAL;
PRAGMA foreign_keys = ON;

-- Risk-isolation unit. Accounts inside one batch share a card BIN, billing
-- template and mailbox domain; batches never mix, so a ban wave is contained.
CREATE TABLE IF NOT EXISTS payment_batches (
    batch_id TEXT PRIMARY KEY,
    bin_prefix TEXT NOT NULL,
    billing_country TEXT NOT NULL,
    max_accounts INTEGER DEFAULT 10,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- One row == one sellable Claude identity. The fingerprint and the egress IP
-- are decided exactly once, at creation, and never regenerated.
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

CREATE INDEX IF NOT EXISTS idx_profiles_status ON profiles(status);
CREATE INDEX IF NOT EXISTS idx_profiles_batch ON profiles(batch_id);

-- Customer-facing delivery credential. The card key is what the launcher
-- presents; the tunnel secret is the second factor for the relay gateway.
CREATE TABLE IF NOT EXISTS delivery_keys (
    card_key TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    plan_tier TEXT NOT NULL CHECK(plan_tier IN ('pro', 'max_5x', 'max_20x', 'env_only')),
    tunnel_secret TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY(profile_id) REFERENCES profiles(profile_id)
);

CREATE INDEX IF NOT EXISTS idx_delivery_keys_profile ON delivery_keys(profile_id);
