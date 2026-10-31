"""FastAPI control plane.

Two audiences:
  * the operator (admin token) — create profiles, issue card keys, inspect state;
  * the customer launcher (card key + tunnel secret) — fetch credentials, geo
    targets and tunnel endpoint, then report health.

Admin routes live under `/admin` and are gated by `CCE_ADMIN_TOKEN`; launcher
routes take the card key as a bearer token so a leaked URL alone is not enough.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from core.browser_pool import BrowserPool
from core.crypto import CryptoError, decrypt_blob
from core.profile_manager import ProfileError, ProfileManager
from core.proxy_inspector import ProxyKillSwitchError, ProxyInspector
from core.singbox_manager import SingBoxError, SingBoxManager
from db.database import PLAN_TIERS, Database, open_database
from util.ids import new_card_key, new_token

DB_PATH = os.environ.get("CCE_DB_PATH", "data/cce.sqlite3")
ADMIN_TOKEN_ENV = "CCE_ADMIN_TOKEN"
TUNNEL_HOST = os.environ.get("CCE_TUNNEL_HOST", "")
TUNNEL_PORT = int(os.environ.get("CCE_TUNNEL_PORT", "8443"))
# Where issued tunnel secrets are mirrored for the gateway (CCE_TUNNEL_SECRETS).
SECRETS_PATH = os.environ.get("CCE_TUNNEL_SECRETS", "")


class ProfileCreate(BaseModel):
    profile_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    upstream_proxy_url: str = Field(min_length=8)
    expected_ip: str = Field(min_length=3)
    os_type: str = Field(default="macos", pattern=r"^(macos|windows|linux)$")
    batch_id: str | None = None
    local_proxy_port: int | None = Field(default=None, ge=10001, le=11000)


class BatchCreate(BaseModel):
    batch_id: str = Field(min_length=2, max_length=64)
    bin_prefix: str = Field(min_length=4, max_length=10)
    billing_country: str = Field(min_length=2, max_length=2)
    max_accounts: int = Field(default=10, ge=1, le=100)


class ImportCredentials(BaseModel):
    path: str


class KeyIssue(BaseModel):
    profile_id: str
    plan_tier: str = Field(pattern=r"^(pro|max_5x|max_20x|env_only)$")
    valid_days: int = Field(default=30, ge=1, le=365)


class State:
    """Process-wide wiring, populated on startup."""

    db: Database
    profiles: ProfileManager
    inspector: ProxyInspector
    pool: BrowserPool
    singbox: SingBoxManager


state = State()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def require_admin(x_admin_token: Annotated[str | None, Header()] = None) -> None:
    expected = os.environ.get(ADMIN_TOKEN_ENV, "")
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "admin token not configured")
    if x_admin_token != expected:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bad admin token")


async def _launcher_key(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_tunnel_secret: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Resolve the card key, and the tunnel secret once the launcher has it.

    `/launcher/session` is what *issues* the tunnel secret, so it cannot require
    the secret itself -- it is required on every other launcher route. Both
    factors are still needed to get anything out of the session: a leaked key
    alone buys a session body, but no credentials and no tunnel.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer card key")
    card_key = authorization.split(" ", 1)[1].strip()
    row = await state.db.active_delivery_key(card_key, _now_iso())
    if row is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "card key invalid, revoked or expired")
    if request.url.path != "/launcher/session" and row["tunnel_secret"] != (x_tunnel_secret or ""):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "tunnel secret mismatch")
    return row


def create_app() -> FastAPI:
    app = FastAPI(title="Claude Cluster Engine", version="0.1.0", docs_url="/docs")

    @app.on_event("startup")
    async def _startup() -> None:
        state.db = Database(DB_PATH)
        await state.db.connect()
        state.profiles = ProfileManager(state.db)
        state.inspector = ProxyInspector(state.db)
        state.singbox = SingBoxManager()
        state.pool = BrowserPool(state.db, state.profiles, state.inspector)
        await _restore_routes()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await state.singbox.stop()
        await state.db.close()

    async def _restore_routes() -> None:
        """Rebuild the port map from the database, then bring sing-box back up.

        The map is in-memory state, so a restart would otherwise leave every
        profile reachable in the records but with no inbound to reach it -- and
        `/admin/singbox/reload` refuses to render an empty map.
        """
        for row in await state.db.list_profiles():
            state.singbox.register(row["profile_id"], row["local_proxy_port"], row["upstream_proxy_url"])
        if state.singbox.available:
            try:
                await state.singbox.reload()
            except SingBoxError:
                # A foreign listener on one of the ports must not stop the API.
                pass

    @app.exception_handler(ProxyKillSwitchError)
    async def _kill_switch(_request: Any, exc: ProxyKillSwitchError) -> JSONResponse:
        return JSONResponse(
            {"error": "kill_switch", "reason": exc.reason, "detail": str(exc)},
            status_code=status.HTTP_409_CONFLICT,
        )

    @app.exception_handler(ProfileError)
    async def _profile_error(_request: Any, exc: ProfileError) -> JSONResponse:
        return JSONResponse({"error": "profile", "detail": str(exc)}, status_code=status.HTTP_400_BAD_REQUEST)

    @app.exception_handler(CryptoError)
    async def _crypto_error(_request: Any, exc: CryptoError) -> JSONResponse:
        return JSONResponse({"error": "crypto", "detail": str(exc)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @app.exception_handler(SingBoxError)
    async def _singbox_error(_request: Any, exc: SingBoxError) -> JSONResponse:
        return JSONResponse({"error": "singbox", "detail": str(exc)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # -- health ------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "time": _now_iso()}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        problems = []
        if not os.environ.get(ADMIN_TOKEN_ENV):
            problems.append("CCE_ADMIN_TOKEN unset")
        if not os.environ.get("CCE_MASTER_KEY"):
            problems.append("CCE_MASTER_KEY unset")
        if state.singbox.available is False:
            problems.append("sing-box binary missing")
        return JSONResponse({"ok": not problems, "problems": problems}, status_code=200 if not problems else 503)

    # -- admin -------------------------------------------------------------

    admin = Depends(require_admin)

    @app.post("/admin/batches", dependencies=[admin], status_code=201)
    async def create_batch(body: BatchCreate) -> dict[str, Any]:
        await state.db.create_batch(body.batch_id, body.bin_prefix, body.billing_country.upper(), body.max_accounts)
        return {"batch": await state.db.get_batch(body.batch_id)}

    @app.post("/admin/profiles", dependencies=[admin], status_code=201)
    async def create_profile(body: ProfileCreate) -> dict[str, Any]:
        record = await state.profiles.create_profile(
            profile_id=body.profile_id,
            local_proxy_port=body.local_proxy_port,
            upstream_proxy_url=body.upstream_proxy_url,
            expected_ip=body.expected_ip,
            os_type=body.os_type,
            batch_id=body.batch_id,
        )
        state.singbox.register(record["profile_id"], record["local_proxy_port"], body.upstream_proxy_url)
        return _public_profile(record)

    @app.get("/admin/profiles", dependencies=[admin])
    async def list_profiles(status_filter: str | None = None) -> dict[str, Any]:
        rows = await state.db.list_profiles(status_filter)
        return {"profiles": [_public_profile(row) for row in rows]}

    @app.get("/admin/profiles/{profile_id}", dependencies=[admin])
    async def get_profile(profile_id: str) -> dict[str, Any]:
        row = await state.db.get_profile(profile_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
        return _public_profile(row)

    @app.post("/admin/profiles/{profile_id}/preflight", dependencies=[admin])
    async def preflight(profile_id: str) -> dict[str, Any]:
        geo = await state.inspector.verify_and_inspect(profile_id)
        return {"profile_id": profile_id, "ok": True, "geo": geo.to_json()}

    @app.post("/admin/profiles/{profile_id}/stealth-check", dependencies=[admin])
    async def stealth_check(profile_id: str) -> dict[str, Any]:
        return await state.pool.verify_stealth(profile_id)

    @app.post("/admin/profiles/{profile_id}/sync-credentials", dependencies=[admin])
    async def sync_credentials(profile_id: str) -> dict[str, Any]:
        blob = await state.pool.sync_claude_cli_credentials(profile_id)
        return {"profile_id": profile_id, "bytes": len(blob)}

    @app.post("/admin/profiles/{profile_id}/import-credentials", dependencies=[admin])
    async def import_credentials(profile_id: str, body: ImportCredentials) -> dict[str, Any]:
        """Seal an existing `.claude` dir (ops path when OAuth cannot be driven)."""
        if await state.db.get_profile(profile_id) is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
        blob = await state.pool.import_claude_credentials(profile_id, Path(body.path))
        return {"profile_id": profile_id, "bytes": len(blob)}

    @app.get("/admin/singbox", dependencies=[admin])
    async def singbox_state() -> dict[str, Any]:
        return {"available": state.singbox.available, "running": state.singbox.running, "config": state.singbox.render()}

    @app.post("/admin/singbox/reload", dependencies=[admin])
    async def singbox_reload() -> dict[str, Any]:
        return await state.singbox.reload()

    @app.post("/admin/keys", dependencies=[admin], status_code=201)
    async def issue_key(body: KeyIssue) -> dict[str, Any]:
        if body.plan_tier not in PLAN_TIERS:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown plan tier")
        profile = await state.db.get_profile(body.profile_id)
        if profile is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
        card_key = new_card_key()
        tunnel_secret = new_token(18)
        record = {
            "card_key": card_key,
            "profile_id": body.profile_id,
            "plan_tier": body.plan_tier,
            "tunnel_secret": tunnel_secret,
            "expires_at": (_now() + timedelta(days=body.valid_days)).isoformat(),
        }
        await state.db.insert_delivery_key(record)
        await _export_secrets()
        return {"card_key": card_key, "tunnel_secret": tunnel_secret, "expires_at": record["expires_at"]}

    @app.get("/admin/keys/{profile_id}", dependencies=[admin])
    async def list_keys(profile_id: str) -> dict[str, Any]:
        return {"keys": await state.db.list_delivery_keys(profile_id)}

    @app.delete("/admin/keys/{card_key}", dependencies=[admin])
    async def revoke_key(card_key: str) -> dict[str, Any]:
        await state.db.revoke_delivery_key(card_key)
        await _export_secrets()
        return {"revoked": card_key}

    @app.post("/admin/tunnel-secrets", dependencies=[admin])
    async def export_secrets() -> dict[str, Any]:
        """Rewrite the gateway's secret file; called after issue/revoke."""
        return await _export_secrets(force=True)

    # -- launcher ----------------------------------------------------------

    @app.post("/launcher/session")
    async def launcher_session(row: Annotated[dict[str, Any], Depends(_launcher_key)]) -> dict[str, Any]:
        """Everything the launcher needs, minus the credential blob itself."""
        return {
            "profile_id": row["profile_id"],
            "plan_tier": row["plan_tier"],
            "os_type": row["os_type"],
            "expected_ip": row["expected_ip"],
            # The gateway routes through this port so traffic leaves from the
            # profile's residential IP instead of the control plane's own.
            "local_proxy_port": row.get("local_proxy_port"),
            "noise_seed": row["noise_seed"],
            "fingerprint": _json_or_none(row.get("fingerprint_json")),
            "geo": _json_or_none(row.get("geo_json")),
            "tunnel": {"host": TUNNEL_HOST, "port": TUNNEL_PORT, "secret": row["tunnel_secret"]},
            "expires_at": row["expires_at"],
            "has_credentials": row.get("claude_credentials_enc") is not None,
        }

    @app.get("/launcher/credentials")
    async def launcher_credentials(row: Annotated[dict[str, Any], Depends(_launcher_key)]) -> Response:
        stored = await state.db.get_profile(row["profile_id"])
        blob = stored.get("claude_credentials_enc") if stored else None
        if not blob:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no credentials synced for this profile")
        tar_gz = decrypt_blob(bytes(blob), associated=row["profile_id"].encode())
        return Response(
            content=tar_gz,
            media_type="application/gzip",
            headers={
                "content-disposition": f'attachment; filename="{row["profile_id"]}.tar.gz"',
                "x-profile-id": row["profile_id"],
            },
        )

    @app.post("/launcher/heartbeat")
    async def launcher_heartbeat(
        row: Annotated[dict[str, Any], Depends(_launcher_key)],
        x_observed_ip: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        drift = bool(x_observed_ip) and x_observed_ip != row["expected_ip"]
        if drift:
            await state.db.set_status(row["profile_id"], "PROXY_DEAD")
        return {"ok": True, "ip_drift": drift, "expected_ip": row["expected_ip"]}

    # -- debug -------------------------------------------------------------

    @app.get("/launcher/credentials/b64")
    async def launcher_credentials_b64(row: Annotated[dict[str, Any], Depends(_launcher_key)]) -> dict[str, Any]:
        stored = await state.db.get_profile(row["profile_id"])
        blob = stored.get("claude_credentials_enc") if stored else None
        if not blob:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no credentials synced")
        return {"profile_id": row["profile_id"], "tar_gz_b64": base64.b64encode(decrypt_blob(bytes(blob), associated=row["profile_id"].encode())).decode()}

    return app


async def _export_secrets(*, force: bool = False) -> dict[str, Any]:
    """Mirror active, unexpired tunnel secrets where the gateway can read them.

    The gateway holds one secret per card key, not a single shared value, so it
    needs the set shipped to it. Writing is idempotent and skipped when nothing
    changed, which keeps a fleet-sized file from being rewritten per request.
    """
    path = Path(SECRETS_PATH) if SECRETS_PATH else Path(DB_PATH).with_suffix(".secrets")
    rows = await state.db.fetch_all(
        "SELECT card_key, tunnel_secret, expires_at FROM delivery_keys"
        " WHERE is_active = 1 AND expires_at > ? ORDER BY card_key",
        (_now_iso(),),
    )
    body = "# card_key secret expires_at\n" + "".join(
        f"{row['card_key']} {row['tunnel_secret']} {row['expires_at']}\n" for row in rows
    )
    if force or not path.exists() or path.read_text(encoding="utf-8") != body:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        os.chmod(path, 0o600)
    return {"path": str(path), "keys": len(rows)}


def _public_profile(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"claude_credentials_enc", "fingerprint_json", "upstream_proxy_url"}
    } | {
        "has_credentials": row.get("claude_credentials_enc") is not None,
        "local_proxy_port": row.get("local_proxy_port"),
        "expected_ip": row.get("expected_ip"),
    }


def _json_or_none(value: str | None) -> Any:
    import json

    if not value:
        return None
    try:
        return json.loads(value)
    except ValueError:
        return None


app = create_app()
