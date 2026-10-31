"""Publish the gateway's active, profile-bound tunnel grants."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db.database import Database


async def export_secrets(db: Database, *, force: bool = False) -> dict[str, Any]:
    path = Path(os.environ.get("CCE_TUNNEL_SECRETS") or Path(db.path).with_suffix(".secrets"))
    # Serialize exporters across API and MCP processes. Otherwise an older
    # snapshot can be written after a concurrent revocation has finished.
    async with db.transaction() as conn:
        await conn.execute("BEGIN IMMEDIATE")
        cursor = await conn.execute(
            "SELECT d.card_key, d.tunnel_secret, d.expires_at, p.local_proxy_port"
            " FROM delivery_keys d JOIN profiles p ON p.profile_id = d.profile_id"
            " WHERE d.is_active = 1 AND d.expires_at > ? AND p.status IN ('IDLE', 'BUSY')"
            " ORDER BY d.card_key",
            (datetime.now(timezone.utc).isoformat(),),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        body = "# card_key secret expires_at profile_port\n" + "".join(
            f"{row['card_key']} {row['tunnel_secret']} {row['expires_at']} {row['local_proxy_port']}\n"
            for row in rows
        )
        if force or not path.exists() or path.read_text(encoding="utf-8") != body:
            temporary = None
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as out:
                    temporary = Path(out.name)
                    out.write(body)
                os.chmod(temporary, 0o600)
                os.replace(temporary, path)
            except OSError:
                # An old grant file would keep revoked keys alive. Remove it so
                # the gateway fails closed if publication cannot finish.
                path.unlink(missing_ok=True)
                raise
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    return {"path": str(path), "keys": len(rows)}
