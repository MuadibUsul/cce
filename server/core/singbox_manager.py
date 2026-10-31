"""sing-box port-mapping manager (1 profile port == 1 static residential exit).

Each profile owns one inbound port in 10001-11000 that forwards to its upstream
SOCKS/HTTP proxy. The launcher only ever talks to the local port, so the real
upstream credentials never leave the server.

sing-box is driven as a single long-lived process: configs are regenerated to a
temp file and applied with a restart, which is what sing-box supports without a
control API. If the binary is absent the manager degrades to "config only" so
tests and single-machine dev still run.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

CONFIG_PATH = Path("data/singbox/config.json")
SINGBOX_BIN = "sing-box"


class SingBoxError(RuntimeError):
    pass


def build_inbound(profile_id: str, local_port: int) -> dict[str, Any]:
    return {
        "type": "mixed",
        "tag": f"p-{local_port}",
        "listen": "127.0.0.1",
        "listen_port": local_port,
        "sniff": True,
    }


def build_outbound(upstream_proxy_url: str, local_port: int) -> dict[str, Any]:
    parsed = urlparse(upstream_proxy_url)
    if not parsed.hostname or not parsed.port:
        raise SingBoxError(f"upstream proxy needs host and port: {upstream_proxy_url!r}")
    scheme = (parsed.scheme or "socks5").lower()
    if scheme not in {"socks5", "socks", "http", "https"}:
        raise SingBoxError(f"unsupported upstream scheme: {scheme}")
    outbound: dict[str, Any] = {
        "type": "socks" if scheme.startswith("socks") else "http",
        "tag": f"up-{local_port}",
        "server": parsed.hostname,
        "server_port": parsed.port,
    }
    if outbound["type"] == "socks":
        outbound["version"] = "5"
    if parsed.username:
        outbound["username"] = unquote(parsed.username)
    if parsed.password:
        outbound["password"] = unquote(parsed.password)
    return outbound


class SingBoxManager:
    def __init__(self, config_path: Path = CONFIG_PATH, binary: str = SINGBOX_BIN) -> None:
        self._config_path = Path(config_path)
        self._binary = binary
        self._route: dict[int, dict[str, Any]] = {}
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    @property
    def available(self) -> bool:
        return shutil.which(self._binary) is not None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    def register(self, profile_id: str, local_port: int, upstream_proxy_url: str) -> None:
        self._route[local_port] = {
            "profile_id": profile_id,
            "inbound": build_inbound(profile_id, local_port),
            "outbound": build_outbound(upstream_proxy_url, local_port),
        }

    def unregister(self, local_port: int) -> None:
        self._route.pop(local_port, None)

    def render(self) -> dict[str, Any]:
        inbounds = [route["inbound"] for _, route in sorted(self._route.items())]
        outbounds = [route["outbound"] for _, route in sorted(self._route.items())]
        rules = [
            {"type": "default", "inbound": route["inbound"]["tag"], "outbound": route["outbound"]["tag"]}
            for _, route in sorted(self._route.items())
        ]
        return {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules},
        }

    def write_config(self) -> Path:
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        self._config_path.write_text(json.dumps(self.render(), indent=2), encoding="utf-8")
        return self._config_path

    async def reload(self) -> dict[str, Any]:
        """Rewrite the config and restart sing-box. No-op without a binary."""
        if not self._route:
            raise SingBoxError("no routes registered")
        path = self.write_config()
        if not self.available:
            return {"applied": False, "reason": "sing-box binary not found", "config": str(path)}
        await self.stop()
        self._proc = await asyncio.create_subprocess_exec(
            self._binary, "run", "-c", str(path), stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        await asyncio.sleep(0.4)
        if self._proc.returncode not in (None, 0):
            err = b""
            if self._proc.stderr:
                err = await self._proc.stderr.read()
            raise SingBoxError(f"sing-box exited immediately: {err.decode('utf-8', 'replace')[-500:]}")
        return {"applied": True, "config": str(path), "inbounds": len(self._route)}

    async def stop(self) -> None:
        async with self._lock:
            if self._proc is None:
                return
            proc, self._proc = self._proc, None
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
