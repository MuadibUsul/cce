"""AES-GCM encryption for customer credential blobs.

Key comes from `CCE_MASTER_KEY` (base64, 32 bytes) so a database dump alone is
useless. Format is `MAGIC | 12-byte nonce | ciphertext`, and the associated data
binds a blob to its profile id, which stops a swapped ciphertext from
authenticating under the wrong account.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CCE1"
NONCE_SIZE = 12
KEY_ENV = "CCE_MASTER_KEY"


class CryptoError(RuntimeError):
    pass


def _load_key() -> bytes:
    raw = os.environ.get(KEY_ENV, "").strip()
    if not raw:
        raise CryptoError(f"{KEY_ENV} is not set")
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise CryptoError(f"{KEY_ENV} is not valid base64") from exc
    if len(key) != 32:
        raise CryptoError(f"{KEY_ENV} must decode to 32 bytes, got {len(key)}")
    return key


def generate_key() -> str:
    """Produce a fresh base64 key for `CCE_MASTER_KEY`."""
    return base64.b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii")


def encrypt_blob(plaintext: bytes, *, associated: bytes | None = None) -> bytes:
    key = _load_key()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated)
    return MAGIC + nonce + ciphertext


def decrypt_blob(payload: bytes, *, associated: bytes | None = None) -> bytes:
    if not payload.startswith(MAGIC):
        raise CryptoError("blob is not a CCE1 payload")
    body = payload[len(MAGIC) :]
    if len(body) <= NONCE_SIZE:
        raise CryptoError("blob is truncated")
    nonce, ciphertext = body[:NONCE_SIZE], body[NONCE_SIZE:]
    try:
        return AESGCM(_load_key()).decrypt(nonce, ciphertext, associated)
    except InvalidTag as exc:
        raise CryptoError("blob failed authentication (wrong key or tampered)") from exc
