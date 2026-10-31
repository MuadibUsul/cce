"""Encryption round-trip and tamper detection."""

from __future__ import annotations

import base64

import pytest

from core.crypto import CryptoError, decrypt_blob, encrypt_blob, generate_key
from conftest import MASTER_KEY


def test_roundtrip() -> None:
    payload = b"oauth-token-material" * 100
    blob = encrypt_blob(payload)
    assert decrypt_blob(blob) == payload


def test_ciphertext_differs_per_call() -> None:
    assert encrypt_blob(b"same") != encrypt_blob(b"same")


def test_associated_data_is_enforced() -> None:
    blob = encrypt_blob(b"secret", associated=b"acct-1")
    assert decrypt_blob(blob, associated=b"acct-1") == b"secret"
    with pytest.raises(CryptoError, match="authentication"):
        decrypt_blob(blob, associated=b"acct-2")


def test_tamper_detected() -> None:
    blob = bytearray(encrypt_blob(b"hello"))
    blob[-1] ^= 0xFF
    with pytest.raises(CryptoError, match="authentication"):
        decrypt_blob(bytes(blob))


def test_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CCE_MASTER_KEY", raising=False)
    with pytest.raises(CryptoError, match="not set"):
        encrypt_blob(b"x")


def test_short_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCE_MASTER_KEY", base64.b64encode(b"short").decode())
    with pytest.raises(CryptoError, match="32 bytes"):
        encrypt_blob(b"x")


def test_non_base64_key_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCE_MASTER_KEY", "not base64!!")
    with pytest.raises(CryptoError, match="base64"):
        encrypt_blob(b"x")


def test_generate_key_is_valid() -> None:
    key = generate_key()
    assert len(base64.b64decode(key)) == 32


def test_wrong_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    blob = encrypt_blob(b"data")
    monkeypatch.setenv("CCE_MASTER_KEY", base64.b64encode(b"0" * 32).decode())
    with pytest.raises(CryptoError):
        decrypt_blob(blob)


def test_magic_prefix_required() -> None:
    with pytest.raises(CryptoError, match="CCE1"):
        decrypt_blob(b"nope-here-padding")


def test_master_key_fixture_is_32_bytes() -> None:
    assert len(base64.b64decode(MASTER_KEY)) == 32
