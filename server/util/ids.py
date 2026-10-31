"""Delivery credential generators.

Card keys are shown to customers and typed by hand, so they use a
Crockford-like alphabet without lookalike characters (0/O, 1/l/I) and are
grouped 4-4-4.
"""

from __future__ import annotations

import secrets

ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CARD_PREFIX = "cce"
KEY_GROUPS = 4
KEY_GROUP_SIZE = 4


def new_card_key() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(KEY_GROUPS * KEY_GROUP_SIZE))
    groups = [body[i : i + KEY_GROUP_SIZE] for i in range(0, len(body), KEY_GROUP_SIZE)]
    return f"{CARD_PREFIX}-" + "-".join(groups)


def new_token(length: int = 24) -> str:
    return secrets.token_urlsafe(length)
