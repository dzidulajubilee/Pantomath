"""
Optional per-webhook protection keys.

A webhook can opt into being "protected": a key (chosen by whoever sets it
up, like a passphrase) gates viewing its real URL and editing it. The key
is never stored in plaintext — only a salted PBKDF2 hash, using stdlib
hashlib rather than adding a bcrypt/argon2 dependency (same "stdlib over a
new dependency" preference as pantomath/alerts/dispatcher.py's urllib use).

There is deliberately no recovery path. If the key is lost, the only way
back in is to delete the webhook and recreate it — that's a design choice,
not a missing feature, so the UI copy around this should say so plainly.
"""
import hashlib
import hmac
import os
import time
import urllib.parse

PBKDF2_ITERATIONS = 200_000
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60


def new_salt() -> bytes:
    return os.urandom(16)


def hash_key(key: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, PBKDF2_ITERATIONS).hex()


def verify_key(row: dict, candidate: str) -> bool:
    """Constant-time comparison against a webhook row's stored hash+salt."""
    if not row.get("key_hash") or not row.get("key_salt"):
        return False
    salt = bytes.fromhex(row["key_salt"])
    return hmac.compare_digest(row["key_hash"], hash_key(candidate, salt))


async def check_and_consume_attempt(db, row: dict, candidate: str) -> tuple[bool, str]:
    """
    Verifies `candidate` against `row`'s stored key, applying a short
    lockout after repeated failures so the key can't be brute-forced by
    hammering the endpoint. Persists updated attempt-tracking columns via
    `db` as a side effect (caller owns commit/close of the connection
    beyond what's needed here). Returns (ok, error_message).
    """
    now = time.time()
    locked_until = row.get("key_locked_until") or 0
    if now < locked_until:
        return False, f"Too many attempts — try again in {int(locked_until - now)}s"

    if verify_key(row, candidate):
        await db.execute(
            "UPDATE webhooks SET key_fail_count = 0, key_locked_until = 0 WHERE id = ?",
            (row["id"],),
        )
        await db.commit()
        return True, ""

    fail_count = (row.get("key_fail_count") or 0) + 1
    if fail_count >= MAX_ATTEMPTS:
        await db.execute(
            "UPDATE webhooks SET key_fail_count = 0, key_locked_until = ? WHERE id = ?",
            (now + LOCKOUT_SECONDS, row["id"]),
        )
    else:
        await db.execute(
            "UPDATE webhooks SET key_fail_count = ? WHERE id = ?",
            (fail_count, row["id"]),
        )
    await db.commit()
    return False, "Incorrect key"


def mask_url(url: str) -> str:
    """Shows enough of a webhook URL to identify the destination service
    (scheme + host) while hiding the path, which for Slack/Discord/Mattermost
    style webhooks is itself the bearer secret."""
    tail = url[-4:] if len(url) >= 4 else url
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/\u2022\u2022\u2022\u00b7\u00b7\u00b7{tail}"
    return f"\u2022\u2022\u2022\u00b7\u00b7\u00b7{tail}"
