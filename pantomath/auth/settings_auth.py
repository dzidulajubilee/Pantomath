"""
The Settings password: it unlocks Settings and Sources (a short-lived,
in-memory Settings token, sent as X-Settings-Token), and since 0.8.0 it
also signs people in to the dashboard (see sign_in.py, which checks it
through password_matches() so sign-in guesses don't trip this module's own
lockout). Stored as a salted PBKDF2 hash, with a one-time recovery code
(also hashed) that can reset it from the sign-in page or the Settings
unlock prompt. First-run creation is protected by the setup code
(setup_code.py); `pantomath-admin reset-settings-password` resets it on the
server.
"""
import hashlib
import hmac
import secrets
import string
import time

from pantomath.alerts.webhook_keys import hash_key, new_salt

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
SESSION_LIFETIME_SECONDS = 3600  # 1 hour
MIN_PASSWORD_LENGTH = 8

# Excludes visually-ambiguous characters (0/O, 1/I/L) since a recovery
# code is meant to be hand-transcribed onto paper or into a password
# manager, not just copy-pasted — easy to misread costs someone their
# only way back in months later.
RECOVERY_CODE_ALPHABET = "".join(c for c in string.ascii_uppercase + string.digits if c not in "0O1IL")

_KEYS = {
    "password_hash": "settings_auth_password_hash",
    "password_salt": "settings_auth_password_salt",
    "recovery_hash": "settings_auth_recovery_hash",
    "recovery_salt": "settings_auth_recovery_salt",
    "fail_count": "settings_auth_fail_count",
    "locked_until": "settings_auth_locked_until",
}

# token -> expiry (epoch seconds). Module-level and in-memory by design — see docstring.
_sessions: dict[str, float] = {}


def _generate_recovery_code() -> str:
    groups = ["".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)


def _normalize_recovery_code(code: str) -> str:
    return (code or "").strip().upper().replace(" ", "")


async def _get(db, key: str) -> str | None:
    cur = await db.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = await cur.fetchone()
    return row["value"] if row else None


async def _set(db, key: str, value: str) -> None:
    await db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


async def is_password_configured(db) -> bool:
    return bool(await _get(db, _KEYS["password_hash"]))


async def setup_password(db, password: str) -> str:
    """
    First-time setup, or a full reset (via the recovery flow or the CLI
    tool). Returns the plaintext recovery code — the ONLY moment it's
    ever available; only its hash gets persisted.
    """
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    pw_salt = new_salt()
    recovery_code = _generate_recovery_code()
    recovery_salt = new_salt()

    await _set(db, _KEYS["password_hash"], hash_key(password, pw_salt))
    await _set(db, _KEYS["password_salt"], pw_salt.hex())
    await _set(db, _KEYS["recovery_hash"], hash_key(recovery_code, recovery_salt))
    await _set(db, _KEYS["recovery_salt"], recovery_salt.hex())
    await _set(db, _KEYS["fail_count"], "0")
    await _set(db, _KEYS["locked_until"], "0")
    await db.commit()
    return recovery_code


async def clear_password(db) -> None:
    """Used by the CLI reset tool — drops back into first-run setup mode. Does not touch anything else."""
    for key in _KEYS.values():
        await _set(db, key, "")
    await db.commit()
    _sessions.clear()


async def _check_lockout(db) -> tuple[bool, str]:
    locked_until = float(await _get(db, _KEYS["locked_until"]) or 0)
    now = time.time()
    if now < locked_until:
        return False, f"Too many attempts — try again in {int(locked_until - now)}s"
    return True, ""


async def _record_attempt(db, ok: bool) -> None:
    if ok:
        await _set(db, _KEYS["fail_count"], "0")
        await _set(db, _KEYS["locked_until"], "0")
        await db.commit()
        return
    fail_count = int(await _get(db, _KEYS["fail_count"]) or 0) + 1
    if fail_count >= MAX_ATTEMPTS:
        await _set(db, _KEYS["locked_until"], str(time.time() + LOCKOUT_SECONDS))
        await _set(db, _KEYS["fail_count"], "0")
    else:
        await _set(db, _KEYS["fail_count"], str(fail_count))
    await db.commit()


async def verify_password(db, password: str) -> tuple[bool, str]:
    """Returns (ok, error_message). Same lockout pattern as webhook keys, persisted so it survives a restart."""
    ok, err = await _check_lockout(db)
    if not ok:
        return False, err

    pw_hash = await _get(db, _KEYS["password_hash"])
    pw_salt_hex = await _get(db, _KEYS["password_salt"])
    if not pw_hash or not pw_salt_hex:
        return False, "No password has been set up yet."

    salt = bytes.fromhex(pw_salt_hex)
    match = hmac.compare_digest(pw_hash, hash_key(password or "", salt))
    await _record_attempt(db, match)
    return (True, "") if match else (False, "Incorrect password")


async def password_matches(db, password: str) -> bool:
    """
    True if `password` is the Settings password, WITHOUT recording an
    attempt: the dashboard sign-in (sign_in.py) checks it as a fallback and
    has its own per-address attempt limit, so wrong guesses there can't lock
    the admin out of Settings.
    """
    pw_hash = await _get(db, _KEYS["password_hash"])
    pw_salt_hex = await _get(db, _KEYS["password_salt"])
    if not pw_hash or not pw_salt_hex:
        return False
    return hmac.compare_digest(pw_hash, hash_key(password or "", bytes.fromhex(pw_salt_hex)))


async def reset_via_recovery_code(db, code: str, new_password: str) -> tuple[bool, str, str | None]:
    """
    Verifies the recovery code and, if valid, immediately replaces both
    the password AND the recovery code — the old code is single-use, so
    even if it somehow leaked alongside this reset, it's already dead.
    Returns (ok, error_message, new_recovery_code_or_None).
    """
    ok, err = await _check_lockout(db)
    if not ok:
        return False, err, None

    recovery_hash = await _get(db, _KEYS["recovery_hash"])
    recovery_salt_hex = await _get(db, _KEYS["recovery_salt"])
    if not recovery_hash or not recovery_salt_hex:
        return False, "No recovery code has been set up.", None

    salt = bytes.fromhex(recovery_salt_hex)
    match = hmac.compare_digest(recovery_hash, hash_key(_normalize_recovery_code(code), salt))
    await _record_attempt(db, match)
    if not match:
        return False, "Incorrect recovery code", None

    if len(new_password or "") < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", None

    new_recovery = await setup_password(db, new_password)
    return True, "", new_recovery


def _prune_expired_sessions() -> None:
    now = time.time()
    for t in [t for t, exp in _sessions.items() if exp < now]:
        _sessions.pop(t, None)


def create_session() -> str:
    _prune_expired_sessions()
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + SESSION_LIFETIME_SECONDS
    return token


def validate_session(token: str | None) -> bool:
    if not token:
        return False
    _prune_expired_sessions()
    expiry = _sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        _sessions.pop(token, None)
        return False
    return True


def invalidate_session(token: str | None) -> None:
    if token:
        _sessions.pop(token, None)
