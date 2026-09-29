"""
The first-run setup code (0.8.1).

Until the Settings password exists, whoever opens Pantomath first could
create it and become the administrator. The setup code closes that window,
the same way Jenkins' "initial admin password" does: the installer (or the
service, on first start) creates a one-time code, and the Welcome screen
won't create the Settings password without it.

  - Only a salted PBKDF2 hash goes in the database; the plain code is in a
    file next to the database (`setup-code`, mode 0600, readable only by the
    service user and root), so an administrator on the server can read it:
    `sudo pantomath-admin setup-code`. It's never written to the logs.
  - It's deleted as soon as the Settings password is created.
  - Wrong codes count toward the sign-in page's per-address attempt limit.
  - 12 characters from a 31-letter alphabet without look-alikes (0/O, 1/I/L):
    about 59 bits, far beyond guessing within the attempt limit.
"""
import hmac
import os
import re
import secrets

from pantomath.alerts.webhook_keys import hash_key, new_salt
from pantomath.auth import settings_auth

_HASH, _SALT = "setup_code_hash", "setup_code_salt"
CODE_LENGTH = 12


def code_path() -> str:
    from pantomath.database.sqlite import DB_PATH

    return os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "setup-code")


def normalize(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def _format(raw: str) -> str:
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def read_code() -> str | None:
    try:
        with open(code_path()) as f:
            return f.read().strip() or None
    except OSError:
        return None


async def pending(db) -> bool:
    return not await settings_auth.is_password_configured(db)


async def ensure_setup_code(db) -> str | None:
    """
    Makes sure an install without a Settings password has a setup code, and
    that a configured one has none. Returns the current code while setup is
    pending (creating it if needed), otherwise None.
    """
    if not await pending(db):
        await discard(db)
        return None
    existing = read_code()
    if existing and await settings_auth._get(db, _HASH):
        return existing
    raw = "".join(secrets.choice(settings_auth.RECOVERY_CODE_ALPHABET) for _ in range(CODE_LENGTH))
    salt = new_salt()
    await settings_auth._set(db, _HASH, hash_key(raw, salt))
    await settings_auth._set(db, _SALT, salt.hex())
    await db.commit()
    path, tmp = code_path(), code_path() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(_format(raw) + "\n")
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return _format(raw)


async def verify(db, code: str) -> bool:
    stored, salt = await settings_auth._get(db, _HASH), await settings_auth._get(db, _SALT)
    if not stored or not salt:
        return False
    return hmac.compare_digest(stored, hash_key(normalize(code), bytes.fromhex(salt)))


async def discard(db) -> None:
    if await settings_auth._get(db, _HASH):
        await settings_auth._set(db, _HASH, "")
        await settings_auth._set(db, _SALT, "")
        await db.commit()
    try:
        os.remove(code_path())
    except FileNotFoundError:
        pass
