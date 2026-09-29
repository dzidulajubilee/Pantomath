"""
Signing in to Pantomath (0.8.0).

Everything except the page shell and the sign-in endpoints needs a
session: once Pantomath knows what an organisation runs (Our stack) and
what is being exploited, the dashboard is a map of where that
organisation is exposed, so it can't be readable by anyone on the network.

Two passwords, two roles:
  - the team password lets people view (role "team");
  - the Settings password (settings_auth.py) also signs people in (role
    "admin") and still separately unlocks Settings and Sources.
The team password can't be the same as the Settings password, so viewers
can never change settings.

Sessions are stored in the database (only a SHA-256 of the token, which is
256 random bits, so a fast hash is enough), so they survive a restart —
the wall screen shouldn't need signing in again after an upgrade.
"Remember this device" keeps a session for 90 days of inactivity; without
it a session ends after 12 idle hours or when the browser closes. API keys
are the same kind of record, sent as `Authorization: Bearer ...`.

PANTOMATH_OPEN_DASHBOARD=1 turns sign-in off entirely (for installs behind
an authenticating reverse proxy, and for the test suite).
"""
import hashlib
import hmac
import os
import re
import secrets
import time
import uuid

from pantomath.alerts.webhook_keys import hash_key, new_salt
from pantomath.auth import settings_auth

COOKIE_NAME = "pantomath_session"
REMEMBER_SECONDS = 90 * 86400
SESSION_SECONDS = 12 * 3600
TOUCH_EVERY = 300          # write last_seen at most every 5 minutes per session
CACHE_SECONDS = 30         # validated sessions are cached briefly to spare the database
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60
MIN_PASSWORD_LENGTH = 8
API_KEY_PREFIX = "pmk_"

_TEAM_HASH, _TEAM_SALT = "team_password_hash", "team_password_salt"
_failures: dict[str, list[float]] = {}                 # ip -> [failures, locked_until]
_cache: dict[str, tuple[dict, float]] = {}              # token hash -> (session, cached until)


def open_dashboard() -> bool:
    return os.environ.get("PANTOMATH_OPEN_DASHBOARD", "") == "1"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def token_from(cookie: str | None, authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return cookie or None


# ------------------------------------------------------------------ passwords

async def _get(db, key: str) -> str:
    cur = await db.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = await cur.fetchone()
    return row["value"] if row and row["value"] else ""


async def _set(db, key: str, value: str) -> None:
    await db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value)
    )


async def team_password_set(db) -> bool:
    return bool(await _get(db, _TEAM_HASH))


async def _matches_team_password(db, password: str) -> bool:
    stored, salt = await _get(db, _TEAM_HASH), await _get(db, _TEAM_SALT)
    if not stored or not salt:
        return False
    return hmac.compare_digest(stored, hash_key(password or "", bytes.fromhex(salt)))


async def match_password(db, password: str) -> str | None:
    """'team', 'admin' or None. Doesn't touch the Settings password's own lockout counter."""
    if await _matches_team_password(db, password):
        return "team"
    if await settings_auth.password_matches(db, password):
        return "admin"
    return None


async def set_team_password(db, password: str) -> None:
    """Sets or changes the team password; everyone signed in with the old one is signed out."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Use at least {MIN_PASSWORD_LENGTH} characters.")
    if await settings_auth.password_matches(db, password):
        raise ValueError("Use a different password from the Settings password, so team members can't change settings.")
    salt = new_salt()
    await _set(db, _TEAM_HASH, hash_key(password, salt))
    await _set(db, _TEAM_SALT, salt.hex())
    await db.execute("DELETE FROM sessions WHERE role = 'team'")
    await db.commit()
    _cache.clear()


async def clear_team_password(db) -> None:
    await _set(db, _TEAM_HASH, "")
    await _set(db, _TEAM_SALT, "")
    await db.execute("DELETE FROM sessions WHERE role = 'team'")
    await db.commit()
    _cache.clear()


# ------------------------------------------------------------ attempt limits
# Per client address, in memory: one person mistyping can't lock everyone
# else out, which a single global counter would allow.

def check_rate(ip: str) -> tuple[bool, int]:
    failures, locked_until = _failures.get(ip, [0, 0.0])
    wait = int(locked_until - time.time()) + 1
    return (False, wait) if locked_until > time.time() else (True, 0)


def record_failure(ip: str) -> None:
    failures, _ = _failures.get(ip, [0, 0.0])
    failures += 1
    _failures[ip] = [0, time.time() + LOCKOUT_SECONDS] if failures >= MAX_FAILURES else [failures, 0.0]


def record_success(ip: str) -> None:
    _failures.pop(ip, None)


# ------------------------------------------------------------------ sessions

def describe_user_agent(user_agent: str) -> str:
    """"Chrome on Windows" and the like — only to tell devices apart in Settings."""
    ua = user_agent or ""
    browser = next((name for pattern, name in (
        (r"Edg/", "Edge"), (r"OPR/|Opera", "Opera"), (r"Firefox/", "Firefox"),
        (r"Chrome/|CriOS/", "Chrome"), (r"Safari/", "Safari"),
    ) if re.search(pattern, ua)), "Browser")
    system = next((name for pattern, name in (
        (r"iPhone", "iPhone"), (r"iPad", "iPad"), (r"Android", "Android"), (r"Windows", "Windows"),
        (r"Mac OS X|Macintosh", "macOS"), (r"CrOS", "ChromeOS"), (r"Linux", "Linux"),
    ) if re.search(pattern, ua)), "")
    return f"{browser} on {system}" if system else browser


async def create_session(db, role: str, remember: bool, ip: str, user_agent: str,
                         kind: str = "browser", label: str = "") -> tuple[str, str]:
    token = (API_KEY_PREFIX if kind == "api" else "") + secrets.token_urlsafe(32)
    session_id = str(uuid.uuid4())
    now = time.time()
    expires = 0 if kind == "api" else now + (REMEMBER_SECONDS if remember else SESSION_SECONDS)
    await db.execute(
        """INSERT INTO sessions (id, token_hash, kind, role, label, remember, created_at, last_seen, expires_at, ip)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (session_id, hash_token(token), kind, role, label or describe_user_agent(user_agent),
         int(remember), now, now, expires, ip),
    )
    await db.commit()
    return token, session_id


async def validate(db, token: str | None) -> dict | None:
    if not token:
        return None
    digest = hash_token(token)
    now = time.time()
    cached = _cache.get(digest)
    if cached and cached[1] > now and (not cached[0]["expires_at"] or cached[0]["expires_at"] > now):
        return cached[0]
    cur = await db.execute("SELECT * FROM sessions WHERE token_hash = ?", (digest,))
    row = await cur.fetchone()
    if not row:
        return None
    session = dict(row)
    if session["expires_at"] and session["expires_at"] < now:
        await db.execute("DELETE FROM sessions WHERE id = ?", (session["id"],))
        await db.commit()
        return None
    if now - (session["last_seen"] or 0) > TOUCH_EVERY:
        expires = 0 if session["kind"] == "api" else now + (REMEMBER_SECONDS if session["remember"] else SESSION_SECONDS)
        await db.execute("UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id = ?", (now, expires, session["id"]))
        await db.commit()
        session.update(last_seen=now, expires_at=expires)
    _cache[digest] = (session, now + CACHE_SECONDS)
    return session


async def revoke(db, session_id: str) -> bool:
    cur = await db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    await db.commit()
    _cache.clear()
    return cur.rowcount > 0


async def revoke_others(db, keep_id: str | None) -> int:
    cur = await db.execute("DELETE FROM sessions WHERE kind = 'browser' AND id != ?", (keep_id or "",))
    await db.commit()
    _cache.clear()
    return cur.rowcount


async def list_sessions(db, current_hash: str | None = None) -> list[dict]:
    await db.execute("DELETE FROM sessions WHERE expires_at != 0 AND expires_at < ?", (time.time(),))
    await db.commit()
    cur = await db.execute("SELECT * FROM sessions ORDER BY last_seen DESC")
    rows = []
    for row in await cur.fetchall():
        item = dict(row)
        item["current"] = bool(current_hash) and item.pop("token_hash") == current_hash
        item.pop("token_hash", None)
        rows.append(item)
    return rows
