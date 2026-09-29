"""
Local admin CLI, installed as `pantomath-admin` (see pyproject.toml's
[project.scripts]). Everything here needs shell access to the server —
there's deliberately no network-facing "forgot everything" path.

  setup-code               show the one-time code the first-run screen asks for
  reset-settings-password  set a new Settings password here, in the terminal
                           (--clear: remove it and go back to first-run setup)
  sign-out-everyone        end every browser sign-in (--api-keys: revoke keys too)
  setup-https              put nginx with HTTPS in front of Pantomath

Commands that touch the database, when run as root, continue as the owner of
the database's folder (the `pantomath` service user): the database runs in
WAL mode, and a -wal/-shm file created by root would stop the service from
writing to its own database.
"""
import argparse
import asyncio
import getpass
import os
import socket
import sys


def _as_service_user() -> None:
    """
    When run as root, continue as the owner of the database's folder (the
    `pantomath` service user on a packaged install), so SQLite's WAL files
    are never created as root. If the folder belongs to root, stay root.
    """
    if os.geteuid() != 0:
        return
    from pantomath.database.sqlite import DB_PATH

    try:
        owner = os.stat(os.path.dirname(os.path.abspath(DB_PATH)))
    except OSError:
        return
    if owner.st_uid == 0:
        return
    os.setgroups([])
    os.setgid(owner.st_gid)
    os.setuid(owner.st_uid)


def _dashboard_url() -> str:
    return f"http://{socket.gethostname()}:{os.environ.get('PANTOMATH_PORT', '7373')}"


async def show_setup_code(bare: bool = False) -> int:
    from pantomath.auth import setup_code
    from pantomath.database.sqlite import get_db, init_db

    await init_db()
    db = await get_db()
    try:
        code = await setup_code.ensure_setup_code(db)
    finally:
        await db.close()
    if bare:
        if code:
            print(code)
        return 0
    if not code:
        print("Pantomath is already set up, so there is no setup code.")
        print("Lost the Settings password? Run: sudo pantomath-admin reset-settings-password")
        return 0
    print(f"Setup code: {code}")
    print(f"Open {_dashboard_url()} and enter it on the Welcome screen to create the Settings password.")
    return 0


def _ask_new_password() -> str:
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")  # scripted use: one line on stdin
    first = getpass.getpass("New Settings password (at least 8 characters): ")
    if first != getpass.getpass("Type it again: "):
        raise ValueError("The two passwords don't match.")
    return first


async def reset_settings_password(new_password: str | None, clear: bool = False) -> int:
    """
    Sets the new Settings password directly (the default), so a reset never
    reopens the first-run screen to whoever reaches it first. Devices signed
    in with the old Settings password are signed out. --clear goes back to
    first-run setup instead: everyone is signed out and a new setup code is
    needed to set Pantomath up again.
    """
    from pantomath.auth import settings_auth, setup_code, sign_in
    from pantomath.database.sqlite import get_db, init_db

    await init_db()
    db = await get_db()
    try:
        if clear:
            # Back to first run: everyone is signed out, so the only way in is
            # the Welcome screen, which needs the new setup code.
            await settings_auth.clear_password(db)
            await db.execute("DELETE FROM sessions WHERE kind = 'browser'")
            await db.commit()
            code = await setup_code.ensure_setup_code(db)
            print("Settings password removed and everyone signed out (API keys still work).")
            print(f"Setup code: {code}")
            print(f"Open {_dashboard_url()} and enter it on the Welcome screen to create a new Settings password.")
            return 0
        if len(new_password or "") < settings_auth.MIN_PASSWORD_LENGTH:
            print(f"Use at least {settings_auth.MIN_PASSWORD_LENGTH} characters.")
            return 1
        if await sign_in._matches_team_password(db, new_password):
            print("Use a different password from the team password, so team members can't change settings.")
            return 1
        recovery_code = await settings_auth.setup_password(db, new_password)
        await setup_code.discard(db)
        removed = await db.execute("DELETE FROM sessions WHERE role = 'admin'")
        await db.commit()
    finally:
        await db.close()
    print("Settings password changed.")
    if removed.rowcount:
        print(f"Signed out {removed.rowcount} device(s) that used the old Settings password.")
    print(f"New recovery code (shown only now, keep it safe): {recovery_code}")
    print("Settings pages already unlocked in a browser stay unlocked for up to an hour.")
    return 0


async def sign_out_everyone(include_api_keys: bool) -> int:
    from pantomath.database.sqlite import get_db, init_db

    await init_db()
    db = await get_db()
    try:
        browsers = await db.execute("DELETE FROM sessions WHERE kind = 'browser'")
        keys = await db.execute("DELETE FROM sessions WHERE kind = 'api'") if include_api_keys else None
        await db.commit()
    finally:
        await db.close()
    print(f"Signed out {browsers.rowcount} device(s).")
    if keys is not None:
        print(f"Revoked {keys.rowcount} API key(s).")
    print("A running Pantomath notices within 30 seconds; no restart needed.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="pantomath-admin", description="Local admin commands for Pantomath.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    code = subparsers.add_parser("setup-code", help="Show the one-time setup code for the first-run screen.")
    code.add_argument("--bare", action="store_true", help="Print only the code, or nothing if already set up (for scripts).")
    reset = subparsers.add_parser("reset-settings-password", help="Set a new Settings password here, in the terminal.")
    reset.add_argument("--clear", action="store_true", help="Remove it instead, and go back to first-run setup (with a new setup code).")
    signout = subparsers.add_parser("sign-out-everyone", help="End every browser sign-in.")
    signout.add_argument("--api-keys", action="store_true", help="Revoke API keys too.")

    from pantomath.https_setup import SetupAborted, build_arg_parser, setup_https
    build_arg_parser(subparsers)

    args = parser.parse_args()
    if args.command == "setup-https":
        try:
            setup_https(port=args.port, assume_yes=args.yes)
        except SetupAborted as e:
            print(f"Aborted: {e}")
            sys.exit(1)
        return

    _as_service_user()
    if args.command == "setup-code":
        sys.exit(asyncio.run(show_setup_code(bare=args.bare)))
    if args.command == "reset-settings-password":
        if args.clear:
            if input("Remove the Settings password and go back to first-run setup? [y/N] ").strip().lower() != "y":
                print("Cancelled.")
                sys.exit(0)
            sys.exit(asyncio.run(reset_settings_password(None, clear=True)))
        try:
            password = _ask_new_password()
        except (ValueError, KeyboardInterrupt, EOFError) as e:
            print(str(e) or "Cancelled.")
            sys.exit(1)
        sys.exit(asyncio.run(reset_settings_password(password)))
    if args.command == "sign-out-everyone":
        sys.exit(asyncio.run(sign_out_everyone(args.api_keys)))


if __name__ == "__main__":
    main()
