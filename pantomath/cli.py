"""
Local admin CLI, installed as `pantomath-admin` (see pyproject.toml's
[project.scripts]). Currently one command: resetting the Settings/Sources
password if both it and the one-time recovery code have been lost.

This deliberately requires running directly on the server — there's no
network-facing "forgot everything" endpoint, and there shouldn't be one.
Whoever can run this already has shell access to the box, which means
they could accomplish the same thing by editing the SQLite file directly
(`sqlite3 $PANTOMATH_DB "DELETE FROM settings WHERE key LIKE 'settings_auth_%'"`)
regardless of whether this command exists. This is just the safe,
official, less error-prone version of that.
"""
import argparse
import asyncio
import sys


async def _reset_settings_password() -> None:
    from pantomath.auth import settings_auth
    from pantomath.database.sqlite import get_db, init_db

    await init_db()
    db = await get_db()
    was_configured = await settings_auth.is_password_configured(db)
    await settings_auth.clear_password(db)
    await db.close()

    if was_configured:
        print("Settings/Sources password cleared.")
    else:
        print("No Settings/Sources password was configured — nothing to clear.")
    print("The app will prompt to set up a NEW password the next time Settings or Sources is opened.")
    print("If pantomath is currently running, no restart is required — sessions are re-checked per request.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="pantomath-admin", description="Local admin utilities for Pantomath.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "reset-settings-password",
        help="Clear the Settings/Sources password (use if both the password and the recovery code are lost).",
    )

    from pantomath.https_setup import SetupAborted, build_arg_parser, setup_https
    build_arg_parser(subparsers)

    args = parser.parse_args()
    if args.command == "reset-settings-password":
        confirm = input(
            "This clears the current Settings/Sources password and recovery code, and does not\n"
            "touch anything else (items, sources, webhooks, retention policy, etc. are untouched).\n"
            "Continue? [y/N] "
        )
        if confirm.strip().lower() != "y":
            print("Cancelled.")
            sys.exit(0)
        asyncio.run(_reset_settings_password())
    elif args.command == "setup-https":
        try:
            setup_https(port=args.port, assume_yes=args.yes)
        except SetupAborted as e:
            print(f"Aborted: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
