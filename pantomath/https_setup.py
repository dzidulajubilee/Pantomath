"""
pantomath-admin setup-https — automates the nginx + self-signed HTTPS
reverse-proxy setup that was previously a fully manual, five-step
process (see the nginx setup guide this project shipped separately).

Deliberately a separate, explicitly-invoked command rather than
something the .deb's postinstall runs automatically — see the resume
prompt for the full reasoning, but in short: this modifies system-wide
nginx configuration, which could conflict with an nginx setup already
serving other sites on the same box, and forcing nginx as a hard
dependency of every install would be a much bigger footprint change than
"install a Python app" implies. Debian/Ubuntu only — installs nginx via
apt-get; there's no equivalent here yet for RPM-based systems.

Safety principles followed throughout:
  - Every destructive step asks for confirmation unless --yes is passed.
  - Nothing is ever deleted — the stock default site gets RENAMED
    (default.disabled-by-pantomath), not removed, so it's trivially
    reversible.
  - nginx config is validated (nginx -t) BEFORE any reload — a broken
    config is caught and reported, not silently left half-applied.
  - Idempotent: safe to run more than once. An existing certificate is
    left alone rather than regenerated (regenerating would invalidate
    anything that had already trusted it); an existing site symlink is
    left alone rather than recreated.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys

NGINX_SSL_DIR = pathlib.Path("/etc/nginx/ssl")
CERT_PATH = NGINX_SSL_DIR / "pantomath.crt"
KEY_PATH = NGINX_SSL_DIR / "pantomath.key"
SITES_ENABLED_DIR = pathlib.Path("/etc/nginx/sites-enabled")
SITE_AVAILABLE = pathlib.Path("/etc/nginx/sites-available/pantomath")
SITE_ENABLED = SITES_ENABLED_DIR / "pantomath"
DEFAULT_SITE_ENABLED = SITES_ENABLED_DIR / "default"
SYSTEMD_OVERRIDE_DIR = pathlib.Path("/etc/systemd/system/pantomath.service.d")
SYSTEMD_OVERRIDE_FILE = SYSTEMD_OVERRIDE_DIR / "override.conf"
VENV_PYTHON = "/opt/pantomath/venv/bin/python3"

NGINX_CONFIG_TEMPLATE = """server {{
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}}

server {{
    listen 443 ssl;
    server_name _;

    ssl_certificate     {cert};
    ssl_certificate_key {key};
    ssl_protocols       TLSv1.2 TLSv1.3;

    # nginx's own default (1MB) is far below Pantomath's application-level
    # upload cap (MAX_UPLOAD_BYTES in pantomath/database/restore.py, 2GB) —
    # without raising it here, nginx rejects a database-restore upload with
    # its own generic HTML 413 page before the request ever reaches
    # Pantomath, which is confusing (looks like a JSON-parsing crash on the
    # frontend) and defeats the whole point of that higher application cap.
    client_max_body_size 2100M;

    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Required for the WebSocket connection (live item updates) — see
        # the nginx setup guide for why this is the single most common
        # thing to miss when configuring this by hand.
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }}
}}
"""


class SetupAborted(Exception):
    pass


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    return input(prompt + " [y/N] ").strip().lower() == "y"


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SetupAborted("This must be run as root — it writes to /etc/nginx and /etc/systemd.")


def _run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, **kwargs)


def _try_systemctl(*args: str) -> bool:
    """
    Best-effort systemctl call — returns True on success. Failures are
    reported but never fatal: the config files this command writes are
    correct and complete regardless of whether systemctl itself
    succeeds in THIS environment (e.g. a container without a real
    systemd PID 1), and the admin can always apply them manually
    (`systemctl reload-or-restart nginx` / `systemctl restart pantomath`).
    """
    try:
        _run(["systemctl", *args], capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"  (systemctl {' '.join(args)} failed — you may need to run this manually: {e.stderr.strip() if e.stderr else e})")
        return False
    except FileNotFoundError:
        print(f"  (systemctl not found — run manually on the target system: systemctl {' '.join(args)})")
        return False


def setup_https(port: int = 7373, assume_yes: bool = False) -> None:
    _require_root()

    if shutil.which("nginx") is None:
        if not _confirm("nginx is not installed. Install it now via apt-get?", assume_yes):
            raise SetupAborted("nginx is required for this command.")
        print("Installing nginx...")
        _run(["apt-get", "update"])
        _run(["apt-get", "install", "-y", "nginx"])
    else:
        print("nginx is already installed.")

    if SITES_ENABLED_DIR.exists():
        other_sites = [p for p in SITES_ENABLED_DIR.iterdir() if p.name not in ("default", "pantomath")]
        if other_sites:
            print(f"Found existing nginx site(s) besides the default: {', '.join(sorted(p.name for p in other_sites))}")
            print("Pantomath's config claims all unmatched requests (server_name _), which could")
            print("shadow or conflict with these if they also rely on being the catch-all.")
            if not _confirm("Continue anyway?", assume_yes):
                raise SetupAborted("cancelled — existing sites present.")

    if DEFAULT_SITE_ENABLED.exists() or DEFAULT_SITE_ENABLED.is_symlink():
        if _confirm(
            "The stock nginx default site is enabled and will shadow Pantomath's config\n"
            "for any request that doesn't match a specific server_name. Disable it?",
            assume_yes,
        ):
            backup = SITES_ENABLED_DIR / "default.disabled-by-pantomath"
            DEFAULT_SITE_ENABLED.rename(backup)
            print(f"Moved to {backup} (not deleted — restore by renaming it back if needed).")
        else:
            print("Leaving the default site enabled — you may see the nginx welcome page instead of Pantomath.")

    NGINX_SSL_DIR.mkdir(parents=True, exist_ok=True)
    if CERT_PATH.exists() and KEY_PATH.exists():
        print(f"Certificate already exists at {CERT_PATH} — leaving it in place.")
    else:
        print("Generating a self-signed certificate (825 day validity)...")
        _run([
            "openssl", "req", "-x509", "-nodes", "-days", "825", "-newkey", "rsa:2048",
            "-keyout", str(KEY_PATH), "-out", str(CERT_PATH), "-subj", "/CN=pantomath.local",
        ], capture_output=True)
        KEY_PATH.chmod(0o600)
        print(f"Wrote {CERT_PATH} and {KEY_PATH}.")

    config = NGINX_CONFIG_TEMPLATE.format(cert=CERT_PATH, key=KEY_PATH, port=port)
    SITE_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
    SITE_AVAILABLE.write_text(config)
    print(f"Wrote {SITE_AVAILABLE}")

    if not SITE_ENABLED.exists() and not SITE_ENABLED.is_symlink():
        SITE_ENABLED.symlink_to(SITE_AVAILABLE)
        print(f"Enabled: {SITE_ENABLED} -> {SITE_AVAILABLE}")
    else:
        print(f"{SITE_ENABLED} already exists — leaving it as-is.")

    result = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if result.returncode != 0:
        print("nginx config validation FAILED:")
        print(result.stderr)
        raise SetupAborted("not reloading nginx — fix the error above and re-run.")
    print("nginx config OK (validated via nginx -t).")

    locked_down = False
    if _confirm(f"Restrict pantomath to 127.0.0.1:{port} (recommended — nginx becomes the only entry point)?", assume_yes):
        SYSTEMD_OVERRIDE_DIR.mkdir(parents=True, exist_ok=True)
        SYSTEMD_OVERRIDE_FILE.write_text(
            "[Service]\n"
            "Environment=\n"
            "ExecStart=\n"
            f"ExecStart={VENV_PYTHON} -m uvicorn pantomath.app:app --host 127.0.0.1 --port {port}\n"
        )
        print(f"Wrote systemd override: {SYSTEMD_OVERRIDE_FILE}")
        if _try_systemctl("daemon-reload") and _try_systemctl("restart", "pantomath"):
            print("Restarted pantomath, now bound to 127.0.0.1 only.")
            locked_down = True
    else:
        print("Skipped — pantomath remains reachable directly on its own port too, not just through nginx.")

    # reload alone only affects an ALREADY-running nginx (SIGHUP to the
    # master process) — if nginx was installed but never actually
    # started (can happen depending on the install path, or if it had
    # been stopped for any reason beforehand), reload silently does
    # nothing and nginx never ends up listening on 80/443 at all.
    # reload-or-restart correctly handles both cases: starts it if it's
    # not running, reloads it if it is. enable ensures it also comes up
    # on the next boot (idempotent — safe even if already enabled).
    _try_systemctl("enable", "nginx")
    _try_systemctl("reload-or-restart", "nginx")

    print("\nDone.")
    print("Visit https://<this-server>/ — your browser will warn about the self-signed")
    print("certificate; that's expected (click through, or use curl -k to skip verification).")
    if not locked_down:
        print(f"Note: pantomath is still also directly reachable on port {port} — nginx isn't the only entry point yet.")


def build_arg_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "setup-https",
        help="Install and configure nginx as an HTTPS reverse proxy in front of Pantomath, with a self-signed certificate.",
    )
    p.add_argument("--port", type=int, default=7373, help="Port Pantomath is running on (default: 7373).")
    p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompts.")
