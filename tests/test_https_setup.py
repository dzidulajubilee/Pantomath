"""
Tests for pantomath/https_setup.py's decision logic. Real end-to-end
verification (actual nginx install, actual self-signed cert, actual
HTTPS proxying, actual WebSocket 101 upgrade through the proxy) was done
directly in a real sandbox with real nginx during development — these
tests instead cover the safety-critical BRANCHES with mocking, since a
CI/test environment can't be assumed to have nginx/systemd/apt
available or safe to actually modify.

Priorities, in order of how bad it would be to get them wrong:
  1. nginx -t failing must ALWAYS abort before any reload/restart —
     never apply a config that hasn't been validated.
  2. Idempotency — re-running must not regenerate a cert (would
     invalidate anything that already trusted it) or duplicate a symlink.
  3. assume_yes correctly bypasses every prompt, and declining a prompt
     correctly leaves things untouched rather than proceeding anyway.
"""
import re
from unittest.mock import MagicMock, patch

import pytest

from pantomath import https_setup


@pytest.fixture(autouse=True)
def _isolated_paths(tmp_path, monkeypatch):
    """Redirects every hardcoded /etc/nginx,/etc/systemd path into a throwaway tmp_path, so tests never touch the real filesystem."""
    monkeypatch.setattr(https_setup, "NGINX_SSL_DIR", tmp_path / "nginx-ssl")
    monkeypatch.setattr(https_setup, "CERT_PATH", tmp_path / "nginx-ssl" / "pantomath.crt")
    monkeypatch.setattr(https_setup, "KEY_PATH", tmp_path / "nginx-ssl" / "pantomath.key")
    sites_enabled = tmp_path / "sites-enabled"
    sites_enabled.mkdir()
    monkeypatch.setattr(https_setup, "SITES_ENABLED_DIR", sites_enabled)
    monkeypatch.setattr(https_setup, "SITE_AVAILABLE", tmp_path / "sites-available" / "pantomath")
    monkeypatch.setattr(https_setup, "SITE_ENABLED", sites_enabled / "pantomath")
    monkeypatch.setattr(https_setup, "DEFAULT_SITE_ENABLED", sites_enabled / "default")
    monkeypatch.setattr(https_setup, "SYSTEMD_OVERRIDE_DIR", tmp_path / "systemd-override")
    monkeypatch.setattr(https_setup, "SYSTEMD_OVERRIDE_FILE", tmp_path / "systemd-override" / "override.conf")
    monkeypatch.setattr(https_setup.os, "geteuid", lambda: 0)  # simulate root by default; individual tests override
    yield


@pytest.fixture(autouse=True)
def _mock_shell_tools(monkeypatch):
    """nginx and openssl are 'installed', and every subprocess call succeeds by default — individual tests override specific calls to test failure paths."""
    monkeypatch.setattr(https_setup.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        if cmd[0] == "openssl":
            # Simulate the real side effect the caller depends on
            # (KEY_PATH.chmod(0o600) runs immediately after) rather than
            # just claiming success with no actual files produced.
            https_setup.CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
            https_setup.CERT_PATH.write_text("FAKE CERT FOR TESTING")
            https_setup.KEY_PATH.write_text("FAKE KEY FOR TESTING")
        return result
    monkeypatch.setattr(https_setup.subprocess, "run", fake_run)
    yield


def test_aborts_immediately_if_not_root(monkeypatch):
    monkeypatch.setattr(https_setup.os, "geteuid", lambda: 1000)
    with pytest.raises(https_setup.SetupAborted, match="root"):
        https_setup.setup_https(assume_yes=True)


def test_nginx_t_failure_aborts_before_any_reload_or_restart(monkeypatch):
    """The single most important safety property: never apply/reload a config that failed validation."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        result = MagicMock()
        if cmd[0] == "openssl":
            https_setup.CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
            https_setup.CERT_PATH.write_text("FAKE CERT FOR TESTING")
            https_setup.KEY_PATH.write_text("FAKE KEY FOR TESTING")
            result.returncode = 0
        elif cmd[:2] == ["nginx", "-t"]:
            result.returncode = 1
            result.stderr = "nginx: [emerg] fake syntax error"
        else:
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
        return result

    monkeypatch.setattr(https_setup.subprocess, "run", fake_run)

    with pytest.raises(https_setup.SetupAborted, match="not reloading"):
        https_setup.setup_https(assume_yes=True)

    reload_or_restart_calls = [c for c in calls if len(c) > 1 and c[0] == "systemctl"]
    assert reload_or_restart_calls == [], (
        f"nginx -t failed but a systemctl call still happened: {reload_or_restart_calls} — "
        "this must never apply a config that failed validation"
    )


def test_existing_certificate_is_not_regenerated():
    https_setup.NGINX_SSL_DIR.mkdir(parents=True, exist_ok=True)
    https_setup.CERT_PATH.write_text("EXISTING CERT — must not be touched")
    https_setup.KEY_PATH.write_text("EXISTING KEY — must not be touched")

    openssl_calls = []
    orig_run = https_setup.subprocess.run

    def tracking_run(cmd, **kwargs):
        if cmd[0] == "openssl":
            openssl_calls.append(cmd)
        return orig_run(cmd, **kwargs)

    with patch.object(https_setup.subprocess, "run", side_effect=tracking_run):
        https_setup.setup_https(assume_yes=True)

    assert openssl_calls == [], "openssl should never be invoked when a certificate already exists"
    assert https_setup.CERT_PATH.read_text() == "EXISTING CERT — must not be touched"


def test_existing_site_symlink_is_left_alone():
    https_setup.SITE_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
    https_setup.SITE_AVAILABLE.write_text("placeholder")
    https_setup.SITE_ENABLED.symlink_to(https_setup.SITE_AVAILABLE)
    original_target = https_setup.SITE_ENABLED.resolve()

    https_setup.setup_https(assume_yes=True)

    assert https_setup.SITE_ENABLED.is_symlink()
    assert https_setup.SITE_ENABLED.resolve() == original_target


def test_config_file_contains_the_correct_port_and_websocket_headers():
    https_setup.setup_https(port=9999, assume_yes=True)
    config = https_setup.SITE_AVAILABLE.read_text()
    assert "proxy_pass http://127.0.0.1:9999;" in config
    assert "proxy_set_header Upgrade $http_upgrade;" in config
    assert "proxy_set_header Connection \"upgrade\";" in config
    assert "return 301 https://$host$request_uri;" in config


def test_config_raises_body_size_limit_above_pantomaths_own_restore_upload_cap():
    """
    Real reported bug: nginx's own default client_max_body_size (1MB) is
    far below MAX_UPLOAD_BYTES in pantomath/database/restore.py (2GB) —
    without an explicit client_max_body_size in the generated config, a
    real database-restore upload gets rejected by nginx ITSELF with its
    own generic HTML 413 error page before the request ever reaches
    Pantomath. The frontend then fails trying to JSON-parse that HTML
    body, surfacing as a confusing "Unexpected token '<'" error that
    looks like an app bug rather than a proxy config gap.
    """
    from pantomath.database.restore import MAX_UPLOAD_BYTES

    https_setup.setup_https(assume_yes=True)
    config = https_setup.SITE_AVAILABLE.read_text()

    match = re.search(r"client_max_body_size\s+(\d+)([kKmMgG]?);", config)
    assert match, "generated nginx config must set client_max_body_size explicitly"
    value, unit = match.groups()
    multiplier = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[unit.lower()]
    configured_bytes = int(value) * multiplier
    assert configured_bytes >= MAX_UPLOAD_BYTES, (
        f"client_max_body_size ({configured_bytes} bytes) must be at least as large as "
        f"Pantomath's own restore-upload cap ({MAX_UPLOAD_BYTES} bytes), or nginx will "
        f"reject valid restore uploads before the app's own (more informative) validation "
        f"ever runs"
    )


def test_default_site_is_moved_out_of_sites_enabled_not_deleted(monkeypatch):
    """
    Real bug: nginx loads EVERY file in sites-enabled/, so renaming the default
    site to default.disabled-by-pantomath inside that folder left it active
    (http:// showed the nginx welcome page). It must leave sites-enabled/
    entirely, into sites-available/, and still not be deleted.
    """
    https_setup.DEFAULT_SITE_ENABLED.write_text("stock nginx default site")
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    https_setup.setup_https(assume_yes=False)

    assert not https_setup.DEFAULT_SITE_ENABLED.exists()
    assert not (https_setup.SITES_ENABLED_DIR / "default.disabled-by-pantomath").exists()
    assert [p.name for p in https_setup.SITES_ENABLED_DIR.iterdir()] == ["pantomath"], \
        "nothing but pantomath may remain in sites-enabled/"
    backup = https_setup.SITE_AVAILABLE.parent / "default.disabled-by-pantomath"
    assert backup.read_text() == "stock nginx default site"


def test_default_site_symlink_keeps_pointing_at_the_real_file(tmp_path):
    """On Ubuntu sites-enabled/default is a relative symlink into sites-available/."""
    https_setup.SITE_AVAILABLE.parent.mkdir(parents=True, exist_ok=True)
    real = https_setup.SITE_AVAILABLE.parent / "default"
    real.write_text("stock nginx default site")
    https_setup.DEFAULT_SITE_ENABLED.symlink_to("../sites-available/default")

    https_setup.setup_https(assume_yes=True)

    assert not https_setup.DEFAULT_SITE_ENABLED.is_symlink()
    moved = https_setup.SITE_AVAILABLE.parent / "default.disabled-by-pantomath"
    assert moved.is_symlink() and moved.resolve() == real.resolve()
    assert real.read_text() == "stock nginx default site"


def test_site_left_in_sites_enabled_by_an_earlier_version_is_repaired():
    """Servers where the old version already ran have default.disabled-by-pantomath inside sites-enabled/."""
    legacy = https_setup.SITES_ENABLED_DIR / "default.disabled-by-pantomath"
    legacy.write_text("stock nginx default site")

    https_setup.setup_https(assume_yes=True)

    assert not legacy.exists()
    assert (https_setup.SITE_AVAILABLE.parent / "default.disabled-by-pantomath").read_text() == "stock nginx default site"


def test_https_is_reported_as_set_up_only_once_the_site_is_enabled():
    assert https_setup.https_is_set_up() is False
    https_setup.setup_https(assume_yes=True)
    assert https_setup.https_is_set_up() is True


def test_default_site_is_left_alone_when_declined(monkeypatch):
    https_setup.DEFAULT_SITE_ENABLED.write_text("stock nginx default site")
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    https_setup.setup_https(assume_yes=False)

    assert https_setup.DEFAULT_SITE_ENABLED.exists(), "declining the prompt must leave the default site untouched"


def test_assume_yes_bypasses_every_prompt(monkeypatch):
    https_setup.DEFAULT_SITE_ENABLED.write_text("stock nginx default site")

    def fail_if_called(prompt):
        raise AssertionError(f"input() must never be called when assume_yes=True, got prompt: {prompt!r}")
    monkeypatch.setattr("builtins.input", fail_if_called)

    https_setup.setup_https(assume_yes=True)  # must not raise


def test_nginx_is_started_not_just_reloaded():
    """
    Regression test for a real bug: 'systemctl reload nginx' only
    affects an ALREADY-RUNNING nginx (it's a SIGHUP to the master
    process) — if nginx had been installed but never actually started
    (confirmed to happen in practice, not just theoretically), a bare
    reload silently does nothing and nginx never ends up listening on
    80/443 at all, even though every file this command wrote was
    correct. Must use 'enable' (so it also survives a reboot) plus
    'reload-or-restart' (correctly starts a stopped service OR reloads
    a running one), not a bare 'reload'.
    """
    systemctl_calls = []
    orig_run = https_setup.subprocess.run

    def tracking_run(cmd, **kwargs):
        if cmd and cmd[0] == "systemctl":
            systemctl_calls.append(tuple(cmd[1:]))
        return orig_run(cmd, **kwargs)

    with patch.object(https_setup.subprocess, "run", side_effect=tracking_run):
        https_setup.setup_https(assume_yes=True)

    assert ("enable", "nginx") in systemctl_calls, f"expected 'systemctl enable nginx', got: {systemctl_calls}"
    assert ("reload-or-restart", "nginx") in systemctl_calls, f"expected 'systemctl reload-or-restart nginx', got: {systemctl_calls}"
    assert ("reload", "nginx") not in systemctl_calls, "a bare 'reload' does nothing if nginx wasn't already running — this is the exact bug being regression-tested"
