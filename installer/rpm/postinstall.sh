#!/bin/sh
set -e

# Dedicated system user
if ! id -u pantomath >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin pantomath
fi

# Data directory (SQLite lives here, separate from the app code)
mkdir -p /var/lib/pantomath
chown -R pantomath:pantomath /var/lib/pantomath

# Isolated Python venv
if [ ! -d /opt/pantomath/venv ]; then
    python3 -m venv /opt/pantomath/venv
fi

# setuptools reuses /opt/pantomath/build between installs, so a module deleted
# in a newer release would otherwise stay in the copy pantomath-admin runs.
# Clear its leftovers before building and again afterwards.
clean_build() {
    rm -rf /opt/pantomath/build /opt/pantomath/*.egg-info
}
clean_build

# Install the dependencies, then the app itself with --force-reinstall: pip
# skips an app whose version number is unchanged (a rebuilt package, a
# hotfix), which would leave the previous code in place.
pip_install() {
    /opt/pantomath/venv/bin/pip install --quiet "$@"
}
install_offline() {
    pip_install --no-index --find-links=/opt/pantomath/wheelhouse /opt/pantomath \
        && pip_install --no-index --find-links=/opt/pantomath/wheelhouse --no-deps --force-reinstall /opt/pantomath
}
install_online() {
    pip_install --upgrade pip \
        && pip_install /opt/pantomath \
        && pip_install --no-deps --force-reinstall /opt/pantomath
}

# Prefer the wheelhouse bundled in the package — this box may have no route
# to pypi.org (air-gapped / restricted-egress hosts like IDS sensors are a
# real deployment target for this tool), so don't require internet access
# for something as basic as installing the app. Fall back to a normal
# networked pip install if the wheelhouse wasn't shipped, or if it has no
# wheels for this Python (e.g. a Python newer than the one the package was
# built against).
if [ -d /opt/pantomath/wheelhouse ] && [ -n "$(ls -A /opt/pantomath/wheelhouse 2>/dev/null)" ] && install_offline; then
    :
else
    echo "Offline install from the bundled wheelhouse was not possible; installing from the Python package index instead." >&2
    clean_build
    install_online
fi
clean_build

# Only the data directory belongs to the service user. The code stays owned
# by root: root runs it whenever an admin uses `sudo pantomath-admin`, so the
# service account must not be able to rewrite it.
chown -R root:root /opt/pantomath

# The admin command on the PATH, as in the Debian package (setup-code,
# reset-settings-password, sign-out-everyone, setup-https).
ln -sf /opt/pantomath/venv/bin/pantomath-admin /usr/local/bin/pantomath-admin

HOST=$(hostname -f 2>/dev/null || hostname)
if [ -e /etc/nginx/sites-enabled/pantomath ]; then
    DASHBOARD_URL="https://$HOST"
else
    DASHBOARD_URL="http://$HOST:7373"
fi

systemctl daemon-reload
systemctl enable pantomath.service
systemctl stop pantomath.service 2>/dev/null || true
# First run (0.8.1): create the one-time setup code before the service
# starts, so it can be shown below. Prints nothing on an install that
# already has a Settings password. Run as the service user so the database
# files stay owned by it.
SETUP_CODE=$(runuser -u pantomath -- env PANTOMATH_DB=/var/lib/pantomath/pantomath.db \
    /opt/pantomath/venv/bin/pantomath-admin setup-code --bare 2>/dev/null || true)
systemctl start pantomath.service

echo ""
echo "Pantomath installed."
echo "Dashboard: $DASHBOARD_URL"
echo "No sources are pre-loaded — add your feeds from the UI."
echo "Data: /var/lib/pantomath/pantomath.db"
echo "Logs: journalctl -u pantomath -f"
echo "Admin commands: pantomath-admin --help"
echo ""
if [ -n "$SETUP_CODE" ]; then
    HOST=$(hostname -f 2>/dev/null || hostname)
    echo "==================== First-time setup ===================="
    echo "  Open $DASHBOARD_URL and enter this setup code on the"
    echo "  Welcome screen to create the Settings password:"
    echo ""
    echo "      $SETUP_CODE"
    echo ""
    echo "  Nobody can set Pantomath up without it. Show it again with:"
    echo "      sudo pantomath-admin setup-code"
    if [ "${DASHBOARD_URL#https:}" = "$DASHBOARD_URL" ]; then
        echo "  Tip: run 'sudo pantomath-admin setup-https' first, so the"
        echo "  password is never sent over plain HTTP."
    fi
    echo "=========================================================="
    echo ""
fi
