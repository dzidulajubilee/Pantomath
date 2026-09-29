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

# Prefer the wheelhouse bundled in the package — this box may have no route
# to pypi.org (air-gapped / restricted-egress hosts like IDS sensors are a
# real deployment target for this tool), so don't require internet access
# for something as basic as installing the app. Only fall back to a normal
# networked pip install if the wheelhouse wasn't shipped (e.g. a package
# built directly from source without installer/wheelhouse present).
if [ -d /opt/pantomath/wheelhouse ] && [ -n "$(ls -A /opt/pantomath/wheelhouse 2>/dev/null)" ]; then
    /opt/pantomath/venv/bin/pip install --quiet --no-index --find-links=/opt/pantomath/wheelhouse /opt/pantomath
else
    /opt/pantomath/venv/bin/pip install --quiet --upgrade pip
    /opt/pantomath/venv/bin/pip install --quiet /opt/pantomath
fi

chown -R pantomath:pantomath /opt/pantomath

# Without this, pantomath-admin only exists at /opt/pantomath/venv/bin/
# and needs its full path typed out every time — not what anyone
# expects from a command meant to be run occasionally, by hand, on a
# real terminal (reset-settings-password, setup-https).
ln -sf /opt/pantomath/venv/bin/pantomath-admin /usr/local/bin/pantomath-admin

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
echo "Dashboard: http://$(hostname -f 2>/dev/null || hostname):7373"
echo "No sources are pre-loaded — add your feeds from the UI."
echo "Data: /var/lib/pantomath/pantomath.db"
echo "Logs: journalctl -u pantomath -f"
echo "Admin commands: pantomath-admin --help (e.g. 'pantomath-admin setup-https' for HTTPS via nginx)"
echo ""
if [ -n "$SETUP_CODE" ]; then
    HOST=$(hostname -f 2>/dev/null || hostname)
    echo "==================== First-time setup ===================="
    echo "  Open http://$HOST:7373 and enter this setup code on the"
    echo "  Welcome screen to create the Settings password:"
    echo ""
    echo "      $SETUP_CODE"
    echo ""
    echo "  Nobody can set Pantomath up without it. Show it again with:"
    echo "      sudo pantomath-admin setup-code"
    echo "  Tip: run 'sudo pantomath-admin setup-https' first, so the"
    echo "  password is never sent over plain HTTP."
    echo "=========================================================="
    echo ""
fi
