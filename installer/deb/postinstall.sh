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

systemctl daemon-reload
systemctl enable pantomath.service
systemctl restart pantomath.service || systemctl start pantomath.service

echo ""
echo "Pantomath installed."
echo "Dashboard: http://localhost:7373"
echo "No sources are pre-loaded — add your feeds from the UI."
echo "Data: /var/lib/pantomath/pantomath.db"
echo "Logs: journalctl -u pantomath -f"
echo ""
