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
/opt/pantomath/venv/bin/pip install --quiet --upgrade pip
/opt/pantomath/venv/bin/pip install --quiet -r /opt/pantomath/requirements.txt

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
