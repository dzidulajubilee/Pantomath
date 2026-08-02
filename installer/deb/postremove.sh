#!/bin/sh
set -e
systemctl daemon-reload || true
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/pantomath
    rm -rf /opt/pantomath/venv
    rm -f /usr/local/bin/pantomath-admin
    userdel pantomath 2>/dev/null || true
fi
