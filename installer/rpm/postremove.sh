#!/bin/sh
set -e
# See preremove.sh: on an upgrade this runs after the new version's install
# script, so it must not delete the new version's venv or admin command.
case "${1:-0}" in
    0|remove|purge) ;;
    *)
        systemctl daemon-reload || true
        exit 0
        ;;
esac

systemctl daemon-reload || true
rm -rf /opt/pantomath/venv /opt/pantomath/build /opt/pantomath/*.egg-info
rm -f /usr/local/bin/pantomath-admin
rmdir /opt/pantomath 2>/dev/null || true
# Data in /var/lib/pantomath and the pantomath user are kept, as before: an
# RPM uninstall has no separate "purge" step.
exit 0
