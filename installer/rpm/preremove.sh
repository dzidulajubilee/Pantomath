#!/bin/sh
set -e
# On an RPM upgrade the old package's remove scripts run AFTER the new
# package's install script ($1 is the number of copies left installed: 0 on a
# real uninstall, 1 or more on an upgrade). Stopping and disabling the service
# then would switch off the freshly upgraded one, so only act on uninstall.
case "${1:-0}" in
    0|remove|purge) ;;
    *) exit 0 ;;
esac
systemctl stop pantomath.service || true
systemctl disable pantomath.service || true
