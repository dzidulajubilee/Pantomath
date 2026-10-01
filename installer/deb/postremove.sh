#!/bin/sh
set -e

NGINX_AVAILABLE=/etc/nginx/sites-available
NGINX_ENABLED=/etc/nginx/sites-enabled

case "$1" in
    remove|purge)
        # Everything the postinst built outside the package's own file list
        # (dpkg only removes files it installed). Nothing here is user data.
        rm -rf /opt/pantomath/venv /opt/pantomath/build /opt/pantomath/*.egg-info
        rm -f /usr/local/bin/pantomath-admin
        rmdir /opt/pantomath 2>/dev/null || true
        systemctl daemon-reload || true
        ;;
    *)
        # upgrade / failed-upgrade / abort-*: the new version is (being) put in
        # place, so leave its venv and the admin command alone.
        systemctl daemon-reload || true
        ;;
esac

if [ "$1" = "purge" ]; then
    # Undo what `pantomath-admin setup-https` did, so the machine isn't left
    # with an nginx site proxying to a service that no longer exists (502)
    # and with nginx's own default site still switched off.
    changed_nginx=no
    if [ -e "$NGINX_ENABLED/pantomath" ] || [ -L "$NGINX_ENABLED/pantomath" ] || [ -e "$NGINX_AVAILABLE/pantomath" ]; then
        rm -f "$NGINX_ENABLED/pantomath" "$NGINX_AVAILABLE/pantomath"
        changed_nginx=yes
    fi
    for disabled in "$NGINX_AVAILABLE/default.disabled-by-pantomath" "$NGINX_ENABLED/default.disabled-by-pantomath"; do
        if [ -e "$disabled" ] || [ -L "$disabled" ]; then
            if [ ! -e "$NGINX_ENABLED/default" ] && [ ! -L "$NGINX_ENABLED/default" ]; then
                mv "$disabled" "$NGINX_ENABLED/default"
            else
                rm -f "$disabled"
            fi
            changed_nginx=yes
        fi
    done
    rm -f /etc/nginx/ssl/pantomath.crt /etc/nginx/ssl/pantomath.key
    rmdir /etc/nginx/ssl 2>/dev/null || true
    # The loopback-only override would leave a reinstalled service unreachable.
    rm -f /etc/systemd/system/pantomath.service.d/override.conf
    rmdir /etc/systemd/system/pantomath.service.d 2>/dev/null || true
    systemctl daemon-reload || true
    if [ "$changed_nginx" = yes ] && command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx 2>/dev/null || true
        fi
    fi

    rm -rf /var/lib/pantomath
    userdel pantomath 2>/dev/null || true
fi

exit 0
