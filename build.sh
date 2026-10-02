#!/bin/bash
# Build Pantomath packages.
#   ./build.sh deb     -> dist/pantomath_<ver>_amd64.deb   (dpkg-deb, no extra tools)
#   ./build.sh all     -> the same (kept so existing scripts and `make package` work)
#
# Version comes from pyproject.toml — the single source of truth. Bump it
# there and every package format picks it up automatically; nothing else
# to edit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${VERSION:-$(python3 -c "import tomllib; print(tomllib.load(open('$ROOT/pyproject.toml','rb'))['project']['version'])")}"
DIST="$ROOT/dist"
mkdir -p "$DIST"

build_deb() {
    echo "==> Building .deb ${VERSION}"
    local pkgroot
    pkgroot="$(mktemp -d)"
    mkdir -p "$pkgroot/DEBIAN" "$pkgroot/opt/pantomath" "$pkgroot/etc/systemd/system" "$pkgroot/usr/share/pixmaps"

    cp -r "$ROOT/pantomath" "$pkgroot/opt/pantomath/"
    cp -r "$ROOT/frontend" "$pkgroot/opt/pantomath/"
    cp -r "$ROOT/config" "$pkgroot/opt/pantomath/"
    cp "$ROOT/pyproject.toml" "$pkgroot/opt/pantomath/"
    cp "$ROOT/README.md" "$pkgroot/opt/pantomath/"
    if [ -d "$ROOT/installer/wheelhouse" ]; then
        cp -r "$ROOT/installer/wheelhouse" "$pkgroot/opt/pantomath/wheelhouse"
    fi
    cp "$ROOT/installer/deb/pantomath.service" "$pkgroot/etc/systemd/system/"
    cp "$ROOT/icons/pantomath.svg" "$pkgroot/usr/share/pixmaps/pantomath.svg"
    find "$pkgroot/opt/pantomath" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

    sed "s/^Version:.*/Version: ${VERSION}/" "$ROOT/installer/deb/DEBIAN/control" > "$pkgroot/DEBIAN/control"
    cp "$ROOT/installer/deb/postinstall.sh" "$pkgroot/DEBIAN/postinst"
    cp "$ROOT/installer/deb/preremove.sh" "$pkgroot/DEBIAN/prerm"
    cp "$ROOT/installer/deb/postremove.sh" "$pkgroot/DEBIAN/postrm"
    chmod 755 "$pkgroot/DEBIAN/postinst" "$pkgroot/DEBIAN/prerm" "$pkgroot/DEBIAN/postrm"
    find "$pkgroot" -type d -exec chmod 755 {} \;

    dpkg-deb --build --root-owner-group "$pkgroot" "$DIST/pantomath_${VERSION}_amd64.deb"
    rm -rf "$pkgroot"
    echo "==> Built $DIST/pantomath_${VERSION}_amd64.deb"
}

case "${1:-all}" in
    deb) build_deb ;;
    all) build_deb ;;
    *) echo "usage: $0 [deb|all]"; exit 1 ;;
esac
