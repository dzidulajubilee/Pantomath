#!/bin/bash
# Build Pantomath packages.
#   ./build.sh deb     -> dist/pantomath_<ver>_amd64.deb   (dpkg-deb, no extra tools)
#   ./build.sh rpm     -> dist/pantomath-<ver>.x86_64.rpm  (requires nfpm)
#   ./build.sh all     -> both
set -euo pipefail

VERSION="${VERSION:-1.4.1}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

build_deb() {
    echo "==> Building .deb ${VERSION}"
    local pkgroot
    pkgroot="$(mktemp -d)"
    mkdir -p "$pkgroot/DEBIAN" "$pkgroot/opt/pantomath" "$pkgroot/etc/systemd/system" "$pkgroot/usr/share/pixmaps"

    cp -r "$ROOT/backend" "$pkgroot/opt/pantomath/"
    cp -r "$ROOT/frontend" "$pkgroot/opt/pantomath/"
    cp -r "$ROOT/config" "$pkgroot/opt/pantomath/"
    cp "$ROOT/requirements.txt" "$pkgroot/opt/pantomath/"
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

build_rpm() {
    echo "==> Building .rpm ${VERSION}"
    if ! command -v nfpm >/dev/null 2>&1; then
        echo "nfpm not found. Install it: https://nfpm.goreleaser.com/install/"
        exit 1
    fi
    VERSION="$VERSION" nfpm package --config "$ROOT/installer/rpm/nfpm.yaml" --packager rpm --target "$DIST/"
    echo "==> Built rpm in $DIST/"
}

case "${1:-all}" in
    deb) build_deb ;;
    rpm) build_rpm ;;
    all) build_deb; build_rpm ;;
    *) echo "usage: $0 [deb|rpm|all]"; exit 1 ;;
esac
