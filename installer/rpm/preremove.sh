#!/bin/sh
set -e
systemctl stop pantomath.service || true
systemctl disable pantomath.service || true
