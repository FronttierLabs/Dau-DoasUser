#!/usr/bin/env bash
# Run as root (sudo ./install.sh)
set -euo pipefail
export CGO_ENABLED=1
# Build hardening: PIE for ASLR, FORTIFY_SOURCE + stack protector for the
# embedded C conversation function.
export CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
go build -buildmode=pie -o dau -ldflags '-s -w' .
install -m 4755 -o root -g root ./dau               /usr/local/bin/dau
install -m 0644 -o root -g root examples/pam.d.dau  /etc/pam.d/dau
install -m 0600 -o root -g root examples/dau.conf   /etc/dau.conf
echo "installed: /usr/local/bin/dau"
