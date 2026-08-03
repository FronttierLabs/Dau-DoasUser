#!/usr/bin/env bash
# Run as root (sudo ./install.sh)
set -euo pipefail
CGO_ENABLED=1 go build -o dau -ldflags '-s -w' .
install -m 4755 -o root -g root ./dau        /usr/local/bin/dau
install -m 0644 examples/pam.d.dau           /etc/pam.d/dau
install -m 0600 -o root -g root examples/dau.conf /etc/dau.conf
echo "installed: /usr/local/bin/dau"
