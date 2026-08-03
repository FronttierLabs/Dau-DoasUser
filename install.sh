#!/usr/bin/env bash
# Run as root: sudo ./install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi

if ! command -v go >/dev/null || ! command -v gcc >/dev/null; then
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends build-essential golang-go libpam0g-dev
  elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm base-devel go
  else
    echo "install go, gcc and libpam headers manually" >&2; exit 1
  fi
fi

export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
go build -buildmode=pie -o dau -ldflags '-s -w' .

install -m 4755 -o root -g root ./dau /usr/local/bin/dau

if [ ! -f /etc/dau.conf ]; then
  install -m 0600 -o root -g root examples/dau.conf /etc/dau.conf
else
  chown root:root /etc/dau.conf; chmod 0600 /etc/dau.conf
fi

if [ ! -f /etc/pam.d/dau ]; then
  if [ -f /etc/pam.d/common-auth ]; then
    printf '#%%PAM-1.0\nauth      include     common-auth\naccount   include     common-account\n' > /etc/pam.d/dau
  else
    printf '#%%PAM-1.0\nauth      include     system-auth\naccount   include     system-auth\n' > /etc/pam.d/dau
  fi
  chown root:root /etc/pam.d/dau; chmod 0644 /etc/pam.d/dau
  echo "generated /etc/pam.d/dau for this distro"
else
  echo "/etc/pam.d/dau already present; leaving untouched"
fi

echo "installed: /usr/local/bin/dau"
