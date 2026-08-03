# dau — do as user

A minimal, PAM-backed privilege-escalation utility for Linux, written in Go + CGO.
A tiny, auditable `sudo`/`doas` alternative.

## Features
- PAM auth against the `dau` service (fail-closed, no silent fallback)
- setuid-root with careful drop / re-acquire (`setresuid`)
- Argument-restricted policy rules (`permit … cmd … args …`)
- TOCTOU-safe exec via `execveat(AT_EMPTY_PATH)` on an `O_NOFOLLOW` fd (no path fallback)
- Trusted-binary invariant: target must be root-owned, non-writable, in a trusted dir
- Hardened child env (hardcoded `safePATH`, LANG/TERM allowlists, no `LD_*`)
- FD hygiene, umask pinning, config hardening (`O_NOFOLLOW` + `fstat`)
- Audit trail to `LOG_AUTHPRIV` syslog; exhaustive `-v` trace (debug only)

## Build
    sudo apt install build-essential gcc libpam0g-dev golang   # Debian/Ubuntu
    export CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong"
    CGO_ENABLED=1 go build -buildmode=pie -o dau -ldflags '-s -w' .

## Install (as root)
    sudo ./install.sh

## Policy (`/etc/dau.conf`)
    permit @wheel as root                                      # blanket (logged as risk)
    permit alice as root cmd /usr/bin/systemctl args restart -- nginx
    permit bob   as root cmd /usr/bin/journalctl args -*

> ⚠️ **GTFOBins warning.** Pinning a command is NOT enough by itself. Binaries
> like `less`, `more`, `vim`, `journalctl`, `awk`, `find`, `tar`, `python`
> can spawn a shell or read arbitrary files from *inside* them (`!sh`, `v`,
> `-exec`, `--checkpoint-action`, …). Once such a binary runs as root, the
> restriction is defeated. **Only permit binaries you have verified have no
> shell-escape or arbitrary-file-read hatch.** Prefer `args any` only for
> binaries with no interactive escape (e.g. `id`, `systemctl`).

## Security model
- Exec is strictly `execveat(AT_EMPTY_PATH)` on an `O_NOFOLLOW` fd — no path
  fallback (a fallback would re-open a TOCTOU race).
- Every executed binary must be root-owned, not group/other-writable, and in a
  root-owned non-writable directory (applies to absolute paths AND safePATH names).
- Auth lifecycle: auth + account + setcred. No PAM session (dau execs directly;
  on SELinux/MLS systems note the child keeps dau's context).
- The 2s failure delay is only a speed-bump; real lockout must come from
  `pam_faillock` (or equivalent) in your PAM stack.
- `-v` is for debugging only; never enable it in production logs.
- The policy file is read as root by design (it is 0600 root:root).

## License
MIT
