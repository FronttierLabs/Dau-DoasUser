<<<<<<< HEAD
# Dau-DoasUser
minimal implemtation of sudo/Doas
=======
# dau — do as user

A minimal, PAM-backed privilege-escalation utility for Linux, written in Go + CGO.
Think of it as a tiny, auditable `sudo`/`doas` alternative.

## Features
- PAM authentication against the `dau` service (fail-closed, no silent fallback)
- setuid-root with careful privilege drop / re-acquire (`setresuid`)
- Argument-restricted policy rules (`permit … cmd … args …`)
- TOCTOU-safe exec via `execveat(AT_EMPTY_PATH)` on an `O_NOFOLLOW` fd
- Hardened child env (hardcoded `safePATH`, LANG/TERM allowlists, `LD_*` purge)
- FD hygiene (`close_range`), umask pinning, safePATH directory-trust checks
- Config hardening: root:root + 0600/0644, `O_NOFOLLOW` + `fstat` (no TOCTOU/symlink)
- Full audit trail to `LOG_AUTHPRIV` syslog
- Exhaustive `-v` trace for debugging

## Build
    sudo apt install build-essential gcc libpam0g-dev golang   # Debian/Ubuntu
    CGO_ENABLED=1 go build -o dau -ldflags '-s -w' .

## Install (as root)
    sudo ./install.sh

## Policy (`/etc/dau.conf`)
    permit @wheel as root                          # blanket (logged as risk)
    permit alice as root cmd /usr/bin/systemctl args restart -- nginx
    permit bob   as root cmd /usr/bin/journalctl args -*
    permit carol as root cmd /usr/bin/less args any   # explicit opt-in

## Security
See `SECURITY.md`. Report issues privately before public disclosure.

## License
MIT
>>>>>>> af903e9 (dau: minimal PAM-backed setuid privilege escalation utility)

## Security model (read this)
- **Trusted-binary invariant:** every executed binary must be root-owned, not
  group/other-writable, and live in a root-owned, non-writable directory.
  This holds for both absolute paths in rules and safePATH-resolved names.
- **No path fallback:** exec is strictly `execveat(AT_EMPTY_PATH)` on an
  `O_NOFOLLOW` fd; there is no path-based fallback (it would re-open a TOCTOU).
- **Auth lifecycle:** auth + account + setcred. No PAM session (dau execs
  directly and cannot close a session after the fact).
- **Rate limiting:** the 2s failure delay is only a speed-bump. Real lockout
  must come from `pam_faillock` (or equivalent) in your PAM stack.
- **`-v` is for debugging only**; never enable it in production logs.
- The policy file is read as root by design (it is 0600 root:root).
