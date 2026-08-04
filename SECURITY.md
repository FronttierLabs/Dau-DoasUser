# Security policy

`dau` is a setuid-root privilege-escalation tool. Deploy only on systems you
own or administer.

## Reporting
Do NOT open public issues for vulnerabilities.
use a GitHub private security advisory and allow time for a fix.

## Design guarantees
- Fail-closed on any config/permission/PAM error.
- Config must be root:root and 0600/0644; opened with O_NOFOLLOW + fstat.
- Commands resolve only via a hardcoded, directory-trusted safePATH.
- Exec is fd-based (`execveat AT_EMPTY_PATH`) to avoid path-swap races.
- Unrestricted rules (`no cmd` / `args any`) are logged as GTFOBins-class risk.

## Known limitations
- No PAM session lifecycle (would require fork/wait).
- Restricted `cmd` rules require root-owned binaries (trusted-binary invariant).
- Brute-force lockout depends on the underlying PAM stack (pam_faillock).
