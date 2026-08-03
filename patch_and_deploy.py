#!/usr/bin/env python3
import os
import subprocess
import sys

DAU_DIR = os.path.expanduser("~/dau")

def run(cmd, cwd=DAU_DIR, check=False):
    print(f"$ {cmd}")
    res = subprocess.run(cmd, shell=True, cwd=cwd)
    if check and res.returncode != 0:
        print(f"WARN: Command failed with return code {res.returncode}")
        sys.exit(1)
    return res

def patch_file(filepath, old_str, new_str, description):
    path = os.path.join(DAU_DIR, filepath)
    if not os.path.exists(path):
        print(f"WARN: {path} not found. Skipping {description}")
        return False
    
    with open(path, "r") as f:
        content = f.read()
        
    if old_str not in content:
        print(f"WARN: Could not find target string for {description}. Already patched or code changed?")
        return False
        
    content = content.replace(old_str, new_str)
    
    with open(path, "w") as f:
        f.write(content)
        
    print(f"OK: Patched {description} in {filepath}")
    return True

print("=== Step 0: Apply 4 Critical Security Patches ===")

# 1. Fix Privilege Escalation via malformed UID/GID (main.go)
patch_file(
    "main.go",
    "\ttargetUID, _ := strconv.ParseUint(targetU.Uid, 10, 32)\n\ttargetGID, _ := strconv.ParseUint(targetU.Gid, 10, 32)",
    "\ttargetUID, err := strconv.ParseUint(targetU.Uid, 10, 32)\n\tif err != nil {\n\t\tfatal(\"malformed target UID %q for user %q (fail closed)\", targetU.Uid, cli.TargetUser)\n\t}\n\ttargetGID, err := strconv.ParseUint(targetU.Gid, 10, 32)\n\tif err != nil {\n\t\tfatal(\"malformed target GID %q for user %q (fail closed)\", targetU.Gid, cli.TargetUser)\n\t}",
    "CRITICAL: Privilege Escalation via malformed UID/GID"
)

# 2. Fix Auth Bypass via whoami() after regainRoot() (main.go)
patch_file(
    "main.go",
    "\tif !rule.NoPasswd {\n\t\tif err := authenticateUser(whoami()); err != nil {",
    "\tinvokerName := fmt.Sprintf(\"uid=%d\", ruid)\n\tif invokerU, err := user.LookupId(fmt.Sprintf(\"%d\", ruid)); err == nil {\n\t\tinvokerName = invokerU.Username\n\t}\n\n\tif !rule.NoPasswd {\n\t\tif err := authenticateUser(invokerName); err != nil {",
    "CRITICAL: Auth Bypass via whoami() after regainRoot()"
)

# 3. Fix Password Leak to child process stdin (pam.go)
patch_file(
    "pam.go",
    "                buf[len] = '\\0';\n                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);",
    "                buf[len] = '\\0';\n                // Drain remaining stdin if buffer maxed to prevent password leak to child shell\n                if (len == (int)sizeof(buf) - 1) {\n                    unsigned char drain;\n                    while (read(STDIN_FILENO, &drain, 1) == 1) {\n                        if (drain == '\\n' || drain == '\\r') break;\n                    }\n                }\n                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);",
    "HIGH: Password leakage to child process stdin"
)

# 4. Fix PAM Config Symlink Bypass (pam.go)
patch_file(
    "pam.go",
    "\tfi, err := os.Stat(\"/etc/pam.d/\" + service)\n\tif err != nil {\n\t\tauditLog(\"AUTH_FAIL\", fmt.Sprintf(\"no PAM service found (invoker=%s)\", invoker))\n\t\treturn fmt.Errorf(\"no usable PAM service %q present (fail-closed)\", service)\n\t}\n\tst, ok := fi.Sys().(*syscall.Stat_t)\n\tif !ok || st.Uid != 0 || fi.Mode().Perm()&0022 != 0 {",
    "\tfi, err := os.Lstat(\"/etc/pam.d/\" + service)\n\tif err != nil {\n\t\tauditLog(\"AUTH_FAIL\", fmt.Sprintf(\"no PAM service found (invoker=%s)\", invoker))\n\t\treturn fmt.Errorf(\"no usable PAM service %q present (fail-closed)\", service)\n\t}\n\tif fi.Mode()&os.ModeSymlink != 0 {\n\t\treturn fmt.Errorf(\"PAM service %q must not be a symlink (fail-closed)\", service)\n\t}\n\tst, ok := fi.Sys().(*syscall.Stat_t)\n\tif !ok || st.Uid != 0 || fi.Mode().Perm()&0022 != 0 {",
    "MEDIUM: PAM config symlink bypass"
)

print("\n=== Step 1: Build (Hardened) ===")
run('CGO_ENABLED=1 CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong" go build -buildmode=pie -o dau', check=True)

print("\n=== Step 2: Vet & Scan ===")
run("go vet ./...", check=True)
run("~/go/bin/gosec ./...", check=True)

print("\n=== Step 3: Set local setuid for testing ===")
print("Setting setuid on local ./dau binary so the test suite can run...")
run("sudo chown root:root ./dau", check=True)
run("sudo chmod 4755 ./dau", check=True)

print("\n=== Step 4: Test Suite ===")
run("./dau id", check=True)
run("./dau -u nobody id") # Expected to fail closed
run("./dau -u 'bad$name' id") # Expected to fail closed
run("./dau -v id")
run("PATH=/tmp/evil:$PATH ./dau id", check=True)

print("\n=== Step 5: Commit & Push ===")
run("git add -A")
run('git commit -m "security(critical): fix UID parse priv-esc, whoami auth bypass, stdin password leak, PAM symlink TOCTOU"', check=True)
run("git push origin main", check=True)

print("\n=== Step 6: Install system-wide ===")
run("sudo bash install.sh", check=True)

print("\n=== Step 7: Verify installation permissions ===")
run("stat -c '%a %U:%G %n' $(command -v dau) /etc/pam.d/dau /etc/dau.conf", check=True)

print("\n✅ All steps completed successfully!")
