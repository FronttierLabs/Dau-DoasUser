package main

import (
	"fmt"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const Version = "v1.1.0-shrike"

var sysLog *syslog.Writer

func initAudit() {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, "dau")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dau: syslog unavailable\n")
		return
	}
	sysLog = w
}

func auditLog(tag, msg string) {
	line := fmt.Sprintf("[%s] %s", tag, msg)
	if sysLog != nil {
		_ = sysLog.Info(line) // #nosec G104
	}
	fmt.Fprintf(os.Stderr, "dau-audit: %s\n", line)
}

//prints for verbose statement - can be removed i just like seeing what my shit does while its being executed
var verbose bool

func vlogf(format string, a ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "dau-verbose: "+format+"\n", a...)
	}
}

func safeUint32(v int) uint32 {
	if v < 0 || v > 0xFFFFFFFF {
		fatal("uid/gid %d out of range", v)
	}
	return uint32(v) // #nosec G115 -- range-checked
}

func getRealUID() uint32      { return safeUint32(syscall.Getuid()) }
func getRealGID() uint32      { return safeUint32(syscall.Getgid()) }
func getEffectiveUID() uint32 { return safeUint32(syscall.Geteuid()) }

func getSupplementaryGIDs() []uint32 {
	gids, err := syscall.Getgroups()
	if err != nil {
		return nil
	}
	primary := getRealGID()
	out := make([]uint32, 0, len(gids)+1)
	out = append(out, primary)
	for _, g := range gids {
		if gu := safeUint32(g); gu != primary {
			out = append(out, gu)
		}
	}
	return out
}

//elavates the user privileges to root then drops down - needed
func dropToUser(uid, gid uint32) error {
	if err := unix.Setgroups([]int{int(gid)}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setresgid(-1, int(gid), 0); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := unix.Setresuid(-1, int(uid), 0); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	vlogf("dropped to invoker uid=%d gid=%d", uid, gid)
	return nil
}

func regainRoot() error {
	if err := unix.Setresuid(-1, 0, 0); err != nil {
		return fmt.Errorf("regain setresuid: %w", err)
	}
	if err := unix.Setresgid(-1, 0, 0); err != nil {
		return fmt.Errorf("regain setresgid: %w", err)
	}
	vlogf("re-acquired root")
	return nil
}

func setTargetCredentials(uid, gid uint32) error {
	// Groups were already securely set by POSIX initgroups(3)
	if err := unix.Setresgid(int(gid), int(gid), int(gid)); err != nil {
		return fmt.Errorf("setresgid(target): %w", err)
	}
	if err := unix.Setresuid(int(uid), int(uid), int(uid)); err != nil {
		return fmt.Errorf("setresuid(target): %w", err)
	}
	vlogf("target credentials set uid=%d gid=%d (groups set by initgroups)", uid, gid)
	return nil
}

//path needed for dau if removed dau wont execute - needed
const safePATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

var envTokenRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.@-]*$`)
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

var allowedLocales = map[string]struct{}{
	"C": {}, "POSIX": {}, "C.UTF-8": {}, "en_US.UTF-8": {}, "en_GB.UTF-8": {},
}

func envValueAllowed(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	return envTokenRe.MatchString(v)
}

func sanitizeEnv(targetUser *user.User) []string {
	safe := map[string]string{
		"HOME":    targetUser.HomeDir,
		"USER":    targetUser.Username,
		"LOGNAME": targetUser.Username,
		"SHELL":   getUserShell(targetUser.Username),
		"PATH":    safePATH,
	}
	if t := os.Getenv("TERM"); envValueAllowed(t) {
		safe["TERM"] = t
		vlogf("env: forwarding TERM=%q", t)
	} else {
		vlogf("env: dropping TERM=%q (not allowlisted)", os.Getenv("TERM"))
	}
	for _, k := range []string{"LANG", "LC_ALL"} {
		if l := os.Getenv(k); envValueAllowed(l) {
			if _, ok := allowedLocales[l]; ok {
				safe[k] = l
				vlogf("env: forwarding %s=%q", k, l)
				continue
			}
		}
		vlogf("env: dropping %s=%q (not allowlisted)", k, os.Getenv(k))
	}
	env := make([]string, 0, len(safe))
	for k, v := range safe {
		if v != "" {
			env = append(env, k+"="+v)
		}
	}
	vlogf("env: final child env = %v", env)
	return env
}

func dirTrustworthy(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if st.Uid != 0 {
		return false
	}
	if fi.Mode().Perm()&0022 != 0 {
		return false
	}
	return true
}

func resolveCommand(cmd string) string {
	if filepath.IsAbs(cmd) {
		vlogf("resolve: %q is absolute", cmd)
		return cmd
	}
	for _, dir := range filepath.SplitList(safePATH) {
		if !dirTrustworthy(dir) {
			vlogf("resolve: skipping untrusted dir %s", dir)
			auditLog("PATH_WARN", fmt.Sprintf("untrusted safePATH dir skipped: %s", dir))
			continue
		}
		candidate := filepath.Join(dir, cmd)
		fi, err := os.Stat(candidate)
		if err == nil && !fi.IsDir() {
			vlogf("resolve: %q → %s (dir %s trusted)", cmd, candidate, dir)
			return candidate
		}
	}
	return ""
}

func verifyTrustedBinary(fd int, path string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a regular file")
	}
	if st.Mode&0111 == 0 {
		return fmt.Errorf("not executable")
	}
	if st.Uid != 0 {
		return fmt.Errorf("not owned by root (uid=%d)", st.Uid)
	}
	if st.Mode&0022 != 0 {
		return fmt.Errorf("group/other writable (mode=%o)", st.Mode)
	}
	if !dirTrustworthy(filepath.Dir(path)) {
		return fmt.Errorf("parent directory %q not trusted", filepath.Dir(path))
	}
	vlogf("verifyTrustedBinary: %s ok (root-owned, non-writable, trusted dir)", path)
	return nil
}

func getUserShell(username string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6]
		}
	}
	return "/bin/sh"
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: dau [-v] [-u target_user] [--] command [args…]
  -v, --verbose   exhaustive trace on stderr (debug only)
`)
	os.Exit(1)
}

type cliArgs struct {
	TargetUser string
	Command    string
	Args       []string
}

func parseArgs() cliArgs {
	a := cliArgs{TargetUser: "root"}
	osArgs := os.Args[1:]
	i := 0
	for i < len(osArgs) {
		arg := osArgs[i]
		switch {
		case arg == "-version" || arg == "--version":
			fmt.Printf("dau %s\n", Version)
			os.Exit(0)
		case arg == "-v" || arg == "--verbose":
			verbose = true
		case arg == "-u" || arg == "--user":
			i++
			if i >= len(osArgs) {
				usage()
			}
			a.TargetUser = osArgs[i]
		case strings.HasPrefix(arg, "-u="):
			a.TargetUser = arg[3:]
		case arg == "--":
			i++
			goto done
		case strings.HasPrefix(arg, "-") && arg != "-":
			usage()
		default:
			goto done
		}
		i++
	}
done:
	if i < len(osArgs) {
		a.Command = osArgs[i]
		a.Args = osArgs[i:]
	}
	return a
}

func stringsToNilPtrs(ss []string) []*byte {
	n := 0
	for _, s := range ss {
		n += len(s) + 1
	}
	buf := make([]byte, n)
	ps := make([]*byte, 0, len(ss)+1)
	for _, s := range ss {
		copy(buf, s)
		ps = append(ps, &buf[0])
		buf = buf[len(s)+1:]
	}
	ps = append(ps, nil)
	return ps
}

func execveat(dirfd int, path string, argv, envv []string, flags int) error {
	argvPtrs := stringsToNilPtrs(argv)
	envPtrs := stringsToNilPtrs(envv)
	pb := append([]byte(path), 0)
	pathPtr := &pb[0]
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathPtr)),        // #nosec G103
		uintptr(unsafe.Pointer(&argvPtrs[0])),   // #nosec G103
		uintptr(unsafe.Pointer(&envPtrs[0])),    // #nosec G103
		uintptr(flags),
		0)
	if errno != 0 {
		return errno
	}
	return nil
}

func main() {
	syscall.Umask(0022)
	initAudit()

	euid := getEffectiveUID()
	ruid := getRealUID()
	if euid != 0 {
		fatal("dau must be installed setuid-root (euid=%d)", euid)
	}
	auditLog("START", fmt.Sprintf("version=%s invoker_uid=%d target=pending", Version, ruid))
	vlogf("dau %s starting | setuid verified: euid=%d ruid=%d rgid=%d", Version, euid, ruid, getRealGID())

	cli := parseArgs()
	setPamVerbose(verbose)
	vlogf("args: target=%q cmd=%q args=%v", cli.TargetUser, cli.Command, cli.Args)

	if !usernameRe.MatchString(cli.TargetUser) {
		fatal("invalid target username %q", cli.TargetUser)
	}
	targetU, err := user.Lookup(cli.TargetUser)
	if err != nil {
		fatal("unknown target user %q: %v", cli.TargetUser, err)
	}
	targetUID, err := strconv.ParseUint(targetU.Uid, 10, 32)
	if err != nil {
		fatal("malformed target UID %q for user %q (fail closed)", targetU.Uid, cli.TargetUser)
	}
	targetGID, err := strconv.ParseUint(targetU.Gid, 10, 32)
	if err != nil {
		fatal("malformed target GID %q for user %q (fail closed)", targetU.Gid, cli.TargetUser)
	}

	if cli.Command == "" {
		fatal("no command specified")
	}
	cmdArgs := []string{}
	if len(cli.Args) > 1 {
		cmdArgs = cli.Args[1:]
	}

	resolvedCmd := resolveCommand(cli.Command)
	if resolvedCmd == "" {
		fatal("cannot resolve %q via safe PATH", cli.Command)
	}

	// TOCTOU fix: open and verify the binary IMMEDIATELY after resolution - not temp fix?
	// the same fd is carried all the way to execveat - kinda needed
	fd, err := unix.Open(resolvedCmd, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		fatal("open %s: %v", resolvedCmd, err)
	}
	vlogf("exec fd=%d opened (O_NOFOLLOW|O_CLOEXEC)", fd)

	if err := verifyTrustedBinary(fd, resolvedCmd); err != nil {
		_ = unix.Close(fd)
		fatal("refusing to exec untrusted binary %s: %v", resolvedCmd, err)
	}

	auditLog("PARSE", fmt.Sprintf("invoker_uid=%d target=%s cmd=%s resolved=%s args=%v",
		ruid, cli.TargetUser, cli.Command, resolvedCmd, cmdArgs))

	cfg := loadConfig()
	vlogf("policy loaded: %d rule(s)", len(cfg.Rules))

	invokerGIDs := getSupplementaryGIDs()
	if err := dropToUser(ruid, getRealGID()); err != nil {
		fatal("drop privileges: %v", err)
	}

	//cheks user prev
	rule := cfg.findRule(ruid, invokerGIDs, cli.TargetUser, resolvedCmd, cmdArgs)
	if rule == nil {
		auditLog("DENY", fmt.Sprintf("uid=%d target=%s cmd=%s args=%v – no matching rule",
			ruid, cli.TargetUser, resolvedCmd, cmdArgs))
		fatal("permission denied: no matching rule for uid %d → %s (%s %v)",
			ruid, cli.TargetUser, resolvedCmd, cmdArgs)
	}
	if rule.Command == "" || rule.Args == argsAny {
		auditLog("GRANT_UNRESTRICTED", fmt.Sprintf("uid=%d target=%s cmd=%s args=%v",
			ruid, cli.TargetUser, resolvedCmd, cmdArgs))
	}

	if err := regainRoot(); err != nil {
		fatal("regain root: %v", err)
	}

	invokerName := fmt.Sprintf("uid=%d", ruid)
	if invokerU, err := user.LookupId(fmt.Sprintf("%d", ruid)); err == nil {
		invokerName = invokerU.Username
	}

	if !rule.NoPasswd {
		if err := authenticateUser(invokerName); err != nil {
			auditLog("AUTH_FAIL", fmt.Sprintf("uid=%d target=%s: %v", ruid, cli.TargetUser, err))
			time.Sleep(2 * time.Second) // speed-bump; pam_faillock does real lockout
			fatal("authentication failed: %v", err)
		}
	} else {
		auditLog("NOPASS", fmt.Sprintf("uid=%d target=%s (nopass rule)", ruid, cli.TargetUser))
	}

	env := sanitizeEnv(targetU)

	// delegate group resolution to POSIX initgroups(3) It is heavily audited
	// handles NSS edge cases natively and prevents Go level parsing bugs - needed 'might be temp'
	if err := initGroups(cli.TargetUser, uint32(targetGID)); err != nil {
		fatal("initgroups(%q): %v", cli.TargetUser, err)
	}
	if err := setTargetCredentials(uint32(targetUID), uint32(targetGID)); err != nil {
		fatal("set target credentials: %v", err)
	}

	auditLog("EXEC", fmt.Sprintf("uid=%d → target_uid=%d cmd=%s args=%v binary=%s",
		ruid, targetUID, resolvedCmd, cmdArgs, resolvedCmd))

	argv := make([]string, len(cli.Args))
	copy(argv, cli.Args)
	argv[0] = cli.Command // preserve the user-invoked name as argv[0]
	vlogf("execveat argv=%v", argv)

	// fd-based exec only no path-based fallback - due to couple security exploits
	if err := execveat(fd, "", argv, env, unix.AT_EMPTY_PATH); err != nil {
		fatal("execveat %s: %v (no fallback by design)", resolvedCmd, err)
	}
}

func fatal(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "dau: %s\n", msg)
	auditLog("FATAL", msg)
	os.Exit(1)
}
