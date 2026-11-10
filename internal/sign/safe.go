package sign

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Path checks live here. internal/apk's writeAtomic and samePath are
// unexported and do not reject git worktrees, symlink ancestors, or loose
// Windows ACLs. Do not import that package until it exports a helper with
// these checks.

func cleanAbs(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%w", ErrRelative)
	}
	if strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return "", fmt.Errorf("%w: device path", ErrRelative)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// rejectUnsafe fails closed: a symlink ancestor is refused rather than
// followed, and both the lexical path and any existing prefix are checked
// for a git worktree (.git file or directory) and a .git path component.
func rejectUnsafe(path string) (string, error) {
	abs, err := cleanAbs(path)
	if err != nil {
		return "", err
	}
	if err := walkNoSymlink(abs); err != nil {
		return "", err
	}
	if err := outsideRepo(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func walkNoSymlink(path string) error {
	vol := filepath.VolumeName(path)
	rest := strings.TrimPrefix(path, vol)
	rest = strings.TrimPrefix(rest, string(filepath.Separator))
	if rest == "" {
		return fmt.Errorf("%w: path is a volume root", ErrRelative)
	}
	cur := vol
	if vol != "" && !strings.HasPrefix(vol, `\\`) {
		cur = vol + string(filepath.Separator)
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%w: unclean path", ErrRelative)
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w", ErrSymlink)
		}
	}
	return nil
}

func outsideRepo(path string) error {
	cur := path
	for {
		if strings.EqualFold(filepath.Base(cur), ".git") {
			return fmt.Errorf("%w", ErrGitDir)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		if st, err := os.Lstat(parent); err == nil && st.IsDir() {
			git := filepath.Join(parent, ".git")
			if _, err := os.Lstat(git); err == nil {
				return fmt.Errorf("%w", ErrRepo)
			}
		}
		cur = parent
	}
}

func distinct(paths ...string) error {
	for i := 0; i < len(paths); i++ {
		if paths[i] == "" {
			continue
		}
		for j := i + 1; j < len(paths); j++ {
			if paths[j] == "" {
				continue
			}
			if samePath(paths[i], paths[j]) {
				return fmt.Errorf("%w", ErrDistinct)
			}
		}
	}
	return nil
}

func requireTool(path string) (string, error) {
	abs, err := cleanAbs(path)
	if err != nil {
		return "", err
	}
	if err := walkNoSymlink(abs); err != nil {
		return "", err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return "", fmt.Errorf("sign: tool is not a regular file: %s", abs)
	}
	return abs, nil
}

// requireInput allows a repo-relative archive. Output and keys still use rejectUnsafe.
func requireInput(path string) (string, error) {
	abs, err := cleanAbs(path)
	if err != nil {
		return "", err
	}
	if err := walkNoSymlink(abs); err != nil {
		return "", err
	}
	return regularFile(abs)
}

func requireRegular(path string) (string, error) {
	abs, err := rejectUnsafe(path)
	if err != nil {
		return "", err
	}
	return regularFile(abs)
}

func regularFile(abs string) (string, error) {
	st, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w", ErrSymlink)
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return "", fmt.Errorf("sign: not a regular file: %s", abs)
	}
	return abs, nil
}

func destAvailable(path string) (string, error) {
	abs, err := rejectUnsafe(path)
	if err != nil {
		return "", err
	}
	st, err := os.Lstat(abs)
	if err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w", ErrSymlink)
		}
		return "", fmt.Errorf("%w", ErrExists)
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	pst, err := os.Lstat(parent)
	if err != nil {
		return "", err
	}
	if !pst.IsDir() || pst.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("sign: parent is not a directory: %s", parent)
	}
	return abs, nil
}

func randToken() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type rollback struct {
	files []string
	dirs  []string
}

func (r *rollback) file(p string) { r.files = append(r.files, p) }
func (r *rollback) dir(p string)  { r.dirs = append(r.dirs, p) }

func (r *rollback) run() {
	for i := len(r.files) - 1; i >= 0; i-- {
		os.Remove(r.files[i])
	}
	for i := len(r.dirs) - 1; i >= 0; i-- {
		p := r.dirs[i]
		if strings.HasPrefix(filepath.Base(p), ".raspberry-") {
			os.RemoveAll(p)
			continue
		}
		os.Remove(p) // empty only; a pre-existing parent is not in this list
	}
}

func mkdirOwner(ctx context.Context, path string, rb *rollback, secret string) error {
	path = filepath.Clean(path)
	if _, err := rejectUnsafe(path); err != nil {
		return err
	}
	var missing []string
	cur := path
	for {
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			missing = append(missing, cur)
			parent := filepath.Dir(cur)
			if parent == cur {
				return fmt.Errorf("sign: cannot create %s", path)
			}
			cur = parent
			continue
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w", ErrSymlink)
		}
		if !st.IsDir() {
			return fmt.Errorf("sign: not a directory: %s", cur)
		}
		break
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o700); err != nil {
			return err
		}
		rb.dir(missing[i])
		if err := lockOwnerOnly(ctx, missing[i], true, secret); err != nil {
			return err
		}
	}
	return nil
}

func scratchDir(ctx context.Context, parent, secret string) (string, error) {
	tok, err := randToken()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(parent, ".raspberry-"+tok)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if err := lockOwnerOnly(ctx, dir, true, secret); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func removeScratch(path string) {
	if path == "" || !strings.HasPrefix(filepath.Base(path), ".raspberry-") {
		return
	}
	os.RemoveAll(path)
}

func hashFile(path string) ([32]byte, error) {
	var sum [32]byte
	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func validAlias(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func validEnvName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func validatePassword(s string) error {
	if len(s) < 6 || len(s) > 256 {
		return fmt.Errorf("sign: password must be 6-256 characters")
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			// shortcut: ASCII only, so keytool and apksigner agree without --pass-encoding
			return fmt.Errorf("sign: password must be printable ASCII")
		}
	}
	return nil
}

func loadSecret(ctx context.Context, s Secret) (string, error) {
	if (s.File == "") == (s.Env == "") {
		return "", fmt.Errorf("sign: set exactly one of password file or env")
	}
	if s.Env != "" {
		if !validEnvName(s.Env) {
			return "", fmt.Errorf("sign: invalid password env name")
		}
		v, ok := os.LookupEnv(s.Env)
		if !ok {
			return "", fmt.Errorf("sign: password env is unset")
		}
		if err := validatePassword(v); err != nil {
			return "", err
		}
		return v, nil
	}
	abs, err := requireRegular(s.File)
	if err != nil {
		return "", err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if st.Size() > 512 {
		return "", fmt.Errorf("sign: password file too large")
	}
	if err := verifyOwnerOnly(ctx, abs, false, ""); err != nil {
		return "", err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return "", err
	}
	pw := string(b)
	pw = strings.TrimSuffix(pw, "\r\n")
	pw = strings.TrimSuffix(pw, "\n")
	if err := validatePassword(pw); err != nil {
		return "", err
	}
	return pw, nil
}

func secretSpec(s Secret) (mode, arg, envName string) {
	if s.File != "" {
		return "file", s.File, ""
	}
	return "env", s.Env, s.Env
}

func containsSecret(s, secret string) bool {
	return secret != "" && strings.Contains(s, secret)
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}

func validateJavaArgs(args []string, secret string) error {
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, "\r\n\x00") || containsSecret(a, secret) {
			return fmt.Errorf("sign: invalid java arg")
		}
		if a == "-jar" || strings.HasPrefix(a, "-jar") {
			return fmt.Errorf("sign: java arg must not include -jar")
		}
	}
	return nil
}

func childEnv(extra map[string]string, scratch string) []string {
	allow := []string{
		"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATH", "PATHEXT",
		"TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
		"LANG", "LC_ALL", "LC_CTYPE", "APPDATA", "LOCALAPPDATA",
		"PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS",
	}
	var out []string
	for _, k := range allow {
		if v, ok := os.LookupEnv(k); ok {
			if k == "TEMP" || k == "TMP" || k == "TMPDIR" {
				v = scratch
			}
			out = append(out, k+"="+v)
		}
	}
	if scratch != "" {
		out = append(out, "TEMP="+scratch, "TMP="+scratch, "TMPDIR="+scratch)
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

type limitBuf struct {
	buf bytes.Buffer
	n   int
}

func (l *limitBuf) Write(p []byte) (int, error) {
	const capN = 64 << 10
	orig := len(p)
	if l.n >= capN {
		return orig, nil
	}
	if l.n+len(p) > capN {
		p = p[:capN-l.n]
	}
	n, err := l.buf.Write(p)
	l.n += n
	if err != nil {
		return n, err
	}
	return orig, nil
}

func runTool(ctx context.Context, timeout time.Duration, name string, argv []string, extra map[string]string, scratch, secret string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = scratch
	cmd.Env = childEnv(extra, scratch)
	cmd.Stdin = strings.NewReader("")
	cmd.WaitDelay = 3 * time.Second
	var buf limitBuf
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	text := buf.buf.String()
	if containsSecret(text, secret) {
		return fmt.Errorf("%w: %s", ErrSecret, name)
	}
	if err == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("sign: %s timed out", name)
	}
	text = strings.TrimSpace(redact(text, secret))
	if len(text) > 2000 {
		text = text[:2000] + "..."
	}
	if text == "" {
		return fmt.Errorf("sign: %s: %w", name, err)
	}
	return fmt.Errorf("sign: %s: %w: %s", name, err, text)
}

func timeoutOr(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	return d
}

func currentIdentity() (sid, username string, err error) {
	u, err := user.Current()
	if err != nil {
		return "", "", err
	}
	sid = u.Uid
	if runtime.GOOS == "windows" && !strings.HasPrefix(strings.ToUpper(sid), "S-1-") {
		return "", "", fmt.Errorf("sign: current user SID unavailable")
	}
	return sid, u.Username, nil
}

func unixOwnerOnly(mode os.FileMode, dir bool) bool {
	perm := mode.Perm()
	if perm&0o077 != 0 {
		return false
	}
	if dir {
		return perm&0o700 == 0o700
	}
	return perm&0o600 == 0o600 && perm&0o111 == 0
}

func lockOwnerOnly(ctx context.Context, path string, dir bool, secret string) error {
	if runtime.GOOS != "windows" {
		mode := os.FileMode(0o600)
		if dir {
			mode = 0o700
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		return verifyOwnerOnly(ctx, path, dir, secret)
	}
	sid, _, err := currentIdentity()
	if err != nil {
		return err
	}
	icacls, err := icaclsExe()
	if err != nil {
		return err
	}
	if err := runPlain(ctx, icacls, []string{path, "/inheritance:r"}, secret); err != nil {
		return err
	}
	grant := "*" + sid + ":(F)"
	if dir {
		grant = "*" + sid + ":(OI)(CI)(F)"
	}
	if err := runPlain(ctx, icacls, []string{path, "/grant:r", grant}, secret); err != nil {
		return err
	}
	aces, err := readACEs(ctx, path, secret)
	if err != nil {
		return err
	}
	_, name, err := currentIdentity()
	if err != nil {
		return err
	}
	for _, a := range aces {
		if identityIsUs(a.id, sid, name) {
			continue
		}
		if err := runPlain(ctx, icacls, []string{path, "/remove", a.id}, secret); err != nil {
			return fmt.Errorf("%w: removing %s: %v", ErrPerm, a.id, err)
		}
	}
	return verifyOwnerOnly(ctx, path, dir, secret)
}

func verifyOwnerOnly(ctx context.Context, path string, dir bool, secret string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w", ErrSymlink)
	}
	if runtime.GOOS != "windows" {
		if !unixOwnerOnly(st.Mode(), dir) {
			return fmt.Errorf("%w", ErrPerm)
		}
		return nil
	}
	aces, err := readACEs(ctx, path, secret)
	if err != nil {
		return err
	}
	if len(aces) == 0 {
		return fmt.Errorf("%w: no ACL entries", ErrPerm)
	}
	sid, name, err := currentIdentity()
	if err != nil {
		return err
	}
	full := false
	for _, a := range aces {
		if !identityIsUs(a.id, sid, name) || !rightsOK(a.rights) {
			return fmt.Errorf("%w", ErrPerm)
		}
		if strings.Contains(a.rights, "(F)") {
			full = true
		}
	}
	if !full {
		return fmt.Errorf("%w", ErrPerm)
	}
	return nil
}

func rightsOK(rights string) bool {
	if !strings.Contains(rights, "(F)") || strings.Contains(strings.ToUpper(rights), "DENY") {
		return false
	}
	s := rights
	for _, tok := range []string{"(F)", "(OI)", "(CI)", "(IO)", "(I)", "(NP)"} {
		s = strings.ReplaceAll(s, tok, "")
	}
	return s == ""
}

type ace struct{ id, rights string }

func identityIsUs(id, sid, username string) bool {
	return strings.EqualFold(id, sid) || strings.EqualFold(id, username) || strings.EqualFold(id, "*"+sid)
}

func icaclsExe() (string, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		return "", fmt.Errorf("sign: SystemRoot is unset")
	}
	p := filepath.Join(root, "System32", "icacls.exe")
	st, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("sign: icacls is not a file")
	}
	return p, nil
}

func runPlain(ctx context.Context, exe string, args []string, secret string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdin = strings.NewReader("")
	cmd.WaitDelay = 3 * time.Second
	var buf limitBuf
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	text := buf.buf.String()
	if containsSecret(text, secret) {
		return fmt.Errorf("%w: icacls", ErrSecret)
	}
	if err == nil {
		return nil
	}
	text = strings.TrimSpace(redact(text, secret))
	if len(text) > 500 {
		text = text[:500] + "..."
	}
	return fmt.Errorf("sign: icacls: %w: %s", err, text)
}

func readACEs(ctx context.Context, path, secret string) ([]ace, error) {
	exe, err := icaclsExe()
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, path)
	cmd.Stdin = strings.NewReader("")
	cmd.WaitDelay = 3 * time.Second
	var buf limitBuf
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		text := redact(buf.buf.String(), secret)
		return nil, fmt.Errorf("sign: icacls: %w: %s", err, strings.TrimSpace(text))
	}
	text := buf.buf.String()
	if containsSecret(text, secret) {
		return nil, fmt.Errorf("%w: icacls", ErrSecret)
	}
	return parseICACLS(text, path)
}

// parseICACLS reads English icacls output, including the trailer lines
// "Successfully processed" and "Failed processing". A localized icacls fails
// closed with ErrPerm. This is not a portable ACL parser.
func parseICACLS(out, path string) ([]ace, error) {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	var (
		aces []ace
		saw  bool
	)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		low := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(low, "successfully processed") || strings.HasPrefix(low, "failed processing") {
			continue
		}
		payload := line
		if !saw {
			if len(line) < len(path) || !strings.EqualFold(line[:len(path)], path) {
				return nil, fmt.Errorf("%w: icacls output unparsable", ErrPerm)
			}
			payload = line[len(path):]
			saw = true
		} else if line[0] != ' ' && line[0] != '\t' {
			return nil, fmt.Errorf("%w: unexpected icacls line", ErrPerm)
		}
		payload = strings.TrimSpace(payload)
		if payload == "" {
			continue
		}
		got, err := splitACEs(payload)
		if err != nil {
			return nil, err
		}
		aces = append(aces, got...)
	}
	if !saw {
		return nil, fmt.Errorf("%w: empty icacls output", ErrPerm)
	}
	return aces, nil
}

func splitACEs(s string) ([]ace, error) {
	var out []ace
	s = strings.TrimSpace(s)
	for len(s) > 0 {
		i := strings.Index(s, ":(")
		if i <= 0 {
			return nil, fmt.Errorf("%w: bad ace %q", ErrPerm, s)
		}
		id := strings.TrimSpace(s[:i])
		s = s[i+1:]
		end := 0
		for end < len(s) && s[end] == '(' {
			j := strings.IndexByte(s[end:], ')')
			if j < 0 {
				return nil, fmt.Errorf("%w: bad ace rights", ErrPerm)
			}
			end += j + 1
		}
		if end == 0 {
			return nil, fmt.Errorf("%w: bad ace rights", ErrPerm)
		}
		out = append(out, ace{id: id, rights: s[:end]})
		s = strings.TrimSpace(s[end:])
	}
	return out, nil
}

func publish(tmp, dst string) error {
	if st, err := os.Lstat(dst); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w", ErrSymlink)
		}
		return fmt.Errorf("%w", ErrExists)
	} else if !os.IsNotExist(err) {
		return err
	}
	// Link does not replace. A filesystem that cannot hard-link fails closed.
	if err := os.Link(tmp, dst); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w", ErrExists)
		}
		return fmt.Errorf("sign: atomic publish failed: %w", err)
	}
	if err := os.Remove(tmp); err != nil {
		return fmt.Errorf("sign: published %s but temp name remains: %w", dst, err)
	}
	return nil
}
