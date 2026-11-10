package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/festivities/raspberry/internal/apk"
	"github.com/festivities/raspberry/internal/baseline"
	"github.com/festivities/raspberry/internal/descriptor"
	"github.com/festivities/raspberry/internal/patch"
	"github.com/festivities/raspberry/internal/sign"
)

const (
	// outputName is the fixed file name under --out. It is not operator data.
	outputName = "raspberry-lineplay-10.1.0.0.apk"
	// devPinAsset is read by dev.raspberry.Raspberry and only when present.
	devPinAsset = "assets/raspberry/devPinSha256"
	// endpointAsset is the baked descriptor.
	endpointAsset = "assets/raspberry/endpoint.json"
)

// portMap collects repeatable --port <client-port>=<endpoint-port> flags.
type portMap map[int]int

func (m portMap) String() string { return "" }

func (m portMap) Set(s string) error {
	orig, dest, ok := strings.Cut(s, "=")
	if !ok {
		return errors.New("want <client-port>=<endpoint-port>")
	}
	o, err := strconv.Atoi(orig)
	if err != nil {
		return errors.New("want <client-port>=<endpoint-port>")
	}
	d, err := strconv.Atoi(dest)
	if err != nil {
		return errors.New("want <client-port>=<endpoint-port>")
	}
	switch o {
	case 80, 443, 10000, 10123:
	default:
		return fmt.Errorf("client port %d is not 80, 443, 10000 or 10123", o)
	}
	if d < 1 || d > 65535 {
		return fmt.Errorf("endpoint port %d is outside 1-65535", d)
	}
	m[o] = d
	return nil
}

// descriptorAsset validates the operator input through the shared parser and
// returns the canonical asset bytes (struct field order, no whitespace).
func descriptorAsset(host string, ports map[int]int) (descriptor.Descriptor, []byte, error) {
	req := map[string]any{"v": 1, "host": host}
	if len(ports) > 0 {
		raw := make(map[string]int, len(ports))
		for orig, dest := range ports {
			raw[strconv.Itoa(orig)] = dest
		}
		req["ports"] = raw
	}
	b, err := json.Marshal(req)
	if err != nil {
		return descriptor.Descriptor{}, nil, err
	}
	d, err := descriptor.Parse(b)
	if err != nil {
		return descriptor.Descriptor{}, nil, err
	}
	asset, err := json.Marshal(d)
	if err != nil {
		return descriptor.Descriptor{}, nil, err
	}
	return d, asset, nil
}

// pinAsset returns the devPinSha256 asset, or nil when no pin was requested.
func pinAsset(pin string) ([]byte, error) {
	if pin == "" {
		return nil, nil
	}
	if len(pin) != 64 {
		return nil, errors.New("--dev-pin-sha256 must be 64 hex characters")
	}
	b, err := hex.DecodeString(strings.ToLower(pin))
	if err != nil || len(b) != 32 {
		return nil, errors.New("--dev-pin-sha256 must be 64 hex characters")
	}
	return []byte(hex.EncodeToString(b) + "\n"), nil
}

func cmdPatch(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("patch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apkPath := fs.String("apk", "", "pristine baseline APK")
	host := fs.String("endpoint", "", "endpoint host (DNS name or IPv4 literal)")
	ports := portMap{}
	fs.Var(ports, "port", "repeatable <client-port>=<endpoint-port>; client ports 80, 443, 10000, 10123")
	pin := fs.String("dev-pin-sha256", "", "embed a developer certificate pin (64 hex, lab only)")
	outDir := fs.String("out", "", "absolute output directory outside every repository")
	buildDir := fs.String("build", "build", "artifact tree: native/<abi>/, dex/, dexpatch/")
	patchesDir := fs.String("patches", "patches", "patch table directory")
	keystore := fs.String("keystore", "", "absolute PKCS#12 keystore outside every repository")
	alias := fs.String("alias", "raspberry", "keystore key alias")
	pwFile := fs.String("password-file", "", "owner-only file holding the keystore password")
	pwEnv := fs.String("password-env", "", "environment variable holding the keystore password")
	java := fs.String("java", javaTool("java.exe"), "absolute java.exe")
	keytool := fs.String("keytool", javaTool("keytool.exe"), "absolute keytool.exe")
	zipalign := fs.String("zipalign", sdkTool("build-tools/36.0.0/zipalign.exe"), "absolute zipalign.exe")
	apksigner := fs.String("apksigner", sdkTool("build-tools/36.0.0/lib/apksigner.jar"), "absolute apksigner.jar")
	classpath := fs.String("dexpatch-classpath", "", "java classpath for tools/dexpatch")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "raspberry patch: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *apkPath == "" || *host == "" || *outDir == "" || *keystore == "" {
		fmt.Fprintln(stderr, "raspberry patch: --apk, --endpoint, --out and --keystore are required")
		return 2
	}
	if (*pwFile == "") == (*pwEnv == "") {
		fmt.Fprintln(stderr, "raspberry patch: set exactly one of --password-file or --password-env")
		return 2
	}
	// Refuse repo outputs before hashing the APK or creating any file.
	if err := refusePrivate(*outDir, filepath.Join(*outDir, outputName), *keystore); err != nil {
		fmt.Fprintf(stderr, "raspberry patch: %v\n", err)
		return 2
	}
	for _, p := range []struct{ flag, val string }{
		{"--out", *outDir}, {"--keystore", *keystore},
	} {
		if !filepath.IsAbs(p.val) {
			fmt.Fprintf(stderr, "raspberry patch: %s must be an absolute path\n", p.flag)
			return 2
		}
	}
	_, asset, err := descriptorAsset(*host, ports)
	if err != nil {
		fmt.Fprintf(stderr, "raspberry patch: %v\n", err)
		return 2
	}
	pinBytes, err := pinAsset(*pin)
	if err != nil {
		fmt.Fprintf(stderr, "raspberry patch: %v\n", err)
		return 2
	}

	// The input lock is the primary gate; nothing else is meaningful without it.
	if err := baseline.Verify(*apkPath); err != nil {
		fmt.Fprintf(stderr, "raspberry patch: %v\n", err)
		return 1
	}

	art := artifacts{build: *buildDir, patches: *patchesDir}
	cp := *classpath
	if cp == "" {
		cp = defaultDexClasspath(*buildDir)
	}
	req := buildRequest{
		apk:       *apkPath,
		outDir:    *outDir,
		endpoint:  asset,
		pin:       pinBytes,
		build:     art,
		keystore:  *keystore,
		alias:     *alias,
		password:  sign.Secret{File: *pwFile, Env: *pwEnv},
		classpath: cp,
		tools:     sign.Tools{Java: *java, Keytool: *keytool, Zipalign: *zipalign, Apksigner: *apksigner},
	}
	if err := req.check(); err != nil {
		fmt.Fprintf(stderr, "raspberry patch: %v\n", err)
		return 1
	}
	if pinBytes != nil {
		fmt.Fprintln(stderr, "raspberry patch: WARNING: embedding a developer certificate pin; this is a lab build, not a normal build")
	}
	if err := buildAPK(context.Background(), req, stdout); err != nil {
		fmt.Fprintf(stderr, "raspberry patch: %v\n", err)
		return 1
	}
	return 0
}

type artifacts struct {
	build   string
	patches string
}

func (a artifacts) native(abi string) string {
	return filepath.Join(a.build, "native", abi, "libraspberry.so")
}

func (a artifacts) classes5() string {
	return filepath.Join(a.build, "dex", "classes5.dex")
}

func (a artifacts) table(name string) string {
	return filepath.Join(a.patches, name)
}

type buildRequest struct {
	apk       string
	outDir    string
	endpoint  []byte
	pin       []byte
	build     artifacts
	keystore  string
	alias     string
	password  sign.Secret
	classpath string
	tools     sign.Tools
}

// check fails before any long step: output safety, then every artifact, tool and the keystore.
func (r buildRequest) check() error {
	if err := refusePrivate(r.outDir, filepath.Join(r.outDir, outputName), r.keystore); err != nil {
		return err
	}
	for _, p := range []struct{ what, path string }{
		{"--build native/arm64-v8a", r.build.native("arm64-v8a")},
		{"--build native/armeabi-v7a", r.build.native("armeabi-v7a")},
		{"--build dex/classes5.dex", r.build.classes5()},
		{"--patches libgame-arm64.tbl", r.build.table("libgame-arm64.tbl")},
		{"--patches libgame-armv7.tbl", r.build.table("libgame-armv7.tbl")},
		{"--java", r.tools.Java},
		{"--keytool", r.tools.Keytool},
		{"--zipalign", r.tools.Zipalign},
		{"--apksigner", r.tools.Apksigner},
		{"--keystore", r.keystore},
	} {
		if err := regularFile(p.path); err != nil {
			return fmt.Errorf("%s: %w", p.what, err)
		}
	}
	if st, err := os.Stat(r.outDir); err != nil {
		return err
	} else if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", r.outDir)
	}
	if _, err := os.Lstat(filepath.Join(r.outDir, outputName)); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite", filepath.Join(r.outDir, outputName))
	}
	return checkClasspath(r.classpath)
}

func regularFile(path string) error {
	if path == "" {
		return errors.New("path is empty; set the flag or its environment variable")
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

// checkClasspath accepts "dir;dir/lib/*" with every directory present.
func checkClasspath(cp string) error {
	if cp == "" {
		return errors.New("empty dexpatch classpath")
	}
	for _, part := range filepath.SplitList(cp) {
		dir := strings.TrimSuffix(part, "*")
		if dir == "" {
			return fmt.Errorf("bad classpath entry %q", part)
		}
		if st, err := os.Stat(dir); err != nil {
			return err
		} else if !st.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
	}
	return nil
}

func buildAPK(ctx context.Context, req buildRequest, stdout io.Writer) error {
	arm64, err := patch.LoadTable(req.build.table("libgame-arm64.tbl"))
	if err != nil {
		return err
	}
	armv7, err := patch.LoadTable(req.build.table("libgame-armv7.tbl"))
	if err != nil {
		return err
	}
	classes5, err := os.ReadFile(req.build.classes5())
	if err != nil {
		return err
	}
	so64, err := os.ReadFile(req.build.native("arm64-v8a"))
	if err != nil {
		return err
	}
	so32, err := os.ReadFile(req.build.native("armeabi-v7a"))
	if err != nil {
		return err
	}

	zr, err := zip.OpenReader(req.apk)
	if err != nil {
		return err
	}
	index := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		index[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f := index[name]
		if f == nil {
			return nil, fmt.Errorf("apk entry missing: %s", name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	lib64, err := read("lib/arm64-v8a/libgame.so")
	if err != nil {
		zr.Close()
		return err
	}
	lib32, err := read("lib/armeabi-v7a/libgame.so")
	if err != nil {
		zr.Close()
		return err
	}
	classes3, err := read("classes3.dex")
	zr.Close()
	if err != nil {
		return err
	}
	new64, err := patch.Apply(lib64, arm64)
	if err != nil {
		return err
	}
	new32, err := patch.Apply(lib32, armv7)
	if err != nil {
		return err
	}

	scratch, err := makeScratch()
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	in := filepath.Join(scratch, "classes3.dex")
	patched := filepath.Join(scratch, "classes3.patched.dex")
	if err := os.WriteFile(in, classes3, 0o600); err != nil {
		return err
	}
	tool := patch.DexTool{JavaExe: req.tools.Java, Classpath: req.classpath, Timeout: 5 * time.Minute}
	if err := tool.PatchClasses3(ctx, in, patched); err != nil {
		return err
	}
	// internal/patch exports patch only. The Java tool's verify command is the
	// semantic check; call it before any APK bytes are assembled.
	if err := verifyClasses3(ctx, req.tools.Java, req.classpath, in, patched); err != nil {
		return err
	}
	classes3New, err := os.ReadFile(patched)
	if err != nil {
		return err
	}

	additions := map[string][]byte{
		"classes5.dex":                    classes5,
		"lib/arm64-v8a/libraspberry.so":   so64,
		"lib/armeabi-v7a/libraspberry.so": so32,
		endpointAsset:                     req.endpoint,
	}
	if req.pin != nil {
		additions[devPinAsset] = req.pin
	}
	replacements := map[string][]byte{
		"lib/arm64-v8a/libgame.so":   new64,
		"lib/armeabi-v7a/libgame.so": new32,
		"classes3.dex":               classes3New,
	}
	unsigned := filepath.Join(scratch, "unsigned.apk")
	if err := apk.Repack(req.apk, unsigned, apk.Options{
		StripSignatures: true,
		Replacements:    replacements,
		Additions:       additions,
	}); err != nil {
		return err
	}

	final := filepath.Join(req.outDir, outputName)
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite", final)
	}
	if _, err := sign.SignAndVerify(ctx, sign.SignRequest{
		Tools:    req.tools,
		Input:    unsigned,
		Output:   final,
		Keystore: req.keystore,
		Alias:    req.alias,
		Password: req.password,
		Timeout:  10 * time.Minute,
	}); err != nil {
		return err
	}
	sum, size, err := fileDigest(final)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "patch: wrote %s (%d bytes, sha256 %s)\n", final, size, sum)
	return nil
}

// makeScratch keeps APK-derived intermediates under the project scratch tree,
// never inside a git worktree.
func makeScratch() (string, error) {
	base := filepath.Join(os.TempDir(), "opencode", "raspberry")
	if err := refusePrivate(base); err != nil {
		return "", err
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(base, "patch-")
}

// verifyClasses3 runs dexpatch's verify command. Same classpath as patch.
func verifyClasses3(ctx context.Context, javaExe, classpath, original, patched string) error {
	if javaExe == "" || classpath == "" {
		return errors.New("dex verify: java or classpath unset")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, javaExe, "-cp", classpath, patch.DexMain, "verify", "--original", original, "--patched", patched)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dex verify: %s", commandTail(err, buf.String()))
	}
	return nil
}

func commandTail(err error, text string) string {
	msg := err.Error()
	fields := strings.Fields(text)
	tail := strings.Join(fields, " ")
	if len(tail) > 180 {
		tail = tail[len(tail)-180:]
	}
	if tail == "" {
		return msg
	}
	return msg + ": " + tail
}

// refusePrivate rejects an output or key path that is relative, a symlink
// ancestor, or inside any git worktree. Sign still enforces this at publish.
func refusePrivate(paths ...string) error {
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := outsideWorktree(path); err != nil {
			return err
		}
	}
	return nil
}

func outsideWorktree(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path outside every git repository", path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	abs = filepath.Clean(abs)
	vol := filepath.VolumeName(abs)
	rest := strings.TrimPrefix(strings.TrimPrefix(abs, vol), string(filepath.Separator))
	cur := vol + string(filepath.Separator)
	var existed []string
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%s is not a clean path", path)
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlink rejected", path)
		}
		existed = append(existed, cur)
	}
	for _, dir := range append([]string{abs}, existed...) {
		if strings.EqualFold(filepath.Base(dir), ".git") {
			return fmt.Errorf("%s is inside a git directory", path)
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return fmt.Errorf("%s is inside a git repository", path)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			continue
		}
		if _, err := os.Lstat(filepath.Join(parent, ".git")); err == nil {
			return fmt.Errorf("%s is inside a git repository", path)
		}
	}
	return nil
}

func fileDigest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// javaTool finds a JDK binary. JAVA_HOME on this host may point at bin/.
func javaTool(name string) string {
	home := os.Getenv("JAVA_HOME")
	if home == "" {
		return ""
	}
	for _, p := range []string{filepath.Join(home, "bin", name), filepath.Join(home, name)} {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return filepath.Join(home, "bin", name)
}

func sdkTool(rel string) string {
	sdk := os.Getenv("ANDROID_SDK_ROOT")
	if sdk == "" {
		sdk = os.Getenv("ANDROID_HOME")
	}
	if sdk == "" {
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			return ""
		}
		sdk = filepath.Join(local, "Android", "Sdk")
	}
	return filepath.Join(sdk, rel)
}

// defaultDexClasspath is what scripts/build-dexpatch.ps1 produces, plus the
// pinned smali 3.0.10 runtime jars.
func defaultDexClasspath(build string) string {
	parts := []string{filepath.Join(build, "dexpatch")}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		parts = append(parts, filepath.Join(local, "Raspberry", "tools", "smali", "3.0.10", "lib", "*"))
	}
	return strings.Join(parts, string(os.PathListSeparator))
}
