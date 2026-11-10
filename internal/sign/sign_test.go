package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseICACLS(t *testing.T) {
	out := "C:\\k\\f.txt TESTBOX\\operator:(F)\n\nSuccessfully processed 1 files; Failed processing 0 files\n"
	aces, err := parseICACLS(out, `C:\k\f.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 1 || aces[0].id != `TESTBOX\operator` || aces[0].rights != "(F)" {
		t.Fatalf("%+v", aces)
	}
	wrapped := "C:\\k\\f.txt NT AUTHORITY\\SYSTEM:(I)(F)\n                 BUILTIN\\Administrators:(F)\n                 TESTBOX\\operator:(OI)(CI)(F)\n"
	aces, err = parseICACLS(wrapped, `C:\k\f.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 3 || aces[2].id != `TESTBOX\operator` || aces[2].rights != "(OI)(CI)(F)" || !rightsOK(aces[2].rights) || rightsOK("(N)") {
		t.Fatalf("%+v", aces)
	}
}

func TestLimitBufWriteContract(t *testing.T) {
	var l limitBuf
	big := bytes.Repeat([]byte("a"), (64<<10)+100)
	n, err := l.Write(big)
	if err != nil || n != len(big) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if l.buf.Len() != 64<<10 {
		t.Fatalf("kept %d", l.buf.Len())
	}
	n, err = l.Write([]byte("more"))
	if err != nil || n != 4 || l.buf.Len() != 64<<10 {
		t.Fatalf("overflow n=%d err=%v kept=%d", n, err, l.buf.Len())
	}
}

func TestPasswordFileOneLine(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"s3cret-token", "s3cret-token\n", "s3cret-token\r\n"} {
		path := filepath.Join(dir, "pw")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := lockOwnerOnly(context.Background(), path, false, ""); err != nil {
			t.Fatal(err)
		}
		got, err := loadSecret(context.Background(), Secret{File: path})
		if err != nil || got != "s3cret-token" {
			t.Fatalf("body %q: %q %v", body, got, err)
		}
		os.Remove(path)
	}
	path := filepath.Join(dir, "two")
	if err := os.WriteFile(path, []byte("s3cret-token\nsecond\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := lockOwnerOnly(context.Background(), path, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecret(context.Background(), Secret{File: path}); err == nil {
		t.Fatal("two-line password file accepted")
	}
}

func TestPublish(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publish(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatal("source name remains")
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "apk" {
		t.Fatalf("dst %q %v", b, err)
	}

	src = filepath.Join(dir, "src2")
	if err := os.WriteFile(src, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publish(src, dst); !errors.Is(err, ErrExists) {
		t.Fatalf("exists: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "apk" {
		t.Fatalf("dst replaced: %q", b)
	}
	if b, err := os.ReadFile(src); err != nil || string(b) != "new" {
		t.Fatalf("source not preserved: %q %v", b, err)
	}

	blocker := filepath.Join(dir, "notdir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := publish(src, filepath.Join(blocker, "out")); err == nil {
		t.Fatal("link failure published")
	}
	if b, err := os.ReadFile(src); err != nil || string(b) != "new" {
		t.Fatalf("link failure moved source: %q %v", b, err)
	}
}

func TestUnixOwnerOnlyBits(t *testing.T) {
	if !unixOwnerOnly(0o600, false) || !unixOwnerOnly(0o700, true) {
		t.Fatal("expected owner-only modes")
	}
	if unixOwnerOnly(0o644, false) || unixOwnerOnly(0o755, true) || unixOwnerOnly(0o700, false) {
		t.Fatal("loose or executable mode accepted")
	}
}

func TestRejectPaths(t *testing.T) {
	ctx := context.Background()
	req := KeygenRequest{Alias: "raspberry", Keystore: "rel.p12"}
	if _, err := Keygen(ctx, req); !errors.Is(err, ErrRelative) {
		t.Fatalf("relative: %v", err)
	}
	if _, err := Keygen(ctx, KeygenRequest{Alias: "raspberry", Keystore: `\\?\C:\temp\ks.p12`}); !errors.Is(err, ErrRelative) {
		t.Fatalf("device: %v", err)
	}
	root := repoRoot(t)
	inside := filepath.Join(root, "internal", "sign", "not-created.p12")
	if _, err := Keygen(ctx, KeygenRequest{Alias: "raspberry", Keystore: inside}); !errors.Is(err, ErrRepo) {
		t.Fatalf("repo: %v", err)
	}
	if _, err := os.Lstat(inside); !os.IsNotExist(err) {
		t.Fatal("repo path was created")
	}
	gitDir := filepath.Join(root, ".git", "objects", "sign-not-created")
	if _, err := Keygen(ctx, KeygenRequest{Alias: "raspberry", Keystore: gitDir}); !errors.Is(err, ErrGitDir) {
		t.Fatalf("gitdir: %v", err)
	}
	wt := t.TempDir()
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: /nowhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(ctx, KeygenRequest{Alias: "raspberry", Keystore: filepath.Join(wt, "ks.p12")}); !errors.Is(err, ErrRepo) {
		t.Fatalf("worktree: %v", err)
	}
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(ctx, KeygenRequest{Alias: "raspberry", Keystore: filepath.Join(link, "ks.p12")}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink: %v", err)
	}
	out := filepath.Join(root, "out.apk")
	if _, err := SignAndVerify(ctx, SignRequest{Alias: "raspberry", Output: out}); !errors.Is(err, ErrRepo) {
		t.Fatalf("sign repo out: %v", err)
	}
}

func TestOwnerOnlyLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locked.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lockOwnerOnly(context.Background(), path, false, ""); err != nil {
		t.Fatal(err)
	}
	if err := verifyOwnerOnly(context.Background(), path, false, ""); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", st.Mode().Perm())
		}
	}
}

func TestKeygenAndSignFakes(t *testing.T) {
	tools := buildTools(t)
	pw := "s3cret-token"
	pwPath := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwPath, []byte(pw+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(context.Background(), KeygenRequest{
		Tools:    Tools{Keytool: tools.keytool},
		Keystore: filepath.Join(t.TempDir(), "missing-parent", "dev.p12"),
		Alias:    "raspberry",
		Password: Secret{File: pwPath},
	}); !errors.Is(err, ErrPerm) {
		t.Fatalf("unlocked password file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(tools.dir, "calls.log")); !os.IsNotExist(err) {
		t.Fatal("tool ran before password file was accepted")
	}
	if err := lockOwnerOnly(context.Background(), pwPath, false, ""); err != nil {
		t.Fatal(err)
	}

	ksDir := filepath.Join(t.TempDir(), "keys")
	ks := filepath.Join(ksDir, "dev.p12")
	got, err := Keygen(context.Background(), KeygenRequest{
		Tools:    Tools{Keytool: tools.keytool},
		Keystore: ks,
		Alias:    "raspberry",
		Password: Secret{File: pwPath},
		Timeout:  15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != ks {
		t.Fatalf("got %s", got)
	}
	if err := verifyOwnerOnly(context.Background(), ks, false, ""); err != nil {
		t.Fatal(err)
	}
	if leftover(t, ksDir, ".raspberry-") {
		t.Fatal("scratch left behind")
	}
	recs := readLog(t, tools.dir)
	kt := recs[0]
	if !strings.Contains(kt.Base, "keytool") {
		t.Fatalf("base %s", kt.Base)
	}
	joined := strings.Join(kt.Args, "\n")
	if strings.Contains(joined, pw) || strings.Contains(joined, "pass:"+pw) {
		t.Fatal("password on argv")
	}
	for _, want := range []string{"-keysize", "3072", "-storetype", "PKCS12", "-storepass:file", "-keypass:file", pwPath} {
		if !containsArg(kt.Args, want) {
			t.Fatalf("missing %s in %v", want, kt.Args)
		}
	}

	os.WriteFile(filepath.Join(tools.dir, "fail-keytool"), []byte("1"), 0o644)
	failDir := filepath.Join(t.TempDir(), "failkeys")
	if _, err := Keygen(context.Background(), KeygenRequest{
		Tools:    Tools{Keytool: tools.keytool},
		Keystore: filepath.Join(failDir, "dev.p12"),
		Alias:    "raspberry",
		Password: Secret{File: pwPath},
	}); err == nil {
		t.Fatal("expected keytool failure")
	}
	if _, err := os.Lstat(filepath.Join(failDir, "dev.p12")); !os.IsNotExist(err) {
		t.Fatal("failed keygen published a keystore")
	}
	if leftover(t, failDir, ".raspberry-") {
		t.Fatal("failed keygen left scratch")
	}
	os.Remove(filepath.Join(tools.dir, "fail-keytool"))

	loose := filepath.Join(t.TempDir(), "loose.p12")
	ksBytes, err := os.ReadFile(ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loose, ksBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	logBefore, err := os.ReadFile(filepath.Join(tools.dir, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	looseIn := filepath.Join(t.TempDir(), "loose-in.apk")
	if err := os.WriteFile(looseIn, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = SignAndVerify(context.Background(), SignRequest{
		Tools:    Tools{Keytool: tools.keytool, Java: tools.java, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input:    looseIn,
		Output:   filepath.Join(t.TempDir(), "loose-out.apk"),
		Keystore: loose, Alias: "raspberry", Password: Secret{File: pwPath},
	})
	if !errors.Is(err, ErrPerm) {
		t.Fatalf("loose key: %v", err)
	}
	logAfter, err := os.ReadFile(filepath.Join(tools.dir, "calls.log"))
	if err != nil || !bytes.Equal(logBefore, logAfter) {
		t.Fatal("loose key invoked a tool or changed the log")
	}
	still, err := os.ReadFile(loose)
	if err != nil || !bytes.Equal(still, ksBytes) {
		t.Fatal("loose key bytes changed")
	}
	if err := verifyOwnerOnly(context.Background(), loose, false, ""); err == nil {
		t.Fatal("loose key was chmodded")
	}
	if err := verifyOwnerOnly(context.Background(), ks, false, ""); err != nil {
		t.Fatal(err)
	}

	in := filepath.Join(t.TempDir(), "in.apk")
	inBytes := []byte("apk-bytes-not-a-real-apk")
	if err := os.WriteFile(in, inBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.apk")
	if _, err := os.Lstat(filepath.Join(repoRoot(t), "LICENSE")); err == nil {
		lic := filepath.Join(repoRoot(t), "LICENSE")
		if _, err := requireInput(lic); err != nil {
			t.Fatalf("repo input should be readable: %v", err)
		}
	}
	signed, err := SignAndVerify(context.Background(), SignRequest{
		Tools: Tools{
			Java: tools.java, JavaArgs: JDK25JavaArgs(), Keytool: tools.keytool,
			Zipalign: tools.zipalign, Apksigner: tools.jar,
		},
		Input: in, Output: out, Keystore: ks, Alias: "raspberry",
		Password: Secret{File: pwPath},
		Timeout:  15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signed != out {
		t.Fatalf("signed %s", signed)
	}
	gotBytes, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBytes, append(inBytes, []byte("-signed")...)) {
		t.Fatalf("output %q", gotBytes)
	}
	after, _ := os.ReadFile(in)
	if !bytes.Equal(after, inBytes) {
		t.Fatal("input mutated")
	}
	if _, err := os.Lstat(out + ".idsig"); !os.IsNotExist(err) {
		t.Fatal("idsig published")
	}
	ktRecs := filter(readLog(t, tools.dir), "keytool")
	exp := ktRecs[len(ktRecs)-1]
	if !containsArg(exp.Args, "-exportcert") || !containsArg(exp.Args, "-rfc") || !containsArg(exp.Args, "-storepass:file") || strings.Contains(strings.Join(exp.Args, "\n"), pw) {
		t.Fatalf("export args %v", exp.Args)
	}
	signRecs := filter(readLog(t, tools.dir), "java")
	zipRecs := filter(readLog(t, tools.dir), "zipalign")
	if len(zipRecs) < 3 || len(signRecs) < 2 {
		t.Fatalf("zip %d java %d", len(zipRecs), len(signRecs))
	}
	// last three zipalign calls are this sign: align, check, check
	z := zipRecs[len(zipRecs)-3:]
	if containsArg(z[0].Args, "-c") || !containsArg(z[0].Args, "-P") || !containsArg(z[0].Args, "16") || !containsArg(z[0].Args, "-f") {
		t.Fatalf("align args %v", z[0].Args)
	}
	if !containsArg(z[1].Args, "-c") || !containsArg(z[2].Args, "-c") {
		t.Fatal("missing zipalign -c before publish")
	}
	if exp.At > z[0].At || z[0].At > z[1].At || signRecs[len(signRecs)-2].At > signRecs[len(signRecs)-1].At {
		t.Fatal("command order")
	}
	if z[1].At > signRecs[len(signRecs)-2].At || signRecs[len(signRecs)-1].At > z[2].At {
		t.Fatal("align/sign/verify order")
	}
	js := signRecs[len(signRecs)-2]
	if js.Args[0] != "--enable-native-access=ALL-UNNAMED" {
		t.Fatalf("java args %v", js.Args)
	}
	jarAt := indexArg(js.Args, "-jar")
	if jarAt < 1 || indexArg(js.Args, "--enable-native-access=ALL-UNNAMED") > jarAt {
		t.Fatalf("flag not before -jar: %v", js.Args)
	}
	joined = strings.Join(js.Args, "\n")
	if strings.Contains(joined, pw) {
		t.Fatal("password on sign argv")
	}
	for _, want := range []string{"--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--alignment-preserved", "true", "--min-sdk-version", "23", "--ks-pass", "file:" + pwPath, "--v1-signer-name", "CERT"} {
		if !containsArg(js.Args, want) {
			t.Fatalf("missing %s in %v", want, js.Args)
		}
	}
	if containsArg(js.Args, "--key-pass") || strings.Contains(joined, "--key-pass") {
		t.Fatalf("key-pass would consume a second password line: %v", js.Args)
	}
	if containsArg(signRecs[len(signRecs)-1].Args, "sign") || !containsArg(signRecs[len(signRecs)-1].Args, "verify") || containsArg(signRecs[len(signRecs)-1].Args, "-Werr") {
		t.Fatalf("verify args %v", signRecs[len(signRecs)-1].Args)
	}
	if err := os.WriteFile(filepath.Join(tools.dir, "export-ec"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	ecOut := filepath.Join(t.TempDir(), "ec.apk")
	_, err = SignAndVerify(context.Background(), SignRequest{
		Tools: Tools{Java: tools.java, Keytool: tools.keytool, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input: in, Output: ecOut, Keystore: ks, Alias: "raspberry", Password: Secret{File: pwPath},
	})
	os.Remove(filepath.Join(tools.dir, "export-ec"))
	if !errors.Is(err, ErrKey) || strings.Contains(err.Error(), pw) || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("ec key: %v", err)
	}
	if _, statErr := os.Lstat(ecOut); !os.IsNotExist(statErr) {
		t.Fatal("non-RSA sign published")
	}

	if err := os.WriteFile(filepath.Join(tools.dir, "fail-verify"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	badOut := filepath.Join(t.TempDir(), "bad-verify.apk")
	_, err = SignAndVerify(context.Background(), SignRequest{
		Tools: Tools{Java: tools.java, Keytool: tools.keytool, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input: in, Output: badOut, Keystore: ks, Alias: "raspberry",
		Password: Secret{File: pwPath},
	})
	os.Remove(filepath.Join(tools.dir, "fail-verify"))
	if !errors.Is(err, ErrCheck) || strings.Contains(err.Error(), pw) {
		t.Fatalf("verify failure: %v", err)
	}
	if _, statErr := os.Lstat(badOut); !os.IsNotExist(statErr) {
		t.Fatal("failed verify published output")
	}

	os.WriteFile(filepath.Join(tools.dir, "echo-secret"), []byte("1"), 0o644)
	echoOut := filepath.Join(t.TempDir(), "echo.apk")
	_, err = SignAndVerify(context.Background(), SignRequest{
		Tools: Tools{Java: tools.java, Keytool: tools.keytool, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input: in, Output: echoOut, Keystore: ks, Alias: "raspberry",
		Password: Secret{File: pwPath},
	})
	if !errors.Is(err, ErrSecret) || strings.Contains(err.Error(), pw) {
		t.Fatalf("secret echo: %v", err)
	}
	if echo := filter(readLog(t, tools.dir), "java"); containsArg(echo[len(echo)-1].Args, "--enable-native-access=ALL-UNNAMED") {
		t.Fatal("native-access flag added without JavaArgs")
	}
	if _, statErr := os.Lstat(echoOut); !os.IsNotExist(statErr) {
		t.Fatal("secret failure published output")
	}
	os.Remove(filepath.Join(tools.dir, "echo-secret"))

	pre := filepath.Join(t.TempDir(), "exists.apk")
	os.WriteFile(pre, []byte("keep"), 0o644)
	_, err = SignAndVerify(context.Background(), SignRequest{
		Tools: Tools{Java: tools.java, Keytool: tools.keytool, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input: in, Output: pre, Keystore: ks, Alias: "raspberry",
		Password: Secret{File: pwPath},
	})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("clobber: %v", err)
	}
	if b, _ := os.ReadFile(pre); string(b) != "keep" {
		t.Fatal("existing output changed")
	}

	os.WriteFile(filepath.Join(tools.dir, "make-idsig"), []byte("1"), 0o644)
	idsigOut := filepath.Join(t.TempDir(), "idsig.apk")
	if _, err := SignAndVerify(context.Background(), SignRequest{
		Tools: Tools{Java: tools.java, Keytool: tools.keytool, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input: in, Output: idsigOut, Keystore: ks, Alias: "raspberry",
		Password: Secret{File: pwPath},
	}); err == nil || strings.Contains(err.Error(), pw) {
		t.Fatalf("idsig: %v", err)
	}
	if _, statErr := os.Lstat(idsigOut); !os.IsNotExist(statErr) {
		t.Fatal("idsig published")
	}
	os.Remove(filepath.Join(tools.dir, "make-idsig"))

	os.WriteFile(filepath.Join(tools.dir, "sleep"), []byte("1"), 0o644)
	t.Cleanup(func() { os.Remove(filepath.Join(tools.dir, "sleep")) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = SignAndVerify(ctx, SignRequest{
		Tools: Tools{Java: tools.java, Keytool: tools.keytool, Zipalign: tools.zipalign, Apksigner: tools.jar},
		Input: in, Output: filepath.Join(t.TempDir(), "slow.apk"), Keystore: ks, Alias: "raspberry",
		Password: Secret{File: pwPath},
		Timeout:  200 * time.Millisecond,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), pw) {
		t.Fatalf("timeout: %v", err)
	}
}

func TestEnvPasswordNotOnArgv(t *testing.T) {
	tools := buildTools(t)
	pw := "env-s3cret"
	t.Setenv("RASPBERRY_SIGN_PW", pw)
	t.Setenv("SIGN_LEAK", "leak-value")
	if err := os.WriteFile(filepath.Join(tools.dir, "watch-env"), []byte("RASPBERRY_SIGN_PW"), 0o644); err != nil {
		t.Fatal(err)
	}
	ks := filepath.Join(t.TempDir(), "dev.p12")
	if _, err := Keygen(context.Background(), KeygenRequest{
		Tools:    Tools{Keytool: tools.keytool},
		Keystore: ks, Alias: "raspberry",
		Password: Secret{Env: "RASPBERRY_SIGN_PW"},
	}); err != nil {
		t.Fatal(err)
	}
	recs := readLog(t, tools.dir)
	sum := sha256.Sum256([]byte(pw))
	if recs[0].Watch != hex.EncodeToString(sum[:]) || recs[0].Leak {
		t.Fatalf("child env %+v", recs[0])
	}
	joined := strings.Join(recs[0].Args, "\n")
	if strings.Contains(joined, pw) || !containsArg(recs[0].Args, "-storepass:env") || !containsArg(recs[0].Args, "RASPBERRY_SIGN_PW") {
		t.Fatalf("args %v", recs[0].Args)
	}
}

type toolSet struct {
	dir, keytool, zipalign, java, jar string
}

type rec struct {
	Base  string   `json:"base"`
	Args  []string `json:"args"`
	At    int64    `json:"at"`
	Watch string   `json:"watch"`
	Leak  bool     `json:"leak"`
}

func buildTools(t *testing.T) toolSet {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fake\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(fakeSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(src, "fake")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = src
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("build fake: %v\n%s", err, buf.String())
	}
	dir := t.TempDir()
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	ts := toolSet{dir: dir, jar: filepath.Join(dir, "apksigner.jar")}
	ts.keytool = filepath.Join(dir, "keytool"+ext)
	ts.zipalign = filepath.Join(dir, "zipalign"+ext)
	ts.java = filepath.Join(dir, "java"+ext)
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ts.keytool, ts.zipalign, ts.java} {
		if err := os.WriteFile(p, b, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(ts.jar, []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	return ts
}

func readLog(t *testing.T, dir string) []rec {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	var out []rec
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var r rec
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func filter(recs []rec, part string) []rec {
	var out []rec
	for _, r := range recs {
		if strings.Contains(r.Base, part) {
			out = append(out, r)
		}
	}
	return out
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func indexArg(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func leftover(t *testing.T, dir, prefix string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			return true
		}
	}
	return false
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root not found")
		}
		dir = parent
	}
}

const fakeSrc = `package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	dir := filepath.Dir(exe)
	base := strings.ToLower(filepath.Base(exe))
	rec := map[string]any{"base": base, "args": os.Args[1:], "at": time.Now().UnixNano()}
	if b, err := os.ReadFile(filepath.Join(dir, "watch-env")); err == nil {
		name := strings.TrimSpace(string(b))
		if v, ok := os.LookupEnv(name); ok {
			sum := sha256.Sum256([]byte(v))
			rec["watch"] = hex.EncodeToString(sum[:])
		}
	}
	if _, ok := os.LookupEnv("SIGN_LEAK"); ok {
		rec["leak"] = true
	}
	if f, err := os.OpenFile(filepath.Join(dir, "calls.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		b, _ := json.Marshal(rec)
		f.Write(append(b, '\n'))
		f.Close()
	}
	if _, err := os.Stat(filepath.Join(dir, "sleep")); err == nil {
		time.Sleep(5 * time.Second)
	}
	args := os.Args[1:]
	if strings.Contains(base, "keytool") {
		if has(args, "-exportcert") {
			kind := "rsa"
			if _, err := os.Stat(filepath.Join(dir, "export-ec")); err == nil {
				kind = "ec"
			}
			if _, err := os.Stat(filepath.Join(dir, "export-small")); err == nil {
				kind = "small"
			}
			out := flagVal(args, "-file")
			if out == "" || writeCert(out, kind) != nil {
				os.Exit(2)
			}
			return
		}
		if has(args, "-genkeypair") {
			if ks := flagVal(args, "-keystore"); ks != "" {
				os.WriteFile(ks, []byte("keystore-bytes"), 0o644)
			}
			if _, err := os.Stat(filepath.Join(dir, "fail-keytool")); err == nil {
				os.Exit(1)
			}
			os.Stderr.WriteString("WARNING: Generating key\n")
			return
		}
		os.Exit(2)
	}
	if strings.Contains(base, "zipalign") {
		if has(args, "-c") {
			if _, err := os.Stat(filepath.Join(dir, "fail-check")); err == nil {
				os.Exit(1)
			}
			return
		}
		if len(args) < 2 {
			os.Exit(2)
		}
		in, out := args[len(args)-2], args[len(args)-1]
		b, err := os.ReadFile(in)
		if err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(out, b, 0o644); err != nil {
			os.Exit(3)
		}
		return
	}
	if _, err := os.Stat(filepath.Join(dir, "echo-secret")); err == nil {
		os.Stderr.WriteString(readPW(args))
		os.Exit(1)
	}
	os.Stderr.WriteString("WARNING: A restricted method in java.lang.System has been called\n")
	if has(args, "verify") {
		os.Stderr.WriteString("WARNING: META-INF/com/android/build/gradle/app-metadata.properties not protected by signature.\n")
		if _, err := os.Stat(filepath.Join(dir, "fail-verify")); err == nil {
			os.Exit(1)
		}
		return
	}
	in, out := flagVal(args, "--in"), flagVal(args, "--out")
	if in == "" || out == "" {
		os.Exit(2)
	}
	b, err := os.ReadFile(in)
	if err != nil {
		os.Exit(3)
	}
	if err := os.WriteFile(out, append(b, []byte("-signed")...), 0o644); err != nil {
		os.Exit(3)
	}
	if _, err := os.Stat(filepath.Join(dir, "make-idsig")); err == nil {
		os.WriteFile(out+".idsig", []byte("idsig"), 0o644)
	}
}

func has(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func flagVal(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func writeCert(path, kind string) error {
	var (
		pub  any
		priv any
	)
	switch kind {
	case "ec":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		pub, priv = &k.PublicKey, k
	case "small":
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return err
		}
		pub, priv = &k.PublicKey, k
	default:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		pub, priv = &k.PublicKey, k
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func readPW(args []string) string {
	for i, a := range args {
		if strings.HasPrefix(a, "file:") {
			b, _ := os.ReadFile(strings.TrimPrefix(a, "file:"))
			return string(b)
		}
		if (a == "-storepass:file" || a == "-keypass:file") && i+1 < len(args) {
			b, _ := os.ReadFile(args[i+1])
			return string(b)
		}
	}
	return ""
}
`
