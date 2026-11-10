// Package sign creates an owner-only RSA PKCS#12 keystore and signs an APK
// with the caller's JDK keytool, zipalign, and apksigner.jar.
//
// Tool paths are explicit. This package does not search PATH, JAVA_HOME, or
// the Android SDK. Passwords are never placed on an argv, and tool output
// that contains a password is returned as ErrSecret with the value removed.
// A non-empty stderr with exit status 0 is not a failure: JDK 25's
// apksigner.jar prints a native-access warning and still succeeds. Callers
// on JDK 25+ may set Tools.JavaArgs to JDK25JavaArgs(); older JDKs reject
// that flag, so it is never added automatically.
//
// Verify does not pass -Werr. API 23 still needs a JAR v1 signature, and v1
// does not cover META-INF/*.version entries, so apksigner warns that those
// stock entries are not protected by the JAR signature. v2 and v3 cover the
// whole APK. The warning is not a failure and the entries are left in place.
// A non-zero verify status is the signature failure.
//
// SignAndVerify is deterministic for the same input bytes, RSA key, alias,
// and tool versions: alignment is zipalign -P 16 -f 4, v1+v2+v3 are on, v4
// is off (no .idsig), and the argv has no timestamp. An operator keystore is
// accepted only after keytool -exportcert shows an RSA key of at least 2048
// bits. Keygen itself is not deterministic.
//
// Output, keystore, and password-file paths must be absolute and outside
// every git worktree, including a worktree whose .git entry is a file.
// Symlink ancestors are rejected rather than followed.
package sign

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	keyBits      = 3072
	validityDays = 10000
	certDN       = "CN=Raspberry"
	minSDK       = 23
	v1Name       = "CERT"

	// DefaultTimeout is the per-command limit when a request leaves Timeout unset.
	DefaultTimeout = 2 * time.Minute
)

var (
	ErrRelative     = errors.New("sign: path must be absolute")
	ErrRepo         = errors.New("sign: path is inside a git repository")
	ErrGitDir       = errors.New("sign: path is inside a .git directory")
	ErrSymlink      = errors.New("sign: symlink path rejected")
	ErrExists       = errors.New("sign: destination exists")
	ErrPerm         = errors.New("sign: owner-only permission check failed")
	ErrSecret       = errors.New("sign: tool output contained a secret")
	ErrInputChanged = errors.New("sign: input file changed")
	ErrDistinct     = errors.New("sign: paths must be distinct")
	ErrCheck        = errors.New("sign: alignment or signature check failed")
	ErrKey          = errors.New("sign: keystore key is not RSA of at least 2048 bits")
)

// JDK25JavaArgs is the JVM flag that silences the JDK 25+ native-access
// warning from apksigner.jar. Pass it as Tools.JavaArgs only when the
// caller's java is JDK 25 or newer.
func JDK25JavaArgs() []string {
	return []string{"--enable-native-access=ALL-UNNAMED"}
}

// Tools are absolute paths. Apksigner is apksigner.jar, not the .bat launcher.
// JavaArgs, if set, are inserted before -jar. Keytool is required for Keygen
// and for SignAndVerify (certificate export). SignAndVerify does not change
// the keystore's permissions.
type Tools struct {
	Java      string
	JavaArgs  []string
	Keytool   string
	Zipalign  string
	Apksigner string
}

// Secret is a password file or an environment variable, never both.
// File must already be owner-only and hold one password line. That password
// is both the PKCS#12 store password and the key password. Env is copied
// only into the tool child.
type Secret struct {
	File string
	Env  string
}

// KeygenRequest creates a new PKCS#12 keystore. Keystore's parent is created
// owner-only when it is missing. An existing keystore is never overwritten.
type KeygenRequest struct {
	Tools    Tools
	Keystore string
	Alias    string
	Password Secret
	Timeout  time.Duration
}

// SignRequest aligns Input, signs it, verifies the signature, and publishes
// Output. Input is opened read-only and must be unchanged at the end.
// Output's parent must already exist. Output is never overwritten.
// Keystore must already be owner-only; a loose key is refused and not chmodded.
// Sign passes only --ks-pass. apksigner reads one line per file: option, so
// a second --key-pass on the same file hits EOF. With --key-pass omitted it
// reuses the keystore password, which matches this PKCS#12.
type SignRequest struct {
	Tools    Tools
	Input    string
	Output   string
	Keystore string
	Alias    string
	Password Secret
	Timeout  time.Duration
}

// Keygen writes a 3072-bit RSA PKCS#12 keystore and returns its path.
func Keygen(ctx context.Context, req KeygenRequest) (string, error) {
	if !validAlias(req.Alias) {
		return "", fmt.Errorf("sign: invalid alias")
	}
	ks, err := rejectUnsafe(req.Keystore)
	if err != nil {
		return "", err
	}
	if st, err := os.Lstat(ks); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w", ErrSymlink)
		}
		return "", fmt.Errorf("%w", ErrExists)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	keytool, err := requireTool(req.Tools.Keytool)
	if err != nil {
		return "", err
	}
	secret, err := loadSecret(ctx, req.Password)
	if err != nil {
		return "", err
	}
	pwPath := ""
	if req.Password.File != "" {
		pwPath, err = cleanAbs(req.Password.File)
		if err != nil {
			return "", err
		}
	}
	if err := distinct(ks, pwPath, keytool); err != nil {
		return "", err
	}
	if containsSecret(ks, secret) || containsSecret(req.Alias, secret) || containsSecret(pwPath, secret) {
		return "", fmt.Errorf("sign: path contains the password")
	}
	var rb rollback
	ok := false
	defer func() {
		if !ok {
			rb.run()
		}
	}()
	parent := filepath.Dir(ks)
	if err := mkdirOwner(ctx, parent, &rb, secret); err != nil {
		return "", err
	}
	scratch, err := scratchDir(ctx, parent, secret)
	if err != nil {
		return "", err
	}
	defer removeScratch(scratch)
	tmp := filepath.Join(scratch, "keystore.p12")
	mode, arg, envName := secretSpec(req.Password)
	if mode == "file" {
		arg = pwPath
	}
	extra := map[string]string{}
	if envName != "" {
		extra[envName] = secret
	}
	argv := []string{
		keytool, "-genkeypair",
		"-alias", req.Alias,
		"-keyalg", "RSA",
		"-keysize", fmt.Sprint(keyBits),
		"-sigalg", "SHA384withRSA",
		"-keystore", tmp,
		"-storetype", "PKCS12",
		"-storepass:" + mode, arg,
		"-keypass:" + mode, arg,
		"-dname", certDN,
		"-validity", fmt.Sprint(validityDays),
		"-J-Djava.io.tmpdir=" + scratch,
	}
	if err := runTool(ctx, timeoutOr(req.Timeout), "keytool", argv, extra, scratch, secret); err != nil {
		return "", err
	}
	st, err := os.Lstat(tmp)
	if err != nil {
		return "", fmt.Errorf("sign: keytool did not create a keystore")
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return "", fmt.Errorf("sign: keytool did not create a keystore")
	}
	if err := lockOwnerOnly(ctx, tmp, false, secret); err != nil {
		return "", err
	}
	if err := publish(tmp, ks); err != nil {
		return "", err
	}
	rb.file(ks)
	if err := verifyOwnerOnly(ctx, ks, false, secret); err != nil {
		return "", err
	}
	ok = true
	return ks, nil
}

// SignAndVerify aligns, signs, checks alignment, verifies, then publishes.
func SignAndVerify(ctx context.Context, req SignRequest) (string, error) {
	if !validAlias(req.Alias) {
		return "", fmt.Errorf("sign: invalid alias")
	}
	out, err := destAvailable(req.Output)
	if err != nil {
		return "", err
	}
	in, err := requireInput(req.Input)
	if err != nil {
		return "", err
	}
	ks, err := requireRegular(req.Keystore)
	if err != nil {
		return "", err
	}
	if err := verifyOwnerOnly(ctx, ks, false, ""); err != nil {
		return "", err
	}
	java, err := requireTool(req.Tools.Java)
	if err != nil {
		return "", err
	}
	keytool, err := requireTool(req.Tools.Keytool)
	if err != nil {
		return "", err
	}
	zipalign, err := requireTool(req.Tools.Zipalign)
	if err != nil {
		return "", err
	}
	jar, err := requireTool(req.Tools.Apksigner)
	if err != nil {
		return "", err
	}
	secret, err := loadSecret(ctx, req.Password)
	if err != nil {
		return "", err
	}
	if err := validateJavaArgs(req.Tools.JavaArgs, secret); err != nil {
		return "", err
	}
	pwPath := ""
	if req.Password.File != "" {
		pwPath, err = cleanAbs(req.Password.File)
		if err != nil {
			return "", err
		}
	}
	if err := distinct(in, out, ks, pwPath, java, keytool, zipalign, jar); err != nil {
		return "", err
	}
	for _, p := range []string{in, out, ks, pwPath, req.Alias} {
		if containsSecret(p, secret) {
			return "", fmt.Errorf("sign: path contains the password")
		}
	}
	before, err := hashFile(in)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(out)
	scratch, err := scratchDir(ctx, parent, secret)
	if err != nil {
		return "", err
	}
	defer removeScratch(scratch)
	aligned := filepath.Join(scratch, "aligned.apk")
	signed := filepath.Join(scratch, "signed.apk")
	to := timeoutOr(req.Timeout)
	extra := map[string]string{}
	mode, arg, envName := secretSpec(req.Password)
	if mode == "file" {
		arg = pwPath
	} else {
		extra[envName] = secret
	}
	passSpec := mode + ":" + arg
	if err := requireRSA(ctx, to, keytool, ks, req.Alias, mode, arg, scratch, secret, extra); err != nil {
		return "", err
	}
	if err := runTool(ctx, to, "zipalign", []string{
		zipalign, "-P", "16", "-f", "4", in, aligned,
	}, nil, scratch, secret); err != nil {
		return "", err
	}
	if st, err := os.Lstat(aligned); err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return "", fmt.Errorf("sign: zipalign did not write an output")
	}
	if err := checkAlign(ctx, to, zipalign, aligned, scratch, secret); err != nil {
		return "", err
	}
	signArgs := []string{java}
	signArgs = append(signArgs, req.Tools.JavaArgs...)
	signArgs = append(signArgs,
		"-Djava.io.tmpdir="+scratch,
		"-jar", jar, "sign",
		"--ks", ks,
		"--ks-key-alias", req.Alias,
		"--ks-type", "PKCS12",
		"--ks-pass", passSpec,
		"--min-sdk-version", fmt.Sprint(minSDK),
		"--v1-signing-enabled", "true",
		"--v2-signing-enabled", "true",
		"--v3-signing-enabled", "true",
		"--v4-signing-enabled", "false",
		"--alignment-preserved", "true",
		"--v1-signer-name", v1Name,
		"--in", aligned,
		"--out", signed,
	)
	if err := runTool(ctx, to, "apksigner", signArgs, extra, scratch, secret); err != nil {
		return "", err
	}
	if err := rejectIDSig(scratch); err != nil {
		return "", err
	}
	if st, err := os.Lstat(signed); err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return "", fmt.Errorf("sign: apksigner did not write an output")
	}
	verifyArgs := []string{java}
	verifyArgs = append(verifyArgs, req.Tools.JavaArgs...)
	verifyArgs = append(verifyArgs,
		"-Djava.io.tmpdir="+scratch,
		"-jar", jar, "verify",
		"--min-sdk-version", fmt.Sprint(minSDK),
		signed,
	)
	if err := runTool(ctx, to, "apksigner verify", verifyArgs, extra, scratch, secret); err != nil {
		if errors.Is(err, ErrSecret) {
			return "", err
		}
		return "", fmt.Errorf("%w: %v", ErrCheck, err)
	}
	if err := checkAlign(ctx, to, zipalign, signed, scratch, secret); err != nil {
		return "", err
	}
	after, err := hashFile(in)
	if err != nil {
		return "", err
	}
	if before != after {
		return "", fmt.Errorf("%w", ErrInputChanged)
	}
	if err := publish(signed, out); err != nil {
		return "", err
	}
	return out, nil
}

func requireRSA(ctx context.Context, to time.Duration, keytool, ks, alias, mode, arg, scratch, secret string, extra map[string]string) error {
	certPath := filepath.Join(scratch, "cert.pem")
	err := runTool(ctx, to, "keytool -exportcert", []string{
		keytool, "-exportcert", "-rfc",
		"-alias", alias,
		"-keystore", ks,
		"-storetype", "PKCS12",
		"-storepass:" + mode, arg,
		"-file", certPath,
	}, extra, scratch, secret)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("%w", ErrKey)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("%w", ErrKey)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return fmt.Errorf("%w", ErrKey)
	}
	return nil
}

func checkAlign(ctx context.Context, to time.Duration, zipalign, file, scratch, secret string) error {
	err := runTool(ctx, to, "zipalign -c", []string{
		zipalign, "-c", "-P", "16", "4", file,
	}, nil, scratch, secret)
	if err != nil {
		if errors.Is(err, ErrSecret) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrCheck, err)
	}
	return nil
}

func rejectIDSig(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".idsig" {
			return fmt.Errorf("sign: v4 idsig was created; refusing to publish")
		}
	}
	return nil
}
