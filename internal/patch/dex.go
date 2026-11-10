package patch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode"
)

const (
	// DexMain is the dexpatch tool's entry class.
	DexMain = "dev.raspberry.dexpatch.Main"
	// HelperType is the classes5 type the DEX edits invoke.
	HelperType = "Ldev/raspberry/Raspberry;"
)

// DexEdit is one classes3 method the Java tool rewrites. Signatures only.
type DexEdit struct {
	Class string
	Name  string
	Proto string
	Kind  string
}

// Classes3Edits is the method set tools/dexpatch changes. Anything else in
// classes3 must stay semantically identical.
func Classes3Edits() []DexEdit {
	return []DexEdit{
		{Class: "Ljp/naver/lineplay/login/LoginAdapter;", Name: "InfoDeviceUUID", Proto: "()Ljava/lang/String;", Kind: "replace-body"},
		{Class: "Ljp/naver/lineplay/android/LinePlay$5;", Name: "run", Proto: "()V", Kind: "gate-and-hook"},
		{Class: "Ljp/naver/lineplay/login/LoginAdapter;", Name: "LoginAppToApp", Proto: "()V", Kind: "return-void"},
		{Class: "Ljp/naver/lineplay/login/LoginAdapter;", Name: "LoginWeb", Proto: "()V", Kind: "return-void"},
		{Class: "Lcom/nhnarts/message/PfHandler;", Name: "LoginAppToAppMessage", Proto: "(Landroid/os/Message;)V", Kind: "return-void"},
		{Class: "Lcom/nhnarts/message/PfHandler;", Name: "LoginWebMessage", Proto: "(Landroid/os/Message;)V", Kind: "return-void"},
		{Class: "Lcom/nhnarts/message/PfHandler;", Name: "LoginBandMessage", Proto: "(Landroid/os/Message;)V", Kind: "return-void"},
		{Class: "Lcom/nhnarts/message/PfHandler;", Name: "LoginNaverId", Proto: "(Landroid/os/Message;)V", Kind: "return-void"},
		{Class: "Ljp/naver/lineplay/android/LinePlay;", Name: "grantedFacebookJNI", Proto: "()V", Kind: "return-void"},
		{Class: "Ljp/naver/lineplay/android/LinePlay;", Name: "onActivityResult", Proto: "(IILandroid/content/Intent;)V", Kind: "skip-request-20000"},
		{Class: "Ljp/naver/lineplay/android/LinePlay;", Name: "updateURLFromUiThread", Proto: "(Ljava/lang/String;)V", Kind: "rewrite-arg"},
		{Class: "Ljp/naver/lineplay/android/LinePlay;", Name: "updateURLSubWebViewFromUiThread", Proto: "(Ljava/lang/String;)V", Kind: "rewrite-arg"},
		{Class: "Ljp/naver/common/android/notice/util/LanLinkUtil;", Name: "setCookieNLoadUrl", Proto: "(Landroid/webkit/WebView;Ljava/lang/String;)V", Kind: "rewrite-arg"},
		{Class: "Ljp/naver/lineplay/android/LinePlay;", Name: "openWebBrowserInGLThread", Proto: "(Ljava/lang/String;)V", Kind: "rewrite-arg"},
	}
}

// DexTool runs the compiled dexpatch program. JavaExe and Classpath are explicit.
type DexTool struct {
	JavaExe   string
	Classpath string
	Timeout   time.Duration
	run       commandRunner
}

type commandRunner func(ctx context.Context, name string, args []string) (stderr string, err error)

// PatchClasses3 runs `patch --in --out` against a classes3 image. inPath is
// hashed by the Java tool; this wrapper only checks size so a wrong file fails
// before the JVM starts. Errors are exit status plus a short printable stderr
// tail, never file bytes.
func (t DexTool) PatchClasses3(ctx context.Context, inPath, outPath string) error {
	st, err := os.Stat(inPath)
	if err != nil {
		return err
	}
	if st.Size() != Classes3Size {
		return fmt.Errorf("%w: classes3 size %d", ErrHash, st.Size())
	}
	if t.JavaExe == "" || t.Classpath == "" {
		return errors.New("dexpatch: java or classpath unset")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{"-cp", t.Classpath, DexMain, "patch", "--in", inPath, "--out", outPath}
	run := t.run
	if run == nil {
		run = execRunner
	}
	stderr, err := run(ctx, t.JavaExe, args)
	if err == nil {
		return nil
	}
	return fmt.Errorf("dexpatch: %s", sanitize(err, stderr))
}

func execRunner(ctx context.Context, name string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

func sanitize(err error, stderr string) string {
	msg := err.Error()
	tail := printableTail(stderr, 180)
	if tail == "" {
		return msg
	}
	return msg + ": " + tail
}

func printableTail(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\t' || (unicode.IsPrint(r) && r < 0x7f) {
			if r == '\r' || r == '\n' || r == '\t' {
				b.WriteByte(' ')
			} else {
				b.WriteRune(r)
			}
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}
