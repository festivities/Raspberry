package patch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPKPlan(t *testing.T) {
	plan := APKPlan()
	if len(plan) != 8 {
		t.Fatalf("len %d", len(plan))
	}
	wantReplace := map[string]string{
		"lib/arm64-v8a/libgame.so":   LibgameArm64SHA,
		"lib/armeabi-v7a/libgame.so": LibgameArmv7SHA,
		"classes3.dex":               Classes3SHA,
		"AndroidManifest.xml":        ManifestSHA,
	}
	wantAdd := map[string]bool{
		"classes5.dex":                    true,
		"lib/arm64-v8a/libraspberry.so":   true,
		"lib/armeabi-v7a/libraspberry.so": true,
		"assets/raspberry/endpoint.json":  true,
	}
	for _, e := range plan {
		if sha, ok := wantReplace[e.Name]; ok {
			if e.Kind != Replace || e.InputSHA256 != sha {
				t.Fatalf("replace %+v", e)
			}
			delete(wantReplace, e.Name)
			continue
		}
		if wantAdd[e.Name] {
			if e.Kind != Add || e.InputSHA256 != "" {
				t.Fatalf("add %+v", e)
			}
			delete(wantAdd, e.Name)
			continue
		}
		t.Fatalf("unexpected %+v", e)
	}
	if len(wantReplace) != 0 || len(wantAdd) != 0 {
		t.Fatalf("missing %v %v", wantReplace, wantAdd)
	}
}

func TestClasses3EditsCoverHelperCalls(t *testing.T) {
	var gate, rewrite, noop, noticeOpen, noticeContext, noticePrepare int
	wantNotice := map[string]string{
		"Ljp/naver/common/android/notice/commons/CustomSimpleHttpClient;->get(Ljava/lang/String;Ljava/util/List;)Ljava/io/InputStream;":                                "notice-open-connection",
		"Ljp/naver/common/android/notice/notification/ImageDownloadTask;->downloadImage()[B":                                                                           "notice-open-connection",
		"Ljp/naver/common/android/notice/log/ErrorLogAPIImpl;->sendFailLog(Ljava/lang/String;Ljava/lang/String;)Z":                                                     "notice-open-connection",
		"Ljp/naver/lineplay/android/LineplayApplication;->initNotice()V":                                                                                               "notice-context-capture",
		"Ljp/naver/common/android/notice/notification/NotificationTask;->doInBackground([Ljava/lang/Void;)Ljp/naver/common/android/notice/model/NoticeCallbackResult;": "notice-prepare",
	}
	for _, e := range Classes3Edits() {
		switch e.Kind {
		case "gate-and-hook":
			gate++
		case "rewrite-arg":
			rewrite++
		case "return-void":
			noop++
		case "notice-open-connection":
			noticeOpen++
		case "notice-context-capture":
			noticeContext++
		case "notice-prepare":
			noticePrepare++
		}
		if e.Class == "" || e.Name == "" || e.Proto == "" {
			t.Fatalf("incomplete %+v", e)
		}
		key := e.Class + "->" + e.Name + e.Proto
		if kind, ok := wantNotice[key]; ok {
			if kind != e.Kind {
				t.Fatalf("notice edit %s kind %s", key, e.Kind)
			}
			delete(wantNotice, key)
		}
	}
	if gate != 1 || rewrite != 4 || noop != 7 || noticeOpen != 3 || noticeContext != 1 || noticePrepare != 1 || len(wantNotice) != 0 {
		t.Fatalf("gate %d rewrite %d noop %d noticeOpen %d noticeContext %d noticePrepare %d missing %v",
			gate, rewrite, noop, noticeOpen, noticeContext, noticePrepare, wantNotice)
	}
	if HelperType != "Ldev/raspberry/Raspberry;" {
		t.Fatal(HelperType)
	}
}

func TestPatchClasses3SanitizesFailure(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "classes3.dex")
	if err := os.WriteFile(in, make([]byte, Classes3Size), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "SECRETBYTES" + strings.Repeat("A", 40)
	tool := DexTool{
		JavaExe:   "java",
		Classpath: "cp",
		Timeout:   time.Second,
		run: func(ctx context.Context, name string, args []string) (string, error) {
			if name != "java" || !strings.Contains(strings.Join(args, " "), "patch") {
				t.Fatalf("cmd %s %v", name, args)
			}
			return secret + strings.Repeat("x", 400) + " \x00\xff tail", errors.New("exit status 1")
		},
	}
	err := tool.PatchClasses3(context.Background(), in, filepath.Join(dir, "out.dex"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("stderr not truncated: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\x00") {
		t.Fatal("nonprintable leaked")
	}
}

func TestPatchClasses3RejectsSize(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "classes3.dex")
	if err := os.WriteFile(in, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	tool := DexTool{JavaExe: "java", Classpath: "cp", run: func(context.Context, string, []string) (string, error) {
		t.Fatal("should not exec")
		return "", nil
	}}
	err := tool.PatchClasses3(context.Background(), in, filepath.Join(dir, "out.dex"))
	if !errors.Is(err, ErrHash) {
		t.Fatalf("got %v", err)
	}
}
