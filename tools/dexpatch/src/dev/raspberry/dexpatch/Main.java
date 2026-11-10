package dev.raspberry.dexpatch;

import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.base.reference.BaseMethodReference;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.rewriter.DexRewriter;
import com.android.tools.smali.dexlib2.rewriter.MethodRewriter;
import com.android.tools.smali.dexlib2.rewriter.Rewriter;
import com.android.tools.smali.dexlib2.rewriter.RewriterModule;
import com.android.tools.smali.dexlib2.rewriter.Rewriters;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** classes3 editor. Refuses any other digest. Does not copy method bodies out. */
public final class Main {
    static final String CLASSES3_SHA = "a2f4a9551f0671f87c22c09f0a9e27e30b6ffe972359511520515cda2c5603f1";
    static final int INDEX_LIMIT = 65536;

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            System.exit(2);
        }
        switch (args[0]) {
            case "patch" -> patch(flag(args, "--in"), flag(args, "--out"));
            case "verify" -> verify(flag(args, "--original"), flag(args, "--patched"));
            case "selftest" -> SelfTest.run();
            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    static void patch(String in, String out) throws Exception {
        byte[] raw = Files.readAllBytes(new File(in).toPath());
        String sha = sha256(raw);
        if (!CLASSES3_SHA.equals(sha)) {
            throw new IllegalStateException("classes3 hash mismatch");
        }
        DexBackedDexFile input = new DexBackedDexFile(Opcodes.forApi(33), raw);
        Counts before = Counts.of(input);
        DexFile rewritten = new DexRewriter(new Module()).getDexFileRewriter().rewrite(input);
        writeChecked(rewritten, new File(out), before);
        System.out.println("patched ok");
    }

    static void verify(String original, String patched) throws Exception {
        DexFile a = load(original);
        DexFile b = load(patched);
        Map<String, Method> right = index(b);
        int untouched = 0;
        int edited = 0;
        int classes = 0;
        for (ClassDef c : a.getClasses()) {
            classes++;
            for (Method m : c.getMethods()) {
                Method n = right.remove(Semantic.key(m));
                if (n == null) {
                    throw new IllegalStateException("missing " + Semantic.key(m));
                }
                if (Edits.edit(m) != null || isEditedKey(Semantic.key(m))) {
                    checkEdited(m, n);
                    edited++;
                } else if (!Semantic.rows(m.getImplementation()).equals(Semantic.rows(n.getImplementation()))) {
                    throw new IllegalStateException("untouched drift " + Semantic.key(m));
                } else {
                    untouched++;
                }
            }
        }
        if (!right.isEmpty()) {
            throw new IllegalStateException("extra methods " + right.size());
        }
        System.out.println("verify ok classes=" + classes + " untouched=" + untouched + " edited=" + edited);
    }

    static void writeChecked(DexFile dex, File out, Counts before) throws Exception {
        DexPool pool = new DexPool(dex.getOpcodes());
        for (ClassDef c : dex.getClasses()) {
            pool.internClass(c);
        }
        int strings = pool.stringSection.getItemCount();
        int types = pool.typeSection.getItemCount();
        int protos = pool.protoSection.getItemCount();
        int fields = pool.fieldSection.getItemCount();
        int methods = pool.methodSection.getItemCount();
        if (types > INDEX_LIMIT || protos > INDEX_LIMIT || fields > INDEX_LIMIT || methods > INDEX_LIMIT || pool.hasOverflowed()) {
            throw new IllegalStateException("index overflow strings=" + strings + " types=" + types
                    + " protos=" + protos + " fields=" + fields + " methods=" + methods);
        }
        pool.writeTo(new FileDataStore(out));
        DexBackedDexFile written = load(out.getPath());
        Counts after = Counts.of(written);
        System.out.println("capacity before strings=" + before.strings + " types=" + before.types
                + " protos=" + before.protos + " fields=" + before.fields + " methods=" + before.methods
                + " methodFree=" + (INDEX_LIMIT - before.methods));
        System.out.println("capacity after strings=" + after.strings + " types=" + after.types
                + " protos=" + after.protos + " fields=" + after.fields + " methods=" + after.methods
                + " methodFree=" + (INDEX_LIMIT - after.methods)
                + " jumboStrings=" + (after.strings > INDEX_LIMIT));
        if (after.methods > INDEX_LIMIT || after.types > INDEX_LIMIT || after.fields > INDEX_LIMIT || after.protos > INDEX_LIMIT) {
            throw new IllegalStateException("written index overflow");
        }
    }

    static boolean isEditedKey(String key) {
        return switch (key) {
            case "Ljp/naver/lineplay/login/LoginAdapter;->InfoDeviceUUID()Ljava/lang/String;",
                    "Ljp/naver/lineplay/android/LinePlay$5;->run()V",
                    "Ljp/naver/lineplay/login/LoginAdapter;->LoginAppToApp()V",
                    "Ljp/naver/lineplay/login/LoginAdapter;->LoginWeb()V",
                    "Lcom/nhnarts/message/PfHandler;->LoginAppToAppMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginWebMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginBandMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginNaverId(Landroid/os/Message;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->grantedFacebookJNI()V",
                    "Ljp/naver/lineplay/android/LinePlay;->onActivityResult(IILandroid/content/Intent;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->updateURLFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->updateURLSubWebViewFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->openWebBrowserInGLThread(Ljava/lang/String;)V",
                    "Ljp/naver/common/android/notice/util/LanLinkUtil;->setCookieNLoadUrl(Landroid/webkit/WebView;Ljava/lang/String;)V" -> true;
            default -> false;
        };
    }

    static void checkEdited(Method orig, Method patched) {
        String key = Semantic.key(orig);
        List<String> rows = Semantic.rows(patched.getImplementation());
        String joined = String.join("\n", rows);
        switch (key) {
            case "Ljp/naver/lineplay/login/LoginAdapter;->InfoDeviceUUID()Ljava/lang/String;" -> {
                require(joined.contains("INVOKE_STATIC ref=Ljp/naver/lineplay/android/LineplayApplication;->getContext()Landroid/content/Context;"), key);
                require(joined.contains("INVOKE_STATIC ref=" + Refs.HELPER + "->deviceUuid(Landroid/content/Context;)Ljava/lang/String;"), key);
                require(!joined.contains("ANDROID") && !joined.contains("Settings$Secure"), key);
            }
            case "Ljp/naver/lineplay/android/LinePlay$5;->run()V" -> {
                require(joined.contains(Refs.HELPER + "->beforeNative(Landroid/app/Activity;)Z"), key);
                require(joined.contains(Refs.HELPER + "->afterGameLoad(Landroid/app/Activity;)V"), key);
                require(joined.contains("Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z"), key);
                require(joined.contains("Ljava/lang/System;->load(Ljava/lang/String;)V"), key);
                require(joined.contains("Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"), key);
                require(joined.contains("cusCocosInit"), key);
                require(joined.contains("Ljava/lang/Throwable;@"), key);
            }
            case "Ljp/naver/lineplay/android/LinePlay;->onActivityResult(IILandroid/content/Intent;)V" -> {
                int at = Edits.requestCompareIndex(orig, orig.getImplementation(), 20000);
                String before = Semantic.rows(orig.getImplementation()).get(at);
                require(rows.get(at).startsWith("GOTO"), key);
                require(branchTarget(rows.get(at)).equals(branchTarget(before)), key);
                require(!rows.get(at).contains("IF_NE"), key);
            }
            case "Ljp/naver/lineplay/login/LoginAdapter;->LoginAppToApp()V",
                    "Ljp/naver/lineplay/login/LoginAdapter;->LoginWeb()V",
                    "Lcom/nhnarts/message/PfHandler;->LoginAppToAppMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginWebMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginBandMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginNaverId(Landroid/os/Message;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->grantedFacebookJNI()V" -> {
                require(rows.get(0).startsWith("RETURN_VOID"), key);
                require(rows.size() == 1, key);
            }
            case "Ljp/naver/lineplay/android/LinePlay;->updateURLFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->updateURLSubWebViewFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->openWebBrowserInGLThread(Ljava/lang/String;)V",
                    "Ljp/naver/common/android/notice/util/LanLinkUtil;->setCookieNLoadUrl(Landroid/webkit/WebView;Ljava/lang/String;)V" ->
                    checkPrefix(orig, rows, Edits.stringParamIndex(key));
            default -> throw new IllegalStateException("not an edit " + key);
        }
    }

    static void checkPrefix(Method orig, List<String> rows, int paramIndex) {
        String key = Semantic.key(orig);
        int reg = Edits.paramRegister(orig, orig.getImplementation(), paramIndex);
        require(rows.get(0).contains(Refs.HELPER + "->rewrite(Ljava/lang/String;)Ljava/lang/String;"), key);
        require(rows.get(0).contains("n=1:" + reg + ","), key);
        require(("MOVE_RESULT_OBJECT a=" + reg).equals(rows.get(1)), key);
    }

    static String branchTarget(String row) {
        int at = row.indexOf("->");
        if (at < 0) {
            return "";
        }
        int end = at + 2;
        while (end < row.length() && (Character.isDigit(row.charAt(end)) || row.charAt(end) == '-')) {
            end++;
        }
        return row.substring(at, end);
    }

    static void require(boolean ok, String key) {
        if (!ok) {
            throw new IllegalStateException("edit check failed " + key);
        }
    }

    static Map<String, Method> index(DexFile dex) {
        Map<String, Method> out = new HashMap<>();
        for (ClassDef c : dex.getClasses()) {
            for (Method m : c.getMethods()) {
                out.put(Semantic.key(m), m);
            }
        }
        return out;
    }

    static DexBackedDexFile load(String path) throws Exception {
        return new DexBackedDexFile(Opcodes.forApi(33), Files.readAllBytes(new File(path).toPath()));
    }

    static String sha256(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    static String flag(String[] args, String name) {
        for (int i = 0; i + 1 < args.length; i++) {
            if (args[i].equals(name)) {
                return args[i + 1];
            }
        }
        throw new IllegalArgumentException("missing " + name);
    }

    static void usage() {
        System.err.println("usage: Main patch --in classes3.dex --out classes3.patched.dex");
        System.err.println("       Main verify --original classes3.dex --patched classes3.patched.dex");
        System.err.println("       Main selftest");
    }

    static final class Module extends RewriterModule {
        @Override
        public Rewriter<Method> getMethodRewriter(Rewriters rewriters) {
            Rewriter<Method> base = new MethodRewriter(rewriters);
            return value -> {
                MethodImplementation edited = Edits.edit(value);
                if (edited == null) {
                    return base.rewrite(value);
                }
                return new Swap(value, edited);
            };
        }
    }

    static final class Swap extends BaseMethodReference implements Method {
        private final Method base;
        private final MethodImplementation impl;

        Swap(Method base, MethodImplementation impl) {
            this.base = base;
            this.impl = impl;
        }

        public String getDefiningClass() { return base.getDefiningClass(); }
        public String getName() { return base.getName(); }
        public List<? extends MethodParameter> getParameters() { return base.getParameters(); }
        public List<? extends CharSequence> getParameterTypes() { return base.getParameterTypes(); }
        public String getReturnType() { return base.getReturnType(); }
        public int getAccessFlags() { return base.getAccessFlags(); }
        public Set<? extends com.android.tools.smali.dexlib2.iface.Annotation> getAnnotations() { return base.getAnnotations(); }
        public Set<com.android.tools.smali.dexlib2.HiddenApiRestriction> getHiddenApiRestrictions() { return base.getHiddenApiRestrictions(); }
        public MethodImplementation getImplementation() { return impl; }
    }

    static final class Counts {
        final int strings, types, protos, fields, methods;

        Counts(int strings, int types, int protos, int fields, int methods) {
            this.strings = strings;
            this.types = types;
            this.protos = protos;
            this.fields = fields;
            this.methods = methods;
        }

        static Counts of(DexBackedDexFile dex) {
            return new Counts(
                    dex.getStringSection().size(),
                    dex.getTypeSection().size(),
                    dex.getProtoSection().size(),
                    dex.getFieldSection().size(),
                    dex.getMethodSection().size());
        }
    }
}
