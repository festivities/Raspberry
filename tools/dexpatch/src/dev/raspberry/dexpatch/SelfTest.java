package dev.raspberry.dexpatch;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction12x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction20t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Synthetic DEX. No APK. Proves branch targets, try handlers, and the prefix gate survive a write. */
final class SelfTest {
    private SelfTest() {}

    static void run() throws Exception {
        File dir = Files.createTempDirectory("dexpatch-selftest").toFile();
        File dex = new File(dir, "synth.dex");
        Method gate = gateMethod();
        Method hook = hookMethod();
        Method skip = skipMethod();
        Method rewrite = rewriteMethod();
        Method rewriteStatic = rewriteStaticMethod();
        write(dex, List.of(gate, hook, skip, rewrite, rewriteStatic));
        var loaded = Main.load(dex.getPath());
        gate = find(loaded, "gate");
        hook = find(loaded, "hook");
        skip = find(loaded, "skip");
        rewrite = find(loaded, "rewrite");
        rewriteStatic = find(loaded, "rewriteStatic");

        List<String> gateBefore = codeRows(gate);
        List<String> hookBefore = codeRows(hook);
        List<String> skipBefore = codeRows(skip);
        List<String> rewriteBefore = codeRows(rewrite);
        List<String> staticBefore = codeRows(rewriteStatic);

        File out = new File(dir, "synth-patched.dex");
        write(out, List.of(
                copy(gate, Edits.prefixGate(gate.getImplementation(), 11)),
                copy(hook, Edits.insertHookBefore(hook.getImplementation(), "anchor")),
                copy(skip, Edits.skipConstBranch(skip, skip.getImplementation(), 20000)),
                copy(rewrite, Edits.prefixRewrite(rewrite, rewrite.getImplementation(), 0)),
                copy(rewriteStatic, Edits.prefixRewrite(rewriteStatic, rewriteStatic.getImplementation(), 1))));
        var back = Main.load(out.getPath());

        List<String> gateAfter = Semantic.rows(find(back, "gate").getImplementation());
        if (!gateAfter.get(1).contains("beforeNative") || !gateAfter.get(3).contains("->" + Edits.GATE_INSNS)) {
            fail("gate prefix " + gateAfter.get(3));
        }
        if (!gateAfter.subList(Edits.GATE_INSNS, Edits.GATE_INSNS + gateBefore.size()).equals(shift(gateBefore, Edits.GATE_INSNS))) {
            fail("gate tail");
        }
        if (!tryRows(gateAfter).equals(shiftTry(tryRows(Semantic.rows(gate.getImplementation())), Edits.GATE_INSNS))) {
            fail("gate handlers " + tryRows(gateAfter));
        }

        List<String> hookAfter = Semantic.rows(find(back, "hook").getImplementation());
        int anchor = indexOf(hookBefore, "anchor");
        if (!hookAfter.get(anchor - 1).startsWith("IGET") || !hookAfter.get(anchor).contains("afterGameLoad")) {
            fail("hook insert point anchor=" + anchor + " prev=" + hookAfter.get(anchor - 1) + " at=" + hookAfter.get(anchor));
        }
        if (!hookAfter.get(anchor + Edits.HOOK_INSNS).contains("anchor")) {
            fail("anchor not shifted by hook");
        }
        if (!contains(hookAfter, "Throwable;@")) {
            fail("hook handler missing");
        }
        if (!hookAfter.subList(0, anchor).equals(hookBefore.subList(0, anchor))) {
            fail("hook prefix drift");
        }

        List<String> skipAfter = Semantic.rows(find(back, "skip").getImplementation());
        int compare = Edits.requestCompareIndex(skip, skip.getImplementation(), 20000);
        if (compare == 1 || skipBefore.get(compare - 1).contains("a=0")) {
            fail("unrelated 20000 selected at " + compare);
        }
        if (!skipAfter.get(compare).startsWith("GOTO") || !target(skipAfter.get(compare)).equals(target(skipBefore.get(compare)))) {
            fail("skip target changed " + skipAfter.get(compare) + " vs " + skipBefore.get(compare));
        }
        if (!skipAfter.get(1).startsWith("CONST") || !skipAfter.get(3).startsWith("IF_NE") || !target(skipAfter.get(3)).equals(target(skipBefore.get(3)))) {
            fail("unrelated 20000 rewritten " + skipAfter.subList(0, 4));
        }
        Main.checkEdited(asActivityResult(skip), asActivityResult(find(back, "skip")));

        List<String> rewriteAfter = Semantic.rows(find(back, "rewrite").getImplementation());
        int rewriteReg = Edits.paramRegister(rewrite, rewrite.getImplementation(), 0);
        if (!rewriteAfter.get(0).contains("n=1:" + rewriteReg + ",") || !rewriteAfter.get(1).equals("MOVE_RESULT_OBJECT a=" + rewriteReg)) {
            fail("rewrite register " + rewriteAfter.get(0) + " / " + rewriteAfter.get(1));
        }
        if (!rewriteAfter.subList(Edits.REWRITE_INSNS, Edits.REWRITE_INSNS + rewriteBefore.size()).equals(shift(rewriteBefore, Edits.REWRITE_INSNS))) {
            fail("rewrite tail");
        }
        if (!tryRows(rewriteAfter).equals(shiftTry(tryRows(Semantic.rows(rewrite.getImplementation())), Edits.REWRITE_INSNS))) {
            fail("rewrite handlers " + tryRows(rewriteAfter));
        }

        List<String> staticAfter = Semantic.rows(find(back, "rewriteStatic").getImplementation());
        int stringReg = Edits.paramRegister(rewriteStatic, rewriteStatic.getImplementation(), 1);
        int viewReg = Edits.paramRegister(rewriteStatic, rewriteStatic.getImplementation(), 0);
        if (stringReg == viewReg || !staticAfter.get(0).contains("n=1:" + stringReg + ",") || staticAfter.get(0).contains("n=1:" + viewReg + ",")) {
            fail("static rewrite used v" + viewReg + " not v" + stringReg + " " + staticAfter.get(0));
        }
        if (!staticAfter.get(1).equals("MOVE_RESULT_OBJECT a=" + stringReg)) {
            fail("static move " + staticAfter.get(1));
        }
        if (!staticAfter.subList(Edits.REWRITE_INSNS, Edits.REWRITE_INSNS + staticBefore.size()).equals(shift(staticBefore, Edits.REWRITE_INSNS))) {
            fail("static tail");
        }
        Main.checkEdited(asSetCookie(rewriteStatic), asSetCookie(find(back, "rewriteStatic")));
        try {
            Main.checkEdited(asSetCookie(rewriteStatic), copy(asSetCookie(rewriteStatic), Edits.prefixRewrite(asSetCookie(rewriteStatic), rewriteStatic.getImplementation(), 0)));
            fail("webview register accepted");
        } catch (IllegalStateException e) {
            if (!e.getMessage().contains("edit check failed")) {
                fail(e.getMessage());
            }
        }

        deviceUuidAsserts();
        substringIsNotAnEdit();
        verifyIgnoresSubstring(dir);
        runShape(dir);
        System.out.println("selftest ok");
    }

    private static Method gateMethod() {
        MutableMethodImplementation impl = new MutableMethodImplementation(12);
        impl.addInstruction(Refs.const4(0, 0));
        impl.addInstruction(Refs.newInstance(1, "Ljava/lang/RuntimeException;"));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_DIRECT, Refs.method("Ljava/lang/RuntimeException;", "<init>", List.of(), "V"), 1));
        impl.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        impl.addInstruction(new BuilderInstruction20t(Opcode.GOTO_16, impl.newLabelForIndex(0)));
        impl.addInstruction(Refs.const16(0, 7));
        impl.addInstruction(Refs.retVoid());
        Label join = impl.newLabelForIndex(6);
        Label end = impl.newLabelForIndex(7);
        impl.replaceInstruction(0, new BuilderInstruction21t(Opcode.IF_NEZ, 0, join));
        impl.replaceInstruction(5, new BuilderInstruction20t(Opcode.GOTO_16, end));
        impl.addCatch("Ljava/lang/RuntimeException;", impl.newLabelForIndex(1), impl.newLabelForIndex(4), impl.newLabelForIndex(4));
        return method("gate", "V", List.of(), impl, false);
    }

    private static Method hookMethod() {
        MutableMethodImplementation impl = new MutableMethodImplementation(4);
        impl.addInstruction(Refs.const4(0, 0));
        impl.addInstruction(Refs.const4(1, 1));
        impl.addInstruction(new BuilderInstruction11x(Opcode.THROW, 1));
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        impl.addInstruction(Refs.retVoid());
        impl.addInstruction(Refs.iget(1, 3, new ImmutableFieldReference(
                "Ldev/raspberry/dexpatch/Synth;", "outer", "Landroid/app/Activity;")));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC, Refs.method("Ldev/raspberry/dexpatch/Marker;", "anchor", List.of(), "V")));
        impl.addInstruction(Refs.retVoid());
        Label join = impl.newLabelForIndex(5);
        impl.addInstruction(1, new BuilderInstruction21t(Opcode.IF_EQZ, 0, join));
        impl.addCatch("Ljava/lang/RuntimeException;", impl.newLabelForIndex(3), impl.newLabelForIndex(4), impl.newLabelForIndex(4));
        return method("hook", "V", List.of(), impl, false);
    }

    /** Earlier 20000 constants are not the request-code comparison. Request register is v3. */
    private static Method skipMethod() {
        MutableMethodImplementation impl = new MutableMethodImplementation(6);
        impl.addInstruction(Refs.const16(0, 20000));
        impl.addInstruction(Refs.const4(1, 1));
        impl.addInstruction(Refs.const16(0, 20000));
        impl.addInstruction(Refs.const4(1, 2));
        impl.addInstruction(Refs.retVoid());
        impl.addInstruction(Refs.const16(1, 20000));
        impl.addInstruction(Refs.retVoid());
        impl.addInstruction(Refs.retVoid());
        impl.addInstruction(Refs.const4(0, 3));
        impl.addInstruction(Refs.retVoid());
        Label decoy = impl.newLabelForIndex(4);
        Label notEqual = impl.newLabelForIndex(8);
        impl.replaceInstruction(3, new BuilderInstruction22t(Opcode.IF_NE, 1, 0, decoy));
        impl.replaceInstruction(6, new BuilderInstruction22t(Opcode.IF_NE, 3, 1, notEqual));
        return method("skip", "V", List.of(
                new ImmutableMethodParameter("I", Set(), "requestCode"),
                new ImmutableMethodParameter("I", Set(), "resultCode"),
                new ImmutableMethodParameter("Landroid/content/Intent;", Set(), "data")), impl, false);
    }

    private static Method rewriteMethod() {
        MutableMethodImplementation impl = new MutableMethodImplementation(4);
        impl.addInstruction(Refs.const4(0, 1));
        impl.addInstruction(Refs.const16(1, 5));
        impl.addInstruction(new BuilderInstruction11x(Opcode.THROW, 0));
        impl.addInstruction(Refs.retVoid());
        Label end = impl.newLabelForIndex(3);
        impl.addInstruction(1, new BuilderInstruction21t(Opcode.IF_EQZ, 0, end));
        impl.addCatch("Ljava/lang/RuntimeException;", impl.newLabelForIndex(2), impl.newLabelForIndex(3), impl.newLabelForIndex(3));
        return method("rewrite", "V", List.of(new ImmutableMethodParameter("Ljava/lang/String;", Set(), "url")), impl, false);
    }

    private static Method rewriteStaticMethod() {
        MutableMethodImplementation impl = new MutableMethodImplementation(7);
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC,
                Refs.method("Landroid/net/Uri;", "parse", List.of("Ljava/lang/String;"), "Landroid/net/Uri;"), 6));
        impl.addInstruction(Refs.moveResultObj(0));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_VIRTUAL,
                Refs.method("Landroid/webkit/WebView;", "loadUrl", List.of("Ljava/lang/String;"), "V"), 5, 6));
        impl.addInstruction(Refs.retVoid());
        return method("rewriteStatic", "V", List.of(
                new ImmutableMethodParameter("Landroid/webkit/WebView;", Set(), "view"),
                new ImmutableMethodParameter("Ljava/lang/String;", Set(), "url")), impl, true);
    }

    /**
     * Instance runnable: this is the last register, the body reads v0, an iget sits immediately
     * before the only cusCocosInit, and both load paths join there. Mirrors LinePlay$5.run.
     */
    private static Method runShapeMethod() {
        MutableMethodImplementation impl = new MutableMethodImplementation(12);
        impl.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 1, 0));
        impl.addInstruction(Refs.const4(1, 1));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC,
                Refs.method("Ljava/lang/System;", "load", List.of("Ljava/lang/String;"), "V"), 1));
        impl.addInstruction(Refs.retVoid());
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_VIRTUAL,
                Refs.method("Ljava/lang/UnsatisfiedLinkError;", "printStackTrace", List.of(), "V"), 1));
        impl.addInstruction(Refs.constString(1, "game"));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC,
                Refs.method("Ljava/lang/System;", "loadLibrary", List.of("Ljava/lang/String;"), "V"), 1));
        impl.addInstruction(Refs.iget(1, 11, Refs.OUTER));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_VIRTUAL,
                Refs.method("Ljp/naver/lineplay/android/LinePlay;", "cusCocosInit", List.of(), "V"), 1));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC,
                Refs.method("Ldev/raspberry/dexpatch/Marker;", "keepV0", List.of("I"), "V"), 0));
        impl.addInstruction(Refs.retVoid());
        impl.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 1));
        impl.addInstruction(Refs.retVoid());
        impl.replaceInstruction(3, new BuilderInstruction20t(Opcode.GOTO_16, impl.newLabelForIndex(8)));
        impl.addCatch("Ljava/lang/UnsatisfiedLinkError;",
                impl.newLabelForIndex(2), impl.newLabelForIndex(3), impl.newLabelForIndex(4));
        impl.addCatch("Ljava/lang/UnsatisfiedLinkError;",
                impl.newLabelForIndex(7), impl.newLabelForIndex(8), impl.newLabelForIndex(12));
        int access = AccessFlags.PRIVATE.getValue() | AccessFlags.SYNTHETIC.getValue();
        return new ImmutableMethod("Ldev/raspberry/dexpatch/Synth;", "runShape", List.of(), "V",
                access, java.util.Set.of(), java.util.Set.of(), impl);
    }

    private static void runShape(File dir) throws Exception {
        File dex = new File(dir, "run.dex");
        write(dex, List.of(runShapeMethod()));
        Method orig = find(Main.load(dex.getPath()), "runShape");
        File out = new File(dir, "run-patched.dex");
        write(out, List.of(copy(orig, Edits.runGate(orig.getImplementation()))));
        List<String> rows = Semantic.rows(find(Main.load(out.getPath()), "runShape").getImplementation());
        List<String> code = new ArrayList<>();
        for (String row : rows) {
            if (!row.startsWith("try ")) {
                code.add(row);
            }
        }
        int gate = Edits.GATE_INSNS;
        int hook = Edits.HOOK_INSNS;
        int load = gate + 2;
        int loadGoto = gate + 3;
        int loadHandler = gate + 4;
        int loadLibrary = gate + 7;
        int join = gate + 8;
        int inserted = join + 1;
        int anchor = inserted + hook;
        int keep = anchor + 1;
        int later = gate + 12 + hook;
        if (!code.get(gate - 1).equals("RETURN_VOID") || !target(code.get(3)).equals("->" + gate)) {
            fail("false path does not return before body " + code.get(3) + " / " + code.get(gate - 1));
        }
        for (int i = 4; i < gate - 1; i++) {
            if (code.get(i).startsWith("GOTO") || code.get(i).startsWith("IF_")) {
                fail("false path branches " + code.get(i));
            }
        }
        for (int i = 0; i < gate; i++) {
            if (writes(code.get(i), 0)) {
                fail("true path clobbers v0 " + code.get(i));
            }
        }
        if (!code.get(gate).equals("MOVE a=1 b=0")) {
            fail("original v0 use not preserved " + code.get(gate));
        }
        if (!code.get(keep).contains("keepV0") || !code.get(keep).contains("n=1:0,")) {
            fail("v0 after anchor not preserved " + code.get(keep));
        }
        if (!code.get(inserted + 1).startsWith("GOTO") || !target(code.get(inserted + 1)).equals("->" + anchor)) {
            fail("hook goto misses anchor " + code.get(inserted + 1));
        }
        if (!code.get(inserted + 2).startsWith("MOVE_EXCEPTION") || !code.get(inserted + 2).contains("a=0")) {
            fail("v0 write is not off the true path " + code.get(inserted + 2));
        }
        if (!code.get(load).contains("Ljava/lang/System;->load(") || code.get(load).contains("loadLibrary")) {
            fail("load site " + code.get(load));
        }
        if (!target(code.get(loadGoto)).equals("->" + join) || !code.get(loadLibrary + 1).startsWith("IGET")) {
            fail("load paths miss join " + code.get(loadGoto) + " / " + code.get(loadLibrary + 1));
        }
        if (!code.get(inserted).contains("afterGameLoad") || !code.get(anchor).contains("cusCocosInit")) {
            fail("anchor not after inserted call " + code.get(inserted) + " / " + code.get(anchor));
        }
        int jumps = 0;
        for (String row : code) {
            if (row.startsWith("GOTO") && target(row).equals("->" + anchor)) {
                jumps++;
            }
        }
        if (jumps != 1) {
            fail("anchor reachable without the inserted call");
        }
        List<String> tries = tryRows(rows);
        String loadTry = "try " + load + ".." + loadGoto + " -> Ljava/lang/UnsatisfiedLinkError;@" + loadHandler;
        String libTry = "try " + loadLibrary + ".." + join + " -> Ljava/lang/UnsatisfiedLinkError;@" + later;
        String hookTry = "try " + inserted + ".." + (inserted + 1) + " -> Ljava/lang/Throwable;@" + (inserted + 2);
        if (!tries.contains(loadTry) || !tries.contains(libTry) || !tries.contains(hookTry) || tries.size() != 3) {
            fail("catches swallowed or moved " + tries + " expected " + List.of(loadTry, libTry, hookTry));
        }
    }

    private static boolean writes(String row, int reg) {
        if (row.startsWith("INVOKE")) {
            return false;
        }
        String needle = "a=" + reg;
        int at = row.indexOf(needle);
        if (at < 0) {
            return false;
        }
        int end = at + needle.length();
        return end == row.length() || row.charAt(end) == ' ';
    }

    private static void deviceUuidAsserts() {
        MutableMethodImplementation bad = new MutableMethodImplementation(1);
        bad.addInstruction(Refs.retObj(0));
        try {
            Edits.deviceUuid(bad);
            fail("deviceUuid replaced without getContext");
        } catch (IllegalStateException e) {
            if (!e.getMessage().contains("getContext")) {
                fail(e.getMessage());
            }
        }
        MutableMethodImplementation ok = new MutableMethodImplementation(1);
        ok.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC, Refs.GET_CONTEXT));
        ok.addInstruction(Refs.retObj(0));
        List<String> rows = Semantic.rows(Edits.deviceUuid(ok));
        if (!rows.get(0).contains("getContext") || !contains(rows, "deviceUuid")) {
            fail("deviceUuid body " + rows);
        }
    }

    private static void substringIsNotAnEdit() {
        String key = "Ldev/raspberry/dexpatch/Synth;->LoginWebMessageExtra(Landroid/os/Message;)V";
        if (Main.isEditedKey(key)) {
            fail("substring key is an edit");
        }
        MutableMethodImplementation body = new MutableMethodImplementation(1);
        body.addInstruction(Refs.retVoid());
        Method fake = method("LoginWebMessageExtra", "V",
                List.of(new ImmutableMethodParameter("Landroid/os/Message;", Set(), null)), body, false);
        try {
            Main.checkEdited(fake, fake);
            fail("substring key accepted as edit");
        } catch (IllegalStateException e) {
            if (!e.getMessage().contains("not an edit")) {
                fail(e.getMessage());
            }
        }
    }

    private static void verifyIgnoresSubstring(File dir) throws Exception {
        MutableMethodImplementation body = new MutableMethodImplementation(2);
        body.addInstruction(Refs.const4(0, 1));
        body.addInstruction(Refs.retVoid());
        Method orig = method("LoginWebMessageExtra", "V",
                List.of(new ImmutableMethodParameter("Landroid/os/Message;", Set(), null)), body, false);
        MutableMethodImplementation changed = new MutableMethodImplementation(1);
        changed.addInstruction(Refs.retVoid());
        File a = new File(dir, "sub-a.dex");
        File b = new File(dir, "sub-b.dex");
        write(a, List.of(orig));
        write(b, List.of(copy(orig, changed)));
        try {
            Main.verify(a.getPath(), b.getPath());
            fail("substring method treated as edit");
        } catch (IllegalStateException e) {
            if (!e.getMessage().contains("untouched drift")) {
                fail(e.getMessage());
            }
        }
    }

    private static Method asActivityResult(Method m) {
        return renamed(m, "Ljp/naver/lineplay/android/LinePlay;", "onActivityResult");
    }

    private static Method asSetCookie(Method m) {
        return renamed(m, "Ljp/naver/common/android/notice/util/LanLinkUtil;", "setCookieNLoadUrl");
    }

    private static Method renamed(Method m, String cls, String name) {
        return new ImmutableMethod(cls, name, ImmutableMethodParameter.immutableListOf(m.getParameters()),
                m.getReturnType(), m.getAccessFlags(), java.util.Set.of(), java.util.Set.of(), m.getImplementation());
    }

    private static java.util.Set<com.android.tools.smali.dexlib2.iface.Annotation> Set() {
        return java.util.Set.of();
    }

    private static Method method(String name, String ret, List<ImmutableMethodParameter> params, MethodImplementation impl, boolean stat) {
        int access = AccessFlags.PUBLIC.getValue();
        if (stat) {
            access |= AccessFlags.STATIC.getValue();
        }
        return new ImmutableMethod("Ldev/raspberry/dexpatch/Synth;", name, params, ret, access, java.util.Set.of(), java.util.Set.of(), impl);
    }

    private static Method copy(Method base, MethodImplementation impl) {
        return new ImmutableMethod(base.getDefiningClass(), base.getName(),
                ImmutableMethodParameter.immutableListOf(base.getParameters()),
                base.getReturnType(), base.getAccessFlags(), java.util.Set.of(), java.util.Set.of(), impl);
    }

    private static void write(File out, List<Method> methods) throws Exception {
        ClassDef cls = new ImmutableClassDef(
                "Ldev/raspberry/dexpatch/Synth;",
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                null, null, java.util.Set.of(), null, methods);
        DexPool pool = new DexPool(Opcodes.forApi(33));
        pool.internClass(cls);
        pool.writeTo(new FileDataStore(out));
    }

    private static Method find(com.android.tools.smali.dexlib2.iface.DexFile dex, String name) {
        for (ClassDef c : dex.getClasses()) {
            for (Method m : c.getMethods()) {
                if (m.getName().equals(name)) {
                    return m;
                }
            }
        }
        throw new IllegalStateException("missing " + name);
    }

    private static List<String> tryRows(List<String> rows) {
        List<String> out = new ArrayList<>();
        for (String row : rows) {
            if (row.startsWith("try ")) {
                out.add(row);
            }
        }
        return out;
    }

    private static List<String> codeRows(Method m) {
        List<String> rows = new ArrayList<>();
        for (String row : Semantic.rows(m.getImplementation())) {
            if (!row.startsWith("try ")) {
                rows.add(row);
            }
        }
        return rows;
    }

    private static List<String> shift(List<String> rows, int by) {
        List<String> out = new ArrayList<>();
        Pattern p = Pattern.compile("->(-?\\d+)");
        for (String row : rows) {
            Matcher m = p.matcher(row);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                int n = Integer.parseInt(m.group(1));
                m.appendReplacement(sb, "->" + (n < 0 ? n : n + by));
            }
            m.appendTail(sb);
            out.add(sb.toString());
        }
        return out;
    }

    private static List<String> shiftTry(List<String> rows, int by) {
        List<String> out = new ArrayList<>();
        Pattern p = Pattern.compile("try (\\d+)\\.\\.(\\d+) -> ([^@]*)@(-?\\d+)");
        for (String row : rows) {
            Matcher m = p.matcher(row);
            if (!m.matches()) {
                throw new IllegalStateException(row);
            }
            out.add("try " + (Integer.parseInt(m.group(1)) + by) + ".." + (Integer.parseInt(m.group(2)) + by)
                    + " -> " + m.group(3) + "@" + (Integer.parseInt(m.group(4)) + by));
        }
        return out;
    }

    private static int indexOf(List<String> rows, String needle) {
        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).contains(needle)) {
                return i;
            }
        }
        throw new IllegalStateException("no " + needle);
    }

    private static String target(String row) {
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

    private static boolean contains(List<String> rows, String needle) {
        for (String row : rows) {
            if (row.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static void fail(String msg) {
        throw new IllegalStateException(msg);
    }
}
