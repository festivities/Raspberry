package dev.raspberry.dexpatch;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction20t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22t;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.debug.DebugItem;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import java.util.ArrayList;
import java.util.List;

/** Method-body edits. Callers pass the references; this class does not assume a DEX. */
final class Edits {
    static final int GATE_INSNS = 10;
    static final int HOOK_INSNS = 13;
    static final int REWRITE_INSNS = 2;
    static final int NOTICE_CONTEXT_INSNS = 1;
    static final int NOTICE_OPEN_INSNS = 1;

    private Edits() {}

    static MethodImplementation edit(Method method) {
        String key = Semantic.key(method);
        MethodImplementation impl = method.getImplementation();
        if (impl == null) {
            return null;
        }
        return switch (key) {
            case "Ljp/naver/lineplay/login/LoginAdapter;->InfoDeviceUUID()Ljava/lang/String;" ->
                    deviceUuid(impl);
            case "Ljp/naver/lineplay/android/LinePlay$5;->run()V" -> runGate(impl);
            case "Ljp/naver/lineplay/login/LoginAdapter;->LoginAppToApp()V",
                    "Ljp/naver/lineplay/login/LoginAdapter;->LoginWeb()V",
                    "Lcom/nhnarts/message/PfHandler;->LoginAppToAppMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginWebMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginBandMessage(Landroid/os/Message;)V",
                    "Lcom/nhnarts/message/PfHandler;->LoginNaverId(Landroid/os/Message;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->grantedFacebookJNI()V" ->
                    returnVoid(method);
            case "Ljp/naver/lineplay/android/LinePlay;->onActivityResult(IILandroid/content/Intent;)V" ->
                    skipConstBranch(method, impl, 20000);
            case "Ljp/naver/lineplay/android/LinePlay;->updateURLFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->updateURLSubWebViewFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->openWebBrowserInGLThread(Ljava/lang/String;)V",
                    "Ljp/naver/common/android/notice/util/LanLinkUtil;->setCookieNLoadUrl(Landroid/webkit/WebView;Ljava/lang/String;)V" ->
                    prefixRewrite(method, impl, stringParamIndex(key));
            case "Ljp/naver/common/android/notice/commons/CustomSimpleHttpClient;->get(Ljava/lang/String;Ljava/util/List;)Ljava/io/InputStream;",
                    "Ljp/naver/common/android/notice/notification/ImageDownloadTask;->downloadImage()[B",
                    "Ljp/naver/common/android/notice/log/ErrorLogAPIImpl;->sendFailLog(Ljava/lang/String;Ljava/lang/String;)Z" ->
                    rewriteNoticeConnection(impl);
            case "Ljp/naver/lineplay/android/LineplayApplication;->initNotice()V" ->
                    prefixNoticeContext(method, impl);
            case "Ljp/naver/common/android/notice/notification/NotificationTask;->doInBackground([Ljava/lang/Void;)Ljp/naver/common/android/notice/model/NoticeCallbackResult;" ->
                    prefixNoticePrepare(impl);
            case "Lcom/nhnarts/ArtsEditTextLayout;->dispatchDraw(Landroid/graphics/Canvas;)V" ->
                    rewriteEditTextClip(impl);
            default -> null;
        };
    }

    /** Replace the body with getContext then helper.deviceUuid. No ANDROID_ID path remains. */
    static MethodImplementation deviceUuid(MethodImplementation orig) {
        Instruction first = orig.getInstructions().iterator().next();
        if (!(first instanceof ReferenceInstruction ri) || !"Ljp/naver/lineplay/android/LineplayApplication;->getContext()Landroid/content/Context;".equals(Refs.refText(ri.getReference()))) {
            throw new IllegalStateException("InfoDeviceUUID does not start with getContext");
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(1);
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC, Refs.GET_CONTEXT));
        impl.addInstruction(Refs.moveResultObj(0));
        impl.addInstruction(Refs.invoke(Opcode.INVOKE_STATIC, Refs.DEVICE_UUID, 0));
        impl.addInstruction(Refs.moveResultObj(0));
        impl.addInstruction(Refs.retObj(0));
        return stripDebug(impl);
    }

    static MethodImplementation returnVoid(Method method) {
        int params = method.getParameters().size();
        if (!AccessFlags.STATIC.isSet(method.getAccessFlags())) {
            params++;
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(Math.max(params, 1));
        impl.addInstruction(Refs.retVoid());
        return stripDebug(impl);
    }

    /** Declared-parameter index of the string, not an incoming-slot offset. Static setCookieNLoadUrl's string is the second parameter. */
    static int stringParamIndex(String key) {
        return switch (key) {
            case "Ljp/naver/lineplay/android/LinePlay;->updateURLFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->updateURLSubWebViewFromUiThread(Ljava/lang/String;)V",
                    "Ljp/naver/lineplay/android/LinePlay;->openWebBrowserInGLThread(Ljava/lang/String;)V" -> 0;
            case "Ljp/naver/common/android/notice/util/LanLinkUtil;->setCookieNLoadUrl(Landroid/webkit/WebView;Ljava/lang/String;)V" -> 1;
            default -> throw new IllegalStateException("no string parameter " + key);
        };
    }

    /** Incoming register for a declared parameter. Instance methods keep this in the first incoming slot. */
    static int paramRegister(Method method, MethodImplementation impl, int paramIndex) {
        int declared = method.getParameters().size();
        if (paramIndex < 0 || paramIndex >= declared) {
            throw new IllegalStateException("parameter index out of range");
        }
        boolean stat = AccessFlags.STATIC.isSet(method.getAccessFlags());
        int incoming = declared + (stat ? 0 : 1);
        int slot = paramIndex + (stat ? 0 : 1);
        int reg = impl.getRegisterCount() - incoming + slot;
        if (reg < 0 || reg >= impl.getRegisterCount()) {
            throw new IllegalStateException("parameter register out of range");
        }
        return reg;
    }

    /** Rewrite the string parameter in place, then run the original body. */
    static MethodImplementation prefixRewrite(Method method, MethodImplementation orig, int paramIndex) {
        int reg = paramRegister(method, orig, paramIndex);
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        impl.addInstruction(0, Refs.invoke(Opcode.INVOKE_STATIC, Refs.REWRITE, reg));
        impl.addInstruction(1, Refs.moveResultObj(reg));
        return stripDebug(impl);
    }

    /** Replace exactly one URL.openConnection invocation without shifting its branches or handlers. */
    static MethodImplementation rewriteNoticeConnection(MethodImplementation orig) {
        List<BuilderInstruction> insns = new ArrayList<>();
        for (BuilderInstruction instruction : new MutableMethodImplementation(orig).getInstructions()) {
            insns.add(instruction);
        }
        int found = -1;
        BuilderInstruction replacement = null;
        for (int i = 0; i < insns.size(); i++) {
            BuilderInstruction instruction = insns.get(i);
            if (!(instruction instanceof ReferenceInstruction ri)
                    || !Refs.refText(ri.getReference()).equals(Refs.refText(Refs.URL_OPEN_CONNECTION))) {
                continue;
            }
            if (found >= 0 || (instruction.getOpcode() != Opcode.INVOKE_VIRTUAL
                    && instruction.getOpcode() != Opcode.INVOKE_VIRTUAL_RANGE)) {
                throw new IllegalStateException("notice openConnection shape");
            }
            int receiver;
            if (instruction instanceof FiveRegisterInstruction five && five.getRegisterCount() == 1) {
                receiver = five.getRegisterC();
            } else if (instruction instanceof RegisterRangeInstruction range && range.getRegisterCount() == 1) {
                receiver = range.getStartRegister();
            } else {
                throw new IllegalStateException("notice openConnection receiver");
            }
            if (receiver < 0 || receiver >= orig.getRegisterCount()) {
                throw new IllegalStateException("notice openConnection register");
            }
            replacement = receiver <= 15
                    ? Refs.invoke(Opcode.INVOKE_STATIC, Refs.OPEN_NOTICE_CONNECTION, receiver)
                    : Refs.invokeRange(Opcode.INVOKE_STATIC_RANGE, receiver, 1, Refs.OPEN_NOTICE_CONNECTION);
            if (replacement.getCodeUnits() != instruction.getCodeUnits()) {
                throw new IllegalStateException("notice openConnection width");
            }
            found = i;
        }
        if (found < 0) {
            throw new IllegalStateException("notice openConnection missing");
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        impl.replaceInstruction(found, replacement);
        return stripDebug(impl);
    }

    /** Swap the single Canvas.clipPath(Path) call for helper.clipEditText(Canvas, Path); same registers and width. */
    static MethodImplementation rewriteEditTextClip(MethodImplementation orig) {
        List<BuilderInstruction> insns = new ArrayList<>(new MutableMethodImplementation(orig).getInstructions());
        int found = -1;
        BuilderInstruction replacement = null;
        for (int i = 0; i < insns.size(); i++) {
            BuilderInstruction instruction = insns.get(i);
            if (!(instruction instanceof ReferenceInstruction ri)
                    || !Refs.refText(ri.getReference()).equals(Refs.refText(Refs.CANVAS_CLIP_PATH))) {
                continue;
            }
            if (found >= 0 || instruction.getOpcode() != Opcode.INVOKE_VIRTUAL
                    || !(instruction instanceof FiveRegisterInstruction five) || five.getRegisterCount() != 2) {
                throw new IllegalStateException("edit clipPath shape");
            }
            replacement = Refs.invoke(Opcode.INVOKE_STATIC, Refs.CLIP_EDIT_TEXT, five.getRegisterC(), five.getRegisterD());
            if (replacement.getCodeUnits() != instruction.getCodeUnits()) {
                throw new IllegalStateException("edit clipPath width");
            }
            found = i;
        }
        if (found < 0) {
            throw new IllegalStateException("edit clipPath missing");
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        impl.replaceInstruction(found, replacement);
        return stripDebug(impl);
    }

    /** initNotice runs on the Application instance; capture its Context before SDK initialization. */
    static MethodImplementation prefixNoticeContext(Method method, MethodImplementation orig) {
        if (AccessFlags.STATIC.isSet(method.getAccessFlags()) || orig.getRegisterCount() == 0) {
            throw new IllegalStateException("notice context register");
        }
        List<Instruction> instructions = new ArrayList<>();
        for (Instruction instruction : orig.getInstructions()) {
            instructions.add(instruction);
        }
        if (instructions.isEmpty() || !(instructions.get(0) instanceof ReferenceInstruction ri)
                || instructions.get(0).getOpcode() != Opcode.INVOKE_STATIC
                || !Refs.refText(ri.getReference()).equals(
                        "Ljp/naver/common/android/notice/LineNotice;->init(Landroid/content/Context;)V")
                || !(instructions.get(0) instanceof FiveRegisterInstruction five)
                || five.getRegisterCount() != 1
                || five.getRegisterC() != orig.getRegisterCount() - 1) {
            throw new IllegalStateException("initNotice does not start with LineNotice.init(Context)");
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        impl.addInstruction(0, Refs.invoke(
                Opcode.INVOKE_STATIC, Refs.CAPTURE_NOTICE_CONTEXT, orig.getRegisterCount() - 1));
        return stripDebug(impl);
    }

    /** Insert after getContext, within its existing Exception handler, before either task path. */
    static MethodImplementation prefixNoticePrepare(MethodImplementation orig) {
        List<Instruction> instructions = new ArrayList<>();
        for (Instruction instruction : orig.getInstructions()) {
            instructions.add(instruction);
        }
        int contextIndex = -1;
        int contextStart = 0;
        int address = 0;
        String contextRef =
                "Ljp/naver/common/android/notice/LineNoticeConfig;->getContext()Landroid/content/Context;";
        for (int i = 0; i < instructions.size(); i++) {
            Instruction instruction = instructions.get(i);
            if (instruction instanceof ReferenceInstruction ri
                    && contextRef.equals(Refs.refText(ri.getReference()))) {
                if (contextIndex >= 0 || instruction.getOpcode() != Opcode.INVOKE_STATIC) {
                    throw new IllegalStateException("notice getContext shape");
                }
                contextIndex = i;
                contextStart = address;
            }
            address += instruction.getCodeUnits();
        }
        if (contextIndex < 0) {
            throw new IllegalStateException("notice task missing getContext");
        }
        if (contextIndex + 1 < instructions.size()) {
            Opcode next = instructions.get(contextIndex + 1).getOpcode();
            if (next == Opcode.MOVE_RESULT || next == Opcode.MOVE_RESULT_OBJECT || next == Opcode.MOVE_RESULT_WIDE) {
                throw new IllegalStateException("notice getContext result must remain unused");
            }
        }
        boolean contextCaught = false;
        int contextEnd = contextStart + instructions.get(contextIndex).getCodeUnits();
        for (TryBlock<? extends ExceptionHandler> block : orig.getTryBlocks()) {
            if (block.getStartCodeAddress() > contextStart
                    || block.getStartCodeAddress() + block.getCodeUnitCount() < contextEnd) {
                continue;
            }
            for (ExceptionHandler handler : block.getExceptionHandlers()) {
                if ("Ljava/lang/Exception;".equals(handler.getExceptionType())) {
                    contextCaught = true;
                }
            }
        }
        if (!contextCaught) {
            throw new IllegalStateException("notice getContext is not caught by Exception");
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        impl.addInstruction(contextIndex + 1, Refs.invoke(Opcode.INVOKE_STATIC, Refs.PREPARE_NOTICE));
        boolean prepareCaught = false;
        int prepareStart = contextEnd;
        int prepareEnd = prepareStart + impl.getInstructions().get(contextIndex + 1).getCodeUnits();
        for (TryBlock<? extends ExceptionHandler> block : impl.getTryBlocks()) {
            if (block.getStartCodeAddress() > prepareStart
                    || block.getStartCodeAddress() + block.getCodeUnitCount() < prepareEnd) {
                continue;
            }
            for (ExceptionHandler handler : block.getExceptionHandlers()) {
                if ("Ljava/lang/Exception;".equals(handler.getExceptionType())) {
                    prepareCaught = true;
                }
            }
        }
        if (!prepareCaught) {
            throw new IllegalStateException("notice prepare is outside Exception handler");
        }
        return stripDebug(impl);
    }

    /**
     * Prefix: beforeNative(this$0). False posts this runnable again in 500ms and
     * returns. True falls through with v0 intact; scratch is v1-v3.
     */
    static MethodImplementation prefixGate(MethodImplementation orig, int thisReg) {
        if (thisReg < 4 || orig.getRegisterCount() <= thisReg) {
            throw new IllegalStateException("gate needs this in a high register");
        }
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        Label ready = impl.newLabelForIndex(0);
        int at = 0;
        impl.addInstruction(at++, Refs.iget(1, thisReg, Refs.OUTER));
        impl.addInstruction(at++, Refs.invoke(Opcode.INVOKE_STATIC, Refs.BEFORE_NATIVE, 1));
        impl.addInstruction(at++, Refs.moveResult(1));
        impl.addInstruction(at++, Refs.ifNez(1, ready));
        impl.addInstruction(at++, Refs.newInstance(1, "Landroid/os/Handler;"));
        impl.addInstruction(at++, Refs.invoke(Opcode.INVOKE_DIRECT, Refs.HANDLER_INIT, 1));
        impl.addInstruction(at++, Refs.constWide16(2, 500));
        impl.addInstruction(at++, Refs.invoke(Opcode.INVOKE_VIRTUAL, Refs.POST_DELAYED, 1, thisReg, 2, 3));
        impl.addInstruction(at++, Refs.moveResult(1));
        impl.addInstruction(at++, Refs.retVoid());
        if (at != GATE_INSNS) {
            throw new IllegalStateException("gate size " + at);
        }
        return stripDebug(impl);
    }

    static MethodImplementation runGate(MethodImplementation orig) {
        MethodImplementation gated = prefixGate(orig, thisReg(orig));
        return insertHookBefore(unwrap(gated), "cusCocosInit");
    }

    /**
     * Insert afterGameLoad on the activity register loaded by the instruction
     * immediately before anchor. A throw shows our error and finishes; it does
     * not fall through to anchor.
     */
    static MethodImplementation insertHookBefore(MethodImplementation orig, String anchor) {
        MutableMethodImplementation impl = orig instanceof MutableMethodImplementation m
                ? m
                : new MutableMethodImplementation(orig);
        int idx = findAnchor(impl, anchor);
        BuilderInstruction prev = impl.getInstructions().get(idx - 1);
        if (prev.getOpcode() != Opcode.IGET_OBJECT || !(prev instanceof TwoRegisterInstruction two)) {
            throw new IllegalStateException("anchor is not preceded by iget-object");
        }
        int activity = two.getRegisterA();
        Label after = impl.newLabelForIndex(idx);
        int base = idx;
        impl.addInstruction(base, Refs.invoke(Opcode.INVOKE_STATIC, Refs.AFTER_LOAD, activity));
        impl.addInstruction(base + 1, new BuilderInstruction20t(Opcode.GOTO_16, after));
        impl.addInstruction(base + 2, new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        impl.addInstruction(base + 3, Refs.invoke(Opcode.INVOKE_VIRTUAL, Refs.GET_MESSAGE, 0));
        impl.addInstruction(base + 4, Refs.moveResultObj(2));
        impl.addInstruction(base + 5, Refs.const4(0, 0));
        impl.addInstruction(base + 6, Refs.constString(2, Refs.HOOK_FAILED));
        impl.addInstruction(base + 7, Refs.const4(3, 1));
        Label toast = impl.newLabelForIndex(base + 7);
        impl.replaceInstruction(base + 5, Refs.ifNez(2, toast));
        impl.addInstruction(base + 8, Refs.invoke(Opcode.INVOKE_STATIC, Refs.TOAST, activity, 2, 3));
        impl.addInstruction(base + 9, Refs.moveResultObj(0));
        impl.addInstruction(base + 10, Refs.invoke(Opcode.INVOKE_VIRTUAL, Refs.TOAST_SHOW, 0));
        impl.addInstruction(base + 11, Refs.invoke(Opcode.INVOKE_VIRTUAL, Refs.FINISH, activity));
        impl.addInstruction(base + 12, Refs.retVoid());
        impl.addCatch("Ljava/lang/Throwable;",
                impl.newLabelForIndex(base),
                impl.newLabelForIndex(base + 1),
                impl.newLabelForIndex(base + 2));
        return stripDebug(impl);
    }

    /**
     * Turn the request-code comparison into a goto to the same not-equal target.
     * Shape is const/16 vT, literal; if-ne vRequest, vT, :notEqual. Other 20000 constants are ignored.
     */
    static MethodImplementation skipConstBranch(Method method, MethodImplementation orig, int literal) {
        MutableMethodImplementation impl = new MutableMethodImplementation(orig);
        int at = requestCompareIndex(method, impl, literal);
        BuilderInstruction br = impl.getInstructions().get(at);
        if (!(br instanceof BuilderInstruction22t cmp)) {
            throw new IllegalStateException("request compare is not if-ne");
        }
        impl.replaceInstruction(at, new BuilderInstruction20t(Opcode.GOTO_16, cmp.getTarget()));
        return stripDebug(impl);
    }

    /** Index of the if-ne in the request-code comparison, not the first copy of the literal. */
    static int requestCompareIndex(Method method, MethodImplementation impl, int literal) {
        int request = paramRegister(method, impl, 0);
        List<Instruction> insns = new ArrayList<>();
        for (Instruction insn : impl.getInstructions()) {
            insns.add(insn);
        }
        int found = -1;
        for (int i = 0; i + 1 < insns.size(); i++) {
            Instruction a = insns.get(i);
            Instruction b = insns.get(i + 1);
            if (a.getOpcode() != Opcode.CONST_16 || !(a instanceof NarrowLiteralInstruction li) || li.getNarrowLiteral() != literal) {
                continue;
            }
            if (!(a instanceof OneRegisterInstruction dest) || b.getOpcode() != Opcode.IF_NE || !(b instanceof TwoRegisterInstruction br)) {
                continue;
            }
            if (br.getRegisterA() != request || br.getRegisterB() != dest.getRegisterA()) {
                continue;
            }
            if (found >= 0) {
                throw new IllegalStateException("request const " + literal + " is not unique");
            }
            found = i + 1;
        }
        if (found < 0) {
            throw new IllegalStateException("request const " + literal + " not found");
        }
        return found;
    }

    private static int findAnchor(MutableMethodImplementation impl, String name) {
        int found = -1;
        List<BuilderInstruction> insns = impl.getInstructions();
        for (int i = 0; i < insns.size(); i++) {
            BuilderInstruction insn = insns.get(i);
            if (!(insn instanceof ReferenceInstruction ri) || !(ri.getReference() instanceof MethodReference mr)) {
                continue;
            }
            if (name.equals(mr.getName())) {
                if (found >= 0) {
                    throw new IllegalStateException("anchor " + name + " is not unique");
                }
                found = i;
            }
        }
        if (found <= 0) {
            throw new IllegalStateException("anchor " + name + " missing");
        }
        return found;
    }

    private static int thisReg(MethodImplementation impl) {
        return impl.getRegisterCount() - 1;
    }

    private static MethodImplementation unwrap(MethodImplementation impl) {
        if (impl instanceof NoDebug n) {
            return n.inner;
        }
        return impl;
    }

    static MethodImplementation stripDebug(MethodImplementation impl) {
        return new NoDebug(impl);
    }

    private static final class NoDebug implements MethodImplementation {
        final MethodImplementation inner;

        NoDebug(MethodImplementation inner) {
            this.inner = inner;
        }

        public int getRegisterCount() {
            return inner.getRegisterCount();
        }

        public Iterable<? extends Instruction> getInstructions() {
            return inner.getInstructions();
        }

        public List<? extends TryBlock<? extends ExceptionHandler>> getTryBlocks() {
            return inner.getTryBlocks();
        }

        public Iterable<? extends DebugItem> getDebugItems() {
            return List.of();
        }
    }
}
