package dev.raspberry.dexpatch;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import java.util.List;

/** Instruction builders. Register numbers are the DEX registers, not smali p-names. */
final class Refs {
    static final String HELPER = "Ldev/raspberry/Raspberry;";
    static final String HOOK_FAILED = "raspberry hook failed";

    static final MethodReference GET_CONTEXT = method(
            "Ljp/naver/lineplay/android/LineplayApplication;", "getContext",
            List.of(), "Landroid/content/Context;");
    static final MethodReference DEVICE_UUID = method(
            HELPER, "deviceUuid", List.of("Landroid/content/Context;"), "Ljava/lang/String;");
    static final MethodReference BEFORE_NATIVE = method(
            HELPER, "beforeNative", List.of("Landroid/app/Activity;"), "Z");
    static final MethodReference AFTER_LOAD = method(
            HELPER, "afterGameLoad", List.of("Landroid/app/Activity;"), "V");
    static final MethodReference REWRITE = method(
            HELPER, "rewrite", List.of("Ljava/lang/String;"), "Ljava/lang/String;");
    static final FieldReference OUTER = new ImmutableFieldReference(
            "Ljp/naver/lineplay/android/LinePlay$5;", "this$0", "Ljp/naver/lineplay/android/LinePlay;");
    static final MethodReference HANDLER_INIT = method(
            "Landroid/os/Handler;", "<init>", List.of(), "V");
    static final MethodReference POST_DELAYED = method(
            "Landroid/os/Handler;", "postDelayed",
            List.of("Ljava/lang/Runnable;", "J"), "Z");
    static final MethodReference GET_MESSAGE = method(
            "Ljava/lang/Throwable;", "getMessage", List.of(), "Ljava/lang/String;");
    static final MethodReference TOAST = method(
            "Landroid/widget/Toast;", "makeText",
            List.of("Landroid/content/Context;", "Ljava/lang/CharSequence;", "I"),
            "Landroid/widget/Toast;");
    static final MethodReference TOAST_SHOW = method(
            "Landroid/widget/Toast;", "show", List.of(), "V");
    static final MethodReference FINISH = method(
            "Landroid/app/Activity;", "finish", List.of(), "V");

    private Refs() {}

    static ImmutableMethodReference method(String cls, String name, List<String> params, String ret) {
        return new ImmutableMethodReference(cls, name, params, ret);
    }

    static BuilderInstruction invoke(Opcode op, MethodReference ref, int... regs) {
        int c = regs.length > 0 ? regs[0] : 0;
        int d = regs.length > 1 ? regs[1] : 0;
        int e = regs.length > 2 ? regs[2] : 0;
        int f = regs.length > 3 ? regs[3] : 0;
        int g = regs.length > 4 ? regs[4] : 0;
        return new BuilderInstruction35c(op, regs.length, c, d, e, f, g, ref);
    }

    static BuilderInstruction moveResultObj(int reg) {
        return new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, reg);
    }

    static BuilderInstruction moveResult(int reg) {
        return new BuilderInstruction11x(Opcode.MOVE_RESULT, reg);
    }

    static BuilderInstruction retVoid() {
        return new BuilderInstruction10x(Opcode.RETURN_VOID);
    }

    static BuilderInstruction retObj(int reg) {
        return new BuilderInstruction11x(Opcode.RETURN_OBJECT, reg);
    }

    static BuilderInstruction iget(int dest, int obj, FieldReference field) {
        return new BuilderInstruction22c(Opcode.IGET_OBJECT, dest, obj, field);
    }

    static BuilderInstruction const4(int reg, int lit) {
        return new BuilderInstruction11n(Opcode.CONST_4, reg, lit);
    }

    static BuilderInstruction const16(int reg, int lit) {
        return new BuilderInstruction21s(Opcode.CONST_16, reg, lit);
    }

    static BuilderInstruction constWide16(int reg, int lit) {
        return new BuilderInstruction21s(Opcode.CONST_WIDE_16, reg, lit);
    }

    static BuilderInstruction constString(int reg, String s) {
        return new BuilderInstruction21c(Opcode.CONST_STRING, reg, new ImmutableStringReference(s));
    }

    static BuilderInstruction newInstance(int reg, String type) {
        return new BuilderInstruction21c(Opcode.NEW_INSTANCE, reg, new ImmutableTypeReference(type));
    }

    static BuilderInstruction ifNez(int reg, com.android.tools.smali.dexlib2.builder.Label label) {
        return new BuilderInstruction21t(Opcode.IF_NEZ, reg, label);
    }

    static String refText(Reference r) {
        if (r instanceof MethodReference m) {
            StringBuilder sb = new StringBuilder();
            sb.append(m.getDefiningClass()).append("->").append(m.getName()).append('(');
            for (CharSequence p : m.getParameterTypes()) {
                sb.append(p);
            }
            return sb.append(')').append(m.getReturnType()).toString();
        }
        if (r instanceof FieldReference f) {
            return f.getDefiningClass() + "->" + f.getName() + ":" + f.getType();
        }
        return String.valueOf(r);
    }
}
