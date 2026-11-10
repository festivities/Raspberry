package dev.raspberry.dexpatch;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Semantic instruction identity. Offsets are instruction indexes, not raw code units or pool indexes. */
final class Semantic {
    private Semantic() {}

    static String key(Method m) {
        StringBuilder sb = new StringBuilder();
        sb.append(m.getDefiningClass()).append("->").append(m.getName()).append('(');
        for (CharSequence p : m.getParameterTypes()) {
            sb.append(p);
        }
        return sb.append(')').append(m.getReturnType()).toString();
    }

    static List<String> rows(MethodImplementation impl) {
        if (impl == null) {
            return List.of("abstract");
        }
        List<Instruction> insns = new ArrayList<>();
        for (Instruction insn : impl.getInstructions()) {
            insns.add(insn);
        }
        Map<Integer, Integer> addrToIndex = new HashMap<>();
        int addr = 0;
        for (int i = 0; i < insns.size(); i++) {
            addrToIndex.put(addr, i);
            addr += insns.get(i).getCodeUnits();
        }
        List<String> rows = new ArrayList<>();
        addr = 0;
        for (Instruction insn : insns) {
            rows.add(row(insn, addr, addrToIndex));
            addr += insn.getCodeUnits();
        }
        for (TryBlock<? extends ExceptionHandler> tb : impl.getTryBlocks()) {
            int start = indexAt(addrToIndex, tb.getStartCodeAddress());
            int end = indexAt(addrToIndex, tb.getStartCodeAddress() + tb.getCodeUnitCount());
            for (ExceptionHandler h : tb.getExceptionHandlers()) {
                int handler = indexAt(addrToIndex, h.getHandlerCodeAddress());
                rows.add("try " + start + ".." + end + " -> " + h.getExceptionType() + "@" + handler);
            }
        }
        return rows;
    }

    private static String row(Instruction insn, int addr, Map<Integer, Integer> addrToIndex) {
        StringBuilder sb = new StringBuilder();
        sb.append(norm(insn.getOpcode()));
        if (insn instanceof ReferenceInstruction ri) {
            sb.append(" ref=").append(Refs.refText(ri.getReference()));
        }
        if (insn instanceof NarrowLiteralInstruction li) {
            sb.append(" lit=").append(li.getNarrowLiteral());
        }
        if (insn instanceof OffsetInstruction oi) {
            int target = addr + oi.getCodeOffset();
            sb.append(" ->").append(indexAt(addrToIndex, target));
        }
        if (insn instanceof FiveRegisterInstruction fi && fi.getRegisterCount() > 0) {
            sb.append(" n=").append(fi.getRegisterCount())
                    .append(':').append(fi.getRegisterC())
                    .append(',').append(fi.getRegisterD())
                    .append(',').append(fi.getRegisterE())
                    .append(',').append(fi.getRegisterF())
                    .append(',').append(fi.getRegisterG());
        } else if (insn instanceof ThreeRegisterInstruction ti) {
            sb.append(" a=").append(ti.getRegisterA()).append(" b=").append(ti.getRegisterB()).append(" c=").append(ti.getRegisterC());
        } else if (insn instanceof TwoRegisterInstruction ti) {
            sb.append(" a=").append(ti.getRegisterA()).append(" b=").append(ti.getRegisterB());
        } else if (insn instanceof OneRegisterInstruction ti) {
            sb.append(" a=").append(ti.getRegisterA());
        }
        return sb.toString();
    }

    static int indexAt(Map<Integer, Integer> addrToIndex, int addr) {
        Integer idx = addrToIndex.get(addr);
        if (idx == null) {
            return -1;
        }
        return idx;
    }

    /** Width variants are the same operation. The target index is compared separately. */
    static String norm(Opcode op) {
        String n = op.name();
        if (n.startsWith("GOTO")) {
            return "GOTO";
        }
        if (n.equals("CONST_STRING_JUMBO")) {
            return "CONST_STRING";
        }
        if (n.startsWith("MOVE") && (n.endsWith("_FROM16") || n.endsWith("_16"))) {
            return n.substring(0, n.lastIndexOf('_'));
        }
        return n;
    }
}
