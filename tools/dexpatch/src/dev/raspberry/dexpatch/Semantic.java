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
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import java.util.ArrayList;
import java.util.Collections;
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
        Map<Integer, Integer> payloadSwitch = new HashMap<>();
        int addr = 0;
        for (int i = 0; i < insns.size(); i++) {
            addrToIndex.put(addr, i);
            Instruction insn = insns.get(i);
            if (insn instanceof OffsetInstruction oi && isPayloadRef(insn.getOpcode())) {
                payloadSwitch.put(addr + oi.getCodeOffset(), addr);
            }
            addr += insn.getCodeUnits();
        }
        int codeUnits = addr;
        // A try that runs to the end has no instruction at that address. Index it past the last one.
        addrToIndex.put(codeUnits, insns.size());
        List<String> rows = new ArrayList<>();
        addr = 0;
        for (Instruction insn : insns) {
            rows.add(row(insn, addr, addrToIndex, payloadSwitch));
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
        rows.add("regs " + impl.getRegisterCount());
        return rows;
    }

    private static boolean isPayloadRef(Opcode op) {
        return op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH || op == Opcode.FILL_ARRAY_DATA;
    }

    private static String row(Instruction insn, int addr, Map<Integer, Integer> addrToIndex, Map<Integer, Integer> payloadSwitch) {
        StringBuilder sb = new StringBuilder();
        sb.append(norm(insn.getOpcode()));
        if (insn instanceof ReferenceInstruction ri) {
            sb.append(" ref=").append(Refs.refText(ri.getReference()));
        }
        if (insn instanceof WideLiteralInstruction wi) {
            sb.append(" wide=").append(wi.getWideLiteral());
        } else if (insn instanceof NarrowLiteralInstruction li) {
            sb.append(" lit=").append(li.getNarrowLiteral());
        }
        if (insn instanceof OffsetInstruction oi) {
            int target = addr + oi.getCodeOffset();
            sb.append(" ->").append(indexAt(addrToIndex, target));
        }
        if (insn instanceof SwitchPayload sp) {
            Integer switchAddr = payloadSwitch.get(addr);
            sb.append(" cases=");
            for (SwitchElement el : sp.getSwitchElements()) {
                int target = switchAddr == null ? -1 : indexAt(addrToIndex, switchAddr + el.getOffset());
                sb.append(el.getKey()).append(':').append(target).append(',');
            }
        }
        if (insn instanceof ArrayPayload ap) {
            sb.append(" w=").append(ap.getElementWidth()).append(" data=");
            for (Number n : ap.getArrayElements()) {
                sb.append(n.longValue()).append(',');
            }
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
        if (insn instanceof RegisterRangeInstruction rr) {
            sb.append(" range=").append(rr.getStartRegister()).append(',').append(rr.getRegisterCount());
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
