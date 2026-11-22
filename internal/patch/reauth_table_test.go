package patch

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestReauthARM64PhdrAndSlackBounds(t *testing.T) {
	tab := mustLoad(t, "patches/libgame-arm64.tbl")

	fileszEdit := findTableEdit(t, tab, 0x60)
	memszEdit := findTableEdit(t, tab, 0x68)
	if len(fileszEdit.Expected) != 8 || len(memszEdit.Expected) != 8 {
		t.Fatalf("PHDR[0] edit lengths = %d/%d, want 8/8", len(fileszEdit.Expected), len(memszEdit.Expected))
	}
	oldFilesz := binary.LittleEndian.Uint64(fileszEdit.Expected)
	newFilesz := binary.LittleEndian.Uint64(fileszEdit.Replacement)
	oldMemsz := binary.LittleEndian.Uint64(memszEdit.Expected)
	newMemsz := binary.LittleEndian.Uint64(memszEdit.Replacement)

	if oldFilesz != 0x384ffce || oldMemsz != 0x384ffce {
		t.Fatalf("PHDR[0] expected = %#x/%#x, want 0x384ffce", oldFilesz, oldMemsz)
	}
	if newFilesz != 0x3850000 || newMemsz != 0x3850000 {
		t.Fatalf("PHDR[0] replacement = %#x/%#x, want 0x3850000", newFilesz, newMemsz)
	}

	pageEnd := (oldFilesz &^ 0xfff) + 0x1000
	if newFilesz > pageEnd || newMemsz > pageEnd {
		t.Fatalf("PHDR[0] expansion %#x/%#x exceeds page end %#x", newFilesz, newMemsz, pageEnd)
	}

	slackEdits := []struct {
		off  uint64
		size uint64
	}{
		{0x384ffd0, 20},
		{0x384ffe4, 20},
	}
	for _, s := range slackEdits {
		ed := findTableEdit(t, tab, int64(s.off))
		if uint64(len(ed.Expected)) != s.size {
			t.Fatalf("arm64 slack edit %#x len = %d, want %d", s.off, len(ed.Expected), s.size)
		}
		if !isAllZero(ed.Expected) {
			t.Fatalf("arm64 slack edit %#x expected non-zero bytes", s.off)
		}
		if s.off < oldFilesz || s.off+s.size > newFilesz || s.off+s.size > newMemsz {
			t.Fatalf("arm64 slack [%#x, %#x) outside [%#x, %#x)", s.off, s.off+s.size, oldFilesz, newFilesz)
		}
	}
}

func TestReauthARM64TrampolinesDecoded(t *testing.T) {
	tab := mustLoad(t, "patches/libgame-arm64.tbl")

	// 1. NaStandAloneLoginPopup::createGuestAccount (0x1cab8cc) -> Slot 2 (0x3e8a610) in-place.
	cgEdit := findTableEdit(t, tab, 0x1cab8cc)
	if len(cgEdit.Replacement) != 16 {
		t.Fatalf("createGuestAccount replacement len = %d, want 16", len(cgEdit.Replacement))
	}
	assertARM64SlotTrampoline(t, cgEdit.Replacement[:12], 0x1cab8cc, 0x3e8a610)
	if imm16, ok := decodeARM64BRK(binary.LittleEndian.Uint32(cgEdit.Replacement[12:16])); !ok || imm16 != 0 {
		t.Fatalf("createGuestAccount tail = %08x, want BRK #0", binary.LittleEndian.Uint32(cgEdit.Replacement[12:16]))
	}
	assertTableWindow(t, tab, 0x1cab8dc, "f30b00f9130040f9de1c3694d8213694e10300aae00313aaf30b40f9fd7bc2a8d64efc17")

	// 2. NaDispatcherCommon::ReqAccessTokenForGuest (0x1bbf454) -> slack 0x384ffd0 -> Slot 0 (0x3e8a600).
	reqEntry := findTableEdit(t, tab, 0x1bbf454)
	assertTableWindow(t, tab, 0x1bbf448, "f0ffff17f30300aaeeffff17")
	assertTableWindow(t, tab, 0x1bbf458, "63ff0090fd030091f35301a9638840f9b3630291f76303a9")
	assertARM64BranchDecoded(t, reqEntry.Replacement, 0x1bbf454, 0x384ffd0)
	assertARM64STP(t, reqEntry.Expected, -0xb0)

	reqSlack := findTableEdit(t, tab, 0x384ffd0)
	assertARM64SlotTrampoline(t, reqSlack.Replacement[:12], 0x384ffd0, 0x3e8a600)
	assertARM64STP(t, reqSlack.Replacement[12:16], -0xb0)
	if !bytes.Equal(reqSlack.Replacement[12:16], reqEntry.Expected) {
		t.Fatalf("ReqAccessTokenForGuest resume STP %x != overwritten %x", reqSlack.Replacement[12:16], reqEntry.Expected)
	}
	assertARM64BranchDecoded(t, reqSlack.Replacement[16:20], 0x384ffe0, 0x1bbf458)

	// 3. NaLoginLayer::SetVisibleLoginBtn (0x1ca9168) -> slack 0x384ffe4 -> Slot 1 (0x3e8a608).
	visEntry := findTableEdit(t, tab, 0x1ca9168)
	assertTableWindow(t, tab, 0x1ca915c, "f30300aaf6ffff170000c842")
	assertTableWindow(t, tab, 0x1ca916c, "fd030091f55b02a9351c005301c440f9f35301a9")
	assertARM64BranchDecoded(t, visEntry.Replacement, 0x1ca9168, 0x384ffe4)
	assertARM64STP(t, visEntry.Expected, -0x50)

	visSlack := findTableEdit(t, tab, 0x384ffe4)
	assertARM64SlotTrampoline(t, visSlack.Replacement[:12], 0x384ffe4, 0x3e8a608)
	assertARM64STP(t, visSlack.Replacement[12:16], -0x50)
	if !bytes.Equal(visSlack.Replacement[12:16], visEntry.Expected) {
		t.Fatalf("SetVisibleLoginBtn resume STP %x != overwritten %x", visSlack.Replacement[12:16], visEntry.Expected)
	}
	assertARM64BranchDecoded(t, visSlack.Replacement[16:20], 0x384fff4, 0x1ca916c)
}

func TestReauthARMv7PhdrAndSlackBounds(t *testing.T) {
	tab := mustLoad(t, "patches/libgame-armv7.tbl")

	fileszEdit := findTableEdit(t, tab, 0x84)
	memszEdit := findTableEdit(t, tab, 0x88)
	if len(fileszEdit.Expected) != 4 || len(memszEdit.Expected) != 4 {
		t.Fatalf("PHDR[2] edit lengths = %d/%d, want 4/4", len(fileszEdit.Expected), len(memszEdit.Expected))
	}
	oldFilesz := binary.LittleEndian.Uint32(fileszEdit.Expected)
	newFilesz := binary.LittleEndian.Uint32(fileszEdit.Replacement)
	oldMemsz := binary.LittleEndian.Uint32(memszEdit.Expected)
	newMemsz := binary.LittleEndian.Uint32(memszEdit.Replacement)

	if oldFilesz != 0x2080674 || oldMemsz != 0x2080674 {
		t.Fatalf("PHDR[2] expected = %#x/%#x, want 0x2080674", oldFilesz, oldMemsz)
	}
	if newFilesz != 0x2080700 || newMemsz != 0x2080700 {
		t.Fatalf("PHDR[2] replacement = %#x/%#x, want 0x2080700", newFilesz, newMemsz)
	}

	pageEnd := (oldFilesz &^ 0xfff) + 0x1000
	if newFilesz > pageEnd || newMemsz > pageEnd {
		t.Fatalf("PHDR[2] expansion %#x/%#x exceeds page end %#x", newFilesz, newMemsz, pageEnd)
	}

	slackEdits := []struct {
		off  uint32
		size uint32
	}{
		{0x2080674, 24},
		{0x2080690, 32},
	}
	for _, s := range slackEdits {
		ed := findTableEdit(t, tab, int64(s.off))
		if uint32(len(ed.Expected)) != s.size {
			t.Fatalf("armv7 slack edit %#x len = %d, want %d", s.off, len(ed.Expected), s.size)
		}
		if !isAllZero(ed.Expected) {
			t.Fatalf("armv7 slack edit %#x expected non-zero bytes", s.off)
		}
		if s.off < oldFilesz || s.off+s.size > newFilesz || s.off+s.size > newMemsz {
			t.Fatalf("armv7 slack [%#x, %#x) outside [%#x, %#x)", s.off, s.off+s.size, oldFilesz, newFilesz)
		}
	}
}

func TestReauthARMv7TrampolinesDecoded(t *testing.T) {
	tab := mustLoad(t, "patches/libgame-armv7.tbl")

	// 1. NaStandAloneLoginPopup::createGuestAccount (0x12655cc) -> Slot 2 (0x24b4408) in-place.
	cgEdit := findTableEdit(t, tab, 0x12655cc)
	if len(cgEdit.Replacement) != 18 {
		t.Fatalf("armv7 createGuestAccount len = %d, want 18", len(cgEdit.Replacement))
	}
	assertThumbSlotTrampoline(t, cgEdit.Replacement[:16], 0x12655cc, 0x24b4408)
	if imm8, ok := decodeThumbUDF(binary.LittleEndian.Uint16(cgEdit.Replacement[16:18])); !ok || imm8 != 0 {
		t.Fatalf("armv7 createGuestAccount tail = %04x, want UDF #0", binary.LittleEndian.Uint16(cgEdit.Replacement[16:18]))
	}
	assertTableWindow(t, tab, 0x12655de, "86f501462046bd46bde8984098f775b9")

	// 2. NaDispatcherCommon::ReqAccessTokenForGuest (0x11fd8d8) -> slack 0x2080690 -> Slot 0 (0x24b4400).
	reqEntry := findTableEdit(t, tab, 0x11fd8d8)
	assertTableWindow(t, tab, 0x11fd8d0, "f613cb00af22cb00")
	assertTableWindow(t, tab, 0x11fd8de, "8eb07b441b6802afd0f81c8007f12004")
	if len(reqEntry.Replacement) != 6 {
		t.Fatalf("armv7 ReqAccessTokenForGuest entry len = %d, want 6", len(reqEntry.Replacement))
	}
	assertThumbBWide(t, reqEntry.Replacement[:4], 0x11fd8d8, 0x2080690)
	if !decodeThumbNOP(binary.LittleEndian.Uint16(reqEntry.Replacement[4:6])) {
		t.Fatalf("armv7 ReqAccessTokenForGuest pad = %04x, want NOP", binary.LittleEndian.Uint16(reqEntry.Replacement[4:6]))
	}

	reqSlack := findTableEdit(t, tab, 0x2080690)
	if len(reqSlack.Replacement) != 32 {
		t.Fatalf("armv7 ReqAccessTokenForGuest slack len = %d, want 32", len(reqSlack.Replacement))
	}
	assertThumbSlotTrampoline(t, reqSlack.Replacement[:16], 0x2080690, 0x24b4400)
	// Resume stub: MOVW R3, #0xadc0; MOVT R3, #0x0102; PUSH.W {R4-R10, LR}; B.W 0x11fd8de.
	valR3 := decodeThumbMovWT32Pair(t, reqSlack.Replacement[16:24], 3)
	if valR3 != 0x0102adc0 {
		t.Fatalf("armv7 ReqAccessTokenForGuest R3 literal = %#x, want 0x0102adc0", valR3)
	}
	maskReq, ok := decodeThumbPushW(reqSlack.Replacement[24:28])
	if !ok || maskReq != 0x47f0 || maskReq&0x000f != 0 {
		t.Fatalf("armv7 ReqAccessTokenForGuest PUSH.W = (%v, %#x), want (true, 0x47f0)", ok, maskReq)
	}
	if !bytes.Equal(reqSlack.Replacement[24:28], reqEntry.Expected[2:6]) {
		t.Fatalf("armv7 ReqAccessTokenForGuest resume PUSH.W %x != overwritten %x", reqSlack.Replacement[24:28], reqEntry.Expected[2:6])
	}
	assertThumbBWide(t, reqSlack.Replacement[28:32], 0x20806ac, 0x11fd8de)

	// 3. NaLoginLayer::SetVisibleLoginBtn (0x1264258) -> slack 0x2080674 -> Slot 1 (0x24b4404).
	visEntry := findTableEdit(t, tab, 0x1264258)
	assertTableWindow(t, tab, 0x1264250, "be91fc00b687fc00")
	assertTableWindow(t, tab, 0x126425c, "04462ded028b0e4682b0d0f8240100af")
	if len(visEntry.Replacement) != 4 {
		t.Fatalf("armv7 SetVisibleLoginBtn entry len = %d, want 4", len(visEntry.Replacement))
	}
	assertThumbBWide(t, visEntry.Replacement, 0x1264258, 0x2080674)

	visSlack := findTableEdit(t, tab, 0x2080674)
	if len(visSlack.Replacement) != 24 {
		t.Fatalf("armv7 SetVisibleLoginBtn slack len = %d, want 24", len(visSlack.Replacement))
	}
	assertThumbSlotTrampoline(t, visSlack.Replacement[:16], 0x2080674, 0x24b4404)
	// Resume stub: PUSH.W {R4-R8, LR}; B.W 0x126425c.
	maskVis, ok := decodeThumbPushW(visSlack.Replacement[16:20])
	if !ok || maskVis != 0x41f0 || maskVis&0x000f != 0 {
		t.Fatalf("armv7 SetVisibleLoginBtn PUSH.W = (%v, %#x), want (true, 0x41f0)", ok, maskVis)
	}
	if !bytes.Equal(visSlack.Replacement[16:20], visEntry.Expected) {
		t.Fatalf("armv7 SetVisibleLoginBtn resume PUSH.W %x != overwritten %x", visSlack.Replacement[16:20], visEntry.Expected)
	}
	assertThumbBWide(t, visSlack.Replacement[20:24], 0x2080688, 0x126425c)
}

func TestReauthTablesNonOverlappingRanges(t *testing.T) {
	for _, name := range []string{"arm64", "armv7"} {
		t.Run(name, func(t *testing.T) {
			tab := mustLoad(t, "patches/libgame-"+name+".tbl")
			type span struct {
				start int64
				end   int64
				kind  string
			}
			var spans []span
			for _, ed := range tab.Edits {
				spans = append(spans, span{ed.Offset, ed.Offset + int64(len(ed.Expected)), "edit"})
			}
			for _, w := range tab.Windows {
				spans = append(spans, span{w.Offset, w.Offset + int64(len(w.Expected)), "window"})
			}
			for i := 0; i < len(spans); i++ {
				for j := i + 1; j < len(spans); j++ {
					if spans[i].start < spans[j].end && spans[j].start < spans[i].end {
						if name == "armv7" &&
							((spans[i].kind == "edit" && spans[i].start == 0x13dc502 && spans[j].kind == "window" && spans[j].start == 0x13dc500) ||
								(spans[j].kind == "edit" && spans[j].start == 0x13dc502 && spans[i].kind == "window" && spans[i].start == 0x13dc500)) {
							continue
						}
						t.Fatalf("overlapping %s [%#x,%#x) and %s [%#x,%#x)",
							spans[i].kind, spans[i].start, spans[i].end,
							spans[j].kind, spans[j].start, spans[j].end)
					}
				}
			}
		})
	}
}

func assertARM64SlotTrampoline(t *testing.T, code []byte, pc, wantSlotVA uint64) {
	t.Helper()
	if len(code) != 12 {
		t.Fatalf("arm64 trampoline len = %d, want 12", len(code))
	}
	w0 := binary.LittleEndian.Uint32(code[0:4])
	w1 := binary.LittleEndian.Uint32(code[4:8])
	w2 := binary.LittleEndian.Uint32(code[8:12])

	rd, page, ok := decodeARM64ADRP(w0, pc)
	if !ok || rd != 16 {
		t.Fatalf("at %#x: ADRP decode = (ok=%v, rd=%d), want (true, X16)", pc, ok, rd)
	}
	rt, rn, off, ok := decodeARM64LDRUImm64(w1)
	if !ok || rt != 16 || rn != 16 {
		t.Fatalf("at %#x: LDR decode = (ok=%v, rt=%d, rn=%d), want (true, X16, X16)", pc+4, ok, rt, rn)
	}
	brRn, ok := decodeARM64BR(w2)
	if !ok || brRn != 16 {
		t.Fatalf("at %#x: BR decode = (ok=%v, rn=%d), want (true, X16)", pc+8, ok, brRn)
	}
	if got := page + off; got != wantSlotVA {
		t.Fatalf("at %#x: computed slot VA = %#x (%#x + %#x), want %#x", pc, got, page, off, wantSlotVA)
	}
}

func assertARM64STP(t *testing.T, insn []byte, wantImm int64) {
	t.Helper()
	if len(insn) != 4 {
		t.Fatalf("STP len = %d, want 4", len(insn))
	}
	w := binary.LittleEndian.Uint32(insn)
	rt, rt2, rn, imm, ok := decodeARM64STPPre64(w)
	if !ok || rt != 29 || rt2 != 30 || rn != 31 || imm != wantImm {
		t.Fatalf("STP decode = (ok=%v, rt=%d, rt2=%d, rn=%d, imm=%#x), want (true, X29, X30, SP, %#x)", ok, rt, rt2, rn, imm, wantImm)
	}
}

func assertARM64BranchDecoded(t *testing.T, insn []byte, pc, wantTarget uint64) {
	t.Helper()
	if len(insn) != 4 {
		t.Fatalf("B len = %d, want 4", len(insn))
	}
	target, link, ok := decodeARM64B(binary.LittleEndian.Uint32(insn), pc)
	if !ok || link || target != wantTarget {
		t.Fatalf("B at %#x = (ok=%v, link=%v, target=%#x), want (true, false, %#x)", pc, ok, link, target, wantTarget)
	}
}

func assertThumbSlotTrampoline(t *testing.T, code []byte, pc, wantSlotVA uint32) {
	t.Helper()
	if len(code) != 16 {
		t.Fatalf("thumb trampoline len = %d, want 16", len(code))
	}
	offset := decodeThumbMovWT32Pair(t, code[0:8], 12)
	addPCAddr := pc + 8
	rdn, rm, ok := decodeThumbAddHighReg(binary.LittleEndian.Uint16(code[8:10]))
	if !ok || rdn != 12 || rm != 15 {
		t.Fatalf("at %#x: ADD decode = (ok=%v, rdn=%d, rm=%d), want (true, R12, PC)", addPCAddr, ok, rdn, rm)
	}
	rt, rn, imm12, ok := decodeThumbLDRWImm12(code[10:14])
	if !ok || rt != 12 || rn != 12 || imm12 != 0 {
		t.Fatalf("at %#x: LDR.W decode = (ok=%v, rt=%d, rn=%d, imm=%#x), want (true, R12, R12, 0)", pc+10, ok, rt, rn, imm12)
	}
	bxRm, ok := decodeThumbBX(binary.LittleEndian.Uint16(code[14:16]))
	if !ok || bxRm != 12 {
		t.Fatalf("at %#x: BX decode = (ok=%v, rm=%d), want (true, R12)", pc+14, ok, bxRm)
	}
	// In Thumb state, reading PC in `ADD Rdn, PC` yields `instr_addr + 4`.
	if got := (addPCAddr + 4) + offset; got != wantSlotVA {
		t.Fatalf("at %#x: computed slot VA = %#x ((%#x + 4) + %#x), want %#x", pc, got, addPCAddr, offset, wantSlotVA)
	}
}

func decodeThumbMovWT32Pair(t *testing.T, code []byte, wantRd uint32) uint32 {
	t.Helper()
	if len(code) != 8 {
		t.Fatalf("MOVW/MOVT pair len = %d, want 8", len(code))
	}
	isT0, rd0, lo16, ok0 := decodeThumbMovWT(code[0:4])
	if !ok0 || isT0 || rd0 != wantRd {
		t.Fatalf("MOVW decode = (ok=%v, movt=%v, rd=%d), want (true, false, R%d)", ok0, isT0, rd0, wantRd)
	}
	isT1, rd1, hi16, ok1 := decodeThumbMovWT(code[4:8])
	if !ok1 || !isT1 || rd1 != wantRd {
		t.Fatalf("MOVT decode = (ok=%v, movt=%v, rd=%d), want (true, true, R%d)", ok1, isT1, rd1, wantRd)
	}
	return (uint32(hi16) << 16) | uint32(lo16)
}

func decodeARM64ADRP(word uint32, pc uint64) (rd uint32, page uint64, ok bool) {
	if word&0x9f000000 != 0x90000000 {
		return 0, 0, false
	}
	immlo := uint64((word >> 29) & 0x3)
	immhi := uint64((word >> 5) & 0x7ffff)
	imm := int64((immhi << 2) | immlo)
	if imm&(1<<20) != 0 {
		imm |= ^int64(0x1fffff)
	}
	page = uint64(int64(pc&^0xfff) + (imm << 12))
	return word & 0x1f, page, true
}

func decodeARM64LDRUImm64(word uint32) (rt, rn uint32, offset uint64, ok bool) {
	if word&0xffc00000 != 0xf9400000 {
		return 0, 0, 0, false
	}
	imm12 := uint64((word >> 10) & 0xfff)
	return word & 0x1f, (word >> 5) & 0x1f, imm12 * 8, true
}

func decodeARM64BR(word uint32) (rn uint32, ok bool) {
	if word&0xfffffc1f != 0xd61f0000 {
		return 0, false
	}
	return (word >> 5) & 0x1f, true
}

func decodeARM64BRK(word uint32) (imm16 uint32, ok bool) {
	if word&0xffe0001f != 0xd4200000 {
		return 0, false
	}
	return (word >> 5) & 0xffff, true
}

func decodeARM64STPPre64(word uint32) (rt, rt2, rn uint32, imm int64, ok bool) {
	if word&0xffc00000 != 0xa9800000 {
		return 0, 0, 0, 0, false
	}
	imm7 := int64((word >> 15) & 0x7f)
	if imm7&(1<<6) != 0 {
		imm7 |= ^int64(0x7f)
	}
	return word & 0x1f, (word >> 10) & 0x1f, (word >> 5) & 0x1f, imm7 * 8, true
}

func decodeARM64B(word uint32, pc uint64) (target uint64, link bool, ok bool) {
	if word&0x7c000000 != 0x14000000 {
		return 0, false, false
	}
	imm := int64(word & 0x03ffffff)
	if imm&(1<<25) != 0 {
		imm |= ^int64(0x03ffffff)
	}
	return uint64(int64(pc) + (imm << 2)), word&(1<<31) != 0, true
}

func decodeThumbMovWT(insn []byte) (isMovT bool, rd uint32, imm16 uint16, ok bool) {
	hw1 := binary.LittleEndian.Uint16(insn[:2])
	hw2 := binary.LittleEndian.Uint16(insn[2:])
	switch hw1 & 0xfbf0 {
	case 0xf240:
		isMovT = false
	case 0xf2c0:
		isMovT = true
	default:
		return false, 0, 0, false
	}
	if hw2&0x8000 != 0 {
		return false, 0, 0, false
	}
	imm4 := hw1 & 0xf
	i := (hw1 >> 10) & 1
	imm3 := (hw2 >> 12) & 0x7
	rd = uint32((hw2 >> 8) & 0xf)
	imm8 := hw2 & 0xff
	imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
	return isMovT, rd, imm16, true
}

func decodeThumbAddHighReg(hw uint16) (rdn, rm uint32, ok bool) {
	if hw&0xff00 != 0x4400 {
		return 0, 0, false
	}
	dn := uint32((hw >> 7) & 1)
	rm = uint32((hw >> 3) & 0xf)
	rdn = (dn << 3) | uint32(hw&0x7)
	return rdn, rm, true
}

func decodeThumbLDRWImm12(insn []byte) (rt, rn uint32, imm12 uint16, ok bool) {
	hw1 := binary.LittleEndian.Uint16(insn[:2])
	hw2 := binary.LittleEndian.Uint16(insn[2:])
	if hw1&0xfff0 != 0xf8d0 {
		return 0, 0, 0, false
	}
	return uint32((hw2 >> 12) & 0xf), uint32(hw1 & 0xf), hw2 & 0xfff, true
}

func decodeThumbBX(hw uint16) (rm uint32, ok bool) {
	if hw&0xff87 != 0x4700 {
		return 0, false
	}
	return uint32((hw >> 3) & 0xf), true
}

func decodeThumbUDF(hw uint16) (imm8 uint8, ok bool) {
	if hw&0xff00 != 0xde00 {
		return 0, false
	}
	return uint8(hw & 0xff), true
}

func decodeThumbNOP(hw uint16) bool {
	return hw == 0xbf00
}

func decodeThumbPushW(insn []byte) (regMask uint16, ok bool) {
	hw1 := binary.LittleEndian.Uint16(insn[:2])
	hw2 := binary.LittleEndian.Uint16(insn[2:])
	if hw1 != 0xe92d || hw2&0xa000 != 0 {
		return 0, false
	}
	return hw2, true
}

func isAllZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}

func TestReauthNativeResumeGuardsMatchTables(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "native", "reauth_android.c"))
	if err != nil {
		t.Fatalf("read reauth_android.c: %v", err)
	}
	src := string(raw)
	arm64Marker := "#if defined(__aarch64__)"
	armMarker := "#elif defined(__arm__)"
	elseMarker := "#else"

	i64 := strings.Index(src, arm64Marker)
	i32 := strings.Index(src, armMarker)
	iEnd := strings.Index(src, elseMarker)
	if i64 < 0 || i32 <= i64 || iEnd <= i32 {
		t.Fatalf("unexpected ABI preprocessor structure in native/reauth_android.c")
	}

	cases := []struct {
		name      string
		tablePath string
		section   string
		stubs     []struct {
			macro    string
			arrName  string
			editOff  int64
			sliceOff int
		}
	}{
		{
			name:      "arm64",
			tablePath: "patches/libgame-arm64.tbl",
			section:   src[i64:i32],
			stubs: []struct {
				macro    string
				arrName  string
				editOff  int64
				sliceOff int
			}{
				{"OFF_RESUME_REQ_GUEST", "k_resume_req_guest_bytes", 0x384ffd0, 12},
				{"OFF_RESUME_SET_VISIBLE_BTN", "k_resume_set_visible_btn_bytes", 0x384ffe4, 12},
			},
		},
		{
			name:      "armv7",
			tablePath: "patches/libgame-armv7.tbl",
			section:   src[i32:iEnd],
			stubs: []struct {
				macro    string
				arrName  string
				editOff  int64
				sliceOff int
			}{
				{"OFF_RESUME_REQ_GUEST", "k_resume_req_guest_bytes", 0x2080690, 16},
				{"OFF_RESUME_SET_VISIBLE_BTN", "k_resume_set_visible_btn_bytes", 0x2080674, 16},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tab := mustLoad(t, tc.tablePath)
			for _, st := range tc.stubs {
				ed := findTableEdit(t, tab, st.editOff)
				wantOff := st.editOff + int64(st.sliceOff)
				wantBytes := ed.Replacement[st.sliceOff:]

				gotOff := mustParseCHexMacro(t, tc.section, st.macro)
				if gotOff != wantOff {
					t.Fatalf("%s %s = %#x, want %#x", tc.name, st.macro, gotOff, wantOff)
				}
				gotBytes := mustParseCByteArray(t, tc.section, st.arrName)
				if !bytes.Equal(gotBytes, wantBytes) {
					t.Fatalf("%s %s = %x, want %x", tc.name, st.arrName, gotBytes, wantBytes)
				}
			}
		})
	}
}

func mustParseCHexMacro(t *testing.T, section, macro string) int64 {
	t.Helper()
	re := regexp.MustCompile(`#define\s+` + regexp.QuoteMeta(macro) + `\s+0x([0-9a-fA-F]+)u?`)
	m := re.FindStringSubmatch(section)
	if len(m) != 2 {
		t.Fatalf("macro %s not found", macro)
	}
	v, err := strconv.ParseInt(m[1], 16, 64)
	if err != nil {
		t.Fatalf("parse macro %s: %v", macro, err)
	}
	return v
}

func mustParseCByteArray(t *testing.T, section, name string) []byte {
	t.Helper()
	re := regexp.MustCompile(`static\s+const\s+uint8_t\s+` + regexp.QuoteMeta(name) + `\[\]\s*=\s*\{([^}]+)\};`)
	m := re.FindStringSubmatch(section)
	if len(m) != 2 {
		t.Fatalf("byte array %s not found", name)
	}
	byteRe := regexp.MustCompile(`0x([0-9a-fA-F]{2})`)
	matches := byteRe.FindAllStringSubmatch(m[1], -1)
	if len(matches) == 0 {
		t.Fatalf("byte array %s has no bytes", name)
	}
	out := make([]byte, 0, len(matches))
	for _, bm := range matches {
		b, err := strconv.ParseUint(bm[1], 16, 8)
		if err != nil {
			t.Fatalf("parse byte %s: %v", bm[1], err)
		}
		out = append(out, byte(b))
	}
	return out
}
