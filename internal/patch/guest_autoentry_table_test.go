package patch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

func TestGuestAutoEntryTables(t *testing.T) {
	arm64 := mustLoad(t, "patches/libgame-arm64.tbl")
	if len(arm64.Edits) != 2 || len(arm64.Windows) != 2 {
		t.Fatalf("arm64 edits/windows = %d/%d", len(arm64.Edits), len(arm64.Windows))
	}
	assertTableEdit(t, arm64, 0x1ceef0c, "97e8fe17", "70f2fe17", "createGuestAccount")
	assertTableEdit(t, arm64, 0x2f98021, "00", "f8", "state-6")
	assertTableWindow(t, arm64, 0x1ceee3c, "20030034")
	assertTableWindow(t, arm64, 0x1ceef00, "f35341a9f55b42a9fd7bc3a8")

	armv7 := mustLoad(t, "patches/libgame-armv7.tbl")
	if len(armv7.Edits) != 2 || len(armv7.Windows) != 3 {
		t.Fatalf("armv7 edits/windows = %d/%d", len(armv7.Edits), len(armv7.Windows))
	}
	assertTableEdit(t, armv7, 0x127a930, "e9f792bc", "eaf74cbe", "createGuestAccount")
	assertTableEdit(t, armv7, 0x13dc502, "39", "19", "state-6")
	assertTableWindow(t, armv7, 0x127a848, "08b3")
	assertTableWindow(t, armv7, 0x127a926, "20460121bd46bde8b040")
	assertTableWindow(t, armv7, 0x13dc500, "40f23933")
}

func TestGuestAutoEntryBranchTargets(t *testing.T) {
	arm64 := findTableEdit(t, mustLoad(t, "patches/libgame-arm64.tbl"), 0x1ceef0c)
	assertARM64Branch(t, arm64.Expected, uint64(arm64.Offset), 0x1ca9168, false)
	assertARM64Branch(t, arm64.Replacement, uint64(arm64.Offset), 0x1cab8cc, false)

	armv7 := findTableEdit(t, mustLoad(t, "patches/libgame-armv7.tbl"), 0x127a930)
	assertThumbBWide(t, armv7.Expected, uint32(armv7.Offset), 0x1264258)
	assertThumbBWide(t, armv7.Replacement, uint32(armv7.Offset), 0x12655cc)
}

func TestGuestAutoEntrySyntheticChangesOnlyChangedBytes(t *testing.T) {
	for _, name := range []string{"arm64", "armv7"} {
		t.Run(name, func(t *testing.T) {
			tab := mustLoad(t, "patches/libgame-"+name+".tbl")
			input := syntheticTableFixture(t, tab)

			// Keep the production hash locked in the table; only this synthetic copy gets a fixture digest.
			sum := sha256.Sum256(input)
			tab.SHA256 = hex.EncodeToString(sum[:])
			output, err := Apply(input, tab)
			if err != nil {
				t.Fatal(err)
			}

			wantOffsets := make([]int, 0)
			for _, edit := range tab.Edits {
				start := int(edit.Offset)
				if !bytes.Equal(output[start:start+len(edit.Replacement)], edit.Replacement) {
					t.Fatalf("replacement missing at %#x", edit.Offset)
				}
				for i := range edit.Replacement {
					if edit.Expected[i] != edit.Replacement[i] {
						wantOffsets = append(wantOffsets, start+i)
					}
				}
			}
			sort.Ints(wantOffsets)
			next := 0
			for i := range input {
				wantChanged := next < len(wantOffsets) && wantOffsets[next] == i
				if changed := input[i] != output[i]; changed != wantChanged {
					t.Fatalf("byte %#x changed=%v, wanted=%v", i, changed, wantChanged)
				}
				if wantChanged {
					next++
				}
			}
			if next != len(wantOffsets) {
				t.Fatalf("verified %d/%d intended changed bytes", next, len(wantOffsets))
			}
		})
	}
}

func assertTableEdit(t *testing.T, tab Table, offset int64, expected, replacement, comment string) {
	t.Helper()
	edit := findTableEdit(t, tab, offset)
	if hex.EncodeToString(edit.Expected) != expected || hex.EncodeToString(edit.Replacement) != replacement {
		t.Fatalf("edit %#x bytes = %x -> %x", offset, edit.Expected, edit.Replacement)
	}
	if !strings.Contains(edit.Comment, comment) {
		t.Fatalf("edit %#x comment = %q, want %q", offset, edit.Comment, comment)
	}
}

func findTableEdit(t *testing.T, tab Table, offset int64) Edit {
	t.Helper()
	for _, edit := range tab.Edits {
		if edit.Offset == offset {
			return edit
		}
	}
	t.Fatalf("no edit at %#x", offset)
	return Edit{}
}

func assertTableWindow(t *testing.T, tab Table, offset int64, expected string) {
	t.Helper()
	for _, window := range tab.Windows {
		if window.Offset == offset {
			if hex.EncodeToString(window.Expected) != expected {
				t.Fatalf("window %#x bytes = %x", offset, window.Expected)
			}
			return
		}
	}
	t.Fatalf("no window at %#x", offset)
}

func syntheticTableFixture(t *testing.T, tab Table) []byte {
	t.Helper()
	var size int64
	for _, window := range tab.Windows {
		if end := window.Offset + int64(len(window.Expected)); end > size {
			size = end
		}
	}
	for _, edit := range tab.Edits {
		if end := edit.Offset + int64(len(edit.Expected)); end > size {
			size = end
		}
	}
	fixture := make([]byte, int(size))
	for _, window := range tab.Windows {
		copy(fixture[window.Offset:], window.Expected)
	}
	for _, edit := range tab.Edits {
		copy(fixture[edit.Offset:], edit.Expected)
	}
	return fixture
}

func assertARM64Branch(t *testing.T, instruction []byte, pc, wantTarget uint64, wantLink bool) {
	t.Helper()
	if len(instruction) != 4 {
		t.Fatalf("arm64 branch length = %d", len(instruction))
	}
	word := binary.LittleEndian.Uint32(instruction)
	if word&0x7c000000 != 0x14000000 {
		t.Fatalf("not an arm64 B/BL encoding: %08x", word)
	}
	imm := int64(word & 0x03ffffff)
	if imm&(1<<25) != 0 {
		imm |= ^int64(0x03ffffff)
	}
	target := uint64(int64(pc) + (imm << 2))
	link := word&(1<<31) != 0
	if target != wantTarget || link != wantLink {
		t.Fatalf("arm64 branch at %#x targets %#x link=%v; want %#x link=%v", pc, target, link, wantTarget, wantLink)
	}
}

func assertThumbBWide(t *testing.T, instruction []byte, pc, wantTarget uint32) {
	t.Helper()
	if len(instruction) != 4 {
		t.Fatalf("Thumb B.W length = %d", len(instruction))
	}
	first := binary.LittleEndian.Uint16(instruction[:2])
	second := binary.LittleEndian.Uint16(instruction[2:])
	if first&0xf800 != 0xf000 || second&0xd000 != 0x9000 {
		t.Fatalf("not a Thumb B.W encoding: %04x %04x", first, second)
	}
	s := int32((first >> 10) & 1)
	j1 := int32((second >> 13) & 1)
	j2 := int32((second >> 11) & 1)
	i1 := ^(j1 ^ s) & 1
	i2 := ^(j2 ^ s) & 1
	imm := s<<24 | i1<<23 | i2<<22 | int32(first&0x03ff)<<12 | int32(second&0x07ff)<<1
	if imm&(1<<24) != 0 {
		imm |= ^int32(0x01ffffff)
	}
	target := uint32(int64(pc) + 4 + int64(imm))
	if target != wantTarget {
		t.Fatalf("Thumb B.W at %#x targets %#x; want %#x", pc, target, wantTarget)
	}
}
