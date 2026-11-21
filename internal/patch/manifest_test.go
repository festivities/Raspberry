package patch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// wantAuthActivity is the new activity as docs/patches.md states it.
const wantAuthActivity = `activity theme(0x1010000)=ref(0x1030055) name(0x1010003)=str("dev.raspberry.AuthReturn") exported(0x1010010)=bool(0xffffffff)
  intent-filter
    action name(0x1010003)=str("android.intent.action.VIEW")
    category name(0x1010003)=str("android.intent.category.DEFAULT")
    category name(0x1010003)=str("android.intent.category.BROWSABLE")
    data scheme(0x1010027)=str("raspberry") host(0x1010028)=str("auth")
`

var errTestAXML = errors.New("test: malformed binary xml")

// synthManifest is a tiny stand-in for the stock manifest:
// manifest > application > activity(name=pkg.Main). The resource map covers
// only the first five strings, as aapt2 output does, and "auth" is pooled.
func synthManifest(flags uint32) []byte {
	strs := []string{"theme", "name", "exported", "scheme", "host",
		axmlNSURI, "android", "manifest", "application", "activity", "pkg.Main", "auth"}
	ids := []uint32{resTheme, resName, resExported, resScheme, resHost}
	var nodes []byte
	nodes = appendNS(nodes, axmlTypeNSBeg, 6, 5)
	nodes = appendStart(nodes, axmlNone, 7, nil)
	nodes = appendStart(nodes, axmlNone, 8, nil)
	nodes = appendStart(nodes, 5, 9, []axmlAttr{strAttr(1, 10)})
	nodes = appendEnd(nodes, 9)
	nodes = appendEnd(nodes, 8)
	nodes = appendEnd(nodes, 7)
	nodes = appendNS(nodes, axmlTypeNSEnd, 6, 5)

	var rmap []byte
	rmap = binary.LittleEndian.AppendUint16(rmap, axmlTypeResMap)
	rmap = binary.LittleEndian.AppendUint16(rmap, 8)
	rmap = binary.LittleEndian.AppendUint32(rmap, uint32(8+4*len(ids)))
	for _, id := range ids {
		rmap = binary.LittleEndian.AppendUint32(rmap, id)
	}

	body := append(append(poolBytes(strs, flags), rmap...), nodes...)
	file := binary.LittleEndian.AppendUint16(nil, axmlTypeXML)
	file = binary.LittleEndian.AppendUint16(file, 8)
	file = binary.LittleEndian.AppendUint32(file, uint32(8+len(body)))
	return append(file, body...)
}

// poolBytes encodes strs as a UTF-16 string pool with the given flags.
func poolBytes(strs []string, flags uint32) []byte {
	var offs, data []byte
	for _, s := range strs {
		offs = binary.LittleEndian.AppendUint32(offs, uint32(len(data)))
		data = appendUTF16(data, s)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	var b []byte
	b = binary.LittleEndian.AppendUint16(b, axmlTypePool)
	b = binary.LittleEndian.AppendUint16(b, 28)
	b = binary.LittleEndian.AppendUint32(b, uint32(28+len(offs)+len(data)))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(strs)))
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, flags)
	b = binary.LittleEndian.AppendUint32(b, uint32(28+len(offs)))
	b = binary.LittleEndian.AppendUint32(b, 0)
	return append(append(b, offs...), data...)
}

// appendNS encodes a namespace start or end node.
func appendNS(b []byte, typ uint16, prefix, uri uint32) []byte {
	b = binary.LittleEndian.AppendUint16(b, typ)
	b = binary.LittleEndian.AppendUint16(b, 16)
	b = binary.LittleEndian.AppendUint32(b, 24)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, axmlNone)
	b = binary.LittleEndian.AppendUint32(b, prefix)
	return binary.LittleEndian.AppendUint32(b, uri)
}

// rdr is a bounds-checked little-endian reader; the first failure sticks.
type rdr struct {
	b   []byte
	err error
}

func (r *rdr) check(off, n int) bool {
	if r.err == nil && (off < 0 || n < 0 || off > len(r.b) || n > len(r.b)-off) {
		r.err = errTestAXML
	}
	return r.err == nil
}

func (r *rdr) u16(off int) int {
	if !r.check(off, 2) {
		return 0
	}
	return int(binary.LittleEndian.Uint16(r.b[off:]))
}

func (r *rdr) u32(off int) uint32 {
	if !r.check(off, 4) {
		return 0
	}
	return binary.LittleEndian.Uint32(r.b[off:])
}

// tAttr, tElem and tDoc are a second, independent decode of the binary XML.
type tAttr struct {
	ns, name, raw uint32
	typ           int
	data          uint32
}

type tElem struct {
	name  string
	ns    uint32
	attrs []tAttr
	kids  []*tElem
}

type tDoc struct {
	flags  uint32
	strs   []string
	ids    []uint32
	resMap []byte
	nodes  []byte
	root   *tElem
	appEnd int // offset of </application> inside nodes, -1 when absent
}

func decodeAXML(b []byte) (*tDoc, error) {
	r := &rdr{b: b}
	if r.u16(0) != 3 || r.u16(2) != 8 || r.u32(4) != uint32(len(b)) {
		return nil, errTestAXML
	}
	const p = 8
	if r.u16(p) != 1 || r.u16(p+2) != 28 {
		return nil, errTestAXML
	}
	poolSize := int(r.u32(p + 4))
	count := int(r.u32(p + 8))
	flags := r.u32(p + 16)
	strStart := int(r.u32(p + 20))
	if !r.check(p, poolSize) || r.u32(p+12) != 0 || flags&axmlFlagUTF8 != 0 ||
		poolSize%4 != 0 || 28+4*count > poolSize || strStart != 28+4*count {
		return nil, errTestAXML
	}
	strs := make([]string, count)
	for i := range strs {
		s, err := decodeUTF16(b, p+strStart+int(r.u32(p+28+4*i)), p+poolSize)
		if err != nil {
			return nil, err
		}
		strs[i] = s
	}

	mapOff := p + poolSize
	mapSize := int(r.u32(mapOff + 4))
	if r.u16(mapOff) != 0x180 || r.u16(mapOff+2) != 8 || mapSize < 8 || mapSize%4 != 0 || !r.check(mapOff, mapSize) {
		return nil, errTestAXML
	}
	ids := make([]uint32, (mapSize-8)/4)
	for i := range ids {
		ids[i] = r.u32(mapOff + 8 + 4*i)
	}
	nodesOff := mapOff + mapSize
	if !r.check(nodesOff, 0) {
		return nil, errTestAXML
	}
	doc := &tDoc{flags: flags, strs: strs, ids: ids, resMap: b[mapOff:nodesOff], nodes: b[nodesOff:], appEnd: -1}

	nameOf := func(i int) (string, error) {
		if i < 0 || i >= len(strs) {
			return "", errTestAXML
		}
		return strs[i], nil
	}
	var stack []*tElem
	appEnds := 0
	for off := nodesOff; off < len(b); {
		typ, size := r.u16(off), int(r.u32(off+4))
		if r.u16(off+2) != 16 || size < 24 || !r.check(off, size) {
			return nil, errTestAXML
		}
		ref := int(r.u32(off + 20))
		switch typ {
		case 0x0100, 0x0101:
			if size != 24 {
				return nil, errTestAXML
			}
		case 0x0102:
			attrCount := r.u16(off + 28)
			if size != 36+20*attrCount || r.u16(off+24) != 20 || r.u16(off+26) != 20 {
				return nil, errTestAXML
			}
			name, err := nameOf(ref)
			if err != nil {
				return nil, err
			}
			e := &tElem{name: name, ns: r.u32(off + 16)}
			for i := 0; i < attrCount; i++ {
				a := off + 36 + 20*i
				if _, err := nameOf(int(r.u32(a + 4))); err != nil {
					return nil, err
				}
				vh := r.u16(a + 14) // res0 low byte, dataType high byte
				if r.u16(a+12) != 8 || vh&0xff != 0 {
					return nil, errTestAXML
				}
				e.attrs = append(e.attrs, tAttr{ns: r.u32(a), name: r.u32(a + 4), raw: r.u32(a + 8), typ: vh >> 8, data: r.u32(a + 16)})
			}
			if r.err != nil {
				return nil, r.err
			}
			if len(stack) == 0 {
				if doc.root != nil {
					return nil, errTestAXML
				}
				doc.root = e
			} else {
				parent := stack[len(stack)-1]
				parent.kids = append(parent.kids, e)
			}
			stack = append(stack, e)
		case 0x0103:
			name, err := nameOf(ref)
			if err != nil || size != 24 || len(stack) == 0 || stack[len(stack)-1].name != name {
				return nil, errTestAXML
			}
			if name == "application" {
				appEnds++
				if len(stack) != 2 || stack[0].name != "manifest" {
					return nil, errTestAXML
				}
				doc.appEnd = off - nodesOff
			}
			stack = stack[:len(stack)-1]
		default:
			return nil, errTestAXML
		}
		if r.err != nil {
			return nil, r.err
		}
		off += size
	}
	if len(stack) != 0 || doc.root == nil || appEnds != 1 || doc.appEnd < 0 {
		return nil, errTestAXML
	}
	return doc, nil
}

// decodeUTF16 reads one pool string at off that must end before end.
func decodeUTF16(b []byte, off, end int) (string, error) {
	if end > len(b) || off < 0 || off+2 > end {
		return "", errTestAXML
	}
	n := int(binary.LittleEndian.Uint16(b[off:]))
	off += 2
	if n&0x8000 != 0 {
		if off+2 > end {
			return "", errTestAXML
		}
		n = (n&0x7fff)<<16 | int(binary.LittleEndian.Uint16(b[off:]))
		off += 2
	}
	if n > (end-off)/2-1 {
		return "", errTestAXML
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[off+2*i:])
	}
	return string(utf16.Decode(u)), nil
}

func (d *tDoc) str(i uint32) string {
	if int(i) < len(d.strs) {
		return d.strs[i]
	}
	return "<out of range>"
}

func (d *tDoc) id(i uint32) uint32 {
	if int(i) < len(d.ids) {
		return d.ids[i]
	}
	return 0
}

// describe prints an element tree in the canonical form wantAuthActivity uses.
func (d *tDoc) describe(e *tElem, indent string) string {
	var sb strings.Builder
	sb.WriteString(indent + e.name)
	for _, a := range e.attrs {
		label, id := d.str(a.name), d.id(a.name)
		switch a.typ {
		case axmlValRef:
			fmt.Fprintf(&sb, " %s(%#x)=ref(%#x)", label, id, a.data)
		case axmlValStr:
			fmt.Fprintf(&sb, " %s(%#x)=str(%q)", label, id, d.str(a.data))
		case axmlValBool:
			fmt.Fprintf(&sb, " %s(%#x)=bool(%#x)", label, id, a.data)
		default:
			fmt.Fprintf(&sb, " %s(%#x)=type%#x(%#x)", label, id, a.typ, a.data)
		}
	}
	sb.WriteString("\n")
	for _, k := range e.kids {
		sb.WriteString(d.describe(k, indent+"  "))
	}
	return sb.String()
}

func child(e *tElem, name string) *tElem {
	for _, k := range e.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func countStr(strs []string, s string) int {
	n := 0
	for _, v := range strs {
		if v == s {
			n++
		}
	}
	return n
}

// checkAuthReturn asserts that out is orig plus exactly one activity, placed
// last in <application>, and that nothing else changed.
func checkAuthReturn(t *testing.T, orig, out []byte) {
	t.Helper()
	before, err := decodeAXML(orig)
	if err != nil {
		t.Fatalf("input does not decode: %v", err)
	}
	after, err := decodeAXML(out)
	if err != nil {
		t.Fatalf("output does not decode: %v", err)
	}
	if want := before.flags &^ axmlFlagSort; after.flags != want {
		t.Fatalf("pool flags %#x, want %#x", after.flags, want)
	}
	if len(after.strs) < len(before.strs) {
		t.Fatal("string pool shrank")
	}
	for i, s := range before.strs {
		if after.strs[i] != s {
			t.Fatalf("pool string %d changed", i)
		}
	}
	if !bytes.Equal(after.resMap, before.resMap) {
		t.Fatal("resource map changed")
	}
	if before.appEnd < 0 {
		t.Fatal("no </application> at depth 2")
	}
	// Only the new block sits between the old bytes before and after </application>.
	k := before.appEnd
	tail := before.nodes[k:]
	if len(after.nodes) < k+len(tail) || !bytes.Equal(after.nodes[:k], before.nodes[:k]) ||
		!bytes.Equal(after.nodes[len(after.nodes)-len(tail):], tail) {
		t.Fatal("existing nodes changed")
	}

	bApp, aApp := child(before.root, "application"), child(after.root, "application")
	if bApp == nil || aApp == nil || after.root.name != "manifest" || len(aApp.kids) != len(bApp.kids)+1 {
		t.Fatal("application does not gain exactly one child")
	}
	for i, kid := range bApp.kids {
		if before.describe(kid, "") != after.describe(aApp.kids[i], "") {
			t.Fatalf("application child %d changed", i)
		}
	}
	act := aApp.kids[len(aApp.kids)-1]
	if got := after.describe(act, ""); got != wantAuthActivity {
		t.Fatalf("new activity:\n%s\nwant:\n%s", got, wantAuthActivity)
	}

	uri := countStr(after.strs, axmlNSURI)
	uriIdx := -1
	for i, s := range after.strs {
		if s == axmlNSURI {
			uriIdx = i
			break
		}
	}
	if uri != 1 || uriIdx < 0 {
		t.Fatalf("android namespace URI pooled %d times", uri)
	}
	var check func(e *tElem)
	check = func(e *tElem) {
		if e.ns != axmlNone {
			t.Fatalf("element %s has namespace %#x", e.name, e.ns)
		}
		for _, a := range e.attrs {
			if a.ns != uint32(uriIdx) {
				t.Fatalf("attribute of %s has namespace %#x", e.name, a.ns)
			}
			if a.typ == axmlValStr && a.raw != a.data {
				t.Fatalf("string attribute of %s has raw %#x data %#x", e.name, a.raw, a.data)
			}
			if a.typ != axmlValStr && a.raw != axmlNone {
				t.Fatalf("typed attribute of %s has raw %#x", e.name, a.raw)
			}
		}
		for _, kid := range e.kids {
			check(kid)
		}
	}
	check(act)
}

func TestAddAuthReturnSynthetic(t *testing.T) {
	for _, flags := range []uint32{0, axmlFlagSort} {
		in := synthManifest(flags)
		out, err := addAuthReturn(in)
		if err != nil {
			t.Fatalf("flags %#x: %v", flags, err)
		}
		checkAuthReturn(t, in, out)
		d, err := decodeAXML(out)
		if err != nil {
			t.Fatal(err)
		}
		if d.flags != 0 {
			t.Fatalf("sorted flag kept: %#x", d.flags)
		}
		// "auth" was already pooled and must be reused; "raspberry" is new.
		if n := countStr(d.strs, "auth"); n != 1 {
			t.Fatalf("auth pooled %d times", n)
		}
		if n := countStr(d.strs, "raspberry"); n != 1 {
			t.Fatalf("raspberry pooled %d times", n)
		}
	}
}

func TestAddAuthReturnRejects(t *testing.T) {
	in := synthManifest(0)
	if _, err := AddAuthReturn(in); !errors.Is(err, ErrHash) {
		t.Fatalf("unlocked input: %v", err)
	}
	for n := range in {
		if _, err := addAuthReturn(in[:n]); err == nil {
			t.Fatalf("truncated to %d bytes accepted", n)
		}
	}
	// Flipped bytes may decode or be refused, but must never panic.
	for i := range in {
		for _, v := range []byte{0x00, 0xff} {
			mut := bytes.Clone(in)
			mut[i] = v
			_, _ = addAuthReturn(mut)
		}
	}
}

func TestAddAuthReturnRealManifest(t *testing.T) {
	path := filepath.Join(os.TempDir(), "opencode", "raspberry", "authreturn-20261121", "AndroidManifest.xml")
	in, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("private stock manifest not present at %s", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	out, err := AddAuthReturn(in)
	if err != nil {
		t.Fatal(err)
	}
	checkAuthReturn(t, in, out)
}
