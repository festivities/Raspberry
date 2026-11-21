package patch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf16"
)

// ManifestSHA is the locked digest of the stock binary AndroidManifest.xml
// (LINE PLAY 10.1.0.0, versionCode 254).
const ManifestSHA = "e8b420e5abdb98f82426f06fb7b86e808e74ae61700d8d4deac16b83e55668df"

// ErrManifest means the binary XML is malformed or lacks a string or resource
// ID the edit needs. Errors never include manifest bytes.
var ErrManifest = errors.New("patch: bad manifest")

// Binary XML chunk types, value types and the android:* resource IDs used.
const (
	axmlTypeXML    = 0x0003
	axmlTypePool   = 0x0001
	axmlTypeResMap = 0x0180
	axmlTypeNSBeg  = 0x0100
	axmlTypeNSEnd  = 0x0101
	axmlTypeBeg    = 0x0102
	axmlTypeEnd    = 0x0103

	axmlNone     = 0xFFFFFFFF
	axmlFlagUTF8 = 0x100
	axmlFlagSort = 0x1
	axmlNSURI    = "http://schemas.android.com/apk/res/android"

	axmlValRef  = 0x01 // TYPE_REFERENCE
	axmlValStr  = 0x03 // TYPE_STRING
	axmlValBool = 0x12 // TYPE_INT_BOOLEAN

	resTheme     = 0x01010000
	resName      = 0x01010003
	resExported  = 0x01010010
	resScheme    = 0x01010027
	resHost      = 0x01010028
	resNoDisplay = 0x01030055 // @android:style/Theme.NoDisplay
)

// AddAuthReturn adds the raspberry://auth return activity as the last child of
// <application> in the locked stock manifest. Strings and nodes that already
// exist keep their indices and bytes; only new strings and nodes are added.
func AddAuthReturn(manifest []byte) ([]byte, error) {
	sum := sha256.Sum256(manifest)
	if got := hex.EncodeToString(sum[:]); got != ManifestSHA {
		return nil, fmt.Errorf("%w: got %s", ErrHash, got)
	}
	return addAuthReturn(manifest)
}

// addAuthReturn is AddAuthReturn without the digest lock, for synthetic inputs.
func addAuthReturn(in []byte) ([]byte, error) {
	root, err := chunkAt(in, 0)
	if err != nil || root.typ != axmlTypeXML || root.hdr != 8 || root.size != len(in) {
		return nil, ErrManifest
	}
	const p = 8 // string pool chunk offset
	pool, err := chunkAt(in, p)
	if err != nil || pool.typ != axmlTypePool || pool.hdr != 28 || pool.size%4 != 0 {
		return nil, ErrManifest
	}
	poolEnd := p + pool.size
	count := int(le32(in, p+8))
	flags := le32(in, p+16)
	strStart := int(le32(in, p+20))
	if le32(in, p+12) != 0 || flags&axmlFlagUTF8 != 0 || 28+4*count > pool.size || strStart != 28+4*count {
		return nil, ErrManifest
	}
	strs := make([]string, count)
	for i := range strs {
		s, err := utf16At(in, p+strStart+int(le32(in, p+28+4*i)), poolEnd)
		if err != nil {
			return nil, err
		}
		strs[i] = s
	}

	mapOff := poolEnd
	rm, err := chunkAt(in, mapOff)
	if err != nil || rm.typ != axmlTypeResMap || rm.hdr != 8 || rm.size%4 != 0 {
		return nil, ErrManifest
	}
	ids := make([]uint32, (rm.size-8)/4)
	for i := range ids {
		ids[i] = le32(in, mapOff+8+4*i)
	}

	// Walk the nodes: the android namespace, strict nesting, and the one
	// </application> that sits at depth 2 under <manifest>.
	var open []string
	nsURI, appEnd, appEnds := -1, -1, 0
	for off := mapOff + rm.size; off < len(in); {
		c, err := chunkAt(in, off)
		if err != nil || c.hdr != 16 || c.size < 24 {
			return nil, ErrManifest
		}
		ref := int(le32(in, off+20)) // namespace URI, or element name
		switch c.typ {
		case axmlTypeNSBeg:
			if ref < count && strs[ref] == axmlNSURI && nsURI < 0 {
				nsURI = ref
			}
		case axmlTypeNSEnd:
		case axmlTypeBeg:
			if ref >= count {
				return nil, ErrManifest
			}
			open = append(open, strs[ref])
		case axmlTypeEnd:
			if ref >= count || len(open) == 0 || open[len(open)-1] != strs[ref] {
				return nil, ErrManifest
			}
			if strs[ref] == "application" {
				appEnds++
				if len(open) != 2 || open[0] != "manifest" {
					return nil, ErrManifest
				}
				appEnd = off
			}
			open = open[:len(open)-1]
		default:
			return nil, ErrManifest
		}
		off += c.size
	}
	if len(open) != 0 || nsURI < 0 || appEnds != 1 {
		return nil, ErrManifest
	}

	// Attribute names are found by resource ID, and the pool entry must agree.
	attr := func(id uint32, label string) (uint32, error) {
		for i, v := range ids {
			if v == id {
				if i < count && strs[i] == label {
					return uint32(i), nil
				}
				break
			}
		}
		return 0, ErrManifest
	}
	var ax [5]uint32 // theme, name, exported, scheme, host
	for i, w := range []struct {
		id    uint32
		label string
	}{{resTheme, "theme"}, {resName, "name"}, {resExported, "exported"}, {resScheme, "scheme"}, {resHost, "host"}} {
		if ax[i], err = attr(w.id, w.label); err != nil {
			return nil, err
		}
	}

	// str reuses an existing pool string when one has the same value.
	all := strs
	str := func(s string) uint32 {
		for i, v := range all {
			if v == s {
				return uint32(i)
			}
		}
		all = append(all, s)
		return uint32(len(all) - 1)
	}
	ns := uint32(nsURI)
	cls := str("dev.raspberry.AuthReturn")
	var add []byte
	add = appendStart(add, ns, str("activity"), []axmlAttr{
		{ax[0], axmlNone, axmlValRef, resNoDisplay},
		strAttr(ax[1], cls),
		{ax[2], axmlNone, axmlValBool, axmlNone},
	})
	add = appendStart(add, ns, str("intent-filter"), nil)
	add = appendStart(add, ns, str("action"), []axmlAttr{strAttr(ax[1], str("android.intent.action.VIEW"))})
	add = appendEnd(add, str("action"))
	add = appendStart(add, ns, str("category"), []axmlAttr{strAttr(ax[1], str("android.intent.category.DEFAULT"))})
	add = appendEnd(add, str("category"))
	add = appendStart(add, ns, str("category"), []axmlAttr{strAttr(ax[1], str("android.intent.category.BROWSABLE"))})
	add = appendEnd(add, str("category"))
	add = appendStart(add, ns, str("data"), []axmlAttr{strAttr(ax[3], str("raspberry")), strAttr(ax[4], str("auth"))})
	add = appendEnd(add, str("data"))
	add = appendEnd(add, str("intent-filter"))
	add = appendEnd(add, str("activity"))

	// Old offsets and string bytes are copied as they are (the old chunk already
	// ends on a 4-byte boundary); new strings are appended after them.
	data := append([]byte(nil), in[p+strStart:poolEnd]...)
	offs := append([]byte(nil), in[p+28:p+28+4*count]...)
	for _, s := range all[count:] {
		offs = binary.LittleEndian.AppendUint32(offs, uint32(len(data)))
		data = appendUTF16(data, s)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	newStart := 28 + len(offs)
	pool2 := make([]byte, 0, newStart+len(data))
	pool2 = binary.LittleEndian.AppendUint16(pool2, axmlTypePool)
	pool2 = binary.LittleEndian.AppendUint16(pool2, 28)
	pool2 = binary.LittleEndian.AppendUint32(pool2, uint32(newStart+len(data)))
	pool2 = binary.LittleEndian.AppendUint32(pool2, uint32(len(all)))
	pool2 = binary.LittleEndian.AppendUint32(pool2, 0) // styleCount
	pool2 = binary.LittleEndian.AppendUint32(pool2, flags&^axmlFlagSort)
	pool2 = binary.LittleEndian.AppendUint32(pool2, uint32(newStart))
	pool2 = binary.LittleEndian.AppendUint32(pool2, 0) // stylesStart
	pool2 = append(pool2, offs...)
	pool2 = append(pool2, data...)

	out := make([]byte, 0, len(in)+len(add)+len(pool2))
	out = append(out, in[:p]...)
	out = append(out, pool2...)
	out = append(out, in[poolEnd:appEnd]...) // resource map and nodes before </application>
	out = append(out, add...)
	out = append(out, in[appEnd:]...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// axmlAttr is one attribute to emit. name is a pool index whose resource ID is
// in the resource map; raw is axmlNone for typed values.
type axmlAttr struct {
	name, raw uint32
	typ       uint8
	data      uint32
}

// strAttr is a string attribute: raw and data both hold the string index.
func strAttr(name, s uint32) axmlAttr { return axmlAttr{name, s, axmlValStr, s} }

// appendStart encodes a start element. attrNS is the namespace index of the
// attributes; the element itself is unqualified.
func appendStart(b []byte, attrNS, name uint32, attrs []axmlAttr) []byte {
	b = binary.LittleEndian.AppendUint16(b, axmlTypeBeg)
	b = binary.LittleEndian.AppendUint16(b, 16)
	b = binary.LittleEndian.AppendUint32(b, uint32(16+20+20*len(attrs)))
	b = binary.LittleEndian.AppendUint32(b, 0)        // line number
	b = binary.LittleEndian.AppendUint32(b, axmlNone) // comment
	b = binary.LittleEndian.AppendUint32(b, axmlNone) // element namespace
	b = binary.LittleEndian.AppendUint32(b, name)
	b = binary.LittleEndian.AppendUint16(b, 20) // attributeStart
	b = binary.LittleEndian.AppendUint16(b, 20) // attributeSize
	b = binary.LittleEndian.AppendUint16(b, uint16(len(attrs)))
	b = append(b, 0, 0, 0, 0, 0, 0) // id, class and style indexes
	for _, a := range attrs {
		b = binary.LittleEndian.AppendUint32(b, attrNS)
		b = binary.LittleEndian.AppendUint32(b, a.name)
		b = binary.LittleEndian.AppendUint32(b, a.raw)
		b = binary.LittleEndian.AppendUint16(b, 8) // Res_value.size
		b = append(b, 0, a.typ)                    // res0, dataType
		b = binary.LittleEndian.AppendUint32(b, a.data)
	}
	return b
}

// appendEnd encodes an end element for an unqualified element.
func appendEnd(b []byte, name uint32) []byte {
	b = binary.LittleEndian.AppendUint16(b, axmlTypeEnd)
	b = binary.LittleEndian.AppendUint16(b, 16)
	b = binary.LittleEndian.AppendUint32(b, 24)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, axmlNone)
	b = binary.LittleEndian.AppendUint32(b, axmlNone)
	return binary.LittleEndian.AppendUint32(b, name)
}

// appendUTF16 appends s as a pool string: unit count, UTF-16LE units, NUL.
func appendUTF16(b []byte, s string) []byte {
	u := utf16.Encode([]rune(s))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(u)))
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return binary.LittleEndian.AppendUint16(b, 0)
}

// chunkAt reads the chunk header at off and checks that the chunk fits in buf.
func chunkAt(buf []byte, off int) (chunk, error) {
	if off < 0 || off > len(buf)-8 {
		return chunk{}, ErrManifest
	}
	c := chunk{
		typ:  int(binary.LittleEndian.Uint16(buf[off:])),
		hdr:  int(binary.LittleEndian.Uint16(buf[off+2:])),
		size: int(binary.LittleEndian.Uint32(buf[off+4:])),
	}
	if c.hdr < 8 || c.size < c.hdr || c.size > len(buf)-off {
		return chunk{}, ErrManifest
	}
	return c, nil
}

type chunk struct{ typ, hdr, size int }

// le32 reads a little-endian uint32; callers check bounds first.
func le32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

// utf16At decodes the pool string at off, which must end before end.
func utf16At(b []byte, off, end int) (string, error) {
	if off < 0 || end > len(b) || off+2 > end {
		return "", ErrManifest
	}
	n := int(binary.LittleEndian.Uint16(b[off:]))
	off += 2
	if n&0x8000 != 0 {
		if off+2 > end {
			return "", ErrManifest
		}
		n = (n&0x7fff)<<16 | int(binary.LittleEndian.Uint16(b[off:]))
		off += 2
	}
	if n > (end-off)/2-1 { // the NUL terminator needs two more bytes
		return "", ErrManifest
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[off+2*i:])
	}
	return string(utf16.Decode(u)), nil
}
