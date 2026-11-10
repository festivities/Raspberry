// Package descriptor parses the v1 endpoint descriptor.
// Unknown top-level keys are ignored and never copied into errors: a caller
// may have put an operator secret in one.
package descriptor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const maxBytes = 64 << 10

// Descriptor is a validated v1 endpoint. Ports always contains the four
// original client ports; a missing key was filled with identity.
type Descriptor struct {
	V     int         `json:"v"`
	Host  string      `json:"host"`
	Ports map[int]int `json:"ports"`
}

// MapPort returns the endpoint port for a client destination port.
// Ports outside the v1 set are unchanged.
func (d Descriptor) MapPort(original int) int {
	if p, ok := d.Ports[original]; ok {
		return p
	}
	return original
}

// Parse validates a v1 descriptor. Host is a DNS name or an IPv4 literal.
// Port object keys must be the four original client ports; values are 1..65535.
// A missing ports key, or a missing key inside ports, means identity.
func Parse(b []byte) (Descriptor, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return Descriptor{}, errDesc("empty")
	}
	if len(b) > maxBytes {
		return Descriptor{}, errDesc("too large")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var top map[string]any
	if err := dec.Decode(&top); err != nil {
		return Descriptor{}, errDesc("not json")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Descriptor{}, errDesc("trailing data")
	}

	v, ok := top["v"]
	if !ok || !exactInt(v, 1) {
		return Descriptor{}, errDesc("v must be 1")
	}
	rawHost, ok := top["host"]
	if !ok {
		return Descriptor{}, errDesc("host required")
	}
	host, ok := rawHost.(string)
	if !ok {
		return Descriptor{}, errDesc("host invalid")
	}
	canon, ok := canonicalHost(host)
	if !ok {
		return Descriptor{}, errDesc("host invalid")
	}

	ports := identityPorts()
	if rawPorts, ok := top["ports"]; ok {
		obj, ok := rawPorts.(map[string]any)
		if !ok {
			return Descriptor{}, errDesc("ports invalid")
		}
		for key, val := range obj {
			orig, ok := originalKey(key)
			if !ok {
				return Descriptor{}, errDesc("port key not allowed")
			}
			p, ok := portValue(val)
			if !ok {
				return Descriptor{}, errDesc("port out of range")
			}
			ports[orig] = p
		}
	}
	return Descriptor{V: 1, Host: canon, Ports: ports}, nil
}

func errDesc(msg string) error {
	return fmt.Errorf("descriptor: %s", msg)
}

func identityPorts() map[int]int {
	return map[int]int{80: 80, 443: 443, 10000: 10000, 10123: 10123}
}

func originalKey(k string) (int, bool) {
	switch k {
	case "80":
		return 80, true
	case "443":
		return 443, true
	case "10000":
		return 10000, true
	case "10123":
		return 10123, true
	default:
		return 0, false
	}
}

func exactInt(v any, want int) bool {
	n, ok := v.(json.Number)
	if !ok || n.String() != fmt.Sprintf("%d", want) {
		return false
	}
	return true
}

func portValue(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := n.String()
	if s == "" || strings.ContainsAny(s, ".eE+") || strings.HasPrefix(s, "-") {
		return 0, false
	}
	p := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		p = p*10 + int(c-'0')
		if p > 65535 {
			return 0, false
		}
	}
	if p < 1 {
		return 0, false
	}
	return p, true
}

func canonicalHost(s string) (string, bool) {
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, r := range s {
		if r > 127 || r < 0x21 {
			return "", false
		}
	}
	if strings.ContainsAny(s, ":/\\@?#") {
		return "", false
	}
	// inet_aton spellings are never DNS, even when the strict quad is invalid.
	if numericAddress(s) {
		return canonicalIPv4(s)
	}
	if !validDNS(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

func numericAddress(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) == 0 {
		return false
	}
	for _, lab := range labels {
		if !numericToken(lab) {
			return false
		}
	}
	return true
}

func numericToken(s string) bool {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		if len(s) == 2 {
			return false
		}
		for _, c := range s[2:] {
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			default:
				return false
			}
		}
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func canonicalIPv4(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	var b [4]byte
	for i, p := range parts {
		// Cap before arithmetic so a long decimal cannot wrap int into 0..255.
		if len(p) == 0 || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
			return "", false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return "", false
			}
			n = n*10 + int(c-'0')
		}
		if n < 0 || n > 255 {
			return "", false
		}
		b[i] = byte(n)
	}
	if b == [4]byte{198, 18, 0, 1} {
		// Native routing reserves this benchmarking address as an internal marker.
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), true
}

func validDNS(s string) bool {
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for _, lab := range labels {
		if len(lab) < 1 || len(lab) > 63 || lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for _, c := range lab {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}
