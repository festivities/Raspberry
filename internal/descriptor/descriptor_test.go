package descriptor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseIdentityAndRemap(t *testing.T) {
	d, err := Parse([]byte(`{"v":1,"host":"Cherry.Example.ORG"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.V != 1 || d.Host != "cherry.example.org" {
		t.Fatalf("%+v", d)
	}
	for _, p := range []int{80, 443, 10000, 10123} {
		if d.Ports[p] != p || d.MapPort(p) != p {
			t.Fatalf("port %d -> %d", p, d.Ports[p])
		}
	}
	if d.MapPort(9) != 9 {
		t.Fatal("unknown port should stay")
	}

	d, err = Parse([]byte(`{"v":1,"host":"cherry.example.org","note":"ignored","ports":{"443":8443}}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Ports[443] != 8443 || d.Ports[80] != 80 || d.Ports[10000] != 10000 || d.Ports[10123] != 10123 {
		t.Fatalf("%v", d.Ports)
	}
	if strings.Contains(d.Host, "note") {
		t.Fatal("unknown key leaked into host")
	}
}

func TestParseIPv4(t *testing.T) {
	d, err := Parse([]byte(`{"v":1,"host":"203.0.113.10","ports":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Host != "203.0.113.10" {
		t.Fatal(d.Host)
	}
	if _, err := Parse([]byte(`{"v":1,"host":"01.2.3.4"}`)); err == nil {
		t.Fatal("leading zero accepted")
	}
	if _, err := Parse([]byte(`{"v":1,"host":"1.2.3.256"}`)); err == nil {
		t.Fatal("octet accepted")
	}
	if _, err := Parse([]byte(`{"v":1,"host":"::1"}`)); err == nil {
		t.Fatal("ipv6 accepted")
	}
	if _, err := Parse([]byte(`{"v":1,"host":"198.18.0.1"}`)); err == nil {
		t.Fatal("reserved marker accepted")
	}
}

func TestParseRejects(t *testing.T) {
	cases := []string{
		``,
		`{}`,
		`{"v":2,"host":"cherry.example.org"}`,
		`{"v":"1","host":"cherry.example.org"}`,
		`{"v":1}`,
		`{"v":1,"host":""}`,
		`{"v":1,"host":"http://cherry.example.org"}`,
		`{"v":1,"host":"cherry.example.org:443"}`,
		`{"v":1,"host":"-bad.example"}`,
		`{"v":1,"host":"bad_host.example"}`,
		`{"v":1,"host":"cherry.example.org","ports":{"22":22}}`,
		`{"v":1,"host":"cherry.example.org","ports":{"80":0}}`,
		`{"v":1,"host":"cherry.example.org","ports":{"80":65536}}`,
		`{"v":1,"host":"cherry.example.org","ports":{"80":"80"}}`,
		`{"v":1,"host":"cherry.example.org","ports":null}`,
		`{"v":1,"host":"cherry.example.org"} trailing`,
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c)); err == nil {
			t.Fatalf("accepted %s", c)
		}
	}
}

func TestParseDoesNotEchoSecret(t *testing.T) {
	const secret = "super-secret-token"
	raw := `{"v":1,"host":"bad host","secret":"` + secret + `","ports":{"80":1}}`
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "bad host") {
		t.Fatalf("error echoed input: %v", err)
	}
}

func TestParsePortEdges(t *testing.T) {
	d, err := Parse([]byte(`{"v":1,"host":"localhost","ports":{"80":1,"443":65535,"10000":10000,"10123":10123}}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.Host != "localhost" || d.Ports[80] != 1 || d.Ports[443] != 65535 {
		t.Fatalf("%+v", d)
	}
}

func TestParseRejectsAmbiguousIP(t *testing.T) {
	rejects := []string{
		"18446744073709551616.2.3.4",
		"9223372036854775808.0.0.1",
		"127.1",
		"2130706433",
		"0x7f000001",
		"0177.0.0.1",
		"0x7f.0.0.1",
	}
	for _, host := range rejects {
		raw := `{"v":1,"host":"` + host + `"}`
		d, err := Parse([]byte(raw))
		if err == nil {
			t.Fatalf("accepted %s as %s", host, d.Host)
		}
		if strings.Contains(err.Error(), host) || strings.Contains(d.Host, ".") {
			t.Fatalf("echoed or canonicalized %s: %v %+v", host, err, d)
		}
	}
	d, err := Parse([]byte(`{"v":1,"host":"localhost"}`))
	if err != nil || d.Host != "localhost" {
		t.Fatalf("localhost: %v %+v", err, d)
	}
	d, err = Parse([]byte(`{"v":1,"host":"127.0.0.1"}`))
	if err != nil || d.Host != "127.0.0.1" {
		t.Fatalf("quad: %v %+v", err, d)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	d, err := Parse([]byte(`{"v":1,"host":"Cherry.Example.ORG","ports":{"443":8443}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"v"`) || !strings.Contains(s, `"host"`) || !strings.Contains(s, `"ports"`) || !strings.Contains(s, `"443"`) || !strings.Contains(s, `"10000"`) {
		t.Fatalf("contract keys missing: %s", s)
	}
	if strings.Contains(s, `"V"`) || strings.Contains(s, `"Host"`) || strings.Contains(s, `"Ports"`) {
		t.Fatalf("go names leaked: %s", s)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != d.V || got.Host != d.Host || got.Ports[80] != 80 || got.Ports[443] != 8443 || got.Ports[10000] != 10000 || got.Ports[10123] != 10123 {
		t.Fatalf("roundtrip %+v", got)
	}
}

func TestParseTooLarge(t *testing.T) {
	b := append([]byte(`{"v":1,"host":"a.example","pad":"`), bytesRepeat('x', maxBytes)...)
	b = append(b, []byte(`"}`)...)
	_, err := Parse(b)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("%v", err)
	}
}

func bytesRepeat(c byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return b
}
