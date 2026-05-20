package mdns

import (
	"fmt"
	"strings"
	"testing"
)

// encodeName builds the wire-format DNS label encoding for a
// dotted name (test helper; no compression).
func encodeName(s string) string {
	const digits = "0123456789ABCDEF"
	var out []byte
	for _, label := range strings.Split(s, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	h := make([]byte, len(out)*2)
	for i, v := range out {
		h[i*2] = digits[v>>4]
		h[i*2+1] = digits[v&0x0F]
	}
	return string(h)
}

// TestDecodeQueryPTRWithQUBit pins a canonical mDNS DNS-SD
// query for `_airdrop._tcp.local` with the QU (Question
// Unicast Response) bit set.
func TestDecodeQueryPTRWithQUBit(t *testing.T) {
	enc := encodeName("_airdrop._tcp.local")
	// QCLASS = 0x8001 (QU + IN).
	in := "0000 0000 0001 0000 0000 0000 " +
		enc + " 000C 8001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Questions) != 1 {
		t.Fatalf("questions: got %d want 1", len(r.Questions))
	}
	q := r.Questions[0]
	if q.Name != "_airdrop._tcp.local" {
		t.Errorf("name: got %q want _airdrop._tcp.local", q.Name)
	}
	if q.TypeName != "PTR" {
		t.Errorf("type: got %q want PTR", q.TypeName)
	}
	if !q.QUUnicast {
		t.Errorf("QU bit: should be set")
	}
	if q.Class != 1 {
		t.Errorf("class: got %d want 1 (IN)", q.Class)
	}
}

// TestDecodePTRAnswerWithCacheFlush pins a PTR response with
// the cache-flush bit set (mDNS responder asserting authority).
func TestDecodePTRAnswerWithCacheFlush(t *testing.T) {
	enc := encodeName("_googlecast._tcp.local")
	target := encodeName("Living-Room-TV._googlecast._tcp.local")
	// Question + Answer. Cache-flush set on answer CLASS
	// (0x8001 = flush + IN).
	in := "0000 8400 0001 0001 0000 0000 " +
		enc + " 000C 0001 " +
		enc + " 000C 8001 00000078 " +
		fmt.Sprintf("%04X ", len(target)/2) + target
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Answers) != 1 {
		t.Fatalf("answers: got %d want 1", len(r.Answers))
	}
	a := r.Answers[0]
	if a.TypeName != "PTR" {
		t.Errorf("type: got %q want PTR", a.TypeName)
	}
	if !a.CacheFlush {
		t.Errorf("cache flush: should be set")
	}
	if a.TTL != 120 {
		t.Errorf("ttl: got %d want 120", a.TTL)
	}
	if a.NameData != "Living-Room-TV._googlecast._tcp.local" {
		t.Errorf("nameData: got %q", a.NameData)
	}
}

// TestDecodeSRVAnswer pins a SRV record decode — the DNS-SD
// instance → host:port mapping.
func TestDecodeSRVAnswer(t *testing.T) {
	question := encodeName("Living-Room-TV._googlecast._tcp.local")
	target := encodeName("LivingRoomTV.local")
	// Question PTR + Answer SRV.
	// Answer SRV body: priority=0, weight=0, port=8009 (0x1F49)
	// + target. RDLength = 6 + len(target).
	rdLen := 6 + len(target)/2
	in := "1234 8400 0001 0001 0000 0000 " +
		question + " 0021 0001 " +
		question + " 0021 8001 00000078 " +
		fmt.Sprintf("%04X ", rdLen) +
		"0000 0000 1F49 " + target
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	a := r.Answers[0]
	if a.TypeName != "SRV" {
		t.Errorf("type: got %q want SRV", a.TypeName)
	}
	if a.SRVPort != 8009 {
		t.Errorf("port: got %d want 8009", a.SRVPort)
	}
	if a.SRVTarget != "LivingRoomTV.local" {
		t.Errorf("target: got %q want LivingRoomTV.local", a.SRVTarget)
	}
}

// TestDecodeTXTKeyValues pins TXT key=value decoding —
// canonical DNS-SD metadata format.
func TestDecodeTXTKeyValues(t *testing.T) {
	question := encodeName("test._tcp.local")
	// TXT body: three length-prefixed strings:
	//   "model=NetBoot" (13 bytes: 0x0D + 13 chars)
	//   "vendor=Apple" (12: 0x0C + 12)
	//   "version=2.1" (11: 0x0B + 11)
	// Total: 1+13 + 1+12 + 1+11 = 39 bytes.
	const k1 = "0D 6D 6F 64 65 6C 3D 4E 65 74 42 6F 6F 74" // "model=NetBoot"
	const k2 = "0C 76 65 6E 64 6F 72 3D 41 70 70 6C 65"    // "vendor=Apple"
	const k3 = "0B 76 65 72 73 69 6F 6E 3D 32 2E 31"       // "version=2.1"
	txtBody := k1 + " " + k2 + " " + k3
	in := "1234 8400 0001 0001 0000 0000 " +
		question + " 0010 0001 " +
		question + " 0010 8001 00000078 " +
		fmt.Sprintf("%04X ", 39) +
		txtBody
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	a := r.Answers[0]
	if a.TypeName != "TXT" {
		t.Errorf("type: got %q want TXT", a.TypeName)
	}
	if len(a.TXTStrings) != 3 {
		t.Errorf("txt strings: got %d want 3", len(a.TXTStrings))
	}
	if a.TXTKeyValues["model"] != "NetBoot" {
		t.Errorf("model: got %q want NetBoot", a.TXTKeyValues["model"])
	}
	if a.TXTKeyValues["vendor"] != "Apple" {
		t.Errorf("vendor: got %q want Apple", a.TXTKeyValues["vendor"])
	}
	if a.TXTKeyValues["version"] != "2.1" {
		t.Errorf("version: got %q want 2.1", a.TXTKeyValues["version"])
	}
}

// TestDecodeAAnswer pins an A record decode.
func TestDecodeAAnswer(t *testing.T) {
	name := encodeName("LivingRoomTV.local")
	// IP 192.168.1.50 = C0 A8 01 32.
	in := "0000 8400 0000 0001 0000 0000 " +
		name + " 0001 8001 00000078 0004 C0A80132"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	a := r.Answers[0]
	if a.IPv4 != "192.168.1.50" {
		t.Errorf("ipv4: got %q want 192.168.1.50", a.IPv4)
	}
}

// TestDecodeAAAAAnswer pins an AAAA record decode.
func TestDecodeAAAAAnswer(t *testing.T) {
	name := encodeName("HomePod.local")
	in := "0000 8400 0000 0001 0000 0000 " +
		name + " 001C 8001 00000078 " +
		"0010 FE800000000000000ABCDEF0FFEE1122"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(r.Answers[0].IPv6, "fe80") {
		t.Errorf("ipv6: got %q want fe80::*", r.Answers[0].IPv6)
	}
}

// TestDecodeCompressionPointer asserts that mDNS DOES support
// compression pointers (unlike LLMNR which forbids them).
func TestDecodeCompressionPointer(t *testing.T) {
	// Question name at offset 12: encodeName("foo.local").
	// Answer name at offset (12 + len(question name) + 4 for
	// type/class) uses compression pointer to offset 12.
	fooLocal := encodeName("foo.local")
	// On-wire question name length = len(fooLocal)/2 bytes.
	// Answer name = compression pointer 0xC0 0x0C (offset 12).
	in := "0000 8400 0001 0001 0000 0000 " +
		fooLocal + " 0001 0001 " +
		"C00C 0001 8001 00000078 0004 0A000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Answers[0].Name != "foo.local" {
		t.Errorf("compressed name: got %q want foo.local",
			r.Answers[0].Name)
	}
	if r.Answers[0].IPv4 != "10.0.0.1" {
		t.Errorf("ipv4: got %q", r.Answers[0].IPv4)
	}
}

// TestTypeNameTable covers each catalogued RR type.
func TestTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
		12: "PTR", 15: "MX", 16: "TXT",
		28: "AAAA", 33: "SRV", 41: "OPT", 47: "NSEC",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(typeName(999), "uncatalogued") {
		t.Errorf("uncatalogued type should be flagged")
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("0000 0000 0001"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 11)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
