package llmnr

import (
	"strings"
	"testing"
)

// encodeName builds the wire-format DNS label encoding for a
// dotted name (test helper).
func encodeName(s string) string {
	const digits = "0123456789ABCDEF"
	var out []byte
	for _, label := range strings.Split(s, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	hex := make([]byte, len(out)*2)
	for i, v := range out {
		hex[i*2] = digits[v>>4]
		hex[i*2+1] = digits[v&0x0F]
	}
	return string(hex)
}

// TestDecodeQueryA pins a canonical LLMNR A-record query for
// the short hostname "fileserv1" — the classic Responder.py
// attack trigger.
func TestDecodeQueryA(t *testing.T) {
	enc := encodeName("fileserv1")
	in := "1234 0000 0001 0000 0000 0000 " +
		enc + " 0001 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TransactionID != 0x1234 {
		t.Errorf("txID: got 0x%X want 0x1234", r.TransactionID)
	}
	if r.QR {
		t.Errorf("QR: should be false for query")
	}
	if r.OpcodeName != "LLMNR_QUERY" {
		t.Errorf("opcode: got %q want LLMNR_QUERY", r.OpcodeName)
	}
	if len(r.Questions) != 1 {
		t.Fatalf("questions: got %d want 1", len(r.Questions))
	}
	q := r.Questions[0]
	if q.Name != "fileserv1" {
		t.Errorf("question name: got %q want fileserv1", q.Name)
	}
	if q.TypeName != "A" {
		t.Errorf("type: got %q want A", q.TypeName)
	}
}

// TestDecodeResponseAWithIP pins an LLMNR response carrying an
// A record IP — the Responder.py poisoned reply shape.
func TestDecodeResponseAWithIP(t *testing.T) {
	enc := encodeName("fileserv1")
	// Response flags: QR=1, Opcode=0, RA, RCODE=0 → 0x8000.
	in := "1234 8000 0001 0001 0000 0000 " +
		enc + " 0001 0001 " +
		// Answer (LLMNR forbids compression — repeat the name).
		enc + " 0001 0001 0000001E 0004 C0A80164"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.QR {
		t.Errorf("QR: should be true for response")
	}
	if len(r.Answers) != 1 {
		t.Fatalf("answers: got %d want 1", len(r.Answers))
	}
	a := r.Answers[0]
	if a.Name != "fileserv1" {
		t.Errorf("answer name: got %q want fileserv1", a.Name)
	}
	if a.TTL != 30 {
		t.Errorf("ttl: got %d want 30", a.TTL)
	}
	if a.IPv4 != "192.168.1.100" {
		t.Errorf("ipv4: got %q want 192.168.1.100", a.IPv4)
	}
}

// TestDecodeResponseAAAA pins an AAAA response (IPv6).
func TestDecodeResponseAAAA(t *testing.T) {
	enc := encodeName("host1")
	in := "AAAA 8000 0001 0001 0000 0000 " +
		enc + " 001C 0001 " +
		enc + " 001C 0001 0000001E 0010 20010DB8000000000000000000000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Answers[0].TypeName != "AAAA" {
		t.Errorf("type: got %q want AAAA", r.Answers[0].TypeName)
	}
	if !strings.HasSuffix(r.Answers[0].IPv6, ":1") {
		t.Errorf("ipv6: got %q", r.Answers[0].IPv6)
	}
}

// TestDecodeConflictFlag pins a response with the C (Conflict)
// flag — the canonical LLMNR-poisoning detection signal.
func TestDecodeConflictFlag(t *testing.T) {
	enc := encodeName("contested")
	// Flags = 0x8400 (QR + C).
	in := "BBBB 8400 0001 0000 0000 0000 " +
		enc + " 0001 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.Conflict {
		t.Errorf("C flag: should be true")
	}
}

// TestDecodeTentativeFlag pins a response with the T flag
// (set during name registration before the name has been
// successfully defended).
func TestDecodeTentativeFlag(t *testing.T) {
	enc := encodeName("registering")
	// Flags = 0x8100 (QR + T).
	in := "CCCC 8100 0001 0000 0000 0000 " +
		enc + " 0001 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.Tentative {
		t.Errorf("T flag: should be true")
	}
}

// TestDecodeNameError pins a response with RCODE = Name_Error
// (the standard "no such name" reply).
func TestDecodeNameError(t *testing.T) {
	enc := encodeName("nonexistent")
	// Flags = 0x8003 (QR + RCODE 3).
	in := "DDDD 8003 0001 0000 0000 0000 " +
		enc + " 0001 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.RCODE != 3 || r.RCODEName != "Name_Error" {
		t.Errorf("rcode: got %d/%q want 3/Name_Error", r.RCODE, r.RCODEName)
	}
}

// TestDecodeRejectsCompressionPointer is a critical test —
// LLMNR explicitly forbids compression pointers per RFC 4795
// §2.1.7. A name byte with high bits 11 must cause a decode
// error.
func TestDecodeRejectsCompressionPointer(t *testing.T) {
	// Header + a single question with a compression pointer
	// (0xC0 0x0C points to offset 12 — the start of the
	// question name region in standard DNS, illegal in
	// LLMNR).
	in := "1111 0000 0001 0000 0000 0000 C00C 0001 0001"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("want error for forbidden compression pointer")
	}
	if !strings.Contains(err.Error(), "compression pointer") {
		t.Errorf("error should mention compression pointer: %v", err)
	}
}

// TestRCODENameTable covers each catalogued RCODE.
func TestRCODENameTable(t *testing.T) {
	cases := map[int]string{
		0: "No_Error", 1: "Format_Error",
		2: "Server_Failure", 3: "Name_Error",
		4: "Not_Implemented", 5: "Refused",
	}
	for k, v := range cases {
		if got := rcodeName(k); got != v {
			t.Errorf("rcodeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(rcodeName(15), "uncatalogued") {
		t.Errorf("uncatalogued rcode should be flagged")
	}
}

// TestTypeNameTable covers each catalogued RR type.
func TestTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
		12: "PTR", 15: "MX", 16: "TXT",
		28: "AAAA", 33: "SRV",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestOpcodeNameTable covers LLMNR_QUERY (the only documented
// opcode).
func TestOpcodeNameTable(t *testing.T) {
	if opcodeName(0) != "LLMNR_QUERY" {
		t.Errorf("opcodeName(0) mismatched")
	}
	if !strings.HasPrefix(opcodeName(5), "uncatalogued") {
		t.Errorf("non-zero opcode should be flagged")
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
	if _, err := Decode("1234 0000 0001"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 11)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
