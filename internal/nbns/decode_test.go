package nbns

import (
	"strings"
	"testing"
)

// encodeNetBIOSName builds the wire-format 32-byte encoding for
// a NetBIOS name + suffix-byte (test helper mirrors RFC 1002
// §4.2.1.2).
func encodeNetBIOSName(name string, suffix byte) string {
	padded := make([]byte, 16)
	for i := 0; i < 15; i++ {
		if i < len(name) {
			padded[i] = name[i]
		} else {
			padded[i] = ' '
		}
	}
	padded[15] = suffix
	out := make([]byte, 32)
	for i := 0; i < 16; i++ {
		out[i*2] = 0x41 + (padded[i] >> 4)
		out[i*2+1] = 0x41 + (padded[i] & 0x0F)
	}
	return toHex(out)
}

func toHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0F]
	}
	return string(out)
}

// TestDecodeQueryWorkstation pins a canonical NBNS broadcast
// QUERY for a Workstation-suffixed name.
func TestDecodeQueryWorkstation(t *testing.T) {
	enc := encodeNetBIOSName("FILESERV01", 0x00)
	in := "1212 0110 0001 0000 0000 0000 " +
		"20 " + enc + " 00 " +
		"0020 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TransactionID != 0x1212 {
		t.Errorf("txID: got 0x%X want 0x1212", r.TransactionID)
	}
	if r.QR {
		t.Errorf("QR: should be false for query")
	}
	if r.OpcodeName != "QUERY" {
		t.Errorf("opcode: got %q want QUERY", r.OpcodeName)
	}
	if !r.RD {
		t.Errorf("RD: should be set")
	}
	if !r.Broadcast {
		t.Errorf("Broadcast: should be set")
	}
	if r.QDCount != 1 || r.ANCount != 0 {
		t.Errorf("counts: got %d/%d want 1/0", r.QDCount, r.ANCount)
	}
	if len(r.Questions) != 1 {
		t.Fatalf("questions: got %d want 1", len(r.Questions))
	}
	q := r.Questions[0]
	if q.Name != "FILESERV01" {
		t.Errorf("question name: got %q want FILESERV01", q.Name)
	}
	if q.Suffix != 0x00 || q.SuffixName != "Workstation" {
		t.Errorf("suffix: got 0x%X/%q want 0x00/Workstation", q.Suffix, q.SuffixName)
	}
	if q.TypeName != "NB" {
		t.Errorf("type: got %q want NB", q.TypeName)
	}
}

// TestDecodeResponseWithIP pins an NBNS response carrying one
// IPv4 in the NB RDATA, using a compression pointer to the
// question name.
func TestDecodeResponseWithIP(t *testing.T) {
	enc := encodeNetBIOSName("FILESERV01", 0x00)
	in := "1212 8580 0001 0001 0000 0000 " +
		// Question name + Type/Class
		"20 " + enc + " 00 0020 0001 " +
		// Answer (compression pointer to offset 12)
		"C00C 0020 0001 000003E8 0006 0000 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.QR || !r.AA || r.OpcodeName != "QUERY" {
		t.Errorf("response flags: QR=%v AA=%v opcode=%q",
			r.QR, r.AA, r.OpcodeName)
	}
	if r.RCODEName != "No_Error" {
		t.Errorf("rcode: got %q want No_Error", r.RCODEName)
	}
	if len(r.Answers) != 1 {
		t.Fatalf("answers: got %d want 1", len(r.Answers))
	}
	a := r.Answers[0]
	if a.Name != "FILESERV01" {
		t.Errorf("answer name (compression): got %q want FILESERV01", a.Name)
	}
	if a.TTL != 1000 {
		t.Errorf("ttl: got %d want 1000", a.TTL)
	}
	if len(a.IPAddresses) != 1 || a.IPAddresses[0] != "192.168.1.1" {
		t.Errorf("ip addresses: got %v want [192.168.1.1]", a.IPAddresses)
	}
}

// TestDecodeDomainControllerSuffix pins a query for the
// canonical Domain Controllers suffix 0x1C — the AD
// enumeration fingerprint.
func TestDecodeDomainControllerSuffix(t *testing.T) {
	enc := encodeNetBIOSName("CORP", 0x1C)
	in := "AAAA 0110 0001 0000 0000 0000 " +
		"20 " + enc + " 00 0020 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	q := r.Questions[0]
	if q.Suffix != 0x1C || q.SuffixName != "Domain_Controllers" {
		t.Errorf("suffix: got 0x%X/%q want 0x1C/Domain_Controllers",
			q.Suffix, q.SuffixName)
	}
}

// TestDecodeFileServerSuffix pins suffix 0x20 (File_Server).
func TestDecodeFileServerSuffix(t *testing.T) {
	enc := encodeNetBIOSName("SHARESRV", 0x20)
	in := "BBBB 0110 0001 0000 0000 0000 " +
		"20 " + enc + " 00 0020 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Questions[0].SuffixName != "File_Server" {
		t.Errorf("suffix: got %q want File_Server",
			r.Questions[0].SuffixName)
	}
}

// TestDecodeNameConflictResponse pins RCODE = Active_Error
// (name in use — the classic NetBIOS name-conflict reply).
func TestDecodeNameConflictResponse(t *testing.T) {
	enc := encodeNetBIOSName("DUPLICATE", 0x00)
	// Flags = 0x8586 → QR + AA + RD + RA + RCODE=6.
	in := "CCCC 8586 0001 0000 0000 0000 " +
		"20 " + enc + " 00 0020 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.RCODE != 6 || r.RCODEName != "Active_Error" {
		t.Errorf("rcode: got %d/%q want 6/Active_Error",
			r.RCODE, r.RCODEName)
	}
}

// TestDecodeRegistration pins an NBNS REGISTRATION opcode
// (sent when a Windows host registers its own name).
func TestDecodeRegistration(t *testing.T) {
	enc := encodeNetBIOSName("NEWHOST", 0x00)
	// Opcode = 5 (REGISTRATION) → flags bits 11-14 = 0101.
	// flags = 0x2900 (opcode 5 + RD + Broadcast → 0x0010 +
	// 0x0100 + 0x2800 = 0x2910). Use 0x2910.
	in := "DDDD 2910 0001 0000 0000 0001 " +
		"20 " + enc + " 00 0020 0001 " +
		// Additional record: same name, type NB, IP claim.
		"C00C 0020 0001 000003E8 0006 0000 C0A80164"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.OpcodeName != "REGISTRATION" {
		t.Errorf("opcode: got %q want REGISTRATION", r.OpcodeName)
	}
	if len(r.Answers) != 1 {
		t.Fatalf("answers (additional): got %d want 1", len(r.Answers))
	}
	if r.Answers[0].IPAddresses[0] != "192.168.1.100" {
		t.Errorf("ip: got %q want 192.168.1.100", r.Answers[0].IPAddresses[0])
	}
}

// TestOpcodeNameTable spot-checks each catalogued opcode.
func TestOpcodeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "QUERY", 5: "REGISTRATION", 6: "RELEASE",
		7: "WACK", 8: "REFRESH",
	}
	for k, v := range cases {
		if got := opcodeName(k); got != v {
			t.Errorf("opcodeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(opcodeName(9), "uncatalogued") {
		t.Errorf("opcodeName(9) should mark uncatalogued")
	}
}

// TestRCODENameTable covers every catalogued response code.
func TestRCODENameTable(t *testing.T) {
	cases := map[int]string{
		0: "No_Error", 1: "Format_Error",
		2: "Server_Failure", 3: "Name_Error",
		4: "Not_Implemented", 5: "Refused_Error",
		6: "Active_Error", 7: "Conflict_Error",
	}
	for k, v := range cases {
		if got := rcodeName(k); got != v {
			t.Errorf("rcodeName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestSuffixNameTable spot-checks key catalogued suffixes.
func TestSuffixNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "Workstation", 0x01: "Master_Browser",
		0x03: "Messenger", 0x1B: "Domain_Master_Browser",
		0x1C: "Domain_Controllers",
		0x20: "File_Server", 0x21: "RAS_Client",
		0x23: "MS_Exchange_Store",
	}
	for k, v := range cases {
		if got := suffixName(k); got != v {
			t.Errorf("suffixName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestReadNetBIOSNameInvalid checks bounds + bad-nibble errors.
func TestReadNetBIOSNameInvalid(t *testing.T) {
	// Length byte must be 0x20.
	b := []byte{0x10, 0x00}
	if _, _, _, err := readNetBIOSName(b, 0); err == nil {
		t.Error("expected error for wrong length byte")
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
	if _, err := Decode("1212 0110 0001"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 11)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
