package smb2

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

// header builds a minimal 64-byte SMB2 sync header with the
// supplied command, flags, status, sessionId, and treeId.
func header(command uint16, flags uint32, status uint32,
	messageID uint64, sessionID uint64, treeID uint32) []byte {
	h := make([]byte, headerSize)
	h[0] = 0xFE
	h[1] = 'S'
	h[2] = 'M'
	h[3] = 'B'
	binary.LittleEndian.PutUint16(h[4:6], 64)
	binary.LittleEndian.PutUint32(h[8:12], status)
	binary.LittleEndian.PutUint16(h[12:14], command)
	binary.LittleEndian.PutUint32(h[16:20], flags)
	binary.LittleEndian.PutUint64(h[24:32], messageID)
	binary.LittleEndian.PutUint32(h[36:40], treeID)
	binary.LittleEndian.PutUint64(h[40:48], sessionID)
	return h
}

func utf16le(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
	}
	return out
}

// TestDecodeNegotiateRequestWithSMB1Wildcard pins the canonical
// EternalBlue-candidate indicator: dialect list includes 0x02FF.
func TestDecodeNegotiateRequestWithSMB1Wildcard(t *testing.T) {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x02FF}
	body := make([]byte, 36+len(dialects)*2)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4],
		uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 0x01) // SIGNING_ENABLED
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(body[36+i*2:38+i*2], d)
	}
	msg := append(header(0x00, 0x00, 0x00, 1, 0, 0), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "NEGOTIATE" {
		t.Errorf("command: got %q want NEGOTIATE", r.CommandName)
	}
	if r.IsResponse {
		t.Errorf("should be a request")
	}
	if len(r.Dialects) != 4 {
		t.Errorf("dialects: got %d want 4", len(r.Dialects))
	}
	if !r.SMB1Offered {
		t.Errorf("SMB1Offered should be true (0x02FF present)")
	}
	if !r.SigningEnabled {
		t.Errorf("SigningEnabled should be true (0x01)")
	}
	if r.SigningRequired {
		t.Errorf("SigningRequired should be false (0x02 not set)")
	}
}

// TestDecodeNegotiateResponseSigningRequired pins the canonical
// hardening-applied indicator.
func TestDecodeNegotiateResponseSigningRequired(t *testing.T) {
	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], 0x03) // ENABLED|REQUIRED
	binary.LittleEndian.PutUint16(body[4:6], 0x0311)
	// SecurityBufferOffset (2) at body[56], Length (2) at [58]
	binary.LittleEndian.PutUint16(body[56:58], headerSize+65)
	binary.LittleEndian.PutUint16(body[58:60], 128)
	msg := append(header(0x00, 0x01, 0x00, 1, 0, 0), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsResponse {
		t.Errorf("should be a response")
	}
	if !r.SigningRequired {
		t.Errorf("SigningRequired should be true (0x02 set)")
	}
	if r.DialectChosen != 0x0311 {
		t.Errorf("DialectChosen: got 0x%04X want 0x0311", r.DialectChosen)
	}
	if r.DialectChosenName != "SMB 3.1.1" {
		t.Errorf("DialectChosenName: got %q", r.DialectChosenName)
	}
	if r.SecurityBufferBytes != 128 {
		t.Errorf("SecurityBufferBytes: got %d want 128", r.SecurityBufferBytes)
	}
}

// TestDecodeTreeConnectAdminShare pins the ADMIN$ access shape.
func TestDecodeTreeConnectAdminShare(t *testing.T) {
	path := `\\dc01\ADMIN$`
	pathBytes := utf16le(path)
	body := make([]byte, 8+len(pathBytes))
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[4:6],
		uint16(headerSize+8))
	binary.LittleEndian.PutUint16(body[6:8],
		uint16(len(pathBytes)))
	copy(body[8:], pathBytes)
	msg := append(header(0x03, 0x00, 0x00, 5, 1, 0), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "TREE_CONNECT" {
		t.Errorf("command: got %q want TREE_CONNECT", r.CommandName)
	}
	if r.TreeConnectPath != path {
		t.Errorf("path: got %q want %q", r.TreeConnectPath, path)
	}
}

// TestDecodeCreatePipeSpoolss pins the PrintNightmare named-pipe
// access shape.
func TestDecodeCreatePipeSpoolss(t *testing.T) {
	name := `spoolss`
	nameBytes := utf16le(name)
	body := make([]byte, 56+len(nameBytes))
	binary.LittleEndian.PutUint16(body[0:2], 57)
	binary.LittleEndian.PutUint16(body[44:46],
		uint16(headerSize+56))
	binary.LittleEndian.PutUint16(body[46:48],
		uint16(len(nameBytes)))
	copy(body[56:], nameBytes)
	msg := append(header(0x05, 0x00, 0x00, 6, 1, 1), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "CREATE" {
		t.Errorf("command: got %q want CREATE", r.CommandName)
	}
	if r.CreateName != name {
		t.Errorf("name: got %q want %q", r.CreateName, name)
	}
}

// TestDecodeSessionSetupLogonFailure pins the password-spray
// feedback signal.
func TestDecodeSessionSetupLogonFailure(t *testing.T) {
	msg := header(0x01, 0x01, 0xC000006D, 2, 0xDEADBEEF, 0)
	// Add a 9-byte minimal SESSION_SETUP response body
	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	msg = append(msg, body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "SESSION_SETUP" {
		t.Errorf("command: got %q want SESSION_SETUP", r.CommandName)
	}
	if r.Status != 0xC000006D {
		t.Errorf("status: got 0x%08X want 0xC000006D", r.Status)
	}
	if r.StatusName != "STATUS_LOGON_FAILURE" {
		t.Errorf("statusName: got %q", r.StatusName)
	}
}

// TestDecodeTransformHeader pins the SMB3 encryption header
// type-flag.
func TestDecodeTransformHeader(t *testing.T) {
	b := []byte{0xFD, 'S', 'M', 'B', 0x00, 0x00, 0x00, 0x00}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.TransformHeaderPresent {
		t.Errorf("TransformHeaderPresent should be true")
	}
}

// TestCommandNameTable spot-checks each catalogued command.
func TestCommandNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "NEGOTIATE",
		0x01: "SESSION_SETUP",
		0x02: "LOGOFF",
		0x03: "TREE_CONNECT",
		0x04: "TREE_DISCONNECT",
		0x05: "CREATE",
		0x06: "CLOSE",
		0x07: "FLUSH",
		0x08: "READ",
		0x09: "WRITE",
		0x0A: "LOCK",
		0x0B: "IOCTL",
		0x0C: "CANCEL",
		0x0D: "ECHO",
		0x0E: "QUERY_DIRECTORY",
		0x0F: "CHANGE_NOTIFY",
		0x10: "QUERY_INFO",
		0x11: "SET_INFO",
		0x12: "OPLOCK_BREAK",
	}
	for k, v := range cases {
		if got := commandName(k); got != v {
			t.Errorf("commandName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestDialectNameTable spot-checks each catalogued dialect.
func TestDialectNameTable(t *testing.T) {
	cases := map[uint16]string{
		0x0202: "SMB 2.0.2",
		0x0210: "SMB 2.1",
		0x0300: "SMB 3.0",
		0x0302: "SMB 3.0.2",
		0x0311: "SMB 3.1.1",
	}
	for k, v := range cases {
		if got := dialectName(k); got != v {
			t.Errorf("dialectName(0x%04X) = %q want %q", k, got, v)
		}
	}
	if !strings.Contains(dialectName(0x02FF), "EternalBlue") {
		t.Errorf("wildcard should flag EternalBlue")
	}
}

// TestStatusNameTable spot-checks high-runner NTSTATUS values.
func TestStatusNameTable(t *testing.T) {
	cases := map[uint32]string{
		0x00000000: "STATUS_SUCCESS",
		0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
		0xC0000022: "STATUS_ACCESS_DENIED",
		0xC000006D: "STATUS_LOGON_FAILURE",
		0xC0000071: "STATUS_PASSWORD_EXPIRED",
		0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
	}
	for k, v := range cases {
		if got := statusName(k); got != v {
			t.Errorf("statusName(0x%08X) = %q want %q", k, got, v)
		}
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

func TestDecodeRejectsNonSMB2(t *testing.T) {
	if _, err := Decode("FF534D42"); err == nil {
		t.Fatal("want error for SMB1 magic (0xFF SMB)")
	}
}
