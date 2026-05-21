package tds

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

func tdsHeader(t byte, status byte, length uint16) []byte {
	h := make([]byte, headerSize)
	h[0] = t
	h[1] = status
	binary.BigEndian.PutUint16(h[2:4], length)
	binary.BigEndian.PutUint16(h[4:6], 0)
	h[6] = 1 // PacketID
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

// TestDecodePreLoginEncryptionNotSupported pins the TLS-
// downgrade-vulnerable shape.
func TestDecodePreLoginEncryptionNotSupported(t *testing.T) {
	// Tokens: VERSION (0x00) at offset 21 / ENCRYPTION (0x01)
	// at offset 27 / TERMINATOR (0xFF).
	// Layout: 3×5-byte token entries + 1-byte terminator + 6
	// bytes VERSION value + 1 byte ENCRYPTION value.
	body := make([]byte, 23)
	// VERSION token at body[0..5]
	body[0] = 0x00
	binary.BigEndian.PutUint16(body[1:3], 16) // offset
	binary.BigEndian.PutUint16(body[3:5], 6)  // length
	// ENCRYPTION token at body[5..10]
	body[5] = 0x01
	binary.BigEndian.PutUint16(body[6:8], 22) // offset
	binary.BigEndian.PutUint16(body[8:10], 1) // length
	// TERMINATOR at body[10]
	body[10] = 0xFF
	// VERSION value at body[16..22] (6 bytes — 4 ver + 2 build)
	body[16] = 0x0F
	body[17] = 0x00
	binary.BigEndian.PutUint16(body[18:20], 4250)
	// ENCRYPTION value at body[22]
	body[22] = 0x02 // ENCRYPT_NOT_SUP
	msg := append(tdsHeader(0x12, 0x01, uint16(headerSize+len(body))), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "PRE_LOGIN" {
		t.Errorf("type: got %q want PRE_LOGIN", r.TypeName)
	}
	if len(r.PreLoginTokens) != 2 {
		t.Errorf("tokens: got %d want 2", len(r.PreLoginTokens))
	}
	if r.EncryptionMode != 0x02 {
		t.Errorf("encryptionMode: got 0x%02X want 0x02", r.EncryptionMode)
	}
	if !strings.Contains(r.EncryptionModeName, "TLS-downgrade vulnerable") {
		t.Errorf("EncryptionModeName should flag downgrade: %q",
			r.EncryptionModeName)
	}
}

// TestDecodePreLoginEncryptionRequired pins the hardened shape.
func TestDecodePreLoginEncryptionRequired(t *testing.T) {
	body := make([]byte, 12)
	body[0] = 0x01
	binary.BigEndian.PutUint16(body[1:3], 11) // offset
	binary.BigEndian.PutUint16(body[3:5], 1)  // length
	body[5] = 0xFF
	body[11] = 0x03 // ENCRYPT_REQ
	msg := append(tdsHeader(0x12, 0x01, uint16(headerSize+len(body))), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.EncryptionModeName, "hardened") {
		t.Errorf("EncryptionModeName should flag hardened: %q",
			r.EncryptionModeName)
	}
}

// TestDecodeLogin7CleartextUsername pins the canonical
// SQL-Server credential disclosure shape.
func TestDecodeLogin7CleartextUsername(t *testing.T) {
	host := utf16le("workstation01")
	user := utf16le("sa")
	pass := utf16le("hunter2") // password (NOT obfuscated in our test)
	app := utf16le(".Net SqlClient Data Provider")
	srv := utf16le("sqlserver.corp.example.com")
	db := utf16le("master")
	// Build the variable data area + offsets
	body := make([]byte, 94)
	binary.LittleEndian.PutUint32(body[4:8], 0x74000004) // TDS 7.4 (SQL 2012+)
	binary.LittleEndian.PutUint32(body[8:12], 4096)      // packet size
	varStart := 94
	addVar := func(idx int, data []byte) {
		base := 36 + idx*4
		body[base] = byte(varStart)
		body[base+1] = byte(varStart >> 8)
		body[base+2] = byte(len(data) / 2)
		body[base+3] = byte((len(data) / 2) >> 8)
		body = append(body, data...)
		varStart += len(data)
	}
	addVar(0, host)
	addVar(1, user)
	addVar(2, pass)
	addVar(3, app)
	addVar(4, srv)
	addVar(5, nil)
	addVar(6, nil)
	addVar(7, nil)
	addVar(8, db)
	addVar(9, nil)
	binary.LittleEndian.PutUint32(body[0:4], uint32(len(body)))
	msg := append(tdsHeader(0x10, 0x01, uint16(headerSize+len(body))), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "TDS7_LOGIN" {
		t.Errorf("type: got %q want TDS7_LOGIN", r.TypeName)
	}
	if r.TDSVersion != 0x74000004 {
		t.Errorf("TDSVersion: got 0x%08X want 0x74000004", r.TDSVersion)
	}
	if !strings.Contains(r.TDSVersionName, "SQL Server 2012") {
		t.Errorf("TDSVersionName: got %q", r.TDSVersionName)
	}
	if r.HostName != "workstation01" {
		t.Errorf("HostName: got %q", r.HostName)
	}
	if r.UserName != "sa" {
		t.Errorf("UserName: got %q want sa", r.UserName)
	}
	if r.PasswordBytes != len(pass) {
		t.Errorf("PasswordBytes: got %d want %d",
			r.PasswordBytes, len(pass))
	}
	if r.AppName != ".Net SqlClient Data Provider" {
		t.Errorf("AppName: got %q", r.AppName)
	}
	if r.ServerName != "sqlserver.corp.example.com" {
		t.Errorf("ServerName: got %q", r.ServerName)
	}
	if r.Database != "master" {
		t.Errorf("Database: got %q want master", r.Database)
	}
}

// TestTypeNameTable spot-checks each catalogued packet type.
func TestTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "SQL_BATCH",
		0x02: "PRE_TDS7_LOGIN",
		0x03: "RPC",
		0x04: "TABULAR_RESULT",
		0x06: "ATTENTION",
		0x07: "BULK_LOAD_DATA",
		0x0E: "TRANSACTION_MANAGER",
		0x10: "TDS7_LOGIN",
		0x11: "SSPI",
		0x12: "PRE_LOGIN",
		0x13: "FEDERATED_AUTH_TOKEN",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestPreLoginTokenNameTable spot-checks each catalogued token.
func TestPreLoginTokenNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "VERSION",
		0x01: "ENCRYPTION",
		0x02: "INSTOPT",
		0x03: "THREADID",
		0x04: "MARS",
		0x05: "TRACEID",
		0x06: "FEDAUTHREQUIRED",
		0x07: "NONCEOPT",
	}
	for k, v := range cases {
		if got := preLoginTokenName(k); got != v {
			t.Errorf("preLoginTokenName(0x%02X) = %q want %q",
				k, got, v)
		}
	}
}

// TestEncryptionModeNameTable spot-checks each catalogued mode.
func TestEncryptionModeNameTable(t *testing.T) {
	if encryptionModeName(0x00) != "ENCRYPT_OFF" {
		t.Errorf("mode 0x00 mislabelled")
	}
	if encryptionModeName(0x01) != "ENCRYPT_ON" {
		t.Errorf("mode 0x01 mislabelled")
	}
	if !strings.Contains(encryptionModeName(0x02),
		"TLS-downgrade vulnerable") {
		t.Errorf("mode 0x02 should flag downgrade")
	}
	if !strings.Contains(encryptionModeName(0x03), "hardened") {
		t.Errorf("mode 0x03 should flag hardened")
	}
}

// TestTDSVersionNameTable spot-checks SQL Server releases.
func TestTDSVersionNameTable(t *testing.T) {
	cases := map[uint32]string{
		0x70000000: "SQL Server 7.0",
		0x71000001: "SQL Server 2000 SP1",
		0x72090002: "SQL Server 2005",
		0x730A0003: "SQL Server 2008",
		0x730B0003: "SQL Server 2008 R2",
	}
	for k, v := range cases {
		if got := tdsVersionName(k); got != v {
			t.Errorf("tdsVersionName(0x%08X) = %q want %q",
				k, got, v)
		}
	}
	if !strings.Contains(tdsVersionName(0x74000004),
		"SQL Server 2012") {
		t.Errorf("0x74000004 should reference SQL Server 2012+")
	}
}

func TestStatusFlagsNames(t *testing.T) {
	names := statusFlagsNames(0x09)
	if len(names) != 2 {
		t.Errorf("statusFlagsNames(0x09): got %d want 2", len(names))
	}
	if names[0] != "EOM" {
		t.Errorf("first flag: got %q want EOM", names[0])
	}
	if names[1] != "RESETCONNECTION" {
		t.Errorf("second flag: got %q want RESETCONNECTION", names[1])
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

func TestDecodeRejectsTruncatedHeader(t *testing.T) {
	if _, err := Decode("1201"); err == nil {
		t.Fatal("want error for truncated header")
	}
}
