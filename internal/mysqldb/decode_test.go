package mysqldb

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// packetHeader builds a 4-byte MySQL packet header.
func packetHeader(payloadLen int, seq byte) []byte {
	return []byte{
		byte(payloadLen),
		byte(payloadLen >> 8),
		byte(payloadLen >> 16),
		seq,
	}
}

// handshakeV10 builds a server Handshake v10 packet.
func handshakeV10(serverVersion, authPluginName string,
	capabilities uint32) []byte {
	payload := []byte{0x0A}
	payload = append(payload, []byte(serverVersion)...)
	payload = append(payload, 0x00)
	// connection_id (4 LE)
	cid := make([]byte, 4)
	binary.LittleEndian.PutUint32(cid, 1234)
	payload = append(payload, cid...)
	// 8 bytes auth-plugin-data-part-1
	payload = append(payload, make([]byte, 8)...)
	// 0x00 filler
	payload = append(payload, 0x00)
	// 2 bytes capability lower (LE)
	capLow := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLow, uint16(capabilities&0xFFFF))
	payload = append(payload, capLow...)
	// 1 byte character set
	payload = append(payload, 0x21) // utf8mb3_general_ci
	// 2 bytes status flags (LE)
	statFlags := make([]byte, 2)
	binary.LittleEndian.PutUint16(statFlags, 0x0002) // AUTOCOMMIT
	payload = append(payload, statFlags...)
	// 2 bytes capability upper (LE)
	capHigh := make([]byte, 2)
	binary.LittleEndian.PutUint16(capHigh, uint16(capabilities>>16))
	payload = append(payload, capHigh...)
	// 1 byte auth-plugin-data length
	payload = append(payload, 21)
	// 10 bytes reserved
	payload = append(payload, make([]byte, 10)...)
	// auth-plugin-data-part-2 (13 bytes)
	payload = append(payload, make([]byte, 13)...)
	// auth_plugin_name (null-terminated) — CLIENT_PLUGIN_AUTH
	// must be set
	payload = append(payload, []byte(authPluginName)...)
	payload = append(payload, 0x00)
	return append(packetHeader(len(payload), 0), payload...)
}

// handshakeResponse41 builds a client HandshakeResponse41 packet.
func handshakeResponse41(user, db, plugin string, caps uint32,
	authDataLen byte) []byte {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[0:4], caps)
	binary.LittleEndian.PutUint32(payload[4:8], 16777216)
	payload[8] = 0x21
	// 23-byte filler is part of the 32-byte fixed area
	// username null-terminated
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0x00)
	// auth-data (length-prefixed if CLIENT_SECURE_CONNECTION)
	payload = append(payload, authDataLen)
	payload = append(payload, make([]byte, int(authDataLen))...)
	// database null-terminated (if CLIENT_CONNECT_WITH_DB)
	if caps&0x00000008 != 0 {
		payload = append(payload, []byte(db)...)
		payload = append(payload, 0x00)
	}
	// client_plugin_name null-terminated (if CLIENT_PLUGIN_AUTH)
	if caps&0x00080000 != 0 {
		payload = append(payload, []byte(plugin)...)
		payload = append(payload, 0x00)
	}
	return append(packetHeader(len(payload), 1), payload...)
}

// errPacket builds a server ERR packet.
func errPacket(code uint16, sqlState, message string) []byte {
	payload := []byte{0xFF}
	codeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(codeBytes, code)
	payload = append(payload, codeBytes...)
	payload = append(payload, '#')
	payload = append(payload, []byte(sqlState)...)
	payload = append(payload, []byte(message)...)
	return append(packetHeader(len(payload), 1), payload...)
}

// TestDecodeHandshakeV10NativePassword pins the canonical MySQL
// 5.7 handshake shape with mysql_native_password (SHA1-weak).
func TestDecodeHandshakeV10NativePassword(t *testing.T) {
	pkt := handshakeV10("5.7.42-0ubuntu0.18.04.1",
		"mysql_native_password",
		0x00000800|0x00080000) // CLIENT_SSL | CLIENT_PLUGIN_AUTH
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsHandshake {
		t.Errorf("IsHandshake should be true")
	}
	if r.ProtocolVersion != 10 {
		t.Errorf("ProtocolVersion: got %d want 10", r.ProtocolVersion)
	}
	if !strings.HasPrefix(r.ServerVersion, "5.7.42") {
		t.Errorf("ServerVersion: got %q", r.ServerVersion)
	}
	if r.AuthPluginName != "mysql_native_password" {
		t.Errorf("AuthPluginName: got %q want mysql_native_password",
			r.AuthPluginName)
	}
	if !strings.Contains(r.AuthPluginDesc, "offline-crackable") {
		t.Errorf("AuthPluginDesc should flag offline-crackable: %q",
			r.AuthPluginDesc)
	}
	if !r.SSLSupported {
		t.Errorf("SSLSupported should be true (CLIENT_SSL bit set)")
	}
}

// TestDecodeHandshakeV10CachingSHA2 pins MySQL 8 default.
func TestDecodeHandshakeV10CachingSHA2(t *testing.T) {
	pkt := handshakeV10("8.0.35-0ubuntu0.22.04.1",
		"caching_sha2_password",
		0x00080000)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.AuthPluginDesc, "MySQL 8 default") {
		t.Errorf("AuthPluginDesc should flag modern: %q",
			r.AuthPluginDesc)
	}
}

// TestDecodeHandshakeV10MariaDB pins MariaDB handshake shape.
func TestDecodeHandshakeV10MariaDB(t *testing.T) {
	pkt := handshakeV10("10.11.5-MariaDB-1ubuntu1",
		"mysql_native_password", 0x00080000)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.ServerVersion, "MariaDB") {
		t.Errorf("ServerVersion: got %q, expected MariaDB", r.ServerVersion)
	}
}

// TestDecodeHandshakeResponse41 pins the canonical cleartext
// credential disclosure shape.
func TestDecodeHandshakeResponse41(t *testing.T) {
	pkt := handshakeResponse41("admin", "production",
		"mysql_native_password",
		0x00000008|0x00008000|0x00080000, // DB|SECURE|PLUGIN_AUTH
		20)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsHandshakeResp {
		t.Errorf("IsHandshakeResp should be true")
	}
	if r.UserName != "admin" {
		t.Errorf("UserName: got %q want admin", r.UserName)
	}
	if r.Database != "production" {
		t.Errorf("Database: got %q want production", r.Database)
	}
	if r.ClientPluginName != "mysql_native_password" {
		t.Errorf("ClientPluginName: got %q", r.ClientPluginName)
	}
	if r.AuthDataBytes != 20 {
		t.Errorf("AuthDataBytes: got %d want 20", r.AuthDataBytes)
	}
}

// TestDecodeERRAccessDenied pins the canonical brute-force
// feedback signal.
func TestDecodeERRAccessDenied(t *testing.T) {
	pkt := errPacket(1045, "28000",
		"Access denied for user 'admin'@'10.0.0.5' (using password: YES)")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsERR {
		t.Errorf("IsERR should be true")
	}
	if r.ErrorCode != 1045 {
		t.Errorf("ErrorCode: got %d want 1045", r.ErrorCode)
	}
	if !strings.Contains(r.ErrorCodeName, "brute-force feedback") {
		t.Errorf("ErrorCodeName should flag brute-force feedback: %q",
			r.ErrorCodeName)
	}
	if r.SQLState != "28000" {
		t.Errorf("SQLState: got %q want 28000", r.SQLState)
	}
	if !strings.HasPrefix(r.ErrorMessage, "Access denied") {
		t.Errorf("ErrorMessage: got %q", r.ErrorMessage)
	}
}

// TestDecodeERRBadDB pins the database enumeration feedback.
func TestDecodeERRBadDB(t *testing.T) {
	pkt := errPacket(1049, "42000", "Unknown database 'wrong_db'")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.ErrorCodeName, "database enumeration") {
		t.Errorf("ErrorCodeName should flag database enumeration: %q",
			r.ErrorCodeName)
	}
}

// TestCapabilityNamesTable spot-checks key flags.
func TestCapabilityNamesTable(t *testing.T) {
	names := capabilityNames(0x00000800 | 0x00080000 | 0x00000008)
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	for _, want := range []string{
		"CLIENT_SSL",
		"CLIENT_PLUGIN_AUTH",
		"CLIENT_CONNECT_WITH_DB",
	} {
		if !found[want] {
			t.Errorf("capability %q should be in name list: %v", want, names)
		}
	}
}

// TestAuthPluginDescriptionTable spot-checks each plugin.
func TestAuthPluginDescriptionTable(t *testing.T) {
	cases := map[string]string{
		"mysql_native_password":   "offline-crackable",
		"caching_sha2_password":   "MySQL 8 default",
		"sha256_password":         "RSA",
		"mysql_clear_password":    "MITM-capturable",
		"auth_socket":             "Unix socket",
		"windows_native_password": "SSPI",
		"dialog":                  "interactive",
		"ed25519":                 "MariaDB Ed25519",
	}
	for k, marker := range cases {
		got := authPluginDescription(k)
		if !strings.Contains(got, marker) {
			t.Errorf("authPluginDescription(%q) = %q want contains %q",
				k, got, marker)
		}
	}
}

// TestErrorCodeNameTable spot-checks each catalogued code.
func TestErrorCodeNameTable(t *testing.T) {
	for _, c := range []int{1044, 1045, 1049, 1129, 1130, 1158, 1251,
		2059, 2061, 2068, 3950} {
		got := errorCodeName(c)
		if strings.HasPrefix(got, "uncatalogued") {
			t.Errorf("errorCodeName(%d) should be catalogued, got %q",
				c, got)
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

func TestDecodeRejectsTruncatedHeader(t *testing.T) {
	if _, err := Decode("0102"); err == nil {
		t.Fatal("want error for truncated header")
	}
}
