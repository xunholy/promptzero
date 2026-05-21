package postgres

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// startupMessage builds a v3 StartupMessage with key/value
// pairs.
func startupMessage(kv map[string]string) []byte {
	var body []byte
	for k, v := range kv {
		body = append(body, []byte(k)...)
		body = append(body, 0x00)
		body = append(body, []byte(v)...)
		body = append(body, 0x00)
	}
	body = append(body, 0x00) // terminator
	total := 4 + 4 + len(body)
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(total))
	binary.BigEndian.PutUint32(out[4:8], 0x00030000)
	copy(out[8:], body)
	return out
}

// typedMessage builds a typed message: Type + Length + Body.
func typedMessage(t byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = t
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

// TestDecodeSSLRequest pins the magic-payload classification.
func TestDecodeSSLRequest(t *testing.T) {
	b := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsSSLRequest {
		t.Errorf("IsSSLRequest should be true")
	}
}

// TestDecodeGSSENCRequest pins the GSS-encryption probe.
func TestDecodeGSSENCRequest(t *testing.T) {
	b := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x30}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsGSSRequest {
		t.Errorf("IsGSSRequest should be true")
	}
}

// TestDecodeStartupMessage pins the canonical credential
// disclosure shape: user + database in cleartext.
func TestDecodeStartupMessage(t *testing.T) {
	msg := startupMessage(map[string]string{
		"user":             "postgres",
		"database":         "production",
		"application_name": "psql",
		"client_encoding":  "UTF8",
	})
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "StartupMessage" {
		t.Errorf("type: got %q want StartupMessage", r.MessageTypeName)
	}
	if r.User != "postgres" {
		t.Errorf("user: got %q want postgres", r.User)
	}
	if r.Database != "production" {
		t.Errorf("database: got %q want production", r.Database)
	}
	if r.ApplicationName != "psql" {
		t.Errorf("application_name: got %q want psql", r.ApplicationName)
	}
	if r.ClientEncoding != "UTF8" {
		t.Errorf("client_encoding: got %q want UTF8", r.ClientEncoding)
	}
}

// TestDecodeAuthCleartextPassword pins the MITM-capturable
// auth method.
func TestDecodeAuthCleartextPassword(t *testing.T) {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 3)
	msg := typedMessage('R', body)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Authentication" {
		t.Errorf("type: got %q want Authentication", r.MessageTypeName)
	}
	if r.AuthSubtype != 3 {
		t.Errorf("subtype: got %d want 3", r.AuthSubtype)
	}
	if !strings.Contains(r.AuthSubtypeName, "MITM-capturable") {
		t.Errorf("subtype name should flag MITM-capturable: %q",
			r.AuthSubtypeName)
	}
}

// TestDecodeAuthMD5Password pins the offline-crackable flag.
func TestDecodeAuthMD5Password(t *testing.T) {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 5)
	msg := typedMessage('R', body)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.AuthSubtypeName, "offline-crackable") {
		t.Errorf("subtype name should flag offline-crackable: %q",
			r.AuthSubtypeName)
	}
}

// TestDecodeAuthSASL pins the modern-hardened flag.
func TestDecodeAuthSASL(t *testing.T) {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 10)
	msg := typedMessage('R', body)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.AuthSubtypeName, "hardened") {
		t.Errorf("subtype name should flag hardened: %q",
			r.AuthSubtypeName)
	}
}

// TestDecodeErrorResponseInvalidPassword pins the canonical
// brute-force feedback signal.
func TestDecodeErrorResponseInvalidPassword(t *testing.T) {
	var body []byte
	body = append(body, 'S')
	body = append(body, []byte("FATAL")...)
	body = append(body, 0x00)
	body = append(body, 'C')
	body = append(body, []byte("28P01")...)
	body = append(body, 0x00)
	body = append(body, 'M')
	body = append(body, []byte("password authentication failed for user \"admin\"")...)
	body = append(body, 0x00)
	body = append(body, 0x00) // terminator
	msg := typedMessage('E', body)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Execute (frontend) / ErrorResponse (backend)" &&
		!strings.Contains(r.MessageTypeName, "ErrorResponse") {
		t.Errorf("type: got %q", r.MessageTypeName)
	}
	if r.SQLState != "28P01" {
		t.Errorf("sqlstate: got %q want 28P01", r.SQLState)
	}
	if !strings.Contains(r.SQLStateName, "invalid_password") {
		t.Errorf("sqlstate name should flag invalid_password: %q",
			r.SQLStateName)
	}
	if !strings.Contains(r.SQLStateName, "brute-force feedback") {
		t.Errorf("sqlstate name should flag brute-force feedback: %q",
			r.SQLStateName)
	}
	if r.ErrorSeverity != "FATAL" {
		t.Errorf("severity: got %q want FATAL", r.ErrorSeverity)
	}
}

// TestDecodeParameterStatusServerVersion pins the canonical
// version-fingerprint signal.
func TestDecodeParameterStatusServerVersion(t *testing.T) {
	var body []byte
	body = append(body, []byte("server_version")...)
	body = append(body, 0x00)
	body = append(body, []byte("16.1")...)
	body = append(body, 0x00)
	msg := typedMessage('S', body)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ParameterName != "server_version" {
		t.Errorf("name: got %q want server_version", r.ParameterName)
	}
	if r.ParameterValue != "16.1" {
		t.Errorf("value: got %q want 16.1", r.ParameterValue)
	}
}

// TestAuthSubtypeNameTable spot-checks each catalogued subtype.
func TestAuthSubtypeNameTable(t *testing.T) {
	for _, s := range []int{0, 2, 3, 5, 7, 8, 9, 10, 11, 12} {
		if got := authSubtypeName(s); strings.HasPrefix(got,
			"uncatalogued") {
			t.Errorf("authSubtypeName(%d) should be catalogued, got %q",
				s, got)
		}
	}
}

// TestSQLStateNameTable spot-checks key codes.
func TestSQLStateNameTable(t *testing.T) {
	cases := map[string]string{
		"00000": "successful_completion",
		"28P01": "invalid_password",
		"28000": "invalid_authorization_specification",
		"3D000": "invalid_catalog_name",
		"42501": "insufficient_privilege",
		"42P01": "undefined_table",
		"53300": "too_many_connections",
		"57P03": "cannot_connect_now",
	}
	for k, v := range cases {
		got := sqlStateName(k)
		if !strings.Contains(got, v) {
			t.Errorf("sqlStateName(%s) = %q want contains %q",
				k, got, v)
		}
	}
}

// TestErrorFieldNameTable spot-checks each catalogued field.
func TestErrorFieldNameTable(t *testing.T) {
	cases := map[byte]string{
		'S': "Severity",
		'C': "SQLSTATE",
		'M': "Message",
		'D': "Detail",
		'H': "Hint",
		'P': "Position",
		's': "Schema",
		't': "Table",
		'c': "Column",
	}
	for k, v := range cases {
		if got := errorFieldName(k); got != v {
			t.Errorf("errorFieldName(%c) = %q want %q", k, got, v)
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
