package redis

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// resp builds a RESP frame from an ASCII string (which uses
// literal "\r\n" — converted to CRLF here).
func resp(s string) []byte {
	return []byte(s)
}

// arr builds an Array of Bulk Strings.
func arr(args ...string) []byte {
	out := fmt.Sprintf("*%d\r\n", len(args))
	for _, a := range args {
		out += fmt.Sprintf("$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(out)
}

// TestDecodeAUTHCleartextPassword pins the canonical Redis
// credential-disclosure shape.
func TestDecodeAUTHCleartextPassword(t *testing.T) {
	r, err := Decode(hex.EncodeToString(arr("AUTH", "hunter2")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsCommand {
		t.Errorf("IsCommand should be true")
	}
	if r.Command != "AUTH" {
		t.Errorf("Command: got %q want AUTH", r.Command)
	}
	if !r.IsAuthCommand {
		t.Errorf("IsAuthCommand should be true")
	}
	if !r.IsDangerousCommand {
		t.Errorf("IsDangerousCommand should be true")
	}
	if r.PasswordBytes != 7 {
		t.Errorf("PasswordBytes: got %d want 7", r.PasswordBytes)
	}
	if r.AuthUsername != "" {
		t.Errorf("AuthUsername should be empty for single-arg AUTH, got %q",
			r.AuthUsername)
	}
}

// TestDecodeAUTHWithUsername pins the Redis 6 ACL two-arg form.
func TestDecodeAUTHWithUsername(t *testing.T) {
	r, err := Decode(hex.EncodeToString(arr("AUTH", "admin", "password123")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.AuthUsername != "admin" {
		t.Errorf("AuthUsername: got %q want admin", r.AuthUsername)
	}
	if r.PasswordBytes != 11 {
		t.Errorf("PasswordBytes: got %d want 11", r.PasswordBytes)
	}
}

// TestDecodeHELLOWithInlineAUTH pins the RESP3 protocol
// negotiation with embedded credentials.
func TestDecodeHELLOWithInlineAUTH(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		arr("HELLO", "3", "AUTH", "admin", "secret")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsHelloCommand {
		t.Errorf("IsHelloCommand should be true")
	}
	if !r.IsAuthCommand {
		t.Errorf("IsAuthCommand should be true (inline AUTH)")
	}
	if r.AuthUsername != "admin" {
		t.Errorf("AuthUsername: got %q want admin", r.AuthUsername)
	}
	if r.PasswordBytes != 6 {
		t.Errorf("PasswordBytes: got %d want 6", r.PasswordBytes)
	}
}

// TestDecodeCONFIGSETRCEPrimitive pins the canonical Redis-to-
// shell attack signal.
func TestDecodeCONFIGSETRCEPrimitive(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		arr("CONFIG", "SET", "dir", "/root/.ssh")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsDangerousCommand {
		t.Errorf("IsDangerousCommand should be true")
	}
	if !strings.Contains(r.DangerousCommandFlag, "RCE primitive") {
		t.Errorf("DangerousCommandFlag should flag RCE primitive: %q",
			r.DangerousCommandFlag)
	}
}

// TestDecodeMODULELOAD pins the direct-RCE primitive.
func TestDecodeMODULELOAD(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		arr("MODULE", "LOAD", "/tmp/evil.so")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousCommandFlag, "direct native-code RCE") {
		t.Errorf("MODULE LOAD should flag direct-RCE: %q",
			r.DangerousCommandFlag)
	}
}

// TestDecodeEVALLuaSandbox pins the CVE-2022-0543 attack vector
// classification.
func TestDecodeEVALLuaSandbox(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		arr("EVAL", "return 1", "0")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousCommandFlag, "CVE-2022-0543") {
		t.Errorf("EVAL should reference CVE-2022-0543: %q",
			r.DangerousCommandFlag)
	}
}

// TestDecodeSLAVEOF pins the replication-RCE primitive.
func TestDecodeSLAVEOF(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		arr("SLAVEOF", "10.0.0.5", "6379")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousCommandFlag,
		"replication-based RCE primitive") {
		t.Errorf("SLAVEOF should flag replication-RCE: %q",
			r.DangerousCommandFlag)
	}
}

// TestDecodeFLUSHALL pins the destructive command classification.
func TestDecodeFLUSHALL(t *testing.T) {
	r, err := Decode(hex.EncodeToString(arr("FLUSHALL")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.DangerousCommandFlag, "data destruction") {
		t.Errorf("FLUSHALL should flag data destruction: %q",
			r.DangerousCommandFlag)
	}
}

// TestDecodeBenignCommand pins that ordinary commands aren't
// flagged.
func TestDecodeBenignCommand(t *testing.T) {
	r, err := Decode(hex.EncodeToString(arr("GET", "users:42")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.IsDangerousCommand {
		t.Errorf("GET should not be flagged dangerous")
	}
	if r.Command != "GET" {
		t.Errorf("Command: got %q want GET", r.Command)
	}
}

// TestDecodeErrorNOAUTH pins the pre-auth signal.
func TestDecodeErrorNOAUTH(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		resp("-NOAUTH Authentication required.\r\n")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsError {
		t.Errorf("IsError should be true")
	}
	if !strings.Contains(r.ErrorCategory, "pre-auth signal") {
		t.Errorf("NOAUTH should flag pre-auth signal: %q",
			r.ErrorCategory)
	}
}

// TestDecodeErrorWRONGPASS pins the brute-force feedback.
func TestDecodeErrorWRONGPASS(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		resp("-WRONGPASS invalid username-password pair or user is disabled.\r\n")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.ErrorCategory, "brute-force feedback") {
		t.Errorf("WRONGPASS should flag brute-force feedback: %q",
			r.ErrorCategory)
	}
}

// TestDecodeErrorMOVEDCluster pins the Cluster slot redirection.
func TestDecodeErrorMOVEDCluster(t *testing.T) {
	r, err := Decode(hex.EncodeToString(
		resp("-MOVED 3999 127.0.0.1:6381\r\n")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.ErrorCategory, "Cluster slot redirection") {
		t.Errorf("MOVED should flag Cluster redirection: %q",
			r.ErrorCategory)
	}
}

// TestDecodeSimpleStringOK pins the canonical +OK response.
func TestDecodeSimpleStringOK(t *testing.T) {
	r, err := Decode(hex.EncodeToString(resp("+OK\r\n")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameTypeName != "SimpleString" {
		t.Errorf("FrameTypeName: got %q want SimpleString", r.FrameTypeName)
	}
	if r.SimpleString != "OK" {
		t.Errorf("SimpleString: got %q want OK", r.SimpleString)
	}
}

// TestDecodeInteger pins the :N response.
func TestDecodeInteger(t *testing.T) {
	r, err := Decode(hex.EncodeToString(resp(":42\r\n")))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Integer != 42 {
		t.Errorf("Integer: got %d want 42", r.Integer)
	}
}

// TestFrameTypeNameTable spot-checks RESP2 + RESP3 types.
func TestFrameTypeNameTable(t *testing.T) {
	cases := map[byte]string{
		'+': "SimpleString",
		'-': "Error",
		':': "Integer",
		'$': "BulkString",
		'*': "Array",
		'%': "Map (RESP3)",
		'~': "Set (RESP3)",
		',': "Double (RESP3)",
		'(': "BigNumber (RESP3)",
		'#': "Boolean (RESP3)",
		'_': "Null (RESP3)",
		'=': "VerbatimString (RESP3)",
		'>': "Push (RESP3)",
	}
	for k, v := range cases {
		if got := frameTypeName(k); got != v {
			t.Errorf("frameTypeName(%c) = %q want %q", k, got, v)
		}
	}
}

// TestErrorCategoryTable spot-checks each catalogued prefix.
func TestErrorCategoryTable(t *testing.T) {
	cases := map[string]string{
		"NOAUTH foo":      "pre-auth signal",
		"WRONGPASS foo":   "brute-force feedback",
		"PERMISSION foo":  "ACL denied",
		"MOVED 1 1.2.3":   "Cluster slot redirection",
		"ASK 1 1.2.3":     "ASK redirection",
		"LOADING foo":     "server warming",
		"BUSY foo":        "script execution",
		"MASTERDOWN foo":  "Sentinel failover",
		"CLUSTERDOWN foo": "Cluster slot coverage",
		"READONLY foo":    "read-only replica",
		"ERR foo":         "generic server error",
	}
	for in, marker := range cases {
		got := errorCategory(in)
		if !strings.Contains(got, marker) {
			t.Errorf("errorCategory(%q) = %q want contains %q",
				in, got, marker)
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

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZZZ"); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
