package kerberos

import (
	"encoding/hex"
	"strings"
	"testing"
)

// derTag builds a single TLV: tag byte + length + content.
func derTag(t byte, content []byte) []byte {
	l := derLength(len(content))
	out := append([]byte{t}, l...)
	return append(out, content...)
}

// derLength encodes a length per BER short / long form.
func derLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	if n < 0x10000 {
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

// derInteger encodes an unsigned integer in minimum DER form.
func derInteger(v int) []byte {
	if v == 0 {
		return derTag(0x02, []byte{0x00})
	}
	// Big-endian bytes, drop leading zeros unless high bit
	// would flip the sign.
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xFF)}, bytes...)
		v >>= 8
	}
	if bytes[0]&0x80 != 0 {
		bytes = append([]byte{0x00}, bytes...)
	}
	return derTag(0x02, bytes)
}

func derGeneralString(s string) []byte {
	return derTag(0x1B, []byte(s))
}

func derSequence(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return derTag(0x30, content)
}

// ctxConstructed wraps content in a [N] CONSTRUCTED context tag.
func ctxConstructed(n int, content []byte) []byte {
	return derTag(byte(0xA0|n), content)
}

// derPrincipalName builds PrincipalName { name-type, name-string }.
func derPrincipalName(nameType int, parts ...string) []byte {
	var strs []byte
	for _, p := range parts {
		strs = append(strs, derGeneralString(p)...)
	}
	return derSequence(
		ctxConstructed(0, derInteger(nameType)),
		ctxConstructed(1, derSequence(strs)),
	)
}

// TestDecodeASREQNoPreAuth pins a canonical AS-REQ WITHOUT
// PA-ENC-TIMESTAMP — the AS-REP-roastable shape.
func TestDecodeASREQNoPreAuth(t *testing.T) {
	// KDC-REQ-BODY: [1] cname, [2] realm "CORP.EXAMPLE.COM",
	// [3] sname = krbtgt/CORP.EXAMPLE.COM, [8] etype = [18, 17, 23].
	cname := derPrincipalName(1, "admin")
	realm := derGeneralString("CORP.EXAMPLE.COM")
	sname := derPrincipalName(2, "krbtgt", "CORP.EXAMPLE.COM")
	etypeSeq := derSequence(
		derInteger(18), derInteger(17), derInteger(23))
	reqBody := derSequence(
		ctxConstructed(1, cname),
		ctxConstructed(2, realm),
		ctxConstructed(3, sname),
		ctxConstructed(8, etypeSeq),
	)
	// KDC-REQ: [1] pvno=5, [2] msg-type=10, [4] req-body
	// (NO [3] padata = AS-REP roastable!)
	kdcReq := derSequence(
		ctxConstructed(1, derInteger(5)),
		ctxConstructed(2, derInteger(10)),
		ctxConstructed(4, reqBody),
	)
	// Outer wrapper [APPLICATION 10] = 0x6A.
	msg := derTag(0x6A, kdcReq)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "AS-REQ" {
		t.Errorf("msgType: got %q want AS-REQ", r.MessageTypeName)
	}
	if r.Realm != "CORP.EXAMPLE.COM" {
		t.Errorf("realm: got %q", r.Realm)
	}
	if r.ClientName != "admin" {
		t.Errorf("cname: got %q want admin", r.ClientName)
	}
	if r.ServerName != "krbtgt/CORP.EXAMPLE.COM" {
		t.Errorf("sname: got %q", r.ServerName)
	}
	if len(r.EncTypes) != 3 {
		t.Errorf("etype count: got %d want 3", len(r.EncTypes))
	}
	if r.PreAuthSet {
		t.Errorf("PreAuthSet: should be false (AS-REP roastable!)")
	}
}

// TestDecodeASREQWithPreAuth pins an AS-REQ WITH PA-ENC-TIMESTAMP
// (preauth enabled = NOT AS-REP-roastable).
func TestDecodeASREQWithPreAuth(t *testing.T) {
	// PA-DATA: SEQUENCE { [1] padata-type=2, [2] padata-value
	// OCTET-STRING (opaque enc-timestamp bytes) }
	paEntry := derSequence(
		ctxConstructed(1, derInteger(2)),
		ctxConstructed(2, derTag(0x04, []byte("opaque"))),
	)
	padata := derSequence(paEntry)
	reqBody := derSequence(
		ctxConstructed(2, derGeneralString("CORP.LOCAL")),
		ctxConstructed(3, derPrincipalName(2, "krbtgt", "CORP.LOCAL")),
		ctxConstructed(8, derSequence(derInteger(18))),
	)
	kdcReq := derSequence(
		ctxConstructed(1, derInteger(5)),
		ctxConstructed(2, derInteger(10)),
		ctxConstructed(3, padata),
		ctxConstructed(4, reqBody),
	)
	msg := derTag(0x6A, kdcReq)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.PreAuthSet {
		t.Errorf("PreAuthSet: should be true (PA-ENC-TIMESTAMP present)")
	}
	if len(r.PADataTypes) != 1 || r.PADataTypes[0] != 2 {
		t.Errorf("padata types: got %v want [2]", r.PADataTypes)
	}
}

// TestDecodeTGSREQKerberoastTarget pins a TGS-REQ with an SPN
// target (the Kerberoasting recon shape).
func TestDecodeTGSREQKerberoastTarget(t *testing.T) {
	// sname = MSSQLSvc/sql01.corp.example.com:1433
	sname := derPrincipalName(2,
		"MSSQLSvc", "sql01.corp.example.com:1433")
	reqBody := derSequence(
		ctxConstructed(2, derGeneralString("CORP.EXAMPLE.COM")),
		ctxConstructed(3, sname),
		ctxConstructed(8, derSequence(derInteger(23))),
	)
	kdcReq := derSequence(
		ctxConstructed(1, derInteger(5)),
		ctxConstructed(2, derInteger(12)),
		ctxConstructed(4, reqBody),
	)
	// Outer tag for TGS-REQ = [APPLICATION 12] = 0x6C.
	msg := derTag(0x6C, kdcReq)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "TGS-REQ" {
		t.Errorf("msgType: got %q want TGS-REQ", r.MessageTypeName)
	}
	if !strings.HasPrefix(r.ServerName, "MSSQLSvc/sql01") {
		t.Errorf("sname: got %q", r.ServerName)
	}
}

// TestDecodeKRBErrorPreauthRequired pins KRB-ERROR with the
// canonical "user is NOT AS-REP-roastable" response code.
func TestDecodeKRBErrorPreauthRequired(t *testing.T) {
	// Error: [4] stime (skip — use a placeholder), [6] error-
	// code=25, [9] realm "CORP.LOCAL", [10] sname.
	errBody := derSequence(
		ctxConstructed(6, derInteger(25)),
		ctxConstructed(7, derGeneralString("CORP.LOCAL")),
		ctxConstructed(9, derGeneralString("CORP.LOCAL")),
		ctxConstructed(10, derPrincipalName(2, "krbtgt", "CORP.LOCAL")),
	)
	msg := derTag(0x7E, errBody)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "KRB-ERROR" {
		t.Errorf("msgType: got %q want KRB-ERROR", r.MessageTypeName)
	}
	if r.ErrorCode != 25 {
		t.Errorf("errorCode: got %d want 25", r.ErrorCode)
	}
	if r.ErrorCodeName != "KDC_ERR_PREAUTH_REQUIRED" {
		t.Errorf("errorCodeName: got %q", r.ErrorCodeName)
	}
}

// TestDecodeKRBErrorPrincipalUnknown pins the canonical
// username-doesn't-exist response.
func TestDecodeKRBErrorPrincipalUnknown(t *testing.T) {
	errBody := derSequence(
		ctxConstructed(6, derInteger(6)),
		ctxConstructed(9, derGeneralString("CORP.LOCAL")),
	)
	msg := derTag(0x7E, errBody)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ErrorCodeName != "KDC_ERR_C_PRINCIPAL_UNKNOWN" {
		t.Errorf("errorCodeName: got %q", r.ErrorCodeName)
	}
}

// TestMessageTypeNameTable spot-checks each catalogued type.
func TestMessageTypeNameTable(t *testing.T) {
	cases := map[int]string{
		10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ",
		13: "TGS-REP", 14: "AP-REQ", 15: "AP-REP",
		30: "KRB-ERROR",
	}
	for k, v := range cases {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(messageTypeName(99), "uncatalogued") {
		t.Errorf("uncatalogued message type should be flagged")
	}
}

// TestEncTypeNameTable spot-checks key encryption types.
func TestEncTypeNameTable(t *testing.T) {
	if encTypeName(17) != "aes128-cts-hmac-sha1-96" {
		t.Errorf("etype 17 mislabelled")
	}
	if encTypeName(18) != "aes256-cts-hmac-sha1-96" {
		t.Errorf("etype 18 mislabelled")
	}
	if !strings.Contains(encTypeName(23), "weak") {
		t.Errorf("etype 23 (rc4-hmac) should flag weak")
	}
}

// TestPADataNameTable spot-checks key padata types.
func TestPADataNameTable(t *testing.T) {
	if !strings.Contains(paDataName(2), "preauth") {
		t.Errorf("padata type 2 should flag preauth")
	}
	if paDataName(128) != "PA-PAC-REQUEST" {
		t.Errorf("padata type 128 mislabelled")
	}
}

// TestErrorCodeNameTable spot-checks high-runner error codes.
func TestErrorCodeNameTable(t *testing.T) {
	cases := map[int]string{
		6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN",
		18: "KDC_ERR_CLIENT_REVOKED",
		24: "KDC_ERR_PREAUTH_FAILED",
		25: "KDC_ERR_PREAUTH_REQUIRED",
		37: "KRB_AP_ERR_SKEW",
	}
	for k, v := range cases {
		if got := errorCodeName(k); got != v {
			t.Errorf("errorCodeName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestReadDERLength covers short and long-form length.
func TestReadDERLength(t *testing.T) {
	v, n, err := readDERLength([]byte{0x7F})
	if err != nil || v != 127 || n != 1 {
		t.Errorf("short-form 0x7F: got v=%d n=%d err=%v", v, n, err)
	}
	v, n, err = readDERLength([]byte{0x81, 0x80})
	if err != nil || v != 128 || n != 2 {
		t.Errorf("long-form 1-octet 0x81 0x80: got v=%d n=%d err=%v",
			v, n, err)
	}
	v, n, err = readDERLength([]byte{0x82, 0x01, 0x00})
	if err != nil || v != 256 || n != 3 {
		t.Errorf("long-form 2-octet 0x82 0x01 0x00: got v=%d n=%d err=%v",
			v, n, err)
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

func TestDecodeRejectsNonApplicationTag(t *testing.T) {
	// 0x30 is SEQUENCE (universal class), not application.
	if _, err := Decode("3000"); err == nil {
		t.Fatal("want error for non-application outer tag")
	}
}
