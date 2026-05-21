package ldap

import (
	"encoding/hex"
	"testing"
)

func derTag(t byte, content []byte) []byte {
	l := derLength(len(content))
	out := append([]byte{t}, l...)
	return append(out, content...)
}

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

func derInteger(v int) []byte {
	if v == 0 {
		return derTag(0x02, []byte{0x00})
	}
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

func derEnumerated(v int) []byte {
	if v == 0 {
		return derTag(0x0A, []byte{0x00})
	}
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xFF)}, bytes...)
		v >>= 8
	}
	return derTag(0x0A, bytes)
}

func derOctetString(s string) []byte {
	return derTag(0x04, []byte(s))
}

func derBoolean(v bool) []byte {
	if v {
		return derTag(0x01, []byte{0xFF})
	}
	return derTag(0x01, []byte{0x00})
}

func derSequence(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return derTag(0x30, content)
}

// TestDecodeSimpleBindCleartextCreds pins the canonical
// credential-disclosure shape: BindRequest with [0] simple
// authentication carrying a cleartext password.
func TestDecodeSimpleBindCleartextCreds(t *testing.T) {
	// BindRequest body: version=3 / name="cn=admin,dc=corp,
	// dc=example,dc=com" / authentication=[0] simple "hunter2"
	password := "hunter2"
	bindBody := []byte{
		// version INTEGER 3
		0x02, 0x01, 0x03,
		// name OCTET STRING "cn=admin,..."
	}
	name := "cn=admin,dc=corp,dc=example,dc=com"
	bindBody = append(bindBody, derOctetString(name)...)
	// authentication [0] simple OCTET STRING (cleartext pwd)
	authSimple := []byte{0x80, byte(len(password))}
	authSimple = append(authSimple, []byte(password)...)
	bindBody = append(bindBody, authSimple...)
	// BindRequest = [APPLICATION 0] = 0x60
	protocolOp := derTag(0x60, bindBody)
	// LDAPMessage = SEQUENCE { messageID=1, protocolOp }
	msg := derSequence(derInteger(1), protocolOp)

	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageID != 1 {
		t.Errorf("messageID: got %d want 1", r.MessageID)
	}
	if r.ProtocolOpName != "BindRequest" {
		t.Errorf("op: got %q want BindRequest", r.ProtocolOpName)
	}
	if r.BindVersion != 3 {
		t.Errorf("version: got %d want 3", r.BindVersion)
	}
	if r.BindName != name {
		t.Errorf("name: got %q want %q", r.BindName, name)
	}
	if !r.SimpleBindPresent {
		t.Errorf("SimpleBindPresent should be true (cleartext-creds!)")
	}
	if r.BindPasswordBytes != len(password) {
		t.Errorf("bindPasswordBytes: got %d want %d",
			r.BindPasswordBytes, len(password))
	}
	if r.BindAuthType != "simple" {
		t.Errorf("authType: got %q want simple", r.BindAuthType)
	}
}

// TestDecodeSASLGSSAPIBind pins a BindRequest using SASL with
// the GSSAPI mechanism (Kerberos integration).
func TestDecodeSASLGSSAPIBind(t *testing.T) {
	// authentication [3] sasl SaslCredentials { mechanism
	// LDAPString "GSSAPI", credentials OPTIONAL omitted }
	saslBody := derOctetString("GSSAPI")
	authSASL := []byte{0xA3, byte(len(saslBody))}
	authSASL = append(authSASL, saslBody...)
	bindBody := []byte{0x02, 0x01, 0x03}
	bindBody = append(bindBody, derOctetString("")...)
	bindBody = append(bindBody, authSASL...)
	protocolOp := derTag(0x60, bindBody)
	msg := derSequence(derInteger(2), protocolOp)

	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.BindAuthType != "sasl" {
		t.Errorf("authType: got %q want sasl", r.BindAuthType)
	}
	if r.SASLMechanism != "GSSAPI" {
		t.Errorf("mechanism: got %q want GSSAPI", r.SASLMechanism)
	}
	if r.SimpleBindPresent {
		t.Errorf("SimpleBindPresent should be false for SASL")
	}
}

// TestDecodeBindResponseInvalidCredentials pins the canonical
// brute-force feedback signal: resultCode 49.
func TestDecodeBindResponseInvalidCredentials(t *testing.T) {
	respBody := derEnumerated(49)
	respBody = append(respBody, derOctetString("")...)
	respBody = append(respBody, derOctetString(
		"80090308: LdapErr: DSID-0C09042F")...)
	protocolOp := derTag(0x61, respBody)
	msg := derSequence(derInteger(3), protocolOp)

	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ProtocolOpName != "BindResponse" {
		t.Errorf("op: got %q want BindResponse", r.ProtocolOpName)
	}
	if r.ResultCode != 49 {
		t.Errorf("resultCode: got %d want 49", r.ResultCode)
	}
	if r.ResultCodeName != "invalidCredentials" {
		t.Errorf("resultCodeName: got %q", r.ResultCodeName)
	}
}

// TestDecodeBindResponseSuccess pins the credential-confirm
// signal that ldapsearch/kerbrute loops consume.
func TestDecodeBindResponseSuccess(t *testing.T) {
	respBody := derEnumerated(0)
	respBody = append(respBody, derOctetString("")...)
	respBody = append(respBody, derOctetString("")...)
	protocolOp := derTag(0x61, respBody)
	msg := derSequence(derInteger(4), protocolOp)

	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ResultCodeName != "success" {
		t.Errorf("resultCodeName: got %q want success", r.ResultCodeName)
	}
}

// TestDecodeSearchRequestWholeSubtree pins the canonical
// full-directory-dump shape: scope=wholeSubtree against the
// domain naming context.
func TestDecodeSearchRequestWholeSubtree(t *testing.T) {
	baseObject := "DC=corp,DC=example,DC=com"
	// minimal Filter: (objectClass=*) — present(0) with value
	// "objectClass". Tag = [7] = 0x87 PRIMITIVE OCTET STRING.
	filter := []byte{0x87, 0x0B}
	filter = append(filter, []byte("objectClass")...)
	// AttributeSelection SEQUENCE OF LDAPString — empty.
	attrs := derSequence()
	searchBody := derOctetString(baseObject)
	searchBody = append(searchBody, derEnumerated(2)...) // wholeSubtree
	searchBody = append(searchBody, derEnumerated(0)...) // derefAliases=never
	searchBody = append(searchBody, derInteger(1000)...) // sizeLimit
	searchBody = append(searchBody, derInteger(30)...)   // timeLimit
	searchBody = append(searchBody, derBoolean(false)...)
	searchBody = append(searchBody, filter...)
	searchBody = append(searchBody, attrs...)
	protocolOp := derTag(0x63, searchBody)
	msg := derSequence(derInteger(5), protocolOp)

	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ProtocolOpName != "SearchRequest" {
		t.Errorf("op: got %q want SearchRequest", r.ProtocolOpName)
	}
	if r.SearchBaseObject != baseObject {
		t.Errorf("baseObject: got %q want %q",
			r.SearchBaseObject, baseObject)
	}
	if r.SearchScope != 2 {
		t.Errorf("scope: got %d want 2", r.SearchScope)
	}
	if r.SearchScopeName != "wholeSubtree" {
		t.Errorf("scopeName: got %q want wholeSubtree", r.SearchScopeName)
	}
	if r.SearchSizeLimit != 1000 {
		t.Errorf("sizeLimit: got %d want 1000", r.SearchSizeLimit)
	}
	if r.SearchTimeLimit != 30 {
		t.Errorf("timeLimit: got %d want 30", r.SearchTimeLimit)
	}
}

// TestDecodeSearchResultEntry pins the directory-enumeration
// leak: each SearchResultEntry frame exposes a DN.
func TestDecodeSearchResultEntry(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"
	entryBody := derOctetString(dn)
	// PartialAttributeList = empty SEQUENCE for this test.
	entryBody = append(entryBody, derSequence()...)
	protocolOp := derTag(0x64, entryBody)
	msg := derSequence(derInteger(6), protocolOp)

	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ProtocolOpName != "SearchResultEntry" {
		t.Errorf("op: got %q want SearchResultEntry",
			r.ProtocolOpName)
	}
	if r.EntryObjectName != dn {
		t.Errorf("objectName: got %q want %q",
			r.EntryObjectName, dn)
	}
}

// TestOpNameTable spot-checks each catalogued operation.
func TestOpNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "BindRequest",
		1:  "BindResponse",
		2:  "UnbindRequest",
		3:  "SearchRequest",
		4:  "SearchResultEntry",
		5:  "SearchResultDone",
		6:  "ModifyRequest",
		7:  "ModifyResponse",
		8:  "AddRequest",
		9:  "AddResponse",
		10: "DelRequest",
		11: "DelResponse",
		12: "ModifyDNRequest",
		13: "ModifyDNResponse",
		14: "CompareRequest",
		15: "CompareResponse",
		16: "AbandonRequest",
		19: "SearchResultReference",
		23: "ExtendedRequest",
		24: "ExtendedResponse",
		25: "IntermediateResponse",
	}
	for k, v := range cases {
		if got := opName(k); got != v {
			t.Errorf("opName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestResultCodeNameTable spot-checks each catalogued
// result code.
func TestResultCodeNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "success",
		1:  "operationsError",
		2:  "protocolError",
		4:  "sizeLimitExceeded",
		7:  "authMethodNotSupported",
		8:  "strongerAuthRequired",
		10: "referral",
		11: "adminLimitExceeded",
		13: "confidentialityRequired",
		14: "saslBindInProgress",
		16: "noSuchAttribute",
		32: "noSuchObject",
		48: "inappropriateAuthentication",
		49: "invalidCredentials",
		50: "insufficientAccessRights",
		51: "busy",
		53: "unwillingToPerform",
	}
	for k, v := range cases {
		if got := resultCodeName(k); got != v {
			t.Errorf("resultCodeName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestScopeNameTable spot-checks each catalogued search scope.
func TestScopeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "baseObject",
		1: "singleLevel",
		2: "wholeSubtree",
		3: "subordinateSubtree",
	}
	for k, v := range cases {
		if got := scopeName(k); got != v {
			t.Errorf("scopeName(%d) = %q want %q", k, got, v)
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

func TestDecodeRejectsNonSequenceOuter(t *testing.T) {
	if _, err := Decode("0200"); err == nil {
		t.Fatal("want error for non-SEQUENCE outer")
	}
}
