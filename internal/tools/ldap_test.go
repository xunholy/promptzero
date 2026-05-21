package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func ldapDerTag(t byte, content []byte) []byte {
	l := ldapDerLength(len(content))
	out := append([]byte{t}, l...)
	return append(out, content...)
}

func ldapDerLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func ldapDerInteger(v int) []byte {
	if v == 0 {
		return ldapDerTag(0x02, []byte{0x00})
	}
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xFF)}, bytes...)
		v >>= 8
	}
	if bytes[0]&0x80 != 0 {
		bytes = append([]byte{0x00}, bytes...)
	}
	return ldapDerTag(0x02, bytes)
}

func ldapDerEnumerated(v int) []byte {
	if v == 0 {
		return ldapDerTag(0x0A, []byte{0x00})
	}
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xFF)}, bytes...)
		v >>= 8
	}
	return ldapDerTag(0x0A, bytes)
}

func ldapDerOctet(s string) []byte {
	return ldapDerTag(0x04, []byte(s))
}

func ldapDerSeq(items ...[]byte) []byte {
	var content []byte
	for _, it := range items {
		content = append(content, it...)
	}
	return ldapDerTag(0x30, content)
}

// TestLDAPDecodeHandler_SimpleBindCleartext pins the canonical
// credential-disclosure shape.
func TestLDAPDecodeHandler_SimpleBindCleartext(t *testing.T) {
	password := "hunter2"
	name := "cn=admin,dc=corp,dc=example,dc=com"
	bindBody := []byte{0x02, 0x01, 0x03}
	bindBody = append(bindBody, ldapDerOctet(name)...)
	authSimple := []byte{0x80, byte(len(password))}
	authSimple = append(authSimple, []byte(password)...)
	bindBody = append(bindBody, authSimple...)
	protocolOp := ldapDerTag(0x60, bindBody)
	msg := ldapDerSeq(ldapDerInteger(1), protocolOp)
	out, err := ldapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"protocol_op_name": "BindRequest"`,
		`"bind_name": "cn=admin,dc=corp,dc=example,dc=com"`,
		`"bind_auth_type": "simple"`,
		`"simple_bind_present": true`,
		`"bind_password_bytes": 7`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLDAPDecodeHandler_BindResponseInvalidCredentials pins
// the canonical brute-force feedback signal.
func TestLDAPDecodeHandler_BindResponseInvalidCredentials(t *testing.T) {
	respBody := ldapDerEnumerated(49)
	respBody = append(respBody, ldapDerOctet("")...)
	respBody = append(respBody, ldapDerOctet("LdapErr: DSID-0C09042F")...)
	protocolOp := ldapDerTag(0x61, respBody)
	msg := ldapDerSeq(ldapDerInteger(3), protocolOp)
	out, err := ldapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"protocol_op_name": "BindResponse"`,
		`"result_code": 49`,
		`"result_code_name": "invalidCredentials"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLDAPDecodeHandler_SearchResultEntry pins the directory-
// enumeration leak.
func TestLDAPDecodeHandler_SearchResultEntry(t *testing.T) {
	dn := "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"
	entryBody := ldapDerOctet(dn)
	entryBody = append(entryBody, ldapDerSeq()...)
	protocolOp := ldapDerTag(0x64, entryBody)
	msg := ldapDerSeq(ldapDerInteger(6), protocolOp)
	out, err := ldapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"protocol_op_name": "SearchResultEntry"`,
		`"entry_object_name": "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestLDAPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ldapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
