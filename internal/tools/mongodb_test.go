package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func mgBSONString(name, value string) []byte {
	out := []byte{0x02}
	out = append(out, []byte(name)...)
	out = append(out, 0x00)
	l := len(value) + 1
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(l))
	out = append(out, lb...)
	out = append(out, []byte(value)...)
	out = append(out, 0x00)
	return out
}

func mgBSONInt32(name string, v int32) []byte {
	out := []byte{0x10}
	out = append(out, []byte(name)...)
	out = append(out, 0x00)
	vb := make([]byte, 4)
	binary.LittleEndian.PutUint32(vb, uint32(v))
	return append(out, vb...)
}

func mgBSONBinary(name string, subtype byte, data []byte) []byte {
	out := []byte{0x05}
	out = append(out, []byte(name)...)
	out = append(out, 0x00)
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, uint32(len(data)))
	out = append(out, lb...)
	out = append(out, subtype)
	return append(out, data...)
}

func mgBSONDoc(elements ...[]byte) []byte {
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	total := 4 + len(body) + 1
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out[0:4], uint32(total))
	out = append(out, body...)
	out = append(out, 0x00)
	return out
}

func mgHeader(opCode int, totalLen int) []byte {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h[0:4], uint32(totalLen))
	binary.LittleEndian.PutUint32(h[4:8], 1)
	binary.LittleEndian.PutUint32(h[8:12], 0)
	binary.LittleEndian.PutUint32(h[12:16], uint32(opCode))
	return h
}

func mgOpMsg(doc []byte) []byte {
	body := make([]byte, 4)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	body = append(body, 0x00)
	body = append(body, doc...)
	total := 16 + len(body)
	return append(mgHeader(2013, total), body...)
}

// TestMongoDecodeHandler_HelloProbe pins the canonical version-
// + auth-mechanism enumeration probe shape.
func TestMongoDecodeHandler_HelloProbe(t *testing.T) {
	doc := mgBSONDoc(
		mgBSONInt32("hello", 1),
		mgBSONString("$db", "admin"),
	)
	out, err := mongodbDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(mgOpMsg(doc))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "hello"`,
		`"database": "admin"`,
		`"is_hello_probe": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMongoDecodeHandler_SASLStartSCRAM pins the auth exchange
// with payload-length-only surfacing (privacy-preserving).
func TestMongoDecodeHandler_SASLStartSCRAM(t *testing.T) {
	payload := []byte("n,,n=admin,r=fyko+d2lbbFgONRv9qkxdawL")
	doc := mgBSONDoc(
		mgBSONInt32("saslStart", 1),
		mgBSONString("mechanism", "SCRAM-SHA-256"),
		mgBSONBinary("payload", 0x00, payload),
		mgBSONString("$db", "admin"),
	)
	out, err := mongodbDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(mgOpMsg(doc))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "saslStart"`,
		`"is_sasl_auth": true`,
		`"sasl_mechanism": "SCRAM-SHA-256"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMongoDecodeHandler_DangerousCreateUser pins the credential
// backdoor primitive classification.
func TestMongoDecodeHandler_DangerousCreateUser(t *testing.T) {
	doc := mgBSONDoc(
		mgBSONString("createUser", "backdoor"),
		mgBSONString("$db", "admin"),
	)
	out, err := mongodbDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(mgOpMsg(doc))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_dangerous_command": true`,
		`backdoor primitive`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMongoDecodeHandler_DangerousEval pins the historical RCE
// primitive classification.
func TestMongoDecodeHandler_DangerousEval(t *testing.T) {
	doc := mgBSONDoc(
		mgBSONString("eval", "function(){return 1;}"),
		mgBSONString("$db", "admin"),
	)
	out, err := mongodbDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(mgOpMsg(doc))})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "RCE primitive") {
		t.Errorf("eval should flag RCE primitive:\n%s", out)
	}
	if !strings.Contains(out, "REMOVED in MongoDB 4.4") {
		t.Errorf("eval should reference removal in 4.4:\n%s", out)
	}
}

func TestMongoDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := mongodbDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
