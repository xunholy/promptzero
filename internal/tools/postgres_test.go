package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func pgStartup(kv map[string]string) []byte {
	var body []byte
	for k, v := range kv {
		body = append(body, []byte(k)...)
		body = append(body, 0x00)
		body = append(body, []byte(v)...)
		body = append(body, 0x00)
	}
	body = append(body, 0x00)
	total := 4 + 4 + len(body)
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(total))
	binary.BigEndian.PutUint32(out[4:8], 0x00030000)
	copy(out[8:], body)
	return out
}

func pgTyped(t byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = t
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

func TestPostgresDecodeHandler_StartupMessage(t *testing.T) {
	msg := pgStartup(map[string]string{
		"user":             "postgres",
		"database":         "production",
		"application_name": "psql",
	})
	out, err := postgresDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "StartupMessage"`,
		`"user": "postgres"`,
		`"database": "production"`,
		`"application_name": "psql"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPostgresDecodeHandler_AuthCleartextPassword(t *testing.T) {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 3)
	msg := pgTyped('R', body)
	out, err := postgresDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Authentication"`,
		`MITM-capturable`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPostgresDecodeHandler_ErrorInvalidPassword(t *testing.T) {
	var body []byte
	body = append(body, 'S')
	body = append(body, []byte("FATAL")...)
	body = append(body, 0x00)
	body = append(body, 'C')
	body = append(body, []byte("28P01")...)
	body = append(body, 0x00)
	body = append(body, 0x00)
	msg := pgTyped('E', body)
	out, err := postgresDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"sqlstate": "28P01"`,
		`invalid_password`,
		`brute-force feedback`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPostgresDecodeHandler_SSLRequest(t *testing.T) {
	b := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
	out, err := postgresDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"is_ssl_request": true`) {
		t.Errorf("expected SSL request flag:\n%s", out)
	}
}

func TestPostgresDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := postgresDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
