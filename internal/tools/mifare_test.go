// mifare_test.go — covers the v0.6 mifare Specs.
//
// As of v0.6:
//
//   • mfoc_attack and mfcuk_attack return status="live_nfc_required" with
//     an error pointing operators at the federated pm3-mcp path. They are
//     stubs because the live-NFC nested/darkside attacks need a real
//     reader.
//   • mfkey32_recover is REAL — it runs the Crypto1 LFSR rollback against
//     the captured (uid, nt, nr, ar) tuples, and returns status="found"
//     with the recovered 6-byte key.
//
// These tests use closed-loop synthetic captures: encrypt with a known
// key via the same crypto1 primitive, then verify Recover gets the key
// back.

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/crypto1"
)

func TestMifare_RegistrationContract(t *testing.T) {
	for _, name := range []string{"mfoc_attack", "mfcuk_attack", "mfkey32_recover"} {
		s, ok := Get(name)
		if !ok {
			t.Errorf("%s: not registered", name)
			continue
		}
		if s.Description == "" {
			t.Errorf("%s: empty description", name)
		}
		if len(s.Schema) == 0 {
			t.Errorf("%s: empty schema", name)
		}
		if s.Handler == nil {
			t.Errorf("%s: nil handler", name)
		}
	}
}

func TestMifare_FederatedFallback(t *testing.T) {
	cases := map[string]map[string]any{
		"mfoc_attack":  {"uid_hex": "CAFEBABE", "known_key_hex": "FFFFFFFFFFFF", "known_sector": float64(0), "key_type": "A"},
		"mfcuk_attack": {"uid_hex": "CAFEBABE"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			s, ok := Get(name)
			if !ok {
				t.Fatalf("not registered")
			}
			body, err := s.Handler(context.Background(), &Deps{}, args)
			if err == nil {
				t.Fatalf("%s: expected error (federated fallback)", name)
			}
			if !strings.Contains(err.Error(), "pm3-mcp") {
				t.Errorf("%s: error %v missing pm3-mcp redirect", name, err)
			}
			var m map[string]any
			if jerr := json.Unmarshal([]byte(body), &m); jerr != nil {
				t.Fatalf("%s: result is not JSON: %v\nbody=%s", name, jerr, body)
			}
			if status, _ := m["status"].(string); status != "live_nfc_required" {
				t.Errorf("%s: status = %q, want live_nfc_required", name, status)
			}
		})
	}
}

func TestMfkey32Recover_ClosedLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("closed-loop search takes ~70 ms; skipped in -short mode")
	}

	const (
		key uint64 = 0x1234 // 16-bit key — Recover with default search_range_bits=16 finds it fast
		uid uint32 = 0xCAFEBABE
		nt0 uint32 = 0x01020304
		nr0 uint32 = 0xDEADBEEF
		nt1 uint32 = 0x55667788
		nr1 uint32 = 0x12345678
	)

	// Synthesise the on-wire encrypted reader response for both captures
	// using the same crypto1 primitive Recover is built on.
	_, ar0 := crypto1.AuthEncrypt(key, uid, crypto1.AuthCapture{NT: nt0, NR: nr0})
	_, ar1 := crypto1.AuthEncrypt(key, uid, crypto1.AuthCapture{NT: nt1, NR: nr1})

	spec, ok := Get("mfkey32_recover")
	if !ok {
		t.Fatal("mfkey32_recover not registered")
	}

	args := map[string]any{
		"uid_hex":           upperHex(uid),
		"nt0_hex":           upperHex(nt0),
		"nr0_hex":           upperHex(nr0),
		"ar0_hex":           upperHex(ar0),
		"nt1_hex":           upperHex(nt1),
		"nr1_hex":           upperHex(nr1),
		"ar1_hex":           upperHex(ar1),
		"search_range_bits": float64(16),
		"timeout_seconds":   float64(60),
	}

	body, err := spec.Handler(context.Background(), &Deps{}, args)
	if err != nil {
		t.Fatalf("handler error: %v\nbody=%s", err, body)
	}

	var m map[string]any
	if jerr := json.Unmarshal([]byte(body), &m); jerr != nil {
		t.Fatalf("body not JSON: %v\n%s", jerr, body)
	}
	if status, _ := m["status"].(string); status != "found" {
		t.Errorf("status = %q, want found; body=%s", status, body)
	}
	if matched, _ := m["matched"].(bool); !matched {
		t.Errorf("matched = false; body=%s", body)
	}
	wantKey := upperHex48(key)
	if got, _ := m["key"].(string); got != wantKey {
		t.Errorf("key = %q, want %q (full body=%s)", got, wantKey, body)
	}
}

func TestMfkey32Recover_MissingNonces(t *testing.T) {
	spec, _ := Get("mfkey32_recover")

	// Provide nr0/ar0/nr1/ar1 but no nt — expect a clear error.
	args := map[string]any{
		"uid_hex": "CAFEBABE",
		"nr0_hex": "DEADBEEF",
		"ar0_hex": "11223344",
		"nr1_hex": "55667788",
		"ar1_hex": "AABBCCDD",
	}
	_, err := spec.Handler(context.Background(), &Deps{}, args)
	if err == nil {
		t.Fatalf("expected error for missing nt")
	}
	if !strings.Contains(err.Error(), "nt") {
		t.Errorf("error missing 'nt': %v", err)
	}
}

func TestMfkey32Recover_BadHex(t *testing.T) {
	spec, _ := Get("mfkey32_recover")

	args := map[string]any{
		"uid_hex": "not-hex",
		"nt_hex":  "01020304",
		"nr0_hex": "DEADBEEF",
		"ar0_hex": "11223344",
		"nr1_hex": "55667788",
		"ar1_hex": "AABBCCDD",
	}
	_, err := spec.Handler(context.Background(), &Deps{}, args)
	if err == nil {
		t.Fatalf("expected error for malformed hex")
	}
}

// upperHex formats a uint32 as 8-char uppercase hex (no 0x prefix).
func upperHex(v uint32) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[7-i] = hexDigits[(v>>uint(i*4))&0xF]
	}
	return string(out)
}

// upperHex48 formats a uint64 as 12-char uppercase hex (low 48 bits).
func upperHex48(v uint64) string {
	const hexDigits = "0123456789ABCDEF"
	out := make([]byte, 12)
	for i := 0; i < 12; i++ {
		out[11-i] = hexDigits[(v>>uint(i*4))&0xF]
	}
	return string(out)
}
