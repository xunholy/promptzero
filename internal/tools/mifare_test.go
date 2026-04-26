// mifare_test.go — covers the mifare Specs.
//
//   • mfoc_attack and mfcuk_attack are now REAL offline implementations
//     backed by internal/crypto1.RecoverNestedWithRange and
//     internal/crypto1.RecoverDarksideWithRange respectively.  Tests use
//     closed-loop synthetic captures: synthesise the captured data from a
//     known key, call the handler, verify the recovered key matches.
//
//   • mfkey32_recover is REAL — unchanged from the prior implementation.

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

// synthesizeNestedAttemptForTools builds the encrypted NTEnc and AR for one
// nested attempt using the given keys and nonces.  Returns (ntEnc, ar).
func synthesizeNestedAttemptForTools(knownKey uint64, targetKey uint64, uid, knownNT, knownNR, plainNT, nr uint32) (ntEnc, ar uint32) {
	c := crypto1.New()
	c.Init(knownKey)
	c.CryptFeedback(uid ^ knownNT)
	c.EncCrypt(knownNR, 0)
	c.Crypt(0) // consume aR-phase keystream
	ks := c.Crypt(0)
	ntEnc = plainNT ^ ks
	_, ar = crypto1.AuthEncrypt(targetKey, uid, crypto1.AuthCapture{NT: plainNT, NR: nr})
	return
}

// TestMfoc_ClosedLoop synthesises a NestedCapture for a known 16-bit key and
// verifies the mfoc_attack handler returns status="found" with the correct key.
func TestMfoc_ClosedLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("mfoc closed-loop search (~70 ms): skipped in -short mode")
	}

	const (
		targetKey = uint64(0x1234)
		knownKey  = uint64(0xA0A1A2A3A4A5)
		uid       = uint32(0xCAFEBABE)
	)

	// Attempt 0 and 1 plain target NTs and their known-sector nonces.
	knownNT0, knownNR0 := uint32(0x01020304), uint32(0xDEADBEEF)
	knownNT1, knownNR1 := uint32(0xE93E12E4), uint32(0x55667788)
	plainNT0, nr0 := uint32(0xABCDABCD), uint32(0x11223344)
	plainNT1, nr1 := uint32(0xDEAD1234), uint32(0x99AABBCC)

	ntEnc0, ar0 := synthesizeNestedAttemptForTools(knownKey, targetKey, uid, knownNT0, knownNR0, plainNT0, nr0)
	ntEnc1, ar1 := synthesizeNestedAttemptForTools(knownKey, targetKey, uid, knownNT1, knownNR1, plainNT1, nr1)

	spec, ok := Get("mfoc_attack")
	if !ok {
		t.Fatal("mfoc_attack not registered")
	}

	args := map[string]any{
		"uid_hex":       upperHex(uid),
		"known_key_hex": upperHex48(knownKey),
		"attempts": []any{
			map[string]any{
				"known_nt_hex": upperHex(knownNT0),
				"known_nr_hex": upperHex(knownNR0),
				"nt_enc_hex":   upperHex(ntEnc0),
				"nr_hex":       upperHex(nr0),
				"ar_hex":       upperHex(ar0),
			},
			map[string]any{
				"known_nt_hex": upperHex(knownNT1),
				"known_nr_hex": upperHex(knownNR1),
				"nt_enc_hex":   upperHex(ntEnc1),
				"nr_hex":       upperHex(nr1),
				"ar_hex":       upperHex(ar1),
			},
		},
		"search_range_bits": float64(16),
		"timeout_seconds":   float64(60),
	}

	body, err := spec.Handler(context.Background(), &Deps{}, args)
	if err != nil {
		t.Fatalf("mfoc_attack handler error: %v\nbody=%s", err, body)
	}

	var m map[string]any
	if jerr := json.Unmarshal([]byte(body), &m); jerr != nil {
		t.Fatalf("body not JSON: %v\n%s", jerr, body)
	}
	if status, _ := m["status"].(string); status != "found" {
		t.Errorf("status = %q, want found; body=%s", status, body)
	}
	wantKey := upperHex48(targetKey)
	if got, _ := m["key"].(string); got != wantKey {
		t.Errorf("key = %q, want %q; body=%s", got, wantKey, body)
	}
}

// TestMfoc_TooFewAttempts verifies the handler rejects < 2 attempts.
func TestMfoc_TooFewAttempts(t *testing.T) {
	spec, _ := Get("mfoc_attack")
	args := map[string]any{
		"uid_hex":       "CAFEBABE",
		"known_key_hex": "A0A1A2A3A4A5",
		"attempts": []any{
			map[string]any{
				"known_nt_hex": "01020304",
				"known_nr_hex": "DEADBEEF",
				"nt_enc_hex":   "12345678",
				"nr_hex":       "11223344",
				"ar_hex":       "AABBCCDD",
			},
		},
	}
	_, err := spec.Handler(context.Background(), &Deps{}, args)
	if err == nil {
		t.Fatal("expected error for < 2 attempts")
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error should mention '2': %v", err)
	}
}

// TestMfoc_BadHex verifies the handler returns an error for malformed hex.
func TestMfoc_BadHex(t *testing.T) {
	spec, _ := Get("mfoc_attack")
	args := map[string]any{
		"uid_hex":       "not-hex",
		"known_key_hex": "A0A1A2A3A4A5",
		"attempts":      []any{},
	}
	_, err := spec.Handler(context.Background(), &Deps{}, args)
	if err == nil {
		t.Fatal("expected error for malformed hex")
	}
}

// TestMfcuk_ClosedLoop synthesises DarksidePairs for a known 16-bit key and
// verifies the mfcuk_attack handler returns status="found" with the correct key.
func TestMfcuk_ClosedLoop(t *testing.T) {
	const (
		key = uint64(0x1234)
		uid = uint32(0xCAFEBABE)
		nt  = uint32(0x01020304)
	)

	// Build 256 pairs with distinct NR low bytes (low byte = i for index i).
	const seed = uint32(uid ^ nt)
	pairs := make([]any, 256)
	for i := 0; i < 256; i++ {
		hi := (seed + uint32(i)*0x00010100) & 0xFFFFFF00
		nr := hi | uint32(i)
		parity := crypto1.SynthesizeDarksideParity(key, uid, nt, nr)
		pairs[i] = map[string]any{
			"nr_hex": upperHex(nr),
			"parity": float64(parity),
		}
	}

	spec, ok := Get("mfcuk_attack")
	if !ok {
		t.Fatal("mfcuk_attack not registered")
	}

	args := map[string]any{
		"uid_hex":           upperHex(uid),
		"nt_hex":            upperHex(nt),
		"pairs":             pairs,
		"search_range_bits": float64(16),
		"timeout_seconds":   float64(60),
	}

	body, err := spec.Handler(context.Background(), &Deps{}, args)
	if err != nil {
		t.Fatalf("mfcuk_attack handler error: %v\nbody=%s", err, body)
	}

	var m map[string]any
	if jerr := json.Unmarshal([]byte(body), &m); jerr != nil {
		t.Fatalf("body not JSON: %v\n%s", jerr, body)
	}
	if status, _ := m["status"].(string); status != "found" {
		t.Errorf("status = %q, want found; body=%s", status, body)
	}
	wantKey := upperHex48(key)
	if got, _ := m["key"].(string); got != wantKey {
		t.Errorf("key = %q, want %q; body=%s", got, wantKey, body)
	}
}

// TestMfcuk_EmptyPairs verifies the handler rejects an empty pairs array.
func TestMfcuk_EmptyPairs(t *testing.T) {
	spec, _ := Get("mfcuk_attack")
	args := map[string]any{
		"uid_hex": "CAFEBABE",
		"nt_hex":  "01020304",
		"pairs":   []any{},
	}
	_, err := spec.Handler(context.Background(), &Deps{}, args)
	if err == nil {
		t.Fatal("expected error for empty pairs")
	}
}

// TestMfcuk_BadHex verifies the handler returns an error for malformed hex.
func TestMfcuk_BadHex(t *testing.T) {
	spec, _ := Get("mfcuk_attack")
	args := map[string]any{
		"uid_hex": "not-hex",
		"nt_hex":  "01020304",
		"pairs":   []any{},
	}
	_, err := spec.Handler(context.Background(), &Deps{}, args)
	if err == nil {
		t.Fatal("expected error for malformed uid_hex")
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
