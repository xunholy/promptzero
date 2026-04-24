// Package tools_test — unit tests for the Mifare stub Specs (v0.5, task #7).
//
// These three Specs (mfoc_attack, mfcuk_attack, mfkey32_recover) are
// registered as STUBS in v0.5: the Handler bodies always return a
// "deferred_v0.5.1" JSON envelope plus a descriptive error.  Full
// algorithm implementation is scheduled for v0.5.1.
//
// Acceptance criteria verified here:
//  1. All three stubs are registered in the pre-init registry snapshot.
//  2. Every invocation — with or without args — returns a non-nil error.
//  3. The returned string is valid JSON containing status="deferred_v0.5.1",
//     the spec name, and a message that mentions v0.5.1 and the workaround.
//  4. The error string includes the spec name and v0.5.1 so callers can
//     diagnose the deferral without inspecting the JSON envelope.
//  5. Each spec's Schema is valid JSON.
//  6. Risk level is High for all three (critical-access-credential recovery).
package tools_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tools"
)

// mifareStubSpec returns the named Mifare stub Spec from the pre-init
// registry snapshot (immune to resetForTest() calls in spec_test.go).
func mifareStubSpec(t *testing.T, name string) tools.Spec {
	t.Helper()
	for _, s := range initialSpecs {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("spec %q not in pre-init registry snapshot — did mifare.go init() register it?", name)
	return tools.Spec{}
}

// allMifareStubNames lists the three Mifare offline-cracker stub Specs.
var allMifareStubNames = []string{"mfoc_attack", "mfcuk_attack", "mfkey32_recover"}

// sampleMifareArgs provides one valid-looking args map per spec (the stubs
// ignore all args, but providing them clarifies intent).
var sampleMifareArgs = map[string]map[string]any{
	"mfoc_attack": {
		"uid_hex":       "aabbccdd",
		"known_key_hex": "ffffffffffff",
		"known_sector":  float64(0),
		"key_type":      "A",
	},
	"mfcuk_attack": {
		"uid_hex": "aabbccdd",
	},
	"mfkey32_recover": {
		"uid_hex": "aabbccdd",
		"nt_hex":  "11223344",
		"nr0_hex": "55667788",
		"ar0_hex": "99aabbcc",
		"nr1_hex": "ddeeff00",
		"ar1_hex": "12345678",
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_Registration — all three stubs exist in the registry.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_Registration(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			if s.Handler == nil {
				t.Errorf("spec %q has nil Handler", name)
			}
			if s.Description == "" {
				t.Errorf("spec %q has empty Description", name)
			}
			if len(s.Schema) == 0 {
				t.Errorf("spec %q has nil/empty Schema", name)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_DeferralStatus — every call returns JSON with status="deferred_v0.5.1"
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_DeferralStatus(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			out, err := s.Handler(context.Background(), nil, sampleMifareArgs[name])

			// 1. Stub MUST return a non-nil error on every call.
			if err == nil {
				t.Fatalf("spec %q: expected non-nil error, got nil", name)
			}

			// 2. The string payload must be valid JSON.
			var m map[string]any
			if jsonErr := json.Unmarshal([]byte(out), &m); jsonErr != nil {
				t.Fatalf("spec %q output is not valid JSON: %v\n  raw: %s", name, jsonErr, out)
			}

			// 3. status field must be "deferred_v0.5.1".
			status, _ := m["status"].(string)
			if status != "deferred_v0.5.1" {
				t.Errorf("spec %q: status = %q, want %q", name, status, "deferred_v0.5.1")
			}

			// 4. spec field must match the canonical spec name.
			specField, _ := m["spec"].(string)
			if specField != name {
				t.Errorf("spec %q: JSON 'spec' = %q, want %q", name, specField, name)
			}

			// 5. message field must mention v0.5.1.
			msg, _ := m["message"].(string)
			if !strings.Contains(msg, "v0.5.1") {
				t.Errorf("spec %q: message does not mention v0.5.1; got: %q", name, msg)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_ErrorWrapping — error string includes spec name + deferral hint.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_ErrorWrapping(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			_, err := s.Handler(context.Background(), nil, sampleMifareArgs[name])
			if err == nil {
				t.Fatalf("spec %q: expected error, got nil", name)
			}

			errMsg := err.Error()

			// Error must contain the spec name so callers can route it.
			if !strings.Contains(errMsg, name) {
				t.Errorf("spec %q: error %q does not contain spec name", name, errMsg)
			}

			// Error must reference v0.5.1 so operators know this is a planned gap.
			if !strings.Contains(errMsg, "v0.5.1") {
				t.Errorf("spec %q: error %q does not contain 'v0.5.1'", name, errMsg)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_DeferralMessageWorkaround — message is actionable (has workaround).
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_DeferralMessageWorkaround(t *testing.T) {
	// mfoc_attack is representative — the deferral message is shared by all three.
	s := mifareStubSpec(t, "mfoc_attack")
	out, _ := s.Handler(context.Background(), nil, sampleMifareArgs["mfoc_attack"])

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("JSON parse failed: %v", err)
	}
	msg, _ := m["message"].(string)

	// The deferral message must point operators at the live-capture workaround.
	if !strings.Contains(msg, "nfc_dump_protocol") {
		t.Errorf("deferral message should mention 'nfc_dump_protocol'; got: %q", msg)
	}
	if !strings.Contains(msg, "loader_mfkey") {
		t.Errorf("deferral message should mention 'loader_mfkey'; got: %q", msg)
	}
	// Message should describe the v0.5.1 intent so operators understand the roadmap.
	if !strings.Contains(msg, "v0.5.1") {
		t.Errorf("deferral message should reference 'v0.5.1'; got: %q", msg)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_NoArgs — stubs return deferral JSON even when required args are absent.
// ─────────────────────────────────────────────────────────────────────────────

// TestMifare_NoArgs ensures the deferred handler does not crash or return a
// different error shape when called with an empty arg map (missing required
// fields).  The real validation guard is in the LLM-agent layer, not the stub.
func TestMifare_NoArgs(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			out, err := s.Handler(context.Background(), nil, map[string]any{})

			if err == nil {
				t.Fatalf("spec %q (no args): expected error, got nil", name)
			}

			var m map[string]any
			if jsonErr := json.Unmarshal([]byte(out), &m); jsonErr != nil {
				t.Fatalf("spec %q (no args): output not valid JSON: %v\n  raw: %s", name, jsonErr, out)
			}

			status, _ := m["status"].(string)
			if status != "deferred_v0.5.1" {
				t.Errorf("spec %q (no args): status = %q, want deferred_v0.5.1", name, status)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_NilArgs — stubs tolerate a nil args map without panicking.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_NilArgs(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			out, err := s.Handler(context.Background(), nil, nil)
			if err == nil {
				t.Fatalf("spec %q (nil args): expected error, got nil", name)
			}
			var m map[string]any
			if jsonErr := json.Unmarshal([]byte(out), &m); jsonErr != nil {
				t.Fatalf("spec %q (nil args): output not valid JSON: %v\n  raw: %s", name, jsonErr, out)
			}
			if status, _ := m["status"].(string); status != "deferred_v0.5.1" {
				t.Errorf("spec %q (nil args): status = %q, want deferred_v0.5.1", name, status)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_SchemaValid — each stub's Schema is valid JSON with "type":"object".
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_SchemaValid(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			var schema map[string]json.RawMessage
			if err := json.Unmarshal(s.Schema, &schema); err != nil {
				t.Fatalf("spec %q Schema is not valid JSON: %v", name, err)
			}
			typeRaw, ok := schema["type"]
			if !ok {
				t.Errorf("spec %q Schema missing 'type' field", name)
			} else {
				var typeVal string
				if err := json.Unmarshal(typeRaw, &typeVal); err != nil || typeVal != "object" {
					t.Errorf("spec %q Schema type = %q, want 'object'", name, typeVal)
				}
			}
			if _, ok := schema["properties"]; !ok {
				t.Errorf("spec %q Schema missing 'properties'", name)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_RiskLevel — all three stubs carry risk.High.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_RiskLevel(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			if s.Risk != risk.High {
				t.Errorf("spec %q Risk = %v, want High", name, s.Risk)
			}
			// Also verify risk.Classify agrees.
			if got := risk.Classify(name); got != risk.High {
				t.Errorf("risk.Classify(%q) = %v, want High", name, got)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_OutputJSONFields — all required keys present in the deferral JSON.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_OutputJSONFields(t *testing.T) {
	requiredKeys := []string{"status", "spec", "message"}

	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			out, _ := s.Handler(context.Background(), nil, sampleMifareArgs[name])

			var m map[string]any
			if err := json.Unmarshal([]byte(out), &m); err != nil {
				t.Fatalf("spec %q: JSON unmarshal failed: %v\n  raw: %s", name, err, out)
			}
			for _, key := range requiredKeys {
				if _, ok := m[key]; !ok {
					t.Errorf("spec %q: deferral JSON missing key %q", name, key)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_RequiredFieldsDeclared — spec.Required slice matches Schema.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_RequiredFieldsDeclared(t *testing.T) {
	cases := []struct {
		name     string
		required []string
	}{
		{"mfoc_attack", []string{"uid_hex", "known_key_hex", "known_sector", "key_type"}},
		{"mfcuk_attack", []string{"uid_hex"}},
		{"mfkey32_recover", []string{"uid_hex", "nt_hex", "nr0_hex", "ar0_hex", "nr1_hex", "ar1_hex"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := mifareStubSpec(t, tc.name)
			if len(s.Required) != len(tc.required) {
				t.Errorf("spec %q: Required len = %d, want %d; got %v",
					tc.name, len(s.Required), len(tc.required), s.Required)
			}
			reqSet := make(map[string]bool, len(s.Required))
			for _, r := range s.Required {
				reqSet[r] = true
			}
			for _, want := range tc.required {
				if !reqSet[want] {
					t.Errorf("spec %q: Required missing %q; got %v", tc.name, want, s.Required)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMifare_GroupFlipperNFC — all three stubs belong to the NFC group.
// ─────────────────────────────────────────────────────────────────────────────

func TestMifare_GroupFlipperNFC(t *testing.T) {
	for _, name := range allMifareStubNames {
		name := name
		t.Run(name, func(t *testing.T) {
			s := mifareStubSpec(t, name)
			if s.Group != tools.GroupFlipperNFC {
				t.Errorf("spec %q Group = %v, want GroupFlipperNFC", name, s.Group)
			}
		})
	}
}
