// canbus_test.go — regression tests for canbus input validation.
//
// These tests cover the shell-injection fix (Phase 0 hotfix #3): id_filter,
// output_path, arbitration_id_hex, data_hex, and path must be validated before
// they are concatenated into a RawCLI command string.
package tools

import (
	"testing"
)

// TestValidateCanHexID covers the hex-ID validator used by canbus_sniff_start
// and canbus_inject to prevent shell-injection via the id_filter /
// arbitration_id_hex parameters.
func TestValidateCanHexID(t *testing.T) {
	valid := []string{
		"7DF", "7df", "0x7DF", "0X7DF",
		"1FFFFFFF", // max 29-bit
		"0",
		"00000001",
		"ABC",
	}
	for _, s := range valid {
		if err := validateCanHexID("test_field", s); err != nil {
			t.Errorf("validateCanHexID(%q) = %v; want nil", s, err)
		}
	}

	invalid := []string{
		"",
		"7DF; rm -rf /",   // shell injection attempt
		"../etc/passwd",   // path traversal
		"FFFFFFFFF",       // 9 hex digits (too long)
		"0xGGG",           // invalid hex
		"hello world",     // spaces
		"7DF\necho pwned", // newline injection
		"$(whoami)",       // command substitution
	}
	for _, s := range invalid {
		if err := validateCanHexID("test_field", s); err == nil {
			t.Errorf("validateCanHexID(%q) = nil; want error", s)
		}
	}
}

// TestValidateFlipperPath covers the path validator used by canbus_sniff_start
// (output_path) and canbus_replay (path) to prevent path-traversal and
// shell-injection.
func TestValidateFlipperPath(t *testing.T) {
	valid := []string{
		"/ext/canbus/sniff.log",
		"/ext/canbus/my_capture.log",
		"/ext/foo/bar/baz.bin",
		"/ext/a",
	}
	for _, s := range valid {
		if err := validateFlipperPath("test_field", s); err != nil {
			t.Errorf("validateFlipperPath(%q) = %v; want nil", s, err)
		}
	}

	invalid := []string{
		"",
		"/tmp/evil",                         // not under /ext/
		"ext/canbus/sniff.log",              // missing leading slash
		"/ext/../etc/passwd",                // path traversal (.. not allowed)
		"/ext/canbus/sniff.log; echo pwned", // shell injection
		"/ext/canbus/sniff log",             // space
		"/ext/canbus/$(id)",                 // command substitution
	}
	for _, s := range invalid {
		if err := validateFlipperPath("test_field", s); err == nil {
			t.Errorf("validateFlipperPath(%q) = nil; want error", s)
		}
	}
}

// TestValidateCanHexData covers the data_hex validator used by canbus_inject.
func TestValidateCanHexData(t *testing.T) {
	valid := []string{
		"", // empty is allowed (0-byte frame)
		"DEADBEEF",
		"deadbeef",
		"CAFEBABE1234ABCD", // 16 chars = 8 bytes (max)
		"01",
	}
	for _, s := range valid {
		if err := validateCanHexData("test_field", s); err != nil {
			t.Errorf("validateCanHexData(%q) = %v; want nil", s, err)
		}
	}

	invalid := []string{
		"CAFEBABE1234ABCDXX", // invalid hex chars
		"0x1234",             // 0x prefix not allowed for data
		"dead beef",          // space
		"$(echo evil)",       // command substitution
	}
	for _, s := range invalid {
		if err := validateCanHexData("test_field", s); err == nil {
			t.Errorf("validateCanHexData(%q) = nil; want error", s)
		}
	}
}

// TestCanbusSniffStartRejectsInjection verifies that canbusSniffStartHandler
// rejects id_filter and output_path values that look like shell injections.
func TestCanbusSniffStartRejectsInjection(t *testing.T) {
	spec, ok := Get("canbus_sniff_start")
	if !ok {
		t.Fatal("canbus_sniff_start not registered")
	}

	// id_filter injection.
	_, err := spec.Handler(t.Context(), &Deps{Flipper: nil}, map[string]any{
		"id_filter": "7DF; echo pwned",
	})
	// We expect an error (either "Flipper not connected" or "invalid hex CAN ID").
	// The key is that it does NOT pass the injected string through.
	if err == nil {
		t.Error("sniff_start: expected error for injected id_filter, got nil")
	}

	// output_path injection.
	_, err = spec.Handler(t.Context(), &Deps{Flipper: nil}, map[string]any{
		"output_path": "/tmp/evil; echo pwned",
	})
	if err == nil {
		t.Error("sniff_start: expected error for injected output_path, got nil")
	}
}

// TestCanbusInjectRejectsInjection verifies that canbusInjectHandler rejects
// arbitration_id_hex and data_hex values that look like shell injections.
func TestCanbusInjectRejectsInjection(t *testing.T) {
	spec, ok := Get("canbus_inject")
	if !ok {
		t.Fatal("canbus_inject not registered")
	}

	// arbitration_id_hex injection — must fail validation, not reach RawCLI.
	_, err := spec.Handler(t.Context(), &Deps{Flipper: nil}, map[string]any{
		"arbitration_id_hex": "7E0; echo pwned",
		"data_hex":           "DEADBEEF",
	})
	if err == nil {
		t.Error("inject: expected error for injected arbitration_id_hex, got nil")
	}

	// data_hex injection.
	_, err = spec.Handler(t.Context(), &Deps{Flipper: nil}, map[string]any{
		"arbitration_id_hex": "7E0",
		"data_hex":           "DEAD$(id)BEEF",
	})
	if err == nil {
		t.Error("inject: expected error for injected data_hex, got nil")
	}
}
