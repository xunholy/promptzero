//go:build !darwin || (darwin && cgo)

package marauder

import (
	"testing"

	"tinygo.org/x/bluetooth"
)

// transport_ble_helpers_test.go covers the BLE UUID + addr-kind
// pure helpers in transport_ble.go. Same pattern as
// internal/flipper/transport/helpers_test.go — these helpers are
// shared in shape across both transport packages, and a regression
// to either copy would silently misclassify GATT characteristics
// or scramble the `ble://` URL parser's address-form labels.

// TestReverseUUID_Marauder pins the 128-bit byte-reversal helper.
// Real Macs deliver custom UUIDs in little-endian wire order; we
// reverse host-side to canonicalise comparison. Must be its own
// inverse (involution).
func TestReverseUUID_Marauder(t *testing.T) {
	in, err := bluetooth.ParseUUID("00010203-0405-0607-0809-0a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	want, err := bluetooth.ParseUUID("0f0e0d0c-0b0a-0908-0706-050403020100")
	if err != nil {
		t.Fatalf("ParseUUID(want): %v", err)
	}
	got := reverseUUID(in)
	if got != want {
		t.Errorf("reverseUUID(%s) = %s, want %s", in.String(), got.String(), want.String())
	}

	// Involution: reverseUUID(reverseUUID(x)) == x.
	if rt := reverseUUID(got); rt != in {
		t.Errorf("reverseUUID involution failed: %s → %s → %s", in, got, rt)
	}
}

// TestUUIDsMatch_Marauder pins the equality helper that treats a
// UUID and its byte-reversed form as the same identifier — the
// host-side workaround for Linux/Darwin endianness mismatch.
func TestUUIDsMatch_Marauder(t *testing.T) {
	a, err := bluetooth.ParseUUID("12345678-9abc-def0-1234-56789abcdef0")
	if err != nil {
		t.Fatalf("ParseUUID(a): %v", err)
	}
	rev := reverseUUID(a)
	other, err := bluetooth.ParseUUID("00010203-0405-0607-0809-0a0b0c0d0e0f")
	if err != nil {
		t.Fatalf("ParseUUID(other): %v", err)
	}

	if !uuidsMatch(a, a) {
		t.Error("uuidsMatch(a, a) should be true")
	}
	if !uuidsMatch(rev, a) {
		t.Error("uuidsMatch(rev, a) should be true (endianness equivalence)")
	}
	if !uuidsMatch(a, rev) {
		t.Error("uuidsMatch(a, rev) should be true (symmetry)")
	}
	if uuidsMatch(a, other) {
		t.Error("uuidsMatch(a, other) should be false")
	}
}

// TestBleAddrKindString_Marauder pins the labels the `ble://`
// URL parser and discovery output use to describe each address
// form. Operators read these directly via `--marauder-ble-discover`
// — a regression renames the columns mid-session.
func TestBleAddrKindString_Marauder(t *testing.T) {
	if got := bleAddrKindMAC.String(); got != "MAC" {
		t.Errorf("bleAddrKindMAC.String() = %q, want MAC", got)
	}
	if got := bleAddrKindUUID.String(); got != "UUID" {
		t.Errorf("bleAddrKindUUID.String() = %q, want UUID", got)
	}
	if got := bleAddrKindName.String(); got != "name" {
		t.Errorf("bleAddrKindName.String() = %q, want name", got)
	}
	// Out-of-range value falls back to "address".
	if got := bleAddrKind(99).String(); got != "address" {
		t.Errorf("bleAddrKind(99).String() = %q, want address (fallback)", got)
	}
}

// TestParseMarauderBLEAddress pins the MAC / UUID / name
// classifier used by --marauder-ble URL handling. Each form has
// a normalisation step: MACs are upper-cased, UUIDs are
// lower-cased, names pass through verbatim (case-insensitive
// matching happens at scan time downstream).
func TestParseMarauderBLEAddress(t *testing.T) {
	t.Run("MAC_upper_canonical", func(t *testing.T) {
		kind, addr, err := parseMarauderBLEAddress("aa:bb:cc:dd:ee:ff")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if kind != bleAddrKindMAC {
			t.Errorf("kind = %v, want MAC", kind)
		}
		if addr != "AA:BB:CC:DD:EE:FF" {
			t.Errorf("addr = %q, want upper-canonical AA:BB:...", addr)
		}
	})
	t.Run("MAC_mixed_case", func(t *testing.T) {
		_, addr, err := parseMarauderBLEAddress("AA:bB:Cc:dd:EE:ff")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if addr != "AA:BB:CC:DD:EE:FF" {
			t.Errorf("addr = %q, want fully upper-canonical", addr)
		}
	})
	t.Run("MAC_with_whitespace", func(t *testing.T) {
		// Surrounding whitespace stripped before classification.
		_, addr, err := parseMarauderBLEAddress("  80:E1:26:69:6E:55  ")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if addr != "80:E1:26:69:6E:55" {
			t.Errorf("addr = %q", addr)
		}
	})
	t.Run("UUID_lower_canonical", func(t *testing.T) {
		kind, addr, err := parseMarauderBLEAddress("E127EFC1-05EC-1234-5678-9ABCDEF01234")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if kind != bleAddrKindUUID {
			t.Errorf("kind = %v, want UUID", kind)
		}
		if addr != "e127efc1-05ec-1234-5678-9abcdef01234" {
			t.Errorf("addr = %q, want lower-canonical", addr)
		}
	})
	t.Run("name_passes_through", func(t *testing.T) {
		// Anything that's not a MAC or UUID shape is treated as a
		// LocalName. Preserves casing verbatim; scan-time matching
		// is case-insensitive.
		kind, addr, err := parseMarauderBLEAddress("Unholy")
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if kind != bleAddrKindName {
			t.Errorf("kind = %v, want name", kind)
		}
		if addr != "Unholy" {
			t.Errorf("addr = %q, want verbatim", addr)
		}
	})
	t.Run("name_with_whitespace_trimmed", func(t *testing.T) {
		_, addr, _ := parseMarauderBLEAddress("  MyMarauder  ")
		if addr != "MyMarauder" {
			t.Errorf("addr = %q, want trimmed", addr)
		}
	})
	t.Run("empty_returns_error", func(t *testing.T) {
		_, _, err := parseMarauderBLEAddress("")
		if err == nil {
			t.Error("empty input: want error, got nil")
		}
	})
	t.Run("whitespace_only_returns_error", func(t *testing.T) {
		_, _, err := parseMarauderBLEAddress("   \t\n  ")
		if err == nil {
			t.Error("whitespace-only: want error, got nil")
		}
	})
}

// TestStripBLEScheme pins the URL parser: tolerates a bare
// address (no scheme), accepts the `ble://` scheme, rejects
// foreign schemes, strips trailing `?query` for forward-compat.
// Hand-rolled (not net/url.Parse) because MAC addresses
// "AA:BB:..." trip "invalid port" errors in the standard parser.
func TestStripBLEScheme(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		// Happy paths.
		{"bare MAC", "AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", false},
		{"bare UUID", "e127efc1-05ec-1234-5678-9abcdef01234", "e127efc1-05ec-1234-5678-9abcdef01234", false},
		{"bare name", "MyMarauder", "MyMarauder", false},
		{"ble scheme MAC", "ble://AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", false},
		{"ble scheme name", "ble://MyMarauder", "MyMarauder", false},
		{"trailing query stripped", "ble://AA:BB:CC:DD:EE:FF?retries=3", "AA:BB:CC:DD:EE:FF", false},
		{"empty query stripped", "ble://AA:BB:CC:DD:EE:FF?", "AA:BB:CC:DD:EE:FF", false},
		{"surrounding whitespace trimmed", "  ble://Unholy  ", "Unholy", false},

		// Error paths.
		{"empty input", "", "", true},
		{"whitespace-only", "   ", "", true},
		{"foreign scheme", "http://example.com", "", true},
		{"unknown scheme", "tcp://AA:BB:CC:DD:EE:FF", "", true},
		{"ble scheme but empty path", "ble://", "", true},
		{"ble scheme empty path with query", "ble://?retries=3", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stripBLEScheme(tc.in)
			if (err != nil) != tc.wantErr {
				t.Errorf("stripBLEScheme(%q) err = %v, wantErr=%v", tc.in, err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("stripBLEScheme(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
