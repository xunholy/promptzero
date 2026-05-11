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
