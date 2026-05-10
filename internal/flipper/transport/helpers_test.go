//go:build !darwin || (darwin && cgo)

package transport

import (
	"strings"
	"testing"

	"tinygo.org/x/bluetooth"
)

// helpers_test.go covers the pure helper functions in ble.go and
// http.go that the existing dial / scan tests don't exercise:
// reverseUUID, uuidsMatch, sortDiscovered, discoveredLess,
// addrKind.String, snippet. These run without any BLE adapter or
// HTTP server, so they're cheap regression insurance.

// TestReverseUUID pins the byte-reversal helper used to align the
// host-side UUID with whatever endianness the underlying
// platform's BLE stack hands us. The 16-byte projection must
// reverse cleanly and be its own inverse.
func TestReverseUUID(t *testing.T) {
	// 8-4-4-4-12 canonical form, byte order easy to eyeball.
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

	// reverseUUID(reverseUUID(x)) == x — involution.
	roundTrip := reverseUUID(got)
	if roundTrip != in {
		t.Errorf("reverseUUID involution failed: %s → %s → %s", in, got, roundTrip)
	}
}

// TestUUIDsMatch pins the equality helper that treats a UUID and
// its byte-reversed form as the same identifier — the workaround
// for the Linux/Darwin endianness mismatch documented in ble.go.
func TestUUIDsMatch(t *testing.T) {
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

// TestSortDiscovered pins the --ble-discover output order:
// strongest RSSI first, ties broken by Name then Address. A
// regression here would scramble the output the operator scans
// to pick the right Flipper.
func TestSortDiscovered(t *testing.T) {
	devices := []DiscoveredDevice{
		{Address: "AA:01", Name: "Flipper-Echo", RSSI: -75},
		{Address: "AA:02", Name: "Flipper-Alpha", RSSI: -50},
		{Address: "AA:03", Name: "Flipper-Bravo", RSSI: -50},
		{Address: "AA:04", Name: "Flipper-Charlie", RSSI: -90},
		{Address: "AA:05", Name: "Flipper-Alpha", RSSI: -50}, // dup name, different addr
	}
	sortDiscovered(devices)

	// First: strongest RSSI (-50, three devices).
	if devices[0].RSSI != -50 {
		t.Errorf("devices[0].RSSI = %d, want -50 (strongest)", devices[0].RSSI)
	}
	// Last: weakest RSSI.
	if devices[len(devices)-1].RSSI != -90 {
		t.Errorf("devices[last].RSSI = %d, want -90 (weakest)", devices[len(devices)-1].RSSI)
	}
	// Among the three -50 devices, name "Flipper-Alpha" < "Flipper-Bravo".
	// And the two "Flipper-Alpha" entries must sort by Address.
	if devices[0].Name != "Flipper-Alpha" || devices[1].Name != "Flipper-Alpha" {
		t.Errorf("first two at RSSI=-50 should both be Flipper-Alpha, got %q / %q",
			devices[0].Name, devices[1].Name)
	}
	if devices[0].Address > devices[1].Address {
		t.Errorf("same-RSSI same-Name tie-break by Address ascending failed: %q after %q",
			devices[1].Address, devices[0].Address)
	}
	if devices[2].Name != "Flipper-Bravo" {
		t.Errorf("devices[2].Name = %q, want Flipper-Bravo (alphabetical after Alpha)", devices[2].Name)
	}
}

// TestDiscoveredLess pins the comparator the sort uses. Direct
// test rather than going through sortDiscovered so a regression
// to a specific tie-breaker is easy to localise.
func TestDiscoveredLess(t *testing.T) {
	cases := []struct {
		name string
		a, b DiscoveredDevice
		want bool
	}{
		// RSSI: higher (closer to 0) is "less" (sorts first).
		{"a-stronger-RSSI", DiscoveredDevice{RSSI: -50}, DiscoveredDevice{RSSI: -70}, true},
		{"b-stronger-RSSI", DiscoveredDevice{RSSI: -70}, DiscoveredDevice{RSSI: -50}, false},

		// Same RSSI: name ascending.
		{"same-RSSI-name-less", DiscoveredDevice{RSSI: -50, Name: "Alpha"}, DiscoveredDevice{RSSI: -50, Name: "Bravo"}, true},
		{"same-RSSI-name-greater", DiscoveredDevice{RSSI: -50, Name: "Bravo"}, DiscoveredDevice{RSSI: -50, Name: "Alpha"}, false},

		// Same RSSI + name: address ascending.
		{"same-RSSI-name-addr-less", DiscoveredDevice{RSSI: -50, Name: "X", Address: "AA:01"}, DiscoveredDevice{RSSI: -50, Name: "X", Address: "AA:02"}, true},
		{"same-RSSI-name-addr-greater", DiscoveredDevice{RSSI: -50, Name: "X", Address: "AA:02"}, DiscoveredDevice{RSSI: -50, Name: "X", Address: "AA:01"}, false},

		// Equal: not less.
		{"equal", DiscoveredDevice{RSSI: -50, Name: "X", Address: "AA:01"}, DiscoveredDevice{RSSI: -50, Name: "X", Address: "AA:01"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoveredLess(tc.a, tc.b); got != tc.want {
				t.Errorf("discoveredLess(%+v, %+v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestAddrKindString pins the human-readable labels the
// --ble-discover output uses to describe each address form. The
// operator reads these directly; a regression renames the
// columns mid-session.
func TestAddrKindString(t *testing.T) {
	if got := addrKindMAC.String(); got != "MAC" {
		t.Errorf("addrKindMAC.String() = %q, want MAC", got)
	}
	if got := addrKindUUID.String(); got != "UUID" {
		t.Errorf("addrKindUUID.String() = %q, want UUID", got)
	}
	if got := addrKindName.String(); got != "name" {
		t.Errorf("addrKindName.String() = %q, want name", got)
	}
	// Out-of-range value falls back to "address".
	if got := addrKind(99).String(); got != "address" {
		t.Errorf("addrKind(99).String() = %q, want address (fallback)", got)
	}
}

// TestSnippet pins the HTTP-error-body truncator. Short inputs
// pass through verbatim; over-length inputs are clipped to 256
// bytes with a "...[truncated]" sentinel so the operator-visible
// error stays bounded even when a misbehaving bridge returns an
// HTML error page.
func TestSnippet(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{}, ""},
		{"short", []byte("hello"), "hello"},
		{"at-limit", make([]byte, 256), strings.Repeat("\x00", 256)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := snippet(tc.in)
			if got != tc.want {
				t.Errorf("snippet(%d bytes) = %q, want %q", len(tc.in), got, tc.want)
			}
		})
	}

	// Over-limit input: clipped to 256 + truncation sentinel.
	t.Run("over-limit", func(t *testing.T) {
		in := []byte(strings.Repeat("A", 300))
		got := snippet(in)
		if !strings.HasSuffix(got, "...[truncated]") {
			t.Errorf("snippet(300 bytes) missing truncation sentinel: %q", got)
		}
		// Body before sentinel must be exactly 256 bytes.
		body := strings.TrimSuffix(got, "...[truncated]")
		if len(body) != 256 {
			t.Errorf("snippet body length = %d, want 256", len(body))
		}
	})
}
