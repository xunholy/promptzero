// SPDX-License-Identifier: AGPL-3.0-or-later

package applecontinuity

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestEncodeIBeacon_FixedBytes hand-verifies the exact iBeacon TLV layout:
// type 0x02, length 0x15, 16-byte UUID, big-endian major/minor, signed tx.
func TestEncodeIBeacon_FixedBytes(t *testing.T) {
	b, err := Encode(EncodeRequest{
		Kind:  "ibeacon",
		UUID:  "E2C56DB5-DFFB-48D2-B060-D0F5A71096E0",
		Major: 0x0001, Minor: 0x0002, TXPower: -59,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// 02 15 | UUID(16) | 0001 | 0002 | C5 (=-59 as int8)
	want := "0215E2C56DB5DFFB48D2B060D0F5A71096E000010002C5"
	if got := strings.ToUpper(hex.EncodeToString(b)); got != want {
		t.Errorf("iBeacon TLV = %s, want %s", got, want)
	}
}

// TestEncodeIBeacon_RoundTrip confirms Encode → Decode recovers every field.
func TestEncodeIBeacon_RoundTrip(t *testing.T) {
	b, err := Encode(EncodeRequest{
		Kind:  "ibeacon",
		UUID:  "0123456789ABCDEF0123456789ABCDEF",
		Major: 4242, Minor: 13, TXPower: -72,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	res, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.MessageCnt != 1 || res.Messages[0].IBeacon == nil {
		t.Fatalf("decoded %d messages, want 1 iBeacon: %+v", res.MessageCnt, res.Messages)
	}
	ib := res.Messages[0].IBeacon
	if ib.UUID != "01234567-89AB-CDEF-0123-456789ABCDEF" {
		t.Errorf("uuid round-trips to %s", ib.UUID)
	}
	if ib.Major != 4242 || ib.Minor != 13 {
		t.Errorf("major/minor = %d/%d, want 4242/13", ib.Major, ib.Minor)
	}
	if ib.TXPower != -72 {
		t.Errorf("tx power = %d, want -72", ib.TXPower)
	}
}

// TestEncodeIBeacon_Wrap confirms the manufacturer and ad framings decode
// via the outer-envelope strippers, reporting the matching outer_format.
func TestEncodeIBeacon_Wrap(t *testing.T) {
	cases := map[string]string{
		"manufacturer": "manufacturer_data",
		"ad":           "ad_record",
	}
	for wrap, wantFmt := range cases {
		b, err := Encode(EncodeRequest{
			Kind: "ibeacon", UUID: "0123456789ABCDEF0123456789ABCDEF",
			Major: 1, Minor: 1, TXPower: -50, Wrap: wrap,
		})
		if err != nil {
			t.Fatalf("Encode(wrap=%s): %v", wrap, err)
		}
		res, err := Decode(hex.EncodeToString(b))
		if err != nil {
			t.Fatalf("Decode(wrap=%s): %v", wrap, err)
		}
		if res.OuterFormat != wantFmt {
			t.Errorf("wrap=%s decoded outer_format=%s, want %s", wrap, res.OuterFormat, wantFmt)
		}
		if res.MessageCnt != 1 || res.Messages[0].IBeacon == nil {
			t.Errorf("wrap=%s did not round-trip to one iBeacon", wrap)
		}
	}
}

func TestEncodeIBeacon_ToleratesUUIDForms(t *testing.T) {
	dashed, err := Encode(EncodeRequest{Kind: "ibeacon", UUID: "E2C56DB5-DFFB-48D2-B060-D0F5A71096E0", Major: 1, Minor: 2, TXPower: -59})
	if err != nil {
		t.Fatalf("Encode dashed: %v", err)
	}
	plain, err := Encode(EncodeRequest{Kind: "ibeacon", UUID: "e2c56db5dffb48d2b060d0f5a71096e0", Major: 1, Minor: 2, TXPower: -59})
	if err != nil {
		t.Fatalf("Encode plain: %v", err)
	}
	if hex.EncodeToString(dashed) != hex.EncodeToString(plain) {
		t.Errorf("UUID form handling diverged:\n %X\n %X", dashed, plain)
	}
}

func TestEncode_Errors(t *testing.T) {
	bad := []EncodeRequest{
		{Kind: "bogus", UUID: "0123456789ABCDEF0123456789ABCDEF"},
		{Kind: "ibeacon", UUID: "0011"},                                           // short UUID
		{Kind: "ibeacon", UUID: "nothex-nothex-nothex-nothex-nothexnothexnothex"}, // non-hex
		{Kind: "ibeacon"}, // missing UUID
		{Kind: "ibeacon", UUID: "0123456789ABCDEF0123456789ABCDEF", Wrap: "bogus"}, // bad wrap
	}
	for i, r := range bad {
		if _, err := Encode(r); err == nil {
			t.Errorf("case %d (%+v): expected error, got nil", i, r)
		}
	}
}
