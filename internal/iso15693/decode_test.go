// SPDX-License-Identifier: AGPL-3.0-or-later

package iso15693

import "testing"

func TestDecodeUID_NXP(t *testing.T) {
	// E0 04 … — 0xE0 prefix (anchor), 0x04 = NXP per the shared ISO 7816-6 table.
	u, err := DecodeUID("E004010050B2A123")
	if err != nil {
		t.Fatal(err)
	}
	if !u.PrefixValid {
		t.Error("0xE0 prefix should be valid")
	}
	if u.ManufacturerCode != "04" || u.Manufacturer != "NXP Semiconductors" {
		t.Errorf("manufacturer: %q (%q)", u.ManufacturerCode, u.Manufacturer)
	}
	if u.Serial != "010050B2A123" {
		t.Errorf("serial: %q", u.Serial)
	}
}

func TestDecodeUID_STMicro(t *testing.T) {
	// E0 02 … = STMicroelectronics (ST LRI series).
	u, err := DecodeUID("E0:02:00:00:12:34:56:78")
	if err != nil {
		t.Fatal(err)
	}
	if u.Manufacturer != "STMicroelectronics" {
		t.Errorf("manufacturer: %q", u.Manufacturer)
	}
}

func TestDecodeUID_NonStandard(t *testing.T) {
	// Not an ISO 15693 UID (no 0xE0 prefix) — flagged, not mis-decoded.
	u, err := DecodeUID("0400010050B2A123")
	if err != nil {
		t.Fatal(err)
	}
	if u.PrefixValid || len(u.Notes) == 0 {
		t.Errorf("non-0xE0 UID should be flagged: %+v", u)
	}
}

func TestDecodeUID_UnknownManufacturer(t *testing.T) {
	u, err := DecodeUID("E0FF00000000ABCD")
	if err != nil {
		t.Fatal(err)
	}
	if u.Manufacturer != "" || len(u.Notes) == 0 {
		t.Errorf("unknown mfr should be raw + noted, not guessed: %+v", u)
	}
}

func TestDecodeUID_Errors(t *testing.T) {
	if _, err := DecodeUID("E004"); err == nil {
		t.Error("short UID should error")
	}
	if _, err := DecodeUID("nothex!!"); err == nil {
		t.Error("non-hex should error")
	}
}

func TestDecodeAFI(t *testing.T) {
	cases := map[byte]string{
		0x00: "all families",
		0x10: "transport",
		0x50: "medical",
		0xE0: "proprietary / RFU",
	}
	for b, want := range cases {
		if got := DecodeAFI(b); got.Family != want {
			t.Errorf("AFI %02X family = %q, want %q", b, got.Family, want)
		}
	}
}
