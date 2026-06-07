// SPDX-License-Identifier: AGPL-3.0-or-later

package bleadv

import "testing"

func TestFlagsAndIBeacon(t *testing.T) {
	// 02 01 06                      Flags: LE General Discoverable + BR/EDR Not Supported
	// 1A FF 4C00 0215 <uuid> 0000 0000 C5   Apple iBeacon, UUID E2C56DB5-... major 0 minor 0 power -59
	r, err := Decode("0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000000000c5")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Structures) != 2 {
		t.Fatalf("got %d structures, want 2", len(r.Structures))
	}
	f := r.Structures[0]
	if f.ADType != 0x01 || len(f.Flags) != 2 {
		t.Errorf("flags = %+v", f)
	}
	if f.Flags[0] != "LE General Discoverable Mode" || f.Flags[1] != "BR/EDR Not Supported" {
		t.Errorf("flags content = %v", f.Flags)
	}
	m := r.Structures[1]
	if m.Manufacturer == nil || m.Manufacturer.CompanyName != "Apple, Inc." {
		t.Fatalf("manufacturer = %+v", m.Manufacturer)
	}
	if m.IBeacon == nil {
		t.Fatal("iBeacon not decoded")
	}
	if m.IBeacon.UUID != "E2C56DB5-DFFB-48D2-B060-D0F5A71096E0" {
		t.Errorf("iBeacon UUID = %q", m.IBeacon.UUID)
	}
	if m.IBeacon.Major != 0 || m.IBeacon.Minor != 0 || m.IBeacon.MeasuredPower != -59 {
		t.Errorf("iBeacon maj/min/pwr = %d/%d/%d", m.IBeacon.Major, m.IBeacon.Minor, m.IBeacon.MeasuredPower)
	}
}

func TestEddystoneURL(t *testing.T) {
	// 02 01 06                       Flags
	// 03 03 AAFE                     Complete 16-bit Service UUID list = 0xFEAA
	// 0E 16 AAFE 10 EB 01 "example" 07   Service Data: Eddystone URL https://www.example.com
	r, err := Decode("0201060303aafe0e16aafe10eb016578616d706c6507")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Structures) != 3 {
		t.Fatalf("got %d structures, want 3", len(r.Structures))
	}
	if uuids := r.Structures[1].ServiceUUIDs; len(uuids) != 1 || uuids[0] != "0xFEAA" {
		t.Errorf("service uuids = %v", r.Structures[1].ServiceUUIDs)
	}
	e := r.Structures[2].Eddystone
	if e == nil || e.FrameType != "URL" {
		t.Fatalf("eddystone = %+v", e)
	}
	if e.URL != "https://www.example.com" {
		t.Errorf("URL = %q", e.URL)
	}
	if e.TxPower0mDBm == nil || *e.TxPower0mDBm != -21 {
		t.Errorf("tx power = %v", e.TxPower0mDBm)
	}
}

func TestEddystoneTLM(t *testing.T) {
	// 11 16 AAFE 20 00 0CE4 1900 000003E8 00008CA0
	//   battery 3300 mV, temp 25.0 C, adv count 1000, uptime 3600.0 s
	r, err := Decode("0201061116aafe2000" + "0ce4" + "1900" + "000003e8" + "00008ca0")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e := r.Structures[1].Eddystone
	if e == nil || e.FrameType != "TLM" {
		t.Fatalf("eddystone = %+v", e)
	}
	if e.BatteryMV == nil || *e.BatteryMV != 3300 {
		t.Errorf("battery = %v", e.BatteryMV)
	}
	if e.TemperatureC == nil || *e.TemperatureC != 25.0 {
		t.Errorf("temp = %v", e.TemperatureC)
	}
	if e.AdvCount == nil || *e.AdvCount != 1000 {
		t.Errorf("adv count = %v", e.AdvCount)
	}
	if e.UptimeSeconds == nil || *e.UptimeSeconds != 3600.0 {
		t.Errorf("uptime = %v", e.UptimeSeconds)
	}
}

func TestNameTxPowerAppearance(t *testing.T) {
	// 02 01 06 | 02 0A EB (TX Power -21) | 03 09 "Hi" | 03 19 4000 (Appearance 0x0040 = Phone)
	r, err := Decode("020106020aeb0309486903194000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Structures) != 4 {
		t.Fatalf("got %d structures, want 4", len(r.Structures))
	}
	if r.Structures[1].TxPowerDBm == nil || *r.Structures[1].TxPowerDBm != -21 {
		t.Errorf("tx power = %v", r.Structures[1].TxPowerDBm)
	}
	if r.Structures[2].LocalName != "Hi" {
		t.Errorf("local name = %q", r.Structures[2].LocalName)
	}
	if r.Structures[3].Appearance != "0x0040 (Phone)" {
		t.Errorf("appearance = %q", r.Structures[3].Appearance)
	}
}

func TestLERoleAnd128BitUUID(t *testing.T) {
	// 02 1C 02 (LE Role) | 11 07 <16-byte 128-bit service UUID, little-endian on the wire>
	// UUID 0000180D-0000-1000-8000-00805F9B34FB (Heart Rate service).
	r, err := Decode("021c02" + "1107" + "fb349b5f80000080001000000d180000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Structures[0].LERole != "Peripheral and Central; Peripheral preferred for connection" {
		t.Errorf("le role = %q", r.Structures[0].LERole)
	}
	u := r.Structures[1].ServiceUUIDs
	if len(u) != 1 || u[0] != "0000180D-0000-1000-8000-00805F9B34FB" {
		t.Errorf("128-bit uuid = %v", u)
	}
}

func TestUnknownCompanyRaw(t *testing.T) {
	// Manufacturer data, company 0x1234 (unknown), body DEADBEEF — surfaced raw, not guessed.
	r, err := Decode("020106" + "07ff3412deadbeef")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// last structure is the manufacturer one
	m := r.Structures[len(r.Structures)-1].Manufacturer
	if m == nil || m.CompanyID != "0x1234" || m.CompanyName != "unknown company (not guessed)" {
		t.Fatalf("manufacturer = %+v", m)
	}
	if m.DataHex != "DEADBEEF" {
		t.Errorf("data = %q", m.DataHex)
	}
}

func TestTruncatedStops(t *testing.T) {
	// A length byte claiming more than is present should stop with a note, not panic.
	r, err := Decode("020106" + "ff16aabb")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Structures) != 1 {
		t.Errorf("got %d structures, want 1 (truncated tail dropped)", len(r.Structures))
	}
	found := false
	for _, n := range r.Notes {
		if len(n) >= 9 && n[:9] == "truncated" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a truncation note, got %v", r.Notes)
	}
}

func TestZeroPaddingTerminates(t *testing.T) {
	// Advertising PDUs are zero-padded to 31 bytes; a 0x00 length terminates.
	r, err := Decode("020106" + "0000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Structures) != 1 {
		t.Errorf("got %d structures, want 1", len(r.Structures))
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "00"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
