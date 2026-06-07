// SPDX-License-Identifier: AGPL-3.0-or-later

package att

import "testing"

func TestReadRequest(t *testing.T) {
	// 0A (Read Request) handle 0x0003 (LE 03 00).
	r, err := Decode("0a0300")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Read Request" || r.Handle != "0x0003" {
		t.Errorf("op/handle = %q/%q", r.Operation, r.Handle)
	}
}

func TestReadByGroupTypeServiceDiscovery(t *testing.T) {
	// 10 (Read By Group Type Request) start 0x0001 end 0xFFFF UUID 0x2800 (Primary Service).
	r, err := Decode("100100ffff0028")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Read By Group Type Request" {
		t.Errorf("Operation = %q", r.Operation)
	}
	if r.StartHandle != "0x0001" || r.EndHandle != "0xFFFF" {
		t.Errorf("handles = %q/%q", r.StartHandle, r.EndHandle)
	}
	if r.UUID != "0x2800 (16-bit)" {
		t.Errorf("UUID = %q", r.UUID)
	}
}

func TestWriteRequest(t *testing.T) {
	// 12 (Write Request) handle 0x0010 value DEADBEEF.
	r, err := Decode("121000deadbeef")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Write Request" || r.Handle != "0x0010" {
		t.Errorf("op/handle = %q/%q", r.Operation, r.Handle)
	}
	if r.ValueHex != "DEADBEEF" {
		t.Errorf("ValueHex = %q", r.ValueHex)
	}
}

func TestNotification(t *testing.T) {
	// 1B (Handle Value Notification) handle 0x0025 value 1234.
	r, err := Decode("1b25001234")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Handle Value Notification" || r.Handle != "0x0025" {
		t.Errorf("op/handle = %q/%q", r.Operation, r.Handle)
	}
	if r.ValueHex != "1234" {
		t.Errorf("ValueHex = %q", r.ValueHex)
	}
}

func TestErrorResponse(t *testing.T) {
	// 01 (Error Response) req-opcode 0A (Read Request) handle 0x0003 error 0A.
	r, err := Decode("010a03000a")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Error Response" {
		t.Errorf("Operation = %q", r.Operation)
	}
	if r.RequestOpcode != "0x0A (Read Request)" {
		t.Errorf("RequestOpcode = %q", r.RequestOpcode)
	}
	if r.Handle != "0x0003" {
		t.Errorf("Handle = %q", r.Handle)
	}
	if r.ErrorCode != "0x0A (Attribute Not Found)" {
		t.Errorf("ErrorCode = %q", r.ErrorCode)
	}
}

func TestExchangeMTU(t *testing.T) {
	// 02 (Exchange MTU Request) MTU 0x0017 = 23.
	r, err := Decode("021700")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MTU == nil || *r.MTU != 23 {
		t.Errorf("MTU = %v, want 23", r.MTU)
	}
}

func TestRead128BitUUID(t *testing.T) {
	// 08 (Read By Type Request) start end + 128-bit UUID, little-endian on the
	// wire. UUID 0000180D-0000-1000-8000-00805F9B34FB (Heart Rate service).
	r, err := Decode("080100ffff" + "fb349b5f80000080001000000d180000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Read By Type Request" {
		t.Errorf("Operation = %q", r.Operation)
	}
	if r.UUID != "0000180D-0000-1000-8000-00805F9B34FB (128-bit)" {
		t.Errorf("UUID = %q", r.UUID)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
