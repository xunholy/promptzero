// SPDX-License-Identifier: AGPL-3.0-or-later

package usbpd

import "testing"

// Vectors are hand-built per the USB Power Delivery spec (header + 32-bit
// little-endian Data Objects); the bit-packing is byte-checkable.

func TestControlGoodCRC(t *testing.T) {
	// Header 0x0041: msgType 1, ndo 0 (control), spec rev 2.0.
	r, err := Decode("4100")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageClass != "control" || r.MessageName != "GoodCRC" {
		t.Errorf("class/name = %q/%q", r.MessageClass, r.MessageName)
	}
	if r.SpecRevision != "2.0" {
		t.Errorf("SpecRevision = %q", r.SpecRevision)
	}
	if r.NumDataObjects != 0 {
		t.Errorf("NumDataObjects = %d, want 0", r.NumDataObjects)
	}
}

func TestSourceCapabilitiesFixedPDO(t *testing.T) {
	// Header 0x1181: Source_Capabilities (data msgType 1), 1 data object, spec
	// rev 3.0, power role Source. PDO 0x2401912C: Fixed 5V/3A, DRP + USB comms.
	r, err := Decode("81112c910124")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageClass != "data" || r.MessageName != "Source_Capabilities" {
		t.Errorf("class/name = %q/%q", r.MessageClass, r.MessageName)
	}
	if r.SpecRevision != "3.0" {
		t.Errorf("SpecRevision = %q", r.SpecRevision)
	}
	if r.PortPowerRole != "Source" {
		t.Errorf("PortPowerRole = %q", r.PortPowerRole)
	}
	if len(r.DataObjects) != 1 {
		t.Fatalf("got %d data objects, want 1", len(r.DataObjects))
	}
	o := r.DataObjects[0]
	if o.Kind != "Fixed Supply PDO" {
		t.Errorf("Kind = %q", o.Kind)
	}
	if o.VoltageV != "5.00" {
		t.Errorf("VoltageV = %q, want 5.00", o.VoltageV)
	}
	if o.MaxCurrentA != "3.00" {
		t.Errorf("MaxCurrentA = %q, want 3.00", o.MaxCurrentA)
	}
	if o.Flags != "dual-role-power,usb-comms-capable" {
		t.Errorf("Flags = %q", o.Flags)
	}
}

func TestRequestRDOSurfacedRaw(t *testing.T) {
	// Header 0x1082: Request (data msgType 2), 1 data object; the RDO is raw.
	r, err := Decode("821012345678")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageName != "Request" {
		t.Errorf("MessageName = %q", r.MessageName)
	}
	if len(r.DataObjects) != 1 {
		t.Fatalf("got %d data objects, want 1", len(r.DataObjects))
	}
	// RDO is not a PDO, so it is surfaced raw (LE 12 34 56 78 = 0x78563412).
	if r.DataObjects[0].Kind != "data object (raw)" || r.DataObjects[0].Raw != "0x78563412" {
		t.Errorf("RDO = %+v", r.DataObjects[0])
	}
}

func TestBatteryAndVariablePDO(t *testing.T) {
	// Source_Capabilities with a Variable PDO: type 10b, max 9V / min 5V / 2A.
	// value = (2<<30) | (180<<20) | (100<<10) | 200
	// 180*50mV=9V, 100*50mV=5V, 200*10mA=2A.
	// 0x80000000 | (180<<20=0xB400000) | (100<<10=0x19000) | 200(0xC8)
	// = 0x8B4190C8 → LE C8 90 41 8B.
	r, err := Decode("8111" + "c890418b")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	o := r.DataObjects[0]
	if o.Kind != "Variable Supply PDO" {
		t.Errorf("Kind = %q", o.Kind)
	}
	if o.VoltageV != "5.00-9.00" {
		t.Errorf("VoltageV = %q, want 5.00-9.00", o.VoltageV)
	}
	if o.MaxCurrentA != "2.00" {
		t.Errorf("MaxCurrentA = %q, want 2.00", o.MaxCurrentA)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "41", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
