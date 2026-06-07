// SPDX-License-Identifier: AGPL-3.0-or-later

package usbdesc

import (
	"strings"
	"testing"
)

// Vectors are hand-built per the USB specification descriptor layouts (and
// match lsusb output); the structures are byte-checkable.

func TestDeviceDescriptor(t *testing.T) {
	// bLength 18, type 1, bcdUSB 2.00, class 0, maxPkt0 64, VID 046A, PID 889F,
	// bcdDevice 1.00, 1 configuration.
	r, err := Decode("12010002000000406a049f88000101020301")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Descriptors) != 1 {
		t.Fatalf("got %d descriptors, want 1", len(r.Descriptors))
	}
	d := r.Descriptors[0]
	if d.TypeName != "Device" {
		t.Errorf("TypeName = %q", d.TypeName)
	}
	if d.USBVersion != "2.00" {
		t.Errorf("USBVersion = %q", d.USBVersion)
	}
	if d.VendorID != "0x046A" {
		t.Errorf("VendorID = %q, want 0x046A", d.VendorID)
	}
	if d.ProductID != "0x889F" {
		t.Errorf("ProductID = %q, want 0x889F", d.ProductID)
	}
	if d.MaxPacketSize0 == nil || *d.MaxPacketSize0 != 64 {
		t.Errorf("MaxPacketSize0 = %v", d.MaxPacketSize0)
	}
	if d.NumConfigurations == nil || *d.NumConfigurations != 1 {
		t.Errorf("NumConfigurations = %v", d.NumConfigurations)
	}
}

func TestConfigBlobHIDKeyboardFlagsBadUSB(t *testing.T) {
	// Config (25 bytes total) + HID boot-keyboard interface + interrupt-IN endpoint.
	const v = "09021900010100a032" + "090400000103010100" + "0705810308000a"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Descriptors) != 3 {
		t.Fatalf("got %d descriptors, want 3 (config, interface, endpoint)", len(r.Descriptors))
	}
	cfg := r.Descriptors[0]
	if cfg.TypeName != "Configuration" || cfg.TotalLength == nil || *cfg.TotalLength != 25 {
		t.Errorf("config = %+v", cfg)
	}
	if cfg.Attributes != "bus-powered, remote-wakeup" {
		t.Errorf("config Attributes = %q", cfg.Attributes)
	}
	if cfg.MaxPowerMA == nil || *cfg.MaxPowerMA != 100 {
		t.Errorf("MaxPowerMA = %v, want 100", cfg.MaxPowerMA)
	}
	iface := r.Descriptors[1]
	if !strings.HasPrefix(iface.InterfaceClass, "HID") || !strings.Contains(iface.InterfaceClass, "boot keyboard") {
		t.Errorf("InterfaceClass = %q", iface.InterfaceClass)
	}
	ep := r.Descriptors[2]
	if ep.EndpointType != "Interrupt" {
		t.Errorf("EndpointType = %q", ep.EndpointType)
	}
	if !strings.Contains(ep.EndpointAddress, "IN, endpoint 1") {
		t.Errorf("EndpointAddress = %q", ep.EndpointAddress)
	}
	// The BadUSB signature note must be present.
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "BadUSB") {
			found = true
		}
	}
	if !found {
		t.Error("expected a BadUSB note for the HID boot-keyboard interface")
	}
}

func TestCompositeDeviceFlag(t *testing.T) {
	// Config with 2 interfaces: HID keyboard + Mass Storage → composite note.
	const v = "09022200020100a032" +
		"090400000103010100" + "0705810308000a" +
		"090401000008065000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	foundComposite := false
	for _, n := range r.Notes {
		if strings.Contains(n, "composite") {
			foundComposite = true
		}
	}
	if !foundComposite {
		t.Errorf("expected a composite-device note; notes=%v", r.Notes)
	}
}

func TestStringDescriptor(t *testing.T) {
	// String descriptor: bLength=06, type=03, UTF-16LE "Hi" = 4800 6900.
	r, err := Decode("060348006900")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Descriptors[0].String != "Hi" {
		t.Errorf("String = %q, want Hi", r.Descriptors[0].String)
	}
}

func TestMalformedLengthStops(t *testing.T) {
	// A descriptor claiming bLength 0xFF (overruns) — stops, surfaced raw.
	r, err := Decode("ff01dead")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Descriptors[0].PayloadHex == "" {
		t.Error("expected the overrunning descriptor surfaced raw")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "12", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
