package zwave

import (
	"strings"
	"testing"
)

// TestDecodeBasicSetSinglecast pins a canonical Z-Wave
// singlecast BASIC SET frame — the classic "turn on light"
// command Yale + GE smart switches accept.
func TestDecodeBasicSetSinglecast(t *testing.T) {
	// HomeID = 0xC0FFEE01, SourceNode = 0x01 (controller),
	// Frame Control byte 0 = 0x21 (Singlecast + AckReq);
	// Frame Control byte 1 = 0x35 (sequence = 3 in high
	// nibble; low nibble = 5). Length = 13 (header 9 +
	// payload 3 + checksum 1), DestNode = 0x05.
	// Payload: 20 01 FF — BASIC (0x20) + SET (0x01) +
	// value 0xFF (turn on). Checksum 0xAA (arbitrary).
	in := "C0FFEE01 01 21 35 0D 05 20 01 FF AA"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.HomeIDHex != "0xC0FFEE01" {
		t.Errorf("homeID: got %q want 0xC0FFEE01", r.HomeIDHex)
	}
	if r.SourceNodeID != 1 {
		t.Errorf("sourceNode: got %d want 1", r.SourceNodeID)
	}
	if r.HeaderTypeName != "Singlecast" {
		t.Errorf("headerType: got %q want Singlecast", r.HeaderTypeName)
	}
	if !r.AckRequested {
		t.Errorf("AckRequested: should be true")
	}
	if r.SequenceNumber != 3 {
		// byte 6 = 0x35; sequence is bits 4-7 of byte 6 = 0x3.
		t.Errorf("sequence: got %d want 3", r.SequenceNumber)
	}
	if r.DestinationNodeID != 5 {
		t.Errorf("destNode: got %d want 5", r.DestinationNodeID)
	}
	if r.CommandClassName != "BASIC" {
		t.Errorf("commandClass: got %q want BASIC", r.CommandClassName)
	}
	if r.Command != 0x01 {
		t.Errorf("command: got 0x%X want 0x01", r.Command)
	}
	if r.ParametersHex != "FF" {
		t.Errorf("parameters: got %q want FF", r.ParametersHex)
	}
	if r.ChecksumHex != "0xAA" {
		t.Errorf("checksum: got %q want 0xAA", r.ChecksumHex)
	}
}

// TestDecodeAckFrame pins a Z-Wave Ack frame (Type 3, no payload).
func TestDecodeAckFrame(t *testing.T) {
	// HeaderType = 3, no payload.
	// Length = 10 (header 9 + checksum 1).
	in := "DEADBEEF 05 03 00 0A 01 BB"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.HeaderTypeName != "Ack" {
		t.Errorf("headerType: got %q want Ack", r.HeaderTypeName)
	}
	if r.CommandClass != 0 {
		t.Errorf("commandClass: should be empty for Ack")
	}
}

// TestDecodeDoorLockOperation pins a DOOR_LOCK command — the
// canonical Yale Z-Wave lock target.
func TestDecodeDoorLockOperation(t *testing.T) {
	// Payload: 62 01 FF — DOOR_LOCK (0x62) +
	// DOOR_LOCK_OPERATION_SET (0x01) + mode 0xFF (locked).
	// Length = 13 (header 9 + payload 3 + checksum 1).
	in := "11223344 01 41 00 0D 02 62 01 FF EE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandClassName != "DOOR_LOCK" {
		t.Errorf("commandClass: got %q want DOOR_LOCK", r.CommandClassName)
	}
}

// TestDecodeWakeUp pins a WAKE_UP command — the battery-drain
// DoS attack target.
func TestDecodeWakeUp(t *testing.T) {
	// Payload: 84 07 00 — WAKE_UP (0x84) +
	// WAKE_UP_NOTIFICATION (0x07) + 1 byte parameter (0x00).
	// Length = 13 (header 9 + payload 3 + checksum 1).
	in := "AABBCCDD 09 41 00 0D 01 84 07 00 33"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandClassName != "WAKE_UP" {
		t.Errorf("commandClass: got %q want WAKE_UP", r.CommandClassName)
	}
}

// TestDecodeSecurityS0 pins a SECURITY (S0) container.
func TestDecodeSecurityS0(t *testing.T) {
	// Payload: 98 81 .. — SECURITY (0x98) +
	// SECURITY_MESSAGE_ENCAPSULATION (0x81) + opaque bytes.
	in := "DEADBEEF 02 41 10 10 03 98 81 AA BB CC DD EE FF 00 CC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandClassName != "SECURITY" {
		t.Errorf("commandClass: got %q want SECURITY", r.CommandClassName)
	}
	if r.Command != 0x81 {
		t.Errorf("command: got 0x%X want 0x81", r.Command)
	}
}

// TestDecodeSecurityS2 pins a SECURITY_2 (S2) container.
func TestDecodeSecurityS2(t *testing.T) {
	in := "11223344 02 41 10 10 03 9F 03 AA BB CC DD EE FF 00 CC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandClassName != "SECURITY_2" {
		t.Errorf("commandClass: got %q want SECURITY_2", r.CommandClassName)
	}
}

// TestDecodeBroadcast pins a broadcast frame (DestNode = 0xFF).
func TestDecodeBroadcast(t *testing.T) {
	// Length = 13 (header 9 + payload 3 + checksum 1).
	in := "DEADBEEF 01 41 00 0D FF 25 01 00 CC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.DestinationNodeID != 0xFF {
		t.Errorf("destNode: got 0x%X want 0xFF", r.DestinationNodeID)
	}
}

// TestDecodeFrameControlFlags asserts every flag bit decodes.
func TestDecodeFrameControlFlags(t *testing.T) {
	// Frame Control byte 0 = 0xFF (Routed + AckReq + LowPower
	// + SpeedModified + HeaderType nibble = 0xF — uncatalogued
	// in our 1-4 name table but the flag bits are all
	// asserted). Frame Control byte 1 = 0x01 (Beam Control).
	// Length = 13 (header 9 + payload 3 + checksum 1).
	in := "DEADBEEF 01 FF 01 0D 02 20 01 FF CC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.Routed || !r.AckRequested || !r.LowPower || !r.SpeedModified {
		t.Errorf("flags: Routed=%v AckReq=%v LowPower=%v SpeedModified=%v",
			r.Routed, r.AckRequested, r.LowPower, r.SpeedModified)
	}
	if !r.BeamControl {
		t.Errorf("BeamControl: should be true")
	}
}

// TestHeaderTypeNameTable spot-checks each catalogued type.
func TestHeaderTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "Singlecast", 2: "Multicast", 3: "Ack", 4: "Explore",
	}
	for k, v := range cases {
		if got := headerTypeName(k); got != v {
			t.Errorf("headerTypeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(headerTypeName(7), "uncatalogued") {
		t.Errorf("headerTypeName(7) should mark uncatalogued")
	}
}

// TestCommandClassNameTable spot-checks high-runners.
func TestCommandClassNameTable(t *testing.T) {
	cases := map[int]string{
		0x20: "BASIC", 0x25: "SWITCH_BINARY",
		0x26: "SWITCH_MULTILEVEL", 0x30: "SENSOR_BINARY",
		0x40: "THERMOSTAT_MODE", 0x62: "DOOR_LOCK",
		0x70: "CONFIGURATION", 0x71: "ALARM",
		0x72: "MANUFACTURER_SPECIFIC", 0x80: "BATTERY",
		0x84: "WAKE_UP", 0x86: "VERSION",
		0x98: "SECURITY", 0x9F: "SECURITY_2",
	}
	for k, v := range cases {
		if got := commandClassName(k); got != v {
			t.Errorf("commandClassName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(commandClassName(0xEE), "uncatalogued") {
		t.Errorf("commandClassName(0xEE) should mark uncatalogued")
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("DEADBEEF 01 41 00"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 9)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
