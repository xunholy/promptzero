// SPDX-License-Identifier: AGPL-3.0-or-later

package ndef

import (
	"encoding/hex"
	"testing"
)

// rec builds one NDEF record (short-record form, payload < 256 bytes).
func rec(mb, me bool, tnf byte, typ, id string, payload []byte) []byte {
	hdr := (tnf & 0x07) | 0x10 // SR=1
	if mb {
		hdr |= 0x80
	}
	if me {
		hdr |= 0x40
	}
	if id != "" {
		hdr |= 0x08 // IL=1
	}
	out := []byte{hdr, byte(len(typ)), byte(len(payload))}
	if id != "" {
		out = append(out, byte(len(id)))
	}
	out = append(out, typ...)
	out = append(out, id...)
	out = append(out, payload...)
	return out
}

// TestHandoverSelectFullTree builds a realistic tap-to-pair tag: a
// Handover Select record whose nested message holds an Alternative
// Carrier referencing (by ID "b") a Bluetooth OOB carrier-config record
// in the outer message — and confirms the whole tree decodes.
func TestHandoverSelectFullTree(t *testing.T) {
	// ac payload: CPS=active(0x01), CDR len 1 = "b", 0 auxiliary refs.
	acPayload := []byte{0x01, 0x01, 'b', 0x00}
	acRecord := rec(true, true, 0x01, "ac", "", acPayload)

	// Hs payload: version 1.5 (0x15) + nested message (the ac record).
	hsPayload := append([]byte{0x15}, acRecord...)
	hsRecord := rec(true, false, 0x01, "Hs", "", hsPayload)

	// Carrier-config record: BR/EDR OOB, ID "b", BD_ADDR 01:..:06.
	oob := []byte{0x08, 0x00, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	carrier := rec(false, true, 0x02, "application/vnd.bluetooth.ep.oob", "b", oob)

	msg, err := Decode(hex.EncodeToString(append(hsRecord, carrier...)))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Records) != 2 {
		t.Fatalf("want 2 outer records, got %d", len(msg.Records))
	}

	hs := msg.Records[0]
	if hs.Type != "Hs" {
		t.Fatalf("record 0 type = %q", hs.Type)
	}
	if hs.Decoded["handover_type"] != "Select" {
		t.Errorf("handover_type = %v", hs.Decoded["handover_type"])
	}
	if hs.Decoded["version"] != "1.5" {
		t.Errorf("version = %v", hs.Decoded["version"])
	}
	nested, ok := hs.Decoded["nested"].(Message)
	if !ok {
		t.Fatalf("nested type = %T", hs.Decoded["nested"])
	}
	if len(nested.Records) != 1 || nested.Records[0].Type != "ac" {
		t.Fatalf("nested records = %+v", nested.Records)
	}
	ac := nested.Records[0].Decoded
	if ac["carrier_power_state"] != "active" {
		t.Errorf("CPS = %v", ac["carrier_power_state"])
	}
	if ac["carrier_data_reference"] != "b" {
		t.Errorf("CDR = %v", ac["carrier_data_reference"])
	}

	// The referenced carrier record is decoded in place.
	carrierRec := msg.Records[1]
	if carrierRec.ID != "b" {
		t.Errorf("carrier ID = %q", carrierRec.ID)
	}
	if carrierRec.Decoded["bluetooth_oob"] == nil {
		t.Errorf("carrier OOB not decoded: %+v", carrierRec.Decoded)
	}
}

func TestAlternativeCarrierWithAuxRefs(t *testing.T) {
	// CPS=activating(0x02), CDR="0", 2 aux refs "x","yz".
	p := []byte{0x02, 0x01, '0', 0x02, 0x01, 'x', 0x02, 'y', 'z'}
	out := decodeAlternativeCarrier(p)
	if out["carrier_power_state"] != "activating" {
		t.Errorf("CPS = %v", out["carrier_power_state"])
	}
	adrs, ok := out["auxiliary_data_references"].([]string)
	if !ok || len(adrs) != 2 || adrs[0] != "x" || adrs[1] != "yz" {
		t.Errorf("aux refs = %v", out["auxiliary_data_references"])
	}
}

func TestCollisionResolution(t *testing.T) {
	out := decodeCollisionResolution([]byte{0x12, 0x34})
	if out["random_number"] != 0x1234 {
		t.Errorf("random = %v", out["random_number"])
	}
	if e := decodeCollisionResolution([]byte{0x01}); e["error"] == nil {
		t.Error("1-byte cr should error")
	}
}

func TestHandoverError(t *testing.T) {
	out := decodeHandoverError([]byte{0x01, 0x05})
	if out["error_reason"] != "temporary memory constraints" {
		t.Errorf("reason = %v", out["error_reason"])
	}
	if out["error_data_hex"] != "05" {
		t.Errorf("data = %v", out["error_data_hex"])
	}
	if r := decodeHandoverError([]byte{0x7F}); r["error_reason"] != "reserved (0x7F)" {
		t.Errorf("reserved reason = %v", r["error_reason"])
	}
}

// TestNestedDepthGuard builds a Smart Poster chain deeper than the
// recursion cap and confirms it decodes without panicking and surfaces
// the depth-limit warning at the bottom rather than exhausting the stack.
func TestNestedDepthGuard(t *testing.T) {
	payload := rec(true, true, 0x01, "T", "", []byte{0x02, 'e', 'n', 'h', 'i'})
	for i := 0; i < maxNestDepth+3; i++ {
		payload = rec(true, true, 0x01, "Sp", "", payload)
	}
	msg, err := Decode(hex.EncodeToString(payload))
	if err != nil {
		t.Fatal(err)
	}
	// Descend the nested chain; the cap must trip before we run out.
	cur := msg
	hitLimit := false
	for depth := 0; depth < maxNestDepth+5; depth++ {
		dec := cur.Records[0].Decoded
		if w, ok := dec["warning"].(string); ok && w != "" {
			hitLimit = true
			break
		}
		nested, ok := dec["nested"].(Message)
		if !ok {
			break
		}
		cur = nested
	}
	if !hitLimit {
		t.Error("depth guard never tripped on an over-deep nested chain")
	}
}

func TestHandoverEdgeCases(t *testing.T) {
	// Empty handover payload.
	if decodeHandoverRecord("Select", nil, 0)["error"] == nil {
		t.Error("empty Hs should error")
	}
	// Truncated ac (CDR length runs past payload).
	if decodeAlternativeCarrier([]byte{0x01, 0x05, 'a'})["error"] == nil {
		t.Error("truncated ac should report error")
	}
	// Version-only Hs (no nested message) is valid.
	out := decodeHandoverRecord("Select", []byte{0x12}, 0)
	if out["version"] != "1.2" || out["nested"] != nil {
		t.Errorf("version-only Hs = %+v", out)
	}
}
