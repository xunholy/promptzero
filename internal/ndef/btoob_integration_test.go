// SPDX-License-Identifier: AGPL-3.0-or-later

package ndef

import (
	"encoding/hex"
	"testing"

	"github.com/xunholy/promptzero/internal/btoob"
)

// TestNDEFDecodesBluetoothOOB wraps a BR/EDR Easy Pairing OOB record in an
// NDEF MIME record (application/vnd.bluetooth.ep.oob) and confirms the
// inline decode path surfaces the peer address.
func TestNDEFDecodesBluetoothOOB(t *testing.T) {
	// OOB: length=8 (LE) + BD_ADDR 06..01 (little-endian -> 01:..:06).
	oob := []byte{0x08, 0x00, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	mime := []byte("application/vnd.bluetooth.ep.oob")
	rec := []byte{0xD2, byte(len(mime)), byte(len(oob))} // MB|ME|SR, TNF=2
	rec = append(rec, mime...)
	rec = append(rec, oob...)

	msg, err := Decode(hex.EncodeToString(rec))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Records) != 1 {
		t.Fatalf("want 1 record, got %d", len(msg.Records))
	}
	dec := msg.Records[0].Decoded
	if dec["mime_type"] != "application/vnd.bluetooth.ep.oob" {
		t.Fatalf("mime_type = %v", dec["mime_type"])
	}
	res, ok := dec["bluetooth_oob"].(*btoob.Result)
	if !ok {
		t.Fatalf("expected *btoob.Result, got %T", dec["bluetooth_oob"])
	}
	if res.Variant != "br_edr" || res.DeviceAddress != "01:02:03:04:05:06" {
		t.Errorf("decoded OOB = %+v", res)
	}
}
