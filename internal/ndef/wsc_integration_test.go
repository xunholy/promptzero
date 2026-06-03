// SPDX-License-Identifier: AGPL-3.0-or-later

package ndef

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/xunholy/promptzero/internal/wsc"
)

// buildWSCNDEF wraps a minimal WSC credential (SSID + WPA2-PSK + AES +
// network key) in an NDEF MIME record (TNF=2, application/vnd.wfa.wsc).
func buildWSCNDEF(t *testing.T) string {
	t.Helper()
	tlv := func(typ uint16, val []byte) []byte {
		b := make([]byte, 4+len(val))
		binary.BigEndian.PutUint16(b[0:], typ)
		binary.BigEndian.PutUint16(b[2:], uint16(len(val)))
		copy(b[4:], val)
		return b
	}
	cred := tlv(0x1045, []byte("CafeWiFi"))                       // SSID
	cred = append(cred, tlv(0x1003, []byte{0x00, 0x20})...)       // auth WPA2-PSK
	cred = append(cred, tlv(0x100f, []byte{0x00, 0x08})...)       // encr AES
	cred = append(cred, tlv(0x1027, []byte("hunter2hunter2"))...) // network key
	blob := tlv(0x100e, cred)                                     // Credential

	mime := []byte("application/vnd.wfa.wsc")
	rec := []byte{0xD2, byte(len(mime)), byte(len(blob))} // MB|ME|SR, TNF=2
	rec = append(rec, mime...)
	rec = append(rec, blob...)
	return hex.EncodeToString(rec)
}

func TestNDEFDecodesWSCCredential(t *testing.T) {
	msg, err := Decode(buildWSCNDEF(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Records) != 1 {
		t.Fatalf("want 1 record, got %d", len(msg.Records))
	}
	dec := msg.Records[0].Decoded
	if dec["mime_type"] != "application/vnd.wfa.wsc" {
		t.Fatalf("mime_type = %v", dec["mime_type"])
	}
	res, ok := dec["wsc"].(*wsc.Result)
	if !ok {
		t.Fatalf("expected *wsc.Result in MIME payload, got %T", dec["wsc"])
	}
	if len(res.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %d", len(res.Credentials))
	}
	c := res.Credentials[0]
	if c.SSID != "CafeWiFi" {
		t.Errorf("SSID = %q", c.SSID)
	}
	if c.NetworkKey != "hunter2hunter2" {
		t.Errorf("network key = %q, want hunter2hunter2", c.NetworkKey)
	}
	if len(c.AuthType) != 1 || c.AuthType[0] != "WPA2-PSK" {
		t.Errorf("auth type = %v", c.AuthType)
	}
}
