package dtls

import (
	"strings"
	"testing"
)

// rep returns a hex string repeating byte b n times.
func rep(n int, b byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, n*2)
	for i := 0; i < n; i++ {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0F]
	}
	return string(out)
}

func TestDecode_ClientHello_DTLS12(t *testing.T) {
	// Record: CT=22 Handshake, version=DTLS 1.2, epoch=0,
	// seq=0, length=58 (12 hdr + 46 body).
	// Handshake: type=1 ClientHello, length=46, msg_seq=0,
	// frag_offset=0, frag_length=46.
	// Body: legacy_version=FEFD, 32 bytes random=0xAA, session
	// id len=0, cookie len=0, cipher suites len=4 (2 suites
	// C02C/C030), compression count=1 (00), extensions len=0.
	in := "16FEFD0000000000000000003A" +
		"0100002E000000000000002E" +
		"FEFD" + rep(32, 0xAA) + "00" + "00" + "0004C02CC030" + "0100" + "0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RecordCount != 1 {
		t.Fatalf("expected 1 record, got %d", r.RecordCount)
	}
	rec := r.Records[0]
	if rec.ContentTypeName != "Handshake" {
		t.Errorf("content type: %q", rec.ContentTypeName)
	}
	if rec.Version != "DTLS 1.2" {
		t.Errorf("version: %q", rec.Version)
	}
	if rec.Epoch != 0 {
		t.Errorf("epoch: %d", rec.Epoch)
	}
	if rec.Handshake == nil {
		t.Fatal("Handshake nil")
	}
	h := rec.Handshake
	if h.MsgTypeName != "ClientHello" {
		t.Errorf("msg type: %q", h.MsgTypeName)
	}
	if h.IsFragmented {
		t.Errorf("should not be fragmented")
	}
	if h.ClientHello == nil {
		t.Fatal("ClientHello nil")
	}
	ch := h.ClientHello
	if ch.LegacyVersion != "DTLS 1.2" {
		t.Errorf("legacy version: %q", ch.LegacyVersion)
	}
	if ch.RandomHex != strings.Repeat("AA", 32) {
		t.Errorf("random mismatch")
	}
	if ch.SessionIDLength != 0 {
		t.Errorf("session id length: %d", ch.SessionIDLength)
	}
	if ch.CookieLength != 0 {
		t.Errorf("cookie length: %d", ch.CookieLength)
	}
	if ch.CipherSuiteCount != 2 || ch.CipherSuitesHex != "C02CC030" {
		t.Errorf("ciphers: %d %q", ch.CipherSuiteCount, ch.CipherSuitesHex)
	}
	if ch.CompressionCount != 1 {
		t.Errorf("compression count: %d", ch.CompressionCount)
	}
}

func TestDecode_HelloVerifyRequest(t *testing.T) {
	// Record: CT=22, ver=FEFD, epoch=0, seq=1, length=23.
	// Handshake: type=3 HelloVerifyRequest, length=11.
	// Body: server_version=FEFD, cookie_length=8, cookie=8 bytes.
	in := "16FEFD000000000000000100170300000B0001000000" +
		"00000BFEFD081122334455667788"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := r.Records[0]
	if rec.Handshake == nil || rec.Handshake.MsgTypeName != "HelloVerifyRequest" {
		t.Fatalf("expected HelloVerifyRequest, got %+v", rec.Handshake)
	}
	hvr := rec.Handshake.HelloVerifyRequest
	if hvr == nil {
		t.Fatal("HelloVerifyRequest body nil")
	}
	if hvr.ServerVersion != "DTLS 1.2" {
		t.Errorf("server version: %q", hvr.ServerVersion)
	}
	if hvr.CookieLength != 8 || hvr.CookieHex != "1122334455667788" {
		t.Errorf("cookie: len=%d hex=%q", hvr.CookieLength, hvr.CookieHex)
	}
}

func TestDecode_Alert_CloseNotify(t *testing.T) {
	// CT=21, ver=FEFD, epoch=1, seq=5, length=2, body=01 00
	// (warning, close_notify).
	in := "15FEFD000100000000000500020100"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := r.Records[0]
	if rec.Alert == nil {
		t.Fatal("Alert nil")
	}
	if rec.Alert.LevelName != "warning" {
		t.Errorf("level: %q", rec.Alert.LevelName)
	}
	if rec.Alert.DescriptionName != "close_notify" {
		t.Errorf("description: %q", rec.Alert.DescriptionName)
	}
}

func TestDecode_ChangeCipherSpec(t *testing.T) {
	// CT=20, ver=FEFD, epoch=0, seq=2, length=1, body=01.
	in := "14FEFD0000000000000002000101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := r.Records[0]
	if rec.ChangeCipherSpec == nil || *rec.ChangeCipherSpec != 1 {
		t.Errorf("CCS: %+v", rec.ChangeCipherSpec)
	}
}

func TestDecode_ApplicationData(t *testing.T) {
	// CT=23, ver=FEFD, epoch=1, seq=6, length=16, 16-byte ciphertext.
	in := "17FEFD000100000000000600100123456789ABCDEF0123456789ABCDEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rec := r.Records[0]
	if rec.ApplicationData == nil || rec.ApplicationData.CipherTextLen != 16 {
		t.Errorf("ApplicationData: %+v", rec.ApplicationData)
	}
}

func TestDecode_Heartbeat_HeartbleedHint(t *testing.T) {
	// CT=24, length=4 (1 type + 2 declared length + 1 actual byte).
	// MessageType=1 Request, declared payload_length=0x0064 (100),
	// actual remaining=1 — Heartbleed pattern.
	in := "18FEFD00010000000000070004010064FF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	hb := r.Records[0].Heartbeat
	if hb == nil {
		t.Fatal("Heartbeat nil")
	}
	if hb.MessageTypeName != "Request" {
		t.Errorf("hb type: %q", hb.MessageTypeName)
	}
	if hb.PayloadLength != 100 {
		t.Errorf("declared payload length: %d", hb.PayloadLength)
	}
	if hb.ActualRemaining != 1 {
		t.Errorf("actual remaining: %d", hb.ActualRemaining)
	}
	if !strings.Contains(hb.HeartbleedHint, "Heartbleed") {
		t.Errorf("expected Heartbleed hint, got: %q", hb.HeartbleedHint)
	}
}

func TestDecode_MultiRecord_ClientHelloPlusHVR(t *testing.T) {
	chRec := "16FEFD0000000000000000003A" +
		"0100002E000000000000002E" +
		"FEFD" + rep(32, 0xAA) + "00" + "00" + "0004C02CC030" + "0100" + "0000"
	hvrRec := "16FEFD000000000000000100170300000B0001000000" +
		"00000BFEFD081122334455667788"
	r, err := Decode(chRec + hvrRec)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RecordCount != 2 {
		t.Fatalf("expected 2 records, got %d", r.RecordCount)
	}
	if r.Summary != "ClientHello + HelloVerifyRequest" {
		t.Errorf("summary: %q", r.Summary)
	}
}

func TestDecode_FragmentedHandshake(t *testing.T) {
	// Frag offset != 0 or frag len != total length → IsFragmented
	// true, body not dissected.
	// CT=22, length=24 (12 hdr + 12 body).
	// Handshake: type=11 Certificate, total length=100, msg_seq=2,
	// frag_offset=50, frag_length=12.
	in := "16FEFD000000000000000200180B000064000200003200000C" +
		"AABBCCDDEEFF001122334455"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	h := r.Records[0].Handshake
	if h == nil {
		t.Fatal("Handshake nil")
	}
	if !h.IsFragmented {
		t.Errorf("expected IsFragmented=true (offset=%d total=%d frag=%d)",
			h.FragmentOffset, h.Length, h.FragmentLength)
	}
	if h.MsgTypeName != "Certificate" {
		t.Errorf("msg type: %q", h.MsgTypeName)
	}
}

func TestDecode_VersionTable(t *testing.T) {
	cases := map[uint16]string{
		0xFEFF: "DTLS 1.0",
		0xFEFD: "DTLS 1.2",
		0xFEFC: "DTLS 1.3",
	}
	for k, v := range cases {
		if got := versionName(k); got != v {
			t.Errorf("versionName(0x%04X): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AlertDescriptionTable(t *testing.T) {
	cases := map[int]string{
		0:   "close_notify",
		40:  "handshake_failure",
		48:  "unknown_ca",
		50:  "decode_error",
		70:  "protocol_version",
		80:  "internal_error",
		110: "unsupported_extension",
	}
	for k, v := range cases {
		if got := alertDescriptionName(k); got != v {
			t.Errorf("alertDescriptionName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"odd hex":           "16FEFD000",
		"header truncated":  "16FEFD0000",
		"fragment too long": "16FEFD0000000000000000FFFF",
		"bad hex":           "ZZFEFD0000000000000000000100",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
