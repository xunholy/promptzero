package ike

import (
	"strings"
	"testing"
)

func TestDecode_IKESAInitHeaderOnly(t *testing.T) {
	// Initiator SPI=0x1122334455667788, Responder SPI=0,
	// Next Payload=33 SA, Version=2.0, Exchange=34
	// IKE_SA_INIT, Flags=I, MsgID=0, Length=28.
	in := "1122334455667788 0000000000000000" +
		"21 20 22 08 00000000 0000001C"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.InitiatorSPI != 0x1122334455667788 {
		t.Errorf("initiator SPI: 0x%016X", r.InitiatorSPI)
	}
	if r.ResponderSPI != 0 {
		t.Errorf("responder SPI: %d", r.ResponderSPI)
	}
	if r.ExchangeTypeName != "IKE_SA_INIT" {
		t.Errorf("exchange: %q", r.ExchangeTypeName)
	}
	if !r.FlagInitiator || r.FlagResponse {
		t.Errorf("flags: %+v", r)
	}
	if r.VersionMajor != 2 || r.VersionMinor != 0 {
		t.Errorf("version: %d.%d", r.VersionMajor, r.VersionMinor)
	}
	if r.FirstPayloadName != "SA (Security Association)" {
		t.Errorf("first payload: %q", r.FirstPayloadName)
	}
}

func TestDecode_IKEAUTH_WithSKPayload(t *testing.T) {
	// IKE_AUTH with single SK (encrypted) payload.
	// Header NextPayload=46 SK. SK body = 12 bytes encrypted.
	// Length = 28 + 16 = 44 = 0x2C.
	in := "1122334455667788 AABBCCDDEEFF0011" +
		"2E 20 23 08 00000001 0000002C" +
		"00 00 0010 DEADBEEFDEADBEEFDEADBEEF"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ExchangeTypeName != "IKE_AUTH" {
		t.Errorf("exchange: %q", r.ExchangeTypeName)
	}
	if len(r.Payloads) != 1 {
		t.Fatalf("payloads: %d", len(r.Payloads))
	}
	p := r.Payloads[0]
	if p.TypeName != "SK (Encrypted and Authenticated)" {
		t.Errorf("payload type: %q", p.TypeName)
	}
	if p.Encrypted == nil {
		t.Fatal("SK body nil")
	}
	if p.Encrypted.EncryptedBytes != 12 {
		t.Errorf("encrypted bytes: %d", p.Encrypted.EncryptedBytes)
	}
	if !strings.Contains(p.Encrypted.Note, "SK_e/SK_a") {
		t.Errorf("expected encryption note: %q", p.Encrypted.Note)
	}
}

func TestDecode_IKESAInitResponse_MultiplePayloads(t *testing.T) {
	// IKE_SA_INIT response (R flag) with chained
	// SA → KE → Nonce → Notify (NAT_DETECTION_SOURCE_IP).
	// Header NP=33 SA, length = 28 + 8*4 = 60 = 0x3C.
	in := "1122334455667788 AABBCCDDEEFF0011" +
		"21 20 22 20 00000000 0000003C" +
		"22 00 0008 AABBCCDD" + // SA → next KE
		"28 00 0008 11223344" + // KE → next Ni
		"29 00 0008 55667788" + // Ni → next N
		"00 00 0008 00 00 4004" // N → end. Type=16388 NAT_DETECTION_SOURCE_IP
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.FlagResponse || r.FlagInitiator {
		t.Errorf("flags: %+v", r)
	}
	if len(r.Payloads) != 4 {
		t.Fatalf("payloads: %d", len(r.Payloads))
	}
	wantNames := []string{
		"SA (Security Association)",
		"KE (Key Exchange)",
		"Ni/Nr (Nonce)",
		"N (Notify)",
	}
	for i, n := range wantNames {
		if r.Payloads[i].TypeName != n {
			t.Errorf("payload %d: got %q want %q",
				i, r.Payloads[i].TypeName, n)
		}
	}
	n := r.Payloads[3].Notify
	if n == nil {
		t.Fatal("notify body nil")
	}
	if n.NotifyMessageName != "NAT_DETECTION_SOURCE_IP" {
		t.Errorf("notify name: %q", n.NotifyMessageName)
	}
	if n.NotifyMessageClass != "Status" {
		t.Errorf("notify class: %q", n.NotifyMessageClass)
	}
}

func TestDecode_AuthenticationFailedNotify(t *testing.T) {
	// INFORMATIONAL with Notify AUTHENTICATION_FAILED (24).
	in := "1122334455667788 AABBCCDDEEFF0011" +
		"29 20 25 20 00000002 00000024" +
		"00 00 0008 00 00 0018"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ExchangeTypeName != "INFORMATIONAL" {
		t.Errorf("exchange: %q", r.ExchangeTypeName)
	}
	n := r.Payloads[0].Notify
	if n.NotifyMessageName != "AUTHENTICATION_FAILED" {
		t.Errorf("notify name: %q", n.NotifyMessageName)
	}
	if n.NotifyMessageClass != "Error" {
		t.Errorf("notify class: %q", n.NotifyMessageClass)
	}
}

func TestDecode_NotifyWithSPI(t *testing.T) {
	// Notify with Protocol=3 ESP, SPI Size=4, Type=INVALID_SPI (11),
	// SPI=0xCAFEBABE.
	in := "1122334455667788 AABBCCDDEEFF0011" +
		"29 20 25 20 00000002 00000028" +
		"00 00 000C 03 04 000B CAFEBABE"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	n := r.Payloads[0].Notify
	if n.ProtocolIDName != "ESP" {
		t.Errorf("protocol: %q", n.ProtocolIDName)
	}
	if n.SPISize != 4 {
		t.Errorf("SPI size: %d", n.SPISize)
	}
	if n.NotifyMessageName != "INVALID_SPI" {
		t.Errorf("notify name: %q", n.NotifyMessageName)
	}
	if n.SPIHex != "CAFEBABE" {
		t.Errorf("SPI hex: %q", n.SPIHex)
	}
}

func TestDecode_ExchangeTypeTable(t *testing.T) {
	cases := map[int]string{
		34: "IKE_SA_INIT",
		35: "IKE_AUTH",
		36: "CREATE_CHILD_SA",
		37: "INFORMATIONAL",
	}
	for k, v := range cases {
		if got := exchangeTypeName(k); got != v {
			t.Errorf("exchangeTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_PayloadTypeTable(t *testing.T) {
	cases := map[int]string{
		33: "SA (Security Association)",
		34: "KE (Key Exchange)",
		35: "IDi (Identification - Initiator)",
		36: "IDr (Identification - Responder)",
		39: "AUTH (Authentication)",
		40: "Ni/Nr (Nonce)",
		41: "N (Notify)",
		42: "D (Delete)",
		43: "V (Vendor ID)",
		44: "TSi (Traffic Selector - Initiator)",
		45: "TSr (Traffic Selector - Responder)",
		46: "SK (Encrypted and Authenticated)",
		47: "CP (Configuration)",
	}
	for k, v := range cases {
		if got := payloadTypeName(k); got != v {
			t.Errorf("payloadTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_NotifyTypeSpotCheck(t *testing.T) {
	cases := map[int]string{
		1:     "UNSUPPORTED_CRITICAL_PAYLOAD",
		11:    "INVALID_SPI",
		14:    "NO_PROPOSAL_CHOSEN",
		17:    "INVALID_KE_PAYLOAD",
		24:    "AUTHENTICATION_FAILED",
		36:    "INTERNAL_ADDRESS_FAILURE",
		16384: "INITIAL_CONTACT",
		16388: "NAT_DETECTION_SOURCE_IP",
		16389: "NAT_DETECTION_DESTINATION_IP",
		16390: "COOKIE",
		16404: "MOBIKE_SUPPORTED",
		16408: "AUTH_LIFETIME",
	}
	for k, v := range cases {
		if got := notifyMessageTypeName(k); got != v {
			t.Errorf("notifyMessageTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_NotifyClassTable(t *testing.T) {
	cases := map[int]string{
		1:     "Error",
		8191:  "Error",
		16384: "Status",
		16389: "Status",
		8192:  "Reserved",
	}
	for k, v := range cases {
		if got := notifyMessageClass(k); got != v {
			t.Errorf("notifyMessageClass(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionNot2_Note(t *testing.T) {
	// Version 1.0 (IKEv1).
	in := "1122334455667788 0000000000000000" +
		"21 10 22 08 00000000 0000001C"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "IKEv2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected IKEv2 note: %v", r.Notes)
	}
}

func TestDecode_LengthMismatch_Note(t *testing.T) {
	// Declared length 100 but only 28 bytes provided.
	in := "1122334455667788 0000000000000000" +
		"21 20 22 08 00000000 00000064"
	r, err := Decode(in, DefaultDecodeOpts())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "declares length") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected length-mismatch note: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "11223344 5566778",
		"short":   "1122334455667788",
		"bad hex": "ZZ22334455667788 0000000000000000 21 20 22 08 00000000 0000001C",
	}
	for name, in := range cases {
		_, err := Decode(in, DefaultDecodeOpts())
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
