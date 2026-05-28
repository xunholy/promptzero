package snmp

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestDecode_v2c_GetRequest_SysDescr pins an SNMPv2c
// GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0) with
// community "public", request ID 0x12345678.
func TestDecode_v2c_GetRequest_SysDescr(t *testing.T) {
	pkt := buildV2cGetRequest(t, "public", 0x12345678, "1.3.6.1.2.1.1.1.0")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d; want 1 (v2c)", got.Version)
	}
	if got.VersionStr != "SNMPv2c" {
		t.Errorf("VersionStr = %q", got.VersionStr)
	}
	if got.Community != "public" {
		t.Errorf("Community = %q", got.Community)
	}
	if got.PDU == nil {
		t.Fatal("PDU nil")
	}
	if got.PDU.Tag != 0xA0 {
		t.Errorf("PDU.Tag = 0x%02X; want 0xA0", got.PDU.Tag)
	}
	if got.PDU.TypeName != "GetRequest" {
		t.Errorf("PDU.TypeName = %q", got.PDU.TypeName)
	}
	if got.PDU.RequestID != 0x12345678 {
		t.Errorf("RequestID = 0x%X; want 0x12345678", got.PDU.RequestID)
	}
	if got.PDU.ErrorStatusName != "noError" {
		t.Errorf("ErrorStatusName = %q", got.PDU.ErrorStatusName)
	}
	if len(got.PDU.VarBinds) != 1 {
		t.Fatalf("VarBinds count = %d", len(got.PDU.VarBinds))
	}
	vb := got.PDU.VarBinds[0]
	if vb.OID != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("VarBind.OID = %q", vb.OID)
	}
	if vb.OIDName != "sysDescr.0" {
		t.Errorf("VarBind.OIDName = %q; want 'sysDescr.0'", vb.OIDName)
	}
	if vb.ValueType != "NULL" {
		t.Errorf("VarBind.ValueType = %q; want 'NULL' (GetRequest value is empty)", vb.ValueType)
	}
}

// TestDecode_v2c_Response_OctetString pins a v2c Response
// returning sysDescr.0 = "Linux router 5.10.0".
func TestDecode_v2c_Response_OctetString(t *testing.T) {
	pkt := buildV2cResponseOctetString(t, "public", 0x12345678,
		"1.3.6.1.2.1.1.1.0", "Linux router 5.10.0")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PDU.TypeName != "Response" {
		t.Errorf("TypeName = %q", got.PDU.TypeName)
	}
	vb := got.PDU.VarBinds[0]
	if vb.ValueType != "OCTET STRING" {
		t.Errorf("ValueType = %q", vb.ValueType)
	}
	if vb.StringValue != "Linux router 5.10.0" {
		t.Errorf("StringValue = %q", vb.StringValue)
	}
}

// TestDecode_v2c_Response_TimeTicks pins a TimeTicks response
// returning sysUpTime.0 = 12345600 (= 1d 10h 17m 36s).
func TestDecode_v2c_Response_TimeTicks(t *testing.T) {
	pkt := buildV2cResponseTimeTicks(t, "public", 1, "1.3.6.1.2.1.1.3.0", 12345600)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	vb := got.PDU.VarBinds[0]
	if vb.OIDName != "sysUpTime.0" {
		t.Errorf("OIDName = %q", vb.OIDName)
	}
	if vb.ValueType != "TimeTicks" {
		t.Errorf("ValueType = %q", vb.ValueType)
	}
	if vb.TimeTicks == nil {
		t.Fatal("TimeTicks nil")
	}
	if vb.TimeTicks.Centiseconds != 12345600 {
		t.Errorf("Centiseconds = %d", vb.TimeTicks.Centiseconds)
	}
	if !strings.Contains(vb.TimeTicks.Pretty, "1d") {
		t.Errorf("Pretty = %q; want '1d ...' prefix", vb.TimeTicks.Pretty)
	}
}

// TestDecode_v2c_Response_IpAddress pins an IpAddress value
// (tag 0x40).
func TestDecode_v2c_Response_IpAddress(t *testing.T) {
	pkt := buildV2cResponseIPAddress(t, "public", 1, "1.3.6.1.4.1.2021.4.5.0", []byte{192, 168, 1, 1})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	vb := got.PDU.VarBinds[0]
	if vb.ValueType != "IpAddress" {
		t.Errorf("ValueType = %q", vb.ValueType)
	}
	if vb.IPValue != "192.168.1.1" {
		t.Errorf("IPValue = %q", vb.IPValue)
	}
}

// TestDecode_v1_Trap pins an SNMPv1 Trap (tag 0xA4) with the
// shape: enterprise OID + agent IP + generic-trap (0=coldStart)
// + specific-trap (0) + time-stamp (1234) + varbinds.
func TestDecode_v1_Trap(t *testing.T) {
	pkt := buildV1Trap(t, "public", "1.3.6.1.4.1.99",
		[]byte{10, 0, 0, 1}, 0, 0, 1234)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Version != 0 {
		t.Errorf("Version = %d; want 0 (v1)", got.Version)
	}
	if got.TrapV1 == nil {
		t.Fatal("TrapV1 nil")
	}
	if got.TrapV1.EnterpriseOID != "1.3.6.1.4.1.99" {
		t.Errorf("EnterpriseOID = %q", got.TrapV1.EnterpriseOID)
	}
	if got.TrapV1.AgentAddrIPv4 != "10.0.0.1" {
		t.Errorf("AgentAddrIPv4 = %q", got.TrapV1.AgentAddrIPv4)
	}
	if got.TrapV1.GenericTrapName != "coldStart" {
		t.Errorf("GenericTrapName = %q", got.TrapV1.GenericTrapName)
	}
	if got.TrapV1.TimestampTicks != 1234 {
		t.Errorf("TimestampTicks = %d", got.TrapV1.TimestampTicks)
	}
}

// TestDecode_v2c_TrapV2 pins an SNMPv2-Trap (tag 0xA7).
func TestDecode_v2c_TrapV2(t *testing.T) {
	pkt := buildV2cTrapV2(t, "public", 0x99)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PDU == nil {
		t.Fatal("PDU nil")
	}
	if got.PDU.Tag != 0xA7 {
		t.Errorf("Tag = 0x%02X; want 0xA7", got.PDU.Tag)
	}
	if got.PDU.TypeName != "SNMPv2-Trap" {
		t.Errorf("TypeName = %q", got.PDU.TypeName)
	}
}

// TestDecode_v2c_GetBulkRequest pins the non-repeaters /
// max-repetitions field naming.
func TestDecode_v2c_GetBulkRequest(t *testing.T) {
	pkt := buildV2cGetBulk(t, "public", 0x55, 2, 10, "1.3.6.1.2.1.2.2")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PDU.Tag != 0xA5 {
		t.Errorf("Tag = 0x%02X", got.PDU.Tag)
	}
	if got.PDU.NonRepeaters != 2 {
		t.Errorf("NonRepeaters = %d", got.PDU.NonRepeaters)
	}
	if got.PDU.MaxRepetitions != 10 {
		t.Errorf("MaxRepetitions = %d", got.PDU.MaxRepetitions)
	}
}

// TestDecode_BadVersion rejects an invalid outer wrapper.
func TestDecode_BadOuter(t *testing.T) {
	// First byte 0x02 (INTEGER) instead of 0x30 (SEQUENCE)
	if _, err := Decode("02 01 01"); err == nil {
		t.Error("non-SEQUENCE outer: want error")
	}
}

// TestDecode_TooShort rejects buffers that can't hold a TLV.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("30"); err == nil {
		t.Error("1-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestDecodeOID exercises the OID encoder edge cases.
func TestDecodeOID(t *testing.T) {
	cases := map[string]string{
		"2A":                      "1.2",               // 42 → 1.2
		"2A 86 48":                "1.2.840",           // 42, base-128 [86 48]
		"2B 06 01 02 01 01 01 00": "1.3.6.1.2.1.1.1.0", // sysDescr.0
		"2B 06 01 04 01 89 64":    "1.3.6.1.4.1.1252",  // big arc (89 64 base-128 = 9<<7|100 = 1252)
	}
	for h, want := range cases {
		b, _ := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		if got := decodeOID(b); got != want {
			t.Errorf("decodeOID(%s) = %q; want %q", h, got, want)
		}
	}
}

// TestPDUTypeNameTable spot-checks.
func TestPDUTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0xA0: "GetRequest",
		0xA1: "GetNextRequest",
		0xA2: "Response",
		0xA3: "SetRequest",
		0xA4: "Trap-PDU (SNMPv1)",
		0xA5: "GetBulkRequest",
		0xA6: "InformRequest",
		0xA7: "SNMPv2-Trap",
		0xA8: "Report",
	}
	for tag, want := range cases {
		if got := pduTypeName(tag); got != want {
			t.Errorf("pduTypeName(0x%02X) = %q; want %q", tag, got, want)
		}
	}
}

// TestErrorStatusTable spot-checks.
func TestErrorStatusTable(t *testing.T) {
	cases := map[int]string{
		0:  "noError",
		1:  "tooBig",
		2:  "noSuchName",
		5:  "genErr",
		16: "authorizationError",
		17: "notWritable",
	}
	for e, want := range cases {
		if got := errorStatusName(e); got != want {
			t.Errorf("errorStatusName(%d) = %q; want %q", e, got, want)
		}
	}
}

// TestGenericTrapTable spot-checks.
func TestGenericTrapTable(t *testing.T) {
	cases := map[int]string{
		0: "coldStart",
		1: "warmStart",
		2: "linkDown",
		3: "linkUp",
		4: "authenticationFailure",
		6: "enterpriseSpecific",
	}
	for g, want := range cases {
		if got := genericTrapName(g); got != want {
			t.Errorf("genericTrapName(%d) = %q; want %q", g, got, want)
		}
	}
}

// --- BER encoding helpers for test vectors ----------------------------

// encodeTLV builds a single TLV with the given tag + value.
func encodeTLV(tag byte, val []byte) []byte {
	out := []byte{tag}
	if len(val) < 128 {
		out = append(out, byte(len(val)))
	} else if len(val) < 256 {
		out = append(out, 0x81, byte(len(val)))
	} else {
		out = append(out, 0x82, byte(len(val)>>8), byte(len(val)))
	}
	return append(out, val...)
}

// encodeInt encodes a signed integer as BER INTEGER.
func encodeInt(v int64) []byte {
	if v == 0 {
		return encodeTLV(0x02, []byte{0x00})
	}
	var b []byte
	n := v
	if n < 0 {
		// Sign-extend properly — for testing we only need the
		// positive path.
		for n != -1 && n != 0 {
			b = append([]byte{byte(n)}, b...)
			n >>= 8
		}
	} else {
		for n > 0 {
			b = append([]byte{byte(n)}, b...)
			n >>= 8
		}
		// Add a leading 0x00 if high bit of MSB is set, to keep
		// the value positive.
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
	}
	return encodeTLV(0x02, b)
}

// encodeOID encodes a dot-separated OID as BER OID. Only the
// canonical 1.x.y.z form (X.690 §8.19) is handled — we don't
// support OIDs whose arc1 > 2.
func encodeOID(s string) []byte {
	arcs := strings.Split(s, ".")
	if len(arcs) < 2 {
		return encodeTLV(0x06, nil)
	}
	var ints []int
	for _, a := range arcs {
		var n int
		for _, c := range a {
			n = n*10 + int(c-'0')
		}
		ints = append(ints, n)
	}
	first := ints[0]*40 + ints[1]
	var body []byte
	body = append(body, byte(first))
	for _, n := range ints[2:] {
		body = append(body, base128(n)...)
	}
	return encodeTLV(0x06, body)
}

func base128(n int) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var rev []byte
	for n > 0 {
		rev = append(rev, byte(n&0x7F))
		n >>= 7
	}
	// MSB first, with high bit set on all but last
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	for i := 0; i < len(rev)-1; i++ {
		rev[i] |= 0x80
	}
	return rev
}

// encodeVarBind encodes a single (OID, value-tlv-bytes) pair
// as a SEQUENCE.
func encodeVarBind(oid string, value []byte) []byte {
	return encodeTLV(0x30, append(encodeOID(oid), value...))
}

// buildV2cGetRequest constructs a complete v2c GetRequest
// packet for the given OID with a NULL value (typical of
// GetRequest).
func buildV2cGetRequest(t *testing.T, community string, requestID int64, oid string) []byte {
	t.Helper()
	vb := encodeVarBind(oid, encodeTLV(0x05, nil))
	vbList := encodeTLV(0x30, vb)
	pdu := encodeTLV(0xA0, append(append(append([]byte{},
		encodeInt(requestID)...),
		encodeInt(0)...),
		append(encodeInt(0), vbList...)...))
	body := append(append(encodeInt(1), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, body)
}

// buildV2cResponseOctetString returns a v2c Response with one
// OCTET STRING varbind value.
func buildV2cResponseOctetString(t *testing.T, community string, requestID int64, oid, val string) []byte {
	t.Helper()
	vb := encodeVarBind(oid, encodeTLV(0x04, []byte(val)))
	vbList := encodeTLV(0x30, vb)
	pdu := encodeTLV(0xA2, append(append(append([]byte{},
		encodeInt(requestID)...),
		encodeInt(0)...),
		append(encodeInt(0), vbList...)...))
	body := append(append(encodeInt(1), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, body)
}

// buildV2cResponseTimeTicks returns a v2c Response with a
// TimeTicks (tag 0x43) varbind value.
func buildV2cResponseTimeTicks(t *testing.T, community string, requestID int64, oid string, ticks uint32) []byte {
	t.Helper()
	val := []byte{byte(ticks >> 24), byte(ticks >> 16), byte(ticks >> 8), byte(ticks)}
	// Trim leading zero bytes (positive uint encoding)
	for len(val) > 1 && val[0] == 0x00 {
		val = val[1:]
	}
	vb := encodeVarBind(oid, encodeTLV(0x43, val))
	vbList := encodeTLV(0x30, vb)
	pdu := encodeTLV(0xA2, append(append(append([]byte{},
		encodeInt(requestID)...),
		encodeInt(0)...),
		append(encodeInt(0), vbList...)...))
	body := append(append(encodeInt(1), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, body)
}

// buildV2cResponseIPAddress returns a v2c Response with an
// IpAddress (tag 0x40) varbind value.
func buildV2cResponseIPAddress(t *testing.T, community string, requestID int64, oid string, ipv4 []byte) []byte {
	t.Helper()
	vb := encodeVarBind(oid, encodeTLV(0x40, ipv4))
	vbList := encodeTLV(0x30, vb)
	pdu := encodeTLV(0xA2, append(append(append([]byte{},
		encodeInt(requestID)...),
		encodeInt(0)...),
		append(encodeInt(0), vbList...)...))
	body := append(append(encodeInt(1), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, body)
}

// buildV1Trap returns an SNMPv1 Trap (tag 0xA4) packet.
func buildV1Trap(t *testing.T, community, enterpriseOID string, agentIP []byte, generic, specific int, ts uint32) []byte {
	t.Helper()
	tsBytes := []byte{byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts)}
	for len(tsBytes) > 1 && tsBytes[0] == 0x00 {
		tsBytes = tsBytes[1:]
	}
	body := append([]byte{}, encodeOID(enterpriseOID)...)
	body = append(body, encodeTLV(0x40, agentIP)...)
	body = append(body, encodeInt(int64(generic))...)
	body = append(body, encodeInt(int64(specific))...)
	body = append(body, encodeTLV(0x43, tsBytes)...)
	body = append(body, encodeTLV(0x30, nil)...) // empty varbind list
	pdu := encodeTLV(0xA4, body)
	full := append(append(encodeInt(0), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, full)
}

// buildV2cTrapV2 returns an SNMPv2-Trap (tag 0xA7) packet
// with the minimal mandatory varbinds (sysUpTime + snmpTrapOID
// — but for simplicity we use the same generic PDU shape with
// an empty varbinds list).
func buildV2cTrapV2(t *testing.T, community string, requestID int64) []byte {
	t.Helper()
	vbList := encodeTLV(0x30, nil)
	pdu := encodeTLV(0xA7, append(append(append([]byte{},
		encodeInt(requestID)...),
		encodeInt(0)...),
		append(encodeInt(0), vbList...)...))
	body := append(append(encodeInt(1), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, body)
}

// buildV2cGetBulk returns a GetBulkRequest packet.
func buildV2cGetBulk(t *testing.T, community string, requestID, nonRepeaters, maxReps int64, oid string) []byte {
	t.Helper()
	vb := encodeVarBind(oid, encodeTLV(0x05, nil))
	vbList := encodeTLV(0x30, vb)
	pdu := encodeTLV(0xA5, append(append(append([]byte{},
		encodeInt(requestID)...),
		encodeInt(nonRepeaters)...),
		append(encodeInt(maxReps), vbList...)...))
	body := append(append(encodeInt(1), encodeTLV(0x04, []byte(community))...), pdu...)
	return encodeTLV(0x30, body)
}

// TestReadTLV_OverflowLengthNoPanic guards a BER length-field
// overflow: a long-form length declaring many bytes (e.g. 0xFF →
// 127 length bytes) used to accumulate into a negative int, slip
// past the "exceeds buffer" check, and panic on an inverted slice
// b[idx:idx+length]. The decoder must reject the wide/over-long
// length field with an error instead.
func TestReadTLV_OverflowLengthNoPanic(t *testing.T) {
	inputs := []string{
		strings.Repeat("ff", 256),          // all-FF: 0xff tag, 0xff long-form len
		"30ff" + strings.Repeat("ff", 200), // SEQUENCE + 127-byte length
		"3088ffffffffffffffff00",           // 8-byte length = overflow territory
		"3085ffffffffff00",                 // 5-byte length (just over the cap)
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Decode panicked on %q: %v", in, r)
				}
			}()
			// Error is fine; panic is not.
			_, _ = Decode(in)
		}()
	}
}
