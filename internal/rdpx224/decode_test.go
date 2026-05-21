package rdpx224

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// crPDU builds a TPKT-wrapped X.224 Connection Request with the
// supplied cookie + RDP_NEG_REQ.
func crPDU(cookie string, negReqFlags byte,
	requestedProtocols uint32) []byte {
	// X.224 CR header: LI(1) + PDU-type+credit(1) + dst-ref(2)
	// + src-ref(2) + class+option(1)
	x224 := []byte{
		0, // LI placeholder, will set after compute
		0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	// LI = header length - 1 byte (the LI byte itself is
	// excluded)
	x224[0] = byte(len(x224) - 1)

	// User data: optional cookie + RDP_NEG_REQ
	var ud []byte
	if cookie != "" {
		ud = append(ud, []byte("Cookie: ")...)
		ud = append(ud, []byte(cookie)...)
		ud = append(ud, '\r', '\n')
	}
	// RDP_NEG_REQ: type(1)=0x01 + flags(1) + length(2 LE)=8 +
	// requestedProtocols(4 LE)
	negReq := []byte{0x01, negReqFlags, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(negReq[4:8], requestedProtocols)
	ud = append(ud, negReq...)

	// TPKT header: version(1)=3 + reserved(1)=0 + length(2 BE)
	body := append(x224, ud...)
	total := 4 + len(body)
	tpkt := []byte{0x03, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	return append(tpkt, body...)
}

// ccPDU builds a TPKT-wrapped X.224 Connection Confirm with the
// supplied NEG_RSP / NEG_FAILURE payload (8 bytes).
func ccPDU(payloadType byte, flags byte, value uint32) []byte {
	x224 := []byte{
		0, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	x224[0] = byte(len(x224) - 1)
	payload := []byte{payloadType, flags, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(payload[4:8], value)
	body := append(x224, payload...)
	total := 4 + len(body)
	tpkt := []byte{0x03, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	return append(tpkt, body...)
}

// TestDecodeCRWithMSTSHashUsername pins the canonical RDP
// username-disclosure shape.
func TestDecodeCRWithMSTSHashUsername(t *testing.T) {
	pkt := crPDU("mstshash=Administrator", 0x00, 0x00000003)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.X224PDUType != 0xE0 {
		t.Errorf("X224PDUType: got 0x%02X want 0xE0", r.X224PDUType)
	}
	if r.X224PDUTypeName != "CR (Connection Request)" {
		t.Errorf("X224PDUTypeName: got %q", r.X224PDUTypeName)
	}
	if r.MSTSHashUsername != "Administrator" {
		t.Errorf("MSTSHashUsername: got %q want Administrator",
			r.MSTSHashUsername)
	}
	if !r.HasNegReq {
		t.Errorf("HasNegReq should be true")
	}
	// Both PROTOCOL_SSL (0x01) and PROTOCOL_HYBRID (0x02) set
	if len(r.NegReqRequestedProtocolsNames) != 2 {
		t.Errorf("requestedProtocols names: got %d want 2 — %v",
			len(r.NegReqRequestedProtocolsNames),
			r.NegReqRequestedProtocolsNames)
	}
}

// TestDecodeCRWithRoutingToken pins the alternative cookie form
// used by RD Connection Broker.
func TestDecodeCRWithRoutingToken(t *testing.T) {
	pkt := crPDU("msts=ABC123base64payload", 0x00, 0x00000002)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MSTSRoutingToken != "ABC123base64payload" {
		t.Errorf("MSTSRoutingToken: got %q", r.MSTSRoutingToken)
	}
	if r.MSTSHashUsername != "" {
		t.Errorf("MSTSHashUsername should be empty when msts= cookie used")
	}
}

// TestDecodeCRStandardRDPNoTLS pins the legacy / vulnerable
// pre-TLS request shape.
func TestDecodeCRStandardRDPNoTLS(t *testing.T) {
	pkt := crPDU("mstshash=guest", 0x00, 0x00000000)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, n := range r.NegReqRequestedProtocolsNames {
		if strings.Contains(n, "PROTOCOL_RDP") {
			found = true
		}
	}
	if !found {
		t.Errorf("standard RDP (0) should surface PROTOCOL_RDP name: %v",
			r.NegReqRequestedProtocolsNames)
	}
	hasVulnFlag := false
	for _, n := range r.NegReqRequestedProtocolsNames {
		if strings.Contains(n, "vulnerable") {
			hasVulnFlag = true
		}
	}
	if !hasVulnFlag {
		t.Errorf("standard RDP should flag vulnerability: %v",
			r.NegReqRequestedProtocolsNames)
	}
}

// TestDecodeCRRestrictedAdminMode pins the restricted-admin
// flag detection.
func TestDecodeCRRestrictedAdminMode(t *testing.T) {
	pkt := crPDU("mstshash=admin", 0x01, 0x00000002)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.NegReqFlagsNames) != 1 {
		t.Errorf("flags: got %d want 1", len(r.NegReqFlagsNames))
	}
	if r.NegReqFlagsNames[0] != "RESTRICTED_ADMIN_MODE_REQUIRED" {
		t.Errorf("flag name: got %q", r.NegReqFlagsNames[0])
	}
}

// TestDecodeCCNegRspHybrid pins server-side NLA confirmation.
func TestDecodeCCNegRspHybrid(t *testing.T) {
	pkt := ccPDU(0x02, 0x01, 0x00000002) // HYBRID selected
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.HasNegRsp {
		t.Errorf("HasNegRsp should be true")
	}
	if !strings.Contains(r.NegRspSelectedProtocolName, "HYBRID") {
		t.Errorf("selectedProtocolName: got %q", r.NegRspSelectedProtocolName)
	}
	if !strings.Contains(r.NegRspSelectedProtocolName, "hardened") {
		t.Errorf("HYBRID should flag hardened: %q",
			r.NegRspSelectedProtocolName)
	}
}

// TestDecodeCCNegFailureHybridRequired pins the canonical NLA-
// hardened server response.
func TestDecodeCCNegFailureHybridRequired(t *testing.T) {
	pkt := ccPDU(0x03, 0x00, 0x00000005)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.HasNegFailure {
		t.Errorf("HasNegFailure should be true")
	}
	if !strings.Contains(r.NegFailureCodeName, "HYBRID_REQUIRED_BY_SERVER") {
		t.Errorf("failureCodeName: got %q", r.NegFailureCodeName)
	}
	if !strings.Contains(r.NegFailureCodeName, "NLA-hardened") {
		t.Errorf("failureCodeName should flag NLA-hardened: %q",
			r.NegFailureCodeName)
	}
}

// TestDecodeCCNegFailureSSLRequired pins the TLS-hardening
// posture.
func TestDecodeCCNegFailureSSLRequired(t *testing.T) {
	pkt := ccPDU(0x03, 0x00, 0x00000001)
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.NegFailureCodeName, "SSL_REQUIRED_BY_SERVER") {
		t.Errorf("failureCodeName: got %q", r.NegFailureCodeName)
	}
}

// TestX224PDUTypeNameTable spot-checks each catalogued PDU.
func TestX224PDUTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0xE0: "CR",
		0xD0: "CC",
		0xF0: "DT",
		0x80: "DR",
		0x70: "ER",
	}
	for k, marker := range cases {
		got := x224PDUTypeName(k)
		if !strings.Contains(got, marker) {
			t.Errorf("x224PDUTypeName(0x%02X) = %q want contains %q",
				k, got, marker)
		}
	}
}

// TestProtocolNamesTable spot-checks each catalogued protocol.
func TestProtocolNamesTable(t *testing.T) {
	cases := map[uint32]string{
		0x00000001: "PROTOCOL_SSL",
		0x00000002: "PROTOCOL_HYBRID",
		0x00000004: "PROTOCOL_RDSTLS",
		0x00000008: "PROTOCOL_HYBRID_EX",
		0x00000010: "PROTOCOL_RDSAAD",
	}
	for k, marker := range cases {
		names := protocolNames(k)
		if len(names) == 0 || !strings.Contains(names[0], marker) {
			t.Errorf("protocolNames(0x%08X) = %v want contains %q",
				k, names, marker)
		}
	}
	// 0 = PROTOCOL_RDP
	if names := protocolNames(0); !strings.Contains(names[0], "PROTOCOL_RDP") {
		t.Errorf("protocolNames(0) should include PROTOCOL_RDP: %v", names)
	}
}

// TestNegFailureCodeNameTable spot-checks each catalogued code.
func TestNegFailureCodeNameTable(t *testing.T) {
	cases := map[uint32]string{
		0x00000001: "SSL_REQUIRED_BY_SERVER",
		0x00000002: "SSL_NOT_ALLOWED_BY_SERVER",
		0x00000003: "SSL_CERT_NOT_ON_SERVER",
		0x00000004: "INCONSISTENT_FLAGS",
		0x00000005: "HYBRID_REQUIRED_BY_SERVER",
		0x00000006: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
	}
	for k, marker := range cases {
		got := negFailureCodeName(k)
		if !strings.Contains(got, marker) {
			t.Errorf("negFailureCodeName(0x%08X) = %q want contains %q",
				k, got, marker)
		}
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

func TestDecodeRejectsNonTPKTv3(t *testing.T) {
	b := []byte{0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}
	if _, err := Decode(hex.EncodeToString(b)); err == nil {
		t.Fatal("want error for non-TPKTv3")
	}
}
