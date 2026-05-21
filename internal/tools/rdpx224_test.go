package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func rdpCR(cookie string, negFlags byte, reqProtos uint32) []byte {
	x224 := []byte{0, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	x224[0] = byte(len(x224) - 1)
	var ud []byte
	if cookie != "" {
		ud = append(ud, []byte("Cookie: ")...)
		ud = append(ud, []byte(cookie)...)
		ud = append(ud, '\r', '\n')
	}
	negReq := []byte{0x01, negFlags, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(negReq[4:8], reqProtos)
	ud = append(ud, negReq...)
	body := append(x224, ud...)
	total := 4 + len(body)
	tpkt := []byte{0x03, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	return append(tpkt, body...)
}

func rdpCC(payloadType byte, flags byte, value uint32) []byte {
	x224 := []byte{0, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00}
	x224[0] = byte(len(x224) - 1)
	payload := []byte{payloadType, flags, 0x08, 0x00, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(payload[4:8], value)
	body := append(x224, payload...)
	total := 4 + len(body)
	tpkt := []byte{0x03, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(tpkt[2:4], uint16(total))
	return append(tpkt, body...)
}

// TestRDPDecodeHandler_CRWithMSTSHash pins the canonical
// username pre-auth disclosure shape.
func TestRDPDecodeHandler_CRWithMSTSHash(t *testing.T) {
	pkt := rdpCR("mstshash=Administrator", 0x00, 0x00000003)
	out, err := rdpx224DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"x224_pdu_type_name": "CR (Connection Request)"`,
		`"mstshash_username": "Administrator"`,
		`"has_neg_req": true`,
		`PROTOCOL_SSL`,
		`PROTOCOL_HYBRID`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRDPDecodeHandler_CRStandardRDPVulnerable pins the BlueKeep-
// candidate indicator (PROTOCOL_RDP=0, no TLS upgrade).
func TestRDPDecodeHandler_CRStandardRDPVulnerable(t *testing.T) {
	pkt := rdpCR("mstshash=admin", 0x00, 0x00000000)
	out, err := rdpx224DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`PROTOCOL_RDP`,
		`vulnerable`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRDPDecodeHandler_CCNegFailureHybridRequired pins the
// canonical NLA-hardened server response.
func TestRDPDecodeHandler_CCNegFailureHybridRequired(t *testing.T) {
	pkt := rdpCC(0x03, 0x00, 0x00000005)
	out, err := rdpx224DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_neg_failure": true`,
		`HYBRID_REQUIRED_BY_SERVER`,
		`NLA-hardened`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRDPDecodeHandler_CCNegRspHybridSelected pins the server-
// side NLA confirmation.
func TestRDPDecodeHandler_CCNegRspHybridSelected(t *testing.T) {
	pkt := rdpCC(0x02, 0x01, 0x00000002)
	out, err := rdpx224DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_neg_rsp": true`,
		`PROTOCOL_HYBRID`,
		`hardened`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRDPDecodeHandler_RoutingToken pins the RD Connection
// Broker routing-cookie form.
func TestRDPDecodeHandler_RoutingToken(t *testing.T) {
	pkt := rdpCR("msts=ABC123base64payload", 0x00, 0x00000002)
	out, err := rdpx224DecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"msts_routing_token": "ABC123base64payload"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestRDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := rdpx224DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
