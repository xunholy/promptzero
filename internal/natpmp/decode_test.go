package natpmp

import (
	"strings"
	"testing"
)

func TestDecode_PublicAddressRequest(t *testing.T) {
	// Version=0, Opcode=0 — minimal 2-byte client query.
	in := "00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 0 || r.Opcode != 0 {
		t.Errorf("header: ver=%d op=%d", r.Version, r.Opcode)
	}
	if r.IsResponse {
		t.Errorf("expected request")
	}
	if r.OpcodeName != "Public Address Request" {
		t.Errorf("opcode name: %q", r.OpcodeName)
	}
	if r.PublicAddressRequest == nil {
		t.Fatal("Public Address Request body nil")
	}
}

func TestDecode_PublicAddressResponse(t *testing.T) {
	// Version=0, Opcode=128, Result=SUCCESS,
	// SecondsSinceEpoch=12345, Public IP=203.0.113.5.
	in := "00 80 0000 00003039 CB007105"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IsResponse {
		t.Errorf("expected response")
	}
	if r.OpcodeName != "Public Address Response" {
		t.Errorf("opcode name: %q", r.OpcodeName)
	}
	resp := r.PublicAddressResponse
	if resp == nil {
		t.Fatal("Public Address Response body nil")
	}
	if resp.ResultCodeName != "SUCCESS" {
		t.Errorf("result: %q", resp.ResultCodeName)
	}
	if resp.SecondsSinceEpoch != 12345 {
		t.Errorf("epoch: %d", resp.SecondsSinceEpoch)
	}
	if resp.PublicIPAddress != "203.0.113.5" {
		t.Errorf("public IP: %q", resp.PublicIPAddress)
	}
}

func TestDecode_MapUDPRequest(t *testing.T) {
	// Map UDP: Internal=80, Suggested External=8080,
	// Lifetime=3600s.
	in := "00 01 0000 0050 1F90 00000E10"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "Map UDP Request" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	req := r.MapRequest
	if req == nil {
		t.Fatal("Map Request body nil")
	}
	if req.Protocol != "UDP" {
		t.Errorf("protocol: %q", req.Protocol)
	}
	if req.InternalPort != 80 || req.SuggestedExternalPort != 8080 {
		t.Errorf("ports: %+v", req)
	}
	if req.RequestedLifetimeSec != 3600 {
		t.Errorf("lifetime: %d", req.RequestedLifetimeSec)
	}
}

func TestDecode_MapTCPRequest(t *testing.T) {
	in := "00 02 0000 01BB 1F90 00000E10"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "Map TCP Request" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	if r.MapRequest.Protocol != "TCP" {
		t.Errorf("protocol: %q", r.MapRequest.Protocol)
	}
	if r.MapRequest.InternalPort != 443 {
		t.Errorf("internal port: %d", r.MapRequest.InternalPort)
	}
}

func TestDecode_MapUDPResponse(t *testing.T) {
	// Map UDP Response: Result=SUCCESS, Epoch=12345,
	// Internal=80, Mapped External=8080, Lifetime=3600.
	in := "00 81 0000 00003039 0050 1F90 00000E10"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "Map UDP Response" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	resp := r.MapResponse
	if resp == nil {
		t.Fatal("Map Response body nil")
	}
	if resp.Protocol != "UDP" || resp.MappedExternalPort != 8080 ||
		resp.LifetimeSec != 3600 {
		t.Errorf("response: %+v", resp)
	}
}

func TestDecode_MapTCPResponse_OutOfResources(t *testing.T) {
	in := "00 82 0004 00003039 0050 0000 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "Map TCP Response" {
		t.Errorf("opcode: %q", r.OpcodeName)
	}
	if r.MapResponse.ResultCodeName != "OUT_OF_RESOURCES" {
		t.Errorf("result: %q", r.MapResponse.ResultCodeName)
	}
}

func TestDecode_PCPVersionNote(t *testing.T) {
	// Version=2 — that's PCP, not NAT-PMP.
	in := "02 00 0000 00000000 00000000000000000000000000000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "pcp_decode") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected pcp_decode note in: %v", r.Notes)
	}
}

func TestDecode_OpcodeTable(t *testing.T) {
	cases := map[int]string{
		0:   "Public Address Request",
		1:   "Map UDP Request",
		2:   "Map TCP Request",
		128: "Public Address Response",
		129: "Map UDP Response",
		130: "Map TCP Response",
	}
	for k, v := range cases {
		if got := opcodeName(k); got != v {
			t.Errorf("opcodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ResultCodeTable(t *testing.T) {
	cases := map[int]string{
		0: "SUCCESS",
		1: "UNSUPP_VERSION",
		2: "NOT_AUTHORIZED",
		3: "NETWORK_FAILURE",
		4: "OUT_OF_RESOURCES",
		5: "UNSUPPORTED_OPCODE",
	}
	for k, v := range cases {
		if got := resultCodeName(k); got != v {
			t.Errorf("resultCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedOpcode_Note(t *testing.T) {
	in := "00 63"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.OpcodeName, "uncatalogued") {
		t.Errorf("expected uncatalogued opcode name: %q", r.OpcodeName)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"odd hex":          "0001 000",
		"short":            "00",
		"bad hex":          "ZZ 00",
		"truncated paresp": "00 80 0000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
