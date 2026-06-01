// SPDX-License-Identifier: AGPL-3.0-or-later

package uds

import "testing"

func ip(v int) *int { return &v }

func TestEncode_RequestFixedBytes(t *testing.T) {
	cases := []struct {
		name string
		req  EncodeRequest
		hex  string
	}{
		{"session-ext", EncodeRequest{Service: 0x10, SubFunction: ip(0x03)}, "1003"},
		{"rdbi-vin", EncodeRequest{Service: 0x22, DataIdentifier: ip(0xF190)}, "22F190"},
		{"sec-seed", EncodeRequest{Service: 0x27, SubFunction: ip(0x01)}, "2701"},
		{"tester-suppress", EncodeRequest{Service: 0x3E, SubFunction: ip(0x00), SuppressPositiveResponse: true}, "3E80"},
		{"wdbi", EncodeRequest{Service: 0x2E, DataIdentifier: ip(0xF190), Payload: []byte{0x01, 0x02}}, "2EF1900102"},
	}
	for _, c := range cases {
		got, err := EncodeHex(c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.hex {
			t.Errorf("%s = %s, want %s", c.name, got, c.hex)
		}
	}
}

func TestEncode_NegativeResponse(t *testing.T) {
	got, err := EncodeHex(EncodeRequest{Direction: "negative_response", Service: 0x27, NRC: ip(0x35)})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != "7F2735" {
		t.Errorf("neg = %s, want 7F2735", got)
	}
}

func TestEncode_PositiveResponse(t *testing.T) {
	// positive response to RDBI: 0x22+0x40 = 0x62.
	got, err := EncodeHex(EncodeRequest{Direction: "positive_response", Service: 0x22, DataIdentifier: ip(0xF190), Payload: []byte{0xAA}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != "62F190AA" {
		t.Errorf("pos = %s, want 62F190AA", got)
	}
}

// TestEncode_RoundTrip closes correctness against the decoder for every
// direction and field combination.
func TestEncode_RoundTrip(t *testing.T) {
	reqs := []EncodeRequest{
		{Service: 0x10, SubFunction: ip(0x03)},
		{Service: 0x22, DataIdentifier: ip(0xF190)},
		{Service: 0x3E, SubFunction: ip(0x00), SuppressPositiveResponse: true},
		{Direction: "negative_response", Service: 0x31, NRC: ip(0x78)},
		{Direction: "positive_response", Service: 0x10, SubFunction: ip(0x03), Payload: []byte{0x00, 0x19, 0x32}},
	}
	for i, r := range reqs {
		b, err := Encode(r)
		if err != nil {
			t.Fatalf("case %d Encode: %v", i, err)
		}
		d, err := DecodeBytes(b)
		if err != nil {
			t.Fatalf("case %d Decode: %v", i, err)
		}
		if d.ServiceID != r.Service {
			t.Errorf("case %d: service = 0x%02X, want 0x%02X", i, d.ServiceID, r.Service)
		}
		if r.Direction == "" && d.Direction != "request" {
			t.Errorf("case %d: direction = %s, want request", i, d.Direction)
		}
		if r.SubFunction != nil && (d.SubFunction == nil || *d.SubFunction != *r.SubFunction) {
			t.Errorf("case %d: subfn = %v, want %v", i, d.SubFunction, r.SubFunction)
		}
		if r.SuppressPositiveResponse && !d.SuppressPositiveResponse {
			t.Errorf("case %d: suppress bit lost", i)
		}
		if r.DataIdentifier != nil && (d.DataIdentifier == nil || *d.DataIdentifier != *r.DataIdentifier) {
			t.Errorf("case %d: DID = %v, want %v", i, d.DataIdentifier, r.DataIdentifier)
		}
		if r.NRC != nil && (d.NRC == nil || *d.NRC != *r.NRC) {
			t.Errorf("case %d: nrc = %v, want %v", i, d.NRC, r.NRC)
		}
	}
}

func TestEncode_Errors(t *testing.T) {
	bad := []EncodeRequest{
		{Service: 0x100}, // out of byte range
		{Direction: "negative_response", Service: 0x10}, // missing NRC
		{Service: 0x10, SubFunction: ip(0x80)},          // subfn > 7-bit
		{Service: 0x22, DataIdentifier: ip(0x10000)},    // DID > 16-bit
		{Direction: "bogus", Service: 0x10},             // bad direction
	}
	for i, r := range bad {
		if _, err := Encode(r); err == nil {
			t.Errorf("case %d (%+v): expected error", i, r)
		}
	}
}
