// SPDX-License-Identifier: AGPL-3.0-or-later

package kwp

import "testing"

func ip(v int) *int { return &v }

func TestEncode_RequestFixedBytes(t *testing.T) {
	cases := []struct {
		name string
		req  EncodeRequest
		hex  string
	}{
		{"rdbli", EncodeRequest{Service: 0x21, Param: ip(0x01)}, "2101"},
		{"start-comm", EncodeRequest{Service: 0x81}, "81"},
		{"session", EncodeRequest{Service: 0x10, Param: ip(0x85)}, "1085"},
		{"wdbli", EncodeRequest{Service: 0x3B, Param: ip(0x05), Payload: []byte{0x12}}, "3B0512"},
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
	got, err := EncodeHex(EncodeRequest{Direction: "negative_response", Service: 0x21, NRC: ip(0x31)})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != "7F2131" {
		t.Errorf("neg = %s, want 7F2131", got)
	}
}

func TestEncode_PositiveResponse(t *testing.T) {
	// positive response to 0x21 -> 0x61.
	got, err := EncodeHex(EncodeRequest{Direction: "positive_response", Service: 0x21, Param: ip(0x01), Payload: []byte{0xAA, 0xBB}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != "6101AABB" {
		t.Errorf("pos = %s, want 6101AABB", got)
	}
}

// TestEncode_RoundTrip closes correctness against the decoder.
func TestEncode_RoundTrip(t *testing.T) {
	reqs := []EncodeRequest{
		{Service: 0x21, Param: ip(0x01)},
		{Service: 0x81},
		{Service: 0x3B, Param: ip(0x05), Payload: []byte{0x12, 0x34}},
		{Direction: "negative_response", Service: 0x10, NRC: ip(0x78)},
		{Direction: "positive_response", Service: 0x21, Param: ip(0x02), Payload: []byte{0xDE}},
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
		if r.Param != nil && d.ParamByte != nil && *d.ParamByte != *r.Param {
			t.Errorf("case %d: param = %v, want %v", i, *d.ParamByte, *r.Param)
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
		{Service: 0x21, Param: ip(0x100)},               // param out of byte range
		{Direction: "bogus", Service: 0x10},             // bad direction
	}
	for i, r := range bad {
		if _, err := Encode(r); err == nil {
			t.Errorf("case %d (%+v): expected error", i, r)
		}
	}
}
