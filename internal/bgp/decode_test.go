package bgp

import (
	"strings"
	"testing"
)

const validMarker = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

func TestDecode_Keepalive(t *testing.T) {
	// 16-byte all-FFs marker, Length 19, Type 4.
	in := validMarker + "0013 04"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "KEEPALIVE" {
		t.Errorf("type: %q", r.TypeName)
	}
	if !r.MarkerValid {
		t.Errorf("marker should be valid")
	}
	if r.Keepalive == nil {
		t.Fatal("Keepalive nil")
	}
	if len(r.Notes) != 0 {
		t.Errorf("expected no notes, got %v", r.Notes)
	}
}

func TestDecode_Open(t *testing.T) {
	// OPEN: Version 4, MyAS 64512 (0xFC00), Hold Time 180,
	// BGP ID 192.168.1.1, no optional params.
	body := "04 FC00 00B4 C0A80101 00"
	in := validMarker + "001D 01" + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "OPEN" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.Open == nil {
		t.Fatal("Open nil")
	}
	if r.Open.Version != 4 || r.Open.MyAS != 64512 || r.Open.HoldTime != 180 {
		t.Errorf("OPEN fields: %+v", r.Open)
	}
	if r.Open.BGPIdentifier != "192.168.1.1" {
		t.Errorf("BGP identifier: %q", r.Open.BGPIdentifier)
	}
	if r.Open.OptParamLen != 0 {
		t.Errorf("opt param len: %d", r.Open.OptParamLen)
	}
}

func TestDecode_Open_WithMPBGPCapability(t *testing.T) {
	// OPEN with one Capability (MP-BGP, AFI IPv4, SAFI unicast).
	// Optional Param: type=2 (Capabilities), length=6.
	// Capability: code=1 (MP-BGP), length=4, value = 0001 00 01.
	body := "04 FC00 00B4 C0A80101 08 02 06 01 04 0001 00 01"
	in := validMarker + "0025 01" + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Open == nil || len(r.Open.OptParameters) != 1 {
		t.Fatalf("opt params: %+v", r.Open)
	}
	op := r.Open.OptParameters[0]
	if op.TypeName != "Capabilities (RFC 5492)" {
		t.Errorf("opt param type: %q", op.TypeName)
	}
	if len(op.Capabilities) != 1 {
		t.Fatalf("expected 1 capability, got %d", len(op.Capabilities))
	}
	cap := op.Capabilities[0]
	if cap.CodeName != "Multiprotocol Extensions (MP-BGP, RFC 4760)" {
		t.Errorf("capability name: %q", cap.CodeName)
	}
}

func TestDecode_Notification_CeaseAdminShutdown(t *testing.T) {
	// NOTIFICATION: Error Code 6 (Cease), Subcode 2 (Admin Shutdown).
	body := "06 02"
	in := validMarker + "0015 03" + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Notification == nil {
		t.Fatal("Notification nil")
	}
	if r.Notification.ErrorCodeName != "Cease (RFC 4486)" {
		t.Errorf("error code: %q", r.Notification.ErrorCodeName)
	}
	if r.Notification.ErrorSubcodeName != "Administrative Shutdown" {
		t.Errorf("error subcode: %q", r.Notification.ErrorSubcodeName)
	}
}

func TestDecode_RouteRefresh(t *testing.T) {
	// AFI IPv4, Reserved 0, SAFI unicast.
	body := "0001 00 01"
	in := validMarker + "0017 05" + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.RouteRefresh == nil {
		t.Fatal("RouteRefresh nil")
	}
	if r.RouteRefresh.AFIName != "IPv4" {
		t.Errorf("AFI: %q", r.RouteRefresh.AFIName)
	}
	if r.RouteRefresh.SAFIName != "unicast" {
		t.Errorf("SAFI: %q", r.RouteRefresh.SAFIName)
	}
}

func TestDecode_Update_MinimalIPv4(t *testing.T) {
	// UPDATE: 0 withdrawn, 1 ORIGIN attribute, 1 NLRI 10.0.0.0/8.
	body := "0000 0004 40 01 01 00 08 0A"
	in := validMarker + "001F 02" + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Update == nil {
		t.Fatal("Update nil")
	}
	if r.Update.WithdrawnRoutesLength != 0 {
		t.Errorf("withdrawn len: %d", r.Update.WithdrawnRoutesLength)
	}
	if len(r.Update.PathAttributes) != 1 {
		t.Fatalf("expected 1 PA, got %d", len(r.Update.PathAttributes))
	}
	pa := r.Update.PathAttributes[0]
	if pa.TypeName != "ORIGIN" {
		t.Errorf("PA name: %q", pa.TypeName)
	}
	if len(r.Update.NLRI) != 1 {
		t.Fatalf("expected 1 NLRI, got %d", len(r.Update.NLRI))
	}
	if r.Update.NLRI[0].PrefixLength != 8 {
		t.Errorf("prefix length: %d", r.Update.NLRI[0].PrefixLength)
	}
	if r.Update.NLRI[0].IPv4 != "10.0.0.0/8" {
		t.Errorf("IPv4: %q", r.Update.NLRI[0].IPv4)
	}
}

func TestDecode_Update_MultipleAttributes(t *testing.T) {
	// ORIGIN + AS_PATH (empty) + NEXT_HOP 192.168.1.1.
	body := "0000 000E 40 01 01 00 40 02 00 40 03 04 C0A80101 08 0A"
	in := validMarker + "0027 02" + body
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Update.PathAttributes) != 3 {
		t.Fatalf("expected 3 PAs, got %d", len(r.Update.PathAttributes))
	}
	wantNames := []string{"ORIGIN", "AS_PATH", "NEXT_HOP"}
	for i, want := range wantNames {
		if r.Update.PathAttributes[i].TypeName != want {
			t.Errorf("PA %d: got %q want %q",
				i, r.Update.PathAttributes[i].TypeName, want)
		}
	}
}

func TestDecode_MarkerInvalid_Note(t *testing.T) {
	// All-zero marker (invalid per RFC 4271 §4.1).
	in := "00000000000000000000000000000000 0013 04"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MarkerValid {
		t.Errorf("marker should be flagged invalid")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Marker bytes") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected marker-invalid note in: %v", r.Notes)
	}
}

func TestDecode_TypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION",
		4: "KEEPALIVE", 5: "ROUTE-REFRESH",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_CapabilityCodeTable(t *testing.T) {
	cases := map[int]string{
		1:  "Multiprotocol Extensions (MP-BGP, RFC 4760)",
		2:  "Route Refresh (RFC 2918)",
		64: "Graceful Restart (RFC 4724)",
		65: "4-byte AS Number (RFC 6793)",
		70: "Enhanced Route Refresh (RFC 7313)",
	}
	for k, v := range cases {
		if got := capabilityCodeName(k); got != v {
			t.Errorf("capabilityCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_PathAttributeTypeTable(t *testing.T) {
	cases := map[int]string{
		1:  "ORIGIN",
		2:  "AS_PATH",
		3:  "NEXT_HOP",
		4:  "MULTI_EXIT_DISC (MED)",
		5:  "LOCAL_PREF",
		8:  "COMMUNITY (RFC 1997)",
		14: "MP_REACH_NLRI (RFC 4760)",
		32: "LARGE_COMMUNITY (RFC 8092)",
	}
	for k, v := range cases {
		if got := pathAttributeTypeName(k); got != v {
			t.Errorf("pathAttributeTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":       "",
		"odd hex":     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0013 0",
		"short":       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0013",
		"length < 19": validMarker + "0010 04",
		"bad hex":     "ZZFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0013 04",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
