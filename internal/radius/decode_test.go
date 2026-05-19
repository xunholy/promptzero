package radius

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// TestDecode_AccessRequest pins a hand-crafted Access-Request
// packet with User-Name, NAS-IP-Address, NAS-Port, and
// Service-Type attributes.
func TestDecode_AccessRequest(t *testing.T) {
	pkt := buildAccessRequest(t, 0x42, "alice",
		net.ParseIP("192.168.1.1").To4(),
		54321, 2, // Service-Type=Framed
	)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Code != 1 {
		t.Errorf("Code = %d; want 1", got.Code)
	}
	if got.CodeName != "Access-Request" {
		t.Errorf("CodeName = %q", got.CodeName)
	}
	if got.Identifier != 0x42 {
		t.Errorf("Identifier = %d", got.Identifier)
	}
	if len(got.Attributes) != 4 {
		t.Fatalf("Attributes count = %d; want 4", len(got.Attributes))
	}
	// User-Name
	if got.Attributes[0].Name != "User-Name" {
		t.Errorf("Attr[0].Name = %q", got.Attributes[0].Name)
	}
	if got.Attributes[0].String != "alice" {
		t.Errorf("Attr[0].String = %q", got.Attributes[0].String)
	}
	// NAS-IP-Address
	if got.Attributes[1].Name != "NAS-IP-Address" {
		t.Errorf("Attr[1].Name = %q", got.Attributes[1].Name)
	}
	if got.Attributes[1].IPv4 != "192.168.1.1" {
		t.Errorf("Attr[1].IPv4 = %q", got.Attributes[1].IPv4)
	}
	// NAS-Port
	if got.Attributes[2].Name != "NAS-Port" {
		t.Errorf("Attr[2].Name = %q", got.Attributes[2].Name)
	}
	if got.Attributes[2].Uint32 == nil || *got.Attributes[2].Uint32 != 54321 {
		t.Errorf("Attr[2].Uint32 = %v", got.Attributes[2].Uint32)
	}
	// Service-Type
	if got.Attributes[3].Name != "Service-Type" {
		t.Errorf("Attr[3].Name = %q", got.Attributes[3].Name)
	}
	if got.Attributes[3].IntName != "Framed" {
		t.Errorf("Attr[3].IntName = %q; want 'Framed'", got.Attributes[3].IntName)
	}
}

// TestDecode_AccountingRequest pins an Accounting-Request
// with Acct-Status-Type=Start + Acct-Session-Id.
func TestDecode_AccountingRequest(t *testing.T) {
	pkt := buildAccountingRequest(t, 0x99, 1, "session-abc-123")
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CodeName != "Accounting-Request" {
		t.Errorf("CodeName = %q", got.CodeName)
	}
	var statusType, sessionID *Attribute
	for _, a := range got.Attributes {
		switch a.Type {
		case 40:
			statusType = a
		case 44:
			sessionID = a
		}
	}
	if statusType == nil {
		t.Fatal("Acct-Status-Type missing")
	}
	if statusType.IntName != "Start" {
		t.Errorf("Acct-Status-Type.IntName = %q", statusType.IntName)
	}
	if sessionID == nil {
		t.Fatal("Acct-Session-Id missing")
	}
	if sessionID.String != "session-abc-123" {
		t.Errorf("Acct-Session-Id.String = %q", sessionID.String)
	}
}

// TestDecode_AccessAccept pins an Access-Accept response.
func TestDecode_AccessAccept(t *testing.T) {
	// Build manually: Code 2 + Identifier + Length + 16-byte
	// Authenticator + Reply-Message attribute.
	hdr := make([]byte, 20)
	hdr[0] = 2 // Access-Accept
	hdr[1] = 0x42
	msg := "Welcome!"
	attrs := append([]byte{18, byte(2 + len(msg))}, []byte(msg)...)
	totalLen := 20 + len(attrs)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	pkt := append(hdr, attrs...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CodeName != "Access-Accept" {
		t.Errorf("CodeName = %q", got.CodeName)
	}
	if got.Attributes[0].Name != "Reply-Message" {
		t.Errorf("Attr[0].Name = %q", got.Attributes[0].Name)
	}
	if got.Attributes[0].String != "Welcome!" {
		t.Errorf("Attr[0].String = %q", got.Attributes[0].String)
	}
}

// TestDecode_VendorSpecific pins a Vendor-Specific (26)
// attribute with sub-TLVs.
func TestDecode_VendorSpecific(t *testing.T) {
	// Vendor-Id = 9 (Cisco), sub-attr type 1 length 6 value
	// "abcd" = 4 bytes vendor-id + 1+1+4 = 10 bytes
	vid := make([]byte, 4)
	binary.BigEndian.PutUint32(vid, 9)
	sub := append([]byte{1, 6}, []byte("abcd")...)
	body := append(vid, sub...)
	attr := append([]byte{26, byte(2 + len(body))}, body...)
	hdr := make([]byte, 20)
	hdr[0] = 1
	totalLen := 20 + len(attr)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	pkt := append(hdr, attr...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Attributes[0]
	if a.VendorSpecific == nil {
		t.Fatal("VendorSpecific nil")
	}
	if a.VendorSpecific.VendorID != 9 {
		t.Errorf("VendorID = %d", a.VendorSpecific.VendorID)
	}
	if a.VendorSpecific.VendorName != "Cisco Systems" {
		t.Errorf("VendorName = %q", a.VendorSpecific.VendorName)
	}
	if len(a.VendorSpecific.SubAttributes) != 1 {
		t.Fatalf("SubAttributes count = %d", len(a.VendorSpecific.SubAttributes))
	}
	if a.VendorSpecific.SubAttributes[0].DataHex != "61626364" {
		t.Errorf("SubAttr[0].DataHex = %q", a.VendorSpecific.SubAttributes[0].DataHex)
	}
}

// TestDecode_NASPortType pins the NAS-Port-Type integer-enum
// lookup (19 = Wireless-802.11).
func TestDecode_NASPortType(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 1
	npt := []byte{61, 6, 0, 0, 0, 19} // NAS-Port-Type = 19
	totalLen := 20 + len(npt)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	pkt := append(hdr, npt...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Attributes[0]
	if a.IntName != "Wireless-802.11" {
		t.Errorf("IntName = %q; want 'Wireless-802.11'", a.IntName)
	}
}

// TestDecode_EventTimestamp pins the time-attribute conversion
// (attribute 55, 4-byte Unix seconds → RFC 3339).
func TestDecode_EventTimestamp(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 1
	ts := []byte{55, 6, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(ts[2:6], 1700000000) // 2023-11-14
	totalLen := 20 + len(ts)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	pkt := append(hdr, ts...)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := got.Attributes[0]
	if a.TimeUnix == nil || *a.TimeUnix != 1700000000 {
		t.Errorf("TimeUnix = %v", a.TimeUnix)
	}
	if !strings.HasPrefix(a.TimeRFC3339, "2023-11") {
		t.Errorf("TimeRFC3339 = %q", a.TimeRFC3339)
	}
}

// TestDecode_DisconnectRequest pins a CoA / Disconnect code
// from the dynamic-authorization extension (RFC 5176).
func TestDecode_DisconnectRequest(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 40 // Disconnect-Request
	binary.BigEndian.PutUint16(hdr[2:4], 20)
	got, err := DecodeBytes(hdr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CodeName != "Disconnect-Request" {
		t.Errorf("CodeName = %q", got.CodeName)
	}
}

// TestDecode_BadLength rejects packets where declared length
// exceeds buffer.
func TestDecode_BadLength(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 1
	binary.BigEndian.PutUint16(hdr[2:4], 9999)
	if _, err := DecodeBytes(hdr); err == nil {
		t.Error("declared length 9999 > buffer: want error")
	}
}

// TestDecode_TooShort rejects packets < 20 bytes.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("01 02 03 04"); err == nil {
		t.Error("4-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_TruncatedAttribute rejects an attribute whose
// length exceeds the remaining packet.
func TestDecode_TruncatedAttribute(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 1
	// Attribute type 1, length 100 but only 4 bytes follow
	attrs := []byte{1, 100, 0, 0}
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(attrs)))
	pkt := append(hdr, attrs...)
	if _, err := DecodeBytes(pkt); err == nil {
		t.Error("truncated attribute: want error")
	}
}

// TestCodeNameTable spot-checks.
func TestCodeNameTable(t *testing.T) {
	cases := map[int]string{
		1:  "Access-Request",
		2:  "Access-Accept",
		3:  "Access-Reject",
		4:  "Accounting-Request",
		5:  "Accounting-Response",
		11: "Access-Challenge",
		40: "Disconnect-Request",
		43: "CoA-Request",
	}
	for c, want := range cases {
		if got := codeName(c); got != want {
			t.Errorf("codeName(%d) = %q; want %q", c, got, want)
		}
	}
}

// TestAttributeNameTable spot-checks.
func TestAttributeNameTable(t *testing.T) {
	cases := map[int]string{
		1:  "User-Name",
		2:  "User-Password",
		4:  "NAS-IP-Address",
		6:  "Service-Type",
		7:  "Framed-Protocol",
		26: "Vendor-Specific",
		40: "Acct-Status-Type",
		61: "NAS-Port-Type",
		79: "EAP-Message",
		80: "Message-Authenticator",
		97: "Framed-IPv6-Prefix",
	}
	for t1, want := range cases {
		if got := attributeName(t1); got != want {
			t.Errorf("attributeName(%d) = %q; want %q", t1, got, want)
		}
	}
}

// TestServiceTypeTable spot-checks.
func TestServiceTypeTable(t *testing.T) {
	cases := map[uint32]string{
		1: "Login",
		2: "Framed",
		6: "Administrative",
		7: "NAS-Prompt",
	}
	for v, want := range cases {
		if got := serviceTypeName(v); got != want {
			t.Errorf("serviceTypeName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestVendorNameTable spot-checks the SMI PEN lookup.
func TestVendorNameTable(t *testing.T) {
	if got := vendorName(9); got != "Cisco Systems" {
		t.Errorf("vendorName(9) = %q", got)
	}
	if got := vendorName(311); got != "Microsoft" {
		t.Errorf("vendorName(311) = %q", got)
	}
	if got := vendorName(14988); got != "MikroTik" {
		t.Errorf("vendorName(14988) = %q", got)
	}
}

// --- test helpers --------------------------------------------------

func buildAccessRequest(t *testing.T, id byte, userName string, nasIP []byte, nasPort, serviceType uint32) []byte {
	t.Helper()
	hdr := make([]byte, 20)
	hdr[0] = 1 // Access-Request
	hdr[1] = id
	// (length filled in below)

	var attrs []byte
	// User-Name (1)
	attrs = append(attrs, 1, byte(2+len(userName)))
	attrs = append(attrs, []byte(userName)...)
	// NAS-IP-Address (4)
	attrs = append(attrs, 4, 6)
	attrs = append(attrs, nasIP...)
	// NAS-Port (5)
	attrs = append(attrs, 5, 6)
	np := make([]byte, 4)
	binary.BigEndian.PutUint32(np, nasPort)
	attrs = append(attrs, np...)
	// Service-Type (6)
	attrs = append(attrs, 6, 6)
	st := make([]byte, 4)
	binary.BigEndian.PutUint32(st, serviceType)
	attrs = append(attrs, st...)

	totalLen := 20 + len(attrs)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	return append(hdr, attrs...)
}

func buildAccountingRequest(t *testing.T, id byte, statusType uint32, sessionID string) []byte {
	t.Helper()
	hdr := make([]byte, 20)
	hdr[0] = 4 // Accounting-Request
	hdr[1] = id

	var attrs []byte
	// Acct-Status-Type (40)
	attrs = append(attrs, 40, 6)
	stb := make([]byte, 4)
	binary.BigEndian.PutUint32(stb, statusType)
	attrs = append(attrs, stb...)
	// Acct-Session-Id (44)
	attrs = append(attrs, 44, byte(2+len(sessionID)))
	attrs = append(attrs, []byte(sessionID)...)

	totalLen := 20 + len(attrs)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	return append(hdr, attrs...)
}
