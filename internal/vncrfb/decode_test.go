package vncrfb

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDecodeProtocolVersionBanner pins the canonical 12-byte
// version banner.
func TestDecodeProtocolVersionBanner(t *testing.T) {
	for _, v := range []string{"003.003", "003.007", "003.008"} {
		b := []byte("RFB " + v + "\n")
		if len(b) != 12 {
			t.Fatalf("test banner wrong length: %d", len(b))
		}
		r, err := Decode(hex.EncodeToString(b))
		if err != nil {
			t.Fatalf("decode %q: %v", v, err)
		}
		if !r.IsVersionBanner {
			t.Errorf("%q: IsVersionBanner should be true", v)
		}
		if r.ProtocolVersion != v {
			t.Errorf("%q: ProtocolVersion got %q", v, r.ProtocolVersion)
		}
	}
}

// TestDecodeSecurityTypesListNoAuth pins the canonical
// "exposed-without-auth" shape.
func TestDecodeSecurityTypesListNoAuth(t *testing.T) {
	// 1 byte count=1 + 1 byte type=1 (None)
	b := []byte{0x01, 0x01}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.HasSecurityTypes {
		t.Errorf("HasSecurityTypes should be true")
	}
	if len(r.SecurityTypes) != 1 || r.SecurityTypes[0] != 1 {
		t.Errorf("SecurityTypes: got %v want [1]", r.SecurityTypes)
	}
	if !strings.Contains(r.SecurityTypesNames[0],
		"NO AUTHENTICATION REQUIRED") {
		t.Errorf("Type 1 should flag no-auth-exposed: %q",
			r.SecurityTypesNames[0])
	}
}

// TestDecodeSecurityTypesListVNCAuth pins the weak DES classifier.
func TestDecodeSecurityTypesListVNCAuth(t *testing.T) {
	// 1 count + type=2 (VNC Authentication)
	b := []byte{0x01, 0x02}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.SecurityTypesNames[0], "DES") {
		t.Errorf("Type 2 should flag DES: %q", r.SecurityTypesNames[0])
	}
	if !strings.Contains(r.SecurityTypesNames[0], "26200") {
		t.Errorf("Type 2 should reference hashcat mode 26200: %q",
			r.SecurityTypesNames[0])
	}
}

// TestDecodeSecurityTypesListMultiple pins a typical modern
// RealVNC/TigerVNC handshake (None + VNC + TLS + VeNCrypt).
func TestDecodeSecurityTypesListMultiple(t *testing.T) {
	b := []byte{0x04, 0x01, 0x02, 0x12, 0x13}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.SecurityTypes) != 4 {
		t.Errorf("SecurityTypes count: got %d want 4",
			len(r.SecurityTypes))
	}
	// Check that VeNCrypt (19) is recognized
	hasVeNCrypt := false
	for _, n := range r.SecurityTypesNames {
		if strings.Contains(n, "VeNCrypt") {
			hasVeNCrypt = true
		}
	}
	if !hasVeNCrypt {
		t.Errorf("Should recognize VeNCrypt: %v", r.SecurityTypesNames)
	}
}

// TestDecodeSecurityTypesListAppleARD pins the macOS ARD
// detection.
func TestDecodeSecurityTypesListAppleARD(t *testing.T) {
	b := []byte{0x01, 30}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.SecurityTypesNames[0],
		"Apple Remote Desktop") {
		t.Errorf("Type 30 should flag Apple Remote Desktop: %q",
			r.SecurityTypesNames[0])
	}
}

// TestDecodeRFB33SingleSecurityType pins the legacy single-
// type form.
func TestDecodeRFB33SingleSecurityType(t *testing.T) {
	// 4-byte BE type=2 (VNC Auth) — RFB 3.3 form
	b := []byte{0x00, 0x00, 0x00, 0x02}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsRFB33 {
		t.Errorf("IsRFB33 should be true")
	}
	if r.SecurityTypes[0] != 2 {
		t.Errorf("SecurityTypes[0]: got %d want 2", r.SecurityTypes[0])
	}
}

// TestDecodeSecurityTypeInvalidWithReason pins the canonical
// "deny" response shape.
func TestDecodeSecurityTypeInvalidWithReason(t *testing.T) {
	reason := "Too many security failures"
	b := []byte{0x00}
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(reason)))
	b = append(b, lenBytes...)
	b = append(b, []byte(reason)...)
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SecurityInvalidReason != reason {
		t.Errorf("SecurityInvalidReason: got %q want %q",
			r.SecurityInvalidReason, reason)
	}
}

// TestDecodeSecurityResultOK pins the canonical authentication-
// success response.
func TestDecodeSecurityResultOK(t *testing.T) {
	b := []byte{0x00, 0x00, 0x00, 0x00}
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.HasSecurityResult {
		t.Errorf("HasSecurityResult should be true")
	}
	if r.SecurityResultFailed {
		t.Errorf("Result 0 should not be Failed")
	}
}

// TestDecodeSecurityResultFailedWithReason pins the canonical
// brute-force feedback shape.
func TestDecodeSecurityResultFailedWithReason(t *testing.T) {
	reason := "Authentication failure"
	b := []byte{0x00, 0x00, 0x00, 0x01}
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(reason)))
	b = append(b, lenBytes...)
	b = append(b, []byte(reason)...)
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.SecurityResultFailed {
		t.Errorf("SecurityResultFailed should be true")
	}
	if r.SecurityFailureReason != reason {
		t.Errorf("SecurityFailureReason: got %q want %q",
			r.SecurityFailureReason, reason)
	}
}

// TestDecodeServerInit pins the canonical hostname-disclosure
// shape.
func TestDecodeServerInit(t *testing.T) {
	desktopName := "Administrator's Mac"
	b := make([]byte, 24+len(desktopName))
	binary.BigEndian.PutUint16(b[0:2], 1920) // width
	binary.BigEndian.PutUint16(b[2:4], 1080) // height
	b[4] = 32                                // bpp
	b[5] = 24                                // depth
	b[6] = 0                                 // big-endian-flag = false
	b[7] = 1                                 // true-colour-flag = true
	binary.BigEndian.PutUint32(b[20:24], uint32(len(desktopName)))
	copy(b[24:], []byte(desktopName))
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.HasServerInit {
		t.Errorf("HasServerInit should be true")
	}
	if r.FramebufferWidth != 1920 {
		t.Errorf("Width: got %d want 1920", r.FramebufferWidth)
	}
	if r.FramebufferHeight != 1080 {
		t.Errorf("Height: got %d want 1080", r.FramebufferHeight)
	}
	if r.BitsPerPixel != 32 {
		t.Errorf("BitsPerPixel: got %d want 32", r.BitsPerPixel)
	}
	if r.Depth != 24 {
		t.Errorf("Depth: got %d want 24", r.Depth)
	}
	if !r.TrueColourFlag {
		t.Errorf("TrueColourFlag should be true")
	}
	if r.DesktopName != desktopName {
		t.Errorf("DesktopName: got %q want %q", r.DesktopName, desktopName)
	}
}

// TestSecurityTypeNameTable spot-checks each catalogued type.
func TestSecurityTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "Invalid",
		1:  "NO AUTHENTICATION REQUIRED",
		2:  "DES",
		5:  "RA2",
		6:  "RA2ne",
		16: "Tight",
		17: "Ultra",
		18: "TLS",
		19: "VeNCrypt",
		20: "SASL",
		21: "MD5 hash",
		22: "xvp",
		30: "Apple Remote Desktop",
	}
	for k, marker := range cases {
		got := securityTypeName(k)
		if !strings.Contains(got, marker) {
			t.Errorf("securityTypeName(%d) = %q want contains %q",
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
