package coap

import (
	"testing"
)

// TestDecode_GETRequest pins a typical CoAP GET request:
//
//	Version=1, Type=Confirmable, TKL=0
//	Code=GET (0x01)
//	Message ID = 0x1234
//	Uri-Path option = "sensors"
//	No payload
//
// Wire bytes:
//
//	40 01 12 34         (header: ver=1, type=0, TKL=0, code=GET, msgID=0x1234)
//	B7 73 65 6E 73 6F 72 73  (option: delta=11 → Uri-Path,
//	                           length=7, value "sensors")
func TestDecode_GETRequest(t *testing.T) {
	hex := "40 01 12 34 B7 73 65 6E 73 6F 72 73"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.Version != 1 {
		t.Errorf("Version = %d; want 1", got.Header.Version)
	}
	if got.Header.TypeName != "Confirmable" {
		t.Errorf("TypeName = %q", got.Header.TypeName)
	}
	if got.Header.CodeName != "GET" {
		t.Errorf("CodeName = %q; want 'GET'", got.Header.CodeName)
	}
	if got.Header.CodeText != "0.01" {
		t.Errorf("CodeText = %q; want '0.01'", got.Header.CodeText)
	}
	if got.Header.MessageID != 0x1234 {
		t.Errorf("MessageID = 0x%X; want 0x1234", got.Header.MessageID)
	}
	if len(got.Options) != 1 {
		t.Fatalf("Options count = %d; want 1", len(got.Options))
	}
	opt := got.Options[0]
	if opt.Name != "Uri-Path" {
		t.Errorf("Option name = %q", opt.Name)
	}
	if opt.ValueString != "sensors" {
		t.Errorf("Option value = %q", opt.ValueString)
	}
}

// TestDecode_2_05ContentResponse pins a 2.05 Content response
// with payload.
//
//	Version=1, Type=Acknowledgement, TKL=2
//	Code=2.05 Content (0x45)
//	Message ID = 0x5678
//	Token = AA BB
//	Content-Format option = 50 (application/json)
//	0xFF payload marker
//	Payload = {"v":42}
func TestDecode_2_05ContentResponse(t *testing.T) {
	hex := "62 45 56 78 AA BB " + // header + token
		"C1 32 " + // option: delta=12 (Content-Format), length=1, value=0x32=50
		"FF " + // payload marker
		"7B 22 76 22 3A 34 32 7D" // {"v":42}
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.TypeName != "Acknowledgement" {
		t.Errorf("TypeName = %q", got.Header.TypeName)
	}
	if got.Header.CodeText != "2.05" {
		t.Errorf("CodeText = %q; want '2.05'", got.Header.CodeText)
	}
	if got.TokenHex != "AABB" {
		t.Errorf("TokenHex = %q", got.TokenHex)
	}
	if len(got.Options) != 1 {
		t.Fatalf("Options count = %d", len(got.Options))
	}
	opt := got.Options[0]
	if opt.Name != "Content-Format" {
		t.Errorf("Option name = %q", opt.Name)
	}
	if opt.ValueUint == nil || *opt.ValueUint != 50 {
		t.Errorf("Content-Format value = %v; want 50", opt.ValueUint)
	}
	if got.PayloadString != `{"v":42}` {
		t.Errorf("PayloadString = %q", got.PayloadString)
	}
}

// TestDecode_4_04NotFound pins a Not Found response.
func TestDecode_4_04NotFound(t *testing.T) {
	// Type=Acknowledgement (2 << 4 = 0x20), TKL=0, Code=0x84
	// (4.04 Not Found), Message ID=0x0001
	got, err := Decode("60 84 00 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.CodeName != "Not Found (4.04)" {
		t.Errorf("CodeName = %q", got.Header.CodeName)
	}
	if got.Header.CodeText != "4.04" {
		t.Errorf("CodeText = %q", got.Header.CodeText)
	}
}

// TestDecode_OptionExtensionDelta pins option delta extension
// encoding. Delta nibble 13 = +1 byte extension that adds 13.
// So a delta nibble of 13 with extension byte 50 → actual
// delta = 50 + 13 = 63.
func TestDecode_OptionExtensionDelta(t *testing.T) {
	// Header: 40 01 00 01
	// Option: D2 50 AA BB
	//   nibble1=13 (delta extension), nibble2=2 (length)
	//   extension byte 0x50 = 80 → delta = 80 + 13 = 93
	//   length = 2 → 2-byte value AA BB
	got, err := Decode("40 01 00 01 D2 50 AA BB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Options) != 1 {
		t.Fatalf("Options count = %d", len(got.Options))
	}
	if got.Options[0].Number != 93 {
		t.Errorf("Option Number = %d; want 93", got.Options[0].Number)
	}
	if got.Options[0].ValueHex != "AABB" {
		t.Errorf("Option ValueHex = %q", got.Options[0].ValueHex)
	}
}

// TestDecode_MultipleUriPathOptions — multiple Uri-Path options
// chain via delta-zero subsequent options.
func TestDecode_MultipleUriPathOptions(t *testing.T) {
	// Header: 40 01 00 01
	// Option 1: B7 + "sensors" (delta=11 → Uri-Path)
	// Option 2: 02 + "fo" (delta=0 → still Uri-Path, length=2)
	got, err := Decode("40 01 00 01 B7 73 65 6E 73 6F 72 73 02 66 6F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Options) != 2 {
		t.Fatalf("Options count = %d; want 2", len(got.Options))
	}
	for i, opt := range got.Options {
		if opt.Name != "Uri-Path" {
			t.Errorf("Options[%d].Name = %q", i, opt.Name)
		}
	}
	if got.Options[0].ValueString != "sensors" {
		t.Errorf("Options[0].ValueString = %q", got.Options[0].ValueString)
	}
	if got.Options[1].ValueString != "fo" {
		t.Errorf("Options[1].ValueString = %q", got.Options[1].ValueString)
	}
}

// TestDecode_NoOptions exercises a packet with only a header
// (no options, no payload).
func TestDecode_NoOptions(t *testing.T) {
	// Type=Reset, TKL=0, Code=Empty (0), Message ID=0x0042
	got, err := Decode("70 00 00 42")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Header.TypeName != "Reset" {
		t.Errorf("TypeName = %q", got.Header.TypeName)
	}
	if got.Header.CodeName != "Empty" {
		t.Errorf("CodeName = %q", got.Header.CodeName)
	}
	if len(got.Options) != 0 {
		t.Errorf("Options count = %d; want 0", len(got.Options))
	}
}

// TestDecode_PayloadWithoutOptions — packet with token + payload
// marker + payload, no options.
func TestDecode_PayloadWithoutOptions(t *testing.T) {
	// Header: 41 (TKL=1) 02 (POST) 00 01 (msgID)
	// Token: AA
	// Payload marker: FF
	// Payload: 31 32 33 ("123")
	got, err := Decode("41 02 00 01 AA FF 31 32 33")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TokenHex != "AA" {
		t.Errorf("TokenHex = %q", got.TokenHex)
	}
	if got.PayloadString != "123" {
		t.Errorf("PayloadString = %q", got.PayloadString)
	}
}

// TestDecode_TruncatedHeader — packet shorter than 4 bytes.
func TestDecode_TruncatedHeader(t *testing.T) {
	if _, err := Decode("40 01"); err == nil {
		t.Error("want error for short header")
	}
}

// TestDecode_InvalidTKL — TKL > 8 is reserved.
func TestDecode_InvalidTKL(t *testing.T) {
	// TKL=9 (invalid) → byte 0 = 0x49
	if _, err := Decode("49 01 00 01"); err == nil {
		t.Error("want error for TKL > 8")
	}
}

// TestDecode_TruncatedToken — TKL declares more bytes than
// available.
func TestDecode_TruncatedToken(t *testing.T) {
	// TKL=4 but no token bytes follow header
	if _, err := Decode("44 01 00 01"); err == nil {
		t.Error("want error for truncated token")
	}
}

// TestDecode_TruncatedOptionValue — option length exceeds
// remaining buffer.
func TestDecode_TruncatedOptionValue(t *testing.T) {
	// Header: 40 01 00 01
	// Option: B7 (delta=11, length=7) but only 2 bytes follow
	if _, err := Decode("40 01 00 01 B7 AA BB"); err == nil {
		t.Error("want error for truncated option value")
	}
}

// TestDecode_BadInput — empty / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_AllRequestMethods spot-checks the documented
// request method codes.
func TestDecode_AllRequestMethods(t *testing.T) {
	cases := map[byte]string{
		0x01: "GET",
		0x02: "POST",
		0x03: "PUT",
		0x04: "DELETE",
		0x05: "FETCH",
		0x06: "PATCH",
		0x07: "iPATCH",
	}
	for code, want := range cases {
		if got := codeName(int(code)); got != want {
			t.Errorf("codeName(0x%02X) = %q; want %q", code, got, want)
		}
	}
}

// TestDecode_TypeNames spot-checks all 4 type names.
func TestTypeNames(t *testing.T) {
	cases := map[Type]string{
		TypeConfirmable:     "Confirmable",
		TypeNonConfirmable:  "Non-Confirmable",
		TypeAcknowledgement: "Acknowledgement",
		TypeReset:           "Reset",
	}
	for t2, want := range cases {
		if got := t2.String(); got != want {
			t.Errorf("Type(%d).String() = %q; want %q", t2, got, want)
		}
	}
}

// TestOptionNames spot-checks the documented option name table.
func TestOptionNames(t *testing.T) {
	cases := map[int]string{
		3:  "Uri-Host",
		7:  "Uri-Port",
		11: "Uri-Path",
		12: "Content-Format",
		15: "Uri-Query",
		17: "Accept",
		35: "Proxy-Uri",
		60: "Size1",
	}
	for n, want := range cases {
		if got := optionName(n); got != want {
			t.Errorf("optionName(%d) = %q; want %q", n, got, want)
		}
	}
}
