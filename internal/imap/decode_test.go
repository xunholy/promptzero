package imap

import (
	"encoding/hex"
	"strings"
	"testing"
)

// hexify converts an ASCII IMAP message to hex for feeding
// the hex-input decoder.
func hexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestDecodeBanner pins the canonical * OK greeting — the
// MTA banner-fingerprinting goldmine.
func TestDecodeBanner(t *testing.T) {
	msg := "* OK Dovecot (Ubuntu) ready.\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindUntaggedResp {
		t.Errorf("kind: got %q want Untagged_Response", r.Kind)
	}
	if r.UntaggedType != "OK" {
		t.Errorf("untagged type: got %q want OK", r.UntaggedType)
	}
	if r.UntaggedData != "Dovecot (Ubuntu) ready." {
		t.Errorf("untagged data: got %q", r.UntaggedData)
	}
}

// TestDecodeCapabilityResponse pins an untagged CAPABILITY
// response that exposes STARTTLS + AUTH mechanisms.
func TestDecodeCapabilityResponse(t *testing.T) {
	msg := "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5 IDLE NAMESPACE\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.UntaggedType != "CAPABILITY" {
		t.Errorf("type: got %q want CAPABILITY", r.UntaggedType)
	}
	if !strings.Contains(r.UntaggedData, "STARTTLS") {
		t.Errorf("data missing STARTTLS: %q", r.UntaggedData)
	}
	if !strings.Contains(r.UntaggedData, "AUTH=PLAIN") {
		t.Errorf("data missing AUTH=PLAIN: %q", r.UntaggedData)
	}
}

// TestDecodeLoginCommand pins the canonical cleartext-creds
// command (before STARTTLS!).
func TestDecodeLoginCommand(t *testing.T) {
	msg := "a001 LOGIN admin hunter2\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindCommand {
		t.Errorf("kind: got %q want Command", r.Kind)
	}
	if r.Tag != "a001" {
		t.Errorf("tag: got %q want a001", r.Tag)
	}
	if r.Verb != "LOGIN" {
		t.Errorf("verb: got %q want LOGIN", r.Verb)
	}
	if r.Argument != "admin hunter2" {
		t.Errorf("argument: got %q", r.Argument)
	}
}

// TestDecodeTaggedOKResponse pins a tagged OK that pairs with
// the LOGIN above (matching tag).
func TestDecodeTaggedOKResponse(t *testing.T) {
	msg := "a001 OK Logged in.\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindTaggedResp {
		t.Errorf("kind: got %q want Tagged_Response", r.Kind)
	}
	if r.Tag != "a001" {
		t.Errorf("tag: got %q want a001", r.Tag)
	}
	if r.Status != "OK" {
		t.Errorf("status: got %q want OK", r.Status)
	}
	if r.StatusText != "Logged in." {
		t.Errorf("status text: got %q", r.StatusText)
	}
}

// TestDecodeTaggedNOResponse pins a tagged NO — the brute-
// force feedback signal.
func TestDecodeTaggedNOResponse(t *testing.T) {
	msg := "a002 NO Authentication failed.\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Status != "NO" {
		t.Errorf("status: got %q want NO", r.Status)
	}
	if !strings.Contains(r.StatusText, "Authentication failed") {
		t.Errorf("status text: got %q", r.StatusText)
	}
}

// TestDecodeSelectCommand pins the SELECT mailbox-open command.
func TestDecodeSelectCommand(t *testing.T) {
	msg := "a003 SELECT INBOX\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "SELECT" {
		t.Errorf("verb: got %q want SELECT", r.Verb)
	}
	if r.Argument != "INBOX" {
		t.Errorf("argument: got %q want INBOX", r.Argument)
	}
}

// TestDecodeFetchCommand pins FETCH — the canonical content-
// disclosure command.
func TestDecodeFetchCommand(t *testing.T) {
	msg := "a004 UID FETCH 1:* BODY[]\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "UID" {
		t.Errorf("verb: got %q want UID", r.Verb)
	}
	if r.Argument != "FETCH 1:* BODY[]" {
		t.Errorf("argument: got %q", r.Argument)
	}
}

// TestDecodeAuthenticateContinuation pins the SASL '+' server
// challenge.
func TestDecodeAuthenticateContinuation(t *testing.T) {
	msg := "+ UGFzc3dvcmQ6\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindContinuation {
		t.Errorf("kind: got %q want Continuation", r.Kind)
	}
	if r.ContinuationPrompt != "UGFzc3dvcmQ6" {
		t.Errorf("prompt: got %q want UGFzc3dvcmQ6", r.ContinuationPrompt)
	}
}

// TestDecodeStarttlsCommand pins the TLS upgrade trigger.
func TestDecodeStarttlsCommand(t *testing.T) {
	msg := "a005 STARTTLS\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "STARTTLS" {
		t.Errorf("verb: got %q want STARTTLS", r.Verb)
	}
}

// TestDecodeExistsUntagged pins the "* 12 EXISTS" numeric-
// prefix untagged form.
func TestDecodeExistsUntagged(t *testing.T) {
	msg := "* 12 EXISTS\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.UntaggedType != "12" {
		t.Errorf("type: got %q want 12 (numeric prefix)", r.UntaggedType)
	}
	if !strings.HasPrefix(r.UntaggedTypeName, "numeric_prefix") {
		t.Errorf("type name should flag numeric prefix: %q", r.UntaggedTypeName)
	}
	if r.UntaggedData != "EXISTS" {
		t.Errorf("data: got %q want EXISTS", r.UntaggedData)
	}
}

// TestDecodeListResponse pins an untagged LIST with attributes.
func TestDecodeListResponse(t *testing.T) {
	msg := "* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.UntaggedType != "LIST" {
		t.Errorf("type: got %q want LIST", r.UntaggedType)
	}
}

// TestDecodeByeResponse pins server-side connection-close
// indication.
func TestDecodeByeResponse(t *testing.T) {
	msg := "* BYE IMAP4rev1 Server logging out\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.UntaggedType != "BYE" {
		t.Errorf("type: got %q want BYE", r.UntaggedType)
	}
}

// TestClassifyFirstLine covers each kind boundary.
func TestClassifyFirstLine(t *testing.T) {
	cases := map[string]MessageKind{
		"* OK greeting":   KindUntaggedResp,
		"a001 OK ok":      KindTaggedResp,
		"a001 NO no":      KindTaggedResp,
		"a001 BAD bad":    KindTaggedResp,
		"a001 BYE bye":    KindTaggedResp,
		"a001 PREAUTH p":  KindTaggedResp,
		"a001 LOGIN x y":  KindCommand,
		"a001 SELECT box": KindCommand,
		"+ challenge":     KindContinuation,
		"":                KindUnknown,
		"~?invalid":       KindUnknown,
	}
	for in, want := range cases {
		if got := classifyFirstLine(in); got != want {
			t.Errorf("classifyFirstLine(%q) = %q want %q", in, got, want)
		}
	}
}

// TestIsStatusToken covers the 5-entry status table.
func TestIsStatusToken(t *testing.T) {
	for _, s := range []string{"OK", "NO", "BAD", "BYE", "PREAUTH",
		"ok", "no", "bad", "bye", "preauth"} {
		if !isStatusToken(s) {
			t.Errorf("isStatusToken(%q) = false want true", s)
		}
	}
	if isStatusToken("OOPS") {
		t.Errorf("isStatusToken(OOPS) should be false")
	}
}

// TestVerbNameTable spot-checks key catalogued verbs.
func TestVerbNameTable(t *testing.T) {
	if !strings.Contains(verbName("LOGIN"), "cleartext credentials") {
		t.Errorf("LOGIN name should flag cleartext-creds risk")
	}
	if !strings.Contains(verbName("FETCH"), "content disclosure") {
		t.Errorf("FETCH name should flag content-disclosure risk")
	}
	if !strings.Contains(verbName("STARTTLS"), "TLS upgrade") {
		t.Errorf("STARTTLS name should flag TLS upgrade")
	}
	if !strings.HasPrefix(verbName("BOGUS"), "uncatalogued") {
		t.Errorf("uncatalogued verb should be flagged")
	}
}

// TestUntaggedTypeNameTable spot-checks key catalogued types.
func TestUntaggedTypeNameTable(t *testing.T) {
	cases := map[string]string{
		"OK":         "Status_OK",
		"NO":         "Status_NO",
		"BAD":        "Status_BAD",
		"BYE":        "Status_BYE",
		"CAPABILITY": "CAPABILITY",
		"FETCH":      "FETCH",
		"EXISTS":     "EXISTS",
		"EXPUNGE":    "EXPUNGE",
	}
	for k, v := range cases {
		if got := untaggedTypeName(k); got != v {
			t.Errorf("untaggedTypeName(%q) = %q want %q", k, got, v)
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

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZZZ"); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
