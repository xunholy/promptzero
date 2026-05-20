package rtsp

import (
	"encoding/hex"
	"strings"
	"testing"
)

// hexify converts an ASCII RTSP message to hex (test helper —
// mirrors operator workflow of pasting bytes from a packet
// capture).
func hexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestDecodeOptionsRequest pins the canonical OPTIONS probe —
// the first request an IP-camera enumeration tool sends.
func TestDecodeOptionsRequest(t *testing.T) {
	msg := "OPTIONS rtsp://192.168.1.100:554/Streaming/Channels/101 RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"User-Agent: PromptZero-IPCam/1.0\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindRequest {
		t.Errorf("kind: got %q want Request", r.Kind)
	}
	if r.Method != "OPTIONS" {
		t.Errorf("method: got %q want OPTIONS", r.Method)
	}
	if !strings.Contains(r.URL, "Streaming/Channels/101") {
		t.Errorf("url: got %q", r.URL)
	}
	if r.Version != "RTSP/1.0" {
		t.Errorf("version: got %q want RTSP/1.0", r.Version)
	}
	if r.CSeq != "1" {
		t.Errorf("cseq: got %q want 1", r.CSeq)
	}
	if r.UserAgent != "PromptZero-IPCam/1.0" {
		t.Errorf("user-agent: got %q", r.UserAgent)
	}
}

// TestDecodeOptions200Response pins the canonical 200 OK
// response with Public method advertisement — the
// fingerprinting goldmine.
func TestDecodeOptions200Response(t *testing.T) {
	msg := "RTSP/1.0 200 OK\r\n" +
		"CSeq: 1\r\n" +
		"Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER\r\n" +
		"Server: H3C IPCam Server/1.0\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindResponse {
		t.Errorf("kind: got %q want Response", r.Kind)
	}
	if r.StatusCode != 200 {
		t.Errorf("status: got %d want 200", r.StatusCode)
	}
	if r.StatusCategory != "Success" {
		t.Errorf("category: got %q want Success", r.StatusCategory)
	}
	if !strings.Contains(r.Public, "DESCRIBE") {
		t.Errorf("public: got %q", r.Public)
	}
	if r.Server != "H3C IPCam Server/1.0" {
		t.Errorf("server: got %q", r.Server)
	}
}

// TestDecodeUnauthorizedWithDigest pins the 401 + Digest
// WWW-Authenticate response — the canonical credentials-harvest
// surface.
func TestDecodeUnauthorizedWithDigest(t *testing.T) {
	msg := "RTSP/1.0 401 Unauthorized\r\n" +
		"CSeq: 2\r\n" +
		"WWW-Authenticate: Digest realm=\"IPCamera\", " +
		"nonce=\"deadbeefcafe1234\", stale=\"FALSE\"\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusCode != 401 || r.StatusCategory != "Client_Error" {
		t.Errorf("status: got %d/%q want 401/Client_Error",
			r.StatusCode, r.StatusCategory)
	}
	if !strings.Contains(r.WWWAuthenticate, "Digest") ||
		!strings.Contains(r.WWWAuthenticate, "nonce=") {
		t.Errorf("WWW-Authenticate: got %q", r.WWWAuthenticate)
	}
}

// TestDecodeDescribeRequest pins a DESCRIBE request — the
// canonical enumeration step that reveals stream tracks.
func TestDecodeDescribeRequest(t *testing.T) {
	msg := "DESCRIBE rtsp://192.168.1.100/cam/realmonitor?channel=1 RTSP/1.0\r\n" +
		"CSeq: 3\r\n" +
		"Accept: application/sdp\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Method != "DESCRIBE" {
		t.Errorf("method: got %q want DESCRIBE", r.Method)
	}
	if r.OtherHeaders["Accept"] != "application/sdp" {
		t.Errorf("Accept header: got %q", r.OtherHeaders["Accept"])
	}
}

// TestDecodeDescribeResponseWithSDPBody pins a DESCRIBE 200
// response carrying an SDP body.
func TestDecodeDescribeResponseWithSDPBody(t *testing.T) {
	sdp := "v=0\r\n" +
		"o=- 0 0 IN IP4 192.168.1.100\r\n" +
		"s=Channel-101\r\n" +
		"m=video 0 RTP/AVP 96\r\n"
	msg := "RTSP/1.0 200 OK\r\n" +
		"CSeq: 3\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: " + itoa(len(sdp)) + "\r\n\r\n" +
		sdp
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ContentType != "application/sdp" {
		t.Errorf("content-type: got %q", r.ContentType)
	}
	if r.ContentLength != len(sdp) {
		t.Errorf("content-length: got %d want %d", r.ContentLength, len(sdp))
	}
	if !strings.HasPrefix(r.BodyString, "v=0") {
		t.Errorf("body: got %q", r.BodyString)
	}
}

// TestDecodeSetupRequestWithTransport pins a SETUP request
// with Transport header — the per-track transport negotiation.
func TestDecodeSetupRequestWithTransport(t *testing.T) {
	msg := "SETUP rtsp://192.168.1.100/streaming/channels/101/trackID=1 RTSP/1.0\r\n" +
		"CSeq: 4\r\n" +
		"Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Method != "SETUP" {
		t.Errorf("method: got %q want SETUP", r.Method)
	}
	if !strings.Contains(r.Transport, "RTP/AVP/TCP") ||
		!strings.Contains(r.Transport, "interleaved=0-1") {
		t.Errorf("transport: got %q", r.Transport)
	}
}

// TestDecodePlayWithRange pins a PLAY request with Range
// header.
func TestDecodePlayWithRange(t *testing.T) {
	msg := "PLAY rtsp://192.168.1.100/stream RTSP/1.0\r\n" +
		"CSeq: 5\r\n" +
		"Session: 1234ABCD\r\n" +
		"Range: npt=0.000-\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Method != "PLAY" {
		t.Errorf("method: got %q want PLAY", r.Method)
	}
	if r.Session != "1234ABCD" {
		t.Errorf("session: got %q want 1234ABCD", r.Session)
	}
	if r.Range != "npt=0.000-" {
		t.Errorf("range: got %q want npt=0.000-", r.Range)
	}
}

// TestDecodeInterleavedRTP pins the binary $-prefixed
// interleaved-RTP frame format.
func TestDecodeInterleavedRTP(t *testing.T) {
	// '$' + channel 0 + length 4 (BE) + 4 RTP payload bytes.
	in := "24 00 0004 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindInterleaved {
		t.Errorf("kind: got %q want Interleaved", r.Kind)
	}
	if r.InterleavedChannel != 0 {
		t.Errorf("channel: got %d want 0", r.InterleavedChannel)
	}
	if r.InterleavedLength != 4 {
		t.Errorf("length: got %d want 4", r.InterleavedLength)
	}
	if r.InterleavedHex != "DEADBEEF" {
		t.Errorf("hex: got %q want DEADBEEF", r.InterleavedHex)
	}
}

// TestDecodeAuthorizationHeader pins the credentials-disclosure
// surface on the request side (Basic / Digest Authorization).
func TestDecodeAuthorizationHeader(t *testing.T) {
	msg := "DESCRIBE rtsp://192.168.1.100/stream RTSP/1.0\r\n" +
		"CSeq: 6\r\n" +
		"Authorization: Digest username=\"admin\", realm=\"IPCamera\", " +
		"nonce=\"deadbeef\", uri=\"rtsp://192.168.1.100/stream\", " +
		"response=\"...\"\r\n\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.Authorization, "Digest") ||
		!strings.Contains(r.Authorization, "username=\"admin\"") {
		t.Errorf("Authorization: got %q", r.Authorization)
	}
}

// TestStatusCategoryTable covers every documented HTTP status
// category.
func TestStatusCategoryTable(t *testing.T) {
	cases := map[int]string{
		100: "Informational",
		200: "Success",
		301: "Redirection",
		404: "Client_Error",
		500: "Server_Error",
		600: "Vendor_Error",
	}
	for k, v := range cases {
		if got := statusCategory(k); got != v {
			t.Errorf("statusCategory(%d) = %q want %q", k, got, v)
		}
	}
}

// TestClassifyStartLine covers each catalogued message kind.
func TestClassifyStartLine(t *testing.T) {
	cases := map[string]MessageKind{
		"OPTIONS rtsp://x RTSP/1.0":  KindRequest,
		"DESCRIBE rtsp://x RTSP/1.0": KindRequest,
		"PLAY rtsp://x RTSP/1.0":     KindRequest,
		"RTSP/1.0 200 OK":            KindResponse,
		"RTSP/2.0 401 Unauthorized":  KindResponse,
		"GARBAGE no_url":             KindUnknown,
	}
	for in, want := range cases {
		if got := classifyStartLine(in); got != want {
			t.Errorf("classifyStartLine(%q) = %q want %q", in, got, want)
		}
	}
}

// TestIsMethodTable covers every catalogued RTSP method.
func TestIsMethodTable(t *testing.T) {
	for _, m := range []string{
		"OPTIONS", "DESCRIBE", "ANNOUNCE", "SETUP",
		"PLAY", "PAUSE", "TEARDOWN",
		"GET_PARAMETER", "SET_PARAMETER",
		"REDIRECT", "RECORD",
	} {
		if !isMethod(m) {
			t.Errorf("isMethod(%q) = false want true", m)
		}
	}
	if isMethod("BOGUS") {
		t.Errorf("isMethod(BOGUS) = true want false")
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

// itoa is a small inline integer-to-string helper (avoids
// importing strconv in the test for a one-off use).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+(n%10))) + digits
		n /= 10
	}
	return digits
}
