package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func rtspHexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestRTSPDecodeHandler_OptionsRequest pins the canonical
// IP-camera probe.
func TestRTSPDecodeHandler_OptionsRequest(t *testing.T) {
	msg := "OPTIONS rtsp://192.168.1.100:554/Streaming/Channels/101 RTSP/1.0\r\n" +
		"CSeq: 1\r\n" +
		"User-Agent: PromptZero-IPCam/1.0\r\n\r\n"
	out, err := rtspDecodeHandler(context.Background(), nil,
		map[string]any{"hex": rtspHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Request"`,
		`"method": "OPTIONS"`,
		`"user_agent": "PromptZero-IPCam/1.0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRTSPDecodeHandler_UnauthorizedDigest pins the
// 401 + Digest credentials-harvest surface.
func TestRTSPDecodeHandler_UnauthorizedDigest(t *testing.T) {
	msg := "RTSP/1.0 401 Unauthorized\r\n" +
		"CSeq: 2\r\n" +
		"WWW-Authenticate: Digest realm=\"IPCamera\", " +
		"nonce=\"deadbeefcafe1234\"\r\n\r\n"
	out, err := rtspDecodeHandler(context.Background(), nil,
		map[string]any{"hex": rtspHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"status_code": 401`,
		`"status_category": "Client_Error"`,
		`"www_authenticate": "Digest realm=\"IPCamera\"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRTSPDecodeHandler_DescribeWithSDPBody pins the DESCRIBE
// 200 response carrying an SDP body.
func TestRTSPDecodeHandler_DescribeWithSDPBody(t *testing.T) {
	sdp := "v=0\r\n" +
		"o=- 0 0 IN IP4 192.168.1.100\r\n" +
		"s=Channel-101\r\n" +
		"m=video 0 RTP/AVP 96\r\n"
	msg := "RTSP/1.0 200 OK\r\n" +
		"CSeq: 3\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 78\r\n\r\n" + sdp
	out, err := rtspDecodeHandler(context.Background(), nil,
		map[string]any{"hex": rtspHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"content_type": "application/sdp"`,
		`"content_length": 78`,
		`"body_string":`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRTSPDecodeHandler_InterleavedRTP pins the `$`-prefixed
// binary interleaved RTP frame format.
func TestRTSPDecodeHandler_InterleavedRTP(t *testing.T) {
	in := "24 00 0004 DEADBEEF"
	out, err := rtspDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Interleaved"`,
		`"interleaved_channel": 0`,
		`"interleaved_length": 4`,
		`"interleaved_hex": "DEADBEEF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestRTSPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := rtspDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
