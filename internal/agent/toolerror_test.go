package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// unmarshalToolErr decodes the JSON representation produced by
// ToolError.JSON() back into a ToolError. Used to assert specific
// fields without hand-parsing the raw JSON in every test case.
func unmarshalToolErr(t *testing.T, s string) ToolError {
	t.Helper()
	var te ToolError
	if err := json.Unmarshal([]byte(s), &te); err != nil {
		t.Fatalf("unmarshal: %v (input: %s)", err, s)
	}
	return te
}

func TestNewToolError_Timeout(t *testing.T) {
	te := newToolError("nfc_detect", errors.New("nfc detect: timeout after 30s"), "")
	if te.Code != "flipper_nfc_timeout" {
		t.Errorf("Code = %q, want flipper_nfc_timeout", te.Code)
	}
	if !te.Retryable {
		t.Errorf("timeout should be retryable")
	}
	if len(te.Remediation) == 0 {
		t.Errorf("timeout should include remediation hints")
	}
}

func TestNewToolError_MarauderNotConnected(t *testing.T) {
	te := newToolError("wifi_scan_ap", errors.New("WiFi devboard not connected — use --wifi flag"), "")
	if te.Code != "marauder_not_connected" {
		t.Errorf("Code = %q, want marauder_not_connected", te.Code)
	}
	if te.Retryable {
		t.Errorf("marauder-not-connected should NOT be retryable")
	}
	if !containsAny(te.Remediation, "--wifi") {
		t.Errorf("remediation missing --wifi hint: %v", te.Remediation)
	}
}

func TestNewToolError_StorageNotReady(t *testing.T) {
	te := newToolError("storage_list", errors.New("Storage error: not ready"), "Storage error: not ready")
	if te.Code != "storage_not_ready" {
		t.Errorf("Code = %q, want storage_not_ready", te.Code)
	}
	if te.Retryable {
		t.Errorf("storage_not_ready should NOT be retryable")
	}
}

func TestNewToolError_Disconnect(t *testing.T) {
	te := newToolError("subghz_transmit", errors.New("flipper disconnected"), "")
	if te.Code != "flipper_rf_subghz_disconnect" {
		t.Errorf("Code = %q, want flipper_rf_subghz_disconnect", te.Code)
	}
	if !te.Retryable {
		t.Errorf("disconnect should be retryable once reconnection works")
	}
}

func TestNewToolError_UnknownTool(t *testing.T) {
	te := newToolError("made_up_tool", errors.New("unknown tool: made_up_tool"), "")
	if te.Code != "unknown_tool" {
		t.Errorf("Code = %q, want unknown_tool", te.Code)
	}
	if te.Retryable {
		t.Errorf("unknown_tool should NOT be retryable")
	}
}

func TestNewToolError_GenericFallback(t *testing.T) {
	// A novel error message should still classify cleanly, defaulting
	// to retryable=true with a group-based code.
	te := newToolError("ir_transmit", errors.New("something weird happened"), "")
	if te.Code != "flipper_rf_ir_error" {
		t.Errorf("Code = %q, want flipper_rf_ir_error", te.Code)
	}
	if !te.Retryable {
		t.Errorf("generic errors should default to retryable=true")
	}
}

func TestToolError_JSONRoundTrip(t *testing.T) {
	te := ToolError{
		Code:        "flipper_nfc_timeout",
		Tool:        "nfc_detect",
		Message:     "timeout after 30s",
		Excerpt:     "waiting for card...",
		Remediation: []string{"reposition", "retry"},
		Retryable:   true,
	}
	js := te.JSON()
	// Must be valid JSON.
	decoded := unmarshalToolErr(t, js)
	if decoded.Code != te.Code ||
		decoded.Tool != te.Tool ||
		decoded.Message != te.Message ||
		decoded.Retryable != te.Retryable {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, te)
	}
	// Must be greppable by a detector without destructuring nested
	// objects — assert flatness.
	for _, key := range []string{`"code":`, `"tool":`, `"message":`, `"retryable":`} {
		if !strings.Contains(js, key) {
			t.Errorf("missing top-level key %s in %s", key, js)
		}
	}
}

func TestTruncateExcerpt_PreservesTail(t *testing.T) {
	// Hardware failure text usually lives in the tail — the last line
	// of output has the actual "Error: ..." line. Make sure that's
	// what we keep.
	head := strings.Repeat("a", toolErrExcerptMax*2)
	tail := "ERROR: access denied"
	in := head + tail
	out := truncateExcerpt(in)
	if !strings.HasSuffix(out, tail) {
		t.Fatalf("excerpt dropped the tail: %q", out[len(out)-40:])
	}
	if len(out) > toolErrExcerptMax {
		t.Fatalf("excerpt longer than cap: %d", len(out))
	}
}

func TestTruncateExcerpt_ShortPassthrough(t *testing.T) {
	in := "short error"
	out := truncateExcerpt(in)
	if out != in {
		t.Fatalf("short input should pass through: got %q", out)
	}
}

func TestTruncateExcerpt_NeverSplitsUTF8(t *testing.T) {
	// Build a string whose byte-level tail-cut would land inside a
	// multi-byte rune. The Japanese filler characters here are 3
	// bytes each; the cut boundary (500 - 3 = 497 bytes from end)
	// will bisect one of them unless the truncator is rune-aware.
	big := strings.Repeat("あ", 300) // 900 bytes
	out := truncateExcerpt(big)
	if !utf8.ValidString(out) {
		t.Fatalf("truncateExcerpt produced invalid UTF-8: %q", out)
	}
	if len(out) > toolErrExcerptMax {
		t.Fatalf("excerpt longer than cap: %d", len(out))
	}
}

// Sanitisation: ANSI and control bytes in the error message must not
// leak into the structured error — that would undermine the same
// protection the quarantine layer applies on happy-path output.
func TestNewToolError_StripsControlChars(t *testing.T) {
	te := newToolError("nfc_detect", errors.New("\x1b[31mtimeout\x1b[0m\x00"), "\x07scan\x1bend")
	if strings.Contains(te.Message, "\x1b") || strings.Contains(te.Message, "\x00") {
		t.Errorf("Message still carries control bytes: %q", te.Message)
	}
	if strings.Contains(te.Excerpt, "\x1b") || strings.Contains(te.Excerpt, "\x07") {
		t.Errorf("Excerpt still carries control bytes: %q", te.Excerpt)
	}
}

func containsAny(hay []string, needle string) bool {
	for _, s := range hay {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
