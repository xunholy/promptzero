package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestMarshalErrorPlaceholder_ValidJSONForControlBytes pins the
// v0.151 contract: the RunTool / workflowConfirmHook fallback rows
// built from a marshal error must be valid JSON regardless of what
// control bytes the error string contains. Pre-v0.150 the audit
// log built its sibling fallback via `fmt.Sprintf("%q", err)` —
// Go-string quoting with escapes (\a / \v / \xNN) outside JSON's
// {\b \f \n \r \t} whitelist — and a BEL (\x07) in the message
// produced an unparseable row. The fix moved every site to
// json.Marshal; this test pins that contract here.
func TestMarshalErrorPlaceholder_ValidJSONForControlBytes(t *testing.T) {
	// Stage an error whose message contains every JSON-hostile
	// control byte we care about (BEL / VT / NUL / arbitrary \x0E).
	err := errors.New("bad bytes: \x07 BEL \x0B VT \x00 NUL \x0E SO end")
	out := marshalErrorPlaceholder(err)

	var parsed map[string]any
	if uerr := json.Unmarshal(out, &parsed); uerr != nil {
		t.Fatalf("placeholder is not valid JSON: %v\nplaceholder = %q", uerr, out)
	}
	got, _ := parsed["_marshal_error"].(string)
	// The original control bytes must round-trip through the
	// encode/decode pair so forensic readers can see what the
	// underlying message was.
	if !strings.Contains(got, "BEL") || !strings.Contains(got, "VT") {
		t.Errorf("round-trip lost message content: %q", got)
	}
}

// TestMarshalErrorPlaceholder_NilError covers the nil-input path —
// no caller is expected to pass nil but the helper must not panic.
func TestMarshalErrorPlaceholder_NilError(t *testing.T) {
	out := marshalErrorPlaceholder(nil)
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("nil-error placeholder is not valid JSON: %v\nplaceholder = %q", err, out)
	}
	if got, _ := parsed["_marshal_error"].(string); got != "" {
		t.Errorf("nil error should yield empty message, got %q", got)
	}
}
