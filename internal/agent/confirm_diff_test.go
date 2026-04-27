package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestBuildConfirmRequest_NonMediumNoDiff verifies that High and
// Critical confirmations don't pay the Storage Read cost — the diff
// preview is a Medium-tier feature only.
func TestBuildConfirmRequest_NonMediumNoDiff(t *testing.T) {
	a := &Agent{} // nil flipper would otherwise crash if the read fired

	cases := []risk.Level{risk.Low, risk.High, risk.Critical}
	for _, lvl := range cases {
		req := a.buildConfirmRequest("storage_write", json.RawMessage(`{"path":"/ext/x.txt","content":"hi"}`), lvl)
		if req.Diff != "" {
			t.Errorf("level=%v: expected empty Diff, got %q", lvl, req.Diff)
		}
	}
}

// TestBuildConfirmRequest_MediumNoWriteIntentNoDiff verifies that
// medium-risk tools without a WriteIntent declaration don't trigger
// the diff path.
func TestBuildConfirmRequest_MediumNoWriteIntentNoDiff(t *testing.T) {
	a := &Agent{}
	// storage_delete is Medium but has no WriteIntent — fetching its
	// "diff" makes no sense (there is no new content).
	req := a.buildConfirmRequest("storage_delete", json.RawMessage(`{"path":"/ext/y.txt"}`), risk.Medium)
	if req.Diff != "" {
		t.Errorf("expected empty Diff for non-WriteIntent tool, got %q", req.Diff)
	}
}

// TestBuildConfirmRequest_MediumNilFlipperNoDiff verifies graceful
// degradation when the flipper transport is unavailable: the
// confirmation flow must NOT panic; it must return an empty diff so
// the caller can render the bare prompt.
func TestBuildConfirmRequest_MediumNilFlipperNoDiff(t *testing.T) {
	a := &Agent{flipper: nil}
	req := a.buildConfirmRequest("storage_write",
		json.RawMessage(`{"path":"/ext/canary.txt","content":"hello"}`),
		risk.Medium)
	if req.Diff != "" {
		t.Errorf("nil flipper should yield empty Diff, got %q", req.Diff)
	}
	// Sanity: the rest of the request still populates.
	if req.Tool != "storage_write" || req.Risk != risk.Medium {
		t.Errorf("request fields unset: %+v", req)
	}
}

// TestBuildConfirmRequest_BadJSONNoDiff verifies that malformed input
// JSON doesn't crash the gate — the prompt still renders, just
// without a diff.
func TestBuildConfirmRequest_BadJSONNoDiff(t *testing.T) {
	a := &Agent{}
	req := a.buildConfirmRequest("storage_write", json.RawMessage(`{not json`), risk.Medium)
	if req.Diff != "" {
		t.Errorf("malformed input should yield empty Diff, got %q", req.Diff)
	}
}

// TestBuildConfirmRequest_WriteIntentReturnsFalseNoDiff verifies that
// a WriteIntent that signals "no write right now" (e.g. a deploy=false
// flag, or empty content path) skips the diff fetch.
func TestBuildConfirmRequest_WriteIntentReturnsFalseNoDiff(t *testing.T) {
	a := &Agent{}
	// storage_write's WriteIntent returns false when path is empty.
	req := a.buildConfirmRequest("storage_write",
		json.RawMessage(`{"content":"hi"}`),
		risk.Medium)
	if req.Diff != "" {
		t.Errorf("expected empty Diff when WriteIntent declines, got %q", req.Diff)
	}
}

// TestIsMissingFileErr verifies the heuristic that decides whether a
// Storage Read failure means "fresh write" (-> empty old side) versus
// a transport-level error (-> warning in the diff field).
func TestIsMissingFileErr(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"file does not exist", true},
		{"Storage error: File does not exist", true},
		{"no such file or directory", true},
		{"path not found on device", true},
		{"timeout waiting for response", false},
		{"protocol error: malformed frame", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isMissingFileErr(errString(tc.msg))
		if got != tc.want {
			t.Errorf("isMissingFileErr(%q) = %v; want %v", tc.msg, got, tc.want)
		}
	}
}

// errString is a tiny error wrapper for the table test above.
type errString string

func (e errString) Error() string { return string(e) }

// TestBuildConfirmRequest_DiffWarningOnReadFailure: when a non-missing
// error comes back, the diff field carries a one-line warning (we
// can't easily induce that in this darwin-friendly test without a
// flipper mock; verify the warning template via isMissingFileErr +
// the message shape we emit).
func TestBuildConfirmRequest_DiffWarningTemplate(t *testing.T) {
	// Sanity: the warning template renders the path and the error in
	// the form the operator expects. The actual emission is exercised
	// by TestBuildConfirmRequest_DiffOnExistingFile (linux-only).
	want := "(unable to fetch existing file /ext/x.txt: boom)"
	got := unableToFetchMsg("/ext/x.txt", errString("boom"))
	if got != want {
		t.Errorf("unableToFetchMsg = %q; want %q", got, want)
	}
	// The substring that the UI matches on:
	if !strings.HasPrefix(got, "(unable to fetch existing file ") {
		t.Errorf("warning template drift: %q", got)
	}
}
