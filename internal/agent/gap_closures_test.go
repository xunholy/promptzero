package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/session"
)

// Tests locking the P0/P1 gap closures landed after the audit of
// docs/specs/roadmap.md. Each test pins a specific behaviour the
// audit flagged as missing so a future refactor can't silently
// regress.

// P1-18: ToolError should carry DeviceState when the agent had a
// Flipper state snapshot at failure time. The spec's canonical
// struct includes this field; it was previously omitted as
// "duplicates the state oracle". The fix populates an optional
// pointer so forensic consumers get a pinned snapshot without
// duplicating the turn-start block.
func TestToolError_DeviceStateAttached(t *testing.T) {
	te := newToolError("nfc_detect", errors.New("timeout after 30s"), "")
	st := &flipper.State{
		Connected:       true,
		Fork:            "Momentum",
		FirmwareVersion: "0.99.1",
		BatteryPct:      84,
	}
	te = te.withDeviceState(st)
	if te.DeviceState == nil {
		t.Fatal("DeviceState should be attached")
	}
	if te.DeviceState.Fork != "Momentum" {
		t.Errorf("Fork = %q", te.DeviceState.Fork)
	}
	js := te.JSON()
	if !strings.Contains(js, `"device_state"`) {
		t.Errorf("JSON missing device_state: %s", js)
	}
	if !strings.Contains(js, `"Momentum"`) {
		t.Errorf("JSON missing Momentum: %s", js)
	}
}

func TestToolError_DeviceStateOmittedWhenNil(t *testing.T) {
	te := newToolError("nfc_detect", errors.New("timeout"), "")
	js := te.JSON()
	// omitempty — nil pointer stays out of the wire payload.
	if strings.Contains(js, `"device_state"`) {
		t.Errorf("nil DeviceState should be omitted: %s", js)
	}
}

func TestToolError_WithDeviceStateNilIsNoop(t *testing.T) {
	te := newToolError("nfc_detect", errors.New("timeout"), "")
	got := te.withDeviceState(nil)
	if got.DeviceState != nil {
		t.Errorf("withDeviceState(nil) should leave DeviceState nil, got %+v", got.DeviceState)
	}
}

// P1-08: ResumeSession should prepend the handoff artifact as a user
// message so the model sees structured findings / threads / blocked
// state on the first turn after resume. Previously the handoff was
// persisted on disk but never reached the live conversation.
func TestResumeSession_InjectsHandoffArtifact(t *testing.T) {
	store, err := session.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Prepare a session state with a handoff JSON block.
	handoff := HandoffArtifact{
		TurnsCovered: 5,
		Findings:     []HandoffFinding{{Tool: "wifi_scan_ap", Count: 3}},
		OpenThreads:  []HandoffThread{{Role: "user", Text: "finish the handshake capture"}},
	}
	handoffJSON := json.RawMessage(handoff.JSON())
	st := &session.State{
		ID:       "resume-test",
		Model:    "claude-sonnet-4-6",
		Messages: nil, // empty history exercises the handoff-only path
		Handoff:  handoffJSON,
	}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}

	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionStore = store

	if err := a.ResumeSession("resume-test"); err != nil {
		t.Fatalf("ResumeSession: %v", err)
	}

	if len(a.history) != 1 {
		t.Fatalf("expected 1 history entry (handoff prefix), got %d", len(a.history))
	}
	// The injected block must be a user-role message containing the
	// <handoff-resume> sentinel + the persisted JSON.
	msg := a.history[0]
	if len(msg.Content) == 0 {
		t.Fatal("handoff message has no content")
	}
	text := ""
	if msg.Content[0].OfText != nil {
		text = msg.Content[0].OfText.Text
	}
	if !strings.Contains(text, "<handoff-resume>") {
		t.Errorf("injected message missing sentinel: %q", text)
	}
	if !strings.Contains(text, "wifi_scan_ap") {
		t.Errorf("injected message missing finding preview: %q", text)
	}
	if !strings.Contains(text, "open_threads") {
		t.Errorf("injected message missing open_threads field: %q", text)
	}
}

func TestResumeSession_NoHandoffIsClean(t *testing.T) {
	store, err := session.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	st := &session.State{
		ID:       "no-handoff",
		Model:    "claude-sonnet-4-6",
		Messages: nil,
		// Handoff left empty — older session files won't have it.
	}
	_ = store.Save(st)

	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionStore = store

	if err := a.ResumeSession("no-handoff"); err != nil {
		t.Fatalf("ResumeSession: %v", err)
	}
	if len(a.history) != 0 {
		t.Errorf("expected no history when session has no handoff, got %d", len(a.history))
	}
}

// P1-09: Agent.DeleteSession should remove both the session store
// entry AND the per-session snapshot tree. The reviewer flagged the
// auto-purge as "Purge() exists but is never called from session-
// delete paths."
func TestDeleteSession_PurgesSnapshots(t *testing.T) {
	store, _ := session.NewStore(t.TempDir())

	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionStore = store
	a.sessionID = "purge-test"
	a.snapshotMgr = stubSnapshotManager(t)

	// Drop a snapshot so there's something to purge.
	a.storeSnapshot(context.Background(), "/ext/foo.sub", []byte("x"))
	if entries, _ := a.snapshotMgr.List("purge-test"); len(entries) != 1 {
		t.Fatalf("precondition: want 1 snapshot, got %d", len(entries))
	}

	// Save the session file, then delete.
	_ = store.Save(&session.State{ID: "purge-test", Model: "x"})
	if err := a.DeleteSession("purge-test"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// Both sides purged.
	if _, err := store.Load("purge-test"); err == nil {
		t.Error("session file still loadable after DeleteSession")
	}
	entries, _ := a.snapshotMgr.List("purge-test")
	if len(entries) != 0 {
		t.Errorf("snapshots still present after DeleteSession: %+v", entries)
	}
}

func TestDeleteSession_EmptyIDErrors(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	store, _ := session.NewStore(t.TempDir())
	a.sessionStore = store
	if err := a.DeleteSession(""); err == nil {
		t.Error("empty session id should error")
	}
}

func TestDeleteSession_NoStoreErrors(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	if err := a.DeleteSession("anything"); err == nil {
		t.Error("missing session store should error")
	}
}

// TestDeleteSession_OfActiveSessionRotatesInMemoryState pins the
// v0.88 fix. Pre-fix, /forget <current-session-id> would silently
// undo itself: the disk file was removed, but autoSaveLocked on
// the next turn (or any state-mutating call) would recreate it
// from a.history, and the next snapshot would recreate the
// per-session directory. Operators thought the session was gone;
// it reappeared on the next REPL turn.
//
// Fix: when the deleted id matches the active sessionID, rotate
// in-memory state — clear history and assign a fresh sessionID —
// so subsequent writes route to a brand-new file and the
// operator's "forget this" intent isn't quietly reversed.
func TestDeleteSession_OfActiveSessionRotatesInMemoryState(t *testing.T) {
	store, _ := session.NewStore(t.TempDir())
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionStore = store
	a.sessionID = "active-target"
	a.snapshotMgr = stubSnapshotManager(t)

	// Seed history so the rotation visibly empties it.
	a.history = append(a.history, anthropic.NewUserMessage(anthropic.NewTextBlock("hello")))
	if len(a.history) == 0 {
		t.Fatal("precondition: history must be non-empty")
	}
	_ = store.Save(&session.State{ID: "active-target", Model: "x"})

	if err := a.DeleteSession("active-target"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	if a.sessionID == "active-target" {
		t.Errorf("sessionID still 'active-target' after deleting it — autosave would recreate the file")
	}
	if a.sessionID == "" {
		t.Errorf("sessionID is empty after delete — should rotate to a fresh id, not blank")
	}
	if len(a.history) != 0 {
		t.Errorf("history not cleared after deleting active session: len=%d", len(a.history))
	}

	// The file is gone and stays gone: rotation didn't recreate it
	// under the old id, and the new id is different so future writes
	// target a different file.
	if _, err := store.Load("active-target"); err == nil {
		t.Error("session file still loadable after DeleteSession of active session")
	}
}

// TestDeleteSession_OfOtherSessionLeavesActiveAlone pins the
// opposite case: deleting a non-active session must NOT touch
// in-memory state. Pre-fix this case already worked, but the
// rotation logic in the v0.88 fix runs unconditionally on the
// id-match — pin the negative branch so a future refactor that
// drops the "id == a.sessionID" guard breaks here.
func TestDeleteSession_OfOtherSessionLeavesActiveAlone(t *testing.T) {
	store, _ := session.NewStore(t.TempDir())
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionStore = store
	a.sessionID = "active-stays"
	a.snapshotMgr = stubSnapshotManager(t)

	a.history = append(a.history, anthropic.NewUserMessage(anthropic.NewTextBlock("hello")))
	_ = store.Save(&session.State{ID: "other-target", Model: "x"})

	if err := a.DeleteSession("other-target"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	if a.sessionID != "active-stays" {
		t.Errorf("sessionID rotated unexpectedly: got %q want active-stays", a.sessionID)
	}
	if len(a.history) != 1 {
		t.Errorf("history mutated when deleting a non-active session: len=%d want 1", len(a.history))
	}
}
