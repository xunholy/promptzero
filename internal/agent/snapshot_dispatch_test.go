package agent

import (
	"context"
	"testing"

	"github.com/xunholy/promptzero/internal/snapshot"
)

// These tests exercise the agent's snapshot decision layer without
// mocking the Flipper serial transport. snapshotBeforeWrite is split
// into snapshotEligible + storeSnapshot precisely so the predicate
// and the write can be validated in isolation: the wider agent
// dispatch (storage_copy, storage_rename, fileformat_edit,
// subghz_bruteforce_generate, generate_*) invokes the same pair.
//
// Reviewer gap closed: the P1-09-b commit documents snapshot hooks
// on storage_copy / storage_rename / generator.Deploy but had no
// agent-level test. These tests verify the decision logic and the
// storeSnapshot round-trip through a real snapshot.Manager rooted
// at t.TempDir().

func TestSnapshot_EligibleRequiresAllThree(t *testing.T) {
	snapDir := t.TempDir()
	mgr := snapshot.NewManager(snapDir)

	cases := []struct {
		name         string
		setup        func(a *Agent)
		path         string
		wantEligible bool
	}{
		{
			name: "all three present",
			setup: func(a *Agent) {
				a.sessionID = "s1"
				a.snapshotMgr = mgr
			},
			path:         "/ext/any.sub",
			wantEligible: true,
		},
		{
			name: "no manager installed",
			setup: func(a *Agent) {
				a.sessionID = "s1"
			},
			path:         "/ext/any.sub",
			wantEligible: false,
		},
		{
			name: "no session id",
			setup: func(a *Agent) {
				a.snapshotMgr = mgr
			},
			path:         "/ext/any.sub",
			wantEligible: false,
		},
		{
			name: "empty path",
			setup: func(a *Agent) {
				a.sessionID = "s1"
				a.snapshotMgr = mgr
			},
			path:         "",
			wantEligible: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := agentForModelTest("claude-sonnet-4-6", nil)
			c.setup(a)
			if got := a.snapshotEligible(c.path); got != c.wantEligible {
				t.Errorf("snapshotEligible(%q) = %v, want %v", c.path, got, c.wantEligible)
			}
		})
	}
}

func TestSnapshot_StoreSnapshotRoundTrip(t *testing.T) {
	snapDir := t.TempDir()
	mgr := snapshot.NewManager(snapDir)

	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionID = "copy-test-session"
	a.snapshotMgr = mgr

	// Simulate what storage_copy / rename / generator.Deploy would
	// do: after confirming the path would be written, stash the
	// pre-write content via storeSnapshot.
	a.storeSnapshot(context.Background(), "/ext/subghz/keep.sub", []byte("canned pre-copy contents"))
	a.storeSnapshot(context.Background(), "/ext/subghz/other.sub", []byte("other"))

	entries, err := mgr.List("copy-test-session")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 snapshot entries, got %d", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.OriginalPath] = true
	}
	for _, want := range []string{"/ext/subghz/keep.sub", "/ext/subghz/other.sub"} {
		if !seen[want] {
			t.Errorf("missing snapshot for %q; entries: %+v", want, entries)
		}
	}
}

// TestSnapshot_StoreFailureLogsAndContinues covers the observability
// side: when the manager rejects a Store (e.g. disk full on a CI
// runner), the helper logs and swallows the error instead of
// propagating. /rewind is a convenience, never load-bearing.
func TestSnapshot_StoreFailureSwallowed(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.sessionID = ""
	a.snapshotMgr = snapshot.NewManager(t.TempDir())

	// storeSnapshot calls Store with an empty sessionID which the
	// manager rejects ("snapshot: sessionID required"). The helper
	// must return without panicking.
	a.storeSnapshot(context.Background(), "/ext/x", []byte("x"))
}
