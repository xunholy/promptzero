// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import "testing"

func ctr(v int64) *int64 { return &v }

// TestRollback_CleanSequence: distinct codes each press, no reuse → no
// observations flagged.
func TestRollback_CleanSequence(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AABB", Code: "01"},
		{ID: "AABB", Code: "02"},
		{ID: "AABB", Code: "03"},
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("clean sequence flagged %d observations: %+v", len(a.Observations), a.Observations)
	}
	if a.PerTx["AABB"].LogicalTransmissions != 3 {
		t.Errorf("logical transmissions = %d, want 3", a.PerTx["AABB"].LogicalTransmissions)
	}
}

// TestRollback_BurstIsBenign: consecutive identical codes (a press burst)
// must NOT be flagged as a replay; they collapse to one logical
// transmission with burst repeats counted.
func TestRollback_BurstIsBenign(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AABB", Code: "01"},
		{ID: "AABB", Code: "01"},
		{ID: "AABB", Code: "01"},
		{ID: "AABB", Code: "02"},
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("burst flagged %d observations: %+v", len(a.Observations), a.Observations)
	}
	s := a.PerTx["AABB"]
	if s.LogicalTransmissions != 2 {
		t.Errorf("logical transmissions = %d, want 2", s.LogicalTransmissions)
	}
	if s.BurstRepeats != 2 {
		t.Errorf("burst repeats = %d, want 2", s.BurstRepeats)
	}
}

// TestRollback_ReplayedCode: a code that reappears after the transmitter
// moved to a different code is the replay signature.
func TestRollback_ReplayedCode(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AABB", Code: "01"},
		{ID: "AABB", Code: "02"},
		{ID: "AABB", Code: "01"}, // reuse of an old code
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if got := countKind(a, "replayed_code"); got != 1 {
		t.Fatalf("replayed_code observations = %d, want 1: %+v", got, a.Observations)
	}
	if a.PerTx["AABB"].ReplayedCodes != 1 {
		t.Errorf("per-tx replayed = %d, want 1", a.PerTx["AABB"].ReplayedCodes)
	}
}

// TestRollback_SeparatorsAndPrefix: codes compare equal regardless of
// case, separators, or a 0x prefix — so a normalised replay is still caught.
func TestRollback_SeparatorsAndPrefix(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AABB", Code: "0x1a2b"},
		{ID: "AABB", Code: "03"},
		{ID: "AABB", Code: "1A:2B"}, // same code, different formatting
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if got := countKind(a, "replayed_code"); got != 1 {
		t.Errorf("replayed_code = %d, want 1 (normalisation should equate the codes)", got)
	}
}

// TestRollback_CounterRegression: a decrypted counter lower than the
// running max is a hard invariant violation.
func TestRollback_CounterRegression(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AABB", Code: "01", Counter: ctr(100)},
		{ID: "AABB", Code: "02", Counter: ctr(101)},
		{ID: "AABB", Code: "03", Counter: ctr(50)}, // regression
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if got := countKind(a, "counter_regression"); got != 1 {
		t.Fatalf("counter_regression = %d, want 1: %+v", got, a.Observations)
	}
	// Forward-advancing counters must not regress-flag.
	if got := countKind(a, "replayed_code"); got != 0 {
		t.Errorf("unexpected replayed_code = %d", got)
	}
}

// TestRollback_CounterMonotonicNoFlag: strictly increasing counters never
// flag, even with a large forward gap.
func TestRollback_CounterMonotonicNoFlag(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AABB", Code: "01", Counter: ctr(1)},
		{ID: "AABB", Code: "02", Counter: ctr(5000)},
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("monotonic counters flagged: %+v", a.Observations)
	}
}

// TestRollback_TransmittersIsolated: a code reused across DIFFERENT
// transmitter IDs is not a replay — state is per transmitter.
func TestRollback_TransmittersIsolated(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "AAAA", Code: "01"},
		{ID: "BBBB", Code: "02"},
		{ID: "AAAA", Code: "09"},
		{ID: "BBBB", Code: "01"}, // same code value but different transmitter
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if got := countKind(a, "replayed_code"); got != 0 {
		t.Errorf("cross-transmitter code reuse flagged %d, want 0", got)
	}
	if a.Transmitters != 2 {
		t.Errorf("transmitters = %d, want 2", a.Transmitters)
	}
}

// TestRollback_MalformedSkipped: frames missing id or code are noted and
// skipped, not counted as valid.
func TestRollback_MalformedSkipped(t *testing.T) {
	frames := []RollbackFrame{
		{ID: "", Code: "01"},
		{ID: "AABB", Code: ""},
		{ID: "AABB", Code: "01"},
	}
	a, err := AnalyzeRollback(frames)
	if err != nil {
		t.Fatalf("AnalyzeRollback: %v", err)
	}
	if a.FramesValid != 1 {
		t.Errorf("valid frames = %d, want 1", a.FramesValid)
	}
	if len(a.Notes) == 0 {
		t.Error("expected notes for skipped malformed frames")
	}
}

func TestRollback_Empty(t *testing.T) {
	if _, err := AnalyzeRollback(nil); err == nil {
		t.Error("expected error for empty frame list")
	}
}

func countKind(a *RollbackAnalysis, kind string) int {
	n := 0
	for _, o := range a.Observations {
		if o.Kind == kind {
			n++
		}
	}
	return n
}
