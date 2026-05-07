package cost

import (
	"sync"
	"testing"
	"time"
)

func TestPricer_DefaultsKnownModels(t *testing.T) {
	p := NewPricer(nil)
	cases := map[string]Rate{
		"claude-opus-4-7":   {InputPerMTok: 15, OutputPerMTok: 75},
		"claude-sonnet-4-6": {InputPerMTok: 3, OutputPerMTok: 15},
		"claude-haiku-4-5":  {InputPerMTok: 0.8, OutputPerMTok: 4},
	}
	for model, want := range cases {
		got, ok := p.Rate(model)
		if !ok {
			t.Errorf("no rate for %s", model)
			continue
		}
		if got != want {
			t.Errorf("%s: got %+v want %+v", model, got, want)
		}
	}
}

func TestPricer_OverridesWinOverDefaults(t *testing.T) {
	p := NewPricer(map[string]Rate{
		"claude-opus-4-7": {InputPerMTok: 1, OutputPerMTok: 2},
	})
	r, _ := p.Rate("claude-opus-4-7")
	if r.InputPerMTok != 1 || r.OutputPerMTok != 2 {
		t.Errorf("override ignored: %+v", r)
	}
}

func TestPricer_CostWithCache(t *testing.T) {
	// Sonnet: $3/MTok input, $15/MTok output. Cache read = 0.1x input
	// ($0.30/MTok), cache creation = 1.25x input ($3.75/MTok).
	// 1M each: 3 + 15 + 0.3 + 3.75 = 22.05
	p := NewPricer(nil)
	got := p.CostWithCache("claude-sonnet-4-6", 1_000_000, 1_000_000, 1_000_000, 1_000_000)
	const want = 22.05
	if diff := got - want; diff < -0.001 || diff > 0.001 {
		t.Fatalf("CostWithCache = %f, want %f", got, want)
	}
}

func TestTracker_AddUsageFull_AccumulatesCache(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.AddUsageFull(1000, 500, 2000, 100)
	snap := tr.Snapshot()
	if snap.InputTokens != 1000 || snap.OutputTokens != 500 {
		t.Errorf("input/output not recorded: %+v", snap)
	}
	if snap.CacheReadTokens != 2000 {
		t.Errorf("cache_read = %d, want 2000", snap.CacheReadTokens)
	}
	if snap.CacheCreationTokens != 100 {
		t.Errorf("cache_creation = %d, want 100", snap.CacheCreationTokens)
	}
	if hr := snap.CacheHitRate(); hr < 0.95 || hr > 0.96 {
		t.Errorf("CacheHitRate = %f, want ~0.952 (2000/2100)", hr)
	}
}

func TestSnapshot_CacheHitRateEmpty(t *testing.T) {
	// Empty snapshot must not divide by zero.
	if got := (Snapshot{}).CacheHitRate(); got != 0 {
		t.Fatalf("CacheHitRate on empty = %f, want 0", got)
	}
}

func TestSnapshot_FormatIncludesCacheWhenPresent(t *testing.T) {
	s := Snapshot{Model: "claude-sonnet-4-6", InputTokens: 100, OutputTokens: 50, CacheReadTokens: 900, CacheCreationTokens: 100}
	got := s.Format()
	for _, want := range []string{"cache_read=900", "cache_write=100", "hit_rate=90%"} {
		if !contains(got, want) {
			t.Errorf("Format missing %q: %s", want, got)
		}
	}
}

func TestSnapshot_FormatOmitsCacheWhenZero(t *testing.T) {
	// A tracker that never cached anything should not clutter /cost with
	// zero cache counters.
	s := Snapshot{Model: "claude-sonnet-4-6", InputTokens: 100, OutputTokens: 50}
	got := s.Format()
	if contains(got, "cache_read") {
		t.Errorf("Format should hide cache fields when zero: %s", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && stringContainsHelper(haystack, needle)
}

// stringContainsHelper avoids an extra import of strings inside the
// cost package's test file.
func stringContainsHelper(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestPricer_UnknownModelIsZero(t *testing.T) {
	p := NewPricer(nil)
	if _, ok := p.Rate("made-up-model"); ok {
		t.Error("expected unknown model to report ok=false")
	}
	if got := p.Cost("made-up-model", 1_000_000, 1_000_000); got != 0 {
		t.Errorf("cost for unknown model = %f want 0", got)
	}
}

func TestPricer_CaseInsensitive(t *testing.T) {
	p := NewPricer(nil)
	if _, ok := p.Rate("Claude-Opus-4-7"); !ok {
		t.Error("expected case-insensitive lookup to hit")
	}
}

func TestPricer_CostArithmetic(t *testing.T) {
	p := NewPricer(nil)
	// 1M input + 1M output on sonnet-4-6 = $3 + $15 = $18
	got := p.Cost("claude-sonnet-4-6", 1_000_000, 1_000_000)
	if got != 18.0 {
		t.Errorf("cost=%f want 18.0", got)
	}
	// 10k input on haiku-4-5 = 10000/1M * 0.80 = $0.008
	got = p.Cost("claude-haiku-4-5", 10_000, 0)
	if got < 0.0079 || got > 0.0081 {
		t.Errorf("cost=%f want ~0.008", got)
	}
}

func TestTracker_AddUsageAccumulates(t *testing.T) {
	p := NewPricer(nil)
	tr := NewTracker(p, "claude-sonnet-4-6", nil)
	tr.AddUsage(1000, 500)
	tr.AddUsage(2000, 1500)
	s := tr.Snapshot()
	if s.InputTokens != 3000 || s.OutputTokens != 2000 {
		t.Errorf("tokens=%d/%d want 3000/2000", s.InputTokens, s.OutputTokens)
	}
	// 3000/1M*$3 + 2000/1M*$15 = 0.009 + 0.030 = 0.039
	if s.TotalUSD < 0.0389 || s.TotalUSD > 0.0391 {
		t.Errorf("cost=%f want ~0.039", s.TotalUSD)
	}
}

func TestTracker_AddUsageSkipsZero(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.AddUsage(0, 0)
	if s := tr.Snapshot(); s.InputTokens != 0 || s.OutputTokens != 0 || s.TotalUSD != 0 {
		t.Errorf("zero AddUsage should be no-op: %+v", s)
	}
}

// TestTracker_AddUsageFull_ClampsNegatives locks the input clamp.
// The original guard only no-op'd when ALL four were <= 0, so a
// mixed call with one negative could DECREMENT the running total.
// Each negative is now clamped to 0; positive components still
// accumulate normally.
func TestTracker_AddUsageFull_ClampsNegatives(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	// Seed with valid usage.
	tr.AddUsageFull(100, 50, 0, 0)
	want := tr.Snapshot()

	// Try to corrupt: negative input + positive output. Expect
	// inTokens unchanged (negative clamped), outTokens incremented.
	tr.AddUsageFull(-1000, 25, 0, 0)
	got := tr.Snapshot()

	if got.InputTokens != want.InputTokens {
		t.Errorf("InputTokens = %d, want unchanged %d (negative should clamp)",
			got.InputTokens, want.InputTokens)
	}
	if got.OutputTokens != want.OutputTokens+25 {
		t.Errorf("OutputTokens = %d, want %d", got.OutputTokens, want.OutputTokens+25)
	}
}

// TestTracker_AddUsageFull_AllNegativeNoOp confirms the existing
// no-op semantics survive: when every component clamps to zero the
// call is a no-op (no lock acquisition, no callback churn).
func TestTracker_AddUsageFull_AllNegativeNoOp(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.AddUsageFull(-1, -2, -3, -4)
	if s := tr.Snapshot(); s.InputTokens != 0 || s.OutputTokens != 0 ||
		s.CacheReadTokens != 0 || s.CacheCreationTokens != 0 || s.TotalUSD != 0 {
		t.Errorf("all-negative AddUsageFull should be no-op: %+v", s)
	}
}

func TestTracker_OfflineAfterThreeErrors(t *testing.T) {
	now := time.Now()
	var (
		mu          sync.Mutex
		transitions []bool
	)
	tr := NewTracker(NewPricer(nil), "claude-opus-4-7", func(v bool) {
		mu.Lock()
		transitions = append(transitions, v)
		mu.Unlock()
	})
	tr.now = func() time.Time { return now }

	tr.RecordStreamError()
	if tr.Snapshot().Offline {
		t.Fatal("offline after 1 error")
	}
	tr.RecordStreamError()
	if tr.Snapshot().Offline {
		t.Fatal("offline after 2 errors")
	}
	tr.RecordStreamError()
	if !tr.Snapshot().Offline {
		t.Fatal("not offline after 3 errors within window")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 1 || transitions[0] != true {
		t.Errorf("transitions=%v want [true]", transitions)
	}
}

func TestTracker_ErrorStreakResetsOnWindow(t *testing.T) {
	now := time.Now()
	tr := NewTracker(NewPricer(nil), "claude-opus-4-7", nil)
	tr.now = func() time.Time { return now }
	tr.RecordStreamError()
	tr.RecordStreamError()

	// Advance past the window; next error should start a new run.
	now = now.Add(70 * time.Second)
	tr.RecordStreamError()
	if tr.Snapshot().Offline {
		t.Error("run should have reset outside window; still offline")
	}
}

func TestTracker_SuccessFlipsBackOnline(t *testing.T) {
	now := time.Now()
	var (
		mu          sync.Mutex
		transitions []bool
	)
	tr := NewTracker(NewPricer(nil), "claude-opus-4-7", func(v bool) {
		mu.Lock()
		transitions = append(transitions, v)
		mu.Unlock()
	})
	tr.now = func() time.Time { return now }

	tr.RecordStreamError()
	tr.RecordStreamError()
	tr.RecordStreamError()
	if !tr.Snapshot().Offline {
		t.Fatal("expected offline after 3 errors")
	}
	tr.AddUsage(100, 100)
	if tr.Snapshot().Offline {
		t.Error("successful AddUsage should flip back online")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) != 2 || transitions[0] != true || transitions[1] != false {
		t.Errorf("transitions=%v want [true false]", transitions)
	}
}
