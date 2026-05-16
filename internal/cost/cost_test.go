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

// TestSetModel_UpdatesSnapshotAndPricingPath pins two contracts for
// SetModel: the change reflects in the next Snapshot.Model, and any
// AddUsage call after SetModel is billed at the new model's rate
// rather than the constructor's. Past usage stays attributed to the
// prior model (the totalUSD running total is intentionally NOT
// re-priced — only future AddUsage calls).
func TestSetModel_UpdatesSnapshotAndPricingPath(t *testing.T) {
	// Opus and Sonnet rates differ enough that 1M-token usage produces
	// a clearly different USD bump; pin that.
	p := NewPricer(nil)
	tr := NewTracker(p, "claude-sonnet-4-6", nil)

	// First batch billed at Sonnet rate.
	tr.AddUsage(1_000_000, 0) // 1M input @ $3/MTok = $3.00
	snapBefore := tr.Snapshot()
	if snapBefore.Model != "claude-sonnet-4-6" {
		t.Errorf("pre-switch Model = %q; want sonnet", snapBefore.Model)
	}
	if snapBefore.TotalUSD < 2.99 || snapBefore.TotalUSD > 3.01 {
		t.Fatalf("pre-switch TotalUSD = %f; want ~$3 (1M @ $3/MTok)", snapBefore.TotalUSD)
	}

	// Switch model — future usage billed at Opus rate ($15/MTok input).
	tr.SetModel("claude-opus-4-7")
	tr.AddUsage(1_000_000, 0) // 1M input @ $15/MTok = $15.00 more

	snapAfter := tr.Snapshot()
	if snapAfter.Model != "claude-opus-4-7" {
		t.Errorf("post-switch Model = %q; want opus", snapAfter.Model)
	}
	wantTotal := 3.0 + 15.0
	if diff := snapAfter.TotalUSD - wantTotal; diff < -0.01 || diff > 0.01 {
		t.Errorf("post-switch TotalUSD = %f; want %f ($3 sonnet + $15 opus)", snapAfter.TotalUSD, wantTotal)
	}
	// Token counters keep accumulating regardless of model.
	if snapAfter.InputTokens != 2_000_000 {
		t.Errorf("InputTokens = %d; want 2_000_000", snapAfter.InputTokens)
	}
}

// TestAddUsageFullForModel_PerCallModelOverridesTrackerModel pins the
// tier-routing pricing fix: a tracker configured with Opus rates must
// bill Haiku-tier calls at Haiku rates when the per-call model is
// supplied. Pre-fix, every persona that routed plan-tier to Haiku
// silently still got billed at Opus rates (5x overstatement on a
// per-token basis, larger gap on cache-heavy turns).
func TestAddUsageFullForModel_PerCallModelOverridesTrackerModel(t *testing.T) {
	p := NewPricer(nil)
	// Tracker primary model: Opus ($15/MTok input). Cost dashboard
	// shows this in Snapshot.Model — operator's configured baseline.
	tr := NewTracker(p, "claude-opus-4-7", nil)

	// Haiku-tier classify call: 1M input tokens.
	// Haiku rate is $0.80/MTok → expected ~$0.80, NOT $15 (Opus).
	tr.AddUsageFullForModel("claude-haiku-4-5", 1_000_000, 0, 0, 0)

	snap := tr.Snapshot()
	if snap.Model != "claude-opus-4-7" {
		t.Errorf("Snapshot.Model = %q; want primary opus (per-call model must NOT overwrite the displayed primary)", snap.Model)
	}
	if snap.TotalUSD < 0.79 || snap.TotalUSD > 0.81 {
		t.Errorf("TotalUSD = %f; want ~$0.80 (Haiku $0.80/MTok), not Opus $15/MTok", snap.TotalUSD)
	}

	// Now an exploit-tier Opus call: 1M input → +$15.
	tr.AddUsageFullForModel("claude-opus-4-7", 1_000_000, 0, 0, 0)
	snap = tr.Snapshot()
	wantTotal := 0.80 + 15.0
	if diff := snap.TotalUSD - wantTotal; diff < -0.01 || diff > 0.01 {
		t.Errorf("TotalUSD after mixed tiers = %f; want %f ($0.80 haiku + $15 opus)", snap.TotalUSD, wantTotal)
	}
}

// TestAddUsageFullForModel_EmptyModelFallsBackToTrackerModel pins the
// backward-compat behaviour: an empty per-call model means "use the
// tracker's configured model", matching the legacy AddUsageFull path.
func TestAddUsageFullForModel_EmptyModelFallsBackToTrackerModel(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)
	tr.AddUsageFullForModel("", 1_000_000, 0, 0, 0)
	// Sonnet rate: $3/MTok input.
	snap := tr.Snapshot()
	if snap.TotalUSD < 2.99 || snap.TotalUSD > 3.01 {
		t.Errorf("empty per-call model: TotalUSD = %f; want ~$3 (Sonnet)", snap.TotalUSD)
	}
}

// TestAddUsageFull_StillUsesTrackerModel pins that the legacy
// AddUsageFull wrapper continues to price using the tracker model —
// it now delegates to AddUsageFullForModel("", ...).
func TestAddUsageFull_StillUsesTrackerModel(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-haiku-4-5", nil)
	tr.AddUsageFull(1_000_000, 0, 0, 0)
	// Haiku rate: $0.80/MTok.
	snap := tr.Snapshot()
	if snap.TotalUSD < 0.79 || snap.TotalUSD > 0.81 {
		t.Errorf("AddUsageFull: TotalUSD = %f; want ~$0.80 (Haiku tracker model)", snap.TotalUSD)
	}
}

// TestSetModel_ConcurrentSafe pins SetModel's mutex coverage —
// concurrent Snapshot reads during a SetModel write must not race.
// `go test -race` is the real check; this just exercises the path.
func TestSetModel_ConcurrentSafe(t *testing.T) {
	tr := NewTracker(NewPricer(nil), "claude-sonnet-4-6", nil)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			tr.SetModel("claude-opus-4-7")
			tr.SetModel("claude-haiku-4-5")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = tr.Snapshot().Model
		}
	}()
	wg.Wait()
	// Either model is valid here — we only care that no race occurred.
	got := tr.Snapshot().Model
	if got != "claude-opus-4-7" && got != "claude-haiku-4-5" {
		t.Errorf("unexpected final model: %q", got)
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

// trackerForBudgetTest builds a Tracker preloaded so that 1 input token
// + 1 output token costs exactly $0.000004 — close to the real Opus
// rate but small enough to keep the test arithmetic in the hundredths.
// Returns the tracker so each test can dial in spend by repeating
// AddUsage. The dollar-per-call helper keeps test math inline.
func trackerForBudgetTest(t *testing.T) (*Tracker, func(usd float64)) {
	t.Helper()
	// Rate: 1.0 input/M, 1.0 output/M. So 1M tokens of each = $2.
	// 1 token = $1e-6 input + $1e-6 output = $2e-6.
	pricer := NewPricer(map[string]Rate{
		"test-model": {InputPerMTok: 1.0, OutputPerMTok: 1.0},
	})
	tr := NewTracker(pricer, "test-model", nil)
	addCents := func(usd float64) {
		tokens := int64((usd / 2.0) * 1_000_000)
		tr.AddUsage(tokens, tokens)
	}
	return tr, addCents
}

// TestTracker_BudgetExceeded_NoBudget pins the documented contract:
// without a budget configured, BudgetExceeded is always false.
func TestTracker_BudgetExceeded_NoBudget(t *testing.T) {
	tr, spend := trackerForBudgetTest(t)
	spend(100.0) // run up the meter
	if tr.BudgetExceeded() {
		t.Error("BudgetExceeded should be false when no budget set, even at high spend")
	}
}

// TestTracker_BudgetExceeded_AtAndAboveCap covers the gate's two
// documented true branches: spend at the cap and spend over the cap.
func TestTracker_BudgetExceeded_AtAndAboveCap(t *testing.T) {
	tr, spend := trackerForBudgetTest(t)
	tr.SetBudget(1.00, nil, nil)
	spend(0.50)
	if tr.BudgetExceeded() {
		t.Error("BudgetExceeded false at half spend")
	}
	spend(0.50) // total now 1.00 == cap
	if !tr.BudgetExceeded() {
		t.Error("BudgetExceeded should be true at exactly the cap")
	}
	spend(0.10) // total now 1.10
	if !tr.BudgetExceeded() {
		t.Error("BudgetExceeded should be true above the cap")
	}
}

// TestTracker_BudgetWarn_FiresOnceAt80Pct exercises the warn-callback
// path. Crossing 80% fires the warn once; further usage that stays
// below 100% does not re-fire. Spend up to the cap also fires the
// hit callback exactly once.
func TestTracker_BudgetWarn_FiresOnceAt80Pct(t *testing.T) {
	tr, spend := trackerForBudgetTest(t)
	var warnFires, hitFires int
	var mu sync.Mutex
	tr.SetBudget(1.00,
		func(spent, cap float64) {
			mu.Lock()
			warnFires++
			mu.Unlock()
			if spent < 0.79 || spent > 0.91 {
				t.Errorf("warn fired at unexpected spend=%.4f (cap=%.4f)", spent, cap)
			}
		},
		func(spent, cap float64) {
			mu.Lock()
			hitFires++
			mu.Unlock()
		},
	)
	spend(0.50) // 50%
	mu.Lock()
	if warnFires != 0 {
		t.Errorf("warn fired prematurely at 50%%, fires=%d", warnFires)
	}
	mu.Unlock()
	spend(0.30) // 80%
	mu.Lock()
	if warnFires != 1 {
		t.Errorf("warn should fire exactly once at 80%%, fires=%d", warnFires)
	}
	mu.Unlock()
	spend(0.10) // 90%
	mu.Lock()
	if warnFires != 1 {
		t.Errorf("warn should not re-fire mid-band, fires=%d", warnFires)
	}
	mu.Unlock()
	spend(0.20) // 110% — crossed cap
	mu.Lock()
	if hitFires != 1 {
		t.Errorf("hit should fire exactly once at cap, fires=%d", hitFires)
	}
	mu.Unlock()
	// Further spend stays past cap; hit must not re-fire.
	spend(0.50)
	mu.Lock()
	if hitFires != 1 {
		t.Errorf("hit should not re-fire past cap, fires=%d", hitFires)
	}
	mu.Unlock()
}

// TestTracker_UpdateBudgetCap_RaisingResetsFlags exercises the
// "operator bumps /budget set" workflow: warn+hit fire once at the
// initial cap; raising the cap clear of current spend resets both
// flags so future re-crossings fire fresh notifications.
func TestTracker_UpdateBudgetCap_RaisingResetsFlags(t *testing.T) {
	tr, spend := trackerForBudgetTest(t)
	var warnFires, hitFires int
	var mu sync.Mutex
	tr.SetBudget(1.00,
		func(spent, cap float64) { mu.Lock(); warnFires++; mu.Unlock() },
		func(spent, cap float64) { mu.Lock(); hitFires++; mu.Unlock() },
	)
	spend(1.10) // cross 80% and 100% in one shot
	mu.Lock()
	if warnFires != 1 || hitFires != 1 {
		t.Fatalf("initial fires: warn=%d hit=%d, want 1/1", warnFires, hitFires)
	}
	mu.Unlock()
	// Operator bumps the cap to $5; spend is $1.10 well under, flags reset.
	tr.UpdateBudgetCap(5.00)
	if tr.BudgetExceeded() {
		t.Error("BudgetExceeded should clear after cap bump above current spend")
	}
	spend(3.00) // now $4.10 = 82% of $5
	mu.Lock()
	if warnFires != 2 {
		t.Errorf("warn should fire again after cap raise, fires=%d", warnFires)
	}
	mu.Unlock()
	spend(1.00) // now $5.10, over cap
	mu.Lock()
	if hitFires != 2 {
		t.Errorf("hit should fire again after cap raise, fires=%d", hitFires)
	}
	mu.Unlock()
}

// TestTracker_UpdateBudgetCap_LoweringDoesNotResetFlags pins the
// inverse: dropping the cap below current spend (or anywhere that
// keeps spend ≥ cap) must NOT reset the flags — that would re-fire
// the hit notification on every dispatch.
func TestTracker_UpdateBudgetCap_LoweringDoesNotResetFlags(t *testing.T) {
	tr, spend := trackerForBudgetTest(t)
	var warnFires, hitFires int
	var mu sync.Mutex
	tr.SetBudget(2.00,
		func(spent, cap float64) { mu.Lock(); warnFires++; mu.Unlock() },
		func(spent, cap float64) { mu.Lock(); hitFires++; mu.Unlock() },
	)
	spend(2.10) // cross both thresholds
	mu.Lock()
	first := hitFires
	mu.Unlock()
	// Now drop the cap to $1 — current spend $2.10 is way over.
	tr.UpdateBudgetCap(1.00)
	// AddUsage of zero won't recompute, but our spender adds tokens.
	spend(0.10)
	mu.Lock()
	if hitFires != first {
		t.Errorf("hit re-fired on cap drop, fires went %d -> %d", first, hitFires)
	}
	mu.Unlock()
}

// TestTracker_SetBudget_DisableViaZero confirms passing usdCap=0
// turns the gate off entirely — the snapshot's BudgetExceeded
// returns false and no callbacks fire.
func TestTracker_SetBudget_DisableViaZero(t *testing.T) {
	tr, spend := trackerForBudgetTest(t)
	var fired bool
	var mu sync.Mutex
	tr.SetBudget(1.00,
		func(spent, cap float64) { mu.Lock(); fired = true; mu.Unlock() },
		func(spent, cap float64) { mu.Lock(); fired = true; mu.Unlock() },
	)
	tr.SetBudget(0, nil, nil)
	spend(100.0)
	if tr.BudgetExceeded() {
		t.Error("BudgetExceeded should return false after SetBudget(0, ...)")
	}
	mu.Lock()
	if fired {
		t.Error("callbacks should not fire after budget disabled")
	}
	mu.Unlock()
}
