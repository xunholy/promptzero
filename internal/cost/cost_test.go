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
