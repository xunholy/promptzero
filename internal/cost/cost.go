// Package cost tracks Anthropic token usage and running dollar cost per
// PromptZero session, and implements the simple "consecutive errors →
// offline" heuristic that flips the observability offline banner.
//
// Pricer is a read-only rate table: model name → USD per million tokens
// (input/output split). PromptZero ships with built-in rates for the
// current Claude lineup; operators can override or extend the table via
// config.
//
// Tracker accumulates tokens and stream errors. When three consecutive
// streams fail within a 60s window, Tracker flips to offline and invokes
// the Offline hook; a successful stream clears the error run and flips
// back online. The three-strikes rule keeps transient network hiccups
// from flipping the banner on every stutter.
package cost

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Rate is one model's price schedule. Values are USD per million tokens.
type Rate struct {
	InputPerMTok  float64
	OutputPerMTok float64
}

// Pricer owns the rate table. Lookup is case-insensitive and falls
// through on unknown models to (0, 0) so the Tracker still records
// token counts even when the rate isn't known.
type Pricer struct {
	rates map[string]Rate
}

// DefaultRates returns a copy of the built-in rate table. Current Claude
// lineup as of late-2025: Opus 4.7 $15/$75, Sonnet 4.6 $3/$15,
// Haiku 4.5 $0.80/$4. Values should track Anthropic's public pricing
// page; adjust via config override when it drifts.
func DefaultRates() map[string]Rate {
	return map[string]Rate{
		"claude-opus-4-7":   {InputPerMTok: 15.0, OutputPerMTok: 75.0},
		"claude-sonnet-4-6": {InputPerMTok: 3.0, OutputPerMTok: 15.0},
		"claude-haiku-4-5":  {InputPerMTok: 0.80, OutputPerMTok: 4.0},
	}
}

// NewPricer seeds a Pricer with DefaultRates plus any overrides. Keys
// are normalized (trimmed, lower-cased) so "Claude-Opus-4-7" and
// "claude-opus-4-7" resolve to the same row.
func NewPricer(overrides map[string]Rate) *Pricer {
	table := DefaultRates()
	for k, v := range overrides {
		table[normalizeKey(k)] = v
	}
	return &Pricer{rates: table}
}

// Rate returns the per-million-token rates for the given model. Unknown
// models return zero rates (and ok=false); callers typically still
// record the token counts with zero cost.
func (p *Pricer) Rate(model string) (Rate, bool) {
	r, ok := p.rates[normalizeKey(model)]
	return r, ok
}

// Cost computes USD for (input, output) token counts against the model's
// rates. Zero rates produce zero cost.
func (p *Pricer) Cost(model string, inTokens, outTokens int64) float64 {
	r, _ := p.Rate(model)
	return float64(inTokens)/1_000_000*r.InputPerMTok +
		float64(outTokens)/1_000_000*r.OutputPerMTok
}

// CostWithCache is Cost plus prompt-cache read and creation tokens.
// Cache reads are billed at 0.1x the normal input rate; cache
// creations at 1.25x. The multipliers match Anthropic's published
// pricing as of late 2025; if they drift, this is the only place to
// update.
func (p *Pricer) CostWithCache(model string, inTokens, outTokens, cacheReadTokens, cacheCreationTokens int64) float64 {
	r, _ := p.Rate(model)
	return float64(inTokens)/1_000_000*r.InputPerMTok +
		float64(outTokens)/1_000_000*r.OutputPerMTok +
		float64(cacheReadTokens)/1_000_000*r.InputPerMTok*0.10 +
		float64(cacheCreationTokens)/1_000_000*r.InputPerMTok*1.25
}

func normalizeKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// errRunWindow is the rolling window used by the offline heuristic: we
// only count an error toward the three-strikes streak if it lands within
// this span of the previous error.
const errRunWindow = 60 * time.Second

// errsForOffline is how many consecutive errors (within the window) flip
// the tracker into offline mode.
const errsForOffline = 3

// Tracker accumulates token counts, dollar cost, and stream error
// streaks. It is safe for concurrent use. A zero-value Tracker is NOT
// usable — call NewTracker.
type Tracker struct {
	pricer *Pricer
	model  string
	now    func() time.Time

	mu                  sync.Mutex
	inTokens            int64
	outTokens           int64
	cacheReadTokens     int64
	cacheCreationTokens int64
	totalUSD            float64
	errorRun            int
	lastErrorAt         time.Time
	offline             bool
	onOffline           func(bool) // fired on transitions (false→true or true→false)
}

// NewTracker builds a Tracker bound to a specific model. The offline
// hook is invoked (with the new state) on every transition — pass nil
// to disable. Model can be changed later via SetModel when the user
// picks a new default mid-session.
func NewTracker(p *Pricer, model string, onOffline func(bool)) *Tracker {
	return &Tracker{
		pricer:    p,
		model:     model,
		now:       time.Now,
		onOffline: onOffline,
	}
}

// SetModel updates the tracker's active model. Past usage stays
// attributed to the prior model's cost — only future AddUsage calls pick
// up the new rate.
func (t *Tracker) SetModel(model string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.model = model
}

// AddUsage records one response's input/output token counts and bumps
// the running USD total. Any successful usage record also clears the
// consecutive-error run and flips the tracker back online if it was
// offline. Prefer AddUsageFull for callers that have cache token
// counters — this wrapper ignores them.
func (t *Tracker) AddUsage(inTokens, outTokens int64) {
	t.AddUsageFull(inTokens, outTokens, 0, 0)
}

// AddUsageFull is the complete version of AddUsage that also records
// prompt-cache read / creation tokens. Cache-read tokens are billed at
// ~10 % of the normal input rate (Anthropic's current published
// number); cache-creation tokens are billed at ~125 % to amortise the
// cache write. Model rates default to uncached input pricing if no
// cache rate is configured, so the dollar line is always conservative.
func (t *Tracker) AddUsageFull(inTokens, outTokens, cacheReadTokens, cacheCreationTokens int64) {
	if inTokens <= 0 && outTokens <= 0 && cacheReadTokens <= 0 && cacheCreationTokens <= 0 {
		return
	}
	t.mu.Lock()
	t.inTokens += inTokens
	t.outTokens += outTokens
	t.cacheReadTokens += cacheReadTokens
	t.cacheCreationTokens += cacheCreationTokens
	t.totalUSD += t.pricer.CostWithCache(t.model, inTokens, outTokens, cacheReadTokens, cacheCreationTokens)
	wasOffline := t.offline
	t.errorRun = 0
	t.offline = false
	hook := t.onOffline
	t.mu.Unlock()

	if wasOffline && hook != nil {
		hook(false)
	}
}

// RecordStreamError notifies the tracker that one Messages.NewStreaming
// call failed. Three failures inside errRunWindow flip offline.
func (t *Tracker) RecordStreamError() {
	t.mu.Lock()
	now := t.now()
	if t.lastErrorAt.IsZero() || now.Sub(t.lastErrorAt) > errRunWindow {
		t.errorRun = 1
	} else {
		t.errorRun++
	}
	t.lastErrorAt = now

	var hook func(bool)
	var flip bool
	if !t.offline && t.errorRun >= errsForOffline {
		t.offline = true
		hook = t.onOffline
		flip = true
	}
	t.mu.Unlock()

	if flip && hook != nil {
		hook(true)
	}
}

// Snapshot is a point-in-time copy of the Tracker's accumulated state.
type Snapshot struct {
	Model               string
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	TotalUSD            float64
	Offline             bool
}

// Snapshot returns the current state for the /cost REPL command and the
// /debug view.
func (t *Tracker) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Snapshot{
		Model:               t.model,
		InputTokens:         t.inTokens,
		OutputTokens:        t.outTokens,
		CacheReadTokens:     t.cacheReadTokens,
		CacheCreationTokens: t.cacheCreationTokens,
		TotalUSD:            t.totalUSD,
		Offline:             t.offline,
	}
}

// CacheHitRate returns the fraction of prompt-cacheable input tokens
// that landed on an existing cache (vs. paid full-price for cache
// creation). Returns 0 when neither counter has moved yet so fresh
// sessions don't render a divide-by-zero. Intended for /stats and
// dashboard display.
func (s Snapshot) CacheHitRate() float64 {
	total := s.CacheReadTokens + s.CacheCreationTokens
	if total == 0 {
		return 0
	}
	return float64(s.CacheReadTokens) / float64(total)
}

// Format returns the single-line human summary used by /cost and
// /status.
func (s Snapshot) Format() string {
	banner := ""
	if s.Offline {
		banner = "  [OFFLINE]"
	}
	cache := ""
	if s.CacheReadTokens+s.CacheCreationTokens > 0 {
		cache = fmt.Sprintf("  cache_read=%d cache_write=%d hit_rate=%.0f%%",
			s.CacheReadTokens, s.CacheCreationTokens, s.CacheHitRate()*100)
	}
	return fmt.Sprintf("model=%s  input=%d  output=%d  cost=$%.4f%s%s",
		s.Model, s.InputTokens, s.OutputTokens, s.TotalUSD, cache, banner)
}
