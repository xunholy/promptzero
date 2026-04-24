package defense

import (
	"sync"
	"time"
)

// Tracker accumulates per-MAC advertisement history so signatures that
// span multiple packets (high-frequency MAC rotation, payload churn) can
// be evaluated. Safe for concurrent use.
//
// Operators wire one Tracker per scan session, feed every observed
// advertisement through Classify, and read accumulated matches with
// Snapshot at the end (or on-the-fly via the per-call return value).
type Tracker struct {
	// RotationWindow is the rolling-window length used by the
	// high-frequency-MAC-rotation detector. Zero defaults to 60s.
	RotationWindow time.Duration

	// RotationThreshold is the number of distinct MACs from the same
	// approximate position (within RotationWindow) that triggers the
	// rotation match. Zero defaults to 8.
	RotationThreshold int

	mu      sync.Mutex
	history []seenMAC
	matches map[string][]Match // mac → matches observed for that mac
}

type seenMAC struct {
	mac        string
	observedAt time.Time
}

// Classify runs the stateless [Classify] plus the stateful rotation
// detector. Returns every match raised by either.
func (t *Tracker) Classify(ad Advertisement) []Match {
	statelessMatches := Classify(ad)

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.matches == nil {
		t.matches = map[string][]Match{}
	}

	now := ad.CapturedAt
	if now.IsZero() {
		now = time.Now()
	}
	if ad.Address != "" {
		t.history = append(t.history, seenMAC{mac: ad.Address, observedAt: now})
		t.gcLocked(now)
	}

	if rot, ok := t.detectRotationLocked(now); ok {
		statelessMatches = append(statelessMatches, rot)
	}

	if ad.Address != "" {
		t.matches[ad.Address] = append(t.matches[ad.Address], statelessMatches...)
	}
	return statelessMatches
}

// Snapshot returns every match observed since this Tracker was created,
// keyed by source MAC. The returned map is a copy — callers may mutate
// it freely.
func (t *Tracker) Snapshot() map[string][]Match {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[string][]Match, len(t.matches))
	for k, v := range t.matches {
		copyV := make([]Match, len(v))
		copy(copyV, v)
		out[k] = copyV
	}
	return out
}

// Reset clears all accumulated state.
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.history = nil
	t.matches = nil
}

func (t *Tracker) window() time.Duration {
	if t.RotationWindow > 0 {
		return t.RotationWindow
	}
	return 60 * time.Second
}

func (t *Tracker) threshold() int {
	if t.RotationThreshold > 0 {
		return t.RotationThreshold
	}
	return 8
}

// gcLocked drops observations older than the rotation window so the
// history slice does not grow unboundedly during long scans. Called
// under t.mu.
func (t *Tracker) gcLocked(now time.Time) {
	cutoff := now.Add(-t.window())
	first := 0
	for first < len(t.history) && t.history[first].observedAt.Before(cutoff) {
		first++
	}
	if first > 0 {
		t.history = t.history[first:]
	}
}

// detectRotationLocked returns a Match when the number of distinct MACs
// observed within the rotation window crosses the threshold. Called
// under t.mu.
func (t *Tracker) detectRotationLocked(now time.Time) (Match, bool) {
	uniq := make(map[string]struct{}, len(t.history))
	for _, h := range t.history {
		uniq[h.mac] = struct{}{}
	}
	if len(uniq) < t.threshold() {
		return Match{}, false
	}
	return Match{
		Signature:   SigHighFrequencyMACRotation,
		Description: formatRotationDescription(len(uniq), t.window()),
		FirstSeen:   now,
	}, true
}

func formatRotationDescription(uniqueCount int, window time.Duration) string {
	return "observed " + itoa(uniqueCount) + " distinct MACs within " + window.String() + " — characteristic of an active BLE-spam attack"
}

// itoa is a tiny stdlib-free integer formatter so this file does not
// pull "strconv" just for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
