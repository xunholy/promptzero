// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"fmt"
	"strings"
)

// RollbackObservation is one signal flagged during rolling-code sequence
// analysis. Like internal/tpms.Anomaly it is an OBSERVATION with
// interpretation, never a definitive attack verdict — every flagged
// condition names its benign explanation so the operator correlates
// rather than concludes.
type RollbackObservation struct {
	Kind     string `json:"kind"`     // "replayed_code" | "counter_regression"
	Severity string `json:"severity"` // "info" | "warning"
	TxID     string `json:"tx_id"`
	Detail   string `json:"detail"`
}

// RollbackFrame is one captured rolling-code transmission supplied by the
// caller (already demodulated/decoded; this analyser does no RF work).
//
//   - ID is the fixed transmitter identity — the serial / fixed code that
//     stays constant across presses (e.g. a KeeLoq 28-bit serial, a
//     Security+ fixed portion). Frames are grouped by it.
//   - Code is the full rolling/hopping code AS TRANSMITTED (hex or any
//     stable string). This is observable without the manufacturer key.
//   - Counter is the OPTIONAL decrypted rolling counter, supplied only
//     when the caller holds the key. When present it enables the hard
//     monotonicity check; when nil only the key-free duplicate check runs.
type RollbackFrame struct {
	ID      string `json:"id"`
	Code    string `json:"code"`
	Counter *int64 `json:"counter,omitempty"`
}

// TxSummary is the per-transmitter roll-up.
type TxSummary struct {
	Frames               int `json:"frames"`
	LogicalTransmissions int `json:"logical_transmissions"`
	BurstRepeats         int `json:"burst_repeats"`
	ReplayedCodes        int `json:"replayed_codes"`
	CounterRegressions   int `json:"counter_regressions"`
}

// RollbackAnalysis is the structured result of AnalyzeRollback.
type RollbackAnalysis struct {
	FramesAnalyzed int                   `json:"frames_analyzed"`
	FramesValid    int                   `json:"frames_valid"`
	Transmitters   int                   `json:"transmitters"`
	PerTx          map[string]*TxSummary `json:"per_tx"`
	Observations   []RollbackObservation `json:"observations"`
	Notes          []string              `json:"notes,omitempty"`
}

// AnalyzeRollback inspects an ordered sequence of captured rolling-code
// frames for the signatures of a RollBack / replay attack (Kaiser et al.,
// "RollBack: A New Time-Agnostic Replay Attack Against the Automotive
// Remote Keyless Entry Systems", DEF CON 2022). Frames are taken in
// observation order (index 0 = earliest) and grouped by transmitter ID.
//
// Two deterministic signals are surfaced, both with their benign
// explanation stated:
//
//   - replayed_code (key-free): a rolling code that REappears for a
//     transmitter after that transmitter had already moved on to a
//     different code. A rolling code is meant to be used exactly once, so
//     a non-consecutive duplicate is the core replay signature. CONSECUTIVE
//     identical codes are NOT flagged — a remote legitimately retransmits
//     the same code several times per button press (a "burst"), and those
//     are collapsed into one logical transmission. Benign explanation: a
//     captured .sub being re-sent by the operator's own tooling, or a
//     duplicated capture file.
//   - counter_regression (only when decrypted counters are supplied): a
//     rolling counter lower than the running maximum already seen for that
//     transmitter. Counters increase monotonically by design, so a
//     regression is a hard invariant violation. Benign explanation: frames
//     fed out of capture order, or two remotes cloned to the same serial.
//
// No RF, timing, or signal-strength heuristic is used — only the
// caller-supplied, deterministically-checkable fields — so the analyser
// never produces the confidently-wrong reading this codebase refuses to.
func AnalyzeRollback(frames []RollbackFrame) (*RollbackAnalysis, error) {
	if len(frames) == 0 {
		return nil, fmt.Errorf("subghz: no frames supplied")
	}

	a := &RollbackAnalysis{
		FramesAnalyzed: len(frames),
		PerTx:          map[string]*TxSummary{},
	}

	// Per-transmitter running state, in observation order.
	type txState struct {
		lastCode   string         // most recent logical code (burst collapse)
		seenAt     map[string]int // code -> index of its first logical use
		maxCounter int64          // running max of supplied counters
		hasCounter bool           // whether any counter has been seen
	}
	state := map[string]*txState{}

	for i, f := range frames {
		id := strings.TrimSpace(f.ID)
		code := normalizeCode(f.Code)
		if id == "" || code == "" {
			a.Notes = append(a.Notes,
				fmt.Sprintf("frame %d skipped: missing id or code", i))
			continue
		}
		a.FramesValid++

		sum := a.PerTx[id]
		if sum == nil {
			sum = &TxSummary{}
			a.PerTx[id] = sum
			state[id] = &txState{seenAt: map[string]int{}}
		}
		sum.Frames++
		st := state[id]

		// Consecutive identical code = burst retransmission of one press.
		if code == st.lastCode {
			sum.BurstRepeats++
			continue
		}

		sum.LogicalTransmissions++

		// Non-consecutive duplicate = the rolling code was reused.
		if first, ok := st.seenAt[code]; ok {
			sum.ReplayedCodes++
			a.Observations = append(a.Observations, RollbackObservation{
				Kind:     "replayed_code",
				Severity: "warning",
				TxID:     id,
				Detail: fmt.Sprintf("transmitter %s reused rolling code %s at frame %d "+
					"(first seen at frame %d, with different codes in between) — a rolling code "+
					"should be used only once, so this is the core replay/RollBack signature. "+
					"Benign explanation: the operator's own tooling re-sent a captured .sub, or a "+
					"duplicated capture. Correlate with who transmitted before concluding.",
					id, code, i, first),
			})
		} else {
			st.seenAt[code] = i
		}
		st.lastCode = code

		// Optional decrypted-counter monotonicity check.
		if f.Counter != nil {
			c := *f.Counter
			if st.hasCounter && c < st.maxCounter {
				sum.CounterRegressions++
				a.Observations = append(a.Observations, RollbackObservation{
					Kind:     "counter_regression",
					Severity: "warning",
					TxID:     id,
					Detail: fmt.Sprintf("transmitter %s counter regressed to %d at frame %d "+
						"(running max %d) — rolling counters increase monotonically, so a decrease is "+
						"a hard invariant violation. Benign explanation: frames fed out of capture "+
						"order, or two remotes cloned to the same serial.",
						id, c, i, st.maxCounter),
				})
			}
			if !st.hasCounter || c > st.maxCounter {
				st.maxCounter = c
			}
			st.hasCounter = true
		}
	}

	a.Transmitters = len(a.PerTx)
	if a.FramesValid == 0 {
		a.Notes = append(a.Notes, "no frame had both an id and a code; nothing to correlate")
	}
	if len(a.Observations) == 0 && a.FramesValid > 0 {
		a.Notes = append(a.Notes,
			"no replayed codes or counter regressions observed across the sequence")
	}
	return a, nil
}

// normalizeCode upper-cases a rolling code and strips the separators and
// any "0x" prefix operators paste, so "0x1A:2B" and "1a2b" compare equal.
func normalizeCode(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t':
			continue
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) >= 2 && (out[0:2] == "0x" || out[0:2] == "0X") {
		out = out[2:]
	}
	return strings.ToUpper(out)
}
