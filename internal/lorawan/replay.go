// SPDX-License-Identifier: AGPL-3.0-or-later

package lorawan

import (
	"fmt"
	"strings"
)

// ReplayFrame is one already-decoded LoRaWAN data frame supplied by the
// caller (e.g. from the lorawan PHYPayload decoder). Only the cleartext
// FHDR fields are needed — no session key.
//
//   - DevAddr is the 4-byte device address (the FHDR field), grouping
//     frames by end-device.
//   - FCnt is the frame counter from the FHDR (the 16-bit on-air value).
//   - MType is the message type string ("UnconfirmedDataUp", "ConfirmedDataDown",
//     …); its Up/Down direction separates the independent uplink and
//     downlink counters. Empty = treated as one stream (with a note).
type ReplayFrame struct {
	DevAddr string `json:"dev_addr"`
	FCnt    int    `json:"fcnt"`
	MType   string `json:"mtype,omitempty"`
}

// ReplayObservation is one flagged signal — an OBSERVATION with its benign
// explanation, never a verdict.
type ReplayObservation struct {
	Kind      string `json:"kind"`     // "fcnt_reuse" | "fcnt_regression"
	Severity  string `json:"severity"` // "warning"
	DevAddr   string `json:"dev_addr"`
	Direction string `json:"direction"`
	Detail    string `json:"detail"`
}

// ReplayStreamSummary is the per-(device,direction) roll-up.
type ReplayStreamSummary struct {
	Frames               int `json:"frames"`
	LogicalTransmissions int `json:"logical_transmissions"`
	Retransmissions      int `json:"retransmissions"`
	MaxFCnt              int `json:"max_fcnt"`
}

// ReplayAnalysis is the structured result of AnalyzeReplay.
type ReplayAnalysis struct {
	FramesAnalyzed int                             `json:"frames_analyzed"`
	Streams        int                             `json:"streams"`
	PerStream      map[string]*ReplayStreamSummary `json:"per_stream"`
	Observations   []ReplayObservation             `json:"observations"`
	Notes          []string                        `json:"notes,omitempty"`
}

// AnalyzeReplay inspects an ordered sequence of decoded LoRaWAN data frames
// for replay / frame-counter-reuse — the attack the spec's mandatory FCnt
// check exists to stop (replayed captured uplinks; ABP devices that reset
// their counter). Frames are grouped by (DevAddr, direction); the uplink
// and downlink counters are independent, so they are tracked separately.
//
// Two deterministic, KEY-FREE signals (FCnt is cleartext in the FHDR), each
// an OBSERVATION with its benign explanation:
//
//   - fcnt_reuse (warning): a frame counter value reappears for a stream
//     after the device had already moved past it — a rolling counter must
//     not repeat, so this is the core replay signature. CONSECUTIVE equal
//     counters are NOT flagged: a confirmed frame is legitimately
//     retransmitted with the same FCnt until acknowledged (collapsed to one
//     logical transmission). Benign explanation: the operator's own tooling
//     re-sent a captured frame.
//   - fcnt_regression (warning): a counter lower than the running max for
//     the stream. Counters increase monotonically by design. Benign
//     explanation: a 16-bit FCnt rollover (65535 -> 0), an ABP device that
//     was power-cycled, or frames fed out of capture order.
func AnalyzeReplay(frames []ReplayFrame) (*ReplayAnalysis, error) {
	if len(frames) == 0 {
		return nil, fmt.Errorf("lorawan: no frames supplied")
	}
	a := &ReplayAnalysis{FramesAnalyzed: len(frames), PerStream: map[string]*ReplayStreamSummary{}}

	type st struct {
		last    int
		hasLast bool
		max     int
		seen    map[int]bool
	}
	state := map[string]*st{}
	sawUnknownDir := false

	for _, f := range frames {
		dev := strings.TrimSpace(f.DevAddr)
		if dev == "" {
			a.Notes = append(a.Notes, "frame skipped: missing dev_addr")
			continue
		}
		dir := direction(f.MType)
		if dir == "unknown" {
			sawUnknownDir = true
		}
		key := dev + "|" + dir

		sum := a.PerStream[key]
		if sum == nil {
			sum = &ReplayStreamSummary{}
			a.PerStream[key] = sum
			state[key] = &st{seen: map[int]bool{}}
		}
		sum.Frames++
		s := state[key]

		// Consecutive equal FCnt = legitimate confirmed-frame retransmission.
		if s.hasLast && f.FCnt == s.last {
			sum.Retransmissions++
			continue
		}
		sum.LogicalTransmissions++

		switch {
		case s.seen[f.FCnt]:
			a.Observations = append(a.Observations, ReplayObservation{
				Kind:      "fcnt_reuse",
				Severity:  "warning",
				DevAddr:   dev,
				Direction: dir,
				Detail: fmt.Sprintf("DevAddr %s (%s) reused frame counter %d after moving past it — a "+
					"rolling counter must be used once, so this is the core LoRaWAN replay signature. "+
					"Benign explanation: the operator's own tooling re-sent a captured frame.", dev, dir, f.FCnt),
			})
		case s.hasLast && f.FCnt < s.max:
			a.Observations = append(a.Observations, ReplayObservation{
				Kind:      "fcnt_regression",
				Severity:  "warning",
				DevAddr:   dev,
				Direction: dir,
				Detail: fmt.Sprintf("DevAddr %s (%s) frame counter regressed to %d (running max %d) — counters "+
					"increase monotonically by design. Benign explanation: a 16-bit FCnt rollover, an ABP "+
					"device power-cycled, or frames fed out of capture order.", dev, dir, f.FCnt, s.max),
			})
		}

		s.seen[f.FCnt] = true
		s.last = f.FCnt
		s.hasLast = true
		if f.FCnt > s.max {
			s.max = f.FCnt
		}
		sum.MaxFCnt = s.max
	}

	a.Streams = len(a.PerStream)
	if sawUnknownDir {
		a.Notes = append(a.Notes,
			"some frames had no Up/Down MType; uplink and downlink counters are independent, so supply MType to avoid cross-counting")
	}
	if len(a.Observations) == 0 && a.Streams > 0 {
		a.Notes = append(a.Notes, "no frame-counter reuse or regression observed")
	}
	return a, nil
}

// direction maps a LoRaWAN MType string to "uplink" / "downlink" /
// "unknown" so the independent up/down counters are tracked separately.
func direction(mtype string) string {
	m := strings.ToLower(mtype)
	switch {
	case strings.Contains(m, "up"):
		return "uplink"
	case strings.Contains(m, "down"):
		return "downlink"
	default:
		return "unknown"
	}
}
