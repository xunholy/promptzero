// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wifidefense provides defensive, blue-team analysers over
// sequences of already-decoded 802.11 frames. It does no RF work — the
// caller supplies frame fields (e.g. from wifi_80211 decodes) and the
// analyser reports deterministic observations.
//
// # Wrap-vs-native judgement
//
// Native. The 802.11 deauthentication / disassociation flood is the
// canonical WiFi denial-of-service (aircrack-ng's aireplay-0, the Marauder
// / ESP32 "deauth" attack, MDK4). Detecting it from a capture is a pure,
// deterministic transform over management-frame metadata — frame subtype,
// the destination address, the source/BSSID, and the 802.11 reason code —
// with no SDR, adapter, or crypto at analysis time. Like internal/tpms's
// AnalyzeFrames and internal/subghz's AnalyzeRollback, every flagged
// condition is an OBSERVATION with its benign explanation stated, never a
// definitive attack verdict.
package wifidefense

import (
	"fmt"
	"strings"
)

// broadcastMAC is the all-ones destination — a frame addressed to every
// station in the BSS.
const broadcastMAC = "FFFFFFFFFFFF"

// DefaultFloodThreshold is the deauth+disassoc count above which the
// volume signal fires when no threshold is supplied.
const DefaultFloodThreshold = 10

// Frame is one already-decoded 802.11 management frame supplied by the
// caller. Only the deauthentication (subtype "deauth") and disassociation
// (subtype "disassoc") subtypes drive the analysis; other subtypes are
// counted toward the total and otherwise ignored.
type Frame struct {
	Subtype string `json:"subtype"`          // "deauth" | "disassoc" | other
	Src     string `json:"src,omitempty"`    // transmitter address
	Dst     string `json:"dst,omitempty"`    // destination address
	BSSID   string `json:"bssid,omitempty"`  // BSS identifier
	Reason  int    `json:"reason,omitempty"` // 802.11 reason code
}

// Observation is one flagged signal. It is an OBSERVATION with
// interpretation, never a verdict — the benign explanation is always
// stated so the operator correlates rather than concludes.
type Observation struct {
	Kind     string `json:"kind"`     // "broadcast_deauth" | "deauth_flood" | "targeted_client"
	Severity string `json:"severity"` // "info" | "warning"
	Detail   string `json:"detail"`
}

// Analysis is the structured result of AnalyzeDeauth.
type Analysis struct {
	FramesAnalyzed  int            `json:"frames_analyzed"`
	DeauthFrames    int            `json:"deauth_frames"`
	DisassocFrames  int            `json:"disassoc_frames"`
	BroadcastFrames int            `json:"broadcast_frames"`
	ReasonCodes     map[string]int `json:"reason_codes,omitempty"`
	Observations    []Observation  `json:"observations"`
	Notes           []string       `json:"notes,omitempty"`
}

// reasonNames maps the common 802.11 reason codes (802.11-2020 Table 9-49)
// to short names, for the surfaced histogram.
var reasonNames = map[int]string{
	1:  "Unspecified",
	2:  "Prior auth no longer valid",
	3:  "Deauth: leaving",
	4:  "Disassoc: inactivity",
	5:  "Disassoc: AP overloaded",
	6:  "Class-2 frame from nonauth STA",
	7:  "Class-3 frame from nonassoc STA",
	8:  "Disassoc: leaving",
	9:  "STA not authenticated",
	15: "4-way handshake timeout",
}

// AnalyzeDeauth inspects a sequence of 802.11 frames for the signatures of
// a deauthentication / disassociation flood. floodThreshold is the
// deauth+disassoc count above which the volume signal fires (<=0 uses
// DefaultFloodThreshold).
//
// Three deterministic signals are surfaced, each with its benign
// explanation:
//
//   - broadcast_deauth (warning): deauth/disassoc frames addressed to the
//     broadcast address kick every client in the BSS at once. There is no
//     benign reason to broadcast-deauth, so this is the clearest flood
//     signature; the only innocent explanation is a misbehaving AP/driver.
//   - deauth_flood (warning): the deauth+disassoc count exceeds the
//     threshold. Consistent with an aireplay/MDK4/Marauder flood OR a very
//     unstable RF environment / a busy AP shedding load — correlate with
//     the reason-code mix.
//   - targeted_client (info): one destination receives a disproportionate
//     share of the deauths from one BSSID — a targeted disconnect (e.g. to
//     force a handshake recapture) rather than an indiscriminate flood.
func AnalyzeDeauth(frames []Frame, floodThreshold int) (*Analysis, error) {
	if len(frames) == 0 {
		return nil, fmt.Errorf("wifidefense: no frames supplied")
	}
	if floodThreshold <= 0 {
		floodThreshold = DefaultFloodThreshold
	}

	a := &Analysis{
		FramesAnalyzed: len(frames),
		ReasonCodes:    map[string]int{},
	}
	// victims keyed by "bssid|dst" → count, for the targeted signal.
	victim := map[string]int{}

	for _, f := range frames {
		st := strings.ToLower(strings.TrimSpace(f.Subtype))
		isDeauth := st == "deauth" || st == "deauthentication"
		isDisassoc := st == "disassoc" || st == "disassociation"
		if !isDeauth && !isDisassoc {
			continue
		}
		if isDeauth {
			a.DeauthFrames++
		} else {
			a.DisassocFrames++
		}
		a.ReasonCodes[reasonName(f.Reason)]++

		if normMAC(f.Dst) == broadcastMAC {
			a.BroadcastFrames++
		} else if dst := normMAC(f.Dst); dst != "" {
			victim[normMAC(f.BSSID)+"|"+dst]++
		}
	}

	total := a.DeauthFrames + a.DisassocFrames

	if a.BroadcastFrames > 0 {
		a.Observations = append(a.Observations, Observation{
			Kind:     "broadcast_deauth",
			Severity: "warning",
			Detail: fmt.Sprintf("%d deauth/disassoc frame(s) addressed to the broadcast address — these "+
				"kick every client in the BSS at once. There is no benign reason to broadcast-deauth, so "+
				"this is the clearest flood signature; the only innocent explanation is a misbehaving "+
				"AP/driver.", a.BroadcastFrames),
		})
	}

	if total >= floodThreshold {
		a.Observations = append(a.Observations, Observation{
			Kind:     "deauth_flood",
			Severity: "warning",
			Detail: fmt.Sprintf("%d deauth/disassoc frames (>= threshold %d) — consistent with an "+
				"aireplay / MDK4 / Marauder deauth flood OR a very unstable RF environment / an AP "+
				"shedding load. Correlate with the reason-code mix and timing.", total, floodThreshold),
		})
	}

	// Targeted: a single victim taking the majority of a meaningful number
	// of deauths.
	for key, n := range victim {
		if n >= 5 && total > 0 && n*2 >= total {
			parts := strings.SplitN(key, "|", 2)
			a.Observations = append(a.Observations, Observation{
				Kind:     "targeted_client",
				Severity: "info",
				Detail: fmt.Sprintf("client %s received %d of %d deauth/disassoc frames from BSSID %s — a "+
					"targeted disconnect (e.g. to force a handshake recapture) rather than an "+
					"indiscriminate flood. Benign explanation: one flaky client roaming.",
					parts[1], n, total, emptyAsAny(parts[0])),
			})
		}
	}

	if total == 0 {
		a.Notes = append(a.Notes, "no deauthentication or disassociation frames in the sequence")
	}
	return a, nil
}

func reasonName(code int) string {
	if code == 0 {
		return "0 (none/unset)"
	}
	if n, ok := reasonNames[code]; ok {
		return fmt.Sprintf("%d (%s)", code, n)
	}
	return fmt.Sprintf("%d", code)
}

// normMAC upper-cases a MAC and strips separators so "ff:ff:.." compares
// equal to "FFFFFF..".
func normMAC(s string) string {
	s = strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(strings.TrimSpace(s))
	return strings.ToUpper(s)
}

func emptyAsAny(s string) string {
	if s == "" {
		return "(any)"
	}
	return s
}
