// SPDX-License-Identifier: AGPL-3.0-or-later

package wifidefense

import (
	"fmt"
	"sort"
	"strings"
)

// AP is one already-decoded beacon / probe-response observation supplied by
// the caller (e.g. from wifi_80211 + wifi_rsn_decode). Security is the
// posture string — "Open", "WPA2-Personal (PSK)", "WPA3-Personal (SAE)",
// etc. (whatever wifi_rsn_decode derived, or "Open" when no RSN IE).
type AP struct {
	SSID     string `json:"ssid"`
	BSSID    string `json:"bssid"`
	Security string `json:"security,omitempty"`
	Channel  int    `json:"channel,omitempty"`
}

// RogueObservation is one flagged rogue-AP / evil-twin signal — an
// OBSERVATION with its benign explanation stated, never a verdict.
type RogueObservation struct {
	Kind     string `json:"kind"`     // "security_mismatch" | "bssid_changed_security" | "ssid_multiple_bssid"
	Severity string `json:"severity"` // "info" | "warning"
	SSID     string `json:"ssid,omitempty"`
	BSSID    string `json:"bssid,omitempty"`
	Detail   string `json:"detail"`
}

// RogueAnalysis is the structured result of AnalyzeRogueAP.
type RogueAnalysis struct {
	APsAnalyzed  int                `json:"aps_analyzed"`
	UniqueSSIDs  int                `json:"unique_ssids"`
	UniqueBSSIDs int                `json:"unique_bssids"`
	Observations []RogueObservation `json:"observations"`
	Notes        []string           `json:"notes,omitempty"`
}

// AnalyzeRogueAP inspects a set of beacon/probe-response observations for
// rogue-AP / evil-twin signatures. Observations are grouped by SSID and by
// BSSID; ordering matters only for the per-BSSID change signal.
//
// Three deterministic signals, each with its benign explanation:
//
//   - security_mismatch (warning): one SSID is advertised with more than one
//     distinct security posture (e.g. Open AND WPA2). This is the classic
//     evil-twin / downgrade lure — a rogue AP cloning a protected network's
//     name with weaker (or no) security to harvest associations. Benign
//     explanation: a site mid-migration running mixed APs, or inconsistent
//     posture labelling by the caller.
//   - bssid_changed_security (warning): a single BSSID's security posture
//     changes across the capture — consistent with a spoofed/cloned BSSID
//     or an AP hijack. Benign explanation: a genuine reconfiguration during
//     the capture window.
//   - ssid_multiple_bssid (info): one SSID is served by several BSSIDs with
//     a consistent posture — normal for enterprise roaming / mesh, but
//     surfaced so the operator can confirm every BSSID is theirs.
//
// Hidden SSIDs (empty name) are excluded from the SSID-grouped signals.
func AnalyzeRogueAP(aps []AP) (*RogueAnalysis, error) {
	if len(aps) == 0 {
		return nil, fmt.Errorf("wifidefense: no APs supplied")
	}
	a := &RogueAnalysis{APsAnalyzed: len(aps)}

	// ssid -> ordered set of distinct securities, set of bssids.
	type ssidAgg struct {
		securities []string
		secSet     map[string]bool
		bssids     map[string]bool
	}
	bySSID := map[string]*ssidAgg{}
	// bssid -> ordered distinct securities (for the change signal).
	type bssidAgg struct {
		securities []string
		secSet     map[string]bool
	}
	byBSSID := map[string]*bssidAgg{}
	allSSID := map[string]bool{}
	allBSSID := map[string]bool{}

	for _, ap := range aps {
		ssid := strings.TrimSpace(ap.SSID)
		bssid := normMAC(ap.BSSID)
		sec := strings.TrimSpace(ap.Security)
		if sec == "" {
			sec = "(unspecified)"
		}
		if ssid != "" {
			allSSID[ssid] = true
		}
		if bssid != "" {
			allBSSID[bssid] = true
		}

		if ssid != "" {
			g := bySSID[ssid]
			if g == nil {
				g = &ssidAgg{secSet: map[string]bool{}, bssids: map[string]bool{}}
				bySSID[ssid] = g
			}
			if !g.secSet[sec] {
				g.secSet[sec] = true
				g.securities = append(g.securities, sec)
			}
			if bssid != "" {
				g.bssids[bssid] = true
			}
		}
		if bssid != "" {
			g := byBSSID[bssid]
			if g == nil {
				g = &bssidAgg{secSet: map[string]bool{}}
				byBSSID[bssid] = g
			}
			if !g.secSet[sec] {
				g.secSet[sec] = true
				g.securities = append(g.securities, sec)
			}
		}
	}
	a.UniqueSSIDs = len(allSSID)
	a.UniqueBSSIDs = len(allBSSID)

	for _, ssid := range sortedKeys(bySSID) {
		g := bySSID[ssid]
		switch {
		case len(g.securities) > 1:
			a.Observations = append(a.Observations, RogueObservation{
				Kind:     "security_mismatch",
				Severity: "warning",
				SSID:     ssid,
				Detail: fmt.Sprintf("SSID %q is advertised with %d distinct security postures (%s) across "+
					"%d BSSID(s) — the classic evil-twin / downgrade lure, a rogue AP cloning the name with "+
					"weaker security to harvest associations. Benign explanation: a site mid-migration "+
					"running mixed APs, or inconsistent posture labelling.",
					ssid, len(g.securities), strings.Join(g.securities, " | "), len(g.bssids)),
			})
		case len(g.bssids) > 1:
			a.Observations = append(a.Observations, RogueObservation{
				Kind:     "ssid_multiple_bssid",
				Severity: "info",
				SSID:     ssid,
				Detail: fmt.Sprintf("SSID %q is served by %d BSSIDs with a consistent posture (%s) — normal "+
					"for enterprise roaming / mesh, but confirm every BSSID is yours.",
					ssid, len(g.bssids), g.securities[0]),
			})
		}
	}

	for _, bssid := range sortedKeys(byBSSID) {
		g := byBSSID[bssid]
		if len(g.securities) > 1 {
			a.Observations = append(a.Observations, RogueObservation{
				Kind:     "bssid_changed_security",
				Severity: "warning",
				BSSID:    bssid,
				Detail: fmt.Sprintf("BSSID %s changed security posture across the capture (%s) — consistent "+
					"with a spoofed/cloned BSSID or an AP hijack. Benign explanation: a genuine "+
					"reconfiguration during the capture window.",
					bssid, strings.Join(g.securities, " -> ")),
			})
		}
	}

	if len(a.Observations) == 0 {
		a.Notes = append(a.Notes, "no security mismatches or BSSID posture changes observed")
	}
	return a, nil
}

// sortedKeys / sortedKeys2 return map keys in deterministic order so the
// observation list is stable (map iteration is randomised in Go).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
