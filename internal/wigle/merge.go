// SPDX-License-Identifier: AGPL-3.0-or-later

package wigle

import (
	"math"
	"sort"
)

// MergeResult reports a wardrive consolidation.
type MergeResult struct {
	// Observations is the deduplicated set, one per BSSID, sorted by BSSID
	// for deterministic, diffable output.
	Observations []Observation
	// InputCount is the total observations seen before merging.
	InputCount int
	// Duplicates is how many observations were folded away
	// (InputCount - len(Observations)).
	Duplicates int
}

// Merge consolidates wardrive observations from one or more sessions,
// deduplicating by BSSID. Operators accumulate overlapping drives over
// time; concatenating the CSVs leaves the same AP listed many times, so a
// real merge has to pick one representative sighting per radio.
//
// For each BSSID it keeps the sighting with the strongest signal — that
// observation has the most reliable fix — where "strongest" treats an RSSI
// of 0 as "unknown / weakest" (0 is the common no-measurement sentinel, so
// a real -80 dBm beats it). Ties break by most-recent FirstSeen, then
// deterministically by coordinate. If the kept sighting has no SSID but
// another sighting of the same BSSID named it, the name (and its AuthMode,
// when the kept one's is empty) is adopted — an AP seen hidden in one pass
// and named in another should carry the name. Output is sorted by BSSID.
func Merge(obs []Observation) MergeResult {
	// agg tracks, per BSSID, the chosen representative plus the best
	// non-empty SSID/AuthMode seen across all of that BSSID's sightings
	// (which may live on a sighting that isn't the strongest).
	type agg struct {
		best Observation
		ssid string
		auth string
	}
	byBSSID := make(map[string]*agg, len(obs))
	for _, o := range obs {
		a := byBSSID[o.BSSID]
		if a == nil {
			a = &agg{best: o}
			byBSSID[o.BSSID] = a
		} else if strongerSighting(o, a.best) {
			a.best = o
		}
		if a.ssid == "" && o.SSID != "" {
			a.ssid = o.SSID
			a.auth = o.AuthMode
		}
	}

	out := make([]Observation, 0, len(byBSSID))
	for _, a := range byBSSID {
		rep := a.best
		if rep.SSID == "" && a.ssid != "" {
			rep.SSID = a.ssid
			if rep.AuthMode == "" {
				rep.AuthMode = a.auth
			}
		}
		out = append(out, rep)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BSSID < out[j].BSSID })

	return MergeResult{
		Observations: out,
		InputCount:   len(obs),
		Duplicates:   len(obs) - len(out),
	}
}

// strongerSighting reports whether candidate c should replace the current
// representative cur for the same BSSID.
func strongerSighting(c, cur Observation) bool {
	cr, curr := signalRank(c.RSSI), signalRank(cur.RSSI)
	if cr != curr {
		return cr > curr
	}
	// Equal signal: prefer the more recent fix.
	if !c.FirstSeen.Equal(cur.FirstSeen) {
		return c.FirstSeen.After(cur.FirstSeen)
	}
	// Fully tied: break deterministically by coordinate so the merge is
	// stable across runs and input orderings.
	if c.Latitude != cur.Latitude {
		return c.Latitude < cur.Latitude
	}
	return c.Longitude < cur.Longitude
}

// signalRank maps an RSSI to a comparable strength where higher is stronger.
// An RSSI of 0 is the conventional "no measurement" sentinel in wardrive
// files, so it ranks below any real (negative) reading rather than above
// them (0 > -80 would otherwise wrongly win).
func signalRank(rssi int) int {
	if rssi == 0 {
		return math.MinInt
	}
	return rssi
}
