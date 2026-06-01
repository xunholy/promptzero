// SPDX-License-Identifier: AGPL-3.0-or-later

package defense

import "sort"

// DefaultSpamFloodThreshold is the number of DISTINCT source MACs emitting
// the same spam signature above which a batch is flagged as an active
// flood. It matches the live Tracker's rotation threshold (8): BLE-spam
// tools rotate the advertiser address per packet, so a genuine flood shows
// as many distinct MACs all carrying the same malformed family, whereas a
// single misbehaving device is one or two MACs.
const DefaultSpamFloodThreshold = 8

// SpamSignatureStat is the per-signature roll-up across a batch.
type SpamSignatureStat struct {
	Signature       string `json:"signature"`
	Matches         int    `json:"matches"`
	DistinctSources int    `json:"distinct_sources"`
	Flood           bool   `json:"flood"`
}

// SpamBatchResult is the structured result of AnalyzeSpamBatch.
type SpamBatchResult struct {
	Advertisements int                 `json:"advertisements"`
	MatchedAds     int                 `json:"matched_ads"`
	Threshold      int                 `json:"flood_threshold"`
	Signatures     []SpamSignatureStat `json:"signatures"`
	Observations   []string            `json:"observations"`
}

// AnalyzeSpamBatch runs the stateless per-advertisement Classify over a
// captured batch of BLE advertisements and reports the cross-advertisement
// spam signal the single-advert classifier cannot see: how many DISTINCT
// source MACs are emitting each spam signature. threshold is the
// distinct-MAC count above which a signature is flagged as an active flood
// (<=0 uses DefaultSpamFloodThreshold).
//
// This is the BLE analogue of wifi_deauth_detect — an OBSERVATION, not a
// verdict: a flood of one spam family across many rotating MACs is the
// characteristic Flipper/ESP32 BLE-spam signature (AppleJuice / SourApple
// Apple-Continuity popups, Microsoft Swift Pair, Google Fast Pair), but the
// benign explanation (a genuinely busy venue, or a single buggy beacon
// re-randomising its address) is left for the operator to rule out.
func AnalyzeSpamBatch(ads []Advertisement, threshold int) *SpamBatchResult {
	if threshold <= 0 {
		threshold = DefaultSpamFloodThreshold
	}
	out := &SpamBatchResult{Advertisements: len(ads), Threshold: threshold}

	type agg struct {
		matches int
		sources map[string]bool
	}
	bySig := map[string]*agg{}

	for _, ad := range ads {
		matches := Classify(ad)
		if len(matches) > 0 {
			out.MatchedAds++
		}
		for _, m := range matches {
			sig := string(m.Signature)
			a := bySig[sig]
			if a == nil {
				a = &agg{sources: map[string]bool{}}
				bySig[sig] = a
			}
			a.matches++
			mac := m.SourceMAC
			if mac == "" {
				mac = ad.Address
			}
			if mac != "" {
				a.sources[mac] = true
			}
		}
	}

	sigs := make([]string, 0, len(bySig))
	for s := range bySig {
		sigs = append(sigs, s)
	}
	sort.Strings(sigs)
	for _, sig := range sigs {
		a := bySig[sig]
		stat := SpamSignatureStat{
			Signature:       sig,
			Matches:         a.matches,
			DistinctSources: len(a.sources),
			Flood:           len(a.sources) >= threshold,
		}
		out.Signatures = append(out.Signatures, stat)
		if stat.Flood {
			out.Observations = append(out.Observations,
				signatureFloodNote(sig, stat.DistinctSources, stat.Matches, threshold))
		}
	}
	if len(out.Observations) == 0 {
		if out.MatchedAds == 0 {
			out.Observations = append(out.Observations, "no spam signatures matched in the batch")
		} else {
			out.Observations = append(out.Observations,
				"spam signatures matched but no signature reached the distinct-MAC flood threshold — likely isolated malformed adverts, not an active flood")
		}
	}
	return out
}

func signatureFloodNote(sig string, distinct, matches, threshold int) string {
	return "active spam flood: " + itoa(distinct) + " distinct source MACs (>= threshold " + itoa(threshold) +
		") emitting " + sig + " across " + itoa(matches) + " advert(s) — the characteristic Flipper/ESP32 " +
		"BLE-spam signature (per-packet MAC rotation). Benign explanation: a very busy venue or a single " +
		"beacon re-randomising its address; correlate before concluding."
}
