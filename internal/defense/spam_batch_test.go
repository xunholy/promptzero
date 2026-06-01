// SPDX-License-Identifier: AGPL-3.0-or-later

package defense

import (
	"fmt"
	"testing"
)

// appleSpamAd builds an advertisement whose Apple-Continuity manufacturer
// data carries an action type (0x00) outside the published set — the
// classifier flags it apple_continuity_spam.
func appleSpamAd(mac string) Advertisement {
	return Advertisement{
		Address:          mac,
		ManufacturerData: map[uint16][]byte{0x004C: {0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
	}
}

func swiftPairBadAd(mac string) Advertisement {
	return Advertisement{
		Address:          mac,
		ManufacturerData: map[uint16][]byte{0x0006: {0x01, 0x02}}, // < 6 bytes -> malformed
	}
}

func macN(i int) string { return fmt.Sprintf("AA:BB:CC:DD:EE:%02X", i) }

func sigStat(r *SpamBatchResult, sig string) *SpamSignatureStat {
	for i := range r.Signatures {
		if r.Signatures[i].Signature == sig {
			return &r.Signatures[i]
		}
	}
	return nil
}

// TestAnalyzeSpamBatch_Flood: many distinct MACs all emitting Apple spam is
// the rotating-MAC flood signature.
func TestAnalyzeSpamBatch_Flood(t *testing.T) {
	var ads []Advertisement
	for i := 0; i < 10; i++ {
		ads = append(ads, appleSpamAd(macN(i)))
	}
	r := AnalyzeSpamBatch(ads, 0) // default threshold 8
	s := sigStat(r, "apple_continuity_spam")
	if s == nil {
		t.Fatalf("no apple_continuity_spam stat: %+v", r)
	}
	if s.DistinctSources != 10 || !s.Flood {
		t.Errorf("distinct=%d flood=%v, want 10/true", s.DistinctSources, s.Flood)
	}
	if r.MatchedAds != 10 {
		t.Errorf("matched_ads = %d, want 10", r.MatchedAds)
	}
	if len(r.Observations) == 0 {
		t.Error("expected a flood observation")
	}
}

// TestAnalyzeSpamBatch_BelowThreshold: a couple of malformed adverts from a
// couple of MACs match but do not constitute a flood.
func TestAnalyzeSpamBatch_BelowThreshold(t *testing.T) {
	ads := []Advertisement{appleSpamAd(macN(1)), appleSpamAd(macN(2)), appleSpamAd(macN(3))}
	r := AnalyzeSpamBatch(ads, 0)
	s := sigStat(r, "apple_continuity_spam")
	if s == nil || s.Flood {
		t.Errorf("expected matched-but-not-flood: %+v", r.Signatures)
	}
	found := false
	for _, o := range r.Observations {
		if len(o) > 0 && o[0] == 's' { // "spam signatures matched but no signature reached..."
			found = true
		}
	}
	if !found {
		t.Errorf("expected the matched-but-no-flood note: %+v", r.Observations)
	}
}

// TestAnalyzeSpamBatch_CustomThreshold lets a small distinct-MAC count flood.
func TestAnalyzeSpamBatch_CustomThreshold(t *testing.T) {
	ads := []Advertisement{appleSpamAd(macN(1)), appleSpamAd(macN(2)), appleSpamAd(macN(3))}
	r := AnalyzeSpamBatch(ads, 3)
	s := sigStat(r, "apple_continuity_spam")
	if s == nil || !s.Flood {
		t.Errorf("threshold 3 with 3 distinct MACs should flood: %+v", r.Signatures)
	}
}

// TestAnalyzeSpamBatch_DistinctSourcesNotInflatedByRepeats: the same MAC
// spamming many times counts as one distinct source.
func TestAnalyzeSpamBatch_DistinctSourcesNotInflatedByRepeats(t *testing.T) {
	var ads []Advertisement
	for i := 0; i < 20; i++ {
		ads = append(ads, appleSpamAd("AA:AA:AA:AA:AA:AA")) // same MAC
	}
	r := AnalyzeSpamBatch(ads, 0)
	s := sigStat(r, "apple_continuity_spam")
	if s == nil || s.DistinctSources != 1 || s.Flood {
		t.Errorf("single MAC spamming should be 1 distinct, no flood: %+v", r.Signatures)
	}
	if s.Matches != 20 {
		t.Errorf("matches = %d, want 20", s.Matches)
	}
}

// TestAnalyzeSpamBatch_MixedSignatures separates per-signature distinct-MAC
// counts.
func TestAnalyzeSpamBatch_MixedSignatures(t *testing.T) {
	var ads []Advertisement
	for i := 0; i < 9; i++ {
		ads = append(ads, appleSpamAd(macN(i)))
	}
	ads = append(ads, swiftPairBadAd(macN(50)), swiftPairBadAd(macN(51)))
	r := AnalyzeSpamBatch(ads, 0)
	apple := sigStat(r, "apple_continuity_spam")
	swift := sigStat(r, "swift_pair_malformed")
	if apple == nil || !apple.Flood {
		t.Errorf("apple should flood: %+v", r.Signatures)
	}
	if swift == nil || swift.Flood {
		t.Errorf("swiftpair (2 MACs) should not flood: %+v", r.Signatures)
	}
}

// TestAnalyzeSpamBatch_Clean: no spam signatures matched.
func TestAnalyzeSpamBatch_Clean(t *testing.T) {
	ads := []Advertisement{
		{Address: macN(1), LocalName: "MyPhone"},
		{Address: macN(2), ManufacturerData: map[uint16][]byte{0x004C: {0x10, 0x02, 0xAA, 0xBB}}}, // legit NearbyInfo
	}
	r := AnalyzeSpamBatch(ads, 0)
	if r.MatchedAds != 0 || len(r.Signatures) != 0 {
		t.Errorf("clean batch flagged: %+v", r)
	}
}
