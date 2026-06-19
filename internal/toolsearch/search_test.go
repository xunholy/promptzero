// SPDX-License-Identifier: AGPL-3.0-or-later

package toolsearch

import (
	"reflect"
	"testing"
)

var testDocs = []Doc{
	{Name: "subghz_bruteforce", Group: "subghz", Description: "brute-force a fixed-code Sub-GHz garage/gate remote by sweeping every code"},
	{Name: "subghz_decode", Group: "subghz", Description: "decode a captured Sub-GHz signal into protocol + key"},
	{Name: "wifi_pmkid_hc22000", Group: "wifi", Description: "convert a captured PMKID into a hashcat 22000 line for cracking the WPA password"},
	{Name: "wifi_deauth", Group: "wifi", Description: "send 802.11 deauthentication frames"},
	{Name: "nfc_mfu_rdbl", Aliases: []string{"mifare_ultralight_read"}, Group: "nfc", Description: "read a MIFARE Ultralight card block"},
	{Name: "ir_decode_file", Group: "ir", Description: "decode a saved infrared .ir signal file"},
	{Name: "device_info", Group: "flipper.system", Description: "get Flipper firmware version and hardware revision"},
}

func names(rs []Result) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

// TestSearch_ExactNameWins: a precise name query ranks that tool first.
func TestSearch_ExactNameWins(t *testing.T) {
	got := Search(testDocs, "subghz_bruteforce", 5)
	if len(got) == 0 || got[0].Name != "subghz_bruteforce" {
		t.Fatalf("exact-name query did not rank its tool first: %v", names(got))
	}
}

// TestSearch_TaskSynonym: a task word reaches the tool via the synonym map even
// though the word never appears in the tool's text ("garage" -> subghz).
func TestSearch_TaskSynonym(t *testing.T) {
	got := Search(testDocs, "garage", 5)
	if len(got) == 0 {
		t.Fatal("garage query returned nothing")
	}
	found := false
	for _, r := range got {
		if r.Name == "subghz_bruteforce" {
			found = true
		}
	}
	if !found {
		t.Errorf("garage did not surface subghz_bruteforce via synonym: %v", names(got))
	}
}

// TestSearch_MultiTerm: "wifi password" should surface the PMKID->hashcat tool
// (password -> hash/pmkid/cred synonyms + wifi).
func TestSearch_MultiTerm(t *testing.T) {
	got := Search(testDocs, "wifi password", 5)
	if len(got) == 0 || got[0].Name != "wifi_pmkid_hc22000" {
		t.Errorf("wifi password did not rank the PMKID tool first: %v", names(got))
	}
}

// TestSearch_AliasMatch: a query hitting only an alias still matches.
func TestSearch_AliasMatch(t *testing.T) {
	got := Search(testDocs, "ultralight", 5)
	found := false
	for _, r := range got {
		if r.Name == "nfc_mfu_rdbl" {
			found = true
		}
	}
	if !found {
		t.Errorf("alias query 'ultralight' did not surface nfc_mfu_rdbl: %v", names(got))
	}
}

// TestSearch_Deterministic: the same query yields an identical ordering every
// run (the score sort has a name tiebreak).
func TestSearch_Deterministic(t *testing.T) {
	first := names(Search(testDocs, "decode signal", 0))
	for i := 0; i < 50; i++ {
		if got := names(Search(testDocs, "decode signal", 0)); !reflect.DeepEqual(got, first) {
			t.Fatalf("non-deterministic order: %v vs %v", got, first)
		}
	}
}

// TestSearch_Edges: empty query and a no-match query both return no results,
// never a panic.
func TestSearch_Edges(t *testing.T) {
	if got := Search(testDocs, "", 5); got != nil {
		t.Errorf("empty query: got %v, want nil", names(got))
	}
	if got := Search(testDocs, "   !!!  ", 5); got != nil {
		t.Errorf("punctuation-only query: got %v, want nil", names(got))
	}
	if got := Search(testDocs, "zzqqxx nonexistentterm", 5); len(got) != 0 {
		t.Errorf("no-match query: got %v, want empty", names(got))
	}
}

// TestSearch_LimitAndScoreOrder: limit caps results and scores are descending.
func TestSearch_LimitAndScoreOrder(t *testing.T) {
	got := Search(testDocs, "subghz", 2)
	if len(got) > 2 {
		t.Fatalf("limit not applied: %d results", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Score < got[i].Score {
			t.Errorf("scores not descending at %d: %v", i, got)
		}
	}
}
