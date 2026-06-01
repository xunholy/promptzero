// SPDX-License-Identifier: AGPL-3.0-or-later

package wifidefense

import "testing"

func countObs(a *Analysis, kind string) int {
	n := 0
	for _, o := range a.Observations {
		if o.Kind == kind {
			n++
		}
	}
	return n
}

// TestAnalyze_BroadcastDeauth: a deauth to the broadcast address is the
// clearest flood signature and must flag regardless of volume.
func TestAnalyze_BroadcastDeauth(t *testing.T) {
	frames := []Frame{
		{Subtype: "deauth", Src: "AA:BB:CC:DD:EE:FF", Dst: "FF:FF:FF:FF:FF:FF", BSSID: "AA:BB:CC:DD:EE:FF", Reason: 7},
	}
	a, err := AnalyzeDeauth(frames, 0)
	if err != nil {
		t.Fatalf("AnalyzeDeauth: %v", err)
	}
	if a.BroadcastFrames != 1 {
		t.Errorf("broadcast_frames = %d, want 1", a.BroadcastFrames)
	}
	if countObs(a, "broadcast_deauth") != 1 {
		t.Errorf("broadcast_deauth observations = %d, want 1", countObs(a, "broadcast_deauth"))
	}
}

// TestAnalyze_Flood: volume over the threshold flags deauth_flood.
func TestAnalyze_Flood(t *testing.T) {
	var frames []Frame
	for i := 0; i < 12; i++ {
		frames = append(frames, Frame{Subtype: "deauth", Src: "AA", Dst: "0000000000" + string(rune('0'+i%10)), BSSID: "AA", Reason: 1})
	}
	a, err := AnalyzeDeauth(frames, 10)
	if err != nil {
		t.Fatalf("AnalyzeDeauth: %v", err)
	}
	if a.DeauthFrames != 12 {
		t.Errorf("deauth_frames = %d, want 12", a.DeauthFrames)
	}
	if countObs(a, "deauth_flood") != 1 {
		t.Errorf("deauth_flood observations = %d, want 1", countObs(a, "deauth_flood"))
	}
}

// TestAnalyze_BelowThresholdQuiet: a handful of unicast deauths below the
// threshold raises no flood/broadcast signal.
func TestAnalyze_BelowThresholdQuiet(t *testing.T) {
	frames := []Frame{
		{Subtype: "deauth", Src: "AA", Dst: "B1", BSSID: "AA", Reason: 3},
		{Subtype: "disassoc", Src: "AA", Dst: "B2", BSSID: "AA", Reason: 8},
	}
	a, err := AnalyzeDeauth(frames, 10)
	if err != nil {
		t.Fatalf("AnalyzeDeauth: %v", err)
	}
	if countObs(a, "broadcast_deauth") != 0 || countObs(a, "deauth_flood") != 0 {
		t.Errorf("unexpected observations: %+v", a.Observations)
	}
}

// TestAnalyze_TargetedClient: one victim taking the majority of the
// deauths from a BSSID flags targeted_client.
func TestAnalyze_TargetedClient(t *testing.T) {
	var frames []Frame
	for i := 0; i < 6; i++ {
		frames = append(frames, Frame{Subtype: "deauth", Src: "AA", Dst: "VICTIM", BSSID: "AA", Reason: 7})
	}
	frames = append(frames, Frame{Subtype: "deauth", Src: "AA", Dst: "OTHER", BSSID: "AA", Reason: 7})
	a, err := AnalyzeDeauth(frames, 100) // high so flood doesn't fire
	if err != nil {
		t.Fatalf("AnalyzeDeauth: %v", err)
	}
	if countObs(a, "targeted_client") != 1 {
		t.Errorf("targeted_client observations = %d, want 1: %+v", countObs(a, "targeted_client"), a.Observations)
	}
}

// TestAnalyze_ReasonHistogramAndNonMgmtIgnored: non-deauth subtypes are
// counted toward the total only, and reason codes are tallied with names.
func TestAnalyze_ReasonHistogramAndNonMgmtIgnored(t *testing.T) {
	frames := []Frame{
		{Subtype: "beacon"},
		{Subtype: "data"},
		{Subtype: "deauth", Dst: "B1", Reason: 7},
	}
	a, err := AnalyzeDeauth(frames, 0)
	if err != nil {
		t.Fatalf("AnalyzeDeauth: %v", err)
	}
	if a.FramesAnalyzed != 3 {
		t.Errorf("frames_analyzed = %d, want 3", a.FramesAnalyzed)
	}
	if a.DeauthFrames != 1 || a.DisassocFrames != 0 {
		t.Errorf("deauth/disassoc = %d/%d, want 1/0", a.DeauthFrames, a.DisassocFrames)
	}
	if a.ReasonCodes["7 (Class-3 frame from nonassoc STA)"] != 1 {
		t.Errorf("reason histogram = %+v", a.ReasonCodes)
	}
}

// TestAnalyze_NoDeauthNote: a sequence with no deauth/disassoc gets a note.
func TestAnalyze_NoDeauthNote(t *testing.T) {
	a, err := AnalyzeDeauth([]Frame{{Subtype: "beacon"}}, 0)
	if err != nil {
		t.Fatalf("AnalyzeDeauth: %v", err)
	}
	if len(a.Notes) == 0 {
		t.Error("expected a note when no deauth/disassoc frames present")
	}
}

func TestAnalyze_Empty(t *testing.T) {
	if _, err := AnalyzeDeauth(nil, 0); err == nil {
		t.Error("expected error for empty frame list")
	}
}
