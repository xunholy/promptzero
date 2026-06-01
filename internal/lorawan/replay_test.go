// SPDX-License-Identifier: AGPL-3.0-or-later

package lorawan

import "testing"

func countKind(a *ReplayAnalysis, kind string) int {
	n := 0
	for _, o := range a.Observations {
		if o.Kind == kind {
			n++
		}
	}
	return n
}

// TestReplay_CleanIncreasing: strictly increasing FCnt → no observations.
func TestReplay_CleanIncreasing(t *testing.T) {
	frames := []ReplayFrame{
		{DevAddr: "26011A2B", FCnt: 10, MType: "UnconfirmedDataUp"},
		{DevAddr: "26011A2B", FCnt: 11, MType: "UnconfirmedDataUp"},
		{DevAddr: "26011A2B", FCnt: 12, MType: "UnconfirmedDataUp"},
	}
	a, err := AnalyzeReplay(frames)
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("clean stream flagged: %+v", a.Observations)
	}
}

// TestReplay_Retransmission: consecutive equal FCnt is a benign confirmed
// retransmission, not a reuse.
func TestReplay_Retransmission(t *testing.T) {
	frames := []ReplayFrame{
		{DevAddr: "AA", FCnt: 5, MType: "ConfirmedDataUp"},
		{DevAddr: "AA", FCnt: 5, MType: "ConfirmedDataUp"},
		{DevAddr: "AA", FCnt: 6, MType: "ConfirmedDataUp"},
	}
	a, err := AnalyzeReplay(frames)
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("retransmission flagged: %+v", a.Observations)
	}
	s := a.PerStream["AA|uplink"]
	if s.Retransmissions != 1 || s.LogicalTransmissions != 2 {
		t.Errorf("retrans=%d logical=%d, want 1/2", s.Retransmissions, s.LogicalTransmissions)
	}
}

// TestReplay_Reuse: an old FCnt reappearing after advancing is a replay.
func TestReplay_Reuse(t *testing.T) {
	frames := []ReplayFrame{
		{DevAddr: "AA", FCnt: 10, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 11, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 10, MType: "UnconfirmedDataUp"}, // replay of FCnt 10
	}
	a, err := AnalyzeReplay(frames)
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	if countKind(a, "fcnt_reuse") != 1 {
		t.Errorf("fcnt_reuse = %d, want 1: %+v", countKind(a, "fcnt_reuse"), a.Observations)
	}
}

// TestReplay_Regression: a counter below the running max (a fresh low value).
func TestReplay_Regression(t *testing.T) {
	frames := []ReplayFrame{
		{DevAddr: "AA", FCnt: 100, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 101, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 50, MType: "UnconfirmedDataUp"}, // regressed, not previously seen
	}
	a, err := AnalyzeReplay(frames)
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	if countKind(a, "fcnt_regression") != 1 {
		t.Errorf("fcnt_regression = %d, want 1: %+v", countKind(a, "fcnt_regression"), a.Observations)
	}
}

// TestReplay_UplinkDownlinkIndependent: the same FCnt on uplink and downlink
// is normal (independent counters) and must not flag.
func TestReplay_UplinkDownlinkIndependent(t *testing.T) {
	frames := []ReplayFrame{
		{DevAddr: "AA", FCnt: 5, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 5, MType: "UnconfirmedDataDown"},
		{DevAddr: "AA", FCnt: 6, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 6, MType: "UnconfirmedDataDown"},
	}
	a, err := AnalyzeReplay(frames)
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	if len(a.Observations) != 0 {
		t.Errorf("independent up/down counters flagged: %+v", a.Observations)
	}
	if a.Streams != 2 {
		t.Errorf("streams = %d, want 2 (uplink + downlink)", a.Streams)
	}
}

// TestReplay_DevicesIsolated: a reused FCnt across different DevAddrs is not
// a replay.
func TestReplay_DevicesIsolated(t *testing.T) {
	frames := []ReplayFrame{
		{DevAddr: "AA", FCnt: 1, MType: "UnconfirmedDataUp"},
		{DevAddr: "BB", FCnt: 9, MType: "UnconfirmedDataUp"},
		{DevAddr: "AA", FCnt: 2, MType: "UnconfirmedDataUp"},
		{DevAddr: "BB", FCnt: 1, MType: "UnconfirmedDataUp"}, // BB's own first FCnt 1
	}
	a, err := AnalyzeReplay(frames)
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	// BB went 9 then 1 -> regression for BB, but no cross-device reuse.
	if countKind(a, "fcnt_reuse") != 0 {
		t.Errorf("cross-device reuse flagged: %+v", a.Observations)
	}
}

// TestReplay_UnknownDirectionNote: frames without Up/Down MType get a note.
func TestReplay_UnknownDirectionNote(t *testing.T) {
	a, err := AnalyzeReplay([]ReplayFrame{{DevAddr: "AA", FCnt: 1}})
	if err != nil {
		t.Fatalf("AnalyzeReplay: %v", err)
	}
	found := false
	for _, n := range a.Notes {
		if len(n) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected a note about missing MType direction")
	}
}

func TestReplay_Empty(t *testing.T) {
	if _, err := AnalyzeReplay(nil); err == nil {
		t.Error("expected error for empty frame list")
	}
}
