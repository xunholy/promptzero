// SPDX-License-Identifier: AGPL-3.0-or-later

package snowflake

import "testing"

func findCand(r *Result, platform string) *Candidate {
	for i := range r.Candidates {
		if r.Candidates[i].Platform == platform {
			return &r.Candidates[i]
		}
	}
	return nil
}

// Anchored to Discord's documented example.
func TestDiscordExample(t *testing.T) {
	r, err := Decode("175928847299117063", "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	d := findCand(r, "Discord")
	if d == nil {
		t.Fatal("no Discord candidate")
	}
	if d.UnixMillis != 1462015105796 || d.TimestampUTC != "2016-04-30T11:18:25.796Z" {
		t.Errorf("Discord = %d/%q, want 1462015105796/2016-04-30T11:18:25.796Z", d.UnixMillis, d.TimestampUTC)
	}
	if d.WorkerID == nil || *d.WorkerID != 1 || d.ProcessID == nil || *d.ProcessID != 0 || d.Sequence != 7 {
		t.Errorf("Discord fields worker/process/seq = %v/%v/%d, want 1/0/7", d.WorkerID, d.ProcessID, d.Sequence)
	}
}

func TestTwitterArithmetic(t *testing.T) {
	// (1234567890123456789 >> 22) + 1288834974657 = 1583178896824
	r, _ := Decode("1234567890123456789", "twitter")
	if len(r.Candidates) != 1 || r.Candidates[0].Platform != "Twitter/X" {
		t.Fatalf("platform filter failed: %+v", r.Candidates)
	}
	tw := r.Candidates[0]
	if tw.UnixMillis != 1583178896824 || tw.TimestampUTC != "2020-03-02T19:54:56.824Z" {
		t.Errorf("Twitter = %d/%q, want 1583178896824/2020-03-02T19:54:56.824Z", tw.UnixMillis, tw.TimestampUTC)
	}
	if tw.MachineID == nil {
		t.Error("Twitter machine_id should be set")
	}
}

func TestAllCandidates(t *testing.T) {
	r, _ := Decode("175928847299117063", "")
	if len(r.Candidates) != 2 {
		t.Errorf("got %d candidates, want 2 (Discord + Twitter/X)", len(r.Candidates))
	}
	// Same int, different epochs -> different timestamps (the whole point).
	if r.Candidates[0].UnixMillis == r.Candidates[1].UnixMillis {
		t.Error("Discord and Twitter timestamps should differ for the same id")
	}
}

func TestRejects(t *testing.T) {
	for _, in := range []string{"", "abc", "-1", "99999999999999999999999999", "12.5"} {
		if _, err := Decode(in, ""); err == nil {
			t.Errorf("Decode(%q) = nil error, want rejection", in)
		}
	}
	if _, err := Decode("123", "myspace"); err == nil {
		t.Error("unknown platform should be rejected")
	}
}
