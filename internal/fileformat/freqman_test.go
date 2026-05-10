package fileformat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFreqman_SingleFrequency(t *testing.T) {
	in := []byte("f=433920000,m=AM_DSB,bw=5,d=Garage door opener\n")
	got, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("ParseFreqman: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(got.Entries))
	}
	e := got.Entries[0]
	if e.Frequency != 433920000 {
		t.Errorf("Frequency = %d, want 433920000", e.Frequency)
	}
	if e.Modulation != "AM_DSB" {
		t.Errorf("Modulation = %q, want AM_DSB", e.Modulation)
	}
	if e.Bandwidth != "5" {
		t.Errorf("Bandwidth = %q, want \"5\"", e.Bandwidth)
	}
	if e.Description != "Garage door opener" {
		t.Errorf("Description = %q", e.Description)
	}
}

func TestParseFreqman_RangeEntry(t *testing.T) {
	in := []byte("a=315000000,b=320000000,m=AM_DSB,s=12500,d=Generic 315 sweep\n")
	got, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("ParseFreqman: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(got.Entries))
	}
	e := got.Entries[0]
	if !e.IsRange() {
		t.Errorf("IsRange = false, want true")
	}
	if e.RangeStart != 315000000 || e.RangeEnd != 320000000 {
		t.Errorf("range = [%d,%d], want [315000000,320000000]", e.RangeStart, e.RangeEnd)
	}
	if e.Step != "12500" {
		t.Errorf("Step = %q", e.Step)
	}
}

func TestParseFreqman_DescriptionWithCommas(t *testing.T) {
	// Sticky-tail rule: everything after the first top-level d= is the description.
	in := []byte("f=433920000,m=AM_DSB,d=Garage door, blue button, 2024\n")
	got, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("ParseFreqman: %v", err)
	}
	if got.Entries[0].Description != "Garage door, blue button, 2024" {
		t.Errorf("Description = %q", got.Entries[0].Description)
	}
}

func TestParseFreqman_CommentsAndBlanks(t *testing.T) {
	in := []byte("# 70cm garage remotes\n\nf=433920000,d=A\n  \n# trailing comment\nf=315000000,d=B\n")
	got, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("ParseFreqman: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(got.Entries))
	}
	if got.Entries[0].Frequency != 433920000 || got.Entries[1].Frequency != 315000000 {
		t.Errorf("entries = %+v", got.Entries)
	}
}

func TestParseFreqman_UnknownKeyPreservedInExtra(t *testing.T) {
	in := []byte("f=433920000,tone=88.5,p=high,d=Repeater\n")
	got, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("ParseFreqman: %v", err)
	}
	e := got.Entries[0]
	if e.Extra["tone"] != "88.5" {
		t.Errorf("Extra[tone] = %q", e.Extra["tone"])
	}
	if e.Extra["p"] != "high" {
		t.Errorf("Extra[p] = %q", e.Extra["p"])
	}
}

func TestParseFreqman_RejectsMissingFrequency(t *testing.T) {
	in := []byte("m=AM_DSB,d=Just a description\n")
	_, err := ParseFreqman(in)
	if err == nil {
		t.Fatalf("ParseFreqman: expected error on missing f= and a=/b=")
	}
}

func TestParseFreqman_RejectsBothSingleAndRange(t *testing.T) {
	in := []byte("f=433920000,a=315000000,b=320000000,d=both\n")
	_, err := ParseFreqman(in)
	if err == nil {
		t.Fatalf("ParseFreqman: expected error on f= + a=/b=")
	}
}

func TestParseFreqman_RejectsFloatFrequency(t *testing.T) {
	// Some forks emit MHz floats; we explicitly reject so units stay obvious.
	in := []byte("f=433.92,d=Test\n")
	_, err := ParseFreqman(in)
	if err == nil {
		t.Fatalf("ParseFreqman: expected error on float frequency")
	}
}

func TestParseFreqman_MalformedTokenErrors(t *testing.T) {
	in := []byte("f=433920000,malformed_token,d=oops\n")
	_, err := ParseFreqman(in)
	if err == nil {
		t.Fatalf("ParseFreqman: expected error on malformed token")
	}
}

func TestFreqmanList_MarshalRoundTrip(t *testing.T) {
	in := []byte(strings.Join([]string{
		"f=433920000,m=AM_DSB,bw=5,s=12500,d=Garage A",
		"a=315000000,b=320000000,m=AM_DSB,s=25000,d=Range scan, sweep",
		"f=868350000,m=NFM,p=high,tone=88.5,d=Repeater",
	}, "\n") + "\n")

	parsed, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("ParseFreqman: %v", err)
	}
	out := parsed.Marshal()
	reparsed, err := ParseFreqman(out)
	if err != nil {
		t.Fatalf("re-ParseFreqman: %v\nbytes:\n%s", err, out)
	}
	if len(reparsed.Entries) != len(parsed.Entries) {
		t.Fatalf("round-trip lost entries: got %d, want %d", len(reparsed.Entries), len(parsed.Entries))
	}
	for i := range parsed.Entries {
		a := parsed.Entries[i]
		b := reparsed.Entries[i]
		if a.Frequency != b.Frequency || a.RangeStart != b.RangeStart || a.RangeEnd != b.RangeEnd ||
			a.Modulation != b.Modulation || a.Bandwidth != b.Bandwidth || a.Step != b.Step ||
			a.Description != b.Description {
			t.Errorf("round-trip mismatch entry %d: %+v vs %+v", i, a, b)
		}
		if len(a.Extra) != len(b.Extra) {
			t.Errorf("round-trip extra lost on entry %d: %v vs %v", i, a.Extra, b.Extra)
			continue
		}
		for k, v := range a.Extra {
			if b.Extra[k] != v {
				t.Errorf("round-trip extra[%s] = %q, want %q", k, b.Extra[k], v)
			}
		}
	}
}

func TestFreqmanFromSub_Roundtrip(t *testing.T) {
	sub := &SubFile{
		Filetype:  "Flipper SubGhz Key File",
		Version:   1,
		Frequency: 433920000,
		Preset:    "FuriHalSubGhzPresetOok650Async",
	}
	entry, err := FreqmanFromSub(sub, "Captured 2026-04-01")
	if err != nil {
		t.Fatalf("FreqmanFromSub: %v", err)
	}
	if entry.Frequency != 433920000 {
		t.Errorf("Frequency = %d", entry.Frequency)
	}
	if entry.Modulation != "AM_DSB" {
		t.Errorf("Modulation = %q, want AM_DSB", entry.Modulation)
	}
	if entry.Description != "Captured 2026-04-01" {
		t.Errorf("Description = %q", entry.Description)
	}

	back, err := entry.ToSubLite()
	if err != nil {
		t.Fatalf("ToSubLite: %v", err)
	}
	if back.Frequency != sub.Frequency {
		t.Errorf("Frequency = %d, want %d", back.Frequency, sub.Frequency)
	}
	if back.Preset != sub.Preset {
		t.Errorf("Preset = %q, want %q", back.Preset, sub.Preset)
	}
	if back.Filetype != "Flipper SubGhz Key File" {
		t.Errorf("Filetype = %q", back.Filetype)
	}
}

func TestFreqmanFromSub_NilOrZeroFrequency(t *testing.T) {
	if _, err := FreqmanFromSub(nil, "x"); err == nil {
		t.Errorf("nil sub: expected error")
	}
	sub := &SubFile{Filetype: "Flipper SubGhz Key File", Version: 1}
	if _, err := FreqmanFromSub(sub, "x"); err == nil {
		t.Errorf("zero frequency: expected error")
	}
}

func TestFreqmanEntry_ToSubLite_RangeRejected(t *testing.T) {
	e := FreqmanEntry{RangeStart: 315000000, RangeEnd: 320000000}
	if _, err := e.ToSubLite(); err == nil {
		t.Errorf("range entry: expected error from ToSubLite")
	}
}

func TestFreqmanEntry_ToSubLite_DefaultsPresetWhenUnknownModulation(t *testing.T) {
	e := FreqmanEntry{Frequency: 433920000, Modulation: "MYSTERY_MOD"}
	got, err := e.ToSubLite()
	if err != nil {
		t.Fatalf("ToSubLite: %v", err)
	}
	if got.Preset != "FuriHalSubGhzPresetOok650Async" {
		t.Errorf("Preset = %q, want fallback OOK650", got.Preset)
	}
}

func TestFreqmanList_Find(t *testing.T) {
	list := &FreqmanList{
		Entries: []FreqmanEntry{
			{Frequency: 433920000, Description: "Garage A"},
			{Frequency: 315000000, Description: "Garage B"},
		},
	}
	if e := list.Find("433920000"); e == nil || e.Description != "Garage A" {
		t.Errorf("find by Hz: got %+v", e)
	}
	if e := list.Find("Garage B"); e == nil || e.Frequency != 315000000 {
		t.Errorf("find by description: got %+v", e)
	}
	if e := list.Find("garage b"); e == nil {
		t.Errorf("find should be case-insensitive")
	}
	if e := list.Find("nothing here"); e != nil {
		t.Errorf("find unknown: got %+v, want nil", e)
	}
	if e := list.Find(""); e != nil {
		t.Errorf("empty query: got %+v, want nil", e)
	}
}

func TestFreqmanList_Sort(t *testing.T) {
	list := &FreqmanList{
		Entries: []FreqmanEntry{
			{Frequency: 868350000},
			{RangeStart: 315000000, RangeEnd: 320000000},
			{Frequency: 433920000},
		},
	}
	list.Sort()
	if list.Entries[0].RangeStart != 315000000 {
		t.Errorf("Sort: index 0 = %+v, want range starting 315MHz", list.Entries[0])
	}
	if list.Entries[1].Frequency != 433920000 {
		t.Errorf("Sort: index 1 = %+v, want 433.92MHz", list.Entries[1])
	}
	if list.Entries[2].Frequency != 868350000 {
		t.Errorf("Sort: index 2 = %+v, want 868.35MHz", list.Entries[2])
	}
}

func TestFreqmanList_Marshal_Empty(t *testing.T) {
	l := &FreqmanList{}
	if got := l.Marshal(); len(got) != 0 {
		t.Errorf("empty list Marshal = %q, want empty", got)
	}
}

func TestParseFreqman_EmptyFile(t *testing.T) {
	got, err := ParseFreqman(nil)
	if err != nil {
		t.Fatalf("nil input: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("nil input entries = %d, want 0", len(got.Entries))
	}

	got, err = ParseFreqman([]byte("\n\n# comment only\n\n"))
	if err != nil {
		t.Fatalf("comment-only: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("comment-only entries = %d, want 0", len(got.Entries))
	}
}

func TestSearchFreqmanDir_FindsByFrequency(t *testing.T) {
	dir := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("garage.txt", "f=433920000,m=AM_DSB,d=Garage A\nf=315000000,m=AM_DSB,d=Garage B\n")
	must("car.txt", "f=433920000,m=AM_DSB,d=Car fob captured 2026-04-01\n")

	matches, errs := SearchFreqmanDir(dir, "433920000", 0)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2 (Garage A + Car fob); got %+v", len(matches), matches)
	}
}

func TestSearchFreqmanDir_FindsByDescriptionSubstring(t *testing.T) {
	dir := t.TempDir()
	body := "f=433920000,m=AM_DSB,d=Garage door, blue button\nf=315000000,d=TV remote\n"
	if err := os.WriteFile(filepath.Join(dir, "lib.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, _ := SearchFreqmanDir(dir, "garage", 0)
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1; got %+v", len(matches), matches)
	}
	if matches[0].Entry.Frequency != 433920000 {
		t.Errorf("matched entry = %+v, want 433.92MHz", matches[0].Entry)
	}
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1", matches[0].Line)
	}
}

func TestSearchFreqmanDir_FrequencyInRange(t *testing.T) {
	dir := t.TempDir()
	body := "a=315000000,b=320000000,m=AM_DSB,d=Sweep 315\nf=433920000,d=Single 433\n"
	if err := os.WriteFile(filepath.Join(dir, "lib.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// 317 MHz falls inside the range scan, not the single 433.
	matches, _ := SearchFreqmanDir(dir, "317000000", 0)
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1 (range hit); got %+v", len(matches), matches)
	}
	if !matches[0].Entry.IsRange() {
		t.Errorf("expected range entry, got %+v", matches[0].Entry)
	}
}

func TestSearchFreqmanDir_LimitCapsResults(t *testing.T) {
	dir := t.TempDir()
	body := "f=433920000,d=A\nf=433920000,d=B\nf=433920000,d=C\n"
	if err := os.WriteFile(filepath.Join(dir, "lib.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, _ := SearchFreqmanDir(dir, "433920000", 2)
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2 (limit); got %+v", len(matches), matches)
	}
}

func TestSearchFreqmanDir_RecursesSubdirs(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "garages")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "f=433920000,d=Nested garage\n"
	if err := os.WriteFile(filepath.Join(sub, "g.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, _ := SearchFreqmanDir(dir, "garage", 0)
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1 (nested); got %+v", len(matches), matches)
	}
}

func TestSearchFreqmanDir_IgnoresNonTxtFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.csv"), []byte("f=433920000,d=A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, _ := SearchFreqmanDir(dir, "433920000", 0)
	if len(matches) != 0 {
		t.Errorf(".csv should be ignored, got %+v", matches)
	}
}

func TestSearchFreqmanDir_MalformedFileSurfacedAsErr(t *testing.T) {
	dir := t.TempDir()
	good := "f=433920000,d=Good\n"
	bad := "this is not a freqman line\n"
	if err := os.WriteFile(filepath.Join(dir, "good.txt"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.txt"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, errs := SearchFreqmanDir(dir, "433920000", 0)
	if len(matches) != 1 {
		t.Errorf("matches = %d, want 1 (good only)", len(matches))
	}
	if len(errs) != 1 {
		t.Errorf("errs = %d, want 1 (bad file)", len(errs))
	}
}

func TestSearchFreqmanDir_NonExistentRootIsZeroResults(t *testing.T) {
	matches, errs := SearchFreqmanDir("/nonexistent-path-xyz-1234", "433", 0)
	if len(matches) != 0 || len(errs) != 0 {
		t.Errorf("non-existent root: matches=%v errs=%v, want both empty", matches, errs)
	}
}

func TestSearchFreqmanDir_EmptyQueryReturnsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.txt"), []byte("f=433,d=A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, _ := SearchFreqmanDir(dir, "", 0)
	if len(matches) != 0 {
		t.Errorf("empty query should return zero matches, got %+v", matches)
	}
}

func TestSearchFreqmanDir_LineNumbersAccountForCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	body := "# header comment\n\nf=433920000,d=First\n# inline comment\nf=315000000,d=Second\n"
	if err := os.WriteFile(filepath.Join(dir, "lib.txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	matches, _ := SearchFreqmanDir(dir, "315000000", 0)
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if matches[0].Line != 5 {
		t.Errorf("Line = %d, want 5 (comments + blanks counted)", matches[0].Line)
	}
}

func TestParseFreqman_CRLF(t *testing.T) {
	in := []byte("f=433920000,d=A\r\nf=315000000,d=B\r\n")
	got, err := ParseFreqman(in)
	if err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Errorf("CRLF entries = %d, want 2", len(got.Entries))
	}
}
