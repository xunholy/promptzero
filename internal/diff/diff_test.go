package diff

import (
	"strings"
	"testing"
)

func TestUnified_Identical(t *testing.T) {
	got := Unified("foo.txt", "alpha\nbeta\n", "alpha\nbeta\n")
	if got != "" {
		t.Fatalf("identical inputs should yield empty diff, got %q", got)
	}
}

func TestUnified_BothEmpty(t *testing.T) {
	if got := Unified("foo.txt", "", ""); got != "" {
		t.Fatalf("two empty inputs should yield empty diff, got %q", got)
	}
}

func TestUnified_FreshFile(t *testing.T) {
	// old empty → every new line is an addition.
	got := Unified("/ext/notes.txt", "", "first\nsecond\n")
	if !strings.HasPrefix(got, "--- /ext/notes.txt\n+++ /ext/notes.txt\n") {
		t.Fatalf("missing or malformed header, got:\n%s", got)
	}
	if !strings.Contains(got, "+first\n") || !strings.Contains(got, "+second\n") {
		t.Fatalf("expected each new line prefixed with '+', got:\n%s", got)
	}
	if strings.Contains(got, "-") {
		// The header line "--- name" starts with '-' too — guard the
		// content scan against the header.
		body := strings.SplitN(got, "@@", 2)[1]
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "-") {
				t.Fatalf("fresh file diff should have no '-' lines, got:\n%s", got)
			}
		}
	}
}

func TestUnified_DeletedFile(t *testing.T) {
	got := Unified("/ext/old.txt", "alpha\nbeta\n", "")
	if !strings.Contains(got, "-alpha\n") || !strings.Contains(got, "-beta\n") {
		t.Fatalf("expected each old line prefixed with '-', got:\n%s", got)
	}
	body := strings.SplitN(got, "@@", 2)[1]
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "+") {
			t.Fatalf("deleted-file diff should have no '+' lines, got:\n%s", got)
		}
	}
}

func TestUnified_SingleLineChange(t *testing.T) {
	old := "alpha\nbeta\ngamma\n"
	neu := "alpha\nBETA\ngamma\n"
	got := Unified("f.txt", old, neu)
	if !strings.Contains(got, "-beta\n") {
		t.Fatalf("expected '-beta' in diff, got:\n%s", got)
	}
	if !strings.Contains(got, "+BETA\n") {
		t.Fatalf("expected '+BETA' in diff, got:\n%s", got)
	}
	if !strings.Contains(got, " alpha\n") {
		t.Fatalf("expected ' alpha' context line, got:\n%s", got)
	}
	if !strings.Contains(got, " gamma\n") {
		t.Fatalf("expected ' gamma' context line, got:\n%s", got)
	}
}

func TestUnified_MultiHunk(t *testing.T) {
	// Two clusters of changes separated by 20 unchanged lines.
	var oldB, newB strings.Builder
	oldB.WriteString("a\nb\nc\n")
	newB.WriteString("a\nB\nc\n")
	for i := 0; i < 20; i++ {
		oldB.WriteString("filler\n")
		newB.WriteString("filler\n")
	}
	oldB.WriteString("x\ny\nz\n")
	newB.WriteString("x\nY\nz\n")

	got := Unified("two.txt", oldB.String(), newB.String())
	hunkCount := strings.Count(got, "@@ -")
	if hunkCount != 2 {
		t.Fatalf("expected 2 hunks separated by unchanged region, got %d in:\n%s", hunkCount, got)
	}
}

func TestUnified_Truncation(t *testing.T) {
	// Force the line cap by replacing every line wholesale.
	var oldB, newB strings.Builder
	for i := 0; i < maxLines+200; i++ {
		oldB.WriteString("old-line\n")
		newB.WriteString("new-line\n")
	}
	got := Unified("big.txt", oldB.String(), newB.String())
	if !strings.Contains(got, "lines truncated") {
		t.Fatalf("expected truncation marker, got tail:\n%s", got[len(got)-200:])
	}
	// Output should be near the cap, not unbounded.
	if len(got) > maxBytes+1024 {
		t.Fatalf("output exceeded byte cap: %d bytes", len(got))
	}
}

func TestUnified_NULBytesSafe(t *testing.T) {
	// A NUL in the middle of a "line" must not panic, abort, or be
	// silently re-encoded — the diff is byte-transparent.
	old := "a\nb\x00c\n"
	neu := "a\nb\x00d\n"
	got := Unified("nul.bin", old, neu)
	if got == "" {
		t.Fatalf("expected a non-empty diff for differing NUL-bearing inputs")
	}
	if !strings.Contains(got, "b\x00c") || !strings.Contains(got, "b\x00d") {
		t.Fatalf("NUL byte not preserved in diff output, got:\n%q", got)
	}
}

func TestUnified_NoTrailingNewline(t *testing.T) {
	// Inputs without a trailing newline should not produce a phantom
	// empty line at the end of the diff.
	got := Unified("f.txt", "alpha\nbeta", "alpha\ngamma")
	if strings.Contains(got, "\n\n\n") {
		t.Fatalf("unexpected blank trailing line in diff:\n%s", got)
	}
	if !strings.Contains(got, "-beta") || !strings.Contains(got, "+gamma") {
		t.Fatalf("expected change lines, got:\n%s", got)
	}
}

func TestSplitLines_TableDriven(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single_no_nl", "abc", []string{"abc"}},
		{"single_with_nl", "abc\n", []string{"abc"}},
		{"two_lines_no_trailing", "a\nb", []string{"a", "b"}},
		{"two_lines_trailing", "a\nb\n", []string{"a", "b"}},
		{"single_blank_line", "\n", []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitLines(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d len(want)=%d got=%v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("line %d: got %q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
