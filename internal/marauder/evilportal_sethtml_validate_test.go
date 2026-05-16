package marauder

import (
	"strings"
	"testing"
)

// EvilPortalSetHTML now rejects empty/whitespace filenames. Pre-fix
// the wrapper would emit `evilportal -c sethtml ""` which the firmware
// rejects with an opaque "no file specified" error.

func TestEvilPortalSetHTML_RejectsEmpty(t *testing.T) {
	for _, name := range []string{"", "   ", "\t"} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.EvilPortalSetHTML(name)
		})
		if err == nil {
			t.Errorf("expected error for filename=%q; got nil", name)
			continue
		}
		if !strings.Contains(err.Error(), "filename") {
			t.Errorf("name=%q err = %v; want filename validation error", name, err)
		}
	}
}

func TestEvilPortalSetHTML_AcceptsValidFilename(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.EvilPortalSetHTML("starbucks.html")
	})
	if err != nil {
		t.Fatalf("EvilPortalSetHTML: %v", err)
	}
	want := `evilportal -c sethtml "starbucks.html"`
	if got != want {
		t.Errorf("wire = %q; want %q", got, want)
	}
}
