package marauder

import (
	"strings"
	"testing"
)

// WardrivePOI and GpsPoi("mark", ...) now reject empty/whitespace
// labels. Pre-fix, the firmware silently wrote an unnamed POI marker
// into the wardrive/gps log — unrecoverable without the label.

func TestWardrivePOI_RejectsEmptyLabel(t *testing.T) {
	for _, label := range []string{"", "   ", "\t", "\n\n"} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.WardrivePOI(label)
		})
		if err == nil {
			t.Errorf("expected error for label=%q; got nil", label)
			continue
		}
		if !strings.Contains(err.Error(), "label") {
			t.Errorf("label=%q err = %v; want label validation error", label, err)
		}
	}
}

func TestGpsPoi_MarkRejectsEmptyLabel(t *testing.T) {
	for _, label := range []string{"", "   ", "\t"} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.GpsPoi("mark", label)
		})
		if err == nil {
			t.Errorf("expected error for mark label=%q; got nil", label)
			continue
		}
		if !strings.Contains(err.Error(), "label") {
			t.Errorf("label=%q err = %v; want label validation error", label, err)
		}
	}
}

func TestGpsPoi_StartAndEndDoNotRequireLabel(t *testing.T) {
	// start + end don't take a label, so the empty-string call must
	// continue to work after the validator lands.
	if _, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsPoi("start", "") }); err != nil {
		t.Errorf("GpsPoi(start, \"\") = %v; want nil", err)
	}
	if _, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsPoi("end", "") }); err != nil {
		t.Errorf("GpsPoi(end, \"\") = %v; want nil", err)
	}
	// Empty label is also fine when the validator isn't on the path
	// — re-pin that "start"/"end" stay unaffected by future tweaks
	// to the mark validator.
}
