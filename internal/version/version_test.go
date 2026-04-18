// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want %q", Version, "dev")
	}
	if Commit != "unknown" {
		t.Errorf("Commit = %q, want %q", Commit, "unknown")
	}
	if Date != "unknown" {
		t.Errorf("Date = %q, want %q", Date, "unknown")
	}
}

func TestString(t *testing.T) {
	got := String()
	want := "dev (unknown built unknown)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	Version = "1.2.3"
	Commit = "abc1234"
	Date = "2026-04-18T00:00:00Z"
	t.Cleanup(func() {
		Version = "dev"
		Commit = "unknown"
		Date = "unknown"
	})

	got = String()
	if !strings.Contains(got, "1.2.3") || !strings.Contains(got, "abc1234") || !strings.Contains(got, "2026-04-18T00:00:00Z") {
		t.Errorf("String() = %q, missing expected parts", got)
	}
}
