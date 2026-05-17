//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// Wire-form tests for the v0.205 RF-sense / hw-recon FAP wrappers
// added from the gap-analysis top-30. Same shape as the v0.204
// suite — each verifies the wrapper goes through LoaderOpen with
// the canonical quoted-name shape so multi-word FAP names ("Sub-GHz
// Jammer Detect", "Logic Analyzer", "Weather Station") survive the
// args parser as one token.

func assertLoaderOpenV205(t *testing.T, fn func(*flipper.Flipper) (string, error), wantName string) {
	t.Helper()
	m := mock.Spawn(t,
		mock.WithHandler("loader", func(_ []string) string { return "" }),
	)
	flip := connectAndDetect(t, m)

	if _, err := fn(flip); err != nil {
		t.Fatalf("loader call: %v", err)
	}
	want := `loader open "` + wantName + `"`
	for _, l := range m.Lines() {
		if strings.TrimSpace(l) == want {
			return
		}
	}
	t.Errorf("expected %q; lines=%v", want, m.Lines())
}

func TestLoaderWeatherStation(t *testing.T) {
	assertLoaderOpenV205(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderWeatherStation()
	}, "Weather Station")
}

func TestLoaderSubGHzJammerDetect(t *testing.T) {
	assertLoaderOpenV205(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderSubGHzJammerDetect()
	}, "Sub-GHz Jammer Detect")
}

func TestLoaderLogicAnalyzer(t *testing.T) {
	assertLoaderOpenV205(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderLogicAnalyzer()
	}, "Logic Analyzer")
}

func TestLoaderOscilloscope(t *testing.T) {
	assertLoaderOpenV205(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderOscilloscope()
	}, "Oscilloscope")
}
