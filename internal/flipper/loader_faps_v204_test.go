//go:build linux

package flipper_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/flipper/mock"
)

// Wire-form tests for the v0.204 FAP wrappers added from the
// gap-analysis top-30. Each verifies the wrapper goes through
// LoaderOpen with the canonical quoted-name shape so:
//   (a) the firmware's args parser sees one token regardless of
//       internal whitespace (Sentry Safe, Pocsag Pager),
//   (b) the BLE-RPC AppStart dispatch path is exercised
//       (LoaderOpen routes through dispatch — direct Exec on BLE
//       would hit ErrCommandRequiresUSB).

func assertLoaderOpenLine(t *testing.T, fn func(*flipper.Flipper) (string, error), wantName string) {
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

func TestLoaderSentrySafe(t *testing.T) {
	assertLoaderOpenLine(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderSentrySafe()
	}, "Sentry Safe")
}

func TestLoaderPocsagPager(t *testing.T) {
	assertLoaderOpenLine(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderPocsagPager()
	}, "Pocsag Pager")
}

func TestLoaderMagSpoof(t *testing.T) {
	assertLoaderOpenLine(t, func(f *flipper.Flipper) (string, error) {
		return f.LoaderMagSpoof()
	}, "MagSpoof")
}
