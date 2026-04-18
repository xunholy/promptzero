package transport

import (
	"errors"
	"strings"
	"testing"
)

// TestOpenByScheme is the registry round-trip: each built-in scheme
// must be dialable by Open to a concrete transport (or to a
// well-known error for reserved schemes). Unknown schemes must fail
// loudly so a typo in a config URL surfaces at startup.
func TestOpenByScheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		url      string
		wantKind string // "" means expect an error
		wantErr  error  // if non-nil, must match with errors.Is
		errSub   string // if non-empty, error must contain this substring
	}{
		{
			name:     "serial URL parses and returns a serial transport",
			url:      "serial:///dev/ttyACM0?baud=230400",
			wantKind: "serial",
		},
		{
			name:     "serial URL defaults baud when unset",
			url:      "serial:///dev/ttyACM0",
			wantKind: "serial",
		},
		{
			name:     "bare device path is treated as serial",
			url:      "/dev/ttyACM0",
			wantKind: "serial",
		},
		{
			name:     "mock URL parses and returns a mock transport",
			url:      "mock:///dev/pts/5",
			wantKind: "mock",
		},
		{
			name:     "ble URL parses and returns a ble transport",
			url:      "ble://AA:BB:CC:DD:EE:FF",
			wantKind: "ble",
		},
		{
			name:   "unknown scheme returns a clean error",
			url:    "vapor://nowhere",
			errSub: "unknown scheme",
		},
		{
			name:   "serial URL with garbage baud is rejected",
			url:    "serial:///dev/ttyACM0?baud=xyz",
			errSub: "invalid baud",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Open(tc.url)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want errors.Is(%v)", err, tc.wantErr)
				}
				return
			}
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %q, want substring %q", err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if got.Kind() != tc.wantKind {
				t.Fatalf("Kind() = %q, want %q", got.Kind(), tc.wantKind)
			}
			if strings.ContainsAny(got.Identity(), "\r\n") {
				t.Errorf("Identity() contains newline: %q", got.Identity())
			}
		})
	}
}

// TestRegisterOverwrites documents the "last writer wins" semantics of
// Register. Tests stub dialers in place; a panic-on-duplicate would
// force them to deregister in cleanup instead.
func TestRegisterOverwrites(t *testing.T) {
	t.Parallel()

	const scheme = "test-overwrite"
	t.Cleanup(func() {
		registryMu.Lock()
		delete(registry, scheme)
		registryMu.Unlock()
	})

	var seen string
	Register(scheme, func(url string) (Transport, error) {
		seen = "first"
		return nil, errors.New("first")
	})
	Register(scheme, func(url string) (Transport, error) {
		seen = "second"
		return nil, errors.New("second")
	})

	_, _ = Open(scheme + "://x")
	if seen != "second" {
		t.Errorf("Register did not overwrite: seen = %q, want %q", seen, "second")
	}
}
