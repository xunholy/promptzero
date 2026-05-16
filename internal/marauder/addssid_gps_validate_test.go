package marauder

import (
	"strings"
	"testing"
)

// AddSSID now rejects empty/whitespace names and SSIDs over the 32-byte
// 802.11 cap. GPSField now allowlists navSystem against the same
// 8-token set its docstring documents.

func TestAddSSID_RejectsEmptyName(t *testing.T) {
	for _, name := range []string{"", "   ", "\t\t"} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.AddSSID(name)
		})
		if err == nil {
			t.Errorf("expected error for name=%q; got nil", name)
			continue
		}
		if !strings.Contains(err.Error(), "SSID") {
			t.Errorf("name=%q err = %v; want SSID validation error", name, err)
		}
	}
}

func TestAddSSID_RejectsOversizedName(t *testing.T) {
	long := strings.Repeat("a", 33)
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddSSID(long)
	})
	if err == nil {
		t.Fatal("expected error for 33-byte SSID; got nil")
	}
	if !strings.Contains(err.Error(), "SSID") {
		t.Errorf("err = %v; want SSID length validation error", err)
	}
}

func TestAddSSID_AcceptsBoundaryLength(t *testing.T) {
	// Exactly 32 bytes — the 802.11 cap, must pass.
	at32 := strings.Repeat("b", 32)
	if _, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddSSID(at32)
	}); err != nil {
		t.Errorf("32-byte SSID rejected unexpectedly: %v", err)
	}
}

func TestGPSField_RejectsBadNavSystem(t *testing.T) {
	cases := []string{"GPS", "iridium", "qzss ", "starlink", "Galileo"}
	for _, nav := range cases {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.GPSField("lat", nav)
		})
		if err == nil {
			t.Errorf("expected error for nav_system=%q; got nil", nav)
			continue
		}
		if !strings.Contains(err.Error(), "nav_system") {
			t.Errorf("nav=%q err = %v; want nav_system validation error", nav, err)
		}
	}
}

func TestGPSField_AcceptsAllNavSystems(t *testing.T) {
	for _, nav := range []string{"native", "all", "gps", "glonass", "galileo", "navic", "qzss", "beidou"} {
		if _, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.GPSField("lat", nav)
		}); err != nil {
			t.Errorf("nav=%q rejected unexpectedly: %v", nav, err)
		}
	}
}

func TestGPSField_EmptyNavSystemSkipsArg(t *testing.T) {
	// Existing behaviour: empty nav_system → no -n flag emitted.
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.GPSField("lat", "")
	})
	if err != nil {
		t.Fatalf("GPSField(lat, \"\"): %v", err)
	}
	if got != "gps -g lat" {
		t.Errorf("wire = %q; want 'gps -g lat'", got)
	}
}
