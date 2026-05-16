package marauder

import (
	"strings"
	"testing"
)

// Tests for the index/count/channel validation helpers and the wrappers
// that route through them. Pre-fix, all of these forwarded negative or
// zero values to the Marauder CLI, which silently no-op'd — leaving the
// LLM no way to tell the request did nothing.

func TestValidateListIndex(t *testing.T) {
	if err := validateListIndex("x", 0); err != nil {
		t.Errorf("validateListIndex(0) = %v; want nil", err)
	}
	if err := validateListIndex("x", 100); err != nil {
		t.Errorf("validateListIndex(100) = %v; want nil", err)
	}
	if err := validateListIndex("x", -1); err == nil {
		t.Error("validateListIndex(-1) = nil; want error")
	}
}

func TestValidateWiFiChannel24Int(t *testing.T) {
	for ch := 1; ch <= 14; ch++ {
		if err := validateWiFiChannel24Int(ch); err != nil {
			t.Errorf("validateWiFiChannel24Int(%d) = %v; want nil", ch, err)
		}
	}
	for _, ch := range []int{0, -1, 15, 36, 100} {
		if err := validateWiFiChannel24Int(ch); err == nil {
			t.Errorf("validateWiFiChannel24Int(%d) = nil; want error", ch)
		}
	}
}

// --- v016 wrappers ---

func TestCloneStaMAC_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "station index", func(m *Marauder) (string, error) {
		return m.CloneStaMAC(-1)
	})
}

func TestInfoAP_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "AP index", func(m *Marauder) (string, error) {
		return m.InfoAP(-5)
	})
}

func TestBTSpoofAirtag_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "scan-list index", func(m *Marauder) (string, error) {
		return m.BTSpoofAirtag(-1)
	})
}

func TestKarma_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "probe-list index", func(m *Marauder) (string, error) {
		return m.Karma(-2)
	})
}

func TestEvilPortalSetAP_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "AP index", func(m *Marauder) (string, error) {
		return m.EvilPortalSetAP(-3)
	})
}

// --- commands.go wrappers ---

func TestSetChannel_RejectsOutOfRange(t *testing.T) {
	for _, ch := range []int{0, -1, 15, 36} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.SetChannel(ch)
		})
		if err == nil {
			t.Errorf("expected error for SetChannel(%d); got nil", ch)
			continue
		}
		if !strings.Contains(err.Error(), "channel") {
			t.Errorf("SetChannel(%d) err = %v; want channel validation", ch, err)
		}
	}
}

func TestGenerateSSIDs_RejectsNonPositiveCount(t *testing.T) {
	for _, c := range []int{0, -1, -100} {
		_, err := wireCmd(t, func(m *Marauder) (string, error) {
			return m.GenerateSSIDs(c)
		})
		if err == nil {
			t.Errorf("expected error for GenerateSSIDs(%d); got nil", c)
			continue
		}
		if !strings.Contains(err.Error(), "count") {
			t.Errorf("GenerateSSIDs(%d) err = %v; want count validation", c, err)
		}
	}
}

func TestRemoveSSID_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "SSID index", func(m *Marauder) (string, error) {
		return m.RemoveSSID(-1)
	})
}

func TestCloneAPMAC_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "AP index", func(m *Marauder) (string, error) {
		return m.CloneAPMAC(-1)
	})
}

func TestJoin_RejectsNegativeIndex(t *testing.T) {
	assertNegativeIndexErr(t, "AP index", func(m *Marauder) (string, error) {
		return m.Join(-1, "password")
	})
}

func assertNegativeIndexErr(t *testing.T, wantNeedle string, fn func(*Marauder) (string, error)) {
	t.Helper()
	_, err := wireCmd(t, fn)
	if err == nil {
		t.Fatal("expected error for negative index; got nil")
	}
	if !strings.Contains(err.Error(), wantNeedle) {
		t.Errorf("err = %v; want %q", err, wantNeedle)
	}
}
