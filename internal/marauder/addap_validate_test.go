package marauder

import (
	"strconv"
	"strings"
	"testing"
)

// AddAP and AddStation validate bssid/channel/apIndex before transport.
// Pre-fix, the Marauder firmware silently no-op'd malformed list entries
// — the LLM had no way to tell whether the AP made it into the list,
// only that the command returned "" with no error.

func TestValidateBSSID_AcceptsAllSeparators(t *testing.T) {
	cases := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"AABB.CCDD.EEFF",
	}
	for _, m := range cases {
		if err := validateBSSID(m); err != nil {
			t.Errorf("validateBSSID(%q) = %v; want nil", m, err)
		}
	}
}

func TestValidateBSSID_Rejects(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"not a mac",
		"aa:bb:cc:dd:ee",       // 5 octets
		"aa:bb:cc:dd:ee:ff:00", // 7 octets (this still parses as MAC-7)
		"zz:zz:zz:zz:zz:zz",
		"aa-bb-cc-dd-ee-ff:00",
	}
	for _, m := range cases {
		if err := validateBSSID(m); err == nil {
			t.Errorf("validateBSSID(%q) = nil; want error", m)
		}
	}
}

func TestValidateWiFiChannel24_AcceptsValid(t *testing.T) {
	for ch := 1; ch <= 14; ch++ {
		s := strconv.Itoa(ch)
		if err := validateWiFiChannel24(s); err != nil {
			t.Errorf("validateWiFiChannel24(%q) = %v; want nil", s, err)
		}
	}
}

func TestValidateWiFiChannel24_Rejects(t *testing.T) {
	cases := []string{"0", "-1", "15", "36", "100", "ch6", "channel 6", "", "abc"}
	for _, ch := range cases {
		if err := validateWiFiChannel24(ch); err == nil {
			t.Errorf("validateWiFiChannel24(%q) = nil; want error", ch)
		}
	}
}

func TestAddAP_RejectsBadBSSID(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddAP("not-a-mac", "6", "ssid")
	})
	if err == nil {
		t.Fatal("expected error for bad bssid; got nil")
	}
	if !strings.Contains(err.Error(), "BSSID") {
		t.Errorf("err = %v; want BSSID validation error", err)
	}
}

func TestAddAP_RejectsBadChannel(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddAP("aa:bb:cc:dd:ee:ff", "36", "ssid")
	})
	if err == nil {
		t.Fatal("expected error for bad channel; got nil")
	}
	if !strings.Contains(err.Error(), "channel") {
		t.Errorf("err = %v; want channel validation error", err)
	}
}

func TestAddAP_RejectsEmptyESSID(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddAP("aa:bb:cc:dd:ee:ff", "6", "")
	})
	if err == nil {
		t.Fatal("expected error for empty essid; got nil")
	}
	if !strings.Contains(err.Error(), "ESSID") {
		t.Errorf("err = %v; want ESSID validation error", err)
	}
}

func TestAddStation_RejectsBadBSSID(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddStation("nope", 1)
	})
	if err == nil {
		t.Fatal("expected error for bad bssid; got nil")
	}
	if !strings.Contains(err.Error(), "BSSID") {
		t.Errorf("err = %v; want BSSID validation error", err)
	}
}

func TestAddStation_RejectsNegativeIndex(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddStation("aa:bb:cc:dd:ee:ff", -1)
	})
	if err == nil {
		t.Fatal("expected error for negative apIndex; got nil")
	}
	if !strings.Contains(err.Error(), "AP index") {
		t.Errorf("err = %v; want AP index validation error", err)
	}
}
