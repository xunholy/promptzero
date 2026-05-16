package bruce

import (
	"context"
	"strings"
	"testing"
)

// Bruce.Deauth and Bruce.EvilTwin now validate args at the wrapper
// layer (defense in depth — the tool spec layer already catches empty
// bssid/ssid + zero channel, but direct callers bypass that and
// malformed MACs / out-of-range channels slipped through).

func TestValidateBSSID(t *testing.T) {
	accept := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA-BB-CC-DD-EE-FF",
		"AABB.CCDD.EEFF",
	}
	for _, m := range accept {
		if err := validateBSSID(m); err != nil {
			t.Errorf("validateBSSID(%q) = %v; want nil", m, err)
		}
	}
	reject := []string{
		"",
		"   ",
		"not-a-mac",
		"aa:bb:cc:dd:ee",          // 5 octets
		"aa:bb:cc:dd:ee:ff:00:11", // 8 octets
	}
	for _, m := range reject {
		if err := validateBSSID(m); err == nil {
			t.Errorf("validateBSSID(%q) = nil; want error", m)
		}
	}
}

func TestValidateWiFiChannel(t *testing.T) {
	accept := []int{1, 6, 14, 36, 100, 149, 165}
	for _, ch := range accept {
		if err := validateWiFiChannel(ch); err != nil {
			t.Errorf("validateWiFiChannel(%d) = %v; want nil", ch, err)
		}
	}
	reject := []int{0, -1, -100, 166, 200, 1000}
	for _, ch := range reject {
		if err := validateWiFiChannel(ch); err == nil {
			t.Errorf("validateWiFiChannel(%d) = nil; want error", ch)
		}
	}
}

func TestDeauth_RejectsBadBSSID(t *testing.T) {
	c, _ := newTestClient(Capabilities{})
	err := c.Deauth(context.Background(), "not-a-mac", 6)
	if err == nil {
		t.Fatal("expected error for bad bssid; got nil")
	}
	if !strings.Contains(err.Error(), "BSSID") {
		t.Errorf("err = %v; want BSSID validation error", err)
	}
}

func TestDeauth_RejectsOutOfRangeChannel(t *testing.T) {
	c, _ := newTestClient(Capabilities{})
	for _, ch := range []int{0, -1, 200, 1000} {
		err := c.Deauth(context.Background(), "aa:bb:cc:dd:ee:ff", ch)
		if err == nil {
			t.Errorf("expected error for channel=%d; got nil", ch)
			continue
		}
		if !strings.Contains(err.Error(), "channel") {
			t.Errorf("ch=%d err = %v; want channel validation error", ch, err)
		}
	}
}

func TestEvilTwin_RejectsBadBSSID(t *testing.T) {
	c, _ := newTestClient(Capabilities{})
	err := c.EvilTwin(context.Background(), "CorpWLAN", "garbage")
	if err == nil {
		t.Fatal("expected error for bad bssid; got nil")
	}
	if !strings.Contains(err.Error(), "BSSID") {
		t.Errorf("err = %v; want BSSID validation error", err)
	}
}

func TestEvilTwin_RejectsEmptySSID(t *testing.T) {
	c, _ := newTestClient(Capabilities{})
	for _, ssid := range []string{"", "   ", "\t"} {
		err := c.EvilTwin(context.Background(), ssid, "aa:bb:cc:dd:ee:ff")
		if err == nil {
			t.Errorf("expected error for ssid=%q; got nil", ssid)
			continue
		}
		if !strings.Contains(err.Error(), "SSID") {
			t.Errorf("ssid=%q err = %v; want SSID validation error", ssid, err)
		}
	}
}
