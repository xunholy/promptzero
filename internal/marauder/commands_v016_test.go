package marauder

import (
	"strings"
	"testing"
	"time"
)

// commands_v016_test.go — happy-path wire-form tests for every method added in
// commands_v016.go. All tests reuse the in-package fakePort / newMarauderWithPort
// helpers defined in fake_port_test.go.

// helper: creates a Marauder backed by a fakePort, calls fn, and returns the
// first command line observed on the wire. Also returns the method's error so
// tests can assert on it when needed.
func wireCmd(t *testing.T, fn func(*Marauder) (string, error)) (string, error) {
	t.Helper()
	fp := newFakePort()
	m := newMarauderWithPort(fp)
	t.Cleanup(func() { _ = m.Close() })
	_, err := fn(m)
	seen := fp.linesSeen()
	if len(seen) == 0 {
		if err != nil {
			// Validation error fired before any write — that's expected for
			// invalid-input tests; let the caller assert on the error.
			return "", err
		}
		t.Fatal("no command line observed on the wire")
	}
	return seen[0], err
}

// --- MAC Manipulation ---

func TestCloneStaMAC_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.CloneStaMAC(3) })
	if err != nil {
		t.Fatalf("CloneStaMAC: %v", err)
	}
	if got != "clonestamac -s 3" {
		t.Fatalf("wire = %q, want %q", got, "clonestamac -s 3")
	}
}

// --- System ---

func TestInfoAP_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.InfoAP(7) })
	if err != nil {
		t.Fatalf("InfoAP: %v", err)
	}
	if got != "info -a 7" {
		t.Fatalf("wire = %q, want %q", got, "info -a 7")
	}
}

// --- Passive Sniffers ---

func TestMacTrack_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.MacTrack(time.Second) })
	if err != nil {
		t.Fatalf("MacTrack: %v", err)
	}
	if got != "mactrack" {
		t.Fatalf("wire = %q, want %q", got, "mactrack")
	}
}

func TestSigmon_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.Sigmon(time.Second) })
	if err != nil {
		t.Fatalf("Sigmon: %v", err)
	}
	if got != "sigmon" {
		t.Fatalf("wire = %q, want %q", got, "sigmon")
	}
}

func TestSniffPineScan_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.SniffPineScan(time.Second) })
	if err != nil {
		t.Fatalf("SniffPineScan: %v", err)
	}
	if got != "sniffpinescan" {
		t.Fatalf("wire = %q, want %q", got, "sniffpinescan")
	}
}

func TestSniffMultiSSID_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.SniffMultiSSID(time.Second) })
	if err != nil {
		t.Fatalf("SniffMultiSSID: %v", err)
	}
	if got != "sniffmultissid" {
		t.Fatalf("wire = %q, want %q", got, "sniffmultissid")
	}
}

// --- Wardrive ---

func TestWardriveStart_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.WardriveStart(time.Second) })
	if err != nil {
		t.Fatalf("WardriveStart: %v", err)
	}
	if got != "wardrive" {
		t.Fatalf("wire = %q, want %q", got, "wardrive")
	}
}

func TestWardriveStop_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.WardriveStop() })
	if err != nil {
		t.Fatalf("WardriveStop: %v", err)
	}
	if got != "stopscan" {
		t.Fatalf("wire = %q, want %q", got, "stopscan")
	}
}

func TestWardrivePOI_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.WardrivePOI("coffee shop") })
	if err != nil {
		t.Fatalf("WardrivePOI: %v", err)
	}
	want := `wardrivepoi "coffee shop"`
	if got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
}

func TestWardrivePOI_StripsFramingBytes(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.WardrivePOI("evil\"\r\npoi")
	})
	if err != nil {
		t.Fatalf("WardrivePOI sanitise: %v", err)
	}
	// The inner double-quote, CR and LF must be stripped; the surrounding
	// quotes from the format string must remain.
	if strings.Count(got, `"`) != 2 {
		t.Fatalf("unexpected quote count on wire: %q", got)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("CRLF leaked into wire command: %q", got)
	}
}

// --- GPS Tracker ---

func TestGpsTrackerStart_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsTrackerStart(time.Second) })
	if err != nil {
		t.Fatalf("GpsTrackerStart: %v", err)
	}
	if got != "gpstracker" {
		t.Fatalf("wire = %q, want %q", got, "gpstracker")
	}
}

func TestGpsTrackerStop_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsTrackerStop() })
	if err != nil {
		t.Fatalf("GpsTrackerStop: %v", err)
	}
	if got != "stopscan" {
		t.Fatalf("wire = %q, want %q", got, "stopscan")
	}
}

func TestGpsPoi_Start(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsPoi("start", "") })
	if err != nil {
		t.Fatalf("GpsPoi start: %v", err)
	}
	if got != "gpspoi -s" {
		t.Fatalf("wire = %q, want %q", got, "gpspoi -s")
	}
}

func TestGpsPoi_Mark(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsPoi("mark", "tower view") })
	if err != nil {
		t.Fatalf("GpsPoi mark: %v", err)
	}
	want := `gpspoi -m "tower view"`
	if got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
}

func TestGpsPoi_End(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsPoi("end", "") })
	if err != nil {
		t.Fatalf("GpsPoi end: %v", err)
	}
	if got != "gpspoi -e" {
		t.Fatalf("wire = %q, want %q", got, "gpspoi -e")
	}
}

func TestGpsPoi_InvalidAction(t *testing.T) {
	_, err := wireCmd(t, func(m *Marauder) (string, error) { return m.GpsPoi("begin", "label") })
	if err == nil {
		t.Fatal("expected error for invalid action, got nil")
	}
	if !strings.Contains(err.Error(), "invalid gpspoi action") {
		t.Fatalf("error missing 'invalid gpspoi action': %v", err)
	}
}

// --- List Manipulation ---

func TestAddAP_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddAP("aa:bb:cc:dd:ee:ff", "6", "My Network")
	})
	if err != nil {
		t.Fatalf("AddAP: %v", err)
	}
	want := `add -a -b aa:bb:cc:dd:ee:ff -c 6 -s "My Network"`
	if got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
}

func TestAddAP_StripsQuote(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddAP("aa:bb:cc:dd:ee:ff", "6", `evil"ssid`)
	})
	if err != nil {
		t.Fatalf("AddAP sanitise: %v", err)
	}
	// Outer quotes from format + none from the sanitised essid.
	if strings.Count(got, `"`) != 2 {
		t.Fatalf("unexpected quote count on wire: %q", got)
	}
}

func TestAddStation_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AddStation("11:22:33:44:55:66", 2)
	})
	if err != nil {
		t.Fatalf("AddStation: %v", err)
	}
	want := "add -c -m 11:22:33:44:55:66 -a 2"
	if got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
}

// --- BLE Spoof ---

func TestBTSpoofAirtag_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.BTSpoofAirtag(1) })
	if err != nil {
		t.Fatalf("BTSpoofAirtag: %v", err)
	}
	if got != "spoofat -t 1" {
		t.Fatalf("wire = %q, want %q", got, "spoofat -t 1")
	}
}

// --- WiFi Attacks ---

func TestKarma_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.Karma(0) })
	if err != nil {
		t.Fatalf("Karma: %v", err)
	}
	if got != "karma -p 0" {
		t.Fatalf("wire = %q, want %q", got, "karma -p 0")
	}
}

func TestAttackQuiet_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.AttackQuiet(time.Second) })
	if err != nil {
		t.Fatalf("AttackQuiet: %v", err)
	}
	if got != "attack -t quiet" {
		t.Fatalf("wire = %q, want %q", got, "attack -t quiet")
	}
}

func TestAttackBadmsg_Untargeted(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AttackBadmsg(false, time.Second)
	})
	if err != nil {
		t.Fatalf("AttackBadmsg untargeted: %v", err)
	}
	if got != "attack -t badmsg" {
		t.Fatalf("wire = %q, want %q", got, "attack -t badmsg")
	}
}

func TestAttackBadmsg_Targeted(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AttackBadmsg(true, time.Second)
	})
	if err != nil {
		t.Fatalf("AttackBadmsg targeted: %v", err)
	}
	if got != "attack -t badmsg -c" {
		t.Fatalf("wire = %q, want %q", got, "attack -t badmsg -c")
	}
}

func TestAttackSleep_Untargeted(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AttackSleep(false, time.Second)
	})
	if err != nil {
		t.Fatalf("AttackSleep untargeted: %v", err)
	}
	if got != "attack -t sleep" {
		t.Fatalf("wire = %q, want %q", got, "attack -t sleep")
	}
}

func TestAttackSleep_Targeted(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) {
		return m.AttackSleep(true, time.Second)
	})
	if err != nil {
		t.Fatalf("AttackSleep targeted: %v", err)
	}
	if got != "attack -t sleep -c" {
		t.Fatalf("wire = %q, want %q", got, "attack -t sleep -c")
	}
}

// --- Evil Portal ---

func TestEvilPortalSetAP_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.EvilPortalSetAP(4) })
	if err != nil {
		t.Fatalf("EvilPortalSetAP: %v", err)
	}
	if got != "evilportal -c setap -i 4" {
		t.Fatalf("wire = %q, want %q", got, "evilportal -c setap -i 4")
	}
}

func TestEvilPortalReset_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.EvilPortalReset() })
	if err != nil {
		t.Fatalf("EvilPortalReset: %v", err)
	}
	if got != "evilportal -c reset" {
		t.Fatalf("wire = %q, want %q", got, "evilportal -c reset")
	}
}

func TestEvilPortalAck_WireForm(t *testing.T) {
	got, err := wireCmd(t, func(m *Marauder) (string, error) { return m.EvilPortalAck() })
	if err != nil {
		t.Fatalf("EvilPortalAck: %v", err)
	}
	if got != "evilportal -c ack" {
		t.Fatalf("wire = %q, want %q", got, "evilportal -c ack")
	}
}
