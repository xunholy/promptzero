package defense

import (
	"strings"
	"testing"
	"time"
)

func TestClassify_AppleContinuitySpam(t *testing.T) {
	// Action type 0x42 — outside the legit set — flags spam.
	ad := Advertisement{
		Address: "AA:BB:CC:DD:EE:FF",
		ManufacturerData: map[uint16][]byte{
			0x004C: {0x42, 0x02, 0xDE, 0xAD},
		},
	}
	matches := Classify(ad)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %v", len(matches), matches)
	}
	if matches[0].Signature != SigAppleContinuitySpam {
		t.Errorf("signature = %v, want %v", matches[0].Signature, SigAppleContinuitySpam)
	}
	if !strings.Contains(matches[0].Description, "0x42") {
		t.Errorf("description missing action type: %q", matches[0].Description)
	}
	if matches[0].SourceMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("SourceMAC = %q, want canonical upper", matches[0].SourceMAC)
	}
}

func TestClassify_AppleContinuityLegit(t *testing.T) {
	// 0x0F NearbyAction is in the legit set — should NOT match.
	ad := Advertisement{
		ManufacturerData: map[uint16][]byte{
			0x004C: {0x0F, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}
	matches := Classify(ad)
	if len(matches) != 0 {
		t.Errorf("legit Apple Continuity classified as spam: %v", matches)
	}
}

func TestClassify_AppleContinuityTruncated(t *testing.T) {
	// Length byte claims 100 bytes follow but only 1 is present.
	ad := Advertisement{
		ManufacturerData: map[uint16][]byte{
			0x004C: {0x07, 0x64, 0xAA},
		},
	}
	matches := Classify(ad)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if matches[0].Signature != SigAppleContinuitySpam {
		t.Errorf("signature = %v, want apple_continuity_spam", matches[0].Signature)
	}
	if !strings.Contains(strings.ToLower(matches[0].Description), "truncated") {
		t.Errorf("description missing 'truncated': %q", matches[0].Description)
	}
}

func TestClassify_SwiftPairTooShort(t *testing.T) {
	ad := Advertisement{
		ManufacturerData: map[uint16][]byte{
			0x0006: {0x01, 0x02, 0x03, 0x04},
		},
	}
	matches := Classify(ad)
	if len(matches) != 1 || matches[0].Signature != SigSwiftPairMalformed {
		t.Fatalf("expected swift_pair_malformed, got %v", matches)
	}
}

func TestClassify_SwiftPairBadFlags(t *testing.T) {
	ad := Advertisement{
		ManufacturerData: map[uint16][]byte{
			0x0006: {0x42, 0x01, 0x02, 0x03, 0x04, 0x05}, // flags 0x42 reserved
		},
	}
	matches := Classify(ad)
	if len(matches) != 1 || matches[0].Signature != SigSwiftPairMalformed {
		t.Fatalf("expected swift_pair_malformed, got %v", matches)
	}
}

func TestClassify_SwiftPairLegit(t *testing.T) {
	ad := Advertisement{
		ManufacturerData: map[uint16][]byte{
			0x0006: {0x01, 0x09, 0x20, 0x01, 0x00, 0x01, 0x02, 0x03},
		},
	}
	matches := Classify(ad)
	if len(matches) != 0 {
		t.Errorf("legit Swift Pair classified as spam: %v", matches)
	}
}

func TestClassify_SamsungSentinelModelId(t *testing.T) {
	ad := Advertisement{
		ManufacturerData: map[uint16][]byte{
			0x0075: {0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB},
		},
	}
	matches := Classify(ad)
	if len(matches) != 1 || matches[0].Signature != SigSamsungWatchSpam {
		t.Fatalf("expected samsung_watch_spam, got %v", matches)
	}

	// 0xFFFFFF sentinel
	ad.ManufacturerData[0x0075] = []byte{0x01, 0xFF, 0xFF, 0xFF, 0xAA}
	matches = Classify(ad)
	if len(matches) != 1 || matches[0].Signature != SigSamsungWatchSpam {
		t.Errorf("0xFFFFFF sentinel not detected: %v", matches)
	}
}

func TestClassify_GoogleFastPairRepeatedByte(t *testing.T) {
	ad := Advertisement{
		ServiceData: map[uint16][]byte{
			0xFE2C: {0xAA, 0xAA, 0xAA, 0x01, 0x02},
		},
	}
	matches := Classify(ad)
	if len(matches) != 1 || matches[0].Signature != SigGoogleFastPairSpam {
		t.Fatalf("expected google_fast_pair_spam, got %v", matches)
	}
}

func TestClassify_FlipperServiceUUID(t *testing.T) {
	cases := []string{
		"0000fe60-0000-1000-8000-00805f9b34fb",
		"0000FE60-0000-1000-8000-00805F9B34FB",
		"0xfe60",
		"fe60",
		"0000fe60-cc7a-482a-984a-7f2ed5b3e58f",
	}
	for _, u := range cases {
		ad := Advertisement{ServiceUUIDs: []string{u}}
		matches := Classify(ad)
		if len(matches) != 1 || matches[0].Signature != SigFlipperServiceUUID {
			t.Errorf("UUID %q: matches = %v, want flipper_service_uuid", u, matches)
		}
	}
}

func TestClassify_NoMatchOnEmpty(t *testing.T) {
	if matches := Classify(Advertisement{}); len(matches) != 0 {
		t.Errorf("empty advertisement matched: %v", matches)
	}
}

func TestTracker_RotationDetector(t *testing.T) {
	tr := &Tracker{RotationWindow: time.Second, RotationThreshold: 3}

	now := time.Now()
	for i := 0; i < 2; i++ {
		mac := []string{"AA:00:00:00:00:01", "AA:00:00:00:00:02"}[i]
		_ = tr.Classify(Advertisement{Address: mac, CapturedAt: now})
	}
	// 2 unique MACs ≥ 3? no.
	matches := tr.Classify(Advertisement{Address: "AA:00:00:00:00:03", CapturedAt: now})
	rotated := false
	for _, m := range matches {
		if m.Signature == SigHighFrequencyMACRotation {
			rotated = true
		}
	}
	if !rotated {
		t.Errorf("rotation detector did not fire after 3 unique MACs in window: %v", matches)
	}
}

func TestTracker_RotationGCsOldEntries(t *testing.T) {
	tr := &Tracker{RotationWindow: 100 * time.Millisecond, RotationThreshold: 3}

	old := time.Now().Add(-1 * time.Second)
	tr.Classify(Advertisement{Address: "01:00:00:00:00:01", CapturedAt: old})
	tr.Classify(Advertisement{Address: "01:00:00:00:00:02", CapturedAt: old})
	tr.Classify(Advertisement{Address: "01:00:00:00:00:03", CapturedAt: old})

	// All old observations have aged out by now; one fresh MAC should
	// not trigger.
	now := time.Now()
	matches := tr.Classify(Advertisement{Address: "01:00:00:00:00:04", CapturedAt: now})
	for _, m := range matches {
		if m.Signature == SigHighFrequencyMACRotation {
			t.Errorf("rotation triggered after old entries should have aged out")
		}
	}
}

func TestTracker_Snapshot(t *testing.T) {
	tr := &Tracker{}
	tr.Classify(Advertisement{
		Address:          "BB:CC:DD:EE:FF:00",
		ManufacturerData: map[uint16][]byte{0x004C: {0x42, 0x01, 0x00}},
	})

	snap := tr.Snapshot()
	matches, ok := snap["BB:CC:DD:EE:FF:00"]
	if !ok || len(matches) == 0 {
		t.Fatalf("snapshot missing the captured MAC: %v", snap)
	}
	if matches[0].Signature != SigAppleContinuitySpam {
		t.Errorf("snapshot signature = %v, want apple_continuity_spam", matches[0].Signature)
	}

	tr.Reset()
	if got := tr.Snapshot(); len(got) != 0 {
		t.Errorf("Reset did not clear: %v", got)
	}
}
