// SPDX-License-Identifier: AGPL-3.0-or-later

package macaddr

import "testing"

func TestClassify_UniversalUnicast(t *testing.T) {
	// 0x00: I/G=0 (unicast), U/L=0 (universal). OUI surfaced.
	r, err := Classify("00:1A:2B:3C:4D:5E")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Unicast || r.Multicast || !r.UniversallyAdministered || r.LocallyAdministered {
		t.Errorf("flags wrong: %+v", r)
	}
	if r.OUI != "00:1A:2B" {
		t.Errorf("OUI = %s, want 00:1A:2B", r.OUI)
	}
	if r.RandomizedLikely {
		t.Error("universal unicast should not be flagged randomized")
	}
}

func TestClassify_RandomizedMAC(t *testing.T) {
	// 0xDE = 1101_1110: I/G=0 (unicast), U/L=1 (locally administered) -> randomized.
	r, err := Classify("DE:AD:BE:EF:00:01")
	if err != nil {
		t.Fatal(err)
	}
	if !r.LocallyAdministered || !r.Unicast || !r.RandomizedLikely {
		t.Errorf("expected locally-administered unicast randomized, got %+v", r)
	}
	if r.OUI != "" {
		t.Errorf("locally-administered address should not surface an OUI, got %s", r.OUI)
	}
	if len(r.Notes) == 0 {
		t.Error("expected a randomized-MAC note")
	}
}

func TestClassify_Multicast(t *testing.T) {
	cases := []string{"01:00:5E:00:00:01", "33:33:00:00:00:01"} // IPv4 + IPv6 multicast
	for _, m := range cases {
		r, err := Classify(m)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Multicast || r.Unicast {
			t.Errorf("%s: expected multicast, got %+v", m, r)
		}
		if r.RandomizedLikely {
			t.Errorf("%s: multicast must not be flagged randomized", m)
		}
	}
}

func TestClassify_Broadcast(t *testing.T) {
	r, err := Classify("FF:FF:FF:FF:FF:FF")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Broadcast || !r.Multicast {
		t.Errorf("broadcast flags wrong: %+v", r)
	}
	if r.RandomizedLikely {
		t.Error("broadcast must not be flagged randomized")
	}
}

func TestClassify_SeparatorsAndCase(t *testing.T) {
	for _, m := range []string{"001a2b3c4d5e", "00-1a-2b-3c-4d-5e", "001a.2b3c.4d5e", "00 1A 2B 3C 4D 5E"} {
		r, err := Classify(m)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if r.MAC != "00:1A:2B:3C:4D:5E" {
			t.Errorf("%s normalised to %s", m, r.MAC)
		}
	}
}

func TestClassify_Errors(t *testing.T) {
	for _, m := range []string{"", "00:1A:2B", "00:1A:2B:3C:4D:5E:6F", "ZZ:1A:2B:3C:4D:5E"} {
		if _, err := Classify(m); err == nil {
			t.Errorf("%q: expected error", m)
		}
	}
}
