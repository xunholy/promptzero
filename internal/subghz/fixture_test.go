// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz_test

import (
	"os"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/subghz"
)

// TestFixturePrincetonPT2262 loads the synthetic Princeton fixture from testdata/
// and verifies the full pipeline: Parse → Classify → correct protocol + payload.
func TestFixturePrincetonPT2262(t *testing.T) {
	data, err := os.ReadFile("testdata/princeton_pt2262.sub")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sf, err := subghz.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(sf.Pulses) == 0 {
		t.Fatal("no pulses in fixture")
	}
	c := subghz.NewClassifier()
	// Request ALL matches: several gate-less protocols accept this PWM frame at
	// full confidence, so Princeton sits in a multi-way tie. A top-N cut would
	// drop it by the deterministic name tiebreak, not by relevance.
	matches := c.Classify(sf.Pulses, 0)
	if len(matches) == 0 {
		t.Fatal("no matches from Princeton PT2262 fixture")
	}
	found := false
	for _, m := range matches {
		if strings.Contains(m.Protocol, "Princeton") {
			found = true
			if m.Confidence < 0.75 {
				t.Errorf("Princeton confidence = %.2f, want ≥ 0.75", m.Confidence)
			}
			// addr = 0xAAA, data = 0x5
			if addr, ok := m.Payload["address"]; ok {
				if addr.(uint32) != 0xAAA {
					t.Errorf("address = 0x%X, want 0xAAA", addr.(uint32))
				}
			}
			break
		}
	}
	if !found {
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.Protocol
		}
		t.Errorf("expected Princeton among matches, got: %v", names)
	}
}

// TestFixtureCAME loads the synthetic CAME fixture and verifies decoding.
func TestFixtureCAME(t *testing.T) {
	data, err := os.ReadFile("testdata/came.sub")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sf, err := subghz.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	c := subghz.NewClassifier()
	matches := c.Classify(sf.Pulses, 0)
	if len(matches) == 0 {
		t.Fatal("no matches from CAME fixture")
	}
	found := false
	for _, m := range matches {
		if strings.Contains(m.Protocol, "CAME") || strings.Contains(m.Protocol, "Beninca") {
			found = true
			if m.Confidence < 0.75 {
				t.Errorf("%s confidence = %.2f, want ≥ 0.75", m.Protocol, m.Confidence)
			}
			break
		}
	}
	if !found {
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.Protocol
		}
		t.Errorf("expected CAME or Beninca among matches, got: %v", names)
	}
}

// TestFixtureKeeLoqHCS loads the synthetic KeeLoq fixture and verifies decoding.
func TestFixtureKeeLoqHCS(t *testing.T) {
	data, err := os.ReadFile("testdata/keeloq_hcs.sub")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sf, err := subghz.Parse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	c := subghz.NewClassifier()
	matches := c.Classify(sf.Pulses, 0)
	if len(matches) == 0 {
		t.Fatal("no matches from KeeLoq fixture")
	}
	found := false
	for _, m := range matches {
		if strings.Contains(m.Protocol, "KeeLoq") {
			found = true
			if m.Confidence < 0.75 {
				t.Errorf("KeeLoq confidence = %.2f, want ≥ 0.75", m.Confidence)
			}
			if hopping, ok := m.Payload["hopping_code"]; ok {
				if hopping.(uint32) != 0xDEADC0DE {
					t.Errorf("hopping_code = 0x%X, want 0xDEADC0DE", hopping.(uint32))
				}
			}
			break
		}
	}
	if !found {
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.Protocol
		}
		t.Errorf("expected KeeLoq among matches, got: %v", names)
	}
}
