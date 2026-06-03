// SPDX-License-Identifier: AGPL-3.0-or-later

package aprs

import (
	"math"
	"testing"
)

// The Mic-E information field from the APRS101 §10 worked example (page 63):
// `(_fn "Oj/ — d+28='(' m+28='_' h+28='f' SP+28='n' DC+28='"' SE+28='O',
// symbol code 'j' on table '/'. Decodes to longitude 112°7.74', speed 20 kt,
// course 251° (the +100 longitude offset comes from the destination address).
const miceInfoExample = "`(_fn\"Oj/"

func near(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s: got %.6f, want %.6f (±%.6f)", name, got, want, tol)
	}
}

// TestMicEDestinationExample pins the APRS101 §10 destination-address worked
// example (page 54): destination S32U6T encodes latitude 33°25.64' North,
// longitude offset +0, West, with standard message bits 1/0/0 (M3 Returning).
func TestMicEDestinationExample(t *testing.T) {
	f, err := Decode("N0CALL>S32U6T:" + miceInfoExample)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := f.MicE
	if m == nil {
		t.Fatal("MicE is nil")
	}
	// 33°25.64'N = 33 + 25.64/60 = 33.427333.
	near(t, "latitude_deg", m.LatitudeDeg, 33.427333, 1e-5)
	if m.MessageType != "M3: Returning" {
		t.Errorf("message_type = %q, want M3: Returning", m.MessageType)
	}
	// This destination has the +0 longitude offset, so the info example's
	// 12-degree base is not shifted to 112: 12°7.74'W = -12.129.
	near(t, "longitude_deg", m.LongitudeDeg, -12.129, 1e-3)
	if m.DataType != "current GPS data" {
		t.Errorf("data_type = %q", m.DataType)
	}
}

// TestMicEInfoExample pins the APRS101 §10 information-field worked example
// (page 63): with a +100-offset / West destination, the info field decodes to
// longitude 112°7.74' West, speed 20 knots, course 251°.
func TestMicEInfoExample(t *testing.T) {
	// Destination S32UQT: like the page-54 example but byte 5 = 'Q' (P–Z) to
	// select the +100 longitude offset, matching the page-63 info example.
	// Lat digits 3,3,2,5,1,4 = 33°25.14'N; message bits 1/0/0 = M3.
	f, err := Decode("N0CALL>S32UQT:" + miceInfoExample)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m := f.MicE
	if m == nil {
		t.Fatal("MicE is nil")
	}
	// 112°7.74'W = -(112 + 7.74/60) = -112.129.
	near(t, "longitude_deg", m.LongitudeDeg, -112.129, 1e-3)
	if m.SpeedKnots != 20 {
		t.Errorf("speed_knots = %d, want 20", m.SpeedKnots)
	}
	if m.CourseDeg != 251 {
		t.Errorf("course_deg = %d, want 251", m.CourseDeg)
	}
	near(t, "latitude_deg", m.LatitudeDeg, 33.419, 1e-3) // 33°25.14'N
}

// TestMicEMessageTypes spot-checks the A/B/C message-bit resolution.
func TestMicEMessageTypes(t *testing.T) {
	cases := []struct {
		dest, want string
	}{
		{"S32U6T", "M3: Returning"},                                // A/B/C = std1/0/0 → idx 4
		{"PQRSPP", "M0: Off Duty"},                                 // std1/std1/std1 → idx 7
		{"012SPP", "Emergency"},                                    // 0/0/0 → idx 0
		{"A2CSPP", "C2: Custom-2"},                                 // custom1/0/custom1 → idx 5
		{"A3PSPP", "Unknown (mixed standard/custom message bits)"}, // custom1 + std1
	}
	for _, c := range cases {
		f, err := Decode("N0CALL>" + c.dest + ":" + miceInfoExample)
		if err != nil {
			t.Fatalf("decode %s: %v", c.dest, err)
		}
		if f.MicE.MessageType != c.want {
			t.Errorf("dest %s: message_type = %q, want %q", c.dest, f.MicE.MessageType, c.want)
		}
	}
}

// TestMicEAmbiguity confirms blanked latitude digits raise the ambiguity count.
func TestMicEAmbiguity(t *testing.T) {
	// Z and L blank the latitude digit (Z = std-1 North, L = std-0 South).
	f, err := Decode("N0CALL>S3ZU6T:" + miceInfoExample)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if f.MicE.Ambiguity != 1 {
		t.Errorf("ambiguity = %d, want 1", f.MicE.Ambiguity)
	}
}

func TestMicERejectsShortInfo(t *testing.T) {
	if _, err := Decode("N0CALL>S32U6T:`short"); err == nil {
		t.Fatal("want error for <9-byte Mic-E info field")
	}
}

func TestMicERejectsBadDest(t *testing.T) {
	// A 5-char destination cannot carry the Mic-E latitude encoding.
	if _, err := Decode("N0CALL>S32U6:" + miceInfoExample); err == nil {
		t.Fatal("want error for non-6-char Mic-E destination")
	}
}
