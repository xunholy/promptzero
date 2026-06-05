// SPDX-License-Identifier: AGPL-3.0-or-later

package bcbp

import "testing"

// canonical is the IATA Resolution 792 worked example: passenger
// DESMARAIS/LUC, PNR ABC123, YUL→FRA on AC flight 0834, Julian day 226,
// compartment F, seat 001A, sequence 0025, status 1, no conditional data.
const canonical = "M1DESMARAIS/LUC       EABC123 YULFRAAC 0834 226F001A0025 100"

func TestDecodeCanonical(t *testing.T) {
	bp, err := Decode(canonical)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if bp.FormatCode != "M" || bp.NumberOfLegs != 1 {
		t.Errorf("format/legs = %s/%d; want M/1", bp.FormatCode, bp.NumberOfLegs)
	}
	if bp.PassengerName != "DESMARAIS/LUC" {
		t.Errorf("name = %q; want DESMARAIS/LUC", bp.PassengerName)
	}
	if !bp.ETicket {
		t.Error("ETicket = false; want true")
	}
	if len(bp.Legs) != 1 {
		t.Fatalf("legs = %d; want 1", len(bp.Legs))
	}
	l := bp.Legs[0]
	if l.PNR != "ABC123" || l.From != "YUL" || l.To != "FRA" || l.OperatingCarrier != "AC" {
		t.Errorf("pnr/from/to/carrier = %s/%s/%s/%s; want ABC123/YUL/FRA/AC", l.PNR, l.From, l.To, l.OperatingCarrier)
	}
	if l.FlightNumber != "0834" || l.FlightDayOfYear != 226 {
		t.Errorf("flight/day = %s/%d; want 0834/226", l.FlightNumber, l.FlightDayOfYear)
	}
	if l.Compartment != "F" || l.SeatNumber != "001A" || l.CheckInSequence != "0025" || l.PassengerStatus != "1" {
		t.Errorf("compartment/seat/seq/status = %s/%s/%s/%s; want F/001A/0025/1",
			l.Compartment, l.SeatNumber, l.CheckInSequence, l.PassengerStatus)
	}
	if l.ConditionalRaw != "" {
		t.Errorf("ConditionalRaw = %q; want empty (condsize 00)", l.ConditionalRaw)
	}
}

func TestDecodeConditionalSurfacedRaw(t *testing.T) {
	// Same leg but with a 4-char conditional section (hex size 04) of
	// airline-use data appended; it must be surfaced raw and not misparse.
	in := "M1DESMARAIS/LUC       EABC123 YULFRAAC 0834 226F001A0025 104WXYZ"
	bp, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if bp.Legs[0].ConditionalRaw != "WXYZ" {
		t.Errorf("ConditionalRaw = %q; want WXYZ", bp.Legs[0].ConditionalRaw)
	}
	if bp.Legs[0].PNR != "ABC123" { // mandatory still correct
		t.Errorf("PNR = %q; want ABC123", bp.Legs[0].PNR)
	}
}

func TestDecodeTwoLegs(t *testing.T) {
	// Two legs, each with condsize 00 — the self-describing length marker
	// must locate leg 2's mandatory block correctly.
	leg := "ABC123 YULFRAAC 0834 226F001A0025 100"
	leg2 := "ABC123 FRALHRBA 0476 227C014C0033 100"
	in := "M2DESMARAIS/LUC       E" + leg + leg2
	bp, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if bp.NumberOfLegs != 2 || len(bp.Legs) != 2 {
		t.Fatalf("legs = %d / %d; want 2", bp.NumberOfLegs, len(bp.Legs))
	}
	if bp.Legs[1].From != "FRA" || bp.Legs[1].To != "LHR" || bp.Legs[1].OperatingCarrier != "BA" {
		t.Errorf("leg2 = %s→%s/%s; want FRA→LHR/BA", bp.Legs[1].From, bp.Legs[1].To, bp.Legs[1].OperatingCarrier)
	}
	if bp.Legs[1].FlightNumber != "0476" || bp.Legs[1].SeatNumber != "014C" {
		t.Errorf("leg2 flight/seat = %s/%s; want 0476/014C", bp.Legs[1].FlightNumber, bp.Legs[1].SeatNumber)
	}
}

func TestRejects(t *testing.T) {
	for _, c := range []string{"", "M1short", "X1DESMARAIS/LUC       EABC123 YULFRAAC 0834 226F001A0025 100"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(canonical)
	f.Add("M1DESMARAIS/LUC       EABC123 YULFRAAC 0834 226F001A0025 104WXYZ")
	f.Add("")
	f.Add("M1")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
