package dcf77

import (
	"strings"
	"testing"
)

// buildFrame is a test helper that constructs a 60-bit DCF77
// frame from the documented field values. Per PTB DCF77 spec:
//
//	bit 0   : start of minute (always 0)
//	bits 1-14: weather data (we set to 0 for tests)
//	bit 15  : antenna switch announcement
//	bit 16  : DST change announcement
//	bits 17-18: CEST=10, CET=01
//	bit 19  : leap-second announcement
//	bit 20  : start of time marker (always 1)
//	bits 21-27: minute BCD (weights 1,2,4,8,10,20,40)
//	bit 28  : minute parity (even over bits 21-27)
//	bits 29-34: hour BCD (weights 1,2,4,8,10,20)
//	bit 35  : hour parity
//	bits 36-41: day of month BCD (1,2,4,8,10,20)
//	bits 42-44: day of week BCD (1,2,4)
//	bits 45-49: month BCD (1,2,4,8,10)
//	bits 50-57: year BCD (1,2,4,8,10,20,40,80)
//	bit 58  : date parity
//	bit 59  : minute end marker (no bit transmitted = 0)
func buildFrame(t *testing.T, minute, hour, day, dow, month, year int, cest bool) string {
	t.Helper()
	b := make([]byte, 60)
	// bit 0: start of minute = 0 (already)
	// bits 17-18: CET=01, CEST=10
	if cest {
		b[17] = 1
	} else {
		b[18] = 1
	}
	// bit 20: start of time = 1
	b[20] = 1
	// Minute BCD
	encodeBCD(b[21:28], minute, []int{1, 2, 4, 8, 10, 20, 40})
	b[28] = byte(evenParity(b[21:28]))
	// Hour BCD
	encodeBCD(b[29:35], hour, []int{1, 2, 4, 8, 10, 20})
	b[35] = byte(evenParity(b[29:35]))
	// Day of month
	encodeBCD(b[36:42], day, []int{1, 2, 4, 8, 10, 20})
	// Day of week
	encodeBCD(b[42:45], dow, []int{1, 2, 4})
	// Month
	encodeBCD(b[45:50], month, []int{1, 2, 4, 8, 10})
	// Year (2-digit)
	encodeBCD(b[50:58], year, []int{1, 2, 4, 8, 10, 20, 40, 80})
	// Date parity
	b[58] = byte(evenParity(b[36:58]))
	// Render as bit string
	var sb strings.Builder
	for _, c := range b {
		if c == 1 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String()
}

// encodeBCD now lives in synth.go (production) — the test's buildFrame
// helper shares that single implementation.

// TestDecode_HappyPath pins decoding of a specific real-world-
// shaped frame: 14:35, Tuesday 2026-04-22, CEST (DST active).
func TestDecode_HappyPath(t *testing.T) {
	bits := buildFrame(t, 35, 14, 22, 2, 4, 26, true)
	got, err := Decode(bits)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Minute != 35 {
		t.Errorf("Minute = %d; want 35", got.Minute)
	}
	if got.Hour != 14 {
		t.Errorf("Hour = %d; want 14", got.Hour)
	}
	if got.DayOfMonth != 22 {
		t.Errorf("DayOfMonth = %d; want 22", got.DayOfMonth)
	}
	if got.DayOfWeek != 2 {
		t.Errorf("DayOfWeek = %d; want 2 (Tuesday)", got.DayOfWeek)
	}
	if got.DayOfWeekName != "Tuesday" {
		t.Errorf("DayOfWeekName = %q", got.DayOfWeekName)
	}
	if got.Month != 4 {
		t.Errorf("Month = %d; want 4", got.Month)
	}
	if got.Year != 26 {
		t.Errorf("Year = %d; want 26", got.Year)
	}
	if !got.CESTActive {
		t.Error("CESTActive should be true")
	}
	if got.TimezoneOffsetHours != 2 {
		t.Errorf("TimezoneOffsetHours = %d; want 2 (CEST)", got.TimezoneOffsetHours)
	}
	if got.FormattedTime != "14:35" {
		t.Errorf("FormattedTime = %q; want '14:35'", got.FormattedTime)
	}
	if got.FormattedDate != "2026-04-22" {
		t.Errorf("FormattedDate = %q; want '2026-04-22'", got.FormattedDate)
	}
	if !got.AllParityValid {
		t.Errorf("AllParityValid = false; parity flags: min=%v hour=%v date=%v",
			got.MinuteParityValid, got.HourParityValid, got.DateParityValid)
	}
}

// TestDecode_CETvsCEST confirms the timezone flag toggles
// between CET (UTC+1) and CEST (UTC+2).
func TestDecode_CETvsCEST(t *testing.T) {
	// Winter time (CET): 10:00, Jan 15, 2025
	bitsCET := buildFrame(t, 0, 10, 15, 3, 1, 25, false)
	gotCET, err := Decode(bitsCET)
	if err != nil {
		t.Fatalf("Decode CET: %v", err)
	}
	if gotCET.CESTActive {
		t.Error("CESTActive should be false in winter")
	}
	if gotCET.TimezoneOffsetHours != 1 {
		t.Errorf("CET offset = %d; want 1", gotCET.TimezoneOffsetHours)
	}

	// Summer time (CEST): 10:00, Jul 15, 2025
	bitsCEST := buildFrame(t, 0, 10, 15, 2, 7, 25, true)
	gotCEST, err := Decode(bitsCEST)
	if err != nil {
		t.Fatalf("Decode CEST: %v", err)
	}
	if !gotCEST.CESTActive {
		t.Error("CESTActive should be true in summer")
	}
	if gotCEST.TimezoneOffsetHours != 2 {
		t.Errorf("CEST offset = %d; want 2", gotCEST.TimezoneOffsetHours)
	}
}

// TestDecode_DayOfWeekNames pins all 7 day mappings (1=Mon).
func TestDecode_DayOfWeekNames(t *testing.T) {
	cases := map[int]string{
		1: "Monday",
		2: "Tuesday",
		3: "Wednesday",
		4: "Thursday",
		5: "Friday",
		6: "Saturday",
		7: "Sunday",
	}
	for dow, want := range cases {
		bits := buildFrame(t, 0, 12, 1, dow, 1, 25, false)
		got, err := Decode(bits)
		if err != nil {
			t.Fatalf("Decode dow=%d: %v", dow, err)
		}
		if got.DayOfWeekName != want {
			t.Errorf("dow=%d: name = %q; want %q", dow, got.DayOfWeekName, want)
		}
	}
}

// TestDecode_StartOfMinuteMustBeZero — bit 0 should be 0; we
// surface false (= "valid") when bit is 0, true (= "set, possibly
// invalid") when bit is 1.
func TestDecode_StartOfMinuteMustBeZero(t *testing.T) {
	// Build a valid frame, then flip bit 0.
	bits := buildFrame(t, 0, 12, 1, 1, 1, 25, false)
	corrupted := "1" + bits[1:] // flip bit 0
	got, err := Decode(corrupted)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StartOfMinute {
		t.Error("StartOfMinute should be false when bit 0 = 1 (malformed marker)")
	}
}

// TestDecode_StartOfTimeMustBeOne — bit 20 should be 1; flip it
// and confirm StartOfTime surfaces false.
func TestDecode_StartOfTimeMustBeOne(t *testing.T) {
	bits := buildFrame(t, 0, 12, 1, 1, 1, 25, false)
	corrupted := bits[:20] + "0" + bits[21:]
	got, err := Decode(corrupted)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StartOfTime {
		t.Error("StartOfTime should be false when bit 20 = 0")
	}
}

// TestDecode_MinuteParityInvalid — flipping bit 28 (minute
// parity) should make the validity flag false.
func TestDecode_MinuteParityInvalid(t *testing.T) {
	bits := buildFrame(t, 35, 14, 22, 2, 4, 26, true)
	// Flip bit 28
	flipped := flipBit(bits, 28)
	got, err := Decode(flipped)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MinuteParityValid {
		t.Error("MinuteParityValid should be false after flipping parity bit")
	}
	if got.AllParityValid {
		t.Error("AllParityValid should be false when minute parity is bad")
	}
}

// TestDecode_HourParityInvalid — same but for hour parity.
func TestDecode_HourParityInvalid(t *testing.T) {
	bits := buildFrame(t, 35, 14, 22, 2, 4, 26, true)
	flipped := flipBit(bits, 35)
	got, err := Decode(flipped)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HourParityValid {
		t.Error("HourParityValid should be false")
	}
}

// TestDecode_DateParityInvalid — same for date parity.
func TestDecode_DateParityInvalid(t *testing.T) {
	bits := buildFrame(t, 35, 14, 22, 2, 4, 26, true)
	flipped := flipBit(bits, 58)
	got, err := Decode(flipped)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DateParityValid {
		t.Error("DateParityValid should be false")
	}
}

// TestDecode_WeatherDataSurfaced — bits 1..14 are the encrypted
// weather data; we don't decode but surface as a 14-bit binary
// string for cross-reference.
func TestDecode_WeatherDataSurfaced(t *testing.T) {
	// Build a frame with all weather bits set to demonstrate.
	bits := []byte(buildFrame(t, 0, 12, 1, 1, 1, 25, false))
	for i := 1; i <= 14; i++ {
		bits[i] = '1'
	}
	got, err := Decode(string(bits))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.WeatherDataBits != "11111111111111" {
		t.Errorf("WeatherDataBits = %q; want all 1s", got.WeatherDataBits)
	}
}

// TestDecode_TimezoneFlags ensures the antenna-switch / DST-
// change / leap-second announcement bits decode independently.
func TestDecode_TimezoneFlags(t *testing.T) {
	bits := []byte(buildFrame(t, 0, 12, 1, 1, 1, 25, false))
	bits[15] = '1' // antenna switch
	bits[16] = '1' // DST change
	bits[19] = '1' // leap second
	got, err := Decode(string(bits))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.AntennaSwitchAnnouncement {
		t.Error("AntennaSwitchAnnouncement should be true")
	}
	if !got.DSTChangeAnnouncement {
		t.Error("DSTChangeAnnouncement should be true")
	}
	if !got.LeapSecondAnnouncement {
		t.Error("LeapSecondAnnouncement should be true")
	}
}

// TestDecode_WrongLength — input not exactly 60 bits is rejected.
func TestDecode_WrongLength(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode(strings.Repeat("0", 59)); err == nil {
		t.Error("59-bit input: want error")
	}
	if _, err := Decode(strings.Repeat("0", 61)); err == nil {
		t.Error("61-bit input: want error")
	}
}

// TestDecode_InvalidCharacters — non-0/1 chars rejected.
func TestDecode_InvalidCharacters(t *testing.T) {
	bad := strings.Repeat("0", 59) + "X"
	if _, err := Decode(bad); err == nil {
		t.Error("invalid char: want error")
	}
}

// TestDecode_Separators — ':' / '-' / '_' / whitespace tolerated.
func TestDecode_Separators(t *testing.T) {
	bits := buildFrame(t, 35, 14, 22, 2, 4, 26, true)
	// Insert separators every 10 chars.
	var withSeps strings.Builder
	for i, c := range bits {
		if i > 0 && i%10 == 0 {
			withSeps.WriteByte(':')
		}
		withSeps.WriteRune(c)
	}
	got, err := Decode(withSeps.String())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FormattedTime != "14:35" {
		t.Errorf("FormattedTime = %q", got.FormattedTime)
	}
}

// flipBit flips one bit in a bit-string.
func flipBit(s string, pos int) string {
	b := []byte(s)
	if b[pos] == '0' {
		b[pos] = '1'
	} else {
		b[pos] = '0'
	}
	return string(b)
}
