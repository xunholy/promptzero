package workflows

// Test-only shims so the external _test package can exercise package-
// private parsers/formatters without exporting them from production
// code. Kept in its own file so they don't clutter the main implementation
// and aren't linked into the binary.

type PMKIDCaptureForTest = pmkidCapture
type MarauderAPForTest = marauderAP

func Hashcat22000LineForTest(c PMKIDCaptureForTest) string {
	return hashcat22000Line(c)
}

func ParsePMKIDForTest(out string) *PMKIDCaptureForTest {
	return parsePMKID(out)
}

func PickStrongestWPAForTest(aps []MarauderAPForTest) *MarauderAPForTest {
	return pickStrongestWPA(aps)
}
