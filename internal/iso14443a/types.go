package iso14443a

// tagKey is the lookup key for the (ATQA, SAK) → tag-type
// table. sak = -1 is the sentinel for "any SAK with this ATQA".
type tagKey struct {
	atqa int
	sak  int
}

// tagEntry pairs a specific tag-type name with its coarser
// family for routing decisions downstream.
type tagEntry struct {
	tagType string
	family  string
}

// identifyTagType picks the best match from the lookup table.
// Exact (ATQA, SAK) wins; falls back to ATQA-only when no exact
// match exists. Returns ("Unknown", "Other", false) when nothing
// matches.
func identifyTagType(atqa ATQA, sak SAK) (string, string) {
	if entry, ok := tagTypes[tagKey{atqa: atqa.Raw, sak: sak.Raw}]; ok {
		return entry.tagType, entry.family
	}
	if entry, ok := tagTypes[tagKey{atqa: atqa.Raw, sak: -1}]; ok {
		return entry.tagType, entry.family
	}
	// SAK-only fallback for cards where only the SAK is
	// distinctive (mostly DESFire variants which can present
	// different ATQAs depending on configuration).
	if entry, ok := sakOnly[sak.Raw]; ok {
		return entry.tagType, entry.family
	}
	return "Unknown", "Other"
}

// tagTypes is the (ATQA, SAK) → tag-type table. Sourced from
// NXP AN10833 Table 6 (Mifare family) and AN10927 (UID
// formats). Covers the cards operators see most often.
var tagTypes = map[tagKey]tagEntry{
	{0x0004, 0x08}: {"Mifare Classic 1K", "Mifare Classic"},
	{0x0004, 0x09}: {"Mifare Mini", "Mifare Classic"},
	{0x0044, 0x09}: {"Mifare Mini", "Mifare Classic"},
	{0x0002, 0x18}: {"Mifare Classic 4K", "Mifare Classic"},
	{0x0042, 0x18}: {"Mifare Classic 4K", "Mifare Classic"},
	{0x0044, 0x00}: {"Mifare Ultralight / NTAG", "Mifare Ultralight / NTAG"},
	{0x0344, 0x00}: {"Mifare Ultralight C", "Mifare Ultralight / NTAG"},
	{0x0044, 0x09}: {"Mifare Mini", "Mifare Classic"},
	{0x0344, 0x20}: {"Mifare DESFire EV1/EV2/EV3", "DESFire"},
	{0x0344, 0x28}: {"JCOP (Java Card OS Platform)", "ISO 14443-4"},
	{0x0004, 0x28}: {"SmartMX with Mifare Classic 1K emulation", "SmartMX"},
	{0x0002, 0x38}: {"SmartMX with Mifare Classic 4K emulation", "SmartMX"},
	{0x0004, 0x88}: {"Infineon Mifare Classic 1K", "Mifare Classic"},
	{0x0042, 0x20}: {"Mifare Plus EV1 (SL3) 2K/4K", "Mifare Plus"},
	{0x0044, 0x20}: {"Mifare Plus EV1 (SL3) 2K/4K", "Mifare Plus"},
	{0x0004, 0x20}: {"Mifare Plus (SL1) 2K/4K", "Mifare Plus"},
	{0x0048, 0x20}: {"Mifare Plus EV2", "Mifare Plus"},
	{0x0008, 0x20}: {"Mifare Plus (SL1)", "Mifare Plus"},
	// Generic ISO 14443-4 tags with SAK 0x20 + 14443-4 bit set
	// fall through to the SAK-only table; many bank-card emulators
	// present this combination.
}

// sakOnly is the fallback for SAK values that uniquely identify
// a family regardless of ATQA. Used after the (ATQA, SAK) and
// (ATQA, -1) lookups fail.
var sakOnly = map[int]tagEntry{
	// SAK 0x00 with no exact ATQA match: Ultralight family.
	0x00: {"Mifare Ultralight family", "Mifare Ultralight / NTAG"},
	// SAK 0x20 with ISO 14443-4 compliance: bank cards, JCOP, etc.
	0x20: {"ISO 14443-4 compliant card", "ISO 14443-4"},
	// SAK 0x28: JCOP / SmartMX with 14443-4
	0x28: {"JCOP / ISO 14443-4 with proprietary protocols", "ISO 14443-4"},
}

// manufacturers maps the ISO/IEC 7816-6 IC manufacturer code
// (the first byte of a UID, or the byte after the cascade tag)
// to the vendor name. Covers the codes operators most often see
// in NFC dumps; not exhaustive.
var manufacturers = map[byte]string{
	0x02: "STMicroelectronics",
	0x04: "NXP Semiconductors",
	0x05: "Infineon Technologies",
	0x07: "Texas Instruments",
	0x08: "Fujitsu Microelectronics",
	0x09: "Matsushita Electronics",
	0x0B: "Hitachi",
	0x0E: "Mitsubishi",
	0x18: "Samsung Electronics",
	0x1B: "Hewlett-Packard",
	0x1C: "Tag-it (TI)",
	0x1F: "Renesas",
	0x22: "Inside Secure",
	0x23: "ON Semiconductor",
	0x24: "LG Semiconductors",
	0x28: "Toshiba",
	0x2B: "Atmel",
	0x33: "AMIC",
	0x34: "Mikron",
	0x35: "Solar Capacitor",
	0x49: "Synaptics",
	0x88: "Cascade Tag (UID continues in next round)",
}

// ManufacturerName returns the IC manufacturer for an ISO/IEC 7816-6 vendor
// code (the registry shared by ISO 14443 and ISO 15693 UIDs). The bool reports
// whether the code is known rather than guessed.
func ManufacturerName(code byte) (string, bool) {
	name, ok := manufacturers[code]
	return name, ok
}
