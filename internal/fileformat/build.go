package fileformat

import (
	"fmt"
	"regexp"
	"strings"
)

// Parametric file builders (P1-13). Each Build* accepts a typed params
// struct, validates the inputs, and returns canonical bytes ready to
// write to the Flipper SD card. Use instead of asking the LLM to emit
// raw file bytes — the LLM supplies parameters, we construct the
// file, and the fileformat parsers get a guaranteed-valid roundtrip.
//
// Validation is firm (frequency bounds, hex sanity, required fields)
// but not exhaustive — a malformed file that survives validation will
// still be rejected by the Flipper firmware when the user actually
// runs it. The goal is to catch obvious typos, not to reimplement the
// firmware's parsers.

// hexRE matches a contiguous hex string — used to validate Data /
// Key / UID fields before we splice them into a file. Spaces between
// octets are permitted in some field types; callers strip them first
// when needed.
var hexRE = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// ----- Sub-GHz -----

// SubBuildParams carries the inputs for BuildSub. Frequency is the
// only required field; everything else is optional and falls back to
// sensible defaults (Preset = Ook650Async which matches the majority
// of ISM-band captures).
type SubBuildParams struct {
	// Frequency in Hz (e.g. 433920000 for 433.92 MHz). Rejected if
	// zero or outside the 1 MHz–1 GHz range the Flipper CC1101 can
	// reach.
	Frequency uint32

	// Protocol name, e.g. "Princeton", "Keeloq", "RAW". Optional —
	// omitted files default to the RAW / unrecognised path.
	Protocol string

	// Preset name understood by the Flipper firmware. Leave empty to
	// have BuildSub pick a default from the frequency band.
	Preset string

	// Key is a space-separated hex byte string, e.g.
	// "1A 2B 3C 4D 00 00 00 00". Produces the Key: line.
	Key string

	// Bit is the protocol's bit-length (e.g. 24 for Princeton,
	// 32 for Came).
	Bit int

	// TE is the protocol's timing element in microseconds. Defaults
	// to 400 (a common Princeton TE) when zero and Protocol is set.
	TE int

	// RawData produces a RAW file instead of a keyed one. When set,
	// Protocol is overridden to "RAW".
	RawData []int32
}

// BuildSub constructs a canonical .sub capture from parameters.
// Required: Frequency. Returns the file bytes; callers typically
// hand the result to Flipper.WriteFileCtx.
func BuildSub(p SubBuildParams) ([]byte, error) {
	if p.Frequency == 0 {
		return nil, fmt.Errorf("sub_build: frequency required")
	}
	if p.Frequency < 1_000_000 || p.Frequency > 1_000_000_000 {
		return nil, fmt.Errorf("sub_build: frequency %d Hz out of Flipper CC1101 range (1 MHz–1 GHz)", p.Frequency)
	}

	s := &SubFile{
		Filetype:  "Flipper SubGhz Key File",
		Version:   1,
		Frequency: p.Frequency,
		Preset:    p.Preset,
		Protocol:  p.Protocol,
		Bit:       p.Bit,
		TE:        p.TE,
		Headers:   map[string]string{},
	}
	if s.Preset == "" {
		s.Preset = defaultSubPreset(p.Frequency)
	}
	if len(p.RawData) > 0 {
		s.Protocol = "RAW"
		s.RawData = append([]int32(nil), p.RawData...)
	} else if p.Key != "" {
		key, err := normaliseHexBytes(p.Key)
		if err != nil {
			return nil, fmt.Errorf("sub_build: invalid key: %w", err)
		}
		s.Key = key
		if s.TE == 0 && s.Protocol != "" {
			s.TE = 400 // common Princeton/Came TE
		}
	}
	return s.Marshal(), nil
}

// defaultSubPreset returns a reasonable preset name for a given
// frequency. The Flipper firmware accepts any of the listed preset
// strings; picking one that matches the band keeps the downstream
// TX wrapper happy.
func defaultSubPreset(freq uint32) string {
	switch {
	case freq >= 300_000_000 && freq <= 348_000_000,
		freq >= 387_000_000 && freq <= 464_000_000,
		freq >= 779_000_000 && freq <= 928_000_000:
		return "FuriHalSubGhzPresetOok650Async"
	default:
		return "FuriHalSubGhzPreset2FSKDev238Async"
	}
}

// ----- RFID (125 kHz) -----

// RFIDBuildParams carries inputs for BuildRFID. Both KeyType and Data
// are required.
type RFIDBuildParams struct {
	// KeyType is the LF protocol name: EM4100, HIDProx, Indala,
	// AWID, FDX-A, FDX-B, etc. Accepted verbatim — the caller is
	// responsible for matching the protocol to the data.
	KeyType string

	// Data is the hex payload, e.g. "1A 2B 3C 4D 5E". Spaces
	// between octets are tolerated; non-hex input is rejected.
	Data string
}

// BuildRFID constructs a canonical .rfid file. The resulting file is
// suitable for writing with the rfid_write tool to clone onto a
// T5577 blank.
func BuildRFID(p RFIDBuildParams) ([]byte, error) {
	if strings.TrimSpace(p.KeyType) == "" {
		return nil, fmt.Errorf("rfid_build: key_type required")
	}
	if strings.TrimSpace(p.Data) == "" {
		return nil, fmt.Errorf("rfid_build: data required")
	}
	data, err := normaliseHexBytes(p.Data)
	if err != nil {
		return nil, fmt.Errorf("rfid_build: invalid data: %w", err)
	}
	r := &RFIDFile{
		Filetype: "Flipper RFID key",
		Version:  1,
		KeyType:  strings.TrimSpace(p.KeyType),
		Data:     data,
		Headers:  map[string]string{},
	}
	return r.Marshal(), nil
}

// ----- IR -----

// IRBuildParams carries inputs for BuildIR. A valid IR file needs at
// least one signal; parsed-type signals require Protocol + Address +
// Command; raw-type signals require Frequency + DutyCycle + Data.
type IRBuildParams struct {
	// Name is a display label for the remote. Optional — defaults to
	// "generated".
	Name string

	// Signals is the ordered list of IR entries. Each must have a
	// Name plus either parsed fields or raw fields populated.
	Signals []IRSignal
}

// BuildIR constructs a canonical .ir remote file. The IRSignal
// struct is shared with the parser, so callers can assemble a file
// programmatically and trust the round-trip.
func BuildIR(p IRBuildParams) ([]byte, error) {
	if len(p.Signals) == 0 {
		return nil, fmt.Errorf("ir_build: at least one signal required")
	}
	for i, sig := range p.Signals {
		if strings.TrimSpace(sig.Name) == "" {
			return nil, fmt.Errorf("ir_build: signals[%d].name required", i)
		}
		if strings.ToLower(sig.Type) == "raw" {
			if sig.Frequency == 0 {
				return nil, fmt.Errorf("ir_build: signals[%d] raw requires frequency", i)
			}
			if sig.DutyCycle == 0 {
				return nil, fmt.Errorf("ir_build: signals[%d] raw requires duty_cycle", i)
			}
			if len(sig.Data) == 0 {
				return nil, fmt.Errorf("ir_build: signals[%d] raw requires data", i)
			}
		} else {
			// Default to "parsed" when Type is empty.
			if sig.Type == "" {
				p.Signals[i].Type = "parsed"
			}
			if strings.TrimSpace(sig.Protocol) == "" {
				return nil, fmt.Errorf("ir_build: signals[%d] parsed requires protocol", i)
			}
			if strings.TrimSpace(sig.Address) == "" {
				return nil, fmt.Errorf("ir_build: signals[%d] parsed requires address", i)
			}
			if strings.TrimSpace(sig.Command) == "" {
				return nil, fmt.Errorf("ir_build: signals[%d] parsed requires command", i)
			}
		}
	}
	f := &IRFile{
		Filetype: "IR signals file",
		Version:  1,
		Signals:  append([]IRSignal(nil), p.Signals...),
	}
	return f.Marshal(), nil
}

// ----- NFC -----

// NFCBuildParams carries inputs for BuildNFC. DeviceType + UID are
// the minimum; for Mifare Classic the caller typically supplies
// ATQA, SAK, and a map of block contents.
type NFCBuildParams struct {
	// DeviceType is one of "Mifare Classic", "Mifare Ultralight",
	// "NTAG213", "NTAG215", "NTAG216", etc. Accepted verbatim.
	DeviceType string

	// UID hex, e.g. "AA BB CC DD". Spaces between bytes are tolerated.
	UID string

	// ATQA / SAK are the ISO/IEC 14443 response bytes. Optional —
	// omitted for NTAG variants that don't expose them.
	ATQA string
	SAK  string

	// MifareType (e.g. "1K" / "4K") for Classic captures.
	MifareType string

	// Blocks maps block index → space-separated hex bytes. Optional
	// — a bare UID capture with no Blocks still produces a valid
	// file useful for UID-only emulation.
	Blocks map[int]string
}

// BuildNFC constructs a canonical .nfc capture. The resulting file is
// suitable for nfc_emulate.
//
// UID byte-length is validated against DeviceType so a 4-byte UID
// paired with "NTAG215" doesn't silently produce a file that would
// fail every reader probe. Allowed lengths per type follow the
// published ISO/IEC 14443 tag-family specs:
//
//	Mifare Classic 1K/4K/Mini          4 or 7 bytes
//	Mifare Ultralight / NTAG21x        7 bytes
//	NTAG215 / NTAG216 / NTAG213        7 bytes
//	Other / unknown                    any non-empty hex passes (permissive)
func BuildNFC(p NFCBuildParams) ([]byte, error) {
	if strings.TrimSpace(p.DeviceType) == "" {
		return nil, fmt.Errorf("nfc_build: device_type required")
	}
	if strings.TrimSpace(p.UID) == "" {
		return nil, fmt.Errorf("nfc_build: uid required")
	}
	uid, err := normaliseHexBytes(p.UID)
	if err != nil {
		return nil, fmt.Errorf("nfc_build: invalid uid: %w", err)
	}
	if err := validateUIDLength(p.DeviceType, uid); err != nil {
		return nil, err
	}

	n := &NFCFile{
		Filetype:   "Flipper NFC device",
		Version:    2,
		DeviceType: strings.TrimSpace(p.DeviceType),
		UID:        uid,
		ATQA:       normaliseHexOrRaw(p.ATQA),
		SAK:        normaliseHexOrRaw(p.SAK),
		MifareType: strings.TrimSpace(p.MifareType),
		Blocks:     map[int]string{},
		Headers:    map[string]string{},
	}
	for idx, hex := range p.Blocks {
		normalised, err := normaliseHexBytes(hex)
		if err != nil {
			return nil, fmt.Errorf("nfc_build: block %d invalid hex: %w", idx, err)
		}
		n.Blocks[idx] = normalised
	}
	return n.Marshal(), nil
}

// validateUIDLength checks that a normalised UID (space-separated
// hex, upper-case) has a byte count matching the DeviceType. The
// normalised form has one space between each hex pair, so the byte
// count is (len+1) / 3. Unknown device types pass silently — the
// goal is to catch obvious mismatches, not enforce a closed list.
func validateUIDLength(deviceType, normalisedUID string) error {
	byteCount := (len(normalisedUID) + 1) / 3
	lower := strings.ToLower(strings.TrimSpace(deviceType))

	var allowed []int
	switch {
	case strings.Contains(lower, "classic"), strings.Contains(lower, "mini"):
		allowed = []int{4, 7}
	case strings.Contains(lower, "ultralight"),
		strings.Contains(lower, "ntag"),
		strings.Contains(lower, "mfu"):
		allowed = []int{7}
	case strings.Contains(lower, "desfire"), strings.Contains(lower, "plus"):
		allowed = []int{4, 7}
	default:
		return nil // unknown type — don't block the build
	}

	for _, n := range allowed {
		if byteCount == n {
			return nil
		}
	}
	return fmt.Errorf("nfc_build: UID is %d bytes but %s expects %v bytes", byteCount, deviceType, allowed)
}

// ----- helpers -----

// normaliseHexBytes validates that s is a hex string (ignoring ASCII
// whitespace) and returns it re-formatted with a single space between
// octets — matching the canonical Flipper file shape. Odd-length
// strings and non-hex characters surface as errors so the LLM gets a
// specific diagnostic.
func normaliseHexBytes(s string) (string, error) {
	cleaned := strings.ReplaceAll(s, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")
	cleaned = strings.ToUpper(strings.TrimSpace(cleaned))
	if cleaned == "" {
		return "", fmt.Errorf("empty hex")
	}
	if len(cleaned)%2 != 0 {
		return "", fmt.Errorf("odd-length hex %q", cleaned)
	}
	if !hexRE.MatchString(cleaned) {
		return "", fmt.Errorf("non-hex characters in %q", cleaned)
	}
	var b strings.Builder
	for i := 0; i < len(cleaned); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(cleaned[i : i+2])
	}
	return b.String(), nil
}

// normaliseHexOrRaw best-effort normalises s as hex when it looks
// like hex, otherwise returns it trimmed. Used for ATQA / SAK
// fields where captures sometimes surface bare hex and sometimes
// pre-spaced pairs.
func normaliseHexOrRaw(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	if out, err := normaliseHexBytes(trimmed); err == nil {
		return out
	}
	return trimmed
}
