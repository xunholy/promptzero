// gap.go — generic BLE GAP / EIR advertisement walker. Decodes
// the outer (length, AD type, data) record structure that wraps
// every BLE advertisement — Flags, Service UUID lists, Local
// Name, TX Power, Service Data, Manufacturer Specific Data,
// Appearance, etc.
//
// Wrap-vs-native judgement: the GAP advertisement format is a
// public Bluetooth SIG spec (Core Spec Vol 3 Part C §11 + the
// "Assigned Numbers - Generic Access Profile" document at
// bluetooth.com/specifications/assigned-numbers). The walker is
// a length-prefixed record loop with a small per-AD-type
// dispatcher. Wrapping a FAP for this would add an SD-card
// install step + a firmware-fork dependency for a pure parser.
// Native delivers offline analysis — operators paste a btmon /
// nrfconnect / Wireshark capture and decode the full
// advertisement before dispatching specific records (Apple
// Continuity, Eddystone, etc.) to their dedicated decoders.
//
// Pairs with the existing per-content decoders in this package
// (DecodeContinuity, DecodeEddystone). This walker surfaces
// the manufacturer-data / service-data hex; the operator then
// runs the dedicated decoder on the inner bytes.
//
// What this package covers (this file):
//   - Record walker: (length, AD type, data) records walked
//     until end-of-buffer or zero-length terminator
//   - AD type name lookup for the documented Bluetooth SIG
//     assigned numbers (~30 most common types)
//   - Per-AD-type decode: Flags bitfield, 16/32/128-bit Service
//     UUID lists, Local Name (UTF-8 string), TX Power signed
//     int8, Service Data 16-bit (UUID + opaque payload),
//     Manufacturer Specific Data (company ID + opaque payload),
//     Appearance (16-bit category)
//   - Bluetooth SIG company-ID lookup table for the ~20 most
//     commonly observed vendors
//
// What this package does NOT cover (deliberately out of scope):
//   - Specific manufacturer/service-data payload decode — Apple
//     Continuity gets dispatched to DecodeContinuity; Eddystone
//     to DecodeEddystone; the walker just surfaces the inner
//     bytes for chaining.
//   - 32-bit and 128-bit Service Data (AD types 0x20, 0x21) —
//     same pattern as 16-bit, happy to add when a caller asks
//   - L2CAP / ATT / GATT — those are higher-layer.

package ble

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// reverseBytes returns a fresh slice with the bytes reversed —
// used for little-endian-on-wire 128-bit UUIDs whose canonical
// rendering is big-endian.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// GAPRecord is one decoded (length, AD type, data) entry.
type GAPRecord struct {
	// Length is the declared record length byte (size of AD
	// type + data; doesn't count the length byte itself).
	Length int `json:"length"`
	// ADType is the 1-byte AD type identifier.
	ADType int `json:"ad_type"`
	// ADTypeHex is the operator-facing form ("01", "FF").
	ADTypeHex string `json:"ad_type_hex"`
	// Name is the documented Bluetooth SIG name for the AD type,
	// or "Unknown" when the type isn't in our table.
	Name string `json:"name"`
	// DataHex is the operator-facing hex rendering of the data
	// portion (the bytes after the AD type, length = Length-1).
	DataHex string `json:"data_hex"`
	// Decoded is the per-AD-type structured field decode.
	// Populated for the documented types we dissect (Flags,
	// Service UUID lists, Local Name, TX Power, Service Data,
	// Manufacturer Data, Appearance). nil for types we leave as
	// raw hex.
	Decoded map[string]any `json:"decoded,omitempty"`
}

// GAPAdvertisement is the top-level walker result.
type GAPAdvertisement struct {
	// Records is the ordered list of decoded records.
	Records []GAPRecord `json:"records"`
	// Count is len(Records).
	Count int `json:"count"`
	// Warnings collects non-fatal observations (zero-length
	// terminator hit, trailing bytes after final record, etc.).
	Warnings []string `json:"warnings,omitempty"`
}

// DecodeGAP parses a hex-encoded BLE GAP / EIR advertisement.
// Tolerates ':' / '-' / '_' / whitespace separators.
func DecodeGAP(hexBlob string) (GAPAdvertisement, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return GAPAdvertisement{}, fmt.Errorf("ble: empty GAP input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return GAPAdvertisement{}, fmt.Errorf("ble: invalid hex: %w", err)
	}
	return DecodeGAPBytes(b)
}

// DecodeGAPBytes is the byte-slice variant of DecodeGAP for
// callers that already have raw bytes.
func DecodeGAPBytes(b []byte) (GAPAdvertisement, error) {
	out := GAPAdvertisement{}
	off := 0
	for off < len(b) {
		l := int(b[off])
		if l == 0 {
			// Zero-length record acts as a terminator — common
			// in fixed-31-byte advertisement buffers padded with
			// zeros.
			out.Warnings = append(out.Warnings,
				fmt.Sprintf("zero-length record at offset %d — treating as terminator", off))
			break
		}
		if off+1+l > len(b) {
			return out, fmt.Errorf("ble: record at offset %d declares length %d, only %d bytes remain",
				off, l, len(b)-off-1)
		}
		if l < 1 {
			return out, fmt.Errorf("ble: record at offset %d has length %d < 1 (no AD type byte)", off, l)
		}
		adType := b[off+1]
		dataStart := off + 2
		dataEnd := off + 1 + l
		data := b[dataStart:dataEnd]
		rec := GAPRecord{
			Length:    l,
			ADType:    int(adType),
			ADTypeHex: fmt.Sprintf("%02X", adType),
			Name:      adTypeName(adType),
			DataHex:   hexString(data),
			Decoded:   decodeADTypeData(adType, data),
		}
		out.Records = append(out.Records, rec)
		off = dataEnd
	}
	out.Count = len(out.Records)
	if off < len(b) {
		out.Warnings = append(out.Warnings,
			fmt.Sprintf("%d trailing bytes after final record (offset %d)", len(b)-off, off))
	}
	if out.Count == 0 {
		return out, fmt.Errorf("ble: no records parsed")
	}
	return out, nil
}

// decodeADTypeData dispatches per-AD-type field decoders. Returns
// nil for types where the raw hex is already the most useful view
// (or for types we deliberately don't dissect here — Continuity
// and Eddystone get dispatched to their dedicated decoders by
// callers).
func decodeADTypeData(adType byte, data []byte) map[string]any {
	switch adType {
	case 0x01:
		return decodeFlags(data)
	case 0x02, 0x03:
		return decodeUUIDList16(data)
	case 0x04, 0x05:
		return decodeUUIDList32(data)
	case 0x06, 0x07:
		return decodeUUIDList128(data)
	case 0x08, 0x09:
		return decodeLocalName(data)
	case 0x0A:
		return decodeTXPower(data)
	case 0x16:
		return decodeServiceData16(data)
	case 0x19:
		return decodeAppearance(data)
	case 0xFF:
		return decodeManufacturerData(data)
	}
	return nil
}

// decodeFlags parses the LE Flags bitfield (AD type 0x01).
// Per Core Spec Vol 3 Part C §18.1.
func decodeFlags(b []byte) map[string]any {
	if len(b) < 1 {
		return map[string]any{"error": "empty flags payload"}
	}
	f := b[0]
	out := map[string]any{
		"raw": int(f),
	}
	var names []string
	if f&0x01 != 0 {
		names = append(names, "LE Limited Discoverable")
	}
	if f&0x02 != 0 {
		names = append(names, "LE General Discoverable")
	}
	if f&0x04 != 0 {
		names = append(names, "BR/EDR Not Supported")
	}
	if f&0x08 != 0 {
		names = append(names, "Simultaneous LE & BR/EDR (Controller)")
	}
	if f&0x10 != 0 {
		names = append(names, "Simultaneous LE & BR/EDR (Host)")
	}
	out["flags"] = names
	return out
}

// decodeUUIDList16 walks a list of 16-bit Service UUIDs (each
// stored little-endian on wire; we render big-endian hex to
// match the Bluetooth SIG assigned-numbers form).
func decodeUUIDList16(b []byte) map[string]any {
	if len(b)%2 != 0 {
		return map[string]any{
			"error": fmt.Sprintf("UUID-16 list length %d not divisible by 2", len(b)),
		}
	}
	var uuids []string
	for i := 0; i+2 <= len(b); i += 2 {
		uuids = append(uuids, fmt.Sprintf("%04X", binary.LittleEndian.Uint16(b[i:i+2])))
	}
	return map[string]any{
		"uuids": uuids,
		"count": len(uuids),
	}
}

// decodeUUIDList32 walks a list of 32-bit Service UUIDs.
func decodeUUIDList32(b []byte) map[string]any {
	if len(b)%4 != 0 {
		return map[string]any{
			"error": fmt.Sprintf("UUID-32 list length %d not divisible by 4", len(b)),
		}
	}
	var uuids []string
	for i := 0; i+4 <= len(b); i += 4 {
		uuids = append(uuids, fmt.Sprintf("%08X", binary.LittleEndian.Uint32(b[i:i+4])))
	}
	return map[string]any{
		"uuids": uuids,
		"count": len(uuids),
	}
}

// decodeUUIDList128 walks a list of 128-bit Service UUIDs.
// 128-bit UUIDs are stored little-endian on wire (reversed
// byte order from the canonical xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
// rendering). We restore the canonical form for display.
func decodeUUIDList128(b []byte) map[string]any {
	if len(b)%16 != 0 {
		return map[string]any{
			"error": fmt.Sprintf("UUID-128 list length %d not divisible by 16", len(b)),
		}
	}
	var uuids []string
	for i := 0; i+16 <= len(b); i += 16 {
		uuids = append(uuids, formatUUID128(b[i:i+16]))
	}
	return map[string]any{
		"uuids": uuids,
		"count": len(uuids),
	}
}

// formatUUID128 turns 16 little-endian-on-wire bytes into the
// canonical big-endian "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// rendering. The wire bytes are in reverse order, so we reverse
// before splitting.
func formatUUID128(b []byte) string {
	rev := reverseBytes(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexString(rev[0:4]),
		hexString(rev[4:6]),
		hexString(rev[6:8]),
		hexString(rev[8:10]),
		hexString(rev[10:16]))
}

// decodeLocalName surfaces the UTF-8 name (Shortened or Complete
// — both use this decoder).
func decodeLocalName(b []byte) map[string]any {
	return map[string]any{
		"name": string(b),
	}
}

// decodeTXPower parses the 1-byte signed TX Power Level.
func decodeTXPower(b []byte) map[string]any {
	if len(b) < 1 {
		return map[string]any{"error": "empty TX Power payload"}
	}
	return map[string]any{
		"tx_power_dbm": int(int8(b[0])),
	}
}

// decodeServiceData16 parses a Service Data record carrying a
// 16-bit UUID + opaque payload. The first 2 bytes are the UUID
// (little-endian on wire); the rest is the service-specific
// payload. We render the UUID big-endian + name lookup; the
// payload is surfaced as hex so callers can dispatch to a
// dedicated decoder (DecodeEddystone for 0xFEAA, etc.).
func decodeServiceData16(b []byte) map[string]any {
	if len(b) < 2 {
		return map[string]any{
			"error": fmt.Sprintf("Service Data 16-bit payload %d bytes; want ≥2 (UUID)", len(b)),
		}
	}
	uuid := binary.LittleEndian.Uint16(b[0:2])
	out := map[string]any{
		"uuid":     fmt.Sprintf("%04X", uuid),
		"data_hex": hexString(b[2:]),
	}
	if name, ok := wellKnownServices[uuid]; ok {
		out["service_name"] = name
	}
	return out
}

// decodeAppearance parses the 2-byte Appearance code (category
// of device). Per the Bluetooth SIG Appearance values document.
// We surface the raw code + a coarse-category name for the
// most common ranges.
func decodeAppearance(b []byte) map[string]any {
	if len(b) < 2 {
		return map[string]any{"error": "empty Appearance payload"}
	}
	v := binary.LittleEndian.Uint16(b[0:2])
	out := map[string]any{
		"raw": int(v),
		"hex": fmt.Sprintf("%04X", v),
	}
	if name, ok := appearanceCategories[v&0xFFC0]; ok {
		out["category"] = name
	}
	return out
}

// decodeManufacturerData parses a Manufacturer Specific Data
// record carrying a 16-bit company ID + opaque payload. The
// first 2 bytes are the company ID (little-endian on wire); the
// rest is vendor-specific. We render the company ID big-endian
// + name lookup; the payload is surfaced as hex so callers can
// dispatch to a dedicated decoder (DecodeContinuity for 0x004C,
// etc.).
func decodeManufacturerData(b []byte) map[string]any {
	if len(b) < 2 {
		return map[string]any{
			"error": fmt.Sprintf("Manufacturer Data payload %d bytes; want ≥2 (company ID)", len(b)),
		}
	}
	co := binary.LittleEndian.Uint16(b[0:2])
	out := map[string]any{
		"company_id":     fmt.Sprintf("%04X", co),
		"company_id_raw": int(co),
		"data_hex":       hexString(b[2:]),
	}
	if name, ok := companyIDs[co]; ok {
		out["company"] = name
	}
	return out
}
