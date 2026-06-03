// SPDX-License-Identifier: AGPL-3.0-or-later

// Package epc decodes GS1 Electronic Product Code (EPC) binary identifiers —
// the data on UHF RAIN RFID (EPC Gen2 / ISO 18000-63) tags used pervasively
// in retail item-level tagging and supply-chain logistics. It turns the
// 96-bit EPC read from a tag into the GS1 identifiers it encodes: the company
// prefix, item reference, serial number, the canonical EPC URIs, and the
// reconstructed GTIN-14.
//
// This is a whole RFID band the toolkit did not decode: PromptZero covers HF
// (ISO 14443 / 15693 / NDEF) and LF (EM4100 / HID / FDX-B / T5577), but not
// the UHF EPC layer. Reading a UHF tag needs a RAIN reader (out of scope —
// hardware), but the EPC binary an operator captures decodes entirely offline
// and deterministically here.
//
// Wrap-vs-native: native. The EPC binary is a fixed bit-field layout with a
// per-partition split table and a GS1 mod-10 check digit; no third-party
// dependency is warranted. The SGTIN-96 layout, the partition table, and the
// SGTIN→GTIN reconstruction are taken from the GS1 EPC Tag Data Standard and
// verified byte-for-byte against its canonical worked example —
// 3074257BF7194E4000001A85 → urn:epc:tag:sgtin-96:3.0614141.812345.6789
// (company prefix 0614141, item reference 812345, serial 6789) — not recalled.
//
// Covered: SGTIN-96 (header 0x30), the dominant retail item-level scheme, and
// SSCC-96 (header 0x31), the logistics-unit scheme — both fully decoded
// (filter, partition, company prefix, item/serial reference, and the
// reconstructed GTIN-14 / SSCC-18 with a recomputed mod-10 check digit), each
// verified against a worked vector. Deferred (no confidently-wrong output):
// the remaining 96-bit schemes (SGLN-96 0x32, GRAI-96 0x33, GIAI-96 0x34,
// GID-96 0x35) are identified by scheme name but not field-decoded — their
// layouts are not yet verified against worked vectors, so the raw bits are
// surfaced with a note rather than guessed; 198-bit and other variants are
// reported as unsupported.
package epc

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// scheme96Names maps the 8-bit EPC header to the 96-bit scheme name.
var scheme96Names = map[byte]string{
	0x30: "SGTIN-96",
	0x31: "SSCC-96",
	0x32: "SGLN-96",
	0x33: "GRAI-96",
	0x34: "GIAI-96",
	0x35: "GID-96",
}

// sgtinPartition maps the 3-bit partition value to the company-prefix and
// item-reference field widths (GS1 EPC TDS SGTIN partition table).
var sgtinPartition = map[int]struct {
	cpBits, cpDigits, irBits, irDigits int
}{
	0: {40, 12, 4, 1},
	1: {37, 11, 7, 2},
	2: {34, 10, 10, 3},
	3: {30, 9, 14, 4},
	4: {27, 8, 17, 5},
	5: {24, 7, 20, 6},
	6: {20, 6, 24, 7},
}

// SGTIN is a decoded SGTIN-96 EPC (Serialised Global Trade Item Number).
type SGTIN struct {
	Filter          int    `json:"filter"`
	Partition       int    `json:"partition"`
	CompanyPrefix   string `json:"company_prefix"`
	ItemReference   string `json:"item_reference"`
	SerialNumber    uint64 `json:"serial_number"`
	GTIN14          string `json:"gtin14"`
	TagURI          string `json:"tag_uri"`
	PureIdentityURI string `json:"pure_identity_uri"`
}

// Result is the decoded EPC.
type Result struct {
	Scheme       string   `json:"scheme"`
	SchemeHeader string   `json:"scheme_header"`
	SGTIN        *SGTIN   `json:"sgtin,omitempty"`
	SSCC         *SSCC    `json:"sscc,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// DecodeHex decodes a hex-encoded 96-bit EPC (24 hex digits; ':' / '-' / '_' /
// whitespace and an optional 0x / urn:epc:tag: prefix not required — just the
// hex). Separators are ignored.
func DecodeHex(s string) (*Result, error) {
	clean := strings.NewReplacer(":", "", "-", "", "_", "", " ", "", "\n", "", "\t", "").Replace(s)
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	if clean == "" {
		return nil, fmt.Errorf("epc: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("epc: invalid hex: %w", err)
	}
	return Decode(b)
}

// Decode decodes a 96-bit (12-byte) EPC binary.
func Decode(b []byte) (*Result, error) {
	if len(b) != 12 {
		return nil, fmt.Errorf("epc: a 96-bit EPC is 12 bytes (24 hex digits), got %d bytes", len(b))
	}
	bits := toBits(b)
	header := b[0]

	res := &Result{SchemeHeader: fmt.Sprintf("0x%02X", header)}
	name, known := scheme96Names[header]
	if !known {
		res.Scheme = "unsupported"
		res.Notes = append(res.Notes, fmt.Sprintf("EPC header 0x%02X is not a recognised 96-bit scheme (only 96-bit SGTIN/SSCC/SGLN/GRAI/GIAI/GID headers 0x30-0x35 are recognised); 198-bit and other variants are not decoded", header))
		return res, nil
	}
	res.Scheme = name

	switch header {
	case 0x30:
		// fall through to SGTIN-96 decode below
	case 0x31:
		decodeSSCC96(bits, res)
		return res, nil
	default: // recognised but not yet field-decoded
		res.Notes = append(res.Notes, fmt.Sprintf("%s recognised by header; full field decode is not yet implemented (only SGTIN-96 and SSCC-96 are decoded) — raw bits not interpreted to avoid a confidently-wrong result", name))
		return res, nil
	}

	// SGTIN-96: header(8) filter(3) partition(3) companyPrefix(P) itemRef(P) serial(38)
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := sgtinPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("SGTIN-96 partition value %d is reserved/invalid (valid 0-6)", partition))
		return res, nil
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	ir := readMSB(bits, off, pt.irBits)
	off += pt.irBits
	serial := readMSB(bits, off, 38)

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	irStr := fmt.Sprintf("%0*d", pt.irDigits, ir)

	s := &SGTIN{
		Filter:          filter,
		Partition:       partition,
		CompanyPrefix:   cpStr,
		ItemReference:   irStr,
		SerialNumber:    serial,
		TagURI:          fmt.Sprintf("urn:epc:tag:sgtin-96:%d.%s.%s.%d", filter, cpStr, irStr, serial),
		PureIdentityURI: fmt.Sprintf("urn:epc:id:sgtin:%s.%s.%d", cpStr, irStr, serial),
		GTIN14:          sgtinGTIN14(cpStr, irStr),
	}
	res.SGTIN = s
	return res, nil
}

// sgtinGTIN14 reconstructs the GTIN-14 from the SGTIN company prefix and the
// item reference (whose leading digit is the GTIN indicator), appending the
// recomputed GS1 mod-10 check digit (GS1 EPC TDS SGTIN→GTIN decoding).
func sgtinGTIN14(companyPrefix, itemRef string) string {
	if len(itemRef) < 1 {
		return ""
	}
	indicator := itemRef[:1]
	rest := itemRef[1:]
	base := indicator + companyPrefix + rest // 13 digits for any SGTIN partition
	if len(base) != 13 {
		return "" // defensive: should always be 13 for SGTIN
	}
	return base + fmt.Sprintf("%d", gs1CheckDigit(base))
}

// gs1CheckDigit computes the GS1 mod-10 check digit over the given digit
// string (rightmost digit weighted 3, alternating).
func gs1CheckDigit(d string) int {
	sum := 0
	for i := 0; i < len(d); i++ {
		n := int(d[i] - '0')
		if (len(d)-i)%2 == 1 { // odd position counting from the right -> weight 3
			sum += n * 3
		} else {
			sum += n
		}
	}
	return (10 - (sum % 10)) % 10
}

func toBits(b []byte) []int {
	out := make([]int, len(b)*8)
	for i, x := range b {
		for j := 0; j < 8; j++ {
			out[i*8+j] = int((x >> uint(7-j)) & 1)
		}
	}
	return out
}

func readMSB(bits []int, off, n int) uint64 {
	var v uint64
	for i := 0; i < n && off+i < len(bits); i++ {
		v = (v << 1) | uint64(bits[off+i])
	}
	return v
}
