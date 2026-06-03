// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// SSCC-96 decoding (EPC header 0x31) — the Serial Shipping Container Code, the
// GS1 identifier for a logistics unit (case / pallet / container). The
// second-most-common EPC scheme after SGTIN-96; where SGTIN identifies a retail
// item, SSCC identifies the shipping unit it travels in.
//
// Layout (GS1 EPC TDS): header(8) filter(3) partition(3) companyPrefix(P)
// serialReference(P) reserved(24, all zero). The serial-reference field's
// leading digit is the SSCC "extension digit". The SSCC-18 is reconstructed as
// extension + companyPrefix + serial-reference-remainder + a recomputed GS1
// mod-10 check digit (cpDigits + srDigits == 17 for every partition, + check
// = 18).
//
// The layout, the SSCC partition table, and the SSCC-18 reconstruction are
// verified byte-for-byte against the worked example 3134257BF4499602D2000000
// → urn:epc:tag:sscc-96:1.0614141.1234567890 (company prefix 0614141, serial
// reference 1234567890) — not recalled.

import "fmt"

// sscc96Partition maps the 3-bit partition value to the company-prefix and
// serial-reference field widths (GS1 EPC TDS SSCC partition table — distinct
// from the SGTIN table: the SSCC has no item reference, so the serial
// reference is wider).
var sscc96Partition = map[int]struct {
	cpBits, cpDigits, srBits, srDigits int
}{
	0: {40, 12, 18, 5},
	1: {37, 11, 21, 6},
	2: {34, 10, 24, 7},
	3: {30, 9, 28, 8},
	4: {27, 8, 31, 9},
	5: {24, 7, 34, 10},
	6: {20, 6, 38, 11},
}

// SSCC is a decoded SSCC-96 EPC (Serial Shipping Container Code).
type SSCC struct {
	Filter          int    `json:"filter"`
	Partition       int    `json:"partition"`
	CompanyPrefix   string `json:"company_prefix"`
	SerialReference string `json:"serial_reference"`
	SSCC18          string `json:"sscc18"`
	TagURI          string `json:"tag_uri"`
	PureIdentityURI string `json:"pure_identity_uri"`
}

// decodeSSCC96 decodes the SSCC-96 fields from the EPC bit slice into the
// result. Called by Decode for header 0x31.
func decodeSSCC96(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := sscc96Partition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("SSCC-96 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	sr := readMSB(bits, off, pt.srBits)
	off += pt.srBits
	if reserved := readMSB(bits, off, 24); reserved != 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("SSCC-96 reserved trailing bits are non-zero (0x%06X); spec requires all-zero", reserved))
	}

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	srStr := fmt.Sprintf("%0*d", pt.srDigits, sr)

	res.SSCC = &SSCC{
		Filter:          filter,
		Partition:       partition,
		CompanyPrefix:   cpStr,
		SerialReference: srStr,
		TagURI:          fmt.Sprintf("urn:epc:tag:sscc-96:%d.%s.%s", filter, cpStr, srStr),
		PureIdentityURI: fmt.Sprintf("urn:epc:id:sscc:%s.%s", cpStr, srStr),
		SSCC18:          ssccSSCC18(cpStr, srStr),
	}
}

// ssccSSCC18 reconstructs the 18-digit SSCC from the company prefix and the
// serial reference (whose leading digit is the extension digit), appending the
// recomputed GS1 mod-10 check digit.
func ssccSSCC18(companyPrefix, serialRef string) string {
	if len(serialRef) < 1 {
		return ""
	}
	extension := serialRef[:1]
	rest := serialRef[1:]
	base := extension + companyPrefix + rest // 17 digits for any SSCC partition
	if len(base) != 17 {
		return "" // defensive: should always be 17 for SSCC
	}
	return base + fmt.Sprintf("%d", gs1CheckDigit(base))
}
