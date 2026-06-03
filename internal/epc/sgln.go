// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// SGLN-96 decoding (EPC header 0x32) — the Serialized Global Location Number,
// the GS1 key for a physical location (a building, a shelf, a dock door).
// Layout: header(8) filter(3) partition(3) companyPrefix(P) locationReference(P)
// extension(41). Company prefix + location reference total 12 digits (the GLN
// without its check digit); the extension serialises a specific location.
// Verified against the epc-encoding-utils oracle:
// 3214257BF460720000000190 → sgln-96:0.0614141.12345.400 and
// 3214257BF460720000000000 → sgln-96:0.0614141.12345.0.

import "fmt"

// sglnPartition maps the partition value to company-prefix and
// location-reference field widths and digit counts (SGLN-96).
var sglnPartition = map[int]struct {
	cpBits, cpDigits, locBits, locDigits int
}{
	0: {40, 12, 1, 0},
	1: {37, 11, 4, 1},
	2: {34, 10, 7, 2},
	3: {30, 9, 11, 3},
	4: {27, 8, 14, 4},
	5: {24, 7, 17, 5},
	6: {20, 6, 21, 6},
}

// SGLN is a decoded SGLN-96 EPC.
type SGLN struct {
	Filter            int    `json:"filter"`
	Partition         int    `json:"partition"`
	CompanyPrefix     string `json:"company_prefix"`
	LocationReference string `json:"location_reference"`
	Extension         uint64 `json:"extension"`
	TagURI            string `json:"tag_uri"`
	PureIdentityURI   string `json:"pure_identity_uri"`
}

func decodeSGLN96(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := sglnPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("SGLN-96 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	loc := readMSB(bits, off, pt.locBits)
	off += pt.locBits
	ext := readMSB(bits, off, 41)

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	locStr := ""
	if pt.locDigits > 0 {
		locStr = fmt.Sprintf("%0*d", pt.locDigits, loc)
	}
	res.SGLN = &SGLN{
		Filter:            filter,
		Partition:         partition,
		CompanyPrefix:     cpStr,
		LocationReference: locStr,
		Extension:         ext,
		TagURI:            fmt.Sprintf("urn:epc:tag:sgln-96:%d.%s.%s.%d", filter, cpStr, locStr, ext),
		PureIdentityURI:   fmt.Sprintf("urn:epc:id:sgln:%s.%s.%d", cpStr, locStr, ext),
	}
}
