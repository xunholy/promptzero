// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// GRAI-96 decoding (EPC header 0x33) — the Global Returnable Asset Identifier,
// the GS1 key for a specific returnable asset (a reusable shipping container, a
// pallet skid). Layout: header(8) filter(3) partition(3) companyPrefix(P)
// assetType(P) serial(38). Company prefix + asset type total 12 digits; the
// serial number distinguishes individual assets of that type. Verified against
// the epc-encoding-utils oracle:
// 3314257BF40C0E400000162E → grai-96:0.0614141.12345.5678.

import "fmt"

// graiPartition maps the partition value to company-prefix and asset-type field
// widths and digit counts (GRAI-96).
var graiPartition = map[int]struct {
	cpBits, cpDigits, atBits, atDigits int
}{
	0: {40, 12, 4, 0},
	1: {37, 11, 7, 1},
	2: {34, 10, 10, 2},
	3: {30, 9, 14, 3},
	4: {27, 8, 17, 4},
	5: {24, 7, 20, 5},
	6: {20, 6, 24, 6},
}

// GRAI is a decoded GRAI-96 EPC.
type GRAI struct {
	Filter          int    `json:"filter"`
	Partition       int    `json:"partition"`
	CompanyPrefix   string `json:"company_prefix"`
	AssetType       string `json:"asset_type"`
	SerialNumber    uint64 `json:"serial_number"`
	TagURI          string `json:"tag_uri"`
	PureIdentityURI string `json:"pure_identity_uri"`
}

func decodeGRAI96(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := graiPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("GRAI-96 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	at := readMSB(bits, off, pt.atBits)
	off += pt.atBits
	serial := readMSB(bits, off, 38)

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	atStr := ""
	if pt.atDigits > 0 {
		atStr = fmt.Sprintf("%0*d", pt.atDigits, at)
	}
	res.GRAI = &GRAI{
		Filter:          filter,
		Partition:       partition,
		CompanyPrefix:   cpStr,
		AssetType:       atStr,
		SerialNumber:    serial,
		TagURI:          fmt.Sprintf("urn:epc:tag:grai-96:%d.%s.%s.%d", filter, cpStr, atStr, serial),
		PureIdentityURI: fmt.Sprintf("urn:epc:id:grai:%s.%s.%d", cpStr, atStr, serial),
	}
}
