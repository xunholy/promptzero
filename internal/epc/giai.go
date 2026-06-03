// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// GIAI-96 decoding (EPC header 0x34) — the Global Individual Asset Identifier,
// the GS1 key for a specific fixed asset (IT equipment, reusable containers,
// plant). Layout: header(8) filter(3) partition(3) companyPrefix(P)
// individualAssetReference(P). No extension, serial, or check digit — the
// asset reference is the remaining field. Verified against the epc-encoding-
// utils oracle: 3414257BF400000000003039 → giai-96:0.0614141.12345 and
// 3400393243F1640000000063 → giai-96:0.061414112345.99.

import "fmt"

// giaiPartition maps the partition value to company-prefix and
// individual-asset-reference field widths (GIAI-96, per epc-encoding-utils /
// GS1 EPC TDS).
var giaiPartition = map[int]struct {
	cpBits, cpDigits, refBits int
}{
	0: {40, 12, 42},
	1: {37, 11, 45},
	2: {34, 10, 48},
	3: {30, 9, 52},
	4: {27, 8, 55},
	5: {24, 7, 58},
	6: {20, 6, 62},
}

// GIAI is a decoded GIAI-96 EPC.
type GIAI struct {
	Filter          int    `json:"filter"`
	Partition       int    `json:"partition"`
	CompanyPrefix   string `json:"company_prefix"`
	AssetReference  uint64 `json:"asset_reference"`
	TagURI          string `json:"tag_uri"`
	PureIdentityURI string `json:"pure_identity_uri"`
}

func decodeGIAI96(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := giaiPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("GIAI-96 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	ref := readMSB(bits, off, pt.refBits)
	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	res.GIAI = &GIAI{
		Filter:          filter,
		Partition:       partition,
		CompanyPrefix:   cpStr,
		AssetReference:  ref,
		TagURI:          fmt.Sprintf("urn:epc:tag:giai-96:%d.%s.%d", filter, cpStr, ref),
		PureIdentityURI: fmt.Sprintf("urn:epc:id:giai:%s.%d", cpStr, ref),
	}
}
