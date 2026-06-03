// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// GID-96 decoding (EPC header 0x35) — the General Identifier, the EPC scheme
// used when no GS1 key (GTIN / SSCC / GLN / …) applies. Unlike the GS1-keyed
// schemes it has no company prefix, no partition table, and no check digit:
// three fixed-width fields only.
//
// Layout (GS1 EPC TDS): header(8) generalManagerNumber(28) objectClass(24)
// serialNumber(36). Verified byte-for-byte against three worked vectors —
// 3500079FF00000B00000000C → gid-96:31231.11.12,
// 3500E82D900000F000000001 → gid-96:951001.15.1, and
// 350000A2600019003ADE56FA → gid-96:2598.400.987649786 — not recalled.

import "fmt"

// GID is a decoded GID-96 EPC (General Identifier).
type GID struct {
	GeneralManagerNumber uint64 `json:"general_manager_number"`
	ObjectClass          uint64 `json:"object_class"`
	SerialNumber         uint64 `json:"serial_number"`
	TagURI               string `json:"tag_uri"`
	PureIdentityURI      string `json:"pure_identity_uri"`
}

// decodeGID96 decodes the GID-96 fields from the EPC bit slice into the
// result. Called by Decode for header 0x35.
func decodeGID96(bits []int, res *Result) {
	manager := readMSB(bits, 8, 28)
	objectClass := readMSB(bits, 36, 24)
	serial := readMSB(bits, 60, 36)
	res.GID = &GID{
		GeneralManagerNumber: manager,
		ObjectClass:          objectClass,
		SerialNumber:         serial,
		TagURI:               fmt.Sprintf("urn:epc:tag:gid-96:%d.%d.%d", manager, objectClass, serial),
		PureIdentityURI:      fmt.Sprintf("urn:epc:id:gid:%d.%d.%d", manager, objectClass, serial),
	}
}
