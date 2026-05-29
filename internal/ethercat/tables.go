// SPDX-License-Identifier: AGPL-3.0-or-later

package ethercat

// headerTypeName maps the 4-bit EtherCAT header Type field to its name
// (ETG.1000-4). Type 1 (command) is by far the most common on the wire.
func headerTypeName(t int) string {
	switch t {
	case 1:
		return "EtherCAT commands (DLPDU)"
	case 4:
		return "Network variables"
	case 5:
		return "Mailbox"
	default:
		return "reserved"
	}
}

// commandNames maps the datagram Command byte to its mnemonic + meaning
// (ETG.1000-3 §5.4). The prefixes encode the addressing mode: A* =
// auto-increment (position) addressing, F* = configured-address
// (fixed) addressing, B* = broadcast, L* = logical addressing.
var commandNames = map[int]string{
	0:  "NOP (no operation)",
	1:  "APRD (auto-increment read)",
	2:  "APWR (auto-increment write)",
	3:  "APRW (auto-increment read/write)",
	4:  "FPRD (configured-address read)",
	5:  "FPWR (configured-address write)",
	6:  "FPRW (configured-address read/write)",
	7:  "BRD (broadcast read)",
	8:  "BWR (broadcast write)",
	9:  "BRW (broadcast read/write)",
	10: "LRD (logical read)",
	11: "LWR (logical write)",
	12: "LRW (logical read/write)",
	13: "ARMW (auto-increment read, multiple write)",
	14: "FRMW (configured-address read, multiple write)",
}

func commandName(c int) string {
	if n, ok := commandNames[c]; ok {
		return n
	}
	return "unknown / reserved"
}
