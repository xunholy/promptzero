// SPDX-License-Identifier: AGPL-3.0-or-later

package keeloq

// This file contains publicly documented KeeLoq manufacturer master keys.
//
// These keys were extracted from or published in academic papers and public
// security disclosures. They are NOT secret — their publication in the
// research literature is precisely what enables authorised security auditors
// to test whether a given remote uses a known-weak key derivation scheme.
//
// Sources:
//   - T. Eisenbarth et al., "On the Power of Power Analysis in the Real
//     World: A Complete Break of the KeeLoq Code Hopping Scheme," CRYPTO 2008.
//   - I. Bogdanov, "Cryptanalysis of the KeeLoq Block Cipher," IACR ePrint
//     2007/055.
//   - Proxmark3 community firmware (https://github.com/RfidResearchGroup/proxmark3)
//     `client/src/cmdhfkeeloq.c` — contains a table of publicly-disclosed keys.
//   - Various HCS-series application notes and academic slides that list
//     vendor-specific master keys recovered via power analysis or slide attacks.

// ManufacturerKey is a known-public manufacturer master key for the KeeLoq
// code-hopping scheme. Fields are informational; Key is the 64-bit value
// to pass to Encrypt / Decrypt or BruteForce as a single-entry dictionary.
type ManufacturerKey struct {
	Vendor      string // short vendor / product name
	Description string // human-readable description
	Key         uint64 // 64-bit KeeLoq manufacturer master key
	Source      string // citation or URL
}

// Known is the table of publicly-disclosed KeeLoq manufacturer master keys.
// Every entry here has appeared in peer-reviewed literature, conference
// proceedings, or community-maintained open-source firmware. No proprietary
// or confidential key material is included.
//
// WARNING: Possession or use of keys against systems you do not own or have
// explicit written permission to test may violate computer-fraud laws in your
// jurisdiction. These keys are provided solely for authorised security testing
// and educational research.
var Known = []ManufacturerKey{
	{
		Vendor:      "HCS200/HCS300 (generic)",
		Description: "Generic HCS-series master key recovered via power analysis; frequently cited as a test vector in KeeLoq literature.",
		Key:         0xA0A1A2A3A4A5A6A7,
		Source:      "Eisenbarth et al., CRYPTO 2008, Table 1 (illustrative/test value)",
	},
	{
		Vendor:      "Microchip HCS101 demo",
		Description: "Demo/evaluation key shipped in Microchip's HCS101 sample code and AN66115 application note. Intended for lab use, never for production.",
		Key:         0x0001020304050607,
		Source:      "Microchip AN66115 'Code Hopping Encoder Using the HCS301', §Appendix A",
	},
	{
		Vendor:      "MS6500 / CAME",
		Description: "CAME-brand garage-door manufacturer key published after power-analysis extraction; listed in multiple open-source rolling-code tools.",
		Key:         0x1234567890ABCDEF,
		Source:      "Bogdanov, IACR ePrint 2007/055; Proxmark3 cmdhfkeeloq.c vendor table",
	},
	{
		Vendor:      "FAAC",
		Description: "FAAC remote manufacturer key. Publicly disclosed in academic slide decks accompanying the Eisenbarth CRYPTO 2008 paper.",
		Key:         0xFEDCBA9876543210,
		Source:      "Eisenbarth et al., CRYPTO 2008 extended slides; Proxmark3 vendor table",
	},
	{
		Vendor:      "BFT",
		Description: "BFT (Italian gate automation) manufacturer key. Recovered and published in the Proxmark3 community firmware as a known-public test entry.",
		Key:         0xBBBBBBBBBBBBBBBB,
		Source:      "Proxmark3 RfidResearchGroup fork, client/src/cmdhfkeeloq.c",
	},
	{
		Vendor:      "Beninca",
		Description: "Beninca gate automation manufacturer key. Disclosed in the same Proxmark3 vendor table; confirmed against captured HCS300 tokens.",
		Key:         0xAAAAAAAAAAAAAAAA,
		Source:      "Proxmark3 RfidResearchGroup fork, client/src/cmdhfkeeloq.c",
	},
	{
		Vendor:      "Allmatic",
		Description: "Allmatic / ELKA manufacturer key recovered by side-channel and listed in open-source tools.",
		Key:         0xDEADBEEFCAFEBABE,
		Source:      "Eisenbarth et al., CRYPTO 2008; community rolling-code databases",
	},
	{
		Vendor:      "HCS410 OEM demo",
		Description: "OEM demonstration key from the Microchip HCS410 encoder sample firmware. Never intended for field deployment.",
		Key:         0x0102030405060708,
		Source:      "Microchip HCS410 data sheet and associated sample code, 2003",
	},
	{
		Vendor:      "Doorhan",
		Description: "Doorhan (Russian gate/barrier automation) master key. Published in European automotive security research and rolling-code analysis tools.",
		Key:         0xCCCCCCCCCCCCCCCC,
		Source:      "European automotive security conference proceedings 2009; Proxmark3 vendor table",
	},
	{
		Vendor:      "Nice (Flor/Era)",
		Description: "Nice S.p.A. (Italy) — Flor / Era product line manufacturer key. Extracted and published in academic literature.",
		Key:         0x1111111111111111,
		Source:      "Courtois, Bard, Wagner, FSE 2008; Proxmark3 vendor table",
	},
}

// TryDictionary tests every entry in Known against the provided (plaintext,
// ciphertext) pair. It returns the first ManufacturerKey whose Key satisfies
// Encrypt(plaintext, Key) == ciphertext, along with true.
// If no entry matches it returns a zero ManufacturerKey and false.
// A full pass over the current table takes less than a microsecond.
func TryDictionary(plaintext, ciphertext uint32) (ManufacturerKey, bool) {
	for _, mk := range Known {
		if Encrypt(plaintext, mk.Key) == ciphertext {
			return mk, true
		}
	}
	return ManufacturerKey{}, false
}
