// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// Extended (>96-bit) EPC schemes — the variants whose serial / asset reference
// is a 7-bit-ISO-646 **alphanumeric** string rather than a numeric field, so
// they need more than 96 bits. All share the header(8) filter(3) partition(3)
// prefix and the per-scheme company-prefix partition split of their 96-bit
// sibling (graiPartition / giaiPartition / sglnPartition / sgtinPartition);
// only the trailing alphanumeric field differs. Layouts and headers are from
// the GS1 EPC Tag Data Standard and verified byte-for-byte against the epc-tds
// library used as an oracle:
//
//	GRAI-170 (0x37): …companyPrefix(P) assetType(P) serial(112b = 16 chars)
//	  3774F4E4E40010E9E5E5A70EC46E4… → grai-170:3.4012345.00067.Serial#9
//	GIAI-202 (0x38): …companyPrefix(P) individualAssetReference(rest, alnum)
//	  381A57BF6C59B4DDC390…         → giai-202:0.614141.XYZ789
//	SGLN-195 (0x39): …companyPrefix(P) locationReference(P) extension(140b = 20 chars)
//	  394DFC24F0F055937EFE4B9B8…    → sgln-195:2.532827919.042.door.7
//
// GDTI-174 (0x3E) and any other extended header are reported unsupported (with
// a note) rather than guessed — no confidently-wrong output.

import "fmt"

// extendedMinBits is the minimum bit length each decoded extended scheme
// requires; a shorter input is truncated and reported rather than silently
// zero-extended into a wrong asset reference.
var extendedMinBits = map[byte]int{0x36: 198, 0x37: 170, 0x38: 202, 0x39: 195}

// decodeExtended decodes an extended (>96-bit) EPC, dispatching on the header
// byte. b is the word-aligned tag word (22, 25 or 26 bytes); the meaningful
// bits are read per scheme and the trailing word padding is ignored.
func decodeExtended(b []byte) (*Result, error) {
	header := b[0]
	res := &Result{SchemeHeader: fmt.Sprintf("0x%02X", header)}
	bits := toBits(b)

	if mb, ok := extendedMinBits[header]; ok && len(bits) < mb {
		res.Scheme = "unsupported"
		res.Notes = append(res.Notes, fmt.Sprintf("EPC header 0x%02X needs at least %d bits but only %d were supplied (truncated tag)", header, mb, len(bits)))
		return res, nil
	}

	switch header {
	case 0x36:
		res.Scheme = "SGTIN-198"
		decodeSGTIN198(bits, res)
	case 0x37:
		res.Scheme = "GRAI-170"
		decodeGRAI170(bits, res)
	case 0x38:
		res.Scheme = "GIAI-202"
		decodeGIAI202(bits, res)
	case 0x39:
		res.Scheme = "SGLN-195"
		decodeSGLN195(bits, res)
	default:
		res.Scheme = "unsupported"
		res.Notes = append(res.Notes, fmt.Sprintf("EPC header 0x%02X is not a supported extended (>96-bit) scheme — SGTIN-198 (0x36), GRAI-170 (0x37), GIAI-202 (0x38) and SGLN-195 (0x39) are decoded; GDTI-174 (0x3E) and others are not", header))
	}
	return res, nil
}

// decodeGRAI170 decodes GRAI-170 (header 0x37): the GRAI-96 company-prefix +
// asset-type split (graiPartition), then a 112-bit (16-char) alphanumeric
// serial in place of the 38-bit numeric one. The asset-type rendering (empty
// when the partition has zero asset-type digits) mirrors GRAI-96.
func decodeGRAI170(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := graiPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("GRAI-170 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	at := readMSB(bits, off, pt.atBits)
	off += pt.atBits
	serial := decodeSerial7(bits, off, 16) // 112-bit serial field = up to 16 chars

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	atStr := ""
	if pt.atDigits > 0 {
		atStr = fmt.Sprintf("%0*d", pt.atDigits, at)
	}
	res.GRAI = &GRAI{
		TagSize:         170,
		Filter:          filter,
		Partition:       partition,
		CompanyPrefix:   cpStr,
		AssetType:       atStr,
		SerialString:    serial,
		TagURI:          fmt.Sprintf("urn:epc:tag:grai-170:%d.%s.%s.%s", filter, cpStr, atStr, serial),
		PureIdentityURI: fmt.Sprintf("urn:epc:id:grai:%s.%s.%s", cpStr, atStr, serial),
	}
}

// decodeGIAI202 decodes GIAI-202 (header 0x38): the GIAI-96 company prefix
// (giaiPartition), then the individual asset reference as the alphanumeric
// remainder of the 202-bit tag — a variable field whose width (202 − 14 −
// companyPrefixBits) depends on the partition, unlike the numeric GIAI-96 ref.
func decodeGIAI202(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := giaiPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("GIAI-202 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14 + pt.cpBits
	cp := readMSB(bits, 14, pt.cpBits)
	ref := decodeSerial7(bits, off, (202-off)/7) // alphanumeric asset reference fills the rest

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	res.GIAI = &GIAI{
		TagSize:              202,
		Filter:               filter,
		Partition:            partition,
		CompanyPrefix:        cpStr,
		AssetReferenceString: ref,
		TagURI:               fmt.Sprintf("urn:epc:tag:giai-202:%d.%s.%s", filter, cpStr, ref),
		PureIdentityURI:      fmt.Sprintf("urn:epc:id:giai:%s.%s", cpStr, ref),
	}
}

// decodeSGLN195 decodes SGLN-195 (header 0x39): the SGLN-96 company-prefix +
// location-reference split (sglnPartition), then a 140-bit (20-char)
// alphanumeric extension in place of the 41-bit numeric one. The
// location-reference rendering mirrors SGLN-96.
func decodeSGLN195(bits []int, res *Result) {
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := sglnPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("SGLN-195 partition value %d is reserved/invalid (valid 0-6)", partition))
		return
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	loc := readMSB(bits, off, pt.locBits)
	off += pt.locBits
	ext := decodeSerial7(bits, off, 20) // 140-bit extension field = up to 20 chars

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	locStr := ""
	if pt.locDigits > 0 {
		locStr = fmt.Sprintf("%0*d", pt.locDigits, loc)
	}
	res.SGLN = &SGLN{
		TagSize:           195,
		Filter:            filter,
		Partition:         partition,
		CompanyPrefix:     cpStr,
		LocationReference: locStr,
		ExtensionString:   ext,
		TagURI:            fmt.Sprintf("urn:epc:tag:sgln-195:%d.%s.%s.%s", filter, cpStr, locStr, ext),
		PureIdentityURI:   fmt.Sprintf("urn:epc:id:sgln:%s.%s.%s", cpStr, locStr, ext),
	}
}
