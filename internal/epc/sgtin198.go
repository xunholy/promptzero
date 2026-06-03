// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

// SGTIN-198 decoding (EPC header 0x36) — the 198-bit form of the Serialised
// Global Trade Item Number, identical to SGTIN-96 except the serial is a
// variable-length **alphanumeric** string (up to 20 characters) rather than a
// numeric value. Used where the GS1 serial is not purely numeric (e.g.
// pharmaceutical serialisation). Layout: header(8) filter(3) partition(3)
// companyPrefix(P) itemReference(P) serial(140 bits = twenty 7-bit ISO-646
// characters, null-padded).
//
// A RAIN reader emits the 198-bit EPC word-aligned to 208 bits (26 bytes /
// 52 hex; the trailing bits are zero padding), so the decoder accepts 25 or
// 26 bytes and reads the meaningful 198 bits. The company prefix, item
// reference and GTIN-14 reconstruction are shared with SGTIN-96; only the
// serial differs. Verified against the epc-encoding-utils oracle:
// 3614257BF7194E60C286C5933… → sgtin-198:0.0614141.812345.ABC123 and
// …6C59B4B5C8… → sgtin-198:0.0614141.812345.XYZ-9.

import (
	"fmt"
	"strings"
)

func decode198(b []byte) (*Result, error) {
	header := b[0]
	res := &Result{SchemeHeader: fmt.Sprintf("0x%02X", header)}
	if header != 0x36 {
		res.Scheme = "unsupported"
		res.Notes = append(res.Notes, fmt.Sprintf("EPC header 0x%02X is not a supported 198-bit scheme (only SGTIN-198 0x36 is decoded; GRAI-170 / GIAI-202 / SGLN-195 are not)", header))
		return res, nil
	}
	res.Scheme = "SGTIN-198"

	bits := toBits(b)
	filter := int(readMSB(bits, 8, 3))
	partition := int(readMSB(bits, 11, 3))
	pt, ok := sgtinPartition[partition]
	if !ok {
		res.Notes = append(res.Notes, fmt.Sprintf("SGTIN-198 partition value %d is reserved/invalid (valid 0-6)", partition))
		return res, nil
	}
	off := 14
	cp := readMSB(bits, off, pt.cpBits)
	off += pt.cpBits
	ir := readMSB(bits, off, pt.irBits)
	off += pt.irBits

	cpStr := fmt.Sprintf("%0*d", pt.cpDigits, cp)
	irStr := fmt.Sprintf("%0*d", pt.irDigits, ir)
	serial := decodeSerial7(bits, off)

	res.SGTIN = &SGTIN{
		TagSize:         198,
		Filter:          filter,
		Partition:       partition,
		CompanyPrefix:   cpStr,
		ItemReference:   irStr,
		SerialString:    serial,
		TagURI:          fmt.Sprintf("urn:epc:tag:sgtin-198:%d.%s.%s.%s", filter, cpStr, irStr, serial),
		PureIdentityURI: fmt.Sprintf("urn:epc:id:sgtin:%s.%s.%s", cpStr, irStr, serial),
		GTIN14:          sgtinGTIN14(cpStr, irStr),
	}
	return res, nil
}

// decodeSerial7 reads the 198-bit SGTIN serial: up to twenty 7-bit ISO-646
// characters starting at off, terminated by a null (0x00) or the field end.
func decodeSerial7(bits []int, off int) string {
	var sb strings.Builder
	for i := 0; i < 20 && off+(i+1)*7 <= len(bits); i++ {
		c := byte(readMSB(bits, off+i*7, 7))
		if c == 0 {
			break
		}
		sb.WriteByte(c)
	}
	return sb.String()
}
