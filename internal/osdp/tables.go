// SPDX-License-Identifier: AGPL-3.0-or-later

package osdp

// Command (CP->PD) codes, OSDP / libosdp.
var commandNames = map[byte]string{
	0x60: "osdp_POLL", 0x61: "osdp_ID", 0x62: "osdp_CAP",
	0x64: "osdp_LSTAT", 0x65: "osdp_ISTAT", 0x66: "osdp_OSTAT",
	0x67: "osdp_RSTAT", 0x68: "osdp_OUT", 0x69: "osdp_LED",
	0x6A: "osdp_BUZ", 0x6B: "osdp_TEXT", 0x6C: "osdp_RMODE",
	0x6D: "osdp_TDSET", 0x6E: "osdp_COMSET", 0x73: "osdp_BIOREAD",
	0x74: "osdp_BIOMATCH", 0x75: "osdp_KEYSET", 0x76: "osdp_CHLNG",
	0x77: "osdp_SCRYPT", 0x7B: "osdp_ACURXSIZE", 0x7C: "osdp_FILETRANSFER",
	0x80: "osdp_MFG", 0xA1: "osdp_XWR", 0xA2: "osdp_ABORT",
	0xA3: "osdp_PIVDATA", 0xA4: "osdp_GENAUTH", 0xA5: "osdp_CRAUTH",
	0xA7: "osdp_KEEPACTIVE",
}

// Reply (PD->CP) codes, OSDP / libosdp.
var replyNames = map[byte]string{
	0x40: "osdp_ACK", 0x41: "osdp_NAK", 0x45: "osdp_PDID",
	0x46: "osdp_PDCAP", 0x48: "osdp_LSTATR", 0x49: "osdp_ISTATR",
	0x4A: "osdp_OSTATR", 0x4B: "osdp_RSTATR", 0x50: "osdp_RAW (card read)",
	0x51: "osdp_FMT", 0x53: "osdp_KEYPAD", 0x54: "osdp_COM",
	0x57: "osdp_BIOREADR", 0x58: "osdp_BIOMATCHR", 0x76: "osdp_CCRYPT",
	0x79: "osdp_BUSY", 0x7A: "osdp_FTSTAT", 0x80: "osdp_PIVDATAR",
	0x81: "osdp_GENAUTHR", 0x82: "osdp_CRAUTHR", 0x83: "osdp_MFGSTATR",
	0x84: "osdp_MFGERRR", 0x90: "osdp_MFGREP", 0xB1: "osdp_XRD",
}

// nakErrorNames maps the osdp_NAK error code to its meaning (OSDP spec /
// libosdp osdp_pd_nak_e).
var nakErrorNames = map[byte]string{
	0x00: "no error",
	0x01: "message check character(s) error (bad checksum/CRC)",
	0x02: "command length error",
	0x03: "unknown command code (not implemented by PD)",
	0x04: "sequence number error",
	0x05: "secure channel not supported by PD",
	0x06: "unsupported security block or security conditions not met",
	0x07: "BIO_TYPE not supported",
	0x08: "BIO_FORMAT not supported",
	0x09: "unable to process command record",
}

// scbTypeNames maps the security control block type to its meaning.
var scbTypeNames = map[byte]string{
	0x11: "SCS_11 (CP->PD CHLNG, secure-session start)",
	0x12: "SCS_12 (PD->CP CCRYPT)",
	0x13: "SCS_13 (CP->PD SCRYPT)",
	0x14: "SCS_14 (PD->CP R-MAC, session established)",
	0x15: "SCS_15 (CP->PD, MAC without encryption)",
	0x16: "SCS_16 (PD->CP, MAC without encryption)",
	0x17: "SCS_17 (CP->PD, MAC with encryption)",
	0x18: "SCS_18 (PD->CP, MAC with encryption)",
}

func commandName(c byte) string {
	if n, ok := commandNames[c]; ok {
		return n
	}
	return "unknown command"
}

func replyName(c byte) string {
	if n, ok := replyNames[c]; ok {
		return n
	}
	return "unknown reply"
}

func nakErrorName(c byte) string {
	if n, ok := nakErrorNames[c]; ok {
		return n
	}
	return "reserved / vendor-specific"
}

func scbTypeName(t byte) string {
	if n, ok := scbTypeNames[t]; ok {
		return n
	}
	return "unknown SCB type"
}
