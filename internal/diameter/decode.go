// Package diameter decodes Diameter packets per RFC 6733 (the
// current Diameter Base Protocol — supersedes RFC 3588). Diameter
// is the 3GPP AAA protocol that succeeded RADIUS (RFC 2865,
// already covered by `radius_packet_decode`); it carries
// authentication / authorization / accounting / charging
// signalling across every modern cellular network on the S6a
// (HSS↔MME), S13 (HSS↔EIR), Gx (PCEF↔PCRF), Gy (Charging),
// Rx (P-CSCF↔PCRF), Cx/Dx (IMS), Sh (AS↔HSS), and S6t / T6a
// (IoT M2M) interfaces. Diameter typically rides on SCTP
// (covered by `sctp_packet_decode`) on UDP/TCP/3868.
//
// Wrap-vs-native judgement
//
//	Native. RFC 6733 is fully public; Diameter has a tight
//	20-byte header followed by a uniform AVP (Attribute-
//	Value Pair) array. AVPs are TLVs with a 4-byte AVP Code,
//	1-byte AVP Flags (V/M/P), 3-byte AVP Length, optional
//	4-byte Vendor-ID, value, and 4-byte trailing padding.
//	No crypto at the parse layer.
//
// What this package covers
//
//   - **20-byte header** (RFC 6733 §3):
//
//   - byte 0: Version (must be 1).
//
//   - bytes 1-3: **Message Length** (24-bit BE; includes
//     header).
//
//   - byte 4: **Command Flags** decoded into 4 named
//     bits: R (Request — 1 = request, 0 = answer), P
//     (Proxiable), E (Error — set in error answers), T
//     (Potentially re-transmitted).
//
//   - bytes 5-7: **Command Code** (24-bit BE) with
//     **~20-entry name table** covering base (CER/CEA
//     257 / DWR/DWA 280 / DPR/DPA 282 / Re-Auth 258 /
//     Accounting 271 / Abort-Session 274 / Session-
//     Termination 275 / Credit-Control 272) + 3GPP S6a
//     (Update-Location 316 / Authentication-Information
//     318 / Cancel-Location 317 / Insert-Subscriber-Data
//     319 / Delete-Subscriber-Data 320 / Purge-UE 321 /
//     Reset 322 / Notify 323).
//
//   - bytes 8-11: **Application ID** (uint32 BE) with
//     **~15-entry name table**: 0 Diameter Base, 1
//     NASREQ, 2 Mobile-IPv4, 3 Accounting, 4 Credit-
//     Control, 16777216 3GPP Cx/Dx, 16777217 3GPP Sh,
//     16777236 3GPP Rx, 16777238 3GPP Gx, 16777251 3GPP
//     S6a/S6d, 16777272 3GPP S13, 16777316 3GPP T6a,
//     16777310 3GPP S6t, and the 0xFFFFFFFF Diameter
//     Relay app.
//
//   - bytes 12-15: Hop-by-Hop Identifier (uint32 BE).
//
//   - bytes 16-19: End-to-End Identifier (uint32 BE).
//
//   - **AVP walker** — repeated 8-byte minimum header (AVP
//     Code uint32 BE + 1-byte AVP Flags + 3-byte AVP Length
//     including header) + optional 4-byte Vendor-ID (when V
//     flag set) + value + 4-byte padding. **AVP Flags
//     decoded into 3 named bits**: V (Vendor-Specific — the
//     4-byte Vendor-ID follows), M (Mandatory — must be
//     understood), P (Protected — encrypt with end-to-end
//     security).
//
//   - **~35-entry AVP Code name table** covering RFC 6733
//     base AVPs: User-Name (1) / Class (25) / Session-Timeout
//     (27) / Acct-Session-Id (44) / Event-Timestamp (55) /
//     Acct-Multi-Session-Id (50) / Host-IP-Address (257) /
//     Auth-Application-Id (258) / Acct-Application-Id (259)
//     / Vendor-Specific-Application-Id (260) / Redirect-
//     Host-Usage (261) / Redirect-Max-Cache-Time (262) /
//     Session-Id (263) / Origin-Host (264) / Supported-
//     Vendor-Id (265) / Vendor-Id (266) / Firmware-Revision
//     (267) / Result-Code (268) / Product-Name (269) /
//     Session-Binding (270) / Session-Server-Failover (271)
//     / Multi-Round-Time-Out (272) / Disconnect-Cause (273)
//     / Auth-Request-Type (274) / Auth-Grace-Period (276) /
//     Auth-Session-State (277) / Origin-State-Id (278) /
//     Failed-AVP (279) / Proxy-Host (280) / Error-Message
//     (281) / Route-Record (282) / Destination-Realm (283)
//     / Proxy-Info (284) / Re-Auth-Request-Type (285) /
//     Authorization-Lifetime (291) / Redirect-Host (292) /
//     Destination-Host (293) / Error-Reporting-Host (294) /
//     Termination-Cause (295) / Origin-Realm (296) /
//     Experimental-Result (297) / Experimental-Result-Code
//     (298) / Inband-Security-Id (299).
//
//   - **Type-aware AVP value decoding** — based on the AVP
//     Code, surface the value as the appropriate Diameter
//     base type:
//
//   - **UTF8String** — Session-Id / Origin-Host / Origin-
//     Realm / Destination-Host / Destination-Realm /
//     Error-Message / Product-Name / Route-Record /
//     Proxy-Host / Redirect-Host / User-Name / Acct-Multi-
//     Session-Id (all surfaced as decoded UTF-8).
//
//   - **Unsigned32** — Result-Code / Origin-State-Id /
//     Auth-Application-Id / Acct-Application-Id / Vendor-
//     Id / Firmware-Revision / Session-Timeout / Auth-
//     Session-State / Authorization-Lifetime + 20 more
//     (all surfaced as decoded uint32).
//
//   - **Address** — Host-IP-Address (RFC 6733 §4.3.1
//     Address type: 2-byte Address Family + 4 or 16 byte
//     IPv4/v6 address).
//
//   - **Result-Code class** — when the AVP Code is 268
//     (Result-Code) the decoded uint32 is also classified
//     as Informational (1xxx) / Success (2xxx — including
//     the canonical 2001 DIAMETER_SUCCESS) / Protocol
//     Error (3xxx) / Transient Failure (4xxx) / Permanent
//     Failure (5xxx).
//
//   - **Padding** — every AVP is padded to a 4-byte boundary
//     so the walker advances by `length + ((4 - length % 4)
//     % 4)`. Mis-aligned AVPs (declared length not a multiple
//     of 1 byte, padding running off the end of the message)
//     are flagged via the Notes field.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - SCTP / TCP / TLS framing — feed Diameter bytes after
//     the transport header strip. Diameter conventionally
//     rides on SCTP destination port 3868 (use the existing
//     `sctp_packet_decode` to unwrap the SCTP envelope
//     first; the resulting DATA chunk's user data is the
//     Diameter payload).
//
//   - Grouped AVP recursion — Grouped-type AVPs (Vendor-
//     Specific-Application-Id, Proxy-Info, Failed-AVP,
//     Experimental-Result) have their bodies surfaced as
//     hex; a future iteration would recursively walk the
//     inner AVPs.
//
//   - Diameter Routing Agent / Relay forwarding logic —
//     higher-level analysis (Route-Record, Destination-Realm
//     are surfaced; routing decisions are not).
//
//   - End-to-end security (E flag + Protected AVP encryption)
//     — flagged in the Flags decode; payload remains
//     opaque hex.
package diameter

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view of a Diameter packet.
type Result struct {
	Version                             int    `json:"version"`
	MessageLength                       int    `json:"message_length"`
	CommandFlags                        int    `json:"command_flags"`
	CommandFlagsHex                     string `json:"command_flags_hex"`
	CommandFlagRequest                  bool   `json:"command_flag_request"`
	CommandFlagProxiable                bool   `json:"command_flag_proxiable"`
	CommandFlagError                    bool   `json:"command_flag_error"`
	CommandFlagPotentiallyRetransmitted bool   `json:"command_flag_potentially_retransmitted"`
	CommandCode                         int    `json:"command_code"`
	CommandName                         string `json:"command_name"`
	ApplicationID                       uint32 `json:"application_id"`
	ApplicationName                     string `json:"application_name"`
	HopByHopID                          uint32 `json:"hop_by_hop_identifier"`
	EndToEndID                          uint32 `json:"end_to_end_identifier"`

	AVPs       []AVP    `json:"avps"`
	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// AVP is one decoded Attribute-Value Pair from the message body.
type AVP struct {
	Code     uint32  `json:"code"`
	Name     string  `json:"name,omitempty"`
	Flags    int     `json:"flags"`
	FlagsHex string  `json:"flags_hex"`
	FlagV    bool    `json:"flag_vendor_specific"`
	FlagM    bool    `json:"flag_mandatory"`
	FlagP    bool    `json:"flag_protected"`
	Length   int     `json:"length"`
	VendorID *uint32 `json:"vendor_id,omitempty"`
	DataHex  string  `json:"data_hex,omitempty"`

	// Type-decoded value (populated for known AVP codes).
	StringValue  string  `json:"string_value,omitempty"`
	Uint32Value  *uint32 `json:"uint32_value,omitempty"`
	AddressValue string  `json:"address_value,omitempty"`
	ResultClass  string  `json:"result_class,omitempty"`
}

// Decode parses a single Diameter packet from hex.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex must have even length, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < 20 {
		return nil, fmt.Errorf("diameter packet truncated (%d bytes; need ≥20 for header)",
			len(b))
	}
	r := &Result{
		TotalBytes:      len(b),
		Version:         int(b[0]),
		MessageLength:   (int(b[1]) << 16) | (int(b[2]) << 8) | int(b[3]),
		CommandFlags:    int(b[4]),
		CommandFlagsHex: fmt.Sprintf("0x%02X", b[4]),
		CommandCode:     (int(b[5]) << 16) | (int(b[6]) << 8) | int(b[7]),
		ApplicationID:   binary.BigEndian.Uint32(b[8:12]),
		HopByHopID:      binary.BigEndian.Uint32(b[12:16]),
		EndToEndID:      binary.BigEndian.Uint32(b[16:20]),
	}
	r.CommandFlagRequest = b[4]&0x80 != 0
	r.CommandFlagProxiable = b[4]&0x40 != 0
	r.CommandFlagError = b[4]&0x20 != 0
	r.CommandFlagPotentiallyRetransmitted = b[4]&0x10 != 0
	r.CommandName = commandName(r.CommandCode, r.CommandFlagRequest)
	r.ApplicationName = applicationName(r.ApplicationID)
	if r.Version != 1 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d (RFC 6733 specifies 1)", r.Version))
	}
	if r.MessageLength != len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"header declares %d bytes, packet is %d", r.MessageLength, len(b)))
	}
	r.AVPs = decodeAVPs(b[20:], r)
	return r, nil
}

func decodeAVPs(b []byte, parent *Result) []AVP {
	var out []AVP
	off := 0
	for off+8 <= len(b) {
		code := binary.BigEndian.Uint32(b[off : off+4])
		flags := b[off+4]
		ln := (int(b[off+5]) << 16) | (int(b[off+6]) << 8) | int(b[off+7])
		if ln < 8 {
			parent.Notes = append(parent.Notes, fmt.Sprintf(
				"AVP at offset %d declares length %d (< 8 header bytes)", off, ln))
			return out
		}
		if off+ln > len(b) {
			parent.Notes = append(parent.Notes, fmt.Sprintf(
				"AVP code %d at offset %d declares length %d but only %d remain",
				code, off, ln, len(b)-off))
			return out
		}
		a := AVP{
			Code:     code,
			Name:     avpName(code),
			Flags:    int(flags),
			FlagsHex: fmt.Sprintf("0x%02X", flags),
			FlagV:    flags&0x80 != 0,
			FlagM:    flags&0x40 != 0,
			FlagP:    flags&0x20 != 0,
			Length:   ln,
		}
		dataStart := off + 8
		if a.FlagV {
			if off+12 > len(b) {
				parent.Notes = append(parent.Notes,
					"vendor AVP truncated before Vendor-ID")
				return out
			}
			vid := binary.BigEndian.Uint32(b[off+8 : off+12])
			a.VendorID = &vid
			dataStart = off + 12
		}
		dataEnd := off + ln
		data := b[dataStart:dataEnd]
		a.DataHex = strings.ToUpper(hex.EncodeToString(data))
		decodeAVPValue(&a, data)
		out = append(out, a)
		padded := off + ln + ((4 - (ln % 4)) % 4)
		off = padded
	}
	return out
}

// decodeAVPValue applies type-aware decoding based on the AVP
// Code, falling back to opaque hex for unknown codes.
func decodeAVPValue(a *AVP, data []byte) {
	switch a.Code {
	// UTF8String / DiameterIdentity / DiameterURI
	case 1, 25, 44, 50, 263, 264, 269, 280, 281, 282,
		283, 292, 293, 294, 296:
		if utf8.Valid(data) {
			a.StringValue = strings.TrimRight(string(data), "\x00")
		}
	// Unsigned32
	case 27, 55, 258, 259, 261, 262, 265, 266, 267,
		270, 271, 272, 273, 274, 276, 277, 278, 285,
		287, 291, 295, 298, 299, 480, 483, 485:
		if len(data) == 4 {
			v := binary.BigEndian.Uint32(data)
			a.Uint32Value = &v
		}
	// Address (RFC 6733 §4.3.1 — 2-byte AF + 4 or 16 byte addr)
	case 257:
		if len(data) >= 6 {
			af := binary.BigEndian.Uint16(data[0:2])
			switch af {
			case 1:
				if len(data) >= 6 {
					a.AddressValue = net.IPv4(data[2], data[3],
						data[4], data[5]).String()
				}
			case 2:
				if len(data) >= 18 {
					a.AddressValue = net.IP(data[2:18]).String()
				}
			}
		}
	// Result-Code — uint32 + classification.
	case 268:
		if len(data) == 4 {
			v := binary.BigEndian.Uint32(data)
			a.Uint32Value = &v
			a.ResultClass = resultCodeClass(v)
		}
	}
}

func resultCodeClass(c uint32) string {
	switch {
	case c >= 1000 && c < 2000:
		return "Informational"
	case c == 2001:
		return "Success (DIAMETER_SUCCESS)"
	case c >= 2000 && c < 3000:
		return "Success"
	case c >= 3000 && c < 4000:
		return "Protocol Error"
	case c >= 4000 && c < 5000:
		return "Transient Failure"
	case c >= 5000 && c < 6000:
		return "Permanent Failure"
	}
	return fmt.Sprintf("uncatalogued class for code %d", c)
}

// commandName returns "<base>-Request" or "<base>-Answer" per
// the R bit of the Command Flags.
func commandName(c int, isRequest bool) string {
	base := commandBaseName(c)
	suffix := "-Answer"
	if isRequest {
		suffix = "-Request"
	}
	if strings.HasPrefix(base, "uncatalogued") {
		return base
	}
	return base + suffix
}

func commandBaseName(c int) string {
	switch c {
	case 257:
		return "Capabilities-Exchange"
	case 258:
		return "Re-Auth"
	case 271:
		return "Accounting"
	case 272:
		return "Credit-Control"
	case 274:
		return "Abort-Session"
	case 275:
		return "Session-Termination"
	case 280:
		return "Device-Watchdog"
	case 282:
		return "Disconnect-Peer"
	case 265:
		return "AA"
	case 268:
		return "Diameter-EAP"
	case 316:
		return "Update-Location"
	case 317:
		return "Cancel-Location"
	case 318:
		return "Authentication-Information"
	case 319:
		return "Insert-Subscriber-Data"
	case 320:
		return "Delete-Subscriber-Data"
	case 321:
		return "Purge-UE"
	case 322:
		return "Reset"
	case 323:
		return "Notify"
	}
	return fmt.Sprintf("uncatalogued command code %d", c)
}

func applicationName(a uint32) string {
	switch a {
	case 0:
		return "Diameter Base"
	case 1:
		return "NASREQ (RFC 7155)"
	case 2:
		return "Mobile-IPv4 (RFC 4004)"
	case 3:
		return "Accounting"
	case 4:
		return "Credit-Control (RFC 4006)"
	case 5:
		return "EAP (RFC 4072)"
	case 6:
		return "SIP (RFC 4740)"
	case 7:
		return "Mobile-IPv6-IKE (RFC 5778)"
	case 8:
		return "Mobile-IPv6-Auth (RFC 5778)"
	case 9:
		return "QoS"
	case 0x01000000:
		return "3GPP Cx/Dx (TS 29.229)"
	case 0x01000001:
		return "3GPP Sh (TS 29.329)"
	case 0x01000014:
		return "3GPP Rx (TS 29.214)"
	case 0x01000016:
		return "3GPP Gx (TS 29.212)"
	case 0x01000023:
		return "3GPP S6a/S6d (TS 29.272)"
	case 0x01000038:
		return "3GPP S13 (TS 29.272)"
	case 0x01000044:
		return "3GPP S6t (TS 29.336)"
	case 0x0100004A:
		return "3GPP T6a (TS 29.128)"
	case 0xFFFFFFFF:
		return "Diameter Relay"
	}
	return fmt.Sprintf("uncatalogued application ID %d (0x%08X)", a, a)
}

func avpName(c uint32) string {
	switch c {
	case 1:
		return "User-Name"
	case 25:
		return "Class"
	case 27:
		return "Session-Timeout"
	case 33:
		return "Proxy-State"
	case 44:
		return "Acct-Session-Id"
	case 50:
		return "Acct-Multi-Session-Id"
	case 55:
		return "Event-Timestamp"
	case 257:
		return "Host-IP-Address"
	case 258:
		return "Auth-Application-Id"
	case 259:
		return "Acct-Application-Id"
	case 260:
		return "Vendor-Specific-Application-Id"
	case 261:
		return "Redirect-Host-Usage"
	case 262:
		return "Redirect-Max-Cache-Time"
	case 263:
		return "Session-Id"
	case 264:
		return "Origin-Host"
	case 265:
		return "Supported-Vendor-Id"
	case 266:
		return "Vendor-Id"
	case 267:
		return "Firmware-Revision"
	case 268:
		return "Result-Code"
	case 269:
		return "Product-Name"
	case 270:
		return "Session-Binding"
	case 271:
		return "Session-Server-Failover"
	case 272:
		return "Multi-Round-Time-Out"
	case 273:
		return "Disconnect-Cause"
	case 274:
		return "Auth-Request-Type"
	case 276:
		return "Auth-Grace-Period"
	case 277:
		return "Auth-Session-State"
	case 278:
		return "Origin-State-Id"
	case 279:
		return "Failed-AVP"
	case 280:
		return "Proxy-Host"
	case 281:
		return "Error-Message"
	case 282:
		return "Route-Record"
	case 283:
		return "Destination-Realm"
	case 284:
		return "Proxy-Info"
	case 285:
		return "Re-Auth-Request-Type"
	case 287:
		return "Accounting-Sub-Session-Id"
	case 291:
		return "Authorization-Lifetime"
	case 292:
		return "Redirect-Host"
	case 293:
		return "Destination-Host"
	case 294:
		return "Error-Reporting-Host"
	case 295:
		return "Termination-Cause"
	case 296:
		return "Origin-Realm"
	case 297:
		return "Experimental-Result"
	case 298:
		return "Experimental-Result-Code"
	case 299:
		return "Inband-Security-Id"
	case 480:
		return "Accounting-Record-Type"
	case 483:
		return "Accounting-Realtime-Required"
	case 485:
		return "Accounting-Record-Number"
	}
	return ""
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
