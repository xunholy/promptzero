// Package l2tp decodes L2TPv3 packets per RFC 3931 (UDP-
// encapsulated mode on UDP port 1701). L2TPv3 is the
// pseudowire encapsulation that pairs with PPPoE (covered by
// `pppoe_decode`) to complete the broadband subscriber-
// management story: PPPoE handles the access-side session
// from the customer modem to the BNG; L2TPv3 handles the
// backhaul/aggregation tunnel from the BNG to a Layer-2 VPN
// concentrator (LAC → LNS in classic deployments).
//
// L2TPv3 is also the dominant transport for:
//
//   - **Lawful intercept (LI) at every ISP** — voice + data
//     captures are funnelled through L2TPv3 tunnels from
//     edge LACs to a centralised LI mediation function.
//
//   - **L2 VPN services** — Ethernet, ATM, Frame Relay,
//     PPP, and HDLC pseudowires across MPLS or IP cores.
//
//   - **Subscriber backhaul** — wholesale broadband
//     resellers tunnel customers from CLEC LACs to their
//     LNS for centralised AAA + IP allocation.
//
// Wrap-vs-native judgement
//
//	Native. RFC 3931 is fully public. L2TPv3 has a tight
//	bit-packed common header that dispatches between
//	Control Messages (T=1) and Data Messages (T=0) via
//	the high bit. Control Messages carry an AVP
//	(Attribute-Value Pair) list with a small set of
//	well-defined Attribute Types; Data Messages carry an
//	opaque L2 frame after a small Session ID + Cookie
//	envelope. No crypto at the parse layer.
//
// What this package covers
//
//   - **16-bit common header** (RFC 3931 §3.2.1):
//     bit 0 = **T** (Type: 0 Data, 1 Control); bit 1 = L
//     (Length present); bits 2-3 reserved; bit 4 = S
//     (Ns/Nr present); bits 5-7 reserved; bits 8-11
//     reserved; bits 12-15 = **Version** (must be 3 for
//     L2TPv3).
//
//   - **Control Message** (T=1; RFC 3931 §3.2.2): Length
//     (uint16 BE; total bytes including this field's
//     position) + Control Connection ID (uint32 BE; the
//     peer-end's connection identifier) + Ns (uint16 BE;
//     send sequence number) + Nr (uint16 BE; expected
//     receive sequence number) + AVP list.
//
//   - **AVP walker** (RFC 3931 §5.2) — each AVP:
//
//   - 2 bytes: 1-bit Mandatory + 1-bit Hidden + 1-bit
//     Reserved + 10-bit Length + 3 reserved bits packed
//     into the high 6 bits + 10-bit Length in low 10
//     bits. (The bit-pack is `M H r r r r LLLLLLLLLL`.)
//
//   - 2 bytes: Vendor ID (uint16 BE; 0 = IETF, others =
//     SMI Private Enterprise Number).
//
//   - 2 bytes: Attribute Type (uint16 BE).
//
//   - Length-6 bytes: Value.
//     **~15-entry IETF AVP name table** (when Vendor ID =
//     0): Message Type / Result Code / Protocol Version /
//     Framing Capabilities / Bearer Capabilities / Tie
//     Breaker / Firmware Revision / Host Name / Vendor
//     Name / Assigned Tunnel ID / Receive Window Size /
//     Challenge / Challenge Response / Cause Code / Q.931
//     Cause Code / Assigned Session ID / Call Serial
//     Number / Local Session ID / Remote Session ID /
//     Random Vector.
//
//   - **Message Type AVP** (Attribute 0) — first AVP in
//     every Control Message; its 2-byte value names the
//     control message kind via a **16-entry name table**
//     (RFC 3931 §5.4): 1 SCCRQ (Start-Control-Connection-
//     Request) / 2 SCCRP (Start-Control-Connection-Reply)
//     / 3 SCCCN (Start-Control-Connection-Connected) /
//     4 StopCCN (Stop-Control-Connection-Notification) /
//     6 HELLO (Keepalive) / 7 OCRQ (Outgoing-Call-Request)
//     / 8 OCRP (Outgoing-Call-Reply) / 9 OCCN (Outgoing-
//     Call-Connected) / 10 ICRQ (Incoming-Call-Request) /
//     11 ICRP (Incoming-Call-Reply) / 12 ICCN (Incoming-
//     Call-Connected) / 14 CDN (Call-Disconnect-Notify) /
//     15 WEN (WAN-Error-Notify) / 16 SLI (Set-Link-Info) /
//     20 ACK (Acknowledgement, RFC 3931 addition).
//
//   - **Data Message** (T=0): Session ID (uint32 BE; the
//     peer-end's session identifier) + optional Cookie
//     (4 or 8 bytes, negotiated during ICRQ/ICRP via
//     "Assigned Cookie" AVP) + L2-Specific Sublayer
//     (varies by encap; default L2SS is empty) + L2 Frame
//     (opaque; surfaced as hex preview). The decoder
//     surfaces the Session ID and the rest as raw hex
//     pending operator-provided framing context.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed L2TPv3 bytes after the UDP header
//     strip. UDP-mode L2TPv3 runs on destination port
//     1701; IP-mode runs as IP protocol 115.
//
//   - IP-mode L2TPv3 (IP protocol 115) — different
//     envelope (no UDP header; Session ID 0 indicates a
//     Control Message). Could share most decoder logic;
//     deferred.
//
//   - Per-AVP value type-aware decoding beyond Message
//     Type and a few well-known integer/string AVPs —
//     values are surfaced as hex with plausibly-text UTF-8
//     surfacing for Host Name / Vendor Name.
//
//   - Hidden (encrypted) AVPs — the H bit is surfaced but
//     decryption requires the shared secret + RFC 3931
//     §4.3 procedure; deferred.
//
//   - PPP / HDLC / Ethernet / ATM / FR frame dissection
//     inside Data Message payload — operator pulls bytes
//     out of the payload preview and feeds into the
//     appropriate L2 decoder.
package l2tp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view of an L2TPv3 packet.
type Result struct {
	Type            int    `json:"type"`
	TypeName        string `json:"type_name"`
	LengthPresent   bool   `json:"length_present"`
	SequencePresent bool   `json:"sequence_present"`
	Version         int    `json:"version"`

	Control *ControlMessage `json:"control_message,omitempty"`
	Data    *DataMessage    `json:"data_message,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// ControlMessage is the decoded body of an L2TPv3 control
// message (T=1).
type ControlMessage struct {
	Length              int    `json:"length"`
	ControlConnectionID uint32 `json:"control_connection_id"`
	Ns                  int    `json:"send_sequence"`
	Nr                  int    `json:"expected_receive_sequence"`
	MessageType         int    `json:"message_type,omitempty"`
	MessageTypeName     string `json:"message_type_name,omitempty"`
	AVPs                []AVP  `json:"avps"`
}

// DataMessage is the decoded body of an L2TPv3 data message
// (T=0).
type DataMessage struct {
	SessionID         uint32 `json:"session_id"`
	PayloadBytes      int    `json:"payload_bytes"`
	PayloadBytesShown int    `json:"payload_bytes_shown,omitempty"`
	PayloadHex        string `json:"payload_hex,omitempty"`
}

// AVP is one (Mandatory, Hidden, Length, Vendor ID, Attribute
// Type, Value) record from the AVP walker.
type AVP struct {
	Mandatory     bool   `json:"mandatory"`
	Hidden        bool   `json:"hidden"`
	Length        int    `json:"length"`
	VendorID      int    `json:"vendor_id"`
	AttributeType int    `json:"attribute_type"`
	AttributeName string `json:"attribute_name,omitempty"`
	ValueHex      string `json:"value_hex,omitempty"`
	ValueText     string `json:"value_text,omitempty"`
}

// DecodeOpts tunes the walker for output size.
type DecodeOpts struct {
	// MaxPayloadBytes caps the Data Message payload hex
	// preview. Zero surfaces the full payload.
	MaxPayloadBytes int
}

// DefaultDecodeOpts returns a 256-byte payload preview cap.
func DefaultDecodeOpts() DecodeOpts {
	return DecodeOpts{MaxPayloadBytes: 256}
}

// Decode parses a single L2TPv3 packet from hex.
func Decode(hexStr string, opts DecodeOpts) (*Result, error) {
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
	if len(b) < 2 {
		return nil, fmt.Errorf("L2TP packet truncated (%d bytes; need ≥2 for header)",
			len(b))
	}
	hdr := binary.BigEndian.Uint16(b[0:2])
	r := &Result{
		TotalBytes:      len(b),
		Type:            int(hdr >> 15),
		LengthPresent:   hdr&0x4000 != 0,
		SequencePresent: hdr&0x0800 != 0,
		Version:         int(hdr & 0x000F),
	}
	if r.Type == 1 {
		r.TypeName = "Control Message"
	} else {
		r.TypeName = "Data Message"
	}
	if r.Version != 3 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"version is %d (this Spec covers L2TPv3 only)", r.Version))
	}
	if r.Type == 1 {
		body, err := decodeControl(b, r)
		if err != nil {
			return r, err
		}
		r.Control = body
	} else {
		body, err := decodeData(b, opts, r)
		if err != nil {
			return r, err
		}
		r.Data = body
	}
	return r, nil
}

func decodeControl(b []byte, r *Result) (*ControlMessage, error) {
	if !r.LengthPresent || !r.SequencePresent {
		r.Notes = append(r.Notes,
			"control message expects L=1 and S=1 per RFC 3931 §3.2.2")
	}
	off := 2
	c := &ControlMessage{}
	if r.LengthPresent {
		if off+2 > len(b) {
			return c, fmt.Errorf("control header truncated before length")
		}
		c.Length = int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
	}
	if off+4 > len(b) {
		return c, fmt.Errorf("control header truncated before connection ID")
	}
	c.ControlConnectionID = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if r.SequencePresent {
		if off+4 > len(b) {
			return c, fmt.Errorf("control header truncated before Ns/Nr")
		}
		c.Ns = int(binary.BigEndian.Uint16(b[off : off+2]))
		c.Nr = int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
	}
	c.AVPs = decodeAVPs(b[off:])
	for _, a := range c.AVPs {
		if a.VendorID == 0 && a.AttributeType == 0 && len(a.ValueHex) >= 4 {
			raw, err := hex.DecodeString(a.ValueHex)
			if err == nil && len(raw) >= 2 {
				c.MessageType = int(binary.BigEndian.Uint16(raw[0:2]))
				c.MessageTypeName = messageTypeName(c.MessageType)
			}
			break
		}
	}
	return c, nil
}

func decodeData(b []byte, opts DecodeOpts, r *Result) (*DataMessage, error) {
	_ = r
	if len(b) < 6 {
		return nil, fmt.Errorf("data header truncated (%d bytes; need ≥6 for session ID)",
			len(b))
	}
	d := &DataMessage{
		SessionID: binary.BigEndian.Uint32(b[2:6]),
	}
	payload := b[6:]
	d.PayloadBytes = len(payload)
	if len(payload) > 0 {
		show := len(payload)
		if opts.MaxPayloadBytes > 0 && show > opts.MaxPayloadBytes {
			show = opts.MaxPayloadBytes
		}
		d.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:show]))
		d.PayloadBytesShown = show
	}
	return d, nil
}

func decodeAVPs(b []byte) []AVP {
	var out []AVP
	off := 0
	for off+6 <= len(b) {
		hdr := binary.BigEndian.Uint16(b[off : off+2])
		mandatory := hdr&0x8000 != 0
		hidden := hdr&0x4000 != 0
		ln := int(hdr & 0x03FF)
		if ln < 6 {
			return out
		}
		if off+ln > len(b) {
			return out
		}
		vid := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		at := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		val := b[off+6 : off+ln]
		a := AVP{
			Mandatory:     mandatory,
			Hidden:        hidden,
			Length:        ln,
			VendorID:      vid,
			AttributeType: at,
			ValueHex:      strings.ToUpper(hex.EncodeToString(val)),
		}
		if vid == 0 {
			a.AttributeName = avpName(at)
		}
		if !hidden && utf8.Valid(val) && looksTextual(val) {
			a.ValueText = strings.TrimRight(string(val), "\x00")
		}
		out = append(out, a)
		off += ln
	}
	return out
}

// looksTextual returns true when the bytes are plausibly text.
func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 {
			if c != '\t' && c != '\n' && c != '\r' && c != 0 {
				return false
			}
		}
		if c == 0x7F {
			return false
		}
	}
	return true
}

func messageTypeName(t int) string {
	switch t {
	case 1:
		return "SCCRQ (Start-Control-Connection-Request)"
	case 2:
		return "SCCRP (Start-Control-Connection-Reply)"
	case 3:
		return "SCCCN (Start-Control-Connection-Connected)"
	case 4:
		return "StopCCN (Stop-Control-Connection-Notification)"
	case 6:
		return "HELLO (Keepalive)"
	case 7:
		return "OCRQ (Outgoing-Call-Request)"
	case 8:
		return "OCRP (Outgoing-Call-Reply)"
	case 9:
		return "OCCN (Outgoing-Call-Connected)"
	case 10:
		return "ICRQ (Incoming-Call-Request)"
	case 11:
		return "ICRP (Incoming-Call-Reply)"
	case 12:
		return "ICCN (Incoming-Call-Connected)"
	case 14:
		return "CDN (Call-Disconnect-Notify)"
	case 15:
		return "WEN (WAN-Error-Notify)"
	case 16:
		return "SLI (Set-Link-Info)"
	case 20:
		return "ACK (Acknowledgement)"
	}
	return fmt.Sprintf("uncatalogued message type %d", t)
}

func avpName(at int) string {
	switch at {
	case 0:
		return "Message Type"
	case 1:
		return "Result Code"
	case 2:
		return "Protocol Version"
	case 3:
		return "Framing Capabilities"
	case 4:
		return "Bearer Capabilities"
	case 5:
		return "Tie Breaker"
	case 6:
		return "Firmware Revision"
	case 7:
		return "Host Name"
	case 8:
		return "Vendor Name"
	case 9:
		return "Assigned Tunnel ID"
	case 10:
		return "Receive Window Size"
	case 11:
		return "Challenge"
	case 13:
		return "Challenge Response"
	case 14:
		return "Cause Code"
	case 15:
		return "Q.931 Cause Code"
	case 63:
		return "Local Session ID"
	case 64:
		return "Remote Session ID"
	case 65:
		return "Assigned Cookie"
	case 36:
		return "Random Vector"
	case 41:
		return "Initial Received LCP CONFREQ"
	case 42:
		return "Last Sent LCP CONFREQ"
	case 43:
		return "Last Received LCP CONFREQ"
	case 44:
		return "Proxy Authen Type"
	case 45:
		return "Proxy Authen Name"
	case 46:
		return "Proxy Authen Challenge"
	case 47:
		return "Proxy Authen ID"
	case 48:
		return "Proxy Authen Response"
	}
	return fmt.Sprintf("uncatalogued IETF AVP %d", at)
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
