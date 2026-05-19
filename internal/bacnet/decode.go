// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bacnet decodes BACnet/IP (BACnet over UDP, ASHRAE
// 135 Annex J) frames — the dominant building-automation
// protocol used in HVAC controllers, lighting panels, energy
// meters, fire-alarm gateways, elevator dispatch, and BMS
// (Building Management Systems) front-ends.
//
// # Wrap-vs-native judgement
//
// Native. BACnet is defined by the public ASHRAE 135 standard.
// The BACnet/IP transport (Annex J) wraps a BACnet NPDU
// + APDU inside a 4-byte BVLC (BACnet Virtual Link Control)
// header, followed by an NPDU (network-layer header with
// optional source / destination addressing + hop count) and
// an APDU (application-layer PDU carrying the actual
// confirmed / unconfirmed service request or response). Every
// envelope field is a fixed-format byte stream; type/function
// dispatch is a series of small lookup tables. Pasting a hex
// blob from Wireshark / YABE (Yet Another BACnet Explorer) /
// a captured UDP/47808 frame is enough — no vendor SDK, no
// handshake.
//
// # What this package covers
//
//   - BVLC envelope: Type byte (always 0x81 for BACnet/IP),
//     Function byte (12 documented values, 0x00 BVLC-Result
//     through 0x0C Secure-BVLL), Length field covering the
//     full frame.
//   - NPDU envelope: Version (always 1 for current spec),
//     Control byte with bit-field decode (Network Layer
//     Message / Destination Specifier / Source Specifier /
//     Reply Expected / Priority), optional Destination Network
//   - Destination Address (length-prefixed), optional Source
//     Network + Source Address (length-prefixed), Hop Count
//     (present when destination is specified), and optional
//     network-layer Message Type.
//   - APDU envelope: 4-bit PDU Type (8 documented types,
//     0x0 Confirmed-Request through 0x7 Abort), per-type flag
//     decode (SEG / MOR / SA / Server / Sent-By-Server /
//     Negative-ACK), Invoke ID, Sequence Number / Window
//     Size for segmented PDUs, Max Segments Accepted / Max
//     APDU Length Accepted for Confirmed-Request,
//     ServiceChoice with a 30+ entry confirmed-service
//     table and a 10+ entry unconfirmed-service table.
//   - Network-layer message type lookup (~16 entries) when
//     the NPDU Control byte's NLM bit is set.
//   - Error / Reject / Abort reason code lookup (~30 entries
//     for Error, 10 for Reject, 8 for Abort).
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - BACnet-tagged data decoding (the APDU body): the
//     ASN.1-style tagged encoding (context vs application
//     tags, primitive vs constructed) requires a recursive
//     walker that's a substantial separate iteration. The
//     ServiceChoice + raw payload hex are surfaced so the
//     operator can compare against the standard's service-
//     specific layouts.
//   - BACnet MS/TP (RS-485 dialect), BACnet/Ethernet
//     (Type 0x82), BACnet/PTP, BACnet/ARCnet — each has a
//     different envelope. Only Annex J BACnet/IP is in
//     scope for this Spec.
//   - BACnet-Secure / BACnet/SC (Secure Connect) — the
//     0x0C Secure-BVLL function is named but the encrypted
//     payload is not decoded.
//   - Object-instance + property-identifier lookup beyond
//     the ServiceChoice level. The standard defines ~50
//     object types and ~250 properties; that catalog will
//     land as a separate Spec when needed.
package bacnet

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Frame is the decoded view of a BACnet/IP frame.
type Frame struct {
	HexInput string `json:"hex_input"`
	BVLC     *BVLC  `json:"bvlc"`
	NPDU     *NPDU  `json:"npdu,omitempty"`
	APDU     *APDU  `json:"apdu,omitempty"`
}

// BVLC is the 4-byte BACnet Virtual Link Control header.
type BVLC struct {
	Type         int    `json:"type"`
	TypeName     string `json:"type_name"`
	Function     int    `json:"function"`
	FunctionName string `json:"function_name"`
	Length       int    `json:"length"`
}

// NPDU is the BACnet Network Protocol Data Unit header.
type NPDU struct {
	Version          int    `json:"version"`
	ControlByte      int    `json:"control_byte"`
	NetworkLayerMsg  bool   `json:"network_layer_message"`
	DestSpecifier    bool   `json:"destination_specifier"`
	SourceSpecifier  bool   `json:"source_specifier"`
	ReplyExpected    bool   `json:"reply_expected"`
	Priority         int    `json:"priority"`
	PriorityName     string `json:"priority_name"`
	DestNetwork      *int   `json:"destination_network,omitempty"`
	DestAddressHex   string `json:"destination_address_hex,omitempty"`
	SourceNetwork    *int   `json:"source_network,omitempty"`
	SourceAddressHex string `json:"source_address_hex,omitempty"`
	HopCount         *int   `json:"hop_count,omitempty"`
	MessageType      *int   `json:"network_message_type,omitempty"`
	MessageTypeName  string `json:"network_message_type_name,omitempty"`
}

// APDU is the BACnet Application Protocol Data Unit header.
type APDU struct {
	PDUType               int    `json:"pdu_type"`
	PDUTypeName           string `json:"pdu_type_name"`
	Segmented             bool   `json:"segmented,omitempty"`
	MoreFollows           bool   `json:"more_follows,omitempty"`
	SegmentedRespAccepted bool   `json:"segmented_response_accepted,omitempty"`
	MaxSegmentsAccepted   *int   `json:"max_segments_accepted,omitempty"`
	MaxAPDULenAccepted    *int   `json:"max_apdu_len_accepted,omitempty"`
	InvokeID              *int   `json:"invoke_id,omitempty"`
	SequenceNumber        *int   `json:"sequence_number,omitempty"`
	WindowSize            *int   `json:"window_size,omitempty"`
	ServiceChoice         *int   `json:"service_choice,omitempty"`
	ServiceChoiceName     string `json:"service_choice_name,omitempty"`
	Server                bool   `json:"server,omitempty"`
	NegativeACK           bool   `json:"negative_acknowledgement,omitempty"`
	ErrorClass            *int   `json:"error_class,omitempty"`
	ErrorCode             *int   `json:"error_code,omitempty"`
	RejectReason          *int   `json:"reject_reason,omitempty"`
	RejectReasonName      string `json:"reject_reason_name,omitempty"`
	AbortReason           *int   `json:"abort_reason,omitempty"`
	AbortReasonName       string `json:"abort_reason_name,omitempty"`
	BodyHex               string `json:"body_hex,omitempty"`
}

// Decode parses a hex-encoded BACnet/IP frame.
func Decode(hexBlob string) (*Frame, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw BACnet/IP frame.
func DecodeBytes(b []byte) (*Frame, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("bacnet: frame too short (%d bytes) — BVLC header alone is 4 bytes", len(b))
	}
	f := &Frame{HexInput: strings.ToUpper(hex.EncodeToString(b))}
	bvlc, npduOffset, err := decodeBVLC(b)
	if err != nil {
		return nil, err
	}
	f.BVLC = bvlc

	// Some BVLC functions carry an NPDU+APDU; some don't.
	switch bvlc.Function {
	case 0x04, 0x09, 0x0A, 0x0B:
		// Forwarded-NPDU (0x04), Distribute-Broadcast-To-Network
		// (0x09), Original-Unicast-NPDU (0x0A), Original-
		// Broadcast-NPDU (0x0B) all carry an NPDU. For
		// Forwarded-NPDU the NPDU is preceded by a 6-byte
		// originating-device B/IP address (4-byte IP + 2-byte
		// port).
		if bvlc.Function == 0x04 {
			if len(b) < npduOffset+6 {
				return nil, fmt.Errorf("bacnet: Forwarded-NPDU truncated before 6-byte B/IP source")
			}
			npduOffset += 6
		}
		if len(b) <= npduOffset {
			return f, nil
		}
		npdu, apduOffset, err := decodeNPDU(b[npduOffset:])
		if err != nil {
			return nil, fmt.Errorf("bacnet: NPDU: %w", err)
		}
		f.NPDU = npdu
		// Skip APDU decode when the NPDU is a network-layer
		// management message — those don't carry an APDU.
		if !npdu.NetworkLayerMsg {
			if len(b) > npduOffset+apduOffset {
				apdu, err := decodeAPDU(b[npduOffset+apduOffset:])
				if err != nil {
					return nil, fmt.Errorf("bacnet: APDU: %w", err)
				}
				f.APDU = apdu
			}
		}
	}
	return f, nil
}

func decodeBVLC(b []byte) (*BVLC, int, error) {
	if b[0] != 0x81 {
		return nil, 0, fmt.Errorf("bacnet: BVLC Type byte = 0x%02X; want 0x81 (BACnet/IP)", b[0])
	}
	length := int(b[2])<<8 | int(b[3])
	if length != len(b) {
		return nil, 0, fmt.Errorf(
			"bacnet: BVLC Length field (%d) does not match buffer length (%d)",
			length, len(b))
	}
	return &BVLC{
		Type:         int(b[0]),
		TypeName:     "BACnet/IP (Annex J)",
		Function:     int(b[1]),
		FunctionName: bvlcFunctionName(int(b[1])),
		Length:       length,
	}, 4, nil
}

func decodeNPDU(b []byte) (*NPDU, int, error) {
	if len(b) < 2 {
		return nil, 0, fmt.Errorf("NPDU too short")
	}
	n := &NPDU{
		Version:     int(b[0]),
		ControlByte: int(b[1]),
	}
	if n.Version != 1 {
		return nil, 0, fmt.Errorf("NPDU Version = %d; expected 1", n.Version)
	}
	ctrl := b[1]
	n.NetworkLayerMsg = ctrl&0x80 != 0
	n.DestSpecifier = ctrl&0x20 != 0
	n.SourceSpecifier = ctrl&0x08 != 0
	n.ReplyExpected = ctrl&0x04 != 0
	n.Priority = int(ctrl & 0x03)
	n.PriorityName = priorityName(n.Priority)

	off := 2
	if n.DestSpecifier {
		if off+3 > len(b) {
			return nil, 0, fmt.Errorf("NPDU dest network/address truncated")
		}
		net := int(b[off])<<8 | int(b[off+1])
		n.DestNetwork = &net
		alen := int(b[off+2])
		off += 3
		if off+alen > len(b) {
			return nil, 0, fmt.Errorf("NPDU dest address (len %d) truncated", alen)
		}
		if alen > 0 {
			n.DestAddressHex = strings.ToUpper(hex.EncodeToString(b[off : off+alen]))
		}
		off += alen
	}
	if n.SourceSpecifier {
		if off+3 > len(b) {
			return nil, 0, fmt.Errorf("NPDU source network/address truncated")
		}
		net := int(b[off])<<8 | int(b[off+1])
		n.SourceNetwork = &net
		alen := int(b[off+2])
		off += 3
		if off+alen > len(b) {
			return nil, 0, fmt.Errorf("NPDU source address (len %d) truncated", alen)
		}
		if alen > 0 {
			n.SourceAddressHex = strings.ToUpper(hex.EncodeToString(b[off : off+alen]))
		}
		off += alen
	}
	if n.DestSpecifier {
		if off >= len(b) {
			return nil, 0, fmt.Errorf("NPDU hop count missing")
		}
		hc := int(b[off])
		n.HopCount = &hc
		off++
	}
	if n.NetworkLayerMsg {
		if off >= len(b) {
			return nil, 0, fmt.Errorf("NPDU message type missing")
		}
		mt := int(b[off])
		n.MessageType = &mt
		n.MessageTypeName = networkMessageTypeName(mt)
		off++
	}
	return n, off, nil
}

func decodeAPDU(b []byte) (*APDU, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("APDU empty")
	}
	a := &APDU{
		PDUType:     int(b[0] >> 4),
		PDUTypeName: pduTypeName(int(b[0] >> 4)),
	}
	first := b[0]
	off := 1
	switch a.PDUType {
	case 0: // Confirmed-Request
		a.Segmented = first&0x08 != 0
		a.MoreFollows = first&0x04 != 0
		a.SegmentedRespAccepted = first&0x02 != 0
		if off >= len(b) {
			return nil, fmt.Errorf("Confirmed-Request truncated")
		}
		ms := int((b[off] >> 4) & 0x07)
		ma := int(b[off] & 0x0F)
		a.MaxSegmentsAccepted = &ms
		a.MaxAPDULenAccepted = &ma
		off++
		if off >= len(b) {
			return nil, fmt.Errorf("Confirmed-Request invoke ID missing")
		}
		id := int(b[off])
		a.InvokeID = &id
		off++
		if a.Segmented {
			if off+2 > len(b) {
				return nil, fmt.Errorf("Confirmed-Request segmented seq/window missing")
			}
			sq := int(b[off])
			ws := int(b[off+1])
			a.SequenceNumber = &sq
			a.WindowSize = &ws
			off += 2
		}
		if off < len(b) {
			sc := int(b[off])
			a.ServiceChoice = &sc
			a.ServiceChoiceName = confirmedServiceName(sc)
			off++
		}
	case 1: // Unconfirmed-Request
		if off < len(b) {
			sc := int(b[off])
			a.ServiceChoice = &sc
			a.ServiceChoiceName = unconfirmedServiceName(sc)
			off++
		}
	case 2: // SimpleACK
		if off >= len(b) {
			return nil, fmt.Errorf("SimpleACK invoke ID missing")
		}
		id := int(b[off])
		a.InvokeID = &id
		off++
		if off < len(b) {
			sc := int(b[off])
			a.ServiceChoice = &sc
			a.ServiceChoiceName = confirmedServiceName(sc)
			off++
		}
	case 3: // ComplexACK
		a.Segmented = first&0x08 != 0
		a.MoreFollows = first&0x04 != 0
		if off >= len(b) {
			return nil, fmt.Errorf("ComplexACK invoke ID missing")
		}
		id := int(b[off])
		a.InvokeID = &id
		off++
		if a.Segmented {
			if off+2 > len(b) {
				return nil, fmt.Errorf("ComplexACK segmented seq/window missing")
			}
			sq := int(b[off])
			ws := int(b[off+1])
			a.SequenceNumber = &sq
			a.WindowSize = &ws
			off += 2
		}
		if off < len(b) {
			sc := int(b[off])
			a.ServiceChoice = &sc
			a.ServiceChoiceName = confirmedServiceName(sc)
			off++
		}
	case 4: // SegmentACK
		a.Server = first&0x01 != 0
		a.NegativeACK = first&0x02 != 0
		if off+3 > len(b) {
			return nil, fmt.Errorf("SegmentACK truncated")
		}
		id := int(b[off])
		sq := int(b[off+1])
		ws := int(b[off+2])
		a.InvokeID = &id
		a.SequenceNumber = &sq
		a.WindowSize = &ws
		off += 3
	case 5: // Error
		if off >= len(b) {
			return nil, fmt.Errorf("error-PDU invoke ID missing")
		}
		id := int(b[off])
		a.InvokeID = &id
		off++
		if off < len(b) {
			sc := int(b[off])
			a.ServiceChoice = &sc
			a.ServiceChoiceName = confirmedServiceName(sc)
			off++
		}
		// Following bytes are the Error structure (tagged
		// error_class + error_code). Surface raw — full tag
		// decode is out of scope.
	case 6: // Reject
		if off+1 >= len(b) {
			return nil, fmt.Errorf("reject-PDU truncated")
		}
		id := int(b[off])
		rr := int(b[off+1])
		a.InvokeID = &id
		a.RejectReason = &rr
		a.RejectReasonName = rejectReasonName(rr)
		off += 2
	case 7: // Abort
		a.Server = first&0x01 != 0
		if off+1 >= len(b) {
			return nil, fmt.Errorf("abort-PDU truncated")
		}
		id := int(b[off])
		ar := int(b[off+1])
		a.InvokeID = &id
		a.AbortReason = &ar
		a.AbortReasonName = abortReasonName(ar)
		off += 2
	}
	if off < len(b) {
		a.BodyHex = strings.ToUpper(hex.EncodeToString(b[off:]))
	}
	return a, nil
}

func bvlcFunctionName(fn int) string {
	switch fn {
	case 0x00:
		return "BVLC-Result"
	case 0x01:
		return "Write-Broadcast-Distribution-Table"
	case 0x02:
		return "Read-Broadcast-Distribution-Table"
	case 0x03:
		return "Read-Broadcast-Distribution-Table-Ack"
	case 0x04:
		return "Forwarded-NPDU"
	case 0x05:
		return "Register-Foreign-Device"
	case 0x06:
		return "Read-Foreign-Device-Table"
	case 0x07:
		return "Read-Foreign-Device-Table-Ack"
	case 0x08:
		return "Delete-Foreign-Device-Table-Entry"
	case 0x09:
		return "Distribute-Broadcast-To-Network"
	case 0x0A:
		return "Original-Unicast-NPDU"
	case 0x0B:
		return "Original-Broadcast-NPDU"
	case 0x0C:
		return "Secure-BVLL"
	}
	return fmt.Sprintf("Reserved (function 0x%02X)", fn)
}

func priorityName(p int) string {
	switch p {
	case 0:
		return "Normal Message"
	case 1:
		return "Urgent Message"
	case 2:
		return "Critical Equipment Message"
	case 3:
		return "Life Safety Message"
	}
	return ""
}

func pduTypeName(t int) string {
	switch t {
	case 0:
		return "Confirmed-Request-PDU"
	case 1:
		return "Unconfirmed-Request-PDU"
	case 2:
		return "SimpleACK-PDU"
	case 3:
		return "ComplexACK-PDU"
	case 4:
		return "SegmentACK-PDU"
	case 5:
		return "Error-PDU"
	case 6:
		return "Reject-PDU"
	case 7:
		return "Abort-PDU"
	}
	return fmt.Sprintf("Reserved (PDU type %d)", t)
}

func confirmedServiceName(sc int) string {
	switch sc {
	case 0:
		return "acknowledgeAlarm"
	case 1:
		return "confirmedCOVNotification"
	case 2:
		return "confirmedEventNotification"
	case 3:
		return "getAlarmSummary"
	case 4:
		return "getEnrollmentSummary"
	case 5:
		return "subscribeCOV"
	case 6:
		return "atomicReadFile"
	case 7:
		return "atomicWriteFile"
	case 8:
		return "addListElement"
	case 9:
		return "removeListElement"
	case 10:
		return "createObject"
	case 11:
		return "deleteObject"
	case 12:
		return "readProperty"
	case 13:
		return "readPropertyConditional (deprecated)"
	case 14:
		return "readPropertyMultiple"
	case 15:
		return "writeProperty"
	case 16:
		return "writePropertyMultiple"
	case 17:
		return "deviceCommunicationControl"
	case 18:
		return "confirmedPrivateTransfer"
	case 19:
		return "confirmedTextMessage"
	case 20:
		return "reinitializeDevice"
	case 21:
		return "vtOpen"
	case 22:
		return "vtClose"
	case 23:
		return "vtData"
	case 24:
		return "authenticate (deprecated)"
	case 25:
		return "requestKey (deprecated)"
	case 26:
		return "readRange"
	case 27:
		return "lifeSafetyOperation"
	case 28:
		return "subscribeCOVProperty"
	case 29:
		return "getEventInformation"
	case 30:
		return "subscribeCOVPropertyMultiple"
	case 31:
		return "confirmedCOVNotificationMultiple"
	case 32:
		return "confirmedAuditNotification"
	case 33:
		return "auditLogQuery"
	}
	return fmt.Sprintf("Reserved (confirmed service %d)", sc)
}

func unconfirmedServiceName(sc int) string {
	switch sc {
	case 0:
		return "i-Am"
	case 1:
		return "i-Have"
	case 2:
		return "unconfirmedCOVNotification"
	case 3:
		return "unconfirmedEventNotification"
	case 4:
		return "unconfirmedPrivateTransfer"
	case 5:
		return "unconfirmedTextMessage"
	case 6:
		return "timeSynchronization"
	case 7:
		return "who-Has"
	case 8:
		return "who-Is"
	case 9:
		return "utcTimeSynchronization"
	case 10:
		return "writeGroup"
	case 11:
		return "unconfirmedCOVNotificationMultiple"
	case 12:
		return "unconfirmedAuditNotification"
	case 13:
		return "who-Am-I"
	case 14:
		return "you-Are"
	}
	return fmt.Sprintf("Reserved (unconfirmed service %d)", sc)
}

func networkMessageTypeName(mt int) string {
	switch mt {
	case 0x00:
		return "Who-Is-Router-To-Network"
	case 0x01:
		return "I-Am-Router-To-Network"
	case 0x02:
		return "I-Could-Be-Router-To-Network"
	case 0x03:
		return "Reject-Message-To-Network"
	case 0x04:
		return "Router-Busy-To-Network"
	case 0x05:
		return "Router-Available-To-Network"
	case 0x06:
		return "Initialize-Routing-Table"
	case 0x07:
		return "Initialize-Routing-Table-Ack"
	case 0x08:
		return "Establish-Connection-To-Network"
	case 0x09:
		return "Disconnect-Connection-To-Network"
	case 0x0A:
		return "Challenge-Request"
	case 0x0B:
		return "Security-Payload"
	case 0x0C:
		return "Security-Response"
	case 0x0D:
		return "Request-Key-Update"
	case 0x0E:
		return "Update-Key-Set"
	case 0x0F:
		return "Update-Distribution-Key"
	case 0x10:
		return "Request-Master-Key"
	case 0x11:
		return "Set-Master-Key"
	case 0x12:
		return "What-Is-Network-Number"
	case 0x13:
		return "Network-Number-Is"
	}
	return fmt.Sprintf("Reserved (network message type 0x%02X)", mt)
}

func rejectReasonName(r int) string {
	switch r {
	case 0:
		return "other"
	case 1:
		return "buffer-overflow"
	case 2:
		return "inconsistent-parameters"
	case 3:
		return "invalid-parameter-data-type"
	case 4:
		return "invalid-tag"
	case 5:
		return "missing-required-parameter"
	case 6:
		return "parameter-out-of-range"
	case 7:
		return "too-many-arguments"
	case 8:
		return "undefined-enumeration"
	case 9:
		return "unrecognized-service"
	}
	return fmt.Sprintf("Reserved (reject reason %d)", r)
}

func abortReasonName(r int) string {
	switch r {
	case 0:
		return "other"
	case 1:
		return "buffer-overflow"
	case 2:
		return "invalid-APDU-in-this-state"
	case 3:
		return "preempted-by-higher-priority-task"
	case 4:
		return "segmentation-not-supported"
	case 5:
		return "security-error"
	case 6:
		return "insufficient-security"
	case 7:
		return "window-size-out-of-range"
	case 8:
		return "application-exceeded-reply-time"
	case 9:
		return "out-of-resources"
	case 10:
		return "tsm-timeout"
	case 11:
		return "apdu-too-long"
	}
	return fmt.Sprintf("Reserved (abort reason %d)", r)
}

func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("bacnet: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bacnet: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
