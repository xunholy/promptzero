// Package lorawan decodes LoRaWAN PHYPayload frames — the
// MAC-layer packet format used by LoRaWAN 1.0.x and 1.1
// networks. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: LoRaWAN is a fully open
// specification (LoRa Alliance LoRaWAN 1.0.x / 1.1
// specifications). The walker is bit-level decoding over a
// ~12-300 byte frame with a documented MAC-header byte and a
// FHDR / FPort / FRMPayload split. Wrapping a FAP for this
// would require an SD-card install + a firmware-fork dependency
// for a pure parser. Native delivers offline analysis —
// operators paste a captured PHYPayload (from a Flipper LoRa
// sub-board, a CatSniffer, or any LoRa SDR) and inspect every
// MAC-layer field without an antenna attached.
//
// Pairs with the bruce_lora_scan capability (which gets a
// device-side LoRa scan running) and with future LoRaWAN
// containerbridge integrations — this Spec is the offline-
// analyst entry point.
//
// What this package covers:
//   - PHYPayload split: MHDR + MACPayload + 4-byte MIC
//   - MHDR decode: MType (Join Request / Accept, Confirmed /
//     Unconfirmed Data Up / Down, Rejoin, Proprietary) + Major
//   - Data-frame MACPayload walk: FHDR (DevAddr little-endian,
//     FCtrl bitfield, FCnt, FOpts MAC commands), FPort,
//     FRMPayload (surfaced as hex; encrypted under AppSKey)
//   - FCtrl bitfield decode with uplink vs downlink interpretation
//     (uplink: ADR / ADRACKReq / ACK / ClassB / FOptsLen;
//     downlink: ADR / RFU / ACK / FPending / FOptsLen)
//   - Join Request decode: JoinEUI + DevEUI + DevNonce (all
//     little-endian on the wire)
//   - Join Accept decode: AppNonce + NetID + DevAddr + DLSettings
//   - RxDelay + optional CFList (encrypted under AppKey; we
//     surface structure when called with the decrypted form)
//
// What this package does NOT cover (deliberately out of scope):
//   - AES-CMAC MIC validation (needs NwkSKey / NwkSEncKey)
//   - FRMPayload decryption (needs AppSKey)
//   - Join Accept decryption (needs AppKey — the Join Accept
//     decoder walks the cleartext-structure form; operators
//     decrypt with their own AppKey before passing)
//   - PHY-layer decode (chirp / spreading-factor / CR — those
//     are the SDR's job, not the MAC-layer parser's)
package lorawan

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// MType is the 3-bit Message Type field at the top of the MHDR.
type MType int

const (
	MTypeJoinRequest         MType = 0
	MTypeJoinAccept          MType = 1
	MTypeUnconfirmedDataUp   MType = 2
	MTypeUnconfirmedDataDown MType = 3
	MTypeConfirmedDataUp     MType = 4
	MTypeConfirmedDataDown   MType = 5
	MTypeRejoinRequest       MType = 6
	MTypeProprietary         MType = 7
)

func (m MType) String() string {
	switch m {
	case MTypeJoinRequest:
		return "Join Request"
	case MTypeJoinAccept:
		return "Join Accept"
	case MTypeUnconfirmedDataUp:
		return "Unconfirmed Data Up"
	case MTypeUnconfirmedDataDown:
		return "Unconfirmed Data Down"
	case MTypeConfirmedDataUp:
		return "Confirmed Data Up"
	case MTypeConfirmedDataDown:
		return "Confirmed Data Down"
	case MTypeRejoinRequest:
		return "Rejoin Request"
	case MTypeProprietary:
		return "Proprietary"
	}
	return "Unknown"
}

// IsUplink reports whether the MType is one of the uplink kinds
// (Join Request, Confirmed/Unconfirmed Data Up, Rejoin Request).
// Drives the FCtrl bitfield interpretation.
func (m MType) IsUplink() bool {
	switch m {
	case MTypeJoinRequest, MTypeUnconfirmedDataUp, MTypeConfirmedDataUp, MTypeRejoinRequest:
		return true
	}
	return false
}

// MHDR is the 1-byte MAC header.
type MHDR struct {
	Raw    int    `json:"raw"`
	MType  int    `json:"mtype"`
	Name   string `json:"mtype_name"`
	Major  int    `json:"major"`
	Uplink bool   `json:"uplink"`
}

// FCtrl is the decoded 1-byte FCtrl field of an FHDR. Bit
// interpretations differ between uplink and downlink frames.
type FCtrl struct {
	Raw int  `json:"raw"`
	ADR bool `json:"adr"`
	// ADRACKReq is set on uplinks only.
	ADRACKReq bool `json:"adr_ack_req,omitempty"`
	ACK       bool `json:"ack"`
	// ClassB is set on uplinks only; FPending on downlinks only.
	ClassB   bool `json:"class_b,omitempty"`
	FPending bool `json:"f_pending,omitempty"`
	FOptsLen int  `json:"f_opts_len"`
}

// FHDR is the Frame Header — DevAddr + FCtrl + FCnt + FOpts.
type FHDR struct {
	// DevAddr is the 32-bit device address. Stored on the wire
	// little-endian; we render the big-endian hex form here so
	// it matches the form network servers / chirpstack use.
	DevAddrHex string `json:"dev_addr_hex"`
	DevAddr    uint32 `json:"dev_addr"`
	FCtrl      FCtrl  `json:"f_ctrl"`
	FCnt       int    `json:"f_cnt"`
	// FOptsHex is the optional MAC-command field (up to 15
	// bytes). Surfaced as hex; we don't dissect MAC commands
	// here (that's a follow-on Spec when a caller materialises).
	FOptsHex string `json:"f_opts_hex,omitempty"`
}

// DataPayload is the structured view of a data-frame MACPayload
// (Unconfirmed/Confirmed Data Up/Down).
type DataPayload struct {
	FHDR FHDR `json:"fhdr"`
	// FPort: 1 byte. nil when FRMPayload is empty.
	FPort *int `json:"f_port,omitempty"`
	// FRMPayloadHex is the encrypted application payload as hex.
	// Empty when no FRMPayload is present. We do not decrypt
	// (needs AppSKey / NwkSEncKey out-of-band).
	FRMPayloadHex string `json:"frm_payload_hex,omitempty"`
}

// JoinRequest is the structured view of a Join Request MACPayload.
type JoinRequest struct {
	// JoinEUI is the 8-byte EUI-64 of the Join Server (LoRaWAN
	// 1.0.x called this AppEUI). Wire form is little-endian; we
	// render the big-endian hex here so it matches the form
	// printed on device labels.
	JoinEUIHex string `json:"join_eui_hex"`
	// DevEUI is the 8-byte EUI-64 of the device. Same little-
	// endian-on-wire convention.
	DevEUIHex string `json:"dev_eui_hex"`
	// DevNonce is the 2-byte little-endian device-supplied nonce.
	DevNonce int `json:"dev_nonce"`
}

// JoinAccept is the structured view of a (decrypted) Join Accept
// MACPayload. Network servers encrypt Join Accept with AppKey
// using AES-128-ECB before transmit; operators bring the
// decrypted bytes before calling this decoder.
type JoinAccept struct {
	// AppNonce is the 3-byte network-supplied nonce.
	AppNonceHex string `json:"app_nonce_hex"`
	// NetID is the 3-byte network identifier.
	NetIDHex string `json:"net_id_hex"`
	// DevAddr is the 4-byte device address assigned to the
	// device for this session.
	DevAddrHex string `json:"dev_addr_hex"`
	DevAddr    uint32 `json:"dev_addr"`
	// DLSettings is the downlink-settings byte (RX1 DR offset +
	// RX2 data rate).
	DLSettings int `json:"dl_settings"`
	// RxDelay is the receive delay byte (0-15 seconds).
	RxDelay int `json:"rx_delay"`
	// CFListHex is the optional 16-byte channel-frequency list.
	// Empty when absent.
	CFListHex string `json:"cf_list_hex,omitempty"`
}

// PHYPayload is the top-level decoded frame.
type PHYPayload struct {
	// MHDR is the parsed MAC header.
	MHDR MHDR `json:"mhdr"`
	// MIC is the 4-byte Message Integrity Code at the frame end.
	MICHex string `json:"mic_hex"`
	// Data is set for the data-frame MTypes (2-5).
	Data *DataPayload `json:"data,omitempty"`
	// JoinRequest is set when MType == 0.
	JoinRequest *JoinRequest `json:"join_request,omitempty"`
	// JoinAccept is set when MType == 1 (assumes operator has
	// decrypted the body).
	JoinAccept *JoinAccept `json:"join_accept,omitempty"`
	// RejoinRequestHex is set when MType == 6 (Rejoin Request).
	// We surface the raw bytes — Rejoin Type byte then variable
	// fields per LoRaWAN 1.1 §6.2.4.
	RejoinRequestHex string `json:"rejoin_request_hex,omitempty"`
	// ProprietaryHex is set when MType == 7.
	ProprietaryHex string `json:"proprietary_hex,omitempty"`
	// PayloadHex is the raw PHYPayload for callers that want to
	// re-render or audit.
	PayloadHex string `json:"payload_hex"`
}

// Decode parses a hex-encoded LoRaWAN PHYPayload frame. Tolerates
// ':' / '-' / '_' / whitespace separators.
func Decode(hexBlob string) (PHYPayload, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return PHYPayload{}, fmt.Errorf("lorawan: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return PHYPayload{}, fmt.Errorf("lorawan: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode.
func DecodeBytes(b []byte) (PHYPayload, error) {
	if len(b) < 5 {
		return PHYPayload{}, fmt.Errorf("lorawan: PHYPayload %d bytes < 5-byte minimum (MHDR + MIC)", len(b))
	}
	mh := decodeMHDR(b[0])
	mic := b[len(b)-4:]
	macPayload := b[1 : len(b)-4]
	out := PHYPayload{
		MHDR:       mh,
		MICHex:     hexString(mic),
		PayloadHex: hexString(b),
	}
	switch MType(mh.MType) {
	case MTypeJoinRequest:
		jr, err := decodeJoinRequest(macPayload)
		if err != nil {
			return out, err
		}
		out.JoinRequest = &jr
	case MTypeJoinAccept:
		ja, err := decodeJoinAccept(macPayload)
		if err != nil {
			return out, err
		}
		out.JoinAccept = &ja
	case MTypeUnconfirmedDataUp, MTypeUnconfirmedDataDown,
		MTypeConfirmedDataUp, MTypeConfirmedDataDown:
		dp, err := decodeDataPayload(macPayload, mh.Uplink)
		if err != nil {
			return out, err
		}
		out.Data = &dp
	case MTypeRejoinRequest:
		out.RejoinRequestHex = hexString(macPayload)
	case MTypeProprietary:
		out.ProprietaryHex = hexString(macPayload)
	}
	return out, nil
}

// decodeMHDR unpacks the 1-byte MAC header.
//
//	bits 7-5: MType
//	bits 4-2: RFU
//	bits 1-0: Major (LoRaWAN R1 = 0)
func decodeMHDR(b byte) MHDR {
	mt := int(b >> 5)
	return MHDR{
		Raw:    int(b),
		MType:  mt,
		Name:   MType(mt).String(),
		Major:  int(b & 0x03),
		Uplink: MType(mt).IsUplink(),
	}
}

// decodeDataPayload parses an Unconfirmed/Confirmed Data
// MACPayload. uplink drives the FCtrl bitfield interpretation.
//
// Minimum size: 7 bytes (DevAddr 4 + FCtrl 1 + FCnt 2). FOpts +
// FPort + FRMPayload are optional.
func decodeDataPayload(b []byte, uplink bool) (DataPayload, error) {
	const minFHDR = 7
	if len(b) < minFHDR {
		return DataPayload{}, fmt.Errorf("lorawan: data MACPayload %d bytes < %d-byte FHDR minimum",
			len(b), minFHDR)
	}
	// DevAddr is little-endian on the wire.
	devAddr := binary.LittleEndian.Uint32(b[0:4])
	fctrlByte := b[4]
	fCnt := int(binary.LittleEndian.Uint16(b[5:7]))
	fctrl := decodeFCtrl(fctrlByte, uplink)
	if 7+fctrl.FOptsLen > len(b) {
		return DataPayload{}, fmt.Errorf("lorawan: FOptsLen %d exceeds MACPayload remaining %d",
			fctrl.FOptsLen, len(b)-7)
	}
	fhdr := FHDR{
		DevAddrHex: fmt.Sprintf("%08X", devAddr),
		DevAddr:    devAddr,
		FCtrl:      fctrl,
		FCnt:       fCnt,
	}
	if fctrl.FOptsLen > 0 {
		fhdr.FOptsHex = hexString(b[7 : 7+fctrl.FOptsLen])
	}
	out := DataPayload{FHDR: fhdr}
	rest := b[7+fctrl.FOptsLen:]
	if len(rest) > 0 {
		port := int(rest[0])
		out.FPort = &port
		if len(rest) > 1 {
			out.FRMPayloadHex = hexString(rest[1:])
		}
	}
	return out, nil
}

// decodeFCtrl unpacks the 1-byte FCtrl field, interpreting bits
// 7 and 4 differently for uplink vs downlink per LoRaWAN spec.
func decodeFCtrl(b byte, uplink bool) FCtrl {
	out := FCtrl{
		Raw:      int(b),
		ADR:      b&0x80 != 0,
		ACK:      b&0x20 != 0,
		FOptsLen: int(b & 0x0F),
	}
	if uplink {
		out.ADRACKReq = b&0x40 != 0
		out.ClassB = b&0x10 != 0
	} else {
		out.FPending = b&0x10 != 0
	}
	return out
}

// decodeJoinRequest parses a Join Request MACPayload. The fields
// are 18 bytes:
//
//	JoinEUI:8 (LE) + DevEUI:8 (LE) + DevNonce:2 (LE)
//
// EUI-64 values are stored little-endian on the wire; we render
// the big-endian hex here so they match the form printed on
// device labels.
func decodeJoinRequest(b []byte) (JoinRequest, error) {
	const want = 18
	if len(b) != want {
		return JoinRequest{}, fmt.Errorf("lorawan: Join Request payload %d bytes; want %d",
			len(b), want)
	}
	return JoinRequest{
		JoinEUIHex: hexString(reverseBytes(b[0:8])),
		DevEUIHex:  hexString(reverseBytes(b[8:16])),
		DevNonce:   int(binary.LittleEndian.Uint16(b[16:18])),
	}, nil
}

// decodeJoinAccept parses a (decrypted) Join Accept MACPayload.
// Layout per LoRaWAN 1.0.x §6.2.5:
//
//	AppNonce:3 (LE) + NetID:3 (LE) + DevAddr:4 (LE) +
//	  DLSettings:1 + RxDelay:1 + CFList:0 or 16
//
// CFList is the optional channel-frequency list (16 bytes when
// present, total payload = 28 bytes; 12 bytes total when absent).
func decodeJoinAccept(b []byte) (JoinAccept, error) {
	if len(b) != 12 && len(b) != 28 {
		return JoinAccept{}, fmt.Errorf("lorawan: Join Accept payload %d bytes; want 12 or 28",
			len(b))
	}
	devAddr := binary.LittleEndian.Uint32(b[6:10])
	out := JoinAccept{
		AppNonceHex: hexString(reverseBytes(b[0:3])),
		NetIDHex:    hexString(reverseBytes(b[3:6])),
		DevAddrHex:  fmt.Sprintf("%08X", devAddr),
		DevAddr:     devAddr,
		DLSettings:  int(b[10]),
		RxDelay:     int(b[11]),
	}
	if len(b) == 28 {
		out.CFListHex = hexString(b[12:28])
	}
	return out, nil
}

// reverseBytes returns a fresh slice with the bytes reversed —
// little-endian to big-endian on-the-fly for the EUI fields.
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// hexString renders bytes as uppercase hex with no separators.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention used across
// internal/ble / internal/emv / internal/eapol / internal/mifare
// / internal/ndef / internal/pocsag.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
