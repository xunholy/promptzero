// Package eapol decodes EAPOL-Key frames — the WPA / WPA2 / WPA3
// 4-way handshake frames captured from any 802.1X-bearing
// medium. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: EAPOL is an IEEE standard (802.1X
// for the L2 frame, 802.11i for the Key descriptor format), all
// fully public. The walker is bit-level decoding over a 95+ byte
// frame. Wrapping a FAP for this would require an SD-card
// install + a firmware-fork dependency for a pure parser.
// Native delivers offline analysis (operators can paste a
// captured EAPOL frame from tcpdump / Wireshark / hcxdumptool /
// Marauder and inspect every field without a WiFi adapter
// attached), unit-testable round-trips, and an output shape that
// chains naturally into the existing marauder_handoff_hashcat
// flow (which converts captured frames to hashcat .hc22000).
//
// What this package covers:
//   - 802.1X frame header decode (version, type, body length)
//   - EAPOL-Key descriptor walk (key info bitfield, key length,
//     replay counter, nonce, IV, RSC, MIC, key data length, key
//     data)
//   - Key Information bitfield decode — descriptor version,
//     pairwise vs group, install / ack / mic / secure / error /
//     request / encrypted / SMK flags
//   - Handshake-message identification (M1 / M2 / M3 / M4 from
//     the Ack / MIC / Install / Secure flag combinations)
//   - Key Data Encapsulation (KDE) walker for the most common
//     elements: RSN IE, GTK, MAC address
//
// What this package does NOT cover (deliberately out of scope):
//   - PMK / PTK derivation (covered by `mfkey32_recover` /
//     hashcat / aircrack — the handshake gets handed off there)
//   - MIC validation (needs the derived PTK)
//   - Encrypted Key Data decryption (needs the KEK)
//   - Reassembling fragmented EAPOL across 802.11 frames
package eapol

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Header is the 802.1X frame header (4 bytes).
type Header struct {
	// Version is the 802.1X protocol version (1=WPA1/802.1X-2001,
	// 2=WPA2/802.1X-2004, 3=802.1X-2010).
	Version int `json:"version"`
	// Type is the EAPOL frame type (3 = EAPOL-Key).
	Type int `json:"type"`
	// TypeName is the human-readable type — "EAPOL-Key",
	// "EAPOL-Start", "EAPOL-Logoff", "EAPOL-Encapsulated-ASF-Alert".
	TypeName string `json:"type_name"`
	// BodyLength is the declared length of the frame body (after
	// the 4-byte header), big-endian uint16.
	BodyLength int `json:"body_length"`
}

// KeyInfo is the decoded 2-byte Key Information bitfield. The
// IEEE 802.11i flags drive the handshake message identification.
type KeyInfo struct {
	// Raw is the 2-byte field for callers that want bit-level
	// access.
	Raw int `json:"raw"`
	// DescriptorVersion is the 3-bit version field (bits 0-2):
	//   1 = ARC4-encrypted, HMAC-MD5 MIC (WPA / TKIP)
	//   2 = NIST-AES-encrypted, HMAC-SHA1 MIC (WPA2 / CCMP)
	//   3 = AES-128-CMAC MIC (802.11w PMF)
	DescriptorVersion int    `json:"descriptor_version"`
	DescriptorName    string `json:"descriptor_name"`
	// KeyType: bit 3. 1 = Pairwise (PTK), 0 = Group (GTK).
	KeyType     int    `json:"key_type"`
	KeyTypeName string `json:"key_type_name"`
	// KeyIndex (bits 4-5) — deprecated in WPA2, kept for WEP/WPA
	// compatibility.
	KeyIndex int  `json:"key_index"`
	Install  bool `json:"install"`
	KeyAck   bool `json:"key_ack"`
	KeyMIC   bool `json:"key_mic"`
	Secure   bool `json:"secure"`
	Error    bool `json:"error"`
	Request  bool `json:"request"`
	// EncryptedKeyData: bit 12 (WPA2/3). When set, the Key Data
	// field is encrypted with the KEK and we cannot dissect KDEs.
	EncryptedKeyData bool `json:"encrypted_key_data"`
	// SMK: bit 13 (Station-to-Station Link). Rare.
	SMK bool `json:"smk_message"`
}

// EAPOLKey is the structured view of an EAPOL-Key frame
// (descriptor type + key info + nonce + ... + key data).
type EAPOLKey struct {
	// Header is the parent 802.1X frame header.
	Header Header `json:"header"`
	// DescriptorType: 1 = RC4 (WPA1), 2 = RSN (WPA2/WPA3).
	DescriptorType     int    `json:"descriptor_type"`
	DescriptorTypeName string `json:"descriptor_type_name"`
	// KeyInfo is the decoded bitfield.
	KeyInfo KeyInfo `json:"key_info"`
	// HandshakeMessage is "M1", "M2", "M3", "M4", or "" when the
	// flag pattern doesn't match a documented message.
	HandshakeMessage string `json:"handshake_message,omitempty"`
	// KeyLength is the 2-byte BE length of the pairwise temporal
	// key (16 for TKIP, 16 for CCMP).
	KeyLength int `json:"key_length"`
	// ReplayCounter is the 8-byte BE replay counter. Same value
	// in both halves of an M1/M2 exchange.
	ReplayCounter string `json:"replay_counter"`
	// KeyNonce is the 32-byte ANonce (from AP) or SNonce (from
	// client) used in PTK derivation.
	KeyNonce string `json:"key_nonce"`
	// KeyIV is the 16-byte IV for the encrypted Key Data field.
	// Zero in pure CCMP setups; non-zero in TKIP.
	KeyIV string `json:"key_iv"`
	// KeyRSC is the 8-byte Receive Sequence Counter (for the
	// installed group key in M3).
	KeyRSC string `json:"key_rsc"`
	// KeyReserved is the 8-byte reserved field.
	KeyReserved string `json:"key_reserved"`
	// KeyMIC is the 16-byte Message Integrity Code (HMAC-SHA1 or
	// AES-CMAC over the rest of the frame). Zero in M1.
	KeyMIC string `json:"key_mic"`
	// KeyDataLength is the 2-byte BE length of the Key Data
	// field.
	KeyDataLength int `json:"key_data_length"`
	// KeyData is the raw Key Data hex. When EncryptedKeyData is
	// set we can't dissect; otherwise KDEs walks the substructure.
	KeyData string `json:"key_data"`
	// KDEs is the decoded list of Key Data Encapsulation
	// elements (RSN IE, GTK, MAC address). nil when KeyData is
	// encrypted or empty.
	KDEs []KDE `json:"kdes,omitempty"`
}

// KDE is one Key Data Encapsulation element. See IEEE
// 802.11-2020 §12.7.2 Table 12-9.
type KDE struct {
	// OUI is the 3-byte vendor identifier (00-0F-AC for IEEE).
	OUI string `json:"oui"`
	// DataType is the 1-byte KDE type:
	//   1 = GTK, 2 = MAC address, 4 = PMKID, 6 = IGTK, 7 = IGTK
	//   PN, 8 = WPA spec
	DataType int    `json:"data_type"`
	TypeName string `json:"type_name"`
	// Length is the total KDE length (after the type byte).
	Length int `json:"length"`
	// DataHex is the raw KDE data after the OUI / type / length
	// header.
	DataHex string `json:"data_hex"`
}

// Decode parses a hex-encoded EAPOL frame. Tolerates ':' / '-'
// / '_' / whitespace separators.
func Decode(hexBlob string) (EAPOLKey, error) {
	cleaned := stripSeparators(hexBlob)
	if cleaned == "" {
		return EAPOLKey{}, fmt.Errorf("eapol: empty input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return EAPOLKey{}, fmt.Errorf("eapol: invalid hex: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBytes is the byte-slice variant of Decode for callers
// that already have raw EAPOL bytes.
func DecodeBytes(b []byte) (EAPOLKey, error) {
	if len(b) < 4 {
		return EAPOLKey{}, fmt.Errorf("eapol: frame %d bytes < 4-byte 802.1X header", len(b))
	}
	hdr := Header{
		Version:    int(b[0]),
		Type:       int(b[1]),
		TypeName:   eapolTypeName(b[1]),
		BodyLength: int(binary.BigEndian.Uint16(b[2:4])),
	}
	if b[1] != 0x03 {
		return EAPOLKey{Header: hdr}, fmt.Errorf("eapol: frame type 0x%02X is not EAPOL-Key (0x03)", b[1])
	}
	const minKeyFrame = 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 + 2 // 99
	if len(b) < minKeyFrame {
		return EAPOLKey{Header: hdr}, fmt.Errorf("eapol: EAPOL-Key frame %d bytes < %d-byte minimum",
			len(b), minKeyFrame)
	}
	descType := b[4]
	keyInfoRaw := binary.BigEndian.Uint16(b[5:7])
	ki := decodeKeyInfo(keyInfoRaw)
	out := EAPOLKey{
		Header:             hdr,
		DescriptorType:     int(descType),
		DescriptorTypeName: descriptorTypeName(descType),
		KeyInfo:            ki,
		HandshakeMessage:   identifyMessage(ki),
		KeyLength:          int(binary.BigEndian.Uint16(b[7:9])),
		ReplayCounter:      hexString(b[9:17]),
		KeyNonce:           hexString(b[17:49]),
		KeyIV:              hexString(b[49:65]),
		KeyRSC:             hexString(b[65:73]),
		KeyReserved:        hexString(b[73:81]),
		KeyMIC:             hexString(b[81:97]),
		KeyDataLength:      int(binary.BigEndian.Uint16(b[97:99])),
	}
	kdLen := out.KeyDataLength
	if kdLen > 0 {
		if 99+kdLen > len(b) {
			return out, fmt.Errorf("eapol: key data length %d exceeds remaining frame bytes %d",
				kdLen, len(b)-99)
		}
		keyData := b[99 : 99+kdLen]
		out.KeyData = hexString(keyData)
		if !ki.EncryptedKeyData {
			out.KDEs = parseKDEs(keyData)
		}
	}
	return out, nil
}

// decodeKeyInfo unpacks the 2-byte Key Information bitfield.
func decodeKeyInfo(raw uint16) KeyInfo {
	ver := int(raw & 0x07)
	keyType := int((raw >> 3) & 0x01)
	ki := KeyInfo{
		Raw:               int(raw),
		DescriptorVersion: ver,
		DescriptorName:    descriptorVersionName(ver),
		KeyType:           keyType,
		KeyTypeName:       keyTypeName(keyType),
		KeyIndex:          int((raw >> 4) & 0x03),
		Install:           raw&0x0040 != 0,
		KeyAck:            raw&0x0080 != 0,
		KeyMIC:            raw&0x0100 != 0,
		Secure:            raw&0x0200 != 0,
		Error:             raw&0x0400 != 0,
		Request:           raw&0x0800 != 0,
		EncryptedKeyData:  raw&0x1000 != 0,
		SMK:               raw&0x2000 != 0,
	}
	return ki
}

// identifyMessage matches the flag pattern to a 4-way handshake
// message:
//
//	M1: Ack=1, MIC=0, Install=0, Secure=0 — AP sends ANonce
//	M2: Ack=0, MIC=1, Install=0, Secure=0 — STA sends SNonce
//	M3: Ack=1, MIC=1, Install=1            — AP installs PTK
//	M4: Ack=0, MIC=1, Install=0, Secure=1 — STA confirms
//
// Returns "" when the pattern doesn't match any of the four.
func identifyMessage(ki KeyInfo) string {
	if ki.KeyType != 1 {
		return ""
	}
	switch {
	case ki.KeyAck && !ki.KeyMIC && !ki.Install && !ki.Secure:
		return "M1"
	case !ki.KeyAck && ki.KeyMIC && !ki.Install && !ki.Secure:
		return "M2"
	case ki.KeyAck && ki.KeyMIC && ki.Install:
		return "M3"
	case !ki.KeyAck && ki.KeyMIC && !ki.Install && ki.Secure:
		return "M4"
	}
	return ""
}

// parseKDEs walks the Key Data field as a sequence of KDEs and
// vendor IEs. Each KDE: type byte (0xDD), length byte, OUI (3
// bytes), data type (1 byte), then `length-4` bytes of data.
// RSN IE (0x30) is also commonly embedded — we surface it as a
// pseudo-KDE with OUI "rsn".
//
// Returns the parsed list. Stops walking on the first
// length-mismatch so a malformed KDE doesn't drop the rest of
// the field silently.
func parseKDEs(b []byte) []KDE {
	var out []KDE
	off := 0
	for off < len(b) {
		// Vendor-specific KDE header: 0xDD, length, OUI(3), type(1), data.
		if b[off] == 0xDD {
			if off+2 > len(b) {
				return out
			}
			l := int(b[off+1])
			if off+2+l > len(b) {
				return out
			}
			body := b[off+2 : off+2+l]
			if len(body) >= 4 {
				out = append(out, KDE{
					OUI:      hexString(body[0:3]),
					DataType: int(body[3]),
					TypeName: kdeTypeName(body[3]),
					Length:   l,
					DataHex:  hexString(body[4:]),
				})
			}
			off += 2 + l
			continue
		}
		// RSN IE: 0x30, length, then RSN body.
		if b[off] == 0x30 {
			if off+2 > len(b) {
				return out
			}
			l := int(b[off+1])
			if off+2+l > len(b) {
				return out
			}
			out = append(out, KDE{
				OUI:      "rsn",
				DataType: 0x30,
				TypeName: "RSN Information Element",
				Length:   l,
				DataHex:  hexString(b[off+2 : off+2+l]),
			})
			off += 2 + l
			continue
		}
		// Unknown / padding byte. Stop walking.
		return out
	}
	return out
}

func eapolTypeName(t byte) string {
	switch t {
	case 0:
		return "EAP-Packet"
	case 1:
		return "EAPOL-Start"
	case 2:
		return "EAPOL-Logoff"
	case 3:
		return "EAPOL-Key"
	case 4:
		return "EAPOL-Encapsulated-ASF-Alert"
	}
	return "Reserved"
}

func descriptorTypeName(t byte) string {
	switch t {
	case 1:
		return "RC4 (WPA1)"
	case 2:
		return "RSN (WPA2 / WPA3)"
	}
	return "Reserved"
}

func descriptorVersionName(v int) string {
	switch v {
	case 1:
		return "HMAC-MD5 MIC + ARC4 encryption (TKIP)"
	case 2:
		return "HMAC-SHA1 MIC + AES encryption (CCMP)"
	case 3:
		return "AES-128-CMAC MIC (PMF / 802.11w)"
	}
	return "Reserved"
}

func keyTypeName(t int) string {
	if t == 1 {
		return "Pairwise (PTK)"
	}
	return "Group (GTK)"
}

func kdeTypeName(t byte) string {
	switch t {
	case 0:
		return "Reserved"
	case 1:
		return "GTK"
	case 2:
		return "MAC address"
	case 3:
		return "PMKID (deprecated)"
	case 4:
		return "PMKID"
	case 5:
		return "SMK"
	case 6:
		return "IGTK"
	case 7:
		return "IGTK packet number"
	case 8:
		return "WPA specification"
	}
	return "Vendor / unknown"
}

// hexString is the uppercase no-separator hex helper used across
// the package.
func hexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// stripSeparators mirrors the convention in internal/ble /
// internal/emv / internal/mifare / internal/ndef.
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
