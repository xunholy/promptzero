// Package bfd decodes BFD Control packets per RFC 5880.
// BFD Echo packets (which are user-defined and opaque) and
// the multi-hop / S-BFD variants are not covered.
//
// Wrap-vs-native judgement
//
//	Native. RFC 5880 is fully public; BFD Control packets
//	have a tight 24-byte mandatory header with an optional
//	variable-length Authentication Section. No crypto, no
//	compression, no varints. Operators paste BFD bytes
//	(UDP dest port 3784 for single-hop or 4784 for multi-
//	hop) from a `tcpdump -X udp port 3784` line, a Wireshark
//	Follow-UDP-Stream view, a Quagga / FRR / BIRD / Juniper /
//	Cisco debug log, or any BFD-speaking router's tcpdump
//	and get the documented header + optional auth section.
//
// What this package covers
//
//   - **24-byte mandatory header** (RFC 5880 §4.1):
//
//   - byte 0: Version (3 bits; 1) + **Diagnostic** (5 bits)
//     with **9-entry name table**:
//
//   - 0 No Diagnostic
//
//   - 1 Control Detection Time Expired
//
//   - 2 Echo Function Failed
//
//   - 3 Neighbor Signaled Session Down
//
//   - 4 Forwarding Plane Reset
//
//   - 5 Path Down
//
//   - 6 Concatenated Path Down
//
//   - 7 Administratively Down
//
//   - 8 Reverse Concatenated Path Down
//
//   - byte 1: **State** (2 bits) with **4-entry name
//     table** (0 AdminDown, 1 Down, 2 Init, 3 Up) + **6
//     flag bits**: P (Poll), F (Final), C (Control Plane
//     Independent), A (Authentication Present), D (Demand
//     Mode), M (Multipoint, reserved).
//
//   - byte 2: Detect Mult — the number of consecutive
//     missed control packets before declaring the session
//     down.
//
//   - byte 3: Length — total BFD packet length in bytes
//     (24 for unauthenticated, 24+auth-section-length
//     for authenticated).
//
//   - bytes 4-7: My Discriminator (uint32 BE) — sender's
//     opaque session identifier.
//
//   - bytes 8-11: Your Discriminator (uint32 BE) — last
//     received My Discriminator from the peer; 0 until
//     the session is established.
//
//   - bytes 12-15: Desired Min TX Interval (uint32 BE
//     microseconds) — minimum interval the sender wants
//     to send control packets.
//
//   - bytes 16-19: Required Min RX Interval (uint32 BE
//     microseconds) — minimum interval the sender is
//     willing to accept control packets.
//
//   - bytes 20-23: Required Min Echo RX Interval (uint32
//     BE microseconds) — minimum interval the sender is
//     willing to accept Echo packets (0 disables Echo).
//
//   - **Authentication Section** (when A flag set):
//
//   - byte 0: **Auth Type** with **5-entry name table**:
//     1 Simple Password (cleartext), 2 Keyed MD5, 3
//     Meticulous Keyed MD5, 4 Keyed SHA1, 5 Meticulous
//     Keyed SHA1.
//
//   - byte 1: Auth Len — total length of the Authentication
//     Section including these 2 header bytes.
//
//   - byte 2: Auth Key ID — operator-chosen identifier
//     for the agreed key.
//
//   - bytes 3+: Auth Data — opaque per Auth Type:
//
//   - Simple Password: 1-16 byte cleartext password.
//
//   - Keyed MD5 / Meticulous Keyed MD5: 1-byte Reserved
//
//   - 4-byte Sequence Number + 16-byte MD5 digest.
//
//   - Keyed SHA1 / Meticulous Keyed SHA1: 1-byte
//     Reserved + 4-byte Sequence Number + 20-byte SHA1
//     digest.
//
//   - **Timing-microsecond → millisecond conversion** — the
//     three timing fields are surfaced both as raw
//     microseconds and converted to milliseconds for
//     human readability.
//
//   - **Conformance check** — Version != 1 surfaces a Note;
//     Length != actual buffer length surfaces a Note;
//     Detect Mult == 0 surfaces a Note (must be ≥ 1).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP / IP framing — feed the UDP payload bytes (after
//     the outer IP+UDP headers; standard UDP dest port 3784
//     single-hop or 4784 multi-hop per RFC 5882).
//
//   - BFD Echo packets — opaque user-defined format; the
//     receiver loops them back without inspection.
//
//   - S-BFD (Seamless BFD, RFC 7880) — uses a different
//     stateless approach with reserved Your Discriminators;
//     future Spec.
//
//   - Cryptographic verification — Auth Type 2-5 are
//     recognised but digest verification belongs in a
//     separate Spec.
//
//   - BFD-on-MPLS / BFD-for-VxLAN / BFD-for-Geneve — same
//     wire format but different encapsulations; the decoder
//     handles the BFD frame itself.
package bfd

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the top-level decoded view.
type Result struct {
	Version              int    `json:"version"`
	Diagnostic           int    `json:"diagnostic"`
	DiagnosticName       string `json:"diagnostic_name"`
	State                int    `json:"state"`
	StateName            string `json:"state_name"`
	FlagPoll             bool   `json:"flag_poll"`
	FlagFinal            bool   `json:"flag_final"`
	FlagCPI              bool   `json:"flag_control_plane_independent"`
	FlagAuth             bool   `json:"flag_authentication_present"`
	FlagDemand           bool   `json:"flag_demand_mode"`
	FlagMultipoint       bool   `json:"flag_multipoint"`
	FlagsHex             string `json:"flags_hex"`
	DetectMult           int    `json:"detect_multiplier"`
	LengthDeclared       int    `json:"length_declared"`
	MyDiscriminator      uint32 `json:"my_discriminator"`
	MyDiscriminatorHex   string `json:"my_discriminator_hex"`
	YourDiscriminator    uint32 `json:"your_discriminator"`
	YourDiscriminatorHex string `json:"your_discriminator_hex"`

	DesiredMinTXIntervalMicros      uint32 `json:"desired_min_tx_interval_us"`
	DesiredMinTXIntervalMs          int    `json:"desired_min_tx_interval_ms"`
	RequiredMinRXIntervalMicros     uint32 `json:"required_min_rx_interval_us"`
	RequiredMinRXIntervalMs         int    `json:"required_min_rx_interval_ms"`
	RequiredMinEchoRXIntervalMicros uint32 `json:"required_min_echo_rx_interval_us"`
	RequiredMinEchoRXIntervalMs     int    `json:"required_min_echo_rx_interval_ms"`

	Authentication *AuthSection `json:"authentication,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// AuthSection is the optional Authentication Section.
type AuthSection struct {
	Type           int     `json:"type"`
	TypeName       string  `json:"type_name"`
	Length         int     `json:"length"`
	KeyID          int     `json:"key_id"`
	DataHex        string  `json:"data_hex,omitempty"`
	SequenceNumber *uint32 `json:"sequence_number,omitempty"`
	DigestHex      string  `json:"digest_hex,omitempty"`
	PasswordText   string  `json:"password_text,omitempty"`
}

// Decode parses a single BFD Control packet from hex.
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
	if len(b) < 24 {
		return nil, fmt.Errorf("BFD Control packet truncated (%d bytes; need ≥24)",
			len(b))
	}

	r := &Result{
		TotalBytes:        len(b),
		Version:           int(b[0] >> 5),
		Diagnostic:        int(b[0] & 0x1F),
		State:             int(b[1] >> 6),
		FlagPoll:          b[1]&0x20 != 0,
		FlagFinal:         b[1]&0x10 != 0,
		FlagCPI:           b[1]&0x08 != 0,
		FlagAuth:          b[1]&0x04 != 0,
		FlagDemand:        b[1]&0x02 != 0,
		FlagMultipoint:    b[1]&0x01 != 0,
		FlagsHex:          fmt.Sprintf("0x%02X", b[1]&0x3F),
		DetectMult:        int(b[2]),
		LengthDeclared:    int(b[3]),
		MyDiscriminator:   binary.BigEndian.Uint32(b[4:8]),
		YourDiscriminator: binary.BigEndian.Uint32(b[8:12]),

		DesiredMinTXIntervalMicros:      binary.BigEndian.Uint32(b[12:16]),
		RequiredMinRXIntervalMicros:     binary.BigEndian.Uint32(b[16:20]),
		RequiredMinEchoRXIntervalMicros: binary.BigEndian.Uint32(b[20:24]),
	}
	r.DiagnosticName = diagnosticName(r.Diagnostic)
	r.StateName = stateName(r.State)
	r.MyDiscriminatorHex = fmt.Sprintf("0x%08X", r.MyDiscriminator)
	r.YourDiscriminatorHex = fmt.Sprintf("0x%08X", r.YourDiscriminator)
	r.DesiredMinTXIntervalMs = int(r.DesiredMinTXIntervalMicros / 1000)
	r.RequiredMinRXIntervalMs = int(r.RequiredMinRXIntervalMicros / 1000)
	r.RequiredMinEchoRXIntervalMs = int(r.RequiredMinEchoRXIntervalMicros / 1000)

	if r.Version != 1 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"BFD version is %d; RFC 5880 §4.1 currently defines only version 1",
			r.Version))
	}
	if r.DetectMult == 0 {
		r.Notes = append(r.Notes,
			"Detect Multiplier is 0 — RFC 5880 §4.1 requires it to be ≥1 (used to "+
				"compute the detection time as DetectMult × peer's TX Interval)")
	}
	if r.LengthDeclared != len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"declared Length %d != actual buffer length %d",
			r.LengthDeclared, len(b)))
	}

	if r.FlagAuth {
		if len(b) < 26 {
			return nil, fmt.Errorf("authentication section truncated (A flag set but " +
				"only 24 bytes present)")
		}
		auth, err := decodeAuth(b[24:])
		if err != nil {
			return nil, fmt.Errorf("authentication section: %w", err)
		}
		r.Authentication = auth
	}

	return r, nil
}

func decodeAuth(b []byte) (*AuthSection, error) {
	if len(b) < 3 {
		return nil, fmt.Errorf("auth header truncated (%d; need ≥3)", len(b))
	}
	a := &AuthSection{
		Type:   int(b[0]),
		Length: int(b[1]),
		KeyID:  int(b[2]),
	}
	a.TypeName = authTypeName(a.Type)
	// Auth Length (RFC 5880 §4.2) counts the whole auth section
	// including the 3-byte Type/Length/KeyID header, so it must be
	// at least 3. A smaller value (e.g. 0 from a malformed/garbage
	// packet) would make body := b[3:a.Length] an inverted slice
	// (b[3:0]) and panic. Reject anything outside [3, len(b)].
	if a.Length < 3 {
		return nil, fmt.Errorf("auth length %d below 3-byte header minimum", a.Length)
	}
	if a.Length > len(b) {
		return nil, fmt.Errorf("auth length %d exceeds %d available bytes",
			a.Length, len(b))
	}
	body := b[3:a.Length]
	a.DataHex = strings.ToUpper(hex.EncodeToString(body))

	switch a.Type {
	case 1: // Simple Password
		a.PasswordText = strings.ToValidUTF8(string(body), "")
	case 2, 3: // Keyed MD5 / Meticulous Keyed MD5
		if len(body) >= 1+4+16 {
			seq := binary.BigEndian.Uint32(body[1:5])
			a.SequenceNumber = &seq
			a.DigestHex = strings.ToUpper(hex.EncodeToString(body[5 : 5+16]))
		}
	case 4, 5: // Keyed SHA1 / Meticulous Keyed SHA1
		if len(body) >= 1+4+20 {
			seq := binary.BigEndian.Uint32(body[1:5])
			a.SequenceNumber = &seq
			a.DigestHex = strings.ToUpper(hex.EncodeToString(body[5 : 5+20]))
		}
	}
	return a, nil
}

func diagnosticName(d int) string {
	switch d {
	case 0:
		return "No Diagnostic"
	case 1:
		return "Control Detection Time Expired"
	case 2:
		return "Echo Function Failed"
	case 3:
		return "Neighbor Signaled Session Down"
	case 4:
		return "Forwarding Plane Reset"
	case 5:
		return "Path Down"
	case 6:
		return "Concatenated Path Down"
	case 7:
		return "Administratively Down"
	case 8:
		return "Reverse Concatenated Path Down"
	}
	return fmt.Sprintf("uncatalogued diagnostic %d", d)
}

func stateName(s int) string {
	switch s {
	case 0:
		return "AdminDown"
	case 1:
		return "Down"
	case 2:
		return "Init"
	case 3:
		return "Up"
	}
	return fmt.Sprintf("uncatalogued state %d", s)
}

func authTypeName(t int) string {
	switch t {
	case 1:
		return "Simple Password"
	case 2:
		return "Keyed MD5"
	case 3:
		return "Meticulous Keyed MD5"
	case 4:
		return "Keyed SHA1"
	case 5:
		return "Meticulous Keyed SHA1"
	}
	return fmt.Sprintf("uncatalogued auth type %d", t)
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
