// Package zmtp decodes ZMTP (ZeroMQ Message Transport Protocol) wire
// frames — the transport layer for every ZeroMQ socket. Runs on any
// TCP port (commonly TCP/5555, 5556, TCP/5557; default ZMQ_REQ/REP
// services and financial-data feeds frequently bind on
// TCP/5555-5560; ZMTP also runs over Unix-domain sockets and
// raw TCP; some deployments bind on TCP/9000-9999 or TCP/4040
// Spark UI with ZMQ backend).
//
// Default ZeroMQ uses the NULL mechanism — NO authentication and
// NO encryption. Any process that can reach the TCP port can send
// and receive messages without credentials. ZeroMQ pub/sub with NULL
// mechanism allows unauthenticated subscription to any topic. PLAIN
// mechanism transmits username and password in cleartext. CURVE
// mechanism (CurveZMQ / NaCl box) is the only secure option.
//
// ZeroMQ is widely used in:
//   - High-frequency trading platforms and market-data feeds
//   - Scientific computing and distributed task-queue systems
//     (Jupyter notebook kernel protocol uses ZMTP)
//   - Distributed messaging in large-scale microservice deployments
//   - Industrial control and telemetry backplanes
//
// Shodan and ZGrab routinely discover exposed ZeroMQ ZMTP sockets
// on the public internet. Exposed sockets allow message injection,
// subscription interception, and in PUSH/PULL topologies arbitrary
// task injection into worker pools.
//
// The wire format leaks:
//
//   - **ZMTP version fingerprint** — version (major.minor) in the
//     64-byte greeting reveals whether the peer speaks ZMTP 3.0
//     (ZeroMQ ≥ 4.0), ZMTP 3.1 (ZeroMQ ≥ 4.2) or ZMTP 2.0
//     (ZeroMQ 3.x / 2.x legacy).
//
//   - **Security mechanism** — mechanism field in greeting is a
//     null-padded 20-byte string that names NULL / PLAIN / CURVE /
//     GSSAPI; NULL = no auth, PLAIN = cleartext creds, CURVE = NaCl
//     encrypted, GSSAPI = Kerberos.
//
//   - **Role disclosure** — as_server flag (1 = server endpoint).
//
//   - **Socket type + identity** — READY command properties contain
//     "Socket-Type" (REQ / REP / DEALER / ROUTER / PUB / SUB /
//     XPUB / XSUB / PUSH / PULL / PAIR / STREAM) and optionally
//     "Identity", revealing the topology role.
//
//   - **PING / PONG heartbeat** — ZMTP 3.1 heartbeat commands;
//     presence implies 3.1 capability.
//
// Wrap-vs-native judgement
//
//	Native. The ZMTP 3.x specification is publicly available at
//	https://rfc.zeromq.org/spec/37/ (ZMTP 3.0) and the successor
//	draft. The greeting is a fixed 64-byte structure with known
//	byte offsets. No crypto at the parse layer (CURVE payload is
//	opaque; only the mechanism name is decoded).
//
// What this package covers
//
//   - **64-byte ZMTP 3.x greeting** — signature (10 bytes:
//     0xFF + 8 padding + 0x7F) + version (2 bytes) + mechanism
//     (20 bytes) + as_server (1 byte) + filler (31 bytes).
//
//   - **ZMTP 2.0 greeting detection** — same 0xFF...0x7F signature
//     but version byte 0x01 at offset 10 + socket_type at offset 11.
//
//   - **Command frame walking** — flags byte (bit 2 = command) +
//     1-byte or 8-byte size (long frame bit 1) + 1-byte name_length
//
//   - command name + command data.
//
//   - **READY command property walker** — 4-byte BE name_length +
//     name + 4-byte BE value_length + value; surfaces Socket-Type
//     and Identity.
//
//   - **Security classification** — NULL flagged as unauthenticated;
//     PLAIN flagged as cleartext; CURVE as encrypted; GSSAPI as
//     Kerberos.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **CURVE / NaCl inner decryption** — encrypted payload is
//     opaque; only the mechanism name is decoded.
//
//   - **PLAIN credential extraction** — username + password in HELLO
//     command deliberately NOT decoded; only their presence is noted.
//
//   - **GSSAPI inner Kerberos blob** — use kerberos_decode.
//
//   - **Application message content** — message body bytes are
//     surfaced as total count only.
//
//   - **ZMTP over IPC / inproc** — same frame format but transport
//     is a Unix-domain socket or in-process queue; TCP captures only.
package zmtp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// greetingSize is the fixed size of a ZMTP 3.x greeting frame.
const greetingSize = 64

// sigByte0 is the first byte of every ZMTP greeting.
const sigByte0 = 0xFF

// sigByte9 is the byte at offset 9 in the ZMTP greeting.
const sigByte9 = 0x7F

// Result is the structured decode of a ZMTP wire-protocol frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Greeting fields
	IsGreeting    bool   `json:"is_greeting"`
	VersionMajor  int    `json:"version_major,omitempty"`
	VersionMinor  int    `json:"version_minor,omitempty"`
	Mechanism     string `json:"mechanism,omitempty"`
	MechanismName string `json:"mechanism_name,omitempty"`
	AsServer      bool   `json:"as_server,omitempty"`

	// Security classification
	IsCleartextAuth   bool   `json:"is_cleartext_auth,omitempty"`
	CleartextAuthFlag string `json:"cleartext_auth_flag,omitempty"`

	// READY command (follows greeting)
	SocketType string `json:"socket_type,omitempty"`
	Identity   string `json:"identity,omitempty"`

	// Frame classification
	IsCommand   bool   `json:"is_command,omitempty"`
	IsMessage   bool   `json:"is_message,omitempty"`
	CommandName string `json:"command_name,omitempty"`
}

// Decode parses a ZMTP wire-protocol frame from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty frame")
	}

	r := &Result{TotalBytes: len(b)}

	// Check for ZMTP greeting: 0xFF at offset 0 and 0x7F at offset 9.
	if len(b) >= 10 && b[0] == sigByte0 && b[9] == sigByte9 {
		return parseGreeting(r, b)
	}

	// Check for a ZMTP command or message frame.
	return parseFrame(r, b)
}

// parseGreeting decodes a ZMTP greeting (ZMTP 2.x or 3.x).
func parseGreeting(r *Result, b []byte) (*Result, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("zmtp greeting truncated (%d bytes; need at least 12)", len(b))
	}

	r.IsGreeting = true
	major := int(b[10])
	r.VersionMajor = major

	// ZMTP 2.0 has version byte 0x01 at offset 10 and a socket_type
	// byte at offset 11; it does not have the 20-byte mechanism field.
	if major <= 1 {
		r.VersionMajor = 2
		r.VersionMinor = 0
		if len(b) > 11 {
			r.SocketType = zmtp2SocketType(int(b[11]))
		}
		r.Mechanism = "NULL"
		r.MechanismName = "No authentication"
		return r, nil
	}

	// ZMTP 3.x requires at least 64 bytes.
	if len(b) < greetingSize {
		return nil, fmt.Errorf("zmtp 3.x greeting truncated (%d bytes; need %d)", len(b), greetingSize)
	}

	r.VersionMinor = int(b[11])

	// Mechanism: bytes 12..31 (20 bytes), null-terminated string.
	mechBytes := b[12:32]
	end := 0
	for end < len(mechBytes) && mechBytes[end] != 0 {
		end++
	}
	mech := string(mechBytes[:end])
	r.Mechanism = mech
	r.MechanismName = mechanismName(mech)

	if mech == "PLAIN" {
		r.IsCleartextAuth = true
		r.CleartextAuthFlag = "PLAIN mechanism transmits username and password in cleartext; passive TCP capture yields credentials immediately"
	}

	// as_server: byte 32.
	r.AsServer = b[32] != 0

	// If there are bytes beyond the 64-byte greeting, try to parse
	// the first command (typically a READY command with socket type).
	if len(b) > greetingSize {
		rest := b[greetingSize:]
		parseFirstCommand(r, rest)
	}

	return r, nil
}

// parseFrame decodes a ZMTP command or message frame that is not a
// greeting (i.e., sent after the greeting handshake).
func parseFrame(r *Result, b []byte) (*Result, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("zmtp frame truncated (%d bytes; need at least 2)", len(b))
	}

	flags := b[0]
	isCommand := (flags & 0x04) != 0
	isLong := (flags & 0x02) != 0

	if isCommand {
		r.IsCommand = true
	} else {
		r.IsMessage = true
	}

	// Determine the body offset after the size field.
	var bodyOff int
	if isLong {
		if len(b) < 9 {
			return nil, fmt.Errorf("zmtp long frame truncated (%d bytes; need 9)", len(b))
		}
		bodyOff = 9
	} else {
		bodyOff = 2
	}

	if isCommand && len(b) > bodyOff {
		body := b[bodyOff:]
		if len(body) >= 1 {
			nameLen := int(body[0])
			if 1+nameLen <= len(body) {
				r.CommandName = string(body[1 : 1+nameLen])
				// Walk READY properties if present.
				if r.CommandName == "READY" && 1+nameLen < len(body) {
					walkReadyProperties(r, body[1+nameLen:])
				}
			}
		}
	}

	return r, nil
}

// parseFirstCommand attempts to decode the first command frame
// immediately following the greeting (typically READY).
func parseFirstCommand(r *Result, b []byte) {
	if len(b) < 2 {
		return
	}
	flags := b[0]
	isCommand := (flags & 0x04) != 0
	if !isCommand {
		return
	}

	isLong := (flags & 0x02) != 0
	var bodyOff int
	if isLong {
		if len(b) < 9 {
			return
		}
		bodyOff = 9
	} else {
		bodyOff = 2
	}

	if len(b) <= bodyOff {
		return
	}
	body := b[bodyOff:]
	if len(body) < 1 {
		return
	}
	nameLen := int(body[0])
	if 1+nameLen > len(body) {
		return
	}
	cmdName := string(body[1 : 1+nameLen])
	r.IsCommand = true
	r.CommandName = cmdName
	if cmdName == "READY" && 1+nameLen < len(body) {
		walkReadyProperties(r, body[1+nameLen:])
	}
}

// walkReadyProperties decodes the READY command property list.
// Format: 4-byte BE name_length + name + 4-byte BE value_length + value.
func walkReadyProperties(r *Result, data []byte) {
	off := 0
	for off+4 <= len(data) {
		nameLen := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if nameLen < 0 || off+nameLen > len(data) {
			break
		}
		propName := string(data[off : off+nameLen])
		off += nameLen
		if off+4 > len(data) {
			break
		}
		valLen := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if valLen < 0 || off+valLen > len(data) {
			break
		}
		propVal := string(data[off : off+valLen])
		off += valLen

		switch propName {
		case "Socket-Type":
			r.SocketType = propVal
		case "Identity":
			r.Identity = propVal
		}
	}
}

// mechanismName returns a human-readable description of a ZMTP
// security mechanism string.
func mechanismName(mech string) string {
	switch mech {
	case "NULL":
		return "No authentication"
	case "PLAIN":
		return "Cleartext password"
	case "CURVE":
		return "CurveZMQ encryption"
	case "GSSAPI":
		return "Kerberos"
	}
	if mech == "" {
		return "No authentication"
	}
	return mech
}

// zmtp2SocketType maps a ZMTP 2.0 socket-type byte to a name.
func zmtp2SocketType(t int) string {
	switch t {
	case 0:
		return "PAIR"
	case 1:
		return "PUB"
	case 2:
		return "SUB"
	case 3:
		return "REQ"
	case 4:
		return "REP"
	case 5:
		return "DEALER"
	case 6:
		return "ROUTER"
	case 7:
		return "PULL"
	case 8:
		return "PUSH"
	}
	return fmt.Sprintf("socket_type_%d", t)
}

// stripSeparators removes whitespace and common hex-string separators
// from s and strips a leading 0x/0X prefix.
func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
