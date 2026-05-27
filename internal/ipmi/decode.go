// Package ipmi decodes IPMI (Intelligent Platform Management Interface)
// messages carried over RMCP (Remote Management Control Protocol) on
// UDP/623. Covers IPMI 1.5 (auth_type != 0x06) and IPMI 2.0 / RMCP+
// (auth_type == 0x06) session headers, plus the inner IPMI message
// frame. Implements no cryptographic operations — all payloads that
// are encrypted are surfaced as opaque byte counts.
//
// Operationally, IPMI is a **critical-severity datacenter BMC surface**
// — every server sold since 1998 includes an out-of-band management
// controller (iLO on HPE, iDRAC on Dell, IMM/XCC on Lenovo, ASMB on
// ASUS, BMC on Supermicro) that speaks IPMI over UDP/623. The BMC
// runs independently of the host OS, persists across reboots, and has
// full power-cycle, firmware-flash, and console-redirection access.
//
// The wire format leaks:
//
//   - **Get Channel Auth Capabilities (NetFn 0x06, cmd 0x38)** —
//     THE canonical pre-auth enumeration command. Every pentest script
//     (ipmitool, metasploit auxiliary/scanner/ipmi/ipmi_version,
//     ipmi-scan) sends this first. The response reveals: supported
//     auth types (None / MD2 / MD5 / Password / OEM), whether IPMI
//     2.0 is available, and supported cipher suites. Auth type None
//     = unauthenticated access, cipher suite 0 = no auth at all
//     (CVE-2013-4786).
//
//   - **Cipher Suite 0 (CVE-2013-4786)** — IPMI 2.0 mandates cipher
//     suite 0 be supported; suite 0 = RAKP-None authentication with
//     no integrity and no confidentiality. Many BMCs accept commands
//     via suite 0 without credentials. Dan Farmer's 2013 "Sold Down
//     the River" paper catalogued this across major vendors; it was
//     present in iDRAC, iLO, IMM, and Supermicro BMCs.
//
//   - **RAKP Message 2 (payload_type 0x13)** — during RMCP+
//     authentication, the BMC responds to the client's RAKP-1 with
//     RAKP-2 which includes a HMAC-SHA1 hash computed over the session
//     IDs + random nonces + username. This hash is offline-crackable
//     with hashcat mode 7300 ("IPMI2 RAKP HMAC-SHA1"). Any unauthenticated
//     client can trigger RAKP-2 and capture the hash.
//
//   - **Get Device ID (NetFn 0x06, cmd 0x01)** — firmware version
//     fingerprint. The response reveals device ID, firmware revision,
//     IPMI version, manufacturer ID (IANA PEN), and product ID.
//     Canonical pre-exploit version check.
//
//   - **Default credentials** — iDRAC 6/7/8 ship root/calvin; iLO
//     ships Administrator/<serial>; Supermicro ships ADMIN/ADMIN;
//     many IMM/XCC ship USERID/PASSW0RD. Shodan finds tens of
//     thousands of IPMI endpoints; ipmitool's default admin/admin
//     succeeds on a startling fraction of unpatched BMCs.
//
// Wrap-vs-native judgement:
//
//	Native. The RMCP specification (ASF 2.0) and IPMI specifications
//	(v1.5 IPMI-Spec-V1.5 / v2.0 IPMI-Spec-V2-Rev1.1) are publicly
//	available. The RMCP header is 4 bytes; the IPMI session wrappers
//	are 9 bytes (v1.5 without auth) / 13+16 bytes (v1.5 with auth) /
//	12 bytes (RMCP+). The inner IPMI message header is 6 bytes. No
//	crypto at the parse layer.
//
// What this package covers:
//
//   - **RMCP header**: version (must be 0x06) + reserved + sequence +
//     message class (0x07 = IPMI, 0x06 = ASF).
//
//   - **IPMI 1.5 session header**: auth_type (0x00=None, 0x01=MD2,
//     0x02=MD5, 0x04=Password, 0x05=OEM) + session_seq (4 LE) +
//     session_id (4 LE) + optional auth_code (16 bytes when
//     auth_type != 0) + message_length (1 byte).
//
//   - **IPMI 2.0 / RMCP+ session header**: auth_type=0x06 +
//     payload_type byte (encrypted/authenticated bits + 6-bit type) +
//     session_id (4 LE) + session_seq (4 LE) + payload_length (2 LE).
//     payload_type values: 0x00=IPMI, 0x10=Open Session Request,
//     0x11=Open Session Response, 0x12=RAKP Message 1,
//     0x13=RAKP Message 2, 0x14=RAKP Message 3, 0x15=RAKP Message 4.
//
//   - **IPMI message**: rsAddr (target, 0x20=BMC) + netFn/rsLUN
//     (upper 6 bits = netFn, lower 2 = rsLUN) + checksum1 + rqAddr
//     (source) + rqSeq/rqLUN + command + data[...] + checksum2.
//
//   - **NetFn + command name table**: NetFn 0x06 App (Get Device ID,
//     Get Channel Auth Capabilities, Get Session Challenge, Activate
//     Session, Close Session, Get Channel Cipher Suites, Get System
//     GUID); NetFn 0x0A Storage (Get SEL Info); NetFn 0x0C Transport;
//     NetFn 0x2C Group Extension.
//
//   - **Security classification**: is_auth_probe (Get Channel Auth
//     Capabilities — THE recon command), is_version_probe (Get Device
//     ID), is_rakp_exchange (RAKP Message 1-4), is_cipher_suite_zero
//     (CVE-2013-4786 no-auth path).
//
// What this package does NOT cover (deliberately out of scope):
//
//   - **Response parsing** — IPMI responses follow command-specific
//     layouts; the decoder focuses on requests where the operator
//     controls the input.
//   - **Payload decryption** — encrypted RMCP+ payloads (AES-CBC-128
//     or xRC4) are surfaced as byte counts only.
//   - **RAKP hash extraction** — RAKP-2 contains the HMAC-SHA1
//     offline-crackable material; the decoder surfaces the payload
//     type name but does not extract the hash bytes.
//   - **ASF (Alert Standard Format, class 0x06)** — ASF Presence
//     Ping / Pong on the same port; surfaced as class_name only.
//   - **Serial-over-LAN (SoL)** — payload type 0x01, complex framing.
package ipmi

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of an IPMI/RMCP datagram.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// RMCP header
	RMCPVersion   int    `json:"rmcp_version"`
	RMCPSequence  int    `json:"rmcp_sequence"`
	RMCPClass     int    `json:"rmcp_class"`
	RMCPClassName string `json:"rmcp_class_name"`

	// Session header (common to 1.5 and 2.0)
	AuthType     int    `json:"auth_type"`
	AuthTypeName string `json:"auth_type_name"`
	SessionID    uint32 `json:"session_id"`
	SessionSeq   uint32 `json:"session_seq"`

	// RMCP+ (IPMI 2.0) specific
	IsRMCPPlus           bool   `json:"is_rmcp_plus"`
	PayloadType          int    `json:"payload_type,omitempty"`
	PayloadTypeName      string `json:"payload_type_name,omitempty"`
	PayloadEncrypted     bool   `json:"payload_encrypted,omitempty"`
	PayloadAuthenticated bool   `json:"payload_authenticated,omitempty"`
	PayloadLength        int    `json:"payload_length,omitempty"`

	// IPMI message fields (populated when payload is parsed as IPMI message)
	RsAddr      int    `json:"rs_addr,omitempty"`
	RqAddr      int    `json:"rq_addr,omitempty"`
	NetFn       int    `json:"net_fn,omitempty"`
	NetFnName   string `json:"net_fn_name,omitempty"`
	RsLUN       int    `json:"rs_lun,omitempty"`
	RqSeq       int    `json:"rq_seq,omitempty"`
	RqLUN       int    `json:"rq_lun,omitempty"`
	Command     int    `json:"command,omitempty"`
	CommandName string `json:"command_name,omitempty"`

	// Security flags
	IsAuthProbe       bool `json:"is_auth_probe"`
	IsVersionProbe    bool `json:"is_version_probe"`
	IsRAKPExchange    bool `json:"is_rakp_exchange"`
	IsCipherSuiteZero bool `json:"is_cipher_suite_zero"`
}

const rmcpHeaderSize = 4 // version(1) + reserved(1) + sequence(1) + class(1)

// Decode parses an IPMI/RMCP datagram from a hex string.
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
	if len(b) < rmcpHeaderSize {
		return nil, fmt.Errorf("rmcp header truncated (%d bytes; need %d)", len(b), rmcpHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	// RMCP header
	r.RMCPVersion = int(b[0])
	// b[1] is reserved
	r.RMCPSequence = int(b[2])
	r.RMCPClass = int(b[3])
	r.RMCPClassName = rmcpClassName(r.RMCPClass)

	if r.RMCPVersion != 0x06 {
		return nil, fmt.Errorf("rmcp version 0x%02x is not 0x06", r.RMCPVersion)
	}

	off := rmcpHeaderSize
	if off >= len(b) {
		return nil, fmt.Errorf("rmcp payload truncated after header")
	}

	authType := int(b[off])
	r.AuthType = authType
	r.AuthTypeName = authTypeName(authType)
	off++

	if authType == 0x06 {
		// IPMI 2.0 / RMCP+ session header
		r.IsRMCPPlus = true
		if off+11 > len(b) {
			return nil, fmt.Errorf("rmcp+ session header truncated (%d bytes remaining; need 11)", len(b)-off)
		}
		payloadTypeByte := b[off]
		off++
		r.PayloadEncrypted = (payloadTypeByte & 0x80) != 0
		r.PayloadAuthenticated = (payloadTypeByte & 0x40) != 0
		rawPayloadType := int(payloadTypeByte & 0x3F)
		r.PayloadType = rawPayloadType
		r.PayloadTypeName = payloadTypeName(rawPayloadType)

		r.SessionID = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		r.SessionSeq = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		if off+2 > len(b) {
			return nil, fmt.Errorf("rmcp+ payload_length field truncated")
		}
		r.PayloadLength = int(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2

		classifyRMCPPlus(r)

		// For non-encrypted IPMI payload type 0x00, try to decode the inner message
		if rawPayloadType == 0x00 && !r.PayloadEncrypted && off < len(b) {
			parseIPMIMessage(r, b[off:])
		}
	} else {
		// IPMI 1.5 session header
		if off+8 > len(b) {
			return nil, fmt.Errorf("ipmi 1.5 session header truncated (%d bytes remaining; need 8)", len(b)-off)
		}
		r.SessionSeq = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		r.SessionID = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4

		// auth_code is present when auth_type != 0
		if authType != 0x00 {
			if off+16 > len(b) {
				return nil, fmt.Errorf("ipmi 1.5 auth_code truncated (%d bytes remaining; need 16)", len(b)-off)
			}
			off += 16 // skip auth_code (16 bytes)
		}

		if off >= len(b) {
			return nil, fmt.Errorf("ipmi 1.5 message_length field missing")
		}
		// message_length tells us how many bytes follow (the IPMI message itself)
		off++ // skip message_length byte

		if off < len(b) {
			parseIPMIMessage(r, b[off:])
		}
	}

	return r, nil
}

// parseIPMIMessage decodes the inner IPMI LAN message.
// Minimum valid message is 7 bytes:
// rsAddr(1) + netFn/rsLUN(1) + checksum1(1) + rqAddr(1) + rqSeq/rqLUN(1) + command(1) + checksum2(1)
func parseIPMIMessage(r *Result, msg []byte) {
	if len(msg) < 6 {
		return
	}
	r.RsAddr = int(msg[0])
	netFnLUN := msg[1]
	r.NetFn = int(netFnLUN >> 2)
	r.RsLUN = int(netFnLUN & 0x03)
	r.NetFnName = netFnName(r.NetFn)
	// msg[2] = checksum1
	r.RqAddr = int(msg[3])
	rqSeqLUN := msg[4]
	r.RqSeq = int(rqSeqLUN >> 2)
	r.RqLUN = int(rqSeqLUN & 0x03)
	r.Command = int(msg[5])
	r.CommandName = commandName(r.NetFn, r.Command)

	classifyCommand(r)
}

func classifyRMCPPlus(r *Result) {
	switch r.PayloadType {
	case 0x12, 0x13, 0x14, 0x15:
		r.IsRAKPExchange = true
	}
}

func classifyCommand(r *Result) {
	if r.NetFn == 0x06 {
		switch r.Command {
		case 0x38:
			r.IsAuthProbe = true
		case 0x01:
			r.IsVersionProbe = true
		case 0x54:
			// Get Channel Cipher Suites — cipher suite 0 probe
			// We flag this as a cipher suite zero probe since the
			// purpose of this command is to enumerate cipher suites
			// including suite 0 (CVE-2013-4786).
			r.IsCipherSuiteZero = true
		}
	}
}

func rmcpClassName(class int) string {
	switch class {
	case 0x06:
		return "ASF"
	case 0x07:
		return "IPMI"
	}
	return fmt.Sprintf("class_0x%02x", class)
}

func authTypeName(t int) string {
	switch t {
	case 0x00:
		return "None"
	case 0x01:
		return "MD2"
	case 0x02:
		return "MD5"
	case 0x04:
		return "Password"
	case 0x05:
		return "OEM"
	case 0x06:
		return "RMCP+"
	}
	return fmt.Sprintf("auth_0x%02x", t)
}

func payloadTypeName(t int) string {
	switch t {
	case 0x00:
		return "IPMI"
	case 0x01:
		return "SOL"
	case 0x10:
		return "Open Session Request"
	case 0x11:
		return "Open Session Response"
	case 0x12:
		return "RAKP Message 1"
	case 0x13:
		return "RAKP Message 2"
	case 0x14:
		return "RAKP Message 3"
	case 0x15:
		return "RAKP Message 4"
	}
	return fmt.Sprintf("payload_0x%02x", t)
}

func netFnName(netFn int) string {
	switch netFn {
	case 0x06:
		return "App"
	case 0x07:
		return "App Response"
	case 0x0A:
		return "Storage"
	case 0x0B:
		return "Storage Response"
	case 0x0C:
		return "Transport"
	case 0x0D:
		return "Transport Response"
	case 0x2C:
		return "Group Extension"
	case 0x2D:
		return "Group Extension Response"
	}
	return fmt.Sprintf("netfn_0x%02x", netFn)
}

func commandName(netFn, cmd int) string {
	switch netFn {
	case 0x06: // App
		switch cmd {
		case 0x01:
			return "Get Device ID"
		case 0x06:
			return "Get System GUID"
		case 0x38:
			return "Get Channel Auth Capabilities"
		case 0x39:
			return "Get Session Challenge"
		case 0x3A:
			return "Activate Session"
		case 0x3C:
			return "Close Session"
		case 0x54:
			return "Get Channel Cipher Suites"
		}
	case 0x0A: // Storage
		switch cmd {
		case 0x44:
			return "Get SEL Info"
		}
	}
	return fmt.Sprintf("cmd_0x%02x", cmd)
}

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
