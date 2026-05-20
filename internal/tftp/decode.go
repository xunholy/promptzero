// Package tftp decodes TFTP (Trivial File Transfer Protocol)
// packets per RFC 1350, with the Option Extension family from
// RFC 2347 (envelope) + RFC 2348 (blksize) + RFC 2349 (timeout
// + tsize) + RFC 7440 (windowsize). TFTP is the canonical
// minimal file-transfer protocol; despite its 1981 vintage it
// remains the dominant transport for:
//
//   - **PXE / network boot** — every PXE-booting machine
//     fetches its boot loader (`pxelinux.0`, `wdsnbp.com`,
//     `ipxe.efi`) and kernel + initrd over TFTP.
//
//   - **IoT firmware updates** — most embedded devices
//     (routers, switches, IP cameras, smart plugs, factory
//     equipment) fetch firmware via TFTP because it fits
//     in 2 KB of ROM.
//
//   - **Network device config push** — every Cisco / Juniper
//     / Arista shop uses TFTP for `copy running-config tftp:`
//     and `copy tftp: flash:` workflows.
//
// Wrap-vs-native judgement
//
//	Native. RFC 1350 + 2347 are fully public; TFTP packets
//	have a tight 2-byte opcode + per-opcode body — no
//	crypto, no compression, no fancy framing. Operators
//	paste TFTP bytes (UDP destination port 69 server-side
//	or the ephemeral port the server picked for an active
//	transfer) from a `tcpdump -X udp port 69` line or a
//	Wireshark Follow-UDP-Stream view and get the documented
//	opcode + body breakdown.
//
// What this package covers
//
//   - **2-byte Opcode** (RFC 1350 §5) with **6-entry name
//     table**: 1 RRQ (Read Request), 2 WRQ (Write Request),
//     3 DATA, 4 ACK, 5 ERROR, 6 OACK (Option Acknowledgment;
//     RFC 2347).
//
//   - **RRQ / WRQ body** (Types 1 + 2):
//
//   - **Filename** (null-terminated UTF-8).
//
//   - **Mode** (null-terminated UTF-8) — RFC 1350 defines
//     "netascii", "octet" (the binary mode most operators
//     use), and the deprecated "mail" mode.
//
//   - **Options** (RFC 2347) — zero or more (name, value)
//     pairs, each null-terminated. **4-entry option name
//     table**: blksize (RFC 2348 — block-size override,
//     default 512), timeout (RFC 2349 — retransmit
//     timeout in seconds), tsize (RFC 2349 — transfer
//     size in bytes; client sends 0 to request the
//     server's value), windowsize (RFC 7440 — number of
//     DATA blocks the sender can transmit before
//     expecting an ACK).
//
//   - **DATA body** (Type 3):
//
//   - **Block Number** (uint16 BE; starts at 1, wraps to
//     0 after 65535 — the rollover is silently the
//     reason for the long-standing 32 MB classic TFTP
//     transfer cap, lifted by the windowsize + blksize
//     options).
//
//   - **Payload** (variable, up to the negotiated blksize
//     — default 512 bytes; a short payload signals the
//     last block).
//
//   - **ACK body** (Type 4):
//
//   - **Block Number** being acknowledged.
//
//   - **ERROR body** (Type 5):
//
//   - **Error Code** (uint16 BE) with **9-entry name
//     table**: 0 Not defined / 1 File not found / 2
//     Access violation / 3 Disk full or allocation
//     exceeded / 4 Illegal TFTP operation / 5 Unknown
//     transfer ID / 6 File already exists / 7 No such
//     user / 8 Option negotiation failure (RFC 2347).
//
//   - **Error Message** (null-terminated UTF-8).
//
//   - **OACK body** (Type 6) — same option-list layout as
//     the options portion of RRQ/WRQ; the server replies
//     with the option values it has agreed to.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - UDP framing — feed TFTP bytes after the UDP header
//     strip. TFTP runs on UDP destination port 69 server-
//     side or the ephemeral port the server picked for
//     transfer-data continuation.
//
//   - TFTP state-machine reasoning (block-number windowing,
//     retransmit-after-timeout logic, lockstep ACK
//     ordering) — higher-level analysis.
//
//   - Reassembly of the file payload across DATA blocks —
//     each DATA block is decoded standalone; concatenating
//     them is collector-side work.
package tftp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view of a TFTP packet.
type Result struct {
	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`

	// One of the following is populated per opcode.
	RRQ   *RequestBody `json:"rrq,omitempty"`
	WRQ   *RequestBody `json:"wrq,omitempty"`
	DATA  *DataBody    `json:"data,omitempty"`
	ACK   *AckBody     `json:"ack,omitempty"`
	ERROR *ErrorBody   `json:"error,omitempty"`
	OACK  *OackBody    `json:"oack,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// RequestBody is the decoded body of RRQ (Type 1) or WRQ
// (Type 2) packets.
type RequestBody struct {
	Filename string   `json:"filename"`
	Mode     string   `json:"mode"`
	Options  []Option `json:"options,omitempty"`
}

// DataBody is the decoded body of DATA (Type 3) packets.
type DataBody struct {
	BlockNumber       int    `json:"block_number"`
	PayloadBytes      int    `json:"payload_bytes"`
	PayloadBytesShown int    `json:"payload_bytes_shown,omitempty"`
	PayloadHex        string `json:"payload_hex,omitempty"`
	PayloadText       string `json:"payload_text,omitempty"`
}

// AckBody is the decoded body of ACK (Type 4) packets.
type AckBody struct {
	BlockNumber int `json:"block_number"`
}

// ErrorBody is the decoded body of ERROR (Type 5) packets.
type ErrorBody struct {
	ErrorCode    int    `json:"error_code"`
	ErrorName    string `json:"error_name"`
	ErrorMessage string `json:"error_message"`
}

// OackBody is the decoded body of OACK (Type 6) packets.
type OackBody struct {
	Options []Option `json:"options"`
}

// Option is one (name, value) option pair from a RRQ / WRQ /
// OACK body.
type Option struct {
	Name      string `json:"name"`
	NameKnown string `json:"name_known,omitempty"`
	Value     string `json:"value"`
}

// DecodeOpts tunes the walker for output size.
type DecodeOpts struct {
	// MaxPayloadBytes caps the per-DATA hex preview. Zero
	// surfaces the entire payload (which can be up to the
	// negotiated blksize, often 64 KB).
	MaxPayloadBytes int
}

// DefaultDecodeOpts returns a 256-byte payload preview cap.
func DefaultDecodeOpts() DecodeOpts {
	return DecodeOpts{MaxPayloadBytes: 256}
}

// Decode parses a single TFTP packet from hex.
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
		return nil, fmt.Errorf("TFTP packet truncated (%d bytes; need ≥2 for opcode)",
			len(b))
	}
	r := &Result{
		TotalBytes: len(b),
		Opcode:     int(binary.BigEndian.Uint16(b[0:2])),
	}
	r.OpcodeName = opcodeName(r.Opcode)
	body := b[2:]
	switch r.Opcode {
	case 1:
		r.RRQ = decodeRequest(body, r)
	case 2:
		r.WRQ = decodeRequest(body, r)
	case 3:
		r.DATA = decodeData(body, opts, r)
	case 4:
		r.ACK = decodeAck(body, r)
	case 5:
		r.ERROR = decodeError(body, r)
	case 6:
		r.OACK = &OackBody{Options: decodeOptions(body)}
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"uncatalogued TFTP opcode %d (RFC 1350 + RFC 2347 define 1-6)", r.Opcode))
	}
	return r, nil
}

func decodeRequest(b []byte, r *Result) *RequestBody {
	parts := splitNullTerminated(b)
	if len(parts) < 2 {
		r.Notes = append(r.Notes,
			"request body missing filename or mode (need ≥2 null-terminated strings)")
		return &RequestBody{}
	}
	req := &RequestBody{
		Filename: parts[0],
		Mode:     strings.ToLower(parts[1]),
	}
	if len(parts) >= 4 {
		for i := 2; i+1 < len(parts); i += 2 {
			req.Options = append(req.Options, makeOption(parts[i], parts[i+1]))
		}
	}
	return req
}

func decodeData(b []byte, opts DecodeOpts, r *Result) *DataBody {
	if len(b) < 2 {
		r.Notes = append(r.Notes, "DATA body < 2 bytes (no block number)")
		return &DataBody{}
	}
	d := &DataBody{
		BlockNumber:  int(binary.BigEndian.Uint16(b[0:2])),
		PayloadBytes: len(b) - 2,
	}
	payload := b[2:]
	if len(payload) > 0 {
		show := len(payload)
		if opts.MaxPayloadBytes > 0 && show > opts.MaxPayloadBytes {
			show = opts.MaxPayloadBytes
		}
		d.PayloadHex = strings.ToUpper(hex.EncodeToString(payload[:show]))
		d.PayloadBytesShown = show
		if utf8.Valid(payload[:show]) && looksTextual(payload[:show]) {
			d.PayloadText = string(payload[:show])
		}
	}
	return d
}

func decodeAck(b []byte, r *Result) *AckBody {
	if len(b) < 2 {
		r.Notes = append(r.Notes, "ACK body < 2 bytes (no block number)")
		return &AckBody{}
	}
	return &AckBody{
		BlockNumber: int(binary.BigEndian.Uint16(b[0:2])),
	}
}

func decodeError(b []byte, r *Result) *ErrorBody {
	if len(b) < 2 {
		r.Notes = append(r.Notes, "ERROR body < 2 bytes (no error code)")
		return &ErrorBody{}
	}
	e := &ErrorBody{
		ErrorCode: int(binary.BigEndian.Uint16(b[0:2])),
	}
	e.ErrorName = errorName(e.ErrorCode)
	if len(b) > 2 {
		msg := b[2:]
		// Drop trailing null if present.
		if msg[len(msg)-1] == 0 {
			msg = msg[:len(msg)-1]
		}
		if utf8.Valid(msg) {
			e.ErrorMessage = string(msg)
		} else {
			e.ErrorMessage = strings.ToUpper(hex.EncodeToString(msg))
		}
	}
	return e
}

func decodeOptions(b []byte) []Option {
	parts := splitNullTerminated(b)
	var out []Option
	for i := 0; i+1 < len(parts); i += 2 {
		out = append(out, makeOption(parts[i], parts[i+1]))
	}
	return out
}

func makeOption(name, value string) Option {
	o := Option{Name: name, Value: value}
	switch strings.ToLower(name) {
	case "blksize":
		o.NameKnown = "Block Size (RFC 2348)"
	case "timeout":
		o.NameKnown = "Retransmit Timeout (RFC 2349)"
	case "tsize":
		o.NameKnown = "Transfer Size (RFC 2349)"
	case "windowsize":
		o.NameKnown = "Window Size (RFC 7440)"
	}
	return o
}

// splitNullTerminated walks a buffer of null-terminated UTF-8
// strings and returns them as a slice. A trailing zero byte is
// treated as the terminator of the last string; bytes after the
// final terminator are ignored.
func splitNullTerminated(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		// Unterminated trailing — surface it as best-effort.
		out = append(out, string(b[start:]))
	}
	return out
}

// looksTextual returns true when the bytes are plausibly text:
// all printable + standard whitespace, no control characters
// other than tab/newline/carriage-return.
func looksTextual(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 {
			if c != '\t' && c != '\n' && c != '\r' {
				return false
			}
		}
		if c == 0x7F {
			return false
		}
	}
	return true
}

func opcodeName(op int) string {
	switch op {
	case 1:
		return "RRQ (Read Request)"
	case 2:
		return "WRQ (Write Request)"
	case 3:
		return "DATA"
	case 4:
		return "ACK"
	case 5:
		return "ERROR"
	case 6:
		return "OACK (Option Acknowledgment, RFC 2347)"
	}
	return fmt.Sprintf("uncatalogued opcode %d", op)
}

func errorName(code int) string {
	switch code {
	case 0:
		return "Not defined"
	case 1:
		return "File not found"
	case 2:
		return "Access violation"
	case 3:
		return "Disk full or allocation exceeded"
	case 4:
		return "Illegal TFTP operation"
	case 5:
		return "Unknown transfer ID"
	case 6:
		return "File already exists"
	case 7:
		return "No such user"
	case 8:
		return "Option negotiation failure (RFC 2347)"
	}
	return fmt.Sprintf("uncatalogued error code %d", code)
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
