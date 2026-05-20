// Package tacacs decodes TACACS+ packets per RFC 8907 (which
// finally documented the Cisco-proprietary protocol after
// decades of use in production). TACACS+ is the third pillar
// AAA protocol alongside RADIUS (RFC 2865, covered by
// `radius_packet_decode`) and Diameter (RFC 6733, covered by
// `diameter_packet_decode`); it remains the dominant device-
// admin AAA on Cisco-heavy enterprise + ISP networks because
// it separates Authentication / Authorization / Accounting
// into independent transactions and supports per-command
// authorization (the killer feature for router CLI access).
//
// Wrap-vs-native judgement
//
//	Native. RFC 8907 is fully public. TACACS+ has a tight
//	12-byte header followed by a variable-length body whose
//	layout is dictated by Packet Type + Sequence Number.
//	The body is XOR-obfuscated by default with a pseudo-pad
//	derived from MD5 hashes over (session_id || key ||
//	version || seq_no || prev_hash) per RFC 8907 §4.5; the
//	TAC_PLUS_UNENCRYPTED_FLAG bit signals plaintext bodies.
//	This package decodes the header always, and decodes the
//	body either when that flag is set or when the operator
//	supplies the shared `key`.
//
// What this package covers
//
//   - **12-byte header** (RFC 8907 §4.1):
//
//   - byte 0: **Version** — 4-bit Major (4 = TACACS+) +
//     4-bit Minor (0 or 1; 1 adds CHAP/MS-CHAP support).
//
//   - byte 1: **Packet Type** with **3-entry name table**:
//     0x01 Authentication, 0x02 Authorization, 0x03
//     Accounting.
//
//   - byte 2: **Sequence Number** — odd from client,
//     even from server, starts at 1; a single session is
//     capped at 0xFF.
//
//   - byte 3: **Flags** decoded into **2 named bits**:
//     0x01 TAC_PLUS_UNENCRYPTED_FLAG (body is plaintext),
//     0x04 TAC_PLUS_SINGLE_CONNECT_FLAG (multiplex
//     multiple sessions on one TCP connection).
//
//   - bytes 4-7: Session ID (uint32 BE).
//
//   - bytes 8-11: Length (uint32 BE; body length, not
//     including the 12-byte header).
//
//   - **Body decryption** (RFC 8907 §4.5) — when the body
//     is encrypted (UNENCRYPTED_FLAG = 0) and a `key` is
//     supplied, generate the pseudo-pad by hashing
//     concatenations of (session_id || key || version ||
//     seq_no || previous_hash) with MD5, then XOR with the
//     ciphertext. When no key is supplied, the body is
//     surfaced as opaque hex with a Note about the
//     encryption.
//
//   - **Authentication body** (Type 1):
//
//   - Sequence 1 (client→server): **START** —
//
//   - byte 0: Action (1 LOGIN / 2 CHPASS / 3 SENDPASS
//     / 4 SENDAUTH).
//
//   - byte 1: Privilege Level (0 MIN ... 15 MAX).
//
//   - byte 2: **Authen-Type** (1 ASCII / 2 PAP / 3
//     CHAP / 4 MS-CHAP / 5 ARAP / 6 MS-CHAPv2).
//
//   - byte 3: **Service** (0 NONE / 1 LOGIN / 2 ENABLE
//     / 3 PPP / 4 ARAP / 5 PT / 6 RCMD / 7 X25 / 8
//     NASI / 9 FWPROXY).
//
//   - bytes 4-7: User-Len + Port-Len + Rem-Addr-Len +
//     Data-Len (each uint8).
//
//   - then user + port + rem_addr + data strings
//     (each surfaced as UTF-8 + raw hex).
//
//   - Sequence 2/4/... (server→client): **REPLY** —
//     Status (1 PASS / 2 FAIL / 3 GETDATA / 4 GETUSER /
//     5 GETPASS / 6 RESTART / 7 ERROR / 0x21 FOLLOW) +
//     Flags (0x01 NOECHO) + Server-Msg-Len (uint16 BE)
//
//   - Data-Len (uint16 BE) + Server-Msg + Data.
//
//   - Sequence 3/5/... (client→server): **CONTINUE** —
//     User-Msg-Len + Data-Len + Flags (0x01 ABORT) +
//     User-Msg + Data.
//
//   - **Authorization body** (Type 2):
//
//   - Odd seq (client→server): **REQUEST** — Authen-
//     Method + Priv-Lvl + Authen-Type + Authen-Service +
//     User-Len + Port-Len + Rem-Addr-Len + Arg-Count +
//     N × Arg-Len + User + Port + Rem-Addr + Arg-Values.
//
//   - Even seq (server→client): **RESPONSE** — Status
//     (1 PASS_ADD / 2 PASS_REPL / 16 FAIL / 17 ERROR /
//     0x21 FOLLOW) + Arg-Count + Server-Msg-Len + Data-
//     Len + N × Arg-Len + Server-Msg + Data + Arg-Values.
//
//   - **Accounting body** (Type 3):
//
//   - Odd seq (client→server): **REQUEST** — Flags (0x02
//     START / 0x04 STOP / 0x08 WATCHDOG) + Authen-Method
//
//   - Priv-Lvl + Authen-Type + Authen-Service + User-
//     Len + Port-Len + Rem-Addr-Len + Arg-Count + arg
//     lengths + User + Port + Rem-Addr + Arg-Values.
//
//   - Even seq (server→client): **REPLY** — Server-Msg-
//     Len + Data-Len + Status (1 SUCCESS / 2 ERROR /
//     0x21 FOLLOW) + Server-Msg + Data.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - TCP framing — feed TACACS+ bytes after the TCP
//     payload extraction. TACACS+ runs on TCP port 49.
//
//   - TACACS (the original, pre-TACACS+ protocol) — long
//     deprecated; not part of any active deployment.
//
//   - State-machine reasoning (mapping REPLY/CONTINUE
//     chains to a coherent session, multi-arg authorization
//     evaluation, per-command authorization decisions) —
//     higher-level analysis.
//
//   - Cryptographic verification — TACACS+ has no integrity
//     check at the protocol layer; the obfuscation pad is
//     reversible with the shared key but doesn't
//     authenticate the bytes.
package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Result is the top-level decoded view of a TACACS+ packet.
type Result struct {
	VersionMajor      int    `json:"version_major"`
	VersionMinor      int    `json:"version_minor"`
	VersionHex        string `json:"version_hex"`
	PacketType        int    `json:"packet_type"`
	PacketTypeName    string `json:"packet_type_name"`
	SequenceNumber    int    `json:"sequence_number"`
	Flags             int    `json:"flags"`
	FlagsHex          string `json:"flags_hex"`
	FlagUnencrypted   bool   `json:"flag_unencrypted"`
	FlagSingleConnect bool   `json:"flag_single_connect"`
	SessionID         uint32 `json:"session_id"`
	BodyLength        uint32 `json:"body_length"`

	// Body decoded if plaintext (or successfully decrypted).
	BodyEncrypted       bool                        `json:"body_encrypted"`
	BodyHex             string                      `json:"body_hex,omitempty"`
	AuthenticationStart *AuthenticationStartBody    `json:"authentication_start,omitempty"`
	AuthenticationReply *AuthenticationReplyBody    `json:"authentication_reply,omitempty"`
	AuthenticationCont  *AuthenticationContinueBody `json:"authentication_continue,omitempty"`
	AuthorizationReq    *AuthorizationRequestBody   `json:"authorization_request,omitempty"`
	AuthorizationResp   *AuthorizationResponseBody  `json:"authorization_response,omitempty"`
	AccountingReq       *AccountingRequestBody      `json:"accounting_request,omitempty"`
	AccountingReply     *AccountingReplyBody        `json:"accounting_reply,omitempty"`

	TotalBytes int      `json:"total_bytes"`
	Notes      []string `json:"notes,omitempty"`
}

// AuthenticationStartBody is the parsed AUTH START packet.
type AuthenticationStartBody struct {
	Action       int    `json:"action"`
	ActionName   string `json:"action_name"`
	Priv         int    `json:"privilege_level"`
	AuthType     int    `json:"authentication_type"`
	AuthTypeName string `json:"authentication_type_name"`
	Service      int    `json:"service"`
	ServiceName  string `json:"service_name"`
	User         string `json:"user"`
	Port         string `json:"port"`
	RemoteAddr   string `json:"remote_address"`
	DataHex      string `json:"data_hex,omitempty"`
}

// AuthenticationReplyBody is the parsed AUTH REPLY packet.
type AuthenticationReplyBody struct {
	Status     int    `json:"status"`
	StatusName string `json:"status_name"`
	FlagNoEcho bool   `json:"flag_no_echo"`
	ServerMsg  string `json:"server_message"`
	DataHex    string `json:"data_hex,omitempty"`
}

// AuthenticationContinueBody is the parsed AUTH CONTINUE.
type AuthenticationContinueBody struct {
	UserMsg   string `json:"user_message"`
	DataHex   string `json:"data_hex,omitempty"`
	FlagAbort bool   `json:"flag_abort"`
}

// AuthorizationRequestBody is the parsed AUTHOR REQUEST.
type AuthorizationRequestBody struct {
	AuthMethod   int      `json:"authentication_method"`
	Priv         int      `json:"privilege_level"`
	AuthType     int      `json:"authentication_type"`
	AuthTypeName string   `json:"authentication_type_name"`
	Service      int      `json:"service"`
	ServiceName  string   `json:"service_name"`
	User         string   `json:"user"`
	Port         string   `json:"port"`
	RemoteAddr   string   `json:"remote_address"`
	Args         []string `json:"args,omitempty"`
}

// AuthorizationResponseBody is the parsed AUTHOR RESPONSE.
type AuthorizationResponseBody struct {
	Status     int      `json:"status"`
	StatusName string   `json:"status_name"`
	ServerMsg  string   `json:"server_message"`
	DataHex    string   `json:"data_hex,omitempty"`
	Args       []string `json:"args,omitempty"`
}

// AccountingRequestBody is the parsed ACCT REQUEST.
type AccountingRequestBody struct {
	Flags        int      `json:"flags"`
	FlagsHex     string   `json:"flags_hex"`
	FlagStart    bool     `json:"flag_start"`
	FlagStop     bool     `json:"flag_stop"`
	FlagWatchdog bool     `json:"flag_watchdog"`
	AuthMethod   int      `json:"authentication_method"`
	Priv         int      `json:"privilege_level"`
	AuthType     int      `json:"authentication_type"`
	AuthTypeName string   `json:"authentication_type_name"`
	Service      int      `json:"service"`
	ServiceName  string   `json:"service_name"`
	User         string   `json:"user"`
	Port         string   `json:"port"`
	RemoteAddr   string   `json:"remote_address"`
	Args         []string `json:"args,omitempty"`
}

// AccountingReplyBody is the parsed ACCT REPLY.
type AccountingReplyBody struct {
	Status     int    `json:"status"`
	StatusName string `json:"status_name"`
	ServerMsg  string `json:"server_message"`
	DataHex    string `json:"data_hex,omitempty"`
}

// Decode parses a single TACACS+ packet from hex. When the
// body is encrypted (UNENCRYPTED_FLAG = 0) and `key` is
// non-empty, the body is decrypted per RFC 8907 §4.5 before
// dispatch.
func Decode(hexStr, key string) (*Result, error) {
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
	if len(b) < 12 {
		return nil, fmt.Errorf("TACACS+ packet truncated (%d bytes; need ≥12 for header)",
			len(b))
	}
	r := &Result{
		TotalBytes:        len(b),
		VersionMajor:      int(b[0] >> 4),
		VersionMinor:      int(b[0] & 0x0F),
		VersionHex:        fmt.Sprintf("0x%02X", b[0]),
		PacketType:        int(b[1]),
		PacketTypeName:    packetTypeName(int(b[1])),
		SequenceNumber:    int(b[2]),
		Flags:             int(b[3]),
		FlagsHex:          fmt.Sprintf("0x%02X", b[3]),
		FlagUnencrypted:   b[3]&0x01 != 0,
		FlagSingleConnect: b[3]&0x04 != 0,
		SessionID:         binary.BigEndian.Uint32(b[4:8]),
		BodyLength:        binary.BigEndian.Uint32(b[8:12]),
	}
	body := b[12:]
	if int(r.BodyLength) != len(body) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"header declares body length %d but %d bytes follow",
			r.BodyLength, len(body)))
	}
	cipher := body
	if !r.FlagUnencrypted {
		r.BodyEncrypted = true
		if key != "" {
			pad := tacacsPad(r.SessionID, []byte(key),
				byte(b[0]), byte(r.SequenceNumber), len(cipher))
			plain := make([]byte, len(cipher))
			for i := range cipher {
				plain[i] = cipher[i] ^ pad[i]
			}
			cipher = plain
		} else {
			r.BodyHex = strings.ToUpper(hex.EncodeToString(body))
			r.Notes = append(r.Notes,
				"body is encrypted (UNENCRYPTED_FLAG clear) and no key was supplied; supply 'key' to decode")
			return r, nil
		}
	}
	r.BodyHex = strings.ToUpper(hex.EncodeToString(cipher))
	dispatchBody(r, cipher)
	return r, nil
}

// dispatchBody walks the (already plaintext) body and fills
// in the per-type structured fields.
func dispatchBody(r *Result, body []byte) {
	switch r.PacketType {
	case 1:
		// Authentication: seq 1 = START, even seq = REPLY,
		// odd seq > 1 = CONTINUE.
		switch {
		case r.SequenceNumber == 1:
			r.AuthenticationStart = decodeAuthStart(body, r)
		case r.SequenceNumber%2 == 0:
			r.AuthenticationReply = decodeAuthReply(body, r)
		default:
			r.AuthenticationCont = decodeAuthContinue(body, r)
		}
	case 2:
		if r.SequenceNumber%2 == 1 {
			r.AuthorizationReq = decodeAuthorRequest(body, r)
		} else {
			r.AuthorizationResp = decodeAuthorResponse(body, r)
		}
	case 3:
		if r.SequenceNumber%2 == 1 {
			r.AccountingReq = decodeAcctRequest(body, r)
		} else {
			r.AccountingReply = decodeAcctReply(body, r)
		}
	}
}

func decodeAuthStart(b []byte, r *Result) *AuthenticationStartBody {
	if len(b) < 8 {
		r.Notes = append(r.Notes, "AUTH START body < 8 fixed bytes")
		return nil
	}
	a := &AuthenticationStartBody{
		Action:   int(b[0]),
		Priv:     int(b[1]),
		AuthType: int(b[2]),
		Service:  int(b[3]),
	}
	a.ActionName = actionName(a.Action)
	a.AuthTypeName = authTypeName(a.AuthType)
	a.ServiceName = serviceName(a.Service)
	userLen := int(b[4])
	portLen := int(b[5])
	remLen := int(b[6])
	dataLen := int(b[7])
	off := 8
	a.User, off = takeString(b, off, userLen, r, "user")
	a.Port, off = takeString(b, off, portLen, r, "port")
	a.RemoteAddr, off = takeString(b, off, remLen, r, "remote address")
	if dataLen > 0 && off+dataLen <= len(b) {
		a.DataHex = strings.ToUpper(hex.EncodeToString(b[off : off+dataLen]))
	}
	return a
}

func decodeAuthReply(b []byte, r *Result) *AuthenticationReplyBody {
	if len(b) < 6 {
		r.Notes = append(r.Notes, "AUTH REPLY body < 6 fixed bytes")
		return nil
	}
	a := &AuthenticationReplyBody{
		Status:     int(b[0]),
		FlagNoEcho: b[1]&0x01 != 0,
	}
	a.StatusName = authReplyStatusName(a.Status)
	smLen := int(binary.BigEndian.Uint16(b[2:4]))
	dataLen := int(binary.BigEndian.Uint16(b[4:6]))
	off := 6
	a.ServerMsg, off = takeString(b, off, smLen, r, "server message")
	if dataLen > 0 && off+dataLen <= len(b) {
		a.DataHex = strings.ToUpper(hex.EncodeToString(b[off : off+dataLen]))
	}
	return a
}

func decodeAuthContinue(b []byte, r *Result) *AuthenticationContinueBody {
	if len(b) < 5 {
		r.Notes = append(r.Notes, "AUTH CONTINUE body < 5 fixed bytes")
		return nil
	}
	c := &AuthenticationContinueBody{
		FlagAbort: b[4]&0x01 != 0,
	}
	userLen := int(binary.BigEndian.Uint16(b[0:2]))
	dataLen := int(binary.BigEndian.Uint16(b[2:4]))
	off := 5
	c.UserMsg, off = takeString(b, off, userLen, r, "user message")
	if dataLen > 0 && off+dataLen <= len(b) {
		c.DataHex = strings.ToUpper(hex.EncodeToString(b[off : off+dataLen]))
	}
	return c
}

func decodeAuthorRequest(b []byte, r *Result) *AuthorizationRequestBody {
	if len(b) < 8 {
		r.Notes = append(r.Notes, "AUTHOR REQUEST body < 8 fixed bytes")
		return nil
	}
	a := &AuthorizationRequestBody{
		AuthMethod: int(b[0]),
		Priv:       int(b[1]),
		AuthType:   int(b[2]),
		Service:    int(b[3]),
	}
	a.AuthTypeName = authTypeName(a.AuthType)
	a.ServiceName = serviceName(a.Service)
	userLen := int(b[4])
	portLen := int(b[5])
	remLen := int(b[6])
	argCount := int(b[7])
	off := 8
	if off+argCount > len(b) {
		r.Notes = append(r.Notes, "AUTHOR REQUEST arg lengths truncated")
		return a
	}
	argLens := make([]int, argCount)
	for i := 0; i < argCount; i++ {
		argLens[i] = int(b[off+i])
	}
	off += argCount
	a.User, off = takeString(b, off, userLen, r, "user")
	a.Port, off = takeString(b, off, portLen, r, "port")
	a.RemoteAddr, off = takeString(b, off, remLen, r, "remote address")
	for _, ln := range argLens {
		v, newOff := takeString(b, off, ln, r, "arg")
		off = newOff
		a.Args = append(a.Args, v)
	}
	return a
}

func decodeAuthorResponse(b []byte, r *Result) *AuthorizationResponseBody {
	if len(b) < 6 {
		r.Notes = append(r.Notes, "AUTHOR RESPONSE body < 6 fixed bytes")
		return nil
	}
	a := &AuthorizationResponseBody{
		Status: int(b[0]),
	}
	a.StatusName = authorResponseStatusName(a.Status)
	argCount := int(b[1])
	smLen := int(binary.BigEndian.Uint16(b[2:4]))
	dataLen := int(binary.BigEndian.Uint16(b[4:6]))
	off := 6
	if off+argCount > len(b) {
		r.Notes = append(r.Notes, "AUTHOR RESPONSE arg lengths truncated")
		return a
	}
	argLens := make([]int, argCount)
	for i := 0; i < argCount; i++ {
		argLens[i] = int(b[off+i])
	}
	off += argCount
	a.ServerMsg, off = takeString(b, off, smLen, r, "server message")
	if dataLen > 0 && off+dataLen <= len(b) {
		a.DataHex = strings.ToUpper(hex.EncodeToString(b[off : off+dataLen]))
		off += dataLen
	}
	for _, ln := range argLens {
		v, newOff := takeString(b, off, ln, r, "arg")
		off = newOff
		a.Args = append(a.Args, v)
	}
	return a
}

func decodeAcctRequest(b []byte, r *Result) *AccountingRequestBody {
	if len(b) < 9 {
		r.Notes = append(r.Notes, "ACCT REQUEST body < 9 fixed bytes")
		return nil
	}
	a := &AccountingRequestBody{
		Flags:        int(b[0]),
		FlagsHex:     fmt.Sprintf("0x%02X", b[0]),
		FlagStart:    b[0]&0x02 != 0,
		FlagStop:     b[0]&0x04 != 0,
		FlagWatchdog: b[0]&0x08 != 0,
		AuthMethod:   int(b[1]),
		Priv:         int(b[2]),
		AuthType:     int(b[3]),
		Service:      int(b[4]),
	}
	a.AuthTypeName = authTypeName(a.AuthType)
	a.ServiceName = serviceName(a.Service)
	userLen := int(b[5])
	portLen := int(b[6])
	remLen := int(b[7])
	argCount := int(b[8])
	off := 9
	if off+argCount > len(b) {
		r.Notes = append(r.Notes, "ACCT REQUEST arg lengths truncated")
		return a
	}
	argLens := make([]int, argCount)
	for i := 0; i < argCount; i++ {
		argLens[i] = int(b[off+i])
	}
	off += argCount
	a.User, off = takeString(b, off, userLen, r, "user")
	a.Port, off = takeString(b, off, portLen, r, "port")
	a.RemoteAddr, off = takeString(b, off, remLen, r, "remote address")
	for _, ln := range argLens {
		v, newOff := takeString(b, off, ln, r, "arg")
		off = newOff
		a.Args = append(a.Args, v)
	}
	return a
}

func decodeAcctReply(b []byte, r *Result) *AccountingReplyBody {
	if len(b) < 5 {
		r.Notes = append(r.Notes, "ACCT REPLY body < 5 fixed bytes")
		return nil
	}
	a := &AccountingReplyBody{
		Status: int(b[4]),
	}
	a.StatusName = acctReplyStatusName(a.Status)
	smLen := int(binary.BigEndian.Uint16(b[0:2]))
	dataLen := int(binary.BigEndian.Uint16(b[2:4]))
	off := 5
	a.ServerMsg, off = takeString(b, off, smLen, r, "server message")
	if dataLen > 0 && off+dataLen <= len(b) {
		a.DataHex = strings.ToUpper(hex.EncodeToString(b[off : off+dataLen]))
	}
	return a
}

// takeString slices off `n` bytes at `off` and returns them as
// a UTF-8 string (when valid) plus the new offset. Truncations
// surface a Note.
func takeString(b []byte, off, n int, r *Result, what string) (string, int) {
	if n == 0 {
		return "", off
	}
	if off+n > len(b) {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"%s field truncated at offset %d (need %d, have %d)",
			what, off, n, len(b)-off))
		return "", len(b)
	}
	s := b[off : off+n]
	if utf8.Valid(s) {
		return string(s), off + n
	}
	return strings.ToUpper(hex.EncodeToString(s)), off + n
}

// tacacsPad generates the RFC 8907 §4.5 pseudo-pad of length
// `n` from the session id, shared key, version byte, and seq.
//
// pad = MD5(session_id || key || version || seq_no) ||
//
//	MD5(session_id || key || version || seq_no || pad_0) ||
//	MD5(session_id || key || version || seq_no || pad_1) ||
//	...
//
// where pad_N is the previous 16-byte MD5 block.
func tacacsPad(sessionID uint32, key []byte, version, seq byte, n int) []byte {
	out := make([]byte, 0, n)
	var prev []byte
	for len(out) < n {
		h := md5.New() //nolint:gosec // RFC 8907 §4.5 mandates MD5
		_ = binary.Write(h, binary.BigEndian, sessionID)
		h.Write(key)
		h.Write([]byte{version, seq})
		if prev != nil {
			h.Write(prev)
		}
		block := h.Sum(nil)
		out = append(out, block...)
		prev = block
	}
	return out[:n]
}

func packetTypeName(t int) string {
	switch t {
	case 1:
		return "Authentication"
	case 2:
		return "Authorization"
	case 3:
		return "Accounting"
	}
	return fmt.Sprintf("uncatalogued packet type %d", t)
}

func actionName(a int) string {
	switch a {
	case 1:
		return "LOGIN"
	case 2:
		return "CHPASS"
	case 3:
		return "SENDPASS (deprecated)"
	case 4:
		return "SENDAUTH"
	}
	return fmt.Sprintf("uncatalogued action %d", a)
}

func authTypeName(t int) string {
	switch t {
	case 1:
		return "ASCII"
	case 2:
		return "PAP"
	case 3:
		return "CHAP"
	case 4:
		return "MS-CHAP"
	case 5:
		return "ARAP"
	case 6:
		return "MS-CHAPv2"
	}
	return fmt.Sprintf("uncatalogued auth type %d", t)
}

func serviceName(s int) string {
	switch s {
	case 0:
		return "NONE"
	case 1:
		return "LOGIN"
	case 2:
		return "ENABLE"
	case 3:
		return "PPP"
	case 4:
		return "ARAP"
	case 5:
		return "PT"
	case 6:
		return "RCMD"
	case 7:
		return "X25"
	case 8:
		return "NASI"
	case 9:
		return "FWPROXY"
	}
	return fmt.Sprintf("uncatalogued service %d", s)
}

func authReplyStatusName(s int) string {
	switch s {
	case 1:
		return "PASS"
	case 2:
		return "FAIL"
	case 3:
		return "GETDATA"
	case 4:
		return "GETUSER"
	case 5:
		return "GETPASS"
	case 6:
		return "RESTART"
	case 7:
		return "ERROR"
	case 0x21:
		return "FOLLOW"
	}
	return fmt.Sprintf("uncatalogued status %d", s)
}

func authorResponseStatusName(s int) string {
	switch s {
	case 1:
		return "PASS_ADD"
	case 2:
		return "PASS_REPL"
	case 16:
		return "FAIL"
	case 17:
		return "ERROR"
	case 0x21:
		return "FOLLOW"
	}
	return fmt.Sprintf("uncatalogued status %d", s)
}

func acctReplyStatusName(s int) string {
	switch s {
	case 1:
		return "SUCCESS"
	case 2:
		return "ERROR"
	case 0x21:
		return "FOLLOW"
	}
	return fmt.Sprintf("uncatalogued status %d", s)
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
