// tacacs.go — host-side TACACS+ packet decoder Spec.
// Wraps the internal/tacacs walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tacacs"
)

func init() { //nolint:gochecknoinits
	Register(tacacsPlusDecodeSpec)
}

var tacacsPlusDecodeSpec = Spec{
	Name: "tacacs_plus_decode",
	Description: "Decode a TACACS+ packet per RFC 8907 (which finally documented the " +
		"Cisco-proprietary protocol after decades of use in production). TACACS+ " +
		"is the third pillar AAA protocol alongside RADIUS (covered by " +
		"`radius_packet_decode`) and Diameter (covered by `diameter_packet_decode`); " +
		"it remains the dominant device-admin AAA on Cisco-heavy enterprise + ISP " +
		"networks because it separates Authentication / Authorization / Accounting " +
		"into independent transactions and supports per-command authorization (the " +
		"killer feature for router CLI access). Decodes:\n\n" +
		"- **12-byte header** (RFC 8907 §4.1): Version (4-bit Major + 4-bit Minor) " +
		"+ **Packet Type** with **3-entry name table** (Authentication / " +
		"Authorization / Accounting) + Sequence Number (odd from client, even " +
		"from server) + **Flags** decoded into **2 named bits** (0x01 " +
		"TAC_PLUS_UNENCRYPTED_FLAG / 0x04 TAC_PLUS_SINGLE_CONNECT_FLAG) + Session " +
		"ID + Length.\n" +
		"- **Body decryption** (RFC 8907 §4.5) — when the body is encrypted " +
		"(UNENCRYPTED_FLAG = 0) and a `key` is supplied, generate the pseudo-pad " +
		"by hashing concatenations of (session_id || key || version || seq_no || " +
		"previous_hash) with MD5, then XOR with the ciphertext. When no key is " +
		"supplied, the body is surfaced as opaque hex with a Note about the " +
		"encryption.\n" +
		"- **Authentication body** (Type 1) — dispatched by Sequence:\n" +
		"  - Seq 1 (client→server): **START** — Action (1 LOGIN / 2 CHPASS / 3 " +
		"SENDPASS / 4 SENDAUTH) + Priv-Lvl + **Authen-Type** (1 ASCII / 2 PAP / 3 " +
		"CHAP / 4 MS-CHAP / 5 ARAP / 6 MS-CHAPv2) + **Service** (NONE / LOGIN / " +
		"ENABLE / PPP / ARAP / PT / RCMD / X25 / NASI / FWPROXY) + User + Port + " +
		"Remote-Address + Data.\n" +
		"  - Even seq (server→client): **REPLY** — Status (1 PASS / 2 FAIL / 3 " +
		"GETDATA / 4 GETUSER / 5 GETPASS / 6 RESTART / 7 ERROR / 0x21 FOLLOW) + " +
		"NOECHO flag + Server-Msg + Data.\n" +
		"  - Odd seq > 1 (client→server): **CONTINUE** — User-Msg + Data + " +
		"ABORT flag.\n" +
		"- **Authorization body** (Type 2):\n" +
		"  - Odd seq: **REQUEST** — Authen-Method + Priv-Lvl + Authen-Type + " +
		"Service + User + Port + Rem-Addr + Args (named arg list).\n" +
		"  - Even seq: **RESPONSE** — Status (1 PASS_ADD / 2 PASS_REPL / 16 FAIL / " +
		"17 ERROR / 0x21 FOLLOW) + Server-Msg + Data + Args.\n" +
		"- **Accounting body** (Type 3):\n" +
		"  - Odd seq: **REQUEST** — Flags (0x02 START / 0x04 STOP / 0x08 " +
		"WATCHDOG) + Authen-Method + Priv-Lvl + Authen-Type + Service + User + " +
		"Port + Rem-Addr + Args.\n" +
		"  - Even seq: **REPLY** — Server-Msg + Data + Status (1 SUCCESS / 2 " +
		"ERROR / 0x21 FOLLOW).\n\n" +
		"Pure offline parser — operators paste TACACS+ bytes (TCP port 49 — typically " +
		"after `tcpdump -X tcp port 49` strip or a Wireshark Follow-TCP-Stream " +
		"view), optionally supplying the shared `key` to decrypt the body.\n\n" +
		"Out of scope (deferred): TCP framing (feed TACACS+ bytes after the TCP " +
		"payload extraction — TACACS+ runs on TCP port 49); TACACS (the original, " +
		"pre-TACACS+ protocol — long deprecated; not part of any active deployment); " +
		"state-machine reasoning (mapping REPLY/CONTINUE chains to a coherent " +
		"session, multi-arg authorization evaluation, per-command authorization " +
		"decisions — higher-level analysis); cryptographic verification (TACACS+ " +
		"has no integrity check at the protocol layer; the obfuscation pad is " +
		"reversible with the shared key but doesn't authenticate the bytes).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the third pillar AAA protocol; " +
		"completes the RADIUS + Diameter + TACACS+ trio for full enterprise + " +
		"telco + ISP AAA coverage; still extremely common in Cisco-heavy " +
		"environments and the only AAA option that supports per-command " +
		"authorization). Wrap-vs-native: native — RFC 8907 is fully public; " +
		"TACACS+ has a tight 12-byte header followed by variable-length per-type " +
		"bodies; the MD5-derived XOR obfuscation pad is implemented in 30 lines " +
		"of stdlib crypto/md5.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"TACACS+ packet bytes (after TCP payload extraction; TCP destination port 49). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"key":{"type":"string","description":"Optional TACACS+ shared key for body decryption per RFC 8907 §4.5. When the UNENCRYPTED_FLAG is clear and no key is supplied, the body is surfaced as opaque hex with an encryption note."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tacacsPlusDecodeHandler,
}

func tacacsPlusDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("tacacs_plus_decode: 'hex' is required")
	}
	key := str(p, "key")
	res, err := tacacs.Decode(raw, key)
	if err != nil {
		return "", fmt.Errorf("tacacs_plus_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
