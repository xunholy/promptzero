// ja3.go — host-side JA3 TLS-client fingerprint Spec, delegating to
// internal/ja3.
//
// Wrap-vs-native: native — a bounds-checked walk of the ClientHello wire
// structure + stdlib crypto/md5. Computes the IDS/threat-intel JA3 fingerprint
// from a captured ClientHello, offline. No network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ja3"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ja3DecodeSpec)
}

var ja3DecodeSpec = Spec{
	Name: "ja3_fingerprint",
	Description: "Compute the **JA3 TLS-client fingerprint** from a captured **ClientHello**. JA3 (Salesforce) " +
		"is the fingerprint format wired into **Suricata, Zeek, and every major EDR / threat-intel feed**: it " +
		"identifies a TLS client stack — and frequently the **malware family** behind it — **independent of " +
		"IP or SNI**, so a beaconing implant that rotates infrastructure still hashes to the **same JA3**. " +
		"Given the ClientHello bytes pulled from a pcap (or any `0x16…` TLS record / `0x01…` handshake), this " +
		"returns the **JA3 string** and its **MD5 digest** ready to pivot against a JA3 blocklist / threat " +
		"feed, plus the parsed offered ciphers, extensions, curves, point formats, and SNI.\n\n" +
		"JA3 concatenates `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat` (values " +
		"dash-joined) and takes the MD5; **GREASE values (RFC 8701) are removed** from the cipher / extension " +
		"/ curve lists so a client that randomises GREASE still yields one stable hash. **No confidently-wrong " +
		"output**: the bytes must parse as a real ClientHello (a bounds-checked walk — a truncated / malformed " +
		"capture is rejected, never half-fingerprinted), and a **ServerHello is detected and reported as " +
		"JA3S-not-yet-supported** rather than mis-fingerprinted. Accepts hex with spaces / colons. No network, " +
		"no device, transmits nothing — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (network / TLS threat-intel — complements the Marauder/WiFi " +
		"surface and the credential-forensics tooling). Wrap-vs-native: native — a ClientHello wire walk " +
		"(RFC 5246 §7.4.1.2) + crypto/md5, stdlib only, **no new go.mod dep**. **Pinned to the Salesforce " +
		"reference implementation (pyja3)** on a real `openssl` ClientHello (digest `0b85eb0d…`) and a " +
		"hand-built GREASE-bearing one (GREASE stripped), and to the two string→MD5 worked examples in the " +
		"JA3 spec. JA3S (server-side) is a scoped follow-up.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"clienthello":{"type":"string","description":"The TLS ClientHello as hex — a full TLS record (starting 0x16) or a bare handshake message (starting 0x01). Spaces and colons are ignored."}
		},
		"required":["clienthello"]
	}`),
	Required:  []string{"clienthello"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ja3DecodeHandler,
}

func ja3DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "clienthello"))
	if in == "" {
		return "", fmt.Errorf("ja3_fingerprint: 'clienthello' is required")
	}
	res, err := ja3.Decode(in)
	if err != nil {
		return "", fmt.Errorf("ja3_fingerprint: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
