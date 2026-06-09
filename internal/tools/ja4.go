// ja4.go — host-side JA4 TLS-client fingerprint Spec, delegating to
// internal/ja3 (the JA4 computation shares the ClientHello parser).
//
// Wrap-vs-native: native — a bounds-checked ClientHello wire walk + stdlib
// crypto/sha256. Computes the FoxIO JA4 fingerprint from a captured
// ClientHello, offline. No network or device.

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
	Register(ja4DecodeSpec)
}

var ja4DecodeSpec = Spec{
	Name: "ja4_fingerprint",
	Description: "Compute the **JA4 TLS-client fingerprint** from a captured **ClientHello** — the modern " +
		"successor to JA3 (FoxIO), now adopted by **CISA, Cloudflare, Zeek, Wireshark** and a growing list of " +
		"vendors. JA4 is **more robust than JA3**: it **sorts** the cipher and extension lists so a client " +
		"that shuffles them (TLS 1.3 randomised extension order) still fingerprints to **one stable value**, " +
		"and the fingerprint is **human-readable** — `t13d1516h2_…` already tells you TLS 1.3, SNI present, 15 " +
		"ciphers, 16 extensions, ALPN h2 before you even pivot on the hash. Given the ClientHello bytes from a " +
		"pcap (a full `0x16…` TLS record or a bare `0x01…` handshake; hex with spaces / colons accepted) this " +
		"returns the **JA4** string, its three sections, the **raw `JA4_r`** (un-hashed, for auditing), and " +
		"the parsed TLS version / SNI / ALPN.\n\n" +
		"JA4 = `JA4_a_JA4_b_JA4_c`: `a` = protocol + TLS version (from supported_versions) + SNI flag + cipher " +
		"/ extension counts + first ALPN; `b` = truncated SHA-256 of the **sorted** ciphers; `c` = truncated " +
		"SHA-256 of the **sorted** extensions (SNI + ALPN excluded) then the signature_algorithms in order. " +
		"**GREASE values (RFC 8701) are removed** throughout. **No confidently-wrong output**: the bytes are " +
		"walked with full bounds-checking and a truncated / malformed capture is **rejected**; a **ServerHello " +
		"is detected and reported** rather than mis-fingerprinted; the empty-extension case emits the spec's " +
		"`000000000000`. No network, no device — Low risk. Pairs with `ja3_fingerprint`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (network / TLS threat-intel). Wrap-vs-native: native — a " +
		"ClientHello wire walk + crypto/sha256, stdlib only, **no new go.mod dep**. **Pinned to the FoxIO " +
		"reference test fixtures** (their own published `JA4` *and* raw `JA4_r` expected values): a TLS 1.3 " +
		"hello with GREASE / SNI / ALPN / sig-algs (`t13d1516h2_8daaf6152771_e5627efa2ab1`) and a TLS 1.0 " +
		"hello exercising the legacy-version + empty-JA4_c path (`t10d230100_6a57a6f57151_000000000000`).",
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
	Handler:   ja4DecodeHandler,
}

func ja4DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "clienthello"))
	if in == "" {
		return "", fmt.Errorf("ja4_fingerprint: 'clienthello' is required")
	}
	res, err := ja3.JA4Decode(in)
	if err != nil {
		return "", fmt.Errorf("ja4_fingerprint: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
