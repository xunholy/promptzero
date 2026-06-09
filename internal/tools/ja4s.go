// ja4s.go — host-side JA4S TLS-server fingerprint Spec, delegating to
// internal/ja3 (the JA4S computation shares the package's TLS wire parser).
//
// Wrap-vs-native: native — a bounds-checked ServerHello wire walk + stdlib
// crypto/sha256. Computes the FoxIO JA4S fingerprint from a captured
// ServerHello, offline. No network or device.

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
	Register(ja4sDecodeSpec)
}

var ja4sDecodeSpec = Spec{
	Name: "ja4s_fingerprint",
	Description: "Compute the **JA4S TLS-server fingerprint** from a captured **ServerHello** — the server-side " +
		"companion to `ja4_fingerprint`. Where JA4 fingerprints the *client*, JA4S fingerprints the **server's " +
		"response**, which is how you fingerprint **C2 / malware server infrastructure**: a server's chosen " +
		"cipher + extension set is distinctive, so pairing the client **JA4** with the server **JA4S** " +
		"fingerprints **both ends of a single handshake** (the strong threat-intel signal — a JA4+JA4S pair " +
		"pins a specific client⇄server stack). Given the ServerHello bytes from a pcap (a full `0x16…` TLS " +
		"record or a bare `0x02…` handshake; hex with spaces / colons accepted) this returns the **JA4S** " +
		"string, its three sections, the **raw `JA4S_r`**, and the negotiated TLS version / chosen cipher / " +
		"ALPN.\n\n" +
		"JA4S = `JA4S_a_JA4S_b_JA4S_c`: `a` = protocol + TLS version (from the ServerHello's supported_versions) " +
		"+ extension count + chosen ALPN; `b` = the server's **single chosen cipher**; `c` = truncated SHA-256 " +
		"of the extension list **in ServerHello order**. Per the FoxIO reference, JA4S **retains GREASE** and " +
		"does **not** sort (the server-side rules differ from client JA4). **No confidently-wrong output**: the " +
		"bytes are walked with full bounds-checking and a truncated capture is **rejected**; a **ClientHello " +
		"is detected and steered to `ja4_fingerprint`** rather than mis-fingerprinted; an extension-less " +
		"ServerHello emits the spec's `000000000000`. No network, no device — Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (network / TLS threat-intel). Wrap-vs-native: native — a " +
		"ServerHello wire walk + crypto/sha256 (shares the `internal/ja3` parser), stdlib only, **no new " +
		"go.mod dep**. **Pinned to the FoxIO reference test fixtures** (their own published `JA4S` *and* raw " +
		"`JA4S_r`): a TLS 1.0 ServerHello (`t100100_0005_bc98f8e001b5`) and a TLS 1.3 ServerHello whose version " +
		"comes from its supported_versions extension (`t130200_1301_234ea6891581`).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"serverhello":{"type":"string","description":"The TLS ServerHello as hex — a full TLS record (starting 0x16) or a bare handshake message (starting 0x02). Spaces and colons are ignored."}
		},
		"required":["serverhello"]
	}`),
	Required:  []string{"serverhello"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ja4sDecodeHandler,
}

func ja4sDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "serverhello"))
	if in == "" {
		return "", fmt.Errorf("ja4s_fingerprint: 'serverhello' is required")
	}
	res, err := ja3.JA4SDecode(in)
	if err != nil {
		return "", fmt.Errorf("ja4s_fingerprint: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
