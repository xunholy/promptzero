// ccache.go — host-side MIT Kerberos credential-cache parser Spec, delegating
// to internal/ccache.
//
// Wrap-vs-native: native — the ccache is a documented big-endian length-prefixed
// binary format; the parse is a byte-cursor walk. The credential-cache
// complement to keytab_decode (long-term keys) + kerberos_decode (wire). Offline.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ccache"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ccacheDecodeSpec)
}

var ccacheDecodeSpec = Spec{
	Name: "ccache_decode",
	Description: "Parse an MIT Kerberos credential cache (the binary FILE: ccache format, version 0x0504) — " +
		"the on-disk `/tmp/krb5cc_*` / KRB5CCNAME file or a Rubeus / Mimikatz dump — into its default " +
		"principal and stored credentials. A ccache lifted from a host is **high-value Active Directory " +
		"loot**: it holds **live Kerberos tickets** usable for **pass-the-ticket**, and a TGT (service " +
		"krbtgt/…) is the golden-ticket / delegation pivot (flagged). The credential-cache complement to " +
		"keytab_decode (long-term keys) and kerberos_decode (the wire protocol).\n\n" +
		"Paste the ccache bytes as hex and get, per credential: the **client** + **server** principals " +
		"(comp/comp@REALM), the session **key_type** + key (hex), the validity **times** (auth / start / " +
		"end / renew-till → RFC 3339), the **ticket_flags** decoded to names (forwardable / renewable / " +
		"initial / pre-authent / ok-as-delegate / …), and the embedded **ticket** (hex — the " +
		"pass-the-ticket blob).\n\n" +
		"Pure offline parser — length fields are bounds-checked, hostile counts are capped, a " +
		"truncated/malformed credential is rejected (never a partial decode), and the legacy 0x0501–0x0503 " +
		"variants (different header / byte-order) are reported rather than mis-decoded. No network, no " +
		"device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (AD-pentest loot decode — pairs with keytab_decode + " +
		"kerberos_decode; a ccache's tickets feed pass-the-ticket / golden-ticket workflows). Wrap-vs-" +
		"native: native — a documented big-endian length-prefixed format, encoding/binary only. Anchored " +
		"to a ccache confirmed by the authoritative MIT `klist -cf` (default principal, service, times, and " +
		"Flags: FRIA).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded MIT credential cache (FILE: ccache, version 0x0504). ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ccacheDecodeHandler,
}

func ccacheDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ccache_decode: 'hex' is required")
	}
	res, err := ccache.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ccache_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
