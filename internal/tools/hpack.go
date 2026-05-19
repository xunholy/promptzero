// hpack.go — host-side HPACK header-decompression Spec.
// Wraps the internal/hpack walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hpack"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(hpackDecodeSpec)
}

var hpackDecodeSpec = Spec{
	Name: "hpack_decode",
	Description: "Decompress an HPACK-encoded HTTP/2 header block per RFC 7541. HPACK is " +
		"the header-compression layer that sits inside every HTTP/2 HEADERS, " +
		"CONTINUATION, and PUSH_PROMISE frame; without it the header bytes that " +
		"`http2_frame_decode` surfaces are opaque. Pure offline parser. Decodes:\n\n" +
		"- **Five representation types** (RFC 7541 §6):\n" +
		"  - **Indexed Header Field** (1xxxxxxx) — references the static (1-61) or " +
		"dynamic table by index; both name and value come from the table.\n" +
		"  - **Literal with Incremental Indexing** (01xxxxxx) — name indexed OR " +
		"literal, value literal; the (name, value) pair is appended to the dynamic " +
		"table.\n" +
		"  - **Literal without Indexing** (0000xxxx) — name indexed OR literal, " +
		"value literal; NOT added to the dynamic table.\n" +
		"  - **Literal Never Indexed** (0001xxxx) — same as without indexing, plus " +
		"a 'never index in any hop' hint (used for sensitive headers like Authorization " +
		"in some deployments).\n" +
		"  - **Dynamic Table Size Update** (001xxxxx) — change max dynamic table " +
		"size (the peer is informed via the SETTINGS HEADER_TABLE_SIZE value; this " +
		"representation is the trigger to actually evict).\n" +
		"- **N-bit prefix integer encoding** (RFC 7541 §5.1) — small values fit in " +
		"the prefix bits; large values use a continuation chain in which each octet " +
		"contributes 7 bits with the high bit signalling 'more octets follow'.\n" +
		"- **Literal string** (RFC 7541 §5.2) — optional H bit (high bit of the " +
		"length byte) signals Huffman-encoded; bytes are then either raw octets or a " +
		"Huffman-encoded stream over the canonical 257-symbol Appendix B code book.\n" +
		"- **Static table** (Appendix A, **61 entries**) — pre-baked into the " +
		"decoder. Covers :authority, :method GET/POST, :path / and /index.html, " +
		":scheme http/https, :status 200/204/206/304/400/404/500, and a long list of " +
		"common request/response headers (accept-* / authorization / cache-control / " +
		"content-* / cookie / etag / etc.).\n" +
		"- **Dynamic table** — newly-indexed headers are inserted with the lowest " +
		"index above the static table (62 per RFC 7541 §2.3.3) and shift older " +
		"entries up. The decoder evicts as needed when the max size is exceeded.\n" +
		"- **Huffman decoder** — bit-trie walker built from the Appendix B table " +
		"(symbols 0-255 plus EOS-256, code lengths 5-30 bits). Trailing partial-byte " +
		"padding must be ≤ 7 bits AND must be all-1s (an MSB prefix of EOS); EOS " +
		"mid-stream is a decoding error per RFC 7541 §5.2.\n" +
		"- **Per-header representation hint** — the response includes which of the " +
		"five representations was used for each header, so operators can spot " +
		"sensitive headers tagged 'never indexed', dynamic-table growth, etc.\n\n" +
		"Pure offline parser — operators paste an HPACK block from the `body_hex` of " +
		"a HEADERS / CONTINUATION / PUSH_PROMISE frame surfaced by " +
		"`http2_frame_decode`, a Wireshark Follow HTTP/2 view's header bytes, or any " +
		"HPACK-emitting tool and get every decoded (name, value) pair. Closes the gap " +
		"explicitly deferred in `http2_frame_decode` (v0.263).\n\n" +
		"Out of scope (deferred): HPACK encoding (the inverse direction); cross-frame " +
		"dynamic-table continuity (each `Decode` call starts with an empty dynamic " +
		"table — a multi-frame session-tracker would feed CONTINUATION bytes back " +
		"into the same Decoder); header validation (lower-case constraint per RFC " +
		"9113 §8.2.1, pseudo-header rules — names and values are surfaced verbatim, " +
		"semantic validation belongs in a separate Spec); QPACK (HTTP/3 — a different " +
		"compression scheme with separate static table and different framing).\n\n" +
		"Source: docs/catalog/gap-analysis.md (closes HTTP/2 stack — explicitly " +
		"deferred from v0.263 http2_frame_decode). Wrap-vs-native: native — RFC 7541 " +
		"is fully public; no cryptography, no third-party libraries; the entire " +
		"static table + Huffman code book are part of the spec.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"HPACK-encoded header block bytes as hex. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   hpackDecodeHandler,
}

func hpackDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("hpack_decode: 'hex' is required")
	}
	res, err := hpack.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("hpack_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
