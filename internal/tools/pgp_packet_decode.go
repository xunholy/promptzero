// pgp_packet_decode.go — host-side OpenPGP packet decoder Spec, delegating to
// internal/pgppacket.
//
// Wrap-vs-native: native — the OpenPGP packet framing, the v4/v5 fingerprint
// formula, and the algorithm/tag tables are a public spec (RFC 4880 / RFC 9580);
// a TLV walker + a hash, stdlib only. We do NOT depend on the deprecated
// golang.org/x/crypto/openpgp at runtime — it is used only as a test oracle.
// Identifies a captured PGP key/message's fingerprint, key ID, algorithm,
// creation time, and user IDs — credential-forensics loot. Offline; no network
// or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pgppacket"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pgpPacketDecodeSpec)
}

var pgpPacketDecodeSpec = Spec{
	Name: "pgp_packet_decode",
	Description: "Decode the **OpenPGP packet stream** of a PGP key or message (RFC 4880 / RFC 9580) — public " +
		"and secret keys, user IDs, signatures, and the encrypted / compressed / literal data packets — " +
		"into a structured per-packet view: tag, length, and for key packets the **version, algorithm, " +
		"creation time, fingerprint, and 64-bit key ID**. A captured PGP key or message (a `.asc` / `.gpg` " +
		"file, an armored block pasted from an email or a key dump) is real credential-forensics / IR loot: " +
		"identifying a key's **fingerprint / key ID**, its algorithm and creation time, and the user IDs it " +
		"certifies is standard triage — and a **secret-key packet is the private key itself**. Signature " +
		"packets surface the forensic subpackets — **signature creation time, issuer key ID + fingerprint** " +
		"(which key signed it), key/signature expiry, and key flags.\n\n" +
		"Accepts an ASCII-armored block (`-----BEGIN PGP …`), a base64 body, a hex string, or raw binary " +
		"bytes. For a public-key packet the fingerprint hashes the whole body (correct for every " +
		"algorithm); for a secret-key packet the public portion is isolated by walking the public MPIs " +
		"(RSA / DSA / Elgamal). **No confidently-wrong output**: an ECC secret key's fingerprint is " +
		"**flagged rather than guessed** (its layout is not cross-verified); a truncated / overrunning " +
		"packet length stops the walk with a warning rather than panicking; non-OpenPGP input is rejected. " +
		"No network, no device, transmits nothing — Low risk. Pairs with the credential tooling " +
		"(`hash_identify` / `jwt_decode` / `kerberos_decode`).\n\n" +
		"Source: docs/catalog/gap-analysis.md (credential / key forensics). Wrap-vs-native: native — an " +
		"OpenPGP TLV walker + the RFC 4880 §12.2 fingerprint hash, stdlib only, no runtime dep " +
		"(golang.org/x/crypto/openpgp is used only as a test oracle). Cross-checked against the reference " +
		"implementation on generated public + secret keys.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"input":{"type":"string","description":"The PGP key/message: an ASCII-armored block (-----BEGIN PGP …), base64, hex, or raw binary bytes."}
		},
		"required":["input"]
	}`),
	Required:  []string{"input"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pgpPacketDecodeHandler,
}

func pgpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "input"))
	if in == "" {
		return "", fmt.Errorf("pgp_packet_decode: 'input' is required")
	}
	res, err := pgppacket.Decode(in)
	if err != nil {
		return "", fmt.Errorf("pgp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
