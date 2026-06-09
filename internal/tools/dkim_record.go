// dkim_record.go — host-side DKIM public-key record decoder Spec, delegating to
// internal/dkim.
//
// Wrap-vs-native: native — tag=value parsing + base64 + stdlib crypto/x509.
// Decodes a DKIM DNS TXT record into its signing-key forensics (type, size,
// weak-key flag, modulus for roca chaining), offline. No network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dkim"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dkimRecordDecodeSpec)
}

var dkimRecordDecodeSpec = Spec{
	Name: "dkim_record_decode",
	Description: "Decode a **DKIM public-key DNS record** (the `<selector>._domainkey.<domain>` TXT record) into " +
		"its **email-signing-key forensics**. A DKIM record is the **public half of a domain's mail-signing " +
		"key**, and it is real anti-spoofing / IR / OSINT loot: the `p=` tag carries the key, so its " +
		"**algorithm and size are directly readable** — and a **short RSA key is a classic, exploitable " +
		"finding** (a 512/768-bit DKIM key can be **factored** and the domain's email **forged**, the " +
		"well-documented 2012 mass-disclosure class). Paste the TXT record and get the **key type** (rsa / " +
		"ed25519), the **key size**, the **hash algorithms**, **service types**, **flags** (`t=y` testing, " +
		"`t=s` strict), notes, and **revocation** (empty `p=`).\n\n" +
		"**Two forensic levers**: the RSA **modulus** is surfaced (hex) so the key chains straight into " +
		"`roca_detect` — a **ROCA-vulnerable DKIM key is likewise forgeable** — and the key size is flagged " +
		"against the **RFC 8301 minimum** (a sub-1024-bit key is reported **WEAK / forgeable**, a 1024-bit key " +
		"as an advisory). **No confidently-wrong output**: weak-key flags are **objective, RFC-anchored " +
		"thresholds** (not subjective verdicts); a `p=` that does not parse as the declared key type is " +
		"surfaced with a warning rather than a fabricated size; an empty `p=` is reported as **revoked**; a " +
		"record with no `p=` tag is rejected as not-a-DKIM-key-record. DNS string folding (whitespace in " +
		"`p=`) is stripped. No network, no device, transmits nothing — Low risk. Pairs with `roca_detect` " +
		"and `x509_certificate_decode`.\n\n" +
		"Source: docs/catalog/gap-analysis.md (email-authentication forensics — a fresh domain). " +
		"Wrap-vs-native: native — tag=value parsing + base64 + stdlib crypto/x509 (SubjectPublicKeyInfo), " +
		"**no new go.mod dep**. Pinned to openssl-generated records (1024-bit → modulus `b71e36fc…`, 512-bit " +
		"flagged WEAK) and the **RFC 8463 Ed25519 test vector**.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"record":{"type":"string","description":"The DKIM public-key TXT record, e.g. 'v=DKIM1; k=rsa; p=MIGf…'. Whitespace inside p= is tolerated."}
		},
		"required":["record"]
	}`),
	Required:  []string{"record"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dkimRecordDecodeHandler,
}

func dkimRecordDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	record := strings.TrimSpace(str(p, "record"))
	if record == "" {
		return "", fmt.Errorf("dkim_record_decode: 'record' is required")
	}
	res, err := dkim.Decode(record)
	if err != nil {
		return "", fmt.Errorf("dkim_record_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
