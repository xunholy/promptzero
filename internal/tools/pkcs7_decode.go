// pkcs7_decode.go — host-side PKCS#7 / CMS structural-decoder Spec, delegating
// to internal/pkcs7.
//
// Wrap-vs-native: native — Go stdlib encoding/asn1 + crypto/x509, no new go.mod
// dep. Surfaces the content type, embedded certificates, signers, and
// encryption metadata of a CMS blob without verifying or decrypting. Offline;
// no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pkcs7"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pkcs7DecodeSpec)
}

var pkcs7DecodeSpec = Spec{
	Name: "pkcs7_decode",
	Description: "Structurally decode a **PKCS#7 / CMS** (Cryptographic Message Syntax, RFC 5652) blob. PKCS#7 / CMS " +
		"is the container behind **S/MIME** signed & encrypted email, **Authenticode** (Windows code signing is a " +
		"SignedData), **`.p7b` / `.p7c` certificate bundles**, **`.p7s` detached signatures**, timestamp tokens, " +
		"and many document signatures. After an operator recovers such a blob the question is *what is this — " +
		"signed or encrypted? whose certificate? signed when, with what algorithm?* This walks the ASN.1 with the " +
		"Go stdlib and surfaces the outer **content type** (SignedData / EnvelopedData / DigestedData / …); for " +
		"**SignedData** the version, the **digest algorithms**, the encapsulated content type and whether the " +
		"content is **embedded or detached**, the embedded **X.509 certificate chain** (subject / issuer / serial " +
		"/ validity / key & signature algorithm / CA flag / SKI), whether CRLs are present, and each **SignerInfo** " +
		"(the issuer+serial or subject-key-id that names the signer, the digest & signature algorithms, whether " +
		"signed attributes are present, and the **signing time** when carried); for **EnvelopedData** the " +
		"recipient count and the content-encryption algorithm. A note **flags weak digests** (MD5 / SHA-1).\n\n" +
		"**No confidently-wrong output**: every field comes straight from the ASN.1; an unknown algorithm / " +
		"content-type OID is surfaced as the dotted OID, never guessed; a parse error is returned, never a partial " +
		"guess. It is a **structural decoder** — it does **not** verify the signature, decrypt the content, or " +
		"validate the chain; weak/legacy algorithms are reported, never trusted. No network, no device, transmits " +
		"nothing — Low risk.\n\n" +
		"Provide the CMS as **PEM** (`-----BEGIN PKCS7-----` …) or as the raw DER **base64-encoded**. Source: " +
		"docs/catalog/gap-analysis.md (credential / certificate triage). Wrap-vs-native: native — `encoding/asn1` " +
		"+ `crypto/x509`, no new go.mod dep; anchored to real openssl-generated CMS.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pkcs7":{"type":"string","description":"The PKCS#7 / CMS blob as PEM text, or the DER base64-encoded."}
		},
		"required":["pkcs7"]
	}`),
	Required:  []string{"pkcs7"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pkcs7DecodeHandler,
}

func pkcs7DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "pkcs7"))
	if in == "" {
		return "", fmt.Errorf("pkcs7_decode: 'pkcs7' is required")
	}
	der, err := pkcs7Bytes(in)
	if err != nil {
		return "", fmt.Errorf("pkcs7_decode: %w", err)
	}
	res, err := pkcs7.Decode(der)
	if err != nil {
		return "", fmt.Errorf("pkcs7_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

// pkcs7Bytes resolves the input to DER: a PEM block if present, else base64.
func pkcs7Bytes(in string) ([]byte, error) {
	if strings.Contains(in, "-----BEGIN") {
		if blk, _ := pem.Decode([]byte(in)); blk != nil {
			return blk.Bytes, nil
		}
		return nil, fmt.Errorf("input looks like PEM but no valid block was found")
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(in), ""))
	if err != nil {
		return nil, fmt.Errorf("not valid base64 (and not PEM): %w", err)
	}
	return der, nil
}
