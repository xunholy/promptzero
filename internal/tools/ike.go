// ike.go — host-side IKEv2 message decoder Spec.
// Wraps the internal/ike walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ike"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ikeV2DecodeSpec)
}

var ikeV2DecodeSpec = Spec{
	Name: "ike_v2_decode",
	Description: "Decode an IKEv2 (Internet Key Exchange version 2) message per RFC " +
		"7296. IKEv2 is the control-plane protocol that negotiates the IPsec " +
		"Security Associations (SAs) consumed by ESP (RFC 4303, covered by " +
		"`esp_decode`) and AH (RFC 4302, covered by `ah_decode`). Without IKE the " +
		"SPIs + keys + algorithms ESP/AH need come from nowhere; with IKEv2 we " +
		"decode the negotiation that produces them. Universal on every site-to-" +
		"site VPN + IPsec remote-access deployment — StrongSwan, OpenSwan/" +
		"Libreswan, Cisco AnyConnect IPsec mode, FortiGate, pfSense, OPNsense, " +
		"Windows IPsec, macOS IKEv2 client. Decodes:\n\n" +
		"- **28-byte fixed header** (RFC 7296 §3.1): Initiator SPI (uint64 BE) + " +
		"Responder SPI (uint64 BE; zero in the first IKE_SA_INIT request, set in " +
		"the reply) + Next Payload (first payload's type) + Version (Major.Minor " +
		"= 2.0) + **Exchange Type** with **4-entry name table** (34 IKE_SA_INIT, " +
		"35 IKE_AUTH, 36 CREATE_CHILD_SA, 37 INFORMATIONAL) + **Flags** decoded " +
		"into **3 named bits** (R Response, V Version — only set by responders, " +
		"I Initiator) + Message ID + Length.\n" +
		"- **Payload walker** — chained list driven by the Next Payload field of " +
		"the previous payload. Each payload header = 4 bytes (Next Payload + " +
		"Critical bit + Payload Length). Walker terminates when Next Payload = 0.\n" +
		"- **~15-entry payload type name table** (RFC 7296 §3.2): 33 SA / 34 KE / " +
		"35 IDi / 36 IDr / 37 CERT / 38 CERTREQ / 39 AUTH / 40 Ni or Nr (Nonce) / " +
		"41 N (Notify) / 42 D (Delete) / 43 V (Vendor ID) / 44 TSi / 45 TSr / 46 " +
		"SK (Encrypted and Authenticated) / 47 CP / 48 EAP.\n" +
		"- **N (Notify) payload body** (Type 41; RFC 7296 §3.10): Protocol ID + " +
		"SPI Size + **Notify Message Type** resolved via a **~30-entry name " +
		"table** covering common error codes (UNSUPPORTED_CRITICAL_PAYLOAD / " +
		"INVALID_SPI / NO_PROPOSAL_CHOSEN / INVALID_KE_PAYLOAD / AUTHENTICATION_" +
		"FAILED / SINGLE_PAIR_REQUIRED / NO_ADDITIONAL_SAS / INTERNAL_ADDRESS_" +
		"FAILURE / FAILED_CP_REQUIRED / TS_UNACCEPTABLE / INVALID_SELECTORS / " +
		"TEMPORARY_FAILURE / CHILD_SA_NOT_FOUND) and status codes (INITIAL_" +
		"CONTACT / SET_WINDOW_SIZE / IPCOMP_SUPPORTED / NAT_DETECTION_SOURCE_IP " +
		"/ NAT_DETECTION_DESTINATION_IP / COOKIE / USE_TRANSPORT_MODE / REKEY_SA " +
		"/ MOBIKE_SUPPORTED / AUTH_LIFETIME / SIGNATURE_HASH_ALGORITHMS), plus a " +
		"class breakdown (Error 1-8191 / Status 16384+).\n" +
		"- **SK (Encrypted) payload** (Type 46) — surfaced with the encrypted " +
		"body as opaque hex pending the IKE-derived SK_e/SK_a keys (full " +
		"decryption would require an IKE-state-aware iteration that tracks the " +
		"KE + Nonce + PRF state from IKE_SA_INIT).\n\n" +
		"Pure offline parser — operators paste IKEv2 bytes (UDP destination port " +
		"500, or 4500 with the 4-byte NAT-T marker stripped) from a `tcpdump -X " +
		"udp port 500` line or a Wireshark Follow-UDP-Stream view and get the " +
		"documented header + payload-chain breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed IKE bytes after the UDP " +
		"header strip — IKE runs on UDP destination port 500 or 4500 with NAT-T " +
		"marker); SA proposal/transform tree deep dissection (the SA payload " +
		"contains a nested list of Proposals + Transforms — encryption / " +
		"integrity / PRF / DH algorithms negotiated; surfaced as opaque hex; " +
		"would warrant a separate iteration); KE / Ni / Nr / IDi / IDr / AUTH " +
		"/ CERT body dissection (surfaced as opaque hex; per-body decoders are " +
		"future work); SK payload decryption (requires SK_e/SK_a keys derived " +
		"from IKE_SA_INIT KE + Nonce exchange; surfaced as opaque hex with an " +
		"encryption note); IKEv1 (RFC 2409 — different header, long-deprecated " +
		"but still seen in legacy deployments; would warrant its own Spec); " +
		"NAT-T marker stripping (when the 4-byte all-zeros marker is present " +
		"on UDP 4500, the operator must strip it before feeding bytes into " +
		"this decoder).\n\n" +
		"Source: docs/catalog/gap-analysis.md (IPsec control-plane protocol; " +
		"natural companion to esp_decode + ah_decode for complete IPsec VPN " +
		"coverage). Wrap-vs-native: native — RFC 7296 is fully public; IKEv2 " +
		"has a tight 28-byte fixed header followed by a chained list of " +
		"payloads with a uniform 4-byte payload header; the first exchange " +
		"(IKE_SA_INIT) is unencrypted so SA proposals + KE + Nonce + NAT-T " +
		"markers decode fully; from IKE_AUTH onwards SK-wrapped payloads are " +
		"opaque without the IKE-derived keys.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IKEv2 message bytes (after UDP header strip; UDP destination port 500, or 4500 with the 4-byte NAT-T marker stripped). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"max_payload_body_bytes":{"type":"integer","description":"Cap the per-payload body hex preview (default 256). Zero shows the full body."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ikeV2DecodeHandler,
}

func ikeV2DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ike_v2_decode: 'hex' is required")
	}
	opts := ike.DefaultDecodeOpts()
	if v, ok := p["max_payload_body_bytes"]; ok {
		if n, ok := intArg(v); ok {
			opts.MaxPayloadBodyBytes = n
		}
	}
	res, err := ike.Decode(raw, opts)
	if err != nil {
		return "", fmt.Errorf("ike_v2_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
