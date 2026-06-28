package tools

import (
	"context"
	"strings"
	"testing"
)

// TestToolSearch_AgentStatusDiscoverability locks in that the
// agent_status posture diagnostic is reachable by the natural ways an
// operator asks about their session's safety state.
func TestToolSearch_AgentStatusDiscoverability(t *testing.T) {
	for _, q := range []string{
		"safety posture",
		"what mode am i in",
		"is this session audited",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "agent_status"`) {
			t.Errorf("query %q did not surface agent_status in the top results:\n%s", q, out)
		}
	}
}

// TestToolSearchHandler verifies the discovery tool wraps the live registry:
// an exact tool name ranks first, a task synonym surfaces a relevant tool, the
// output carries risk/group, and bad input is rejected.
func TestToolSearchHandler(t *testing.T) {
	// Exact name → that tool is present and (being an exact match) ranked first.
	out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": "device_info"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"name": "device_info"`) {
		t.Errorf("exact-name query missing device_info:\n%s", out)
	}
	if !strings.Contains(out, `"risk":`) || !strings.Contains(out, `"group":`) {
		t.Errorf("result missing risk/group enrichment:\n%s", out)
	}

	// Task query via synonym map: 'garage' should reach a subghz tool.
	out, err = toolSearchHandler(context.Background(), nil, map[string]any{"query": "garage door"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "subghz") {
		t.Errorf("garage door did not surface any subghz tool:\n%s", out)
	}

	// Empty query is rejected.
	if _, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": "  "}); err == nil {
		t.Error("empty query: expected error, got nil")
	}

	// No-match query returns a clean zero-result body, not an error.
	out, err = toolSearchHandler(context.Background(), nil, map[string]any{"query": "zzqqxx-nonexistent"})
	if err != nil {
		t.Fatalf("no-match handler: %v", err)
	}
	if !strings.Contains(out, `"count": 0`) {
		t.Errorf("no-match query should report count 0:\n%s", out)
	}
}

// TestToolSearch_AutomotiveDiscoverability guards that the OBD-II / UDS / CAN
// diagnostic tool family is reachable by natural automotive queries — a gap
// before the synonym map gained the engine/vehicle/diagnostic/obd/ecu/dtc
// entries and obd2_pid_decode's description listed its full (post-v0.726) PID
// coverage. Each query must surface its intended tool somewhere in the ranked
// results.
func TestToolSearch_AutomotiveDiscoverability(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		{"catalyst temperature", "obd2_pid_decode"}, // a v0.726 PID, now in the description
		{"engine sensor value", "obd2_pid_decode"},  // engine -> obd2/pid
		{"car diagnostic trouble code", "obd2_dtc_decode"},
		{"diagnostic trouble code status", "uds_dtc_status_decode"},
		{"ecu calibration flash", "xcp_decode"}, // ecu -> xcp/ccp
		{"vehicle identification number", "vin_decode"},
	}
	for _, c := range cases {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": c.query, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", c.query, err)
		}
		if !strings.Contains(out, `"name": "`+c.want+`"`) {
			t.Errorf("query %q did not surface %s in the top results:\n%s", c.query, c.want, out)
		}
	}
}

// TestToolSearch_IBANDiscoverability locks in that iban_decode is reachable by
// the natural ways an operator would ask for it (the discoverability concern
// codified in v0.729's automotive fix).
func TestToolSearch_IBANDiscoverability(t *testing.T) {
	for _, q := range []string{
		"IBAN",
		"international bank account number",
		"validate bank account number",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "iban_decode"`) {
			t.Errorf("query %q did not surface iban_decode in the top results:\n%s", q, out)
		}
	}
	// The encoder must be reachable by generation-flavoured queries.
	for _, q := range []string{
		"build a valid IBAN",
		"compute IBAN check digits",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "iban_encode"`) {
			t.Errorf("query %q did not surface iban_encode in the top results:\n%s", q, out)
		}
	}
}

// TestToolSearch_LEIDiscoverability locks in that lei_decode is reachable
// by the natural ways an operator would ask for it.
func TestToolSearch_LEIDiscoverability(t *testing.T) {
	for _, q := range []string{
		"LEI",
		"legal entity identifier",
		"validate ISO 17442",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "lei_decode"`) {
			t.Errorf("query %q did not surface lei_decode in the top results:\n%s", q, out)
		}
	}
}

// TestToolSearch_ISINDiscoverability locks in that isin_decode is reachable
// by the natural ways an operator would ask for it.
func TestToolSearch_ISINDiscoverability(t *testing.T) {
	for _, q := range []string{
		"ISIN",
		"securities identification number",
		"validate stock identifier",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "isin_decode"`) {
			t.Errorf("query %q did not surface isin_decode in the top results:\n%s", q, out)
		}
	}
}

// TestToolSearch_ABADiscoverability locks in that aba_routing_decode is
// reachable by the natural ways an operator would ask for it.
func TestToolSearch_ABADiscoverability(t *testing.T) {
	for _, q := range []string{
		"ABA routing number",
		"bank routing transit number",
		"validate RTN",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "aba_routing_decode"`) {
			t.Errorf("query %q did not surface aba_routing_decode in the top results:\n%s", q, out)
		}
	}
}

// TestToolSearch_FinancialObliqueDiscoverability locks in that the
// financial-data decoder family (iban/lei/isin/aba) is reachable by the
// oblique task phrasings an operator actually uses — not just the exact
// acronyms. These all returned nothing before the finance synonym cluster
// was added to internal/toolsearch.
func TestToolSearch_FinancialObliqueDiscoverability(t *testing.T) {
	cases := map[string]string{
		"wire transfer details":   "iban_decode",
		"swift payment fields":    "iban_decode",
		"what bank is this":       "aba_routing_decode",
		"ach routing":             "aba_routing_decode",
		"decode a stock ticker":   "isin_decode",
		"brokerage securities id": "isin_decode",
	}
	for q, want := range cases {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "`+want+`"`) {
			t.Errorf("query %q did not surface %s in the top results:\n%s", q, want, out)
		}
	}
}

// TestToolSearch_CloudCredentialDiscoverability locks in that the
// cloud-platform credential decoders, which name themselves by the
// platform contraction (kubeconfig_decode, gcp_service_account_decode),
// are reachable by an operator's full-word phrasing. These returned
// nothing before the kubernetes/k8s/google synonyms were added.
func TestToolSearch_CloudCredentialDiscoverability(t *testing.T) {
	cases := map[string]string{
		"kubernetes config":            "kubeconfig_decode",
		"k8s credentials":              "kubeconfig_decode",
		"google cloud service account": "gcp_service_account_decode",
	}
	for q, want := range cases {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "`+want+`"`) {
			t.Errorf("query %q did not surface %s in the top results:\n%s", q, want, out)
		}
	}
}

// TestToolSearch_AirTagDiscoverability locks in that the Apple Continuity
// decoders (the AirTag / Find My BLE-tracker sweep) are reachable by the
// consumer terms operators actually use. All of these returned nothing
// before the airtag/tracker/beacon synonyms were added — only the jargon
// "apple continuity" worked.
func TestToolSearch_AirTagDiscoverability(t *testing.T) {
	for _, q := range []string{
		"airtag",
		"find my tracker",
		"is someone tracking me airtag",
		"apple beacon",
	} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "ble_continuity_decode"`) {
			t.Errorf("query %q did not surface ble_continuity_decode in the top results:\n%s", q, out)
		}
	}
}

// TestToolSearch_CellularObliqueDiscoverability locks in that the cellular
// identifier triad (iccid/imsi/imei) is reachable by the family terms "sim"
// and "cellular" — both returned nothing before the cellular synonym cluster
// was added. (The "card"-heavy phrasing "sim card number" is deliberately
// not pinned: it is dominated by the card-decoder cluster, a legitimate
// interpretation.)
func TestToolSearch_CellularObliqueDiscoverability(t *testing.T) {
	cases := map[string]string{
		"decode this sim":      "iccid_decode",
		"cellular identifiers": "imei_decode",
		"sim swap forensics":   "iccid_decode",
	}
	for q, want := range cases {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: handler: %v", q, err)
		}
		if !strings.Contains(out, `"name": "`+want+`"`) {
			t.Errorf("query %q did not surface %s in the top results:\n%s", q, want, out)
		}
	}
}

// TestToolSearch_WigleWardriveDiscoverability locks in that the wardrive
// CSV exporter is reachable by the terms a wardriver actually uses.
func TestToolSearch_WigleWardriveDiscoverability(t *testing.T) {
	for _, q := range []string{"wardrive", "wardriving", "wigle", "geolocate access points"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "wigle_wardrive_export"`) {
			t.Errorf("query %q did not surface wigle_wardrive_export:\n%s", q, out)
		}
	}
}

// TestToolSearch_WigleAnalyzeDiscoverability locks in that the wardrive
// import/triage tool is reachable by its natural terms.
func TestToolSearch_WigleAnalyzeDiscoverability(t *testing.T) {
	for _, q := range []string{"analyze wardrive", "import wigle csv", "wardrive"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "wigle_wardrive_analyze"`) {
			t.Errorf("query %q did not surface wigle_wardrive_analyze:\n%s", q, out)
		}
	}
}

// TestToolSearch_WigleMergeDiscoverability locks in discoverability of the
// wardrive merge tool.
func TestToolSearch_WigleMergeDiscoverability(t *testing.T) {
	for _, q := range []string{"merge wardrive", "consolidate wardrive csv", "dedupe wigle"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "wigle_wardrive_merge"`) {
			t.Errorf("query %q did not surface wigle_wardrive_merge:\n%s", q, out)
		}
	}
}

// TestToolSearch_WebAuthnDiscoverability locks in discoverability of the
// WebAuthn authenticator-data decoder.
func TestToolSearch_WebAuthnDiscoverability(t *testing.T) {
	for _, q := range []string{"webauthn", "fido2 authenticator data", "passkey attestation"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "webauthn_authdata_decode"`) {
			t.Errorf("query %q did not surface webauthn_authdata_decode:\n%s", q, out)
		}
	}
}

// TestToolSearch_CoseKeyDiscoverability locks in discoverability of the
// COSE_Key decoder.
func TestToolSearch_CoseKeyDiscoverability(t *testing.T) {
	for _, q := range []string{"cose key", "decode cose_key", "credential public key cose"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "cose_key_decode"`) {
			t.Errorf("query %q did not surface cose_key_decode:\n%s", q, out)
		}
	}
}

// TestToolSearch_CWTDiscoverability locks in discoverability of the CWT decoder.
func TestToolSearch_CWTDiscoverability(t *testing.T) {
	for _, q := range []string{"cwt", "cbor web token", "decode cwt token"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "cwt_decode"`) {
			t.Errorf("query %q did not surface cwt_decode:\n%s", q, out)
		}
	}
}

// TestToolSearch_CoseMessageDiscoverability locks in discoverability of the
// general COSE message decoder.
func TestToolSearch_CoseMessageDiscoverability(t *testing.T) {
	for _, q := range []string{"cose message", "cose_sign1 decode", "cose signed attestation"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "cose_message_decode"`) {
			t.Errorf("query %q did not surface cose_message_decode:\n%s", q, out)
		}
	}
}

// TestToolSearch_AuditVerifyDiscoverability locks in discoverability of the
// audit tamper-evidence tool.
func TestToolSearch_AuditVerifyDiscoverability(t *testing.T) {
	for _, q := range []string{"audit verify", "audit log integrity", "detect tampered audit"} {
		out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !strings.Contains(out, `"name": "audit_verify"`) {
			t.Errorf("query %q did not surface audit_verify:\n%s", q, out)
		}
	}
}

// TestToolSearch_CSRCRLDiscoverability locks in discoverability of the CSR
// and CRL decoders.
func TestToolSearch_CSRCRLDiscoverability(t *testing.T) {
	checks := map[string][]string{
		"csr_decode": {"certificate signing request", "csr decode", "pkcs10 request"},
		"crl_decode": {"x509 crl", "crl decode", "revoked certificates"},
	}
	for name, queries := range checks {
		for _, q := range queries {
			out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": q, "limit": 8})
			if err != nil {
				t.Fatalf("%q: %v", q, err)
			}
			if !strings.Contains(out, `"name": "`+name+`"`) {
				t.Errorf("query %q did not surface %s:\n%s", q, name, out)
			}
		}
	}
}
