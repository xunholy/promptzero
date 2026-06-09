package spf

import (
	"strings"
	"testing"
)

// Vectors are live, published SPF records (dig +short TXT <domain>), used as
// authoritative field-extraction / lookup-count anchors.
const (
	googleSPF = "v=spf1 include:_spf.google.com ~all"
	githubSPF = "v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com include:_netblocks.google.com include:_netblocks2.google.com include:mail.zendesk.com include:_spf.salesforce.com include:servers.mcsv.net include:mktomail.com include:sendgrid.net ip4:62.253.227.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all"
)

func TestSPF_Google(t *testing.T) {
	res, err := Decode(googleSPF)
	if err != nil {
		t.Fatal(err)
	}
	if res.AllQualifier != "~" {
		t.Errorf("all qualifier = %q, want ~", res.AllQualifier)
	}
	if res.DirectLookups != 1 {
		t.Errorf("direct lookups = %d, want 1 (one include)", res.DirectLookups)
	}
	if len(res.Mechanisms) != 2 { // include + all
		t.Errorf("mechanisms = %d, want 2", len(res.Mechanisms))
	}
	if res.Mechanisms[0].Type != "include" || res.Mechanisms[0].Value != "_spf.google.com" || !res.Mechanisms[0].CausesLookup {
		t.Errorf("include mechanism = %+v", res.Mechanisms[0])
	}
}

func TestSPF_Github8Lookups(t *testing.T) {
	res, err := Decode(githubSPF)
	if err != nil {
		t.Fatal(err)
	}
	// 8 includes; the ip4 terms cause no lookups.
	if res.DirectLookups != 8 {
		t.Errorf("direct lookups = %d, want 8", res.DirectLookups)
	}
	if res.AllQualifier != "~" {
		t.Errorf("all qualifier = %q, want ~", res.AllQualifier)
	}
}

// TestSPF_DigMultiString feeds the raw dig output (two quoted strings split
// mid-token) and confirms it normalises to the joined record.
func TestSPF_DigMultiString(t *testing.T) {
	raw := `"v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com ip4:62.253.2" "27.114 ip4:166.78.69.169 ~all"`
	res, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode dig form: %v", err)
	}
	// The split ip4 62.253.2 + 27.114 must rejoin to one ip4 term, not two.
	for _, m := range res.Mechanisms {
		if m.Type == "ip4" && (m.Value == "62.253.2" || m.Value == "27.114") {
			t.Errorf("multi-string join failed: got fragment %q", m.Value)
		}
	}
	if res.AllQualifier != "~" {
		t.Errorf("all qualifier = %q after join, want ~", res.AllQualifier)
	}
}

// TestSPF_PassAllCritical is the critical finding: +all authorises everyone.
func TestSPF_PassAllCritical(t *testing.T) {
	res, err := Decode("v=spf1 +all")
	if err != nil {
		t.Fatal(err)
	}
	if res.AllQualifier != "+" {
		t.Errorf("all qualifier = %q, want +", res.AllQualifier)
	}
	if !strings.Contains(res.Note, "ENTIRE internet") {
		t.Errorf("note should flag pass-all as critical, got %q", res.Note)
	}
}

func TestSPF_AllQualifiers(t *testing.T) {
	cases := map[string]string{
		"v=spf1 -all": "FAIL",
		"v=spf1 ~all": "SOFTFAIL",
		"v=spf1 ?all": "NEUTRAL",
	}
	for rec, want := range cases {
		res, err := Decode(rec)
		if err != nil {
			t.Fatalf("%q: %v", rec, err)
		}
		if !strings.Contains(res.Note, want) {
			t.Errorf("%q note = %q, want substring %q", rec, res.Note, want)
		}
	}
}

// TestSPF_PtrDeprecated flags the deprecated ptr mechanism.
func TestSPF_PtrDeprecated(t *testing.T) {
	res, err := Decode("v=spf1 ptr -all")
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(res.Warnings, "ptr") {
		t.Errorf("expected ptr-deprecated warning, got %v", res.Warnings)
	}
	if res.DirectLookups != 1 {
		t.Errorf("ptr should count as 1 lookup, got %d", res.DirectLookups)
	}
}

// TestSPF_Redirect counts redirect as a lookup and notes it governs the result.
func TestSPF_Redirect(t *testing.T) {
	res, err := Decode("v=spf1 redirect=_spf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Redirect != "_spf.example.com" {
		t.Errorf("redirect = %q", res.Redirect)
	}
	if res.DirectLookups != 1 {
		t.Errorf("redirect should count as 1 lookup, got %d", res.DirectLookups)
	}
}

// TestSPF_NoAll warns that a record without a terminal all/redirect is neutral.
func TestSPF_NoAll(t *testing.T) {
	res, err := Decode("v=spf1 ip4:1.2.3.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if res.AllQualifier != "" {
		t.Errorf("all qualifier = %q, want empty", res.AllQualifier)
	}
	if !hasWarning(res.Warnings, "terminal") {
		t.Errorf("expected missing-terminal warning, got %v", res.Warnings)
	}
}

func TestSPF_Errors(t *testing.T) {
	for _, c := range []string{"", "v=DMARC1; p=reject", "include:example.com -all"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error", c)
		}
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
