package dmarc

import (
	"strings"
	"testing"
)

// These records are live, published DMARC records (dig +short TXT
// _dmarc.<domain>), used as authoritative field-extraction vectors.
func TestDMARC_RealRecords(t *testing.T) {
	t.Run("google_reject", func(t *testing.T) {
		res, err := Decode("v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com")
		if err != nil {
			t.Fatal(err)
		}
		if res.Policy != "reject" || !res.Enforcing {
			t.Errorf("policy=%q enforcing=%v, want reject/true", res.Policy, res.Enforcing)
		}
		if len(res.AggregateReports) != 1 || res.AggregateReports[0] != "mailto:mailauth-reports@google.com" {
			t.Errorf("rua = %v", res.AggregateReports)
		}
	})

	t.Run("github_quarantine_sp_pct_fo", func(t *testing.T) {
		res, err := Decode("v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ruf=mailto:dmarc@github.com; fo=1")
		if err != nil {
			t.Fatal(err)
		}
		if res.Policy != "quarantine" || !res.Enforcing {
			t.Errorf("policy=%q enforcing=%v", res.Policy, res.Enforcing)
		}
		if res.SubdomainPolicy != "reject" {
			t.Errorf("sp = %q, want reject", res.SubdomainPolicy)
		}
		if res.Pct != 100 {
			t.Errorf("pct = %d", res.Pct)
		}
		if len(res.ForensicReports) != 1 || len(res.FailureOptions) != 1 || res.FailureOptions[0] != "1" {
			t.Errorf("ruf=%v fo=%v", res.ForensicReports, res.FailureOptions)
		}
	})

	t.Run("paypal_rua_ruf", func(t *testing.T) {
		res, err := Decode("v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.AggregateReports) != 1 || len(res.ForensicReports) != 1 {
			t.Errorf("rua=%v ruf=%v", res.AggregateReports, res.ForensicReports)
		}
	})
}

// TestDMARC_NoneIsMonitoring pins the headline finding: p=none does not enforce.
func TestDMARC_NoneIsMonitoring(t *testing.T) {
	res, err := Decode("v=DMARC1; p=none; rua=mailto:r@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Enforcing {
		t.Error("p=none must not be enforcing")
	}
	if !strings.Contains(res.Note, "MONITORING ONLY") {
		t.Errorf("note should flag monitoring-only, got %q", res.Note)
	}
}

// TestDMARC_Defaults checks the RFC default values when tags are absent.
func TestDMARC_Defaults(t *testing.T) {
	res, err := Decode("v=DMARC1; p=reject")
	if err != nil {
		t.Fatal(err)
	}
	if res.Pct != 100 || res.DKIMAlignment != "r" || res.SPFAlignment != "r" || res.ReportInterval != 86400 {
		t.Errorf("defaults wrong: pct=%d adkim=%q aspf=%q ri=%d", res.Pct, res.DKIMAlignment, res.SPFAlignment, res.ReportInterval)
	}
}

func TestDMARC_StrictAlignment(t *testing.T) {
	res, err := Decode("v=DMARC1; p=reject; adkim=s; aspf=s")
	if err != nil {
		t.Fatal(err)
	}
	if res.DKIMAlignment != "s" || res.SPFAlignment != "s" {
		t.Errorf("alignment = %q/%q, want s/s", res.DKIMAlignment, res.SPFAlignment)
	}
}

// TestDMARC_PctPartial flags partial enforcement.
func TestDMARC_PctPartial(t *testing.T) {
	res, err := Decode("v=DMARC1; p=reject; pct=20")
	if err != nil {
		t.Fatal(err)
	}
	if res.Pct != 20 {
		t.Errorf("pct = %d", res.Pct)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "20%") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected partial-enforcement warning, got %v", res.Warnings)
	}
}

// TestDMARC_MissingPolicy: p is required; surfaced with a warning, not enforcing.
func TestDMARC_MissingPolicy(t *testing.T) {
	res, err := Decode("v=DMARC1; rua=mailto:r@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Enforcing {
		t.Error("missing p must not be enforcing")
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for missing p=")
	}
}

func TestDMARC_Errors(t *testing.T) {
	// Not a DMARC record (no v=, or wrong version, or v not first).
	cases := []string{"", "p=reject; v=DMARC1", "v=spf1 -all", "v=DKIM1; p=foo"}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error", c)
		}
	}
}
