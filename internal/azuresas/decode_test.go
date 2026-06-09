// SPDX-License-Identifier: AGPL-3.0-or-later

package azuresas_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/azuresas"
)

// TestMicrosoftWorkedExample anchors against the worked example from the Azure
// "Create a service SAS" reference:
//
//	?sp=rw&st=2023-05-24T01:13:55Z&se=2023-05-24T09:13:55Z
//	&sip=198.51.100.10-198.51.100.20&spr=https&sv=2022-11-02&sr=b&sig=<signature>
//
// → Read + Write on a blob, HTTPS only, with the stated window and IP range.
func TestMicrosoftWorkedExample(t *testing.T) {
	const sas = "https://myaccount.blob.core.windows.net/sascontainer/blob1.txt?" +
		"sp=rw&st=2023-05-24T01:13:55Z&se=2023-05-24T09:13:55Z" +
		"&sip=198.51.100.10-198.51.100.20&spr=https&sv=2022-11-02&sr=b&sig=abc123"
	r, err := azuresas.Decode(sas)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != "service SAS" {
		t.Errorf("type = %q; want service SAS", r.Type)
	}
	if r.Resource != "Blob" {
		t.Errorf("resource = %q; want Blob", r.Resource)
	}
	if r.Version != "2022-11-02" {
		t.Errorf("version = %q; want 2022-11-02", r.Version)
	}
	if r.Start != "2023-05-24T01:13:55Z" || r.Expiry != "2023-05-24T09:13:55Z" {
		t.Errorf("window = %q..%q", r.Start, r.Expiry)
	}
	if r.IPRange != "198.51.100.10-198.51.100.20" {
		t.Errorf("ip_range = %q", r.IPRange)
	}
	if r.Protocol != "https" {
		t.Errorf("protocol = %q; want https", r.Protocol)
	}
	if !r.HasSignature {
		t.Errorf("has_signature = false; want true")
	}
	if got := joined(r.Permissions); got != "r = Read | w = Write" {
		t.Errorf("permissions = %q; want 'r = Read | w = Write'", got)
	}
	if r.Note != "" {
		t.Errorf("unexpected note for a definite sr=b context: %q", r.Note)
	}
}

// TestAccountSAS covers an account SAS (ss + srt + sp), and confirms the
// service/resource-type expansion plus the account-SAS permission note.
func TestAccountSAS(t *testing.T) {
	const sas = "?sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupiytfx&se=2024-01-01T00:00:00Z&spr=https&sig=xyz"
	r, err := azuresas.Decode(sas)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != "account SAS" {
		t.Errorf("type = %q; want account SAS", r.Type)
	}
	// ss=bfqt → Blob, File, Queue, Table (sorted by the expand helper).
	if got := joined(r.Services); !strings.Contains(got, "b = Blob") || !strings.Contains(got, "q = Queue") ||
		!strings.Contains(got, "t = Table") || !strings.Contains(got, "f = File") {
		t.Errorf("services = %q; want all of Blob/File/Queue/Table", got)
	}
	// srt=sco → Service, Container, Object.
	if got := joined(r.ResourceTypes); !strings.Contains(got, "s = Service") ||
		!strings.Contains(got, "c = Container") || !strings.Contains(got, "o = Object") {
		t.Errorf("resource_types = %q", got)
	}
	if r.Note == "" {
		t.Errorf("expected an account-SAS permission caveat note")
	}
	// A few well-known letters should expand to the common Blob meaning.
	got := joined(r.Permissions)
	for _, want := range []string{"r = Read", "w = Write", "d = Delete", "l = List", "a = Add"} {
		if !strings.Contains(got, want) {
			t.Errorf("permissions %q missing %q", got, want)
		}
	}
}

// TestTableSAS confirms the table permission context (r = Query, not Read).
func TestTableSAS(t *testing.T) {
	r, err := azuresas.Decode("?sv=2022-11-02&tn=mytable&sp=raud&se=2024-01-01T00:00:00Z&sig=z")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TableName != "mytable" {
		t.Errorf("table_name = %q", r.TableName)
	}
	if got := joined(r.Permissions); !strings.Contains(got, "r = Query") || !strings.Contains(got, "u = Update") {
		t.Errorf("table permissions = %q; want r = Query / u = Update", got)
	}
}

// TestUserDelegationSAS is identified by the skoid/sktid fields.
func TestUserDelegationSAS(t *testing.T) {
	r, err := azuresas.Decode("?sv=2022-11-02&sr=c&sp=rl&se=2024-01-01T00:00:00Z&skoid=11111111-1111-1111-1111-111111111111&sktid=22222222-2222-2222-2222-222222222222&sig=z")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != "user delegation SAS" {
		t.Errorf("type = %q; want user delegation SAS", r.Type)
	}
	if r.Resource != "Container" {
		t.Errorf("resource = %q; want Container", r.Resource)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"no sas fields": "https://example.com/path?foo=bar&baz=1",
		"bad query":     "?sv=%zz",
	}
	for name, in := range cases {
		if _, err := azuresas.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}

// joined renders a permission/service list as "a | b | c" for assertions.
func joined(s []string) string { return strings.Join(s, " | ") }
