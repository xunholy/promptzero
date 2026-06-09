package emailauth

import "testing"

const (
	spfRec   = "v=spf1 include:_spf.google.com ~all"
	dmarcRec = "v=DMARC1; p=reject; rua=mailto:r@example.com"
	dkimRec  = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Hjb8Op39GmMzJe24RjyFdkuqKZPqTsVZjmjth9ueE/6eguK27DpnnZ4S3e9dyxfFmTdylcS2YiCPpwV4JtshkSXJk0st3kxynhmazzclnsuNS5HEmH/Ibh0EuBpmf9oToP3M03xjDds1YP+8nKiu+IdJyexkUnHNKTOW7VYLjQIDAQAB"
	// DKIM without the optional v= tag (recognised by k=/p=).
	dkimNoV = "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Hjb8Op39GmMzJe24RjyFdkuqKZPqTsVZjmjth9ueE/6eguK27DpnnZ4S3e9dyxfFmTdylcS2YiCPpwV4JtshkSXJk0st3kxynhmazzclnsuNS5HEmH/Ibh0EuBpmf9oToP3M03xjDds1YP+8nKiu+IdJyexkUnHNKTOW7VYLjQIDAQAB"
)

func TestRoute(t *testing.T) {
	cases := []struct {
		name, rec, wantKind string
	}{
		{"spf", spfRec, "spf"},
		{"dmarc", dmarcRec, "dmarc"},
		{"dkim", dkimRec, "dkim"},
		{"dkim_no_v", dkimNoV, "dkim"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Decode(c.rec)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if res.Kind != c.wantKind {
				t.Fatalf("kind = %q, want %q", res.Kind, c.wantKind)
			}
			// Exactly the matching sub-result must be populated.
			switch c.wantKind {
			case "spf":
				if res.SPF == nil || res.DMARC != nil || res.DKIM != nil {
					t.Errorf("spf routing populated wrong fields: %+v", res)
				}
			case "dmarc":
				if res.DMARC == nil || res.SPF != nil || res.DKIM != nil {
					t.Errorf("dmarc routing populated wrong fields: %+v", res)
				}
			case "dkim":
				if res.DKIM == nil || res.SPF != nil || res.DMARC != nil {
					t.Errorf("dkim routing populated wrong fields: %+v", res)
				}
			}
		})
	}
}

// TestRouteCaseInsensitive confirms the version prefix is matched
// case-insensitively (v=DMARC1, v=SPF1 casings vary in the wild).
func TestRouteCaseInsensitive(t *testing.T) {
	res, err := Decode("V=SPF1 -all")
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "spf" {
		t.Errorf("kind = %q, want spf", res.Kind)
	}
}

// TestRouteDigQuoted confirms a dig-quoted record routes correctly.
func TestRouteDigQuoted(t *testing.T) {
	res, err := Decode(`"v=spf1 include:_spf.google.com ~all"`)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "spf" || res.SPF == nil {
		t.Errorf("dig-quoted spf not routed: %+v", res)
	}
}

func TestRouteErrors(t *testing.T) {
	for _, c := range []string{"", "   ", "not a record", "v=STSv1; id=x"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error", c)
		}
	}
}

// TestSPFNotMisroutedToDKIM ensures an SPF record is never sent to the DKIM
// decoder (its terms have no p=/k= tags).
func TestSPFNotMisroutedToDKIM(t *testing.T) {
	res, err := Decode(spfRec)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "spf" {
		t.Errorf("kind = %q, want spf", res.Kind)
	}
}
