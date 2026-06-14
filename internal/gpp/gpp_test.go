package gpp

import (
	"strings"
	"testing"
)

// The two cpassword vectors are the well-known public examples (decryption
// cross-checked with openssl using the published MS-GPPREF AES-256 key):
//
//	localP4ssCp -> "Local*P4ssword!"  (the classic Metasploit / pentest sample)
//	gpp2k18Cp   -> "GPPstillStandingStrong2k18"
const (
	localP4ssCp = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
	localP4ssPw = "Local*P4ssword!"
	gpp2k18Cp   = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
	gpp2k18Pw   = "GPPstillStandingStrong2k18"
)

func TestDecode_RawCpassword(t *testing.T) {
	r, err := Decode([]byte(localP4ssCp))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 1 {
		t.Fatalf("count = %d, want 1", r.Count)
	}
	if r.Entries[0].Password != localP4ssPw {
		t.Errorf("password = %q, want %q", r.Entries[0].Password, localP4ssPw)
	}
	if !strings.Contains(r.Note, "CRITICAL") {
		t.Errorf("note = %q", r.Note)
	}
}

func TestDecode_SecondVector(t *testing.T) {
	r, err := Decode([]byte("  " + gpp2k18Cp + "\n"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Entries[0].Password != gpp2k18Pw {
		t.Errorf("password = %q, want %q", r.Entries[0].Password, gpp2k18Pw)
	}
}

func TestDecode_GroupsXML(t *testing.T) {
	xml := `<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)">
    <Properties action="U" newName="" fullName="" description=""
      cpassword="` + localP4ssCp + `" changeLogon="0" noChange="1"
      userName="Administrator (built-in)"/>
  </User>
  <User name="svc-backup">
    <Properties action="U" cpassword="` + gpp2k18Cp + `" userName="CONTOSO\svc-backup"/>
  </User>
</Groups>`
	r, err := Decode([]byte(xml))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 2 {
		t.Fatalf("count = %d, want 2", r.Count)
	}
	got := map[string]string{}
	for _, e := range r.Entries {
		got[e.Username] = e.Password
	}
	if got["Administrator (built-in)"] != localP4ssPw {
		t.Errorf("admin pw = %q, want %q", got["Administrator (built-in)"], localP4ssPw)
	}
	if got[`CONTOSO\svc-backup`] != gpp2k18Pw {
		t.Errorf("svc-backup pw = %q, want %q", got[`CONTOSO\svc-backup`], gpp2k18Pw)
	}
}

func TestDecode_ServicesAccountName(t *testing.T) {
	// Services.xml uses accountName instead of userName.
	xml := `<NTServices><NTService><Properties accountName="LocalSystemSvc" cpassword="` + localP4ssCp + `"/></NTService></NTServices>`
	r, err := Decode([]byte(xml))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 1 || r.Entries[0].Username != "LocalSystemSvc" || r.Entries[0].Password != localP4ssPw {
		t.Errorf("entry = %+v", r.Entries[0])
	}
}

func TestDecode_EmptyCleared(t *testing.T) {
	// A cleared cpassword (empty attribute) is a real pattern: admins thought
	// blanking the field removed the secret.
	r, err := Decode([]byte(`<Properties cpassword="" userName="bob"/>`))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 1 || !r.Entries[0].Empty || r.Entries[0].Password != "" {
		t.Errorf("expected empty entry, got %+v", r.Entries[0])
	}
}

func TestDecode_CorruptCpassword(t *testing.T) {
	// Valid base64 but wrong block length / garbage → per-entry error, not a panic.
	r, err := Decode([]byte("AAAA"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Entries[0].Error == "" {
		t.Errorf("expected an error for a too-short ciphertext")
	}
}

func TestDecode_Empty(t *testing.T) {
	if _, err := Decode([]byte("   ")); err == nil {
		t.Errorf("expected error on empty input")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte(localP4ssCp))
	f.Add([]byte(`<Properties cpassword="` + gpp2k18Cp + `" userName="x"/>`))
	f.Add([]byte("cpassword=\"AAAA\""))
	f.Add([]byte(""))
	f.Add([]byte("<a cpassword="))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Decode(data) // must never panic
	})
}
