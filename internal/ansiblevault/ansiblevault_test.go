package ansiblevault

import "testing"

// Header shapes verified against real ansible-core VaultLib output:
//
//	v1.1: $ANSIBLE_VAULT;1.1;AES256
//	v1.2: $ANSIBLE_VAULT;1.2;AES256;<vault-id>
const vault11 = `$ANSIBLE_VAULT;1.1;AES256
33646465656565623236346564356435616563656639613862613835663930383231353931313464
3930666461386162393463343031326635613639336131613664383738653263636533653063`

const vault12 = `$ANSIBLE_VAULT;1.2;AES256;prod
32393365616336626534356463373437666361393762303030303734646265663633343962353639
6464336265643731376337373764626161393432663036340a353837623466653937333834303237`

func TestDecode_V11(t *testing.T) {
	r, err := Decode(vault11)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "1.1" || r.Cipher != "AES256" || r.VaultID != "" {
		t.Errorf("v=%q cipher=%q id=%q", r.Version, r.Cipher, r.VaultID)
	}
	if r.HashcatMode != 16900 || r.JohnTool != "ansible2john" {
		t.Errorf("mode=%d john=%q", r.HashcatMode, r.JohnTool)
	}
	if r.BodyBytes <= 0 {
		t.Errorf("body bytes = %d, want > 0", r.BodyBytes)
	}
}

func TestDecode_V12VaultID(t *testing.T) {
	r, err := Decode(vault12)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "1.2" || r.VaultID != "prod" {
		t.Errorf("v=%q id=%q, want 1.2/prod", r.Version, r.VaultID)
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"not vault":  "secret: plaintext value\n",
		"bad header": "$ANSIBLE_VAULT;1.1\n",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(vault11)
	f.Add(vault12)
	f.Add("$ANSIBLE_VAULT;")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
